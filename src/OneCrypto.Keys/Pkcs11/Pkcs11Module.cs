using System.Runtime.InteropServices;
using System.Text;

namespace RecursiveAI.OneCrypto.Keys.Pkcs11;

/// <summary>What the module says about itself (CK_INFO, PKCS #11 v3.1 §5.4).</summary>
public sealed class Pkcs11ModuleInfo
{
    internal Pkcs11ModuleInfo(byte[] info)
    {
        CryptokiVersion = new Version(info[0], info[1]);
        Manufacturer = Pkcs11Text.Field(info.AsSpan(2, 32));
        Description = Pkcs11Text.Field(info.AsSpan(48, 32));
        LibraryVersion = new Version(info[80], info[81]);
    }

    /// <summary>The version of the PKCS #11 interface the module implements.</summary>
    public Version CryptokiVersion { get; }

    /// <summary>The manufacturer, as the module reports it (blank padding removed).</summary>
    public string Manufacturer { get; }

    /// <summary>The module's description.</summary>
    public string Description { get; }

    /// <summary>The module's own version.</summary>
    public Version LibraryVersion { get; }
}

internal static class Pkcs11Text
{
    /// <summary>A blank-padded UTF-8 field of a PKCS #11 info structure, without the padding.</summary>
    internal static string Field(ReadOnlySpan<byte> field) => Encoding.UTF8.GetString(field).TrimEnd(' ', '\0');
}

/// <summary>
/// A loaded PKCS #11 module (a token vendor's shared library, or SoftHSM2): the entry point for slots, tokens and sessions. Loading is by path and
/// nothing is searched for: the caller says which module. Loading the same path twice shares one initialised copy, which the last
/// <see cref="Dispose"/> finalises. Disposing closes every session opened through it.
/// </summary>
/// <remarks>
/// Only 64-bit macOS and Linux are supported. A module that needs settings (SoftHSM2 reads <c>SOFTHSM2_CONF</c>) reads them when it is first
/// initialised in the process.
/// </remarks>
public sealed class Pkcs11Module : IDisposable
{
    private readonly NativeModule _native;
    private readonly List<Pkcs11Session> _sessions = [];
    private bool _disposed;

    private Pkcs11Module(string path, NativeModule native)
    {
        Path = path;
        _native = native;
        Info = new Pkcs11ModuleInfo(Raw.GetInfo(native));
    }

    /// <summary>The path the module was loaded from, as given.</summary>
    public string Path { get; }

    /// <summary>What the module reports about itself.</summary>
    public Pkcs11ModuleInfo Info { get; }

    internal NativeModule Native => _disposed ? throw new ObjectDisposedException(nameof(Pkcs11Module)) : _native;

    /// <summary>Loads and initialises the module at <paramref name="path"/> (C_GetFunctionList, then C_Initialize with OS locking so several threads may use it).</summary>
    /// <param name="path">The module file. A name without a directory goes through the system's library search.</param>
    /// <exception cref="Pkcs11ModuleException">The file is missing, is not a module for this platform, or failed to initialise; or the platform is not supported.</exception>
    public static Pkcs11Module Load(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        NativeModule native = NativeModule.Acquire(path);
        try
        {
            return new Pkcs11Module(path, native);
        }
        catch
        {
            native.Release();
            throw;
        }
    }

    /// <summary>The slots of the module (C_GetSlotList, §5.5.1).</summary>
    /// <param name="tokenPresentOnly">True (the default) to list only slots that hold a token.</param>
    /// <exception cref="Pkcs11Exception">The module reported an error.</exception>
    public IReadOnlyList<Pkcs11Slot> GetSlots(bool tokenPresentOnly = true)
    {
        NativeModule n = Native;
        nuint[] ids = Raw.GetSlotList(n, tokenPresentOnly);
        var slots = new List<Pkcs11Slot>(ids.Length);
        foreach (nuint id in ids)
        {
            slots.Add(new Pkcs11Slot(this, id));
        }

        return slots;
    }

    internal void Register(Pkcs11Session s)
    {
        lock (_sessions)
        {
            _sessions.Add(s);
        }
    }

    internal void Unregister(Pkcs11Session s)
    {
        lock (_sessions)
        {
            _sessions.Remove(s);
        }
    }

    /// <summary>Closes every session opened through this module and releases it.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Pkcs11Session[] open;
        lock (_sessions)
        {
            open = [.. _sessions];
        }

        foreach (Pkcs11Session s in open)
        {
            s.Dispose();
        }

        _disposed = true;
        _native.Release();
    }
}

/// <summary>A slot of a module (CK_SLOT_INFO, §5.5.2): a reader or a token position, with or without a token in it.</summary>
public sealed class Pkcs11Slot
{
    private HashSet<ulong>? _mechanisms;

    internal Pkcs11Slot(Pkcs11Module module, nuint id)
    {
        Module = module;
        Id = id;
        byte[] info = Raw.GetSlotInfo(module.Native, id);
        Description = Pkcs11Text.Field(info.AsSpan(0, 64));
        Manufacturer = Pkcs11Text.Field(info.AsSpan(64, 32));
        nuint flags = MemoryMarshal.Read<nuint>(info.AsSpan(96));
        TokenPresent = (flags & 1) != 0;
        Removable = (flags & 2) != 0;
    }

    /// <summary>The module the slot belongs to.</summary>
    public Pkcs11Module Module { get; }

    /// <summary>The slot identifier (CK_SLOT_ID). Identifiers are not stable across module restarts for every module; find a token by its label or serial number.</summary>
    public ulong Id { get; }

    /// <summary>The slot's description.</summary>
    public string Description { get; }

    /// <summary>The slot's manufacturer.</summary>
    public string Manufacturer { get; }

    /// <summary>True when a token was present when the slot was listed (CKF_TOKEN_PRESENT).</summary>
    public bool TokenPresent { get; }

    /// <summary>True when the token can be removed (CKF_REMOVABLE_DEVICE).</summary>
    public bool Removable { get; }

    /// <summary>The token in the slot (C_GetTokenInfo, §5.5.3).</summary>
    /// <exception cref="Pkcs11TokenException">No token is present, or it is not recognised.</exception>
    public Pkcs11TokenInfo GetTokenInfo() => new(Raw.GetTokenInfo(Module.Native, (nuint)Id));

    /// <summary>The mechanisms the token offers (C_GetMechanismList, §5.5.5), as CKM_ numbers. Read once and kept.</summary>
    /// <exception cref="Pkcs11TokenException">No token is present.</exception>
    public IReadOnlySet<ulong> GetMechanisms()
    {
        if (_mechanisms is null)
        {
            var set = new HashSet<ulong>();
            foreach (nuint m in Raw.GetMechanismList(Module.Native, (nuint)Id))
            {
                set.Add(m);
            }

            _mechanisms = set;
        }

        return _mechanisms;
    }

    /// <summary>Opens a session on the token (C_OpenSession, §5.6.1). Read-only sessions cannot create or destroy objects.</summary>
    /// <param name="readWrite">True for a read/write session.</param>
    /// <exception cref="Pkcs11TokenException">No token is present, or the module refused another session.</exception>
    public Pkcs11Session OpenSession(bool readWrite = false) => Pkcs11Session.Open(this, readWrite);
}

/// <summary>What a token reports about itself (CK_TOKEN_INFO, §5.5.3).</summary>
public sealed class Pkcs11TokenInfo
{
    internal Pkcs11TokenInfo(byte[] info)
    {
        Label = Pkcs11Text.Field(info.AsSpan(0, 32));
        Manufacturer = Pkcs11Text.Field(info.AsSpan(32, 32));
        Model = Pkcs11Text.Field(info.AsSpan(64, 16));
        SerialNumber = Pkcs11Text.Field(info.AsSpan(80, 16));
        Flags = (ulong)MemoryMarshal.Read<nuint>(info.AsSpan(96));
        MaxPinLength = (int)MemoryMarshal.Read<nuint>(info.AsSpan(136));
        MinPinLength = (int)MemoryMarshal.Read<nuint>(info.AsSpan(144));
    }

    /// <summary>The token label, which the owner chose when initialising it.</summary>
    public string Label { get; }

    /// <summary>The manufacturer.</summary>
    public string Manufacturer { get; }

    /// <summary>The model.</summary>
    public string Model { get; }

    /// <summary>The serial number (not unique across vendors).</summary>
    public string SerialNumber { get; }

    /// <summary>The CKF_ flags as reported.</summary>
    public ulong Flags { get; }

    /// <summary>The longest PIN the token accepts.</summary>
    public int MaxPinLength { get; }

    /// <summary>The shortest PIN the token accepts.</summary>
    public int MinPinLength { get; }

    /// <summary>True when private objects need a login (CKF_LOGIN_REQUIRED).</summary>
    public bool LoginRequired => (Flags & 0x4) != 0;

    /// <summary>True when the user PIN has been set (CKF_USER_PIN_INITIALIZED).</summary>
    public bool UserPinInitialized => (Flags & 0x8) != 0;

    /// <summary>True when the token has its own PIN pad or prompt, so the PIN is not passed by the caller (CKF_PROTECTED_AUTHENTICATION_PATH).</summary>
    public bool ProtectedAuthenticationPath => (Flags & 0x100) != 0;

    /// <summary>True when the token has been initialised (CKF_TOKEN_INITIALIZED).</summary>
    public bool Initialized => (Flags & 0x400) != 0;

    /// <summary>True when only a few wrong attempts remain before the user PIN locks (CKF_USER_PIN_COUNT_LOW).</summary>
    public bool UserPinCountLow => (Flags & 0x10000) != 0;

    /// <summary>True when one more wrong attempt locks the user PIN (CKF_USER_PIN_FINAL_TRY).</summary>
    public bool UserPinFinalTry => (Flags & 0x20000) != 0;

    /// <summary>True when the user PIN is locked (CKF_USER_PIN_LOCKED).</summary>
    public bool UserPinLocked => (Flags & 0x40000) != 0;
}
