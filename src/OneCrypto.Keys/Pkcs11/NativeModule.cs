using System.Runtime.InteropServices;

namespace RecursiveAI.OneCrypto.Keys.Pkcs11;

/// <summary>CK_ATTRIBUTE (PKCS #11 v3.1): type, value pointer, value length.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct CkAttribute
{
    public nuint Type;
    public void* Value;
    public nuint Length;
}

/// <summary>CK_MECHANISM: type, parameter pointer, parameter length.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct CkMechanism
{
    public nuint Type;
    public void* Parameter;
    public nuint ParameterLength;
}

/// <summary>
/// One loaded PKCS #11 module: the library handle and the function table from <c>C_GetFunctionList</c>. Calls go through function
/// pointers of the C calling convention, so no interface marshalling is generated and nothing needs reflection. CK_ULONG is the platform's
/// <c>unsigned long</c>, which is <see cref="nuint"/> on every 64-bit Unix platform; other platforms are refused at load (Windows uses a 32-bit
/// CK_ULONG and byte-packed structures, which this backend does not do).
/// Every pointer argument points into memory the caller keeps pinned for the duration of the call (a <c>fixed</c> block or a pinned array).
/// </summary>
internal sealed unsafe class NativeModule : IDisposable
{
    // The order of the function list (CK_FUNCTION_LIST): the version, then one pointer per function.
    private const int Initialize = 0, Finalize = 1, GetInfo = 2, GetSlotList = 4, GetSlotInfo = 5, GetTokenInfo = 6, GetMechanismList = 7,
        GetMechanismInfo = 8, OpenSession = 12, CloseSession = 13, CloseAllSessions = 14, GetSessionInfo = 15, Login = 18, Logout = 19,
        CreateObject = 20, DestroyObject = 22, GetAttributeValue = 24, SetAttributeValue = 25, FindObjectsInit = 26, FindObjects = 27, FindObjectsFinal = 28,
        DecryptInit = 33, Decrypt = 34, SignInit = 42, Sign = 43, GenerateKeyPair = 59, DeriveKey = 62;
    private const int FunctionCount = 65;

    private static readonly object Gate = new();
    private static readonly Dictionary<string, NativeModule> Loaded = [];

    private readonly nint _library;
    private readonly nint[] _f;
    private readonly string _key;
    private readonly bool _ownsInitialize;
    private int _references;
    private bool _disposed;

    private NativeModule(string key, nint library, nint[] functions, bool ownsInitialize)
    {
        _key = key;
        _library = library;
        _f = functions;
        _ownsInitialize = ownsInitialize;
    }

    /// <summary>A module made of the given function table, for tests that play a misbehaving module. The caller keeps the pointers valid.</summary>
    internal static NativeModule ForFunctions(nint[] functions) => new("test", 0, functions, false) { _references = 1 };

    /// <summary>The slot of a function in the table (the order of CK_FUNCTION_LIST), so a test can fill it.</summary>
    internal static class Slots
    {
        public const int GetSlotList = NativeModule.GetSlotList, GetAttributeValue = NativeModule.GetAttributeValue, FindObjectsInit = NativeModule.FindObjectsInit,
            FindObjects = NativeModule.FindObjects, FindObjectsFinal = NativeModule.FindObjectsFinal, SignInit = NativeModule.SignInit, Sign = NativeModule.Sign,
            DeriveKey = NativeModule.DeriveKey, DestroyObject = NativeModule.DestroyObject, Count = NativeModule.FunctionCount;
    }

    /// <summary>Serialises every call into this module (see the remarks of <see cref="Pkcs11Session"/>).</summary>
    internal object CallGate { get; } = new();

    /// <summary>True when this process can talk to a module: a 64-bit Unix platform.</summary>
    internal static bool Supported => !OperatingSystem.IsWindows() && nuint.Size == 8;

    /// <summary>Loads (or shares the already loaded copy of) the module at <paramref name="path"/> and initialises it once per process.</summary>
    internal static NativeModule Acquire(string path)
    {
        if (!Supported)
        {
            throw new Pkcs11ModuleException("PKCS #11 modules are supported on 64-bit macOS and Linux only.", modulePath: path);
        }

        string key = path.Contains('/') ? Path.GetFullPath(path) : path;
        lock (Gate)
        {
            if (Loaded.TryGetValue(key, out NativeModule? have))
            {
                have._references++;
                return have;
            }

            if (key.Contains('/') && !File.Exists(key))
            {
                throw new Pkcs11ModuleException($"The PKCS #11 module '{path}' does not exist.", modulePath: path);
            }

            if (!NativeLibrary.TryLoad(key, out nint lib))
            {
                throw new Pkcs11ModuleException($"The PKCS #11 module '{path}' could not be loaded (wrong architecture, or a library it needs is missing).", modulePath: path);
            }

            try
            {
                if (!NativeLibrary.TryGetExport(lib, "C_GetFunctionList", out nint export))
                {
                    throw new Pkcs11ModuleException($"'{path}' is not a PKCS #11 module: it has no C_GetFunctionList.", modulePath: path);
                }

                nint list;
                nuint rv = ((delegate* unmanaged[Cdecl]<nint*, nuint>)export)(&list);
                if (rv != 0 || list == 0)
                {
                    throw new Pkcs11ModuleException($"C_GetFunctionList failed: {Pkcs11Errors.Name(rv)}.", "C_GetFunctionList", unchecked((uint)rv), path);
                }

                // CK_VERSION is two octets; the first pointer follows at the next pointer-aligned offset.
                nint* table = (nint*)((byte*)list + nint.Size);
                var f = new nint[FunctionCount];
                for (int i = 0; i < f.Length; i++)
                {
                    f[i] = table[i];
                }

                if (f[Initialize] == 0 || f[Sign] == 0 || f[Login] == 0)
                {
                    throw new Pkcs11ModuleException($"'{path}' does not provide the functions this backend needs.", modulePath: path);
                }

                // §5.4.1 (C_Initialize): with CKF_OS_LOCKING_THREADS the module locks with the operating system's primitives, so several threads may call it.
                byte* args = stackalloc byte[48]; // CK_C_INITIALIZE_ARGS: four mutex pointers, flags, reserved: 6 x 8 octets
                new Span<byte>(args, 48).Clear();
                *(nuint*)(args + 32) = 0x2;
                nuint irv = ((delegate* unmanaged[Cdecl]<void*, nuint>)f[Initialize])(args);
                bool owns = true;
                if (irv == (nuint)Pkcs11Result.CryptokiAlreadyInitialized)
                {
                    owns = false; // another component of this process initialised it; it is not ours to finalise
                }
                else if (irv != 0)
                {
                    throw new Pkcs11ModuleException($"C_Initialize failed in '{path}': {Pkcs11Errors.Name(irv)}.", "C_Initialize", unchecked((uint)irv), path);
                }

                var m = new NativeModule(key, lib, f, owns) { _references = 1 };
                Loaded[key] = m;
                return m;
            }
            catch
            {
                NativeLibrary.Free(lib);
                throw;
            }
        }
    }

    /// <summary>Drops one reference; the last one finalises the module and unloads it.</summary>
    internal void Release()
    {
        lock (Gate)
        {
            if (_disposed || --_references > 0)
            {
                return;
            }

            _disposed = true;
            Loaded.Remove(_key);
            if (_ownsInitialize)
            {
                _ = ((delegate* unmanaged[Cdecl]<void*, nuint>)_f[Finalize])(null);
            }

            NativeLibrary.Free(_library);
        }
    }

    public void Dispose() => Release();

    internal nuint C_GetInfo(byte* info) => ((delegate* unmanaged[Cdecl]<byte*, nuint>)_f[GetInfo])(info);

    internal nuint C_GetSlotList(bool tokenPresent, nuint* slots, nuint* count) =>
        ((delegate* unmanaged[Cdecl]<byte, nuint*, nuint*, nuint>)_f[GetSlotList])(tokenPresent ? (byte)1 : (byte)0, slots, count);

    internal nuint C_GetSlotInfo(nuint slot, byte* info) => ((delegate* unmanaged[Cdecl]<nuint, byte*, nuint>)_f[GetSlotInfo])(slot, info);

    internal nuint C_GetTokenInfo(nuint slot, byte* info) => ((delegate* unmanaged[Cdecl]<nuint, byte*, nuint>)_f[GetTokenInfo])(slot, info);

    internal nuint C_GetMechanismList(nuint slot, nuint* list, nuint* count) =>
        ((delegate* unmanaged[Cdecl]<nuint, nuint*, nuint*, nuint>)_f[GetMechanismList])(slot, list, count);

    internal nuint C_GetMechanismInfo(nuint slot, nuint mechanism, byte* info) =>
        ((delegate* unmanaged[Cdecl]<nuint, nuint, byte*, nuint>)_f[GetMechanismInfo])(slot, mechanism, info);

    internal nuint C_OpenSession(nuint slot, nuint flags, nuint* session) =>
        ((delegate* unmanaged[Cdecl]<nuint, nuint, void*, void*, nuint*, nuint>)_f[OpenSession])(slot, flags, null, null, session);

    internal nuint C_CloseSession(nuint session) => ((delegate* unmanaged[Cdecl]<nuint, nuint>)_f[CloseSession])(session);

    internal nuint C_GetSessionInfo(nuint session, byte* info) => ((delegate* unmanaged[Cdecl]<nuint, byte*, nuint>)_f[GetSessionInfo])(session, info);

    internal nuint C_Login(nuint session, nuint userType, byte* pin, nuint length) =>
        ((delegate* unmanaged[Cdecl]<nuint, nuint, byte*, nuint, nuint>)_f[Login])(session, userType, pin, length);

    internal nuint C_Logout(nuint session) => ((delegate* unmanaged[Cdecl]<nuint, nuint>)_f[Logout])(session);

    internal nuint C_CreateObject(nuint session, CkAttribute* template, nuint count, nuint* handle) =>
        ((delegate* unmanaged[Cdecl]<nuint, CkAttribute*, nuint, nuint*, nuint>)_f[CreateObject])(session, template, count, handle);

    internal nuint C_DestroyObject(nuint session, nuint handle) => ((delegate* unmanaged[Cdecl]<nuint, nuint, nuint>)_f[DestroyObject])(session, handle);

    internal nuint C_GetAttributeValue(nuint session, nuint handle, CkAttribute* template, nuint count) =>
        ((delegate* unmanaged[Cdecl]<nuint, nuint, CkAttribute*, nuint, nuint>)_f[GetAttributeValue])(session, handle, template, count);

    internal nuint C_SetAttributeValue(nuint session, nuint handle, CkAttribute* template, nuint count) =>
        ((delegate* unmanaged[Cdecl]<nuint, nuint, CkAttribute*, nuint, nuint>)_f[SetAttributeValue])(session, handle, template, count);

    internal nuint C_FindObjectsInit(nuint session, CkAttribute* template, nuint count) =>
        ((delegate* unmanaged[Cdecl]<nuint, CkAttribute*, nuint, nuint>)_f[FindObjectsInit])(session, template, count);

    internal nuint C_FindObjects(nuint session, nuint* handles, nuint max, nuint* found) =>
        ((delegate* unmanaged[Cdecl]<nuint, nuint*, nuint, nuint*, nuint>)_f[FindObjects])(session, handles, max, found);

    internal nuint C_FindObjectsFinal(nuint session) => ((delegate* unmanaged[Cdecl]<nuint, nuint>)_f[FindObjectsFinal])(session);

    internal nuint C_DecryptInit(nuint session, CkMechanism* mechanism, nuint key) =>
        ((delegate* unmanaged[Cdecl]<nuint, CkMechanism*, nuint, nuint>)_f[DecryptInit])(session, mechanism, key);

    internal nuint C_Decrypt(nuint session, byte* input, nuint inputLength, byte* output, nuint* outputLength) =>
        ((delegate* unmanaged[Cdecl]<nuint, byte*, nuint, byte*, nuint*, nuint>)_f[Decrypt])(session, input, inputLength, output, outputLength);

    internal nuint C_SignInit(nuint session, CkMechanism* mechanism, nuint key) =>
        ((delegate* unmanaged[Cdecl]<nuint, CkMechanism*, nuint, nuint>)_f[SignInit])(session, mechanism, key);

    internal nuint C_Sign(nuint session, byte* data, nuint dataLength, byte* signature, nuint* signatureLength) =>
        ((delegate* unmanaged[Cdecl]<nuint, byte*, nuint, byte*, nuint*, nuint>)_f[Sign])(session, data, dataLength, signature, signatureLength);

    internal nuint C_GenerateKeyPair(nuint session, CkMechanism* mechanism, CkAttribute* publicTemplate, nuint publicCount, CkAttribute* privateTemplate, nuint privateCount, nuint* publicKey, nuint* privateKey) =>
        ((delegate* unmanaged[Cdecl]<nuint, CkMechanism*, CkAttribute*, nuint, CkAttribute*, nuint, nuint*, nuint*, nuint>)_f[GenerateKeyPair])(session, mechanism, publicTemplate, publicCount, privateTemplate, privateCount, publicKey, privateKey);

    internal nuint C_DeriveKey(nuint session, CkMechanism* mechanism, nuint baseKey, CkAttribute* template, nuint count, nuint* newKey) =>
        ((delegate* unmanaged[Cdecl]<nuint, CkMechanism*, nuint, CkAttribute*, nuint, nuint*, nuint>)_f[DeriveKey])(session, mechanism, baseKey, template, count, newKey);

    internal nuint C_CloseAllSessions(nuint slot) => ((delegate* unmanaged[Cdecl]<nuint, nuint>)_f[CloseAllSessions])(slot);
}
