using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Keys.Pkcs11;

/// <summary>The family of a private key object (CKA_KEY_TYPE, PKCS #11 v3.1 §6.1 onwards).</summary>
public enum Pkcs11KeyType
{
    /// <summary>A key type the library does not use (DSA, DH, symmetric and so on).</summary>
    Other,
    /// <summary>CKK_RSA.</summary>
    Rsa,
    /// <summary>CKK_EC: ECDSA and ECDH on a Weierstrass curve.</summary>
    EllipticCurve,
    /// <summary>CKK_EC_EDWARDS: Ed25519 and Ed448.</summary>
    EdwardsCurve,
    /// <summary>CKK_EC_MONTGOMERY: X25519 and X448 (listed, not usable through this backend yet).</summary>
    MontgomeryCurve,
}

/// <summary>A private key object found on a token, before it is opened as a key.</summary>
/// <param name="Handle">The object handle in the session that found it.</param>
/// <param name="Label">CKA_LABEL, or empty.</param>
/// <param name="Id">CKA_ID, or empty. Keys, certificates and public keys of one identity share it.</param>
/// <param name="KeyType">The family of the key.</param>
public sealed record Pkcs11KeyInfo(ulong Handle, string Label, ReadOnlyMemory<byte> Id, Pkcs11KeyType KeyType);

/// <summary>A certificate object found on a token.</summary>
/// <param name="Handle">The object handle in the session that found it.</param>
/// <param name="Label">CKA_LABEL, or empty.</param>
/// <param name="Id">CKA_ID, or empty: the same value as the key it belongs to.</param>
/// <param name="Certificate">The certificate (CKA_VALUE).</param>
public sealed record Pkcs11CertificateInfo(ulong Handle, string Label, ReadOnlyMemory<byte> Id, Certificate Certificate);

/// <summary>What <see cref="Pkcs11Session.GenerateKeyPair"/> makes on the token.</summary>
public sealed class Pkcs11KeyPairSpec
{
    private Pkcs11KeyPairSpec(Pkcs11KeyType type, int rsaBits, string curveOid)
    {
        KeyType = type;
        RsaBits = rsaBits;
        CurveOid = curveOid;
    }

    /// <summary>The family.</summary>
    public Pkcs11KeyType KeyType { get; }

    /// <summary>The RSA modulus size in bits; 0 for the curve families.</summary>
    public int RsaBits { get; }

    /// <summary>The dotted curve identifier; empty for RSA.</summary>
    public string CurveOid { get; }

    /// <summary>An RSA key pair (CKM_RSA_PKCS_KEY_PAIR_GEN), public exponent 65537.</summary>
    /// <param name="bits">The modulus size; at least 2048.</param>
    public static Pkcs11KeyPairSpec Rsa(int bits = 3072) => bits >= 2048 ? new(Pkcs11KeyType.Rsa, bits, string.Empty) : throw new ArgumentOutOfRangeException(nameof(bits), "RSA keys of fewer than 2048 bits are not generated.");

    /// <summary>An EC key pair on NIST P-256 (CKM_EC_KEY_PAIR_GEN); it signs (ECDSA) and agrees (ECDH).</summary>
    public static Pkcs11KeyPairSpec P256() => new(Pkcs11KeyType.EllipticCurve, 0, "1.2.840.10045.3.1.7");

    /// <summary>An EC key pair on NIST P-384.</summary>
    public static Pkcs11KeyPairSpec P384() => new(Pkcs11KeyType.EllipticCurve, 0, "1.3.132.0.34");

    /// <summary>An EC key pair on NIST P-521.</summary>
    public static Pkcs11KeyPairSpec P521() => new(Pkcs11KeyType.EllipticCurve, 0, "1.3.132.0.35");

    /// <summary>An Ed25519 key pair (CKM_EC_EDWARDS_KEY_PAIR_GEN), for tokens that have it.</summary>
    public static Pkcs11KeyPairSpec Ed25519() => new(Pkcs11KeyType.EdwardsCurve, 0, "1.3.101.112");
}

/// <summary>
/// A session with a token (C_OpenSession, PKCS #11 v3.1 §5.6): login, object lookup and the private-key operations. Sessions serve any number of
/// threads: calls into one module are serialised, because a session holds one operation at a time (§5.2) and because modules do not all stand up to
/// calls from several sessions at once (SoftHSM2 failed key generation with CKR_GENERAL_ERROR when sessions ran in parallel). A token is one device with one
/// pipe in any case; the cost is that two threads never sign at the same moment.
/// </summary>
/// <remarks>
/// The user PIN is never kept: <see cref="Login(ReadOnlySpan{char})"/> passes it to the token and wipes its copy. A key found in a session is valid
/// while the session is open and logged in.
/// </remarks>
public sealed class Pkcs11Session : IDisposable
{
    private const nuint ClassPrivateKey = 3, ClassPublicKey = 2, ClassCertificate = 1;

    private readonly object _gate;
    private readonly nuint _handle;
    private bool _disposed;

    private Pkcs11Session(Pkcs11Slot slot, nuint handle, bool readWrite)
    {
        Slot = slot;
        _gate = slot.Module.Native.CallGate;
        _handle = handle;
        ReadWrite = readWrite;
    }

    /// <summary>The slot the session is on.</summary>
    public Pkcs11Slot Slot { get; }

    /// <summary>True for a read/write session.</summary>
    public bool ReadWrite { get; }

    /// <summary>
    /// True while the user is logged in on the token (C_GetSessionInfo, §5.6: the login state belongs to the token, so a login or logout in any
    /// session of this application shows in all of them).
    /// </summary>
    public bool IsLoggedIn
    {
        get
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    return false;
                }

                // CK_SESSION_INFO.state: CKS_RO_USER_FUNCTIONS 1, CKS_RW_USER_FUNCTIONS 3, CKS_RW_SO_FUNCTIONS 4.
                nuint state = System.Runtime.InteropServices.MemoryMarshal.Read<nuint>(Raw.GetSessionInfo(Native, _handle).AsSpan(8));
                return state is 1 or 3 or 4;
            }
        }
    }

    internal NativeModule Native => Slot.Module.Native;

    internal static Pkcs11Session Open(Pkcs11Slot slot, bool readWrite)
    {
        // CKF_SERIAL_SESSION is required (§5.6); CKF_RW_SESSION asks for write access.
        nuint h = Raw.OpenSession(slot.Module.Native, (nuint)slot.Id, readWrite ? (nuint)6 : 4);
        var s = new Pkcs11Session(slot, h, readWrite);
        slot.Module.Register(s);
        return s;
    }

    /// <summary>
    /// Logs the user in (C_Login with CKU_USER, §5.6). The PIN is sent as UTF-8 and the library's copy is wiped. A wrong PIN is a
    /// <see cref="Pkcs11PinException"/>; a locked token a <see cref="Pkcs11PinLockedException"/>. Logging in twice is not an error.
    /// </summary>
    /// <param name="pin">The user PIN; not empty (an empty value would ask for the protected authentication path, which has its own method).</param>
    /// <exception cref="ArgumentException">The PIN is empty.</exception>
    /// <exception cref="Pkcs11PinException">The token refused the PIN.</exception>
    public void Login(ReadOnlySpan<char> pin)
    {
        if (pin.IsEmpty)
        {
            throw new ArgumentException("The PIN is empty. For a token with its own PIN pad use LoginProtectedAuthenticationPath.", nameof(pin));
        }

        byte[] bytes = GC.AllocateUninitializedArray<byte>(Encoding.UTF8.GetMaxByteCount(pin.Length), pinned: true);
        try
        {
            int n = Encoding.UTF8.GetBytes(pin, bytes);
            byte[] exact = GC.AllocateUninitializedArray<byte>(n, pinned: true);
            try
            {
                bytes.AsSpan(0, n).CopyTo(exact);
                DoLogin(exact);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(exact);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Logs the user in through the token's own PIN entry (C_Login with no PIN, §5.6, for tokens with CKF_PROTECTED_AUTHENTICATION_PATH): a pad or a
    /// prompt of the module's own. The call blocks until the user answers.
    /// </summary>
    /// <exception cref="Pkcs11PinException">The token has no protected authentication path, or the user did not enter a valid PIN.</exception>
    public void LoginProtectedAuthenticationPath()
    {
        if (!Slot.GetTokenInfo().ProtectedAuthenticationPath)
        {
            throw new Pkcs11PinException("The token has no protected authentication path; give the PIN to Login.");
        }

        DoLogin(null);
    }

    private void DoLogin(byte[]? pin)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            nuint rv = Raw.Login(Native, _handle, 1, pin);
            if (rv != (nuint)Pkcs11Result.UserAlreadyLoggedIn)
            {
                Raw.Check("C_Login", rv);
            }
        }
    }

    /// <summary>Logs out (C_Logout); private objects become invisible and keys opened in this session stop working.</summary>
    public void Logout()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            nuint rv = Native.C_Logout(_handle);
            if (rv != (nuint)Pkcs11Result.UserNotLoggedIn)
            {
                Raw.Check("C_Logout", rv);
            }

        }
    }

    /// <summary>Lists the private keys that match the label and ID (C_FindObjects, §5.7). Without a login, tokens that guard their private objects list none.</summary>
    /// <param name="label">CKA_LABEL to match, or null for any.</param>
    /// <param name="id">CKA_ID to match, or empty for any.</param>
    public IReadOnlyList<Pkcs11KeyInfo> FindPrivateKeys(string? label = null, ReadOnlySpan<byte> id = default)
    {
        Template t = Match(ClassPrivateKey, label, id);
        lock (_gate)
        {
            ThrowIfDisposed();
            var list = new List<Pkcs11KeyInfo>();
            foreach (nuint h in Raw.Find(Native, _handle, t))
            {
                list.Add(new Pkcs11KeyInfo(h, Text(h, 0x3), Bytes(h, 0x102), KeyTypeOf(h)));
            }

            return list;
        }
    }

    /// <summary>Lists the certificates that match the label and ID. Certificates that do not parse are skipped.</summary>
    public IReadOnlyList<Pkcs11CertificateInfo> FindCertificates(string? label = null, ReadOnlySpan<byte> id = default)
    {
        Template t = Match(ClassCertificate, label, id);
        lock (_gate)
        {
            ThrowIfDisposed();
            var list = new List<Pkcs11CertificateInfo>();
            foreach (nuint h in Raw.Find(Native, _handle, t))
            {
                byte[]? der = Raw.GetAttribute(Native, _handle, h, 0x11);
                if (der is not null && Certificate.TryParse(der, out Certificate? cert) && cert is not null)
                {
                    list.Add(new Pkcs11CertificateInfo(h, Text(h, 0x3), Bytes(h, 0x102), cert));
                }
            }

            return list;
        }
    }

    /// <summary>
    /// Opens the one private key that matches the label and ID as a key that signs, decrypts or agrees on the token. The public key comes from, in
    /// order: <paramref name="publicKey"/>; a public key object with the same CKA_ID; the RSA modulus and exponent on the private object; a certificate
    /// with the same CKA_ID. Nothing is checked against the private key; a wrong public key shows when a signature fails to verify.
    /// </summary>
    /// <param name="label">CKA_LABEL to match, or null.</param>
    /// <param name="id">CKA_ID to match, or empty. At least one of label and id is required.</param>
    /// <param name="publicKey">The public key, for a token that keeps none beside the private key.</param>
    /// <returns>A <see cref="Pkcs11RsaKey"/>, <see cref="Pkcs11EcKey"/> or <see cref="Pkcs11EdKey"/>.</returns>
    /// <exception cref="Pkcs11KeyException">No key, or more than one, matches; the key type is not supported; or no public key could be found.</exception>
    public Pkcs11Key OpenKey(string? label = null, ReadOnlySpan<byte> id = default, PublicKeyInfo? publicKey = null)
    {
        if (label is null && id.IsEmpty)
        {
            throw new ArgumentException("Give a label or an ID.");
        }

        Template t = Match(ClassPrivateKey, label, id);
        lock (_gate)
        {
            ThrowIfDisposed();
            nuint[] found = Raw.Find(Native, _handle, t);
            if (found.Length == 0)
            {
                throw new Pkcs11KeyException("No private key matches" + (IsLoggedInLocked() || !Slot.GetTokenInfo().LoginRequired ? "." : " (the session is not logged in, and the token hides private keys until it is)."), "C_FindObjects", (uint)Pkcs11Result.ObjectHandleInvalid);
            }

            if (found.Length > 1)
            {
                throw new Pkcs11KeyException($"{found.Length} private keys match; give a label and an ID that pick one.", "C_FindObjects");
            }

            nuint h = found[0];
            Pkcs11KeyType type = KeyTypeOf(h);
            byte[] keyId = Bytes(h, 0x102);
            string keyLabel = Text(h, 0x3);
            PublicKeyInfo pub = publicKey ?? ResolvePublicKey(h, type, keyId);
            bool canSign = Flag(h, 0x108), canDecrypt = Flag(h, 0x105), canDerive = Flag(h, 0x10C);
            bool always = Flag(h, 0x202, defaultValue: false);
            return type switch
            {
                Pkcs11KeyType.Rsa => new Pkcs11RsaKey(this, h, keyLabel, keyId, pub, canSign, canDecrypt, always),
                Pkcs11KeyType.EllipticCurve => new Pkcs11EcKey(this, h, keyLabel, keyId, pub, canSign, canDerive, always),
                Pkcs11KeyType.EdwardsCurve => new Pkcs11EdKey(this, h, keyLabel, keyId, pub, canSign, always),
                _ => throw new Pkcs11KeyException("The key is of a type this backend does not use (only RSA, EC and Edwards keys).", "C_GetAttributeValue"),
            };
        }
    }

    /// <summary>
    /// Makes a key pair on the token (C_GenerateKeyPair, §5.18). The private key stays on the token: sensitive, not extractable, usable for signing
    /// (and decryption for RSA, derivation for EC). Needs a read/write session and a login.
    /// </summary>
    /// <param name="spec">What to make.</param>
    /// <param name="label">CKA_LABEL for both objects.</param>
    /// <param name="id">CKA_ID for both objects; not empty.</param>
    /// <exception cref="Pkcs11Exception">The token refused (read-only session, no login, mechanism missing).</exception>
    public Pkcs11Key GenerateKeyPair(Pkcs11KeyPairSpec spec, string label, ReadOnlySpan<byte> id)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(label);
        if (id.IsEmpty)
        {
            throw new ArgumentException("An ID is required so the key can be found again.", nameof(id));
        }

        var pub = new Template().Bool(0x1, true).Bool(0x108 + 2, true).Text(0x3, label).Bytes(0x102, id);
        var priv = new Template().Bool(0x1, true).Bool(0x2, true).Bool(0x103, true).Bool(0x162, false).Bool(0x108, true).Text(0x3, label).Bytes(0x102, id);
        nuint mech;
        switch (spec.KeyType)
        {
            case Pkcs11KeyType.Rsa:
                mech = 0x0; // CKM_RSA_PKCS_KEY_PAIR_GEN
                pub.Ulong(0x121, (nuint)spec.RsaBits).Bytes(0x122, [0x01, 0x00, 0x01]).Bool(0x104, true);
                priv.Bool(0x105, true);
                break;
            case Pkcs11KeyType.EllipticCurve:
                mech = 0x1040; // CKM_EC_KEY_PAIR_GEN
                pub.Bytes(0x180, Pkcs11PublicKeys.OidDer(spec.CurveOid));
                priv.Bool(0x10C, true);
                break;
            default:
                mech = 0x1055; // CKM_EC_EDWARDS_KEY_PAIR_GEN
                pub.Bytes(0x180, Pkcs11PublicKeys.OidDer(spec.CurveOid));
                break;
        }

        lock (_gate)
        {
            ThrowIfDisposed();
            RequireMechanism(mech, "key pair generation");
            _ = Raw.GenerateKeyPair(Native, _handle, mech, pub, priv);
        }

        return OpenKey(label, id);
    }

    /// <summary>Stores a certificate on the token (C_CreateObject, §5.7), with the same ID as the key it belongs to. Needs a read/write session.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="label">CKA_LABEL.</param>
    /// <param name="id">CKA_ID; matches the key's.</param>
    public void ImportCertificate(Certificate certificate, string label, ReadOnlySpan<byte> id)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(label);
        var t = new Template().Ulong(0x0, ClassCertificate).Bool(0x1, true).Ulong(0x80, 0).Bytes(0x11, certificate.Encoded.Span)
            .Bytes(0x101, certificate.Subject.Encoded.Span).Text(0x3, label).Bytes(0x102, id);
        lock (_gate)
        {
            ThrowIfDisposed();
            _ = Raw.Create(Native, _handle, t);
        }
    }

    /// <summary>Removes a key's objects from the token: the private key, and the public key and certificate that share its ID (C_DestroyObject, §5.7). Needs a read/write session.</summary>
    /// <param name="key">The key to remove. Its handle is invalid afterwards.</param>
    public void Destroy(Pkcs11Key key)
    {
        ArgumentNullException.ThrowIfNull(key);
        lock (_gate)
        {
            ThrowIfDisposed();
            Raw.Check("C_DestroyObject", Native.C_DestroyObject(_handle, (nuint)key.Handle));
            if (key.Id.Length > 0)
            {
                foreach (nuint cls in new[] { ClassPublicKey, ClassCertificate })
                {
                    foreach (nuint h in Raw.Find(Native, _handle, Match(cls, null, key.Id.Span)))
                    {
                        _ = Native.C_DestroyObject(_handle, h);
                    }
                }
            }
        }
    }

    /// <summary>
    /// A raw one-shot signature with an explicit mechanism (C_SignInit and C_Sign, §5.13): the data goes to the token as given and the result is
    /// the token's output. For mechanisms the key interfaces do not cover; an unknown mechanism is a <see cref="Pkcs11MechanismException"/>.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="mechanism">The CKM_ number.</param>
    /// <param name="parameter">The mechanism's parameter structure as octets, or null. It must not contain pointers.</param>
    /// <param name="data">What to sign.</param>
    public byte[] SignRaw(Pkcs11Key key, ulong mechanism, byte[]? parameter, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(key);
        byte[] copy = data.ToArray();
        return Run(() => Raw.Sign(Native, _handle, (nuint)key.Handle, (nuint)mechanism, parameter, copy, 512));
    }

    /// <summary>Closes the session (C_CloseSession). Keys opened in it stop working.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _ = Native.C_CloseSession(_handle);
        }

        Slot.Module.Unregister(this);
    }

    // ---- used by the key classes ----

    internal T Run<T>(Func<T> operation)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            return operation();
        }
    }

    internal NativeModule Module => Native;

    internal nuint Handle => _handle;

    internal bool HasMechanism(ulong mechanism)
    {
        try
        {
            return Slot.GetMechanisms().Contains(mechanism);
        }
        catch (Pkcs11Exception)
        {
            return false;
        }
    }

    internal void RequireMechanism(ulong mechanism, string what)
    {
        if (!HasMechanism(mechanism))
        {
            throw new AlgorithmNotSupportedException($"PKCS #11 mechanism 0x{mechanism:X} ({what})", $"token '{TokenLabel()}' of module {Slot.Module.Path}", "the token does not list the mechanism");
        }
    }

    private string TokenLabel()
    {
        try
        {
            return Slot.GetTokenInfo().Label;
        }
        catch (Pkcs11Exception)
        {
            return "?";
        }
    }

    private bool IsLoggedInLocked() => System.Runtime.InteropServices.MemoryMarshal.Read<nuint>(Raw.GetSessionInfo(Native, _handle).AsSpan(8)) is 1 or 3 or 4;

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private static Template Match(nuint cls, string? label, ReadOnlySpan<byte> id)
    {
        Template t = new Template().Ulong(0x0, cls);
        if (label is not null)
        {
            t.Text(0x3, label);
        }

        if (!id.IsEmpty)
        {
            t.Bytes(0x102, id);
        }

        return t;
    }

    private string Text(nuint h, nuint type) => Encoding.UTF8.GetString(Raw.GetAttribute(Native, _handle, h, type) ?? []);

    private byte[] Bytes(nuint h, nuint type) => Raw.GetAttribute(Native, _handle, h, type) ?? [];

    private bool Flag(nuint h, nuint type, bool defaultValue = true)
    {
        byte[]? v = Raw.GetAttribute(Native, _handle, h, type);
        return v is { Length: 1 } ? v[0] != 0 : defaultValue;
    }

    private Pkcs11KeyType KeyTypeOf(nuint h)
    {
        byte[]? v = Raw.GetAttribute(Native, _handle, h, 0x100);
        if (v is null || v.Length != nuint.Size)
        {
            return Pkcs11KeyType.Other;
        }

        return (ulong)System.Runtime.InteropServices.MemoryMarshal.Read<nuint>(v) switch
        {
            0x0 => Pkcs11KeyType.Rsa,
            0x3 => Pkcs11KeyType.EllipticCurve,
            0x40 => Pkcs11KeyType.EdwardsCurve,
            0x41 => Pkcs11KeyType.MontgomeryCurve,
            _ => Pkcs11KeyType.Other,
        };
    }

    // Where the public key of a private key object comes from (see OpenKey). Called with the session lock held.
    private PublicKeyInfo ResolvePublicKey(nuint priv, Pkcs11KeyType type, byte[] id)
    {
        if (id.Length > 0)
        {
            foreach (nuint ph in Raw.Find(Native, _handle, Match(ClassPublicKey, null, id)))
            {
                PublicKeyInfo? fromPublic = Pkcs11PublicKeys.FromObject(type, Raw.GetAttribute(Native, _handle, ph, 0x120), Raw.GetAttribute(Native, _handle, ph, 0x122), Raw.GetAttribute(Native, _handle, ph, 0x180), Raw.GetAttribute(Native, _handle, ph, 0x181));
                if (fromPublic is not null)
                {
                    return fromPublic;
                }
            }
        }

        PublicKeyInfo? own = Pkcs11PublicKeys.FromObject(type, Raw.GetAttribute(Native, _handle, priv, 0x120), Raw.GetAttribute(Native, _handle, priv, 0x122), Raw.GetAttribute(Native, _handle, priv, 0x180), Raw.GetAttribute(Native, _handle, priv, 0x181));
        if (own is not null)
        {
            return own;
        }

        if (id.Length > 0)
        {
            foreach (nuint ch in Raw.Find(Native, _handle, Match(ClassCertificate, null, id)))
            {
                byte[]? der = Raw.GetAttribute(Native, _handle, ch, 0x11);
                if (der is not null && Certificate.TryParse(der, out Certificate? c) && c is not null)
                {
                    return c.PublicKey;
                }
            }
        }

        throw new Pkcs11KeyException("The token holds no public key or certificate for this private key; pass the public key to OpenKey.", "C_FindObjects");
    }
}
