using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Keys.Pkcs11;

/// <summary>
/// A private key that stays on a PKCS #11 token. Signing, decryption and agreement run in the token; hashing, DigestInfo and signature encodings
/// are done here, with the same results as the in-memory keys. Disposing does nothing: the key belongs to its <see cref="Pkcs11Session"/>, and
/// closing the session (or the module) is what ends its use. The key works while its session is open and logged in; removing the object from the
/// token makes the next call a <see cref="Pkcs11KeyException"/>.
/// </summary>
public abstract class Pkcs11Key : IKey
{
    private readonly bool _canSign;
    private readonly bool _canOther;
    private readonly bool _alwaysAuthenticate;

    internal Pkcs11Key(Pkcs11Session session, nuint handle, string label, byte[] id, PublicKeyInfo publicKey, bool canSign, bool canOther, bool alwaysAuthenticate)
    {
        Session = session;
        Handle = handle;
        Label = label;
        Id = id;
        PublicKey = publicKey;
        _canSign = canSign;
        _canOther = canOther;
        _alwaysAuthenticate = alwaysAuthenticate;
    }

    /// <summary>The session the key lives in.</summary>
    public Pkcs11Session Session { get; }

    /// <summary>The object handle (CK_OBJECT_HANDLE) in <see cref="Session"/>.</summary>
    public ulong Handle { get; }

    /// <summary>CKA_LABEL, or empty.</summary>
    public string Label { get; }

    /// <summary>CKA_ID, or empty.</summary>
    public ReadOnlyMemory<byte> Id { get; }

    /// <inheritdoc/>
    public PublicKeyInfo PublicKey { get; }

    /// <inheritdoc/>
    public abstract KeyCapabilities Capabilities { get; }

    internal bool CanSign => _canSign;

    internal bool CanOther => _canOther;

    /// <summary>Nothing to release: see the class remarks.</summary>
    public void Dispose() => GC.SuppressFinalize(this);

    // §5.13: a key with CKA_ALWAYS_AUTHENTICATE needs a C_Login(CKU_CONTEXT_SPECIFIC) after every C_SignInit; that needs the PIN again, which the
    // library never keeps. It is refused rather than left to fail inside the token.
    internal void RequireNoReauthentication()
    {
        if (_alwaysAuthenticate)
        {
            throw new Pkcs11KeyException("The key asks for authentication before every use (CKA_ALWAYS_AUTHENTICATE); this backend does not support that.", "C_SignInit");
        }
    }

    internal string Describe() => $"token '{Session.Slot.GetTokenInfo().Label}' of module {Session.Slot.Module.Path}";

    internal AlgorithmNotSupportedException Unsupported(string what, ulong mechanism) =>
        new($"{what} (PKCS #11 mechanism 0x{mechanism:X})", Describe(), "the token does not list the mechanism");

    internal static void RequireHash(HashAlgorithmName hash)
    {
        if (HashInfo.Of(hash) is null)
        {
            throw new NotSupportedException($"The hash {hash.Name} is not offered for token signatures (SHA-1, SHA-256, SHA-384, SHA-512).");
        }
    }
}

/// <summary>The hash facts RSA and ECDSA token signatures need.</summary>
internal sealed record HashInfo(int Size, ulong Mechanism, ulong Mgf, byte[] DigestInfoPrefix)
{
    internal static HashInfo? Of(HashAlgorithmName name) => name.Name switch
    {
        "SHA1" => new(20, 0x220, 0x1, [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14]),
        "SHA256" => new(32, 0x250, 0x2, [0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
        "SHA384" => new(48, 0x260, 0x3, [0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
        "SHA512" => new(64, 0x270, 0x4, [0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
        _ => null,
    };
}

/// <summary>An RSA private key on a token: PKCS #1 v1.5 and PSS signatures, PKCS #1 v1.5 and OAEP decryption (CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_RSA_PKCS_OAEP).</summary>
public sealed class Pkcs11RsaKey : Pkcs11Key, IRsaKey
{
    private const ulong RsaPkcs = 0x1, RsaPkcsOaep = 0x9, RsaPkcsPss = 0xD;

    internal Pkcs11RsaKey(Pkcs11Session session, nuint handle, string label, byte[] id, PublicKeyInfo pub, bool canSign, bool canDecrypt, bool always)
        : base(session, handle, label, id, pub, canSign, canDecrypt, always)
    {
    }

    /// <inheritdoc/>
    public override KeyCapabilities Capabilities => (CanSign ? KeyCapabilities.Sign : 0) | (CanOther ? KeyCapabilities.Decrypt : 0);

    /// <inheritdoc/>
    public SignatureSpec DefaultSpec => SignatureSpec.DefaultFor(PublicKey);

    /// <inheritdoc/>
    public bool Supports(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (!CanSign || !spec.FitsKey(PublicKey) || HashInfo.Of(spec.Hash) is null)
        {
            return false;
        }

        return spec.Kind switch
        {
            SignatureKind.RsaPkcs1 => Session.HasMechanism(RsaPkcs),
            SignatureKind.RsaPss => Session.HasMechanism(RsaPkcsPss),
            _ => false,
        };
    }

    /// <inheritdoc/>
    public bool Supports(DecryptionSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return CanOther && spec.Kind switch
        {
            DecryptionKind.RsaPkcs1 => Session.HasMechanism(RsaPkcs),
            DecryptionKind.RsaOaep => HashInfo.Of(spec.Hash) is not null && Session.HasMechanism(RsaPkcsOaep),
            _ => false,
        };
    }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (!spec.SignsDigest)
        {
            throw new NotSupportedException("An RSA key signs RSA specs only.");
        }

        RequireHash(spec.Hash);
        return SignDigest(CryptographicOperations.HashData(spec.Hash, data), spec);
    }

    /// <inheritdoc/>
    public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.Kind is not (SignatureKind.RsaPkcs1 or SignatureKind.RsaPss) || !spec.FitsKey(PublicKey) || !CanSign)
        {
            throw new NotSupportedException($"The key cannot sign {spec}.");
        }

        RequireHash(spec.Hash);
        HashInfo h = HashInfo.Of(spec.Hash)!;
        if (digest.Length != h.Size)
        {
            throw new ArgumentException($"A {spec.Hash.Name} digest is {h.Size} octets.", nameof(digest));
        }

        RequireNoReauthentication();
        int k = (PublicKey.KeySizeBits + 7) / 8;
        if (spec.Kind == SignatureKind.RsaPkcs1)
        {
            // RFC 8017 §9.2: the token pads the DigestInfo (CKM_RSA_PKCS signs what it is given, §6.1.14), so the DigestInfo is built here.
            if (!Session.HasMechanism(RsaPkcs))
            {
                throw Unsupported("RSASSA-PKCS1-v1_5", RsaPkcs);
            }

            byte[] input = [.. h.DigestInfoPrefix, .. digest];
            return Session.Run(() => Raw.Sign(Session.Module, Session.Handle, (nuint)Handle, (nuint)RsaPkcs, null, input, k));
        }

        if (!Session.HasMechanism(RsaPkcsPss))
        {
            throw Unsupported("RSASSA-PSS", RsaPkcsPss);
        }

        // §6.1.9 CK_RSA_PKCS_PSS_PARAMS: hashAlg, mgf, sLen. The salt is as long as the digest (RFC 8017 §9.1, RFC 4055 §3.1).
        byte[] param = new byte[3 * nuint.Size];
        WriteNative(param, 0, h.Mechanism);
        WriteNative(param, 8, h.Mgf);
        WriteNative(param, 16, (ulong)h.Size);

        byte[] digestCopy = digest.ToArray();
        return Session.Run(() => Raw.Sign(Session.Module, Session.Handle, (nuint)Handle, (nuint)RsaPkcsPss, param, digestCopy, k));
    }

    /// <inheritdoc/>
    /// <remarks>
    /// A failed decryption is a plain <see cref="CryptographicException"/> that says nothing about why (RFC 8017 §7.2.2). A token reports failure on
    /// its own terms, so a caller that returns the outcome of PKCS #1 v1.5 decryption to an untrusted party gives that party an oracle (RFC 8017 §7.2 note); the library's
    /// CMS and OpenPGP code does not.
    /// </remarks>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, DecryptionSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (!Supports(spec))
        {
            if (spec.Kind is DecryptionKind.RsaPkcs1 or DecryptionKind.RsaOaep && CanOther)
            {
                throw Unsupported(spec.ToString(), spec.Kind == DecryptionKind.RsaOaep ? RsaPkcsOaep : RsaPkcs);
            }

            throw new NotSupportedException($"The key cannot decrypt {spec}.");
        }

        RequireNoReauthentication();
        int k = (PublicKey.KeySizeBits + 7) / 8;
        byte[]? param = null;
        ulong mech = RsaPkcs;
        if (spec.Kind == DecryptionKind.RsaOaep)
        {
            // §6.1.7 CK_RSA_PKCS_OAEP_PARAMS: hashAlg, mgf, source (CKZ_DATA_SPECIFIED), pSourceData, ulSourceDataLen; the label is empty (RFC 8017 §7.1).
            HashInfo h = HashInfo.Of(spec.Hash)!;
            mech = RsaPkcsOaep;
            param = new byte[5 * nuint.Size];
            WriteNative(param, 0, h.Mechanism);
            WriteNative(param, 8, h.Mgf);
            WriteNative(param, 16, 1);
        }

        byte[] ct = ciphertext.ToArray();
        try
        {
            return Session.Run(() => Raw.Decrypt(Session.Module, Session.Handle, (nuint)Handle, (nuint)mech, param, ct, k));
        }
        catch (Pkcs11Exception e) when (e.Function == "C_Decrypt" && e is not (Pkcs11TokenException or Pkcs11PinException or Pkcs11KeyException))
        {
            throw new CryptographicException("The ciphertext did not decrypt.");
        }
    }

    // CK_ULONG fields are in the host byte order (the module is a native library of this process).
    internal static void WriteNative(byte[] buffer, int offset, ulong value)
    {
        if (BitConverter.IsLittleEndian)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(offset), value);
        }
        else
        {
            BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(offset), value);
        }
    }
}

/// <summary>An EC private key on a token: ECDSA signatures (CKM_ECDSA, over a digest computed here) and ECDH agreement (CKM_ECDH1_DERIVE).</summary>
public sealed class Pkcs11EcKey : Pkcs11Key, ISigningKey, IAgreementKey
{
    private const ulong Ecdsa = 0x1041, Ecdh1Derive = 0x1050;

    internal Pkcs11EcKey(Pkcs11Session session, nuint handle, string label, byte[] id, PublicKeyInfo pub, bool canSign, bool canDerive, bool always)
        : base(session, handle, label, id, pub, canSign, canDerive, always)
    {
    }

    /// <inheritdoc/>
    public override KeyCapabilities Capabilities => (CanSign ? KeyCapabilities.Sign : 0) | (CanOther ? KeyCapabilities.Agree : 0);

    /// <inheritdoc/>
    public SignatureSpec DefaultSpec => SignatureSpec.DefaultFor(PublicKey);

    /// <inheritdoc/>
    public bool Supports(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return CanSign && spec.Kind == SignatureKind.Ecdsa && spec.FitsKey(PublicKey) && HashInfo.Of(spec.Hash) is not null && Session.HasMechanism(Ecdsa);
    }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.Kind != SignatureKind.Ecdsa)
        {
            throw new NotSupportedException("An EC key signs ECDSA specs only.");
        }

        RequireHash(spec.Hash);
        return SignDigest(CryptographicOperations.HashData(spec.Hash, data), spec);
    }

    /// <inheritdoc/>
    public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.Kind != SignatureKind.Ecdsa || !spec.FitsKey(PublicKey) || !CanSign)
        {
            throw new NotSupportedException($"The key cannot sign {spec}.");
        }

        RequireHash(spec.Hash);
        HashInfo h = HashInfo.Of(spec.Hash)!;
        if (digest.Length != h.Size)
        {
            throw new ArgumentException($"A {spec.Hash.Name} digest is {h.Size} octets.", nameof(digest));
        }

        if (!Session.HasMechanism(Ecdsa))
        {
            throw Unsupported("ECDSA", Ecdsa);
        }

        RequireNoReauthentication();
        int size = (PublicKey.KeySizeBits + 7) / 8;
        byte[] d = digest.ToArray();
        // §6.3.12 CKM_ECDSA: the token signs the digest as given and returns r || s, each as wide as the curve's order (RFC 4754 / IEEE P1363).
        byte[] raw = Session.Run(() => Raw.Sign(Session.Module, Session.Handle, (nuint)Handle, (nuint)Ecdsa, null, d, 2 * size));
        if (raw.Length != 2 * size)
        {
            throw new Pkcs11Exception($"The token returned an ECDSA signature of {raw.Length} octets; {2 * size} were expected.", "C_Sign");
        }

        return spec.Format == EcdsaSignatureFormat.Rfc4754 ? raw : DerWriter.Sequence(DerWriter.UnsignedInteger(raw.AsSpan(0, size)), DerWriter.UnsignedInteger(raw.AsSpan(size)));
    }

    /// <inheritdoc/>
    public byte[] Agree(PublicKeyInfo peer)
    {
        ArgumentNullException.ThrowIfNull(peer);
        if (!CanOther)
        {
            throw new NotSupportedException("The key is not allowed to derive (CKA_DERIVE is false).");
        }

        if (peer.KeyAlgorithm != KeyAlgorithm.EllipticCurve || peer.CurveOid is null || peer.CurveOid != PublicKey.CurveOid)
        {
            throw new ArgumentException("The peer's key is not an EC key on the same curve.", nameof(peer));
        }

        int size = (PublicKey.KeySizeBits + 7) / 8;
        ReadOnlySpan<byte> point = peer.KeyBits.Span;
        if (point.Length != 1 + (2 * size) || point[0] != 4)
        {
            throw new ArgumentException("The peer's point must be an uncompressed point (SEC 1 §2.3.3) of the key's curve.", nameof(peer));
        }

        if (!Session.HasMechanism(Ecdh1Derive))
        {
            throw Unsupported("ECDH", Ecdh1Derive);
        }

        RequireNoReauthentication();
        byte[] p = point.ToArray();
        // §6.3.17: with CKD_NULL the derived value is the x-coordinate. v3.1 takes the peer's point raw (uncompressed) or as a DER OCTET STRING.
        // Modules that only read the older DER form refuse the raw one with a parameter error; that case is retried once.
        try
        {
            return Session.Run(() => Raw.DeriveEcdh(Session.Module, Session.Handle, (nuint)Handle, p, size));
        }
        catch (Pkcs11Exception e) when (e.Result is Pkcs11Result.MechanismParamInvalid or Pkcs11Result.ArgumentsBad or Pkcs11Result.FunctionFailed)
        {
            byte[] der = DerWriter.OctetString(p);
            return Session.Run(() => Raw.DeriveEcdh(Session.Module, Session.Handle, (nuint)Handle, der, size));
        }
    }
}

/// <summary>An Ed25519 or Ed448 private key on a token (CKM_EDDSA): pure EdDSA over the message, as RFC 8032 defines it.</summary>
public sealed class Pkcs11EdKey : Pkcs11Key, ISigningKey
{
    private const ulong Eddsa = 0x1057;

    internal Pkcs11EdKey(Pkcs11Session session, nuint handle, string label, byte[] id, PublicKeyInfo pub, bool canSign, bool always)
        : base(session, handle, label, id, pub, canSign, false, always)
    {
    }

    /// <inheritdoc/>
    public override KeyCapabilities Capabilities => CanSign ? KeyCapabilities.Sign : KeyCapabilities.None;

    /// <inheritdoc/>
    public SignatureSpec DefaultSpec => SignatureSpec.DefaultFor(PublicKey);

    /// <inheritdoc/>
    public bool Supports(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return CanSign && spec.Kind is SignatureKind.Ed25519 or SignatureKind.Ed448 && spec.FitsKey(PublicKey) && Session.HasMechanism(Eddsa);
    }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.Kind is not (SignatureKind.Ed25519 or SignatureKind.Ed448) || !spec.FitsKey(PublicKey) || !CanSign)
        {
            throw new NotSupportedException($"The key cannot sign {spec}.");
        }

        if (!Session.HasMechanism(Eddsa))
        {
            throw Unsupported(spec.Kind == SignatureKind.Ed25519 ? "Ed25519" : "Ed448", Eddsa);
        }

        RequireNoReauthentication();
        byte[] m = data.ToArray();
        byte[] context = spec.Context.ToArray();
        bool parameters = spec.Kind == SignatureKind.Ed448; // RFC 8032 §5.2: Ed448 always has a context, possibly empty
        int size = spec.Kind == SignatureKind.Ed25519 ? 64 : 114;
        return Session.Run(() => Raw.SignEddsa(Session.Module, Session.Handle, (nuint)Handle, m, context, parameters, size));
    }

    /// <inheritdoc/>
    public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec) => throw new NotSupportedException("EdDSA signs the message, not a digest.");
}
