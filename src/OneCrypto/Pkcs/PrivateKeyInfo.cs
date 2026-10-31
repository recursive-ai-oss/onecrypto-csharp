using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.Pkcs;

/// <summary>
/// A private key in the PKCS#8 <c>PrivateKeyInfo</c> / <c>OneAsymmetricKey</c> container (RFC 5208, RFC 5958). The encoding is kept as
/// received in a pinned buffer that is zeroed on <see cref="Dispose"/>; nothing is re-encoded when the key is read back.
/// </summary>
/// <remarks>
/// Algorithm-specific key structures are not decoded here: <see cref="PrivateKey"/> is the content of the inner OCTET STRING (an
/// RSAPrivateKey, an ECPrivateKey, a CurvePrivateKey, an ML-DSA or ML-KEM private key). The <c>To…</c> methods hand the key to the
/// platform or to this library's own key types.
/// </remarks>
public sealed class PrivateKeyInfo : IDisposable
{
    private readonly PinnedSecret _encoded;
    private readonly int _keyOffset;
    private readonly int _keyLength;
    private readonly byte[] _publicKeyBits;
    private readonly byte[][] _attributes;

    private PrivateKeyInfo(PinnedSecret encoded, int version, AlgorithmIdentifier algorithm, int keyOffset, int keyLength, byte[] publicKeyBits, byte[][] attributes)
    {
        _encoded = encoded;
        Version = version;
        Algorithm = algorithm;
        KeyAlgorithm = PublicKeyInfo.Classify(algorithm.Oid);
        _keyOffset = keyOffset;
        _keyLength = keyLength;
        _publicKeyBits = publicKeyBits;
        _attributes = attributes;
    }

    /// <summary>0 for PrivateKeyInfo (version v1), 1 for OneAsymmetricKey (v2, which may carry the public key).</summary>
    public int Version { get; }

    /// <summary>The <c>privateKeyAlgorithm</c>.</summary>
    public AlgorithmIdentifier Algorithm { get; }

    /// <summary>The key family derived from <see cref="Algorithm"/>; <see cref="Algorithm"/> for the exact identifier.</summary>
    public KeyAlgorithm KeyAlgorithm { get; }

    /// <summary>The content of the inner <c>privateKey</c> OCTET STRING. Valid until <see cref="Dispose"/>.</summary>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public ReadOnlySpan<byte> PrivateKey => _encoded.ReadOnlySpan.Slice(_keyOffset, _keyLength);

    /// <summary>The whole encoding as received. Valid until <see cref="Dispose"/>.</summary>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public ReadOnlySpan<byte> Encoded => _encoded.ReadOnlySpan;

    /// <summary>The <c>publicKey</c> BIT STRING of a version 2 key (the bytes, without the unused-bits octet); empty when absent.</summary>
    public ReadOnlyMemory<byte> PublicKeyBits => _publicKeyBits;

    /// <summary>The encoded <c>Attribute</c> elements of the <c>attributes</c> field, in order.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Attributes => Array.ConvertAll(_attributes, a => (ReadOnlyMemory<byte>)a);

    /// <summary>The curve OID of an EC key, or null.</summary>
    public string? CurveOid => KeyAlgorithm == KeyAlgorithm.EllipticCurve && !Algorithm.Parameters.IsEmpty && new Asn1Reader(Algorithm.Parameters.Span, Asn1Rules.Ber).TryReadObjectIdentifier(out string oid) ? oid : null;

    /// <summary>A copy of the encoding. The caller owns the copy and should zero it.</summary>
    public byte[] ExportEncoded() => _encoded.ReadOnlySpan.ToArray();

    /// <summary>Zeroes the key material.</summary>
    public void Dispose() => _encoded.Dispose();

    // ---- parsing ----

    /// <summary>Reads a PrivateKeyInfo or OneAsymmetricKey (BER is accepted; the bytes are kept as received).</summary>
    /// <param name="encoded">The encoding. The caller keeps ownership of the span and should zero it if it holds a secret.</param>
    /// <param name="limits">Limits; null for <see cref="PkcsLimits.Default"/>.</param>
    /// <exception cref="PkcsParseException">The input is not a PrivateKeyInfo.</exception>
    public static PrivateKeyInfo Parse(ReadOnlySpan<byte> encoded, PkcsLimits? limits = null) => Adopt(new PinnedSecret(encoded), limits ?? PkcsLimits.Default);

    /// <summary>Reads a PrivateKeyInfo, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlySpan<byte> encoded, out PrivateKeyInfo? key, PkcsLimits? limits = null)
    {
        var s = new PinnedSecret(encoded);
        try
        {
            key = Adopt(s, limits ?? PkcsLimits.Default);
            return true;
        }
        catch (PkcsParseException)
        {
            key = null;
            return false;
        }
    }

    /// <summary>Takes ownership of <paramref name="secret"/>; it is disposed when parsing fails.</summary>
    internal static PrivateKeyInfo Adopt(PinnedSecret secret, PkcsLimits limits)
    {
        const string what = "PrivateKeyInfo";
        try
        {
            if (secret.Length > limits.MaxEncodedSize)
            {
                throw PkcsFail.Limit(what, "The key is larger than the configured limit.");
            }

            ReadOnlySpan<byte> all = secret.ReadOnlySpan;
            var r = new Asn1Reader(all, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            int version = s.ReadInt32();
            if (version is not (0 or 1))
            {
                throw PkcsFail.Unsupported(what, $"Version {version} is not defined (RFC 5958 §2).");
            }

            AlgorithmIdentifier alg = AlgorithmIdentifier.Parse(s.ReadEncodedValue().ToArray());
            ReadOnlySpan<byte> key = s.ReadOctetString();
            if (!all.Overlaps(key, out int offset))
            {
                // A constructed (BER) OCTET STRING has no single slice: re-pin the joined bytes into the container.
                throw PkcsFail.Bad(what, "The privateKey OCTET STRING must be primitive.");
            }

            var attrs = new List<byte[]>();
            if (s.HasData && s.PeekTag() == Asn1Tag.Context(0, true))
            {
                Asn1Reader a = s.ReadSequence(Asn1Tag.Context(0, true));
                while (a.HasData)
                {
                    attrs.Add(a.ReadEncodedValue().ToArray());
                }
            }

            byte[] pub = [];
            if (s.HasData && s.PeekTag() == Asn1Tag.Context(1))
            {
                if (version == 0)
                {
                    throw PkcsFail.Invalid(what, "A version 1 key cannot carry a public key (RFC 5958 §2).");
                }

                pub = s.ReadBitStringBytes(out _, Asn1Tag.Context(1));
            }

            s.ThrowIfNotEmpty();
            return new PrivateKeyInfo(secret, version, alg, offset, key.Length, pub, [.. attrs]);
        }
        catch (Asn1ParseException ex)
        {
            secret.Dispose();
            throw new PkcsParseException(what, ex);
        }
        catch (X509ParseException ex)
        {
            secret.Dispose();
            throw new PkcsParseException(what, PkcsError.Malformed, ex.Message);
        }
        catch
        {
            secret.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Reads the first PEM block of <paramref name="pem"/> labelled <c>PRIVATE KEY</c>, or a legacy <c>RSA PRIVATE KEY</c> (PKCS#1) or
    /// <c>EC PRIVATE KEY</c> (SEC 1) block, which is wrapped into PKCS#8. Encrypted blocks are refused: use <see cref="PrivateKeyPem"/>.
    /// </summary>
    /// <exception cref="PkcsParseException">There is no usable block.</exception>
    public static PrivateKeyInfo FromPem(string pem) => PrivateKeyPem.Parse(pem, default);

    /// <summary>The key as a <c>PRIVATE KEY</c> PEM block (RFC 7468 §10). The result holds secret text; the caller must handle it accordingly.</summary>
    public string ToPem() => PemCodec.Write("PRIVATE KEY", _encoded.ReadOnlySpan);

    /// <summary>Wraps a PKCS#1 <c>RSAPrivateKey</c> (RFC 8017 appendix A.1.2) as PKCS#8.</summary>
    /// <exception cref="PkcsParseException">The input is not an RSAPrivateKey.</exception>
    public static PrivateKeyInfo FromRsaPrivateKey(ReadOnlySpan<byte> rsaPrivateKey)
    {
        // RFC 8017 appendix A.1.2: version and eight integers. Checking them here means a wrong password that happens to leave valid
        // padding is still refused.
        try
        {
            var r = new Asn1Reader(rsaPrivateKey, Asn1Rules.Ber);
            Asn1Reader s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            int version = s.ReadInt32();
            if (version is not (0 or 1))
            {
                throw PkcsFail.Invalid("RSAPrivateKey", "The version must be 0 or 1.");
            }

            for (int i = 0; i < 8; i++)
            {
                s.ReadIntegerBytes();
            }

            if (version == 0)
            {
                s.ThrowIfNotEmpty();
            }
        }
        catch (Asn1ParseException ex)
        {
            throw new PkcsParseException("RSAPrivateKey", ex);
        }

        var w = new Asn1Writer();
        w.PushSequence();
        w.WriteInteger(0);
        w.PushSequence();
        w.WriteObjectIdentifier(KnownOids.RsaEncryption);
        w.WriteNull();
        w.Pop();
        w.WriteOctetString(rsaPrivateKey);
        w.Pop();
        return Wrap(w);
    }

    /// <summary>Wraps a SEC 1 <c>ECPrivateKey</c> (RFC 5915) as PKCS#8. The curve comes from the structure's <c>parameters</c> field.</summary>
    /// <exception cref="PkcsParseException">The structure names no curve or is malformed.</exception>
    public static PrivateKeyInfo FromEcPrivateKey(ReadOnlySpan<byte> ecPrivateKey)
    {
        string? curve = null;
        try
        {
            var r = new Asn1Reader(ecPrivateKey, Asn1Rules.Ber);
            Asn1Reader s = r.ReadSequence();
            s.ReadInt32();
            s.ReadOctetString();
            if (s.HasData && s.PeekTag() == Asn1Tag.Context(0, true))
            {
                Asn1Reader p = s.ReadSequence(Asn1Tag.Context(0, true));
                curve = p.ReadObjectIdentifier();
            }
        }
        catch (Asn1ParseException ex)
        {
            throw new PkcsParseException("ECPrivateKey", ex);
        }

        if (curve is null)
        {
            throw PkcsFail.Bad("ECPrivateKey", "The key names no curve.");
        }

        var w = new Asn1Writer();
        w.PushSequence();
        w.WriteInteger(0);
        w.PushSequence();
        w.WriteObjectIdentifier(KnownOids.EcPublicKey);
        w.WriteObjectIdentifier(curve);
        w.Pop();
        w.WriteOctetString(ecPrivateKey);
        w.Pop();
        return Wrap(w);
    }

    /// <summary>
    /// Wraps OpenSSL's traditional <c>DSA PRIVATE KEY</c> structure (version, p, q, g, y, x) as PKCS#8 with the id-dsa algorithm (RFC 3279 §2.3.2,
    /// private key as in RFC 5958 over a DSA INTEGER). DSA keys are read so that old files load; this library never signs with DSA.
    /// </summary>
    /// <exception cref="PkcsParseException">The input is not a DSA private key structure.</exception>
    public static PrivateKeyInfo FromDsaPrivateKey(ReadOnlySpan<byte> dsaPrivateKey)
    {
        const string what = "DSAPrivateKey";
        ReadOnlySpan<byte> p, q, g, x;
        try
        {
            var r = new Asn1Reader(dsaPrivateKey, Asn1Rules.Ber);
            Asn1Reader s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            if (s.ReadInt32() != 0)
            {
                throw PkcsFail.Invalid(what, "The version must be 0.");
            }

            p = s.ReadIntegerBytes();
            q = s.ReadIntegerBytes();
            g = s.ReadIntegerBytes();
            s.ReadIntegerBytes();
            x = s.ReadIntegerBytes();
            s.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException ex)
        {
            throw new PkcsParseException(what, ex);
        }

        var w = new Asn1Writer();
        w.PushSequence();
        w.WriteInteger(0);
        w.PushSequence();
        w.WriteObjectIdentifier("1.2.840.10040.4.1");
        w.PushSequence();
        w.WriteContent(Asn1Tag.Universal(Asn1Tags.IntegerType), p);
        w.WriteContent(Asn1Tag.Universal(Asn1Tags.IntegerType), q);
        w.WriteContent(Asn1Tag.Universal(Asn1Tags.IntegerType), g);
        w.Pop();
        w.Pop();
        // privateKey OCTET STRING holds the DER INTEGER x.
        var xw = new Asn1Writer();
        xw.WriteContent(Asn1Tag.Universal(Asn1Tags.IntegerType), x);
        byte[] xi = xw.Encode();
        w.WriteOctetString(xi);
        CryptographicOperations.ZeroMemory(xi);
        w.Pop();
        return Wrap(w);
    }

    private static PrivateKeyInfo Wrap(Asn1Writer w)
    {
        byte[] enc = w.Encode();
        try
        {
            return Parse(enc);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(enc);
        }
    }

    // ---- to platform and library key objects ----

    /// <summary>The key as an <see cref="RSA"/> object (rsaEncryption keys).</summary>
    /// <exception cref="InvalidOperationException">The key is not an RSA key.</exception>
    /// <exception cref="CryptographicException">The platform refused the key.</exception>
    public RSA ToRsa()
    {
        Require(KeyAlgorithm.Rsa);
        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportPkcs8PrivateKey(Encoded, out _);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    /// <summary>The key as an <see cref="ECDsa"/> object (id-ecPublicKey keys on a curve the platform has).</summary>
    public ECDsa ToECDsa()
    {
        Require(KeyAlgorithm.EllipticCurve);
        ECDsa k = ECDsa.Create();
        try
        {
            k.ImportPkcs8PrivateKey(Encoded, out _);
            return k;
        }
        catch
        {
            k.Dispose();
            throw;
        }
    }

    /// <summary>The key as an <see cref="ECDiffieHellman"/> object.</summary>
    public ECDiffieHellman ToECDiffieHellman()
    {
        Require(KeyAlgorithm.EllipticCurve);
        ECDiffieHellman k = ECDiffieHellman.Create();
        try
        {
            k.ImportPkcs8PrivateKey(Encoded, out _);
            return k;
        }
        catch
        {
            k.Dispose();
            throw;
        }
    }

    /// <summary>The key as an <see cref="MLDsa"/> object, from the seed, expanded or both-form of RFC 9881 §6 as the platform allows. Preview: the platform marks its PKCS#8 support for ML-DSA experimental.</summary>
    /// <exception cref="PlatformNotSupportedException">The platform has no ML-DSA.</exception>
    public MLDsa ToMLDsa()
    {
        Require(KeyAlgorithm.MlDsa);
        return PqKeys.ImportMLDsa(Encoded);
    }

    /// <summary>The key as an <see cref="MLKem"/> object. Preview: the platform marks its PKCS#8 support for ML-KEM experimental.</summary>
    /// <exception cref="PlatformNotSupportedException">The platform has no ML-KEM.</exception>
    public MLKem ToMLKem()
    {
        Require(KeyAlgorithm.MlKem);
        return PqKeys.ImportMLKem(Encoded);
    }

    /// <summary>The key as this library's Ed25519 private key (RFC 8410 §7: the seed).</summary>
    public Ed25519PrivateKey ToEd25519() => Ed25519PrivateKey.FromSeed(Curve(KeyAlgorithm.Ed25519, 32));

    /// <summary>The key as this library's Ed448 private key.</summary>
    public Ed448PrivateKey ToEd448() => Ed448PrivateKey.FromSeed(Curve(KeyAlgorithm.Ed448, 57));

    /// <summary>The key as this library's X25519 private key.</summary>
    public X25519PrivateKey ToX25519() => X25519PrivateKey.FromBytes(Curve(KeyAlgorithm.X25519, 32));

    /// <summary>The key as this library's X448 private key.</summary>
    public X448PrivateKey ToX448() => X448PrivateKey.FromBytes(Curve(KeyAlgorithm.X448, 56));

    private void Require(KeyAlgorithm expected)
    {
        if (KeyAlgorithm != expected)
        {
            throw new InvalidOperationException($"The key is {Algorithm.Name}, not {expected}.");
        }
    }

    /// <summary>The CurvePrivateKey of RFC 8410 §7: an OCTET STRING inside the privateKey OCTET STRING. The returned span points into the pinned buffer.</summary>
    private ReadOnlySpan<byte> Curve(KeyAlgorithm expected, int length)
    {
        Require(expected);
        ReadOnlySpan<byte> inner;
        try
        {
            var r = new Asn1Reader(PrivateKey, Asn1Rules.Der);
            inner = r.ReadOctetString();
            r.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException ex)
        {
            throw new PkcsParseException("CurvePrivateKey", ex);
        }

        if (inner.Length != length)
        {
            throw PkcsFail.Invalid("CurvePrivateKey", $"{Algorithm.Name} private keys are {length} bytes (RFC 8410 §7).");
        }

        return inner;
    }

    /// <summary>The public key: the stored one of a version 2 key, otherwise computed from the private key.</summary>
    /// <exception cref="NotSupportedException">The algorithm is not one this library can derive a public key for.</exception>
    public PublicKeyInfo GetPublicKey()
    {
        if (_publicKeyBits.Length > 0)
        {
            var w = new Asn1Writer();
            w.PushSequence();
            w.WriteEncodedValue(Algorithm.Encoded.Span);
            w.WriteBitString(_publicKeyBits);
            w.Pop();
            return PublicKeyInfo.Parse(w.Encode());
        }

        switch (KeyAlgorithm)
        {
            case KeyAlgorithm.Rsa:
                using (RSA rsa = ToRsa())
                {
                    return PublicKeyInfo.Parse(rsa.ExportSubjectPublicKeyInfo());
                }

            case KeyAlgorithm.EllipticCurve:
                using (ECDsa ec = ToECDsa())
                {
                    return PublicKeyInfo.Parse(ec.ExportSubjectPublicKeyInfo());
                }

            case KeyAlgorithm.Ed25519:
                using (Ed25519PrivateKey k = ToEd25519())
                {
                    byte[] pk = new byte[32];
                    k.PublicKey.Export(pk);
                    return Spki(pk);
                }

            case KeyAlgorithm.Ed448:
                using (Ed448PrivateKey k = ToEd448())
                {
                    byte[] pk = new byte[57];
                    k.PublicKey.Export(pk);
                    return Spki(pk);
                }

            case KeyAlgorithm.X25519:
                using (X25519PrivateKey k = ToX25519())
                {
                    byte[] pk = new byte[32];
                    k.PublicKey.Export(pk);
                    return Spki(pk);
                }

            case KeyAlgorithm.X448:
                using (X448PrivateKey k = ToX448())
                {
                    byte[] pk = new byte[56];
                    k.PublicKey.Export(pk);
                    return Spki(pk);
                }

            case KeyAlgorithm.MlDsa:
                using (MLDsa k = ToMLDsa())
                {
                    return PublicKeyInfo.Parse(PqKeys.SpkiOf(k));
                }

            case KeyAlgorithm.MlKem:
                using (MLKem k = ToMLKem())
                {
                    return PublicKeyInfo.Parse(PqKeys.SpkiOf(k));
                }

            default:
                throw new NotSupportedException($"A public key cannot be derived for {Algorithm.Name}.");
        }
    }

    private PublicKeyInfo Spki(byte[] pk)
    {
        var w = new Asn1Writer();
        w.PushSequence();
        w.WriteEncodedValue(Algorithm.Encoded.Span);
        w.WriteBitString(pk);
        w.Pop();
        return PublicKeyInfo.Parse(w.Encode());
    }

    // ---- from platform and library key objects ----

    /// <summary>Exports a platform key (RSA, ECDsa, ECDiffieHellman, MLDsa, MLKem) as PKCS#8.</summary>
    /// <exception cref="CryptographicException">The key cannot be exported.</exception>
    public static PrivateKeyInfo FromAsymmetricAlgorithm(AsymmetricAlgorithm key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return FromExported(key.ExportPkcs8PrivateKey());
    }

    /// <summary>Exports an ML-DSA key as PKCS#8 (the platform picks the form).</summary>
    public static PrivateKeyInfo FromMLDsa(MLDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return FromExported(PqKeys.Pkcs8Of(key));
    }

    /// <summary>Exports an ML-KEM key as PKCS#8.</summary>
    public static PrivateKeyInfo FromMLKem(MLKem key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return FromExported(PqKeys.Pkcs8Of(key));
    }

    private static PrivateKeyInfo FromExported(byte[] exported)
    {
        try
        {
            return Parse(exported);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exported);
        }
    }

    /// <summary>An Ed25519 key as PKCS#8 (RFC 8410 §7). With <paramref name="includePublicKey"/> the result is a version 2 key that carries the public key (RFC 5958).</summary>
    public static PrivateKeyInfo FromEd25519(Ed25519PrivateKey key, bool includePublicKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        Span<byte> seed = stackalloc byte[32]; // fixed size, 32 bytes
        Span<byte> pub = stackalloc byte[32]; // fixed size, 32 bytes
        try
        {
            key.ExportSeed(seed);
            key.PublicKey.Export(pub);
            return FromCurve(KnownOids.Ed25519, seed, includePublicKey ? pub : default);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>An Ed448 key as PKCS#8.</summary>
    public static PrivateKeyInfo FromEd448(Ed448PrivateKey key, bool includePublicKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        Span<byte> seed = stackalloc byte[57]; // fixed size, 57 bytes
        Span<byte> pub = stackalloc byte[57]; // fixed size, 57 bytes
        try
        {
            key.ExportSeed(seed);
            key.PublicKey.Export(pub);
            return FromCurve(KnownOids.Ed448, seed, includePublicKey ? pub : default);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>An X25519 key as PKCS#8.</summary>
    public static PrivateKeyInfo FromX25519(X25519PrivateKey key, bool includePublicKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        Span<byte> sk = stackalloc byte[32]; // fixed size, 32 bytes
        Span<byte> pub = stackalloc byte[32]; // fixed size, 32 bytes
        try
        {
            key.Export(sk);
            key.PublicKey.Export(pub);
            return FromCurve(KnownOids.X25519, sk, includePublicKey ? pub : default);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sk);
        }
    }

    /// <summary>An X448 key as PKCS#8.</summary>
    public static PrivateKeyInfo FromX448(X448PrivateKey key, bool includePublicKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        Span<byte> sk = stackalloc byte[56]; // fixed size, 56 bytes
        Span<byte> pub = stackalloc byte[56]; // fixed size, 56 bytes
        try
        {
            key.Export(sk);
            key.PublicKey.Export(pub);
            return FromCurve(KnownOids.X448, sk, includePublicKey ? pub : default);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sk);
        }
    }

    private static PrivateKeyInfo FromCurve(string oid, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> publicKey)
    {
        var w = new Asn1Writer();
        w.PushSequence();
        w.WriteInteger(publicKey.IsEmpty ? 0 : 1);
        w.PushSequence();
        w.WriteObjectIdentifier(oid);
        w.Pop();

        // RFC 8410 §7: the privateKey OCTET STRING contains a CurvePrivateKey, itself an OCTET STRING.
        byte[] inner = new byte[secret.Length + 2 + (secret.Length > 127 ? 1 : 0)];
        try
        {
            int n = 0;
            inner[n++] = 4;
            if (secret.Length > 127)
            {
                inner[n++] = 0x81;
            }

            inner[n++] = (byte)secret.Length;
            secret.CopyTo(inner.AsSpan(n));
            w.WriteOctetString(inner);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inner);
        }

        if (!publicKey.IsEmpty)
        {
            w.WriteBitString(publicKey, 0, Asn1Tag.Context(1));
        }

        w.Pop();
        return Wrap(w);
    }

    // ---- encryption ----

    /// <summary>Encrypts the key with a password into an <c>EncryptedPrivateKeyInfo</c> using PBES2 (RFC 8018 §6.2).</summary>
    /// <param name="password">The password; it is encoded as UTF-8 (RFC 8018 §3).</param>
    /// <param name="options">Cipher and key-derivation choices; null for <see cref="Pbes2Options.Default"/>.</param>
    public EncryptedPrivateKeyInfo Encrypt(ReadOnlySpan<char> password, Pbes2Options? options = null) => EncryptedPrivateKeyInfo.Create(this, password, options ?? Pbes2Options.Default);
}
