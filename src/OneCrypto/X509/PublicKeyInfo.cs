using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto;

/// <summary>The family of a public key, from the algorithm identifier of its <c>SubjectPublicKeyInfo</c>.</summary>
public enum KeyAlgorithm
{
    /// <summary>An algorithm the library does not know; the key is preserved as received.</summary>
    Unknown,
    /// <summary>rsaEncryption (RFC 8017).</summary>
    Rsa,
    /// <summary>id-RSASSA-PSS: an RSA key restricted to PSS signatures (RFC 4055).</summary>
    RsaPss,
    /// <summary>id-RSAES-OAEP: an RSA key restricted to OAEP encryption (RFC 4055).</summary>
    RsaOaep,
    /// <summary>id-ecPublicKey on a named curve (RFC 5480), including the Brainpool curves (RFC 5639).</summary>
    EllipticCurve,
    /// <summary>Ed25519 (RFC 8410).</summary>
    Ed25519,
    /// <summary>Ed448 (RFC 8410).</summary>
    Ed448,
    /// <summary>X25519 (RFC 8410).</summary>
    X25519,
    /// <summary>X448 (RFC 8410).</summary>
    X448,
    /// <summary>ML-DSA-44, -65 or -87 (FIPS 204; the identifier says which).</summary>
    MlDsa,
    /// <summary>One of the twelve SLH-DSA parameter sets (FIPS 205).</summary>
    SlhDsa,
    /// <summary>ML-KEM-512, -768 or -1024 (FIPS 203).</summary>
    MlKem,
    /// <summary>A composite ML-DSA key (draft-ietf-lamps-pq-composite-sigs). Preview: recognised but not verified.</summary>
    CompositeMlDsa,
}

/// <summary>How a signature check ended.</summary>
public enum SignatureStatus
{
    /// <summary>The signature is correct for the data and key.</summary>
    Valid,
    /// <summary>The signature does not match.</summary>
    Invalid,
    /// <summary>The algorithm is not available on this platform or not known to the library.</summary>
    AlgorithmNotSupported,
    /// <summary>The signature algorithm cannot be used with this kind of key (for example ECDSA with an RSA key).</summary>
    KeyMismatch,
    /// <summary>The public key or the signature algorithm parameters could not be decoded.</summary>
    Malformed,
}

/// <summary>The outcome of checking a signature, with the reason and the section of the specification the rule comes from.</summary>
/// <param name="Status">How the check ended.</param>
/// <param name="Algorithm">The signature algorithm in readable form.</param>
/// <param name="Reason">A sentence explaining a result other than <see cref="SignatureStatus.Valid"/>; empty when valid.</param>
/// <param name="Reference">The RFC section behind the rule that decided the result.</param>
public readonly record struct SignatureVerification(SignatureStatus Status, string Algorithm, string Reason, string Reference)
{
    /// <summary>True only when <see cref="Status"/> is <see cref="SignatureStatus.Valid"/>.</summary>
    public bool IsValid => Status == SignatureStatus.Valid;
}

/// <summary>
/// A <c>SubjectPublicKeyInfo</c> (RFC 5280 §4.1.2.7): algorithm and key bits, exactly as received. Algorithms the library does not know are
/// preserved and reported as <see cref="KeyAlgorithm.Unknown"/>.
/// </summary>
public sealed class PublicKeyInfo : IEquatable<PublicKeyInfo>
{
    private PublicKeyInfo(ReadOnlyMemory<byte> encoded, AlgorithmIdentifier algorithm, ReadOnlyMemory<byte> key)
    {
        Encoded = encoded;
        Algorithm = algorithm;
        KeyBits = key;
        KeyAlgorithm = Classify(algorithm.Oid);
    }

    /// <summary>The whole SubjectPublicKeyInfo SEQUENCE.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The key's algorithm identifier.</summary>
    public AlgorithmIdentifier Algorithm { get; }

    /// <summary>The content of the <c>subjectPublicKey</c> BIT STRING (the octets after the unused-bits count).</summary>
    public ReadOnlyMemory<byte> KeyBits { get; }

    /// <summary>The key family.</summary>
    public KeyAlgorithm KeyAlgorithm { get; }

    /// <summary>The dotted identifier of the named curve of an EC key, or null (not an EC key, or explicit or implicit parameters).</summary>
    public string? CurveOid
    {
        get
        {
            if (KeyAlgorithm != KeyAlgorithm.EllipticCurve || Algorithm.Parameters.IsEmpty)
            {
                return null;
            }

            var r = new Asn1Reader(Algorithm.Parameters.Span, Asn1Rules.Ber);
            return r.TryReadObjectIdentifier(out string oid) ? oid : null;
        }
    }

    /// <summary>The size of the key in bits: the RSA modulus, the curve size or the fixed size of the algorithm; 0 when it cannot be told.</summary>
    public int KeySizeBits
    {
        get
        {
            switch (KeyAlgorithm)
            {
                case KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss or KeyAlgorithm.RsaOaep:
                    var r = new Asn1Reader(KeyBits.Span, Asn1Rules.Ber);
                    if (!r.TryReadSequence(out Asn1Reader s) || !s.TryReadUnsignedIntegerBytes(out ReadOnlySpan<byte> n))
                    {
                        return 0;
                    }

                    while (n.Length > 1 && n[0] == 0)
                    {
                        n = n[1..];
                    }

                    return n.Length == 0 ? 0 : ((n.Length - 1) * 8) + (32 - System.Numerics.BitOperations.LeadingZeroCount((uint)n[0]));
                case KeyAlgorithm.EllipticCurve:
                    return CurveOid switch
                    {
                        KnownOids.P256 or KnownOids.BrainpoolP256r1 => 256,
                        KnownOids.P384 or KnownOids.BrainpoolP384r1 => 384,
                        KnownOids.P521 => 521,
                        KnownOids.BrainpoolP512r1 => 512,
                        _ => KeyBits.Length > 1 && KeyBits.Span[0] == 4 ? (KeyBits.Length - 1) / 2 * 8 : 0,
                    };
                case KeyAlgorithm.Ed25519 or KeyAlgorithm.X25519:
                    return 256;
                case KeyAlgorithm.Ed448:
                    return 456;
                case KeyAlgorithm.X448:
                    return 448;
                default:
                    return 0;
            }
        }
    }

    private static KeyAlgorithm Classify(string oid) => oid switch
    {
        KnownOids.RsaEncryption => KeyAlgorithm.Rsa,
        KnownOids.RsaPss => KeyAlgorithm.RsaPss,
        KnownOids.RsaOaep => KeyAlgorithm.RsaOaep,
        KnownOids.EcPublicKey => KeyAlgorithm.EllipticCurve,
        KnownOids.Ed25519 => KeyAlgorithm.Ed25519,
        KnownOids.Ed448 => KeyAlgorithm.Ed448,
        KnownOids.X25519 => KeyAlgorithm.X25519,
        KnownOids.X448 => KeyAlgorithm.X448,
        KnownOids.MlDsa44 or KnownOids.MlDsa65 or KnownOids.MlDsa87 => KeyAlgorithm.MlDsa,
        KnownOids.MlKem512 or KnownOids.MlKem768 or KnownOids.MlKem1024 => KeyAlgorithm.MlKem,
        _ when AlgorithmNames.SlhDsaName(oid) is not null => KeyAlgorithm.SlhDsa,
        _ when SignatureAlgorithms.IsComposite(oid) => KeyAlgorithm.CompositeMlDsa,
        _ => KeyAlgorithm.Unknown,
    };

    /// <summary>Reads a SubjectPublicKeyInfo.</summary>
    /// <exception cref="X509ParseException">The octets are not a SubjectPublicKeyInfo.</exception>
    public static PublicKeyInfo Parse(ReadOnlyMemory<byte> encoded)
    {
        try
        {
            var r = new Asn1Reader(encoded.Span, Asn1Rules.Ber);
            PublicKeyInfo k = Read(ref r, encoded);
            r.ThrowIfNotEmpty();
            return k;
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("SubjectPublicKeyInfo", e);
        }
    }

    /// <summary>Reads a SubjectPublicKeyInfo, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out PublicKeyInfo? key)
    {
        try
        {
            key = Parse(encoded);
            return true;
        }
        catch (X509ParseException)
        {
            key = null;
            return false;
        }
    }

    internal static PublicKeyInfo Read(ref Asn1Reader r, ReadOnlyMemory<byte> root)
    {
        ReadOnlySpan<byte> whole = r.ReadEncodedValue();
        var o = new Asn1Reader(whole, Asn1Rules.Ber, r.Limits);
        Asn1Reader seq = o.ReadSequence();
        o.ThrowIfNotEmpty();
        AlgorithmIdentifier alg = AlgorithmIdentifier.Read(ref seq, root);
        ReadOnlySpan<byte> bits = seq.ReadBitString(out _);
        seq.ThrowIfNotEmpty();
        return new PublicKeyInfo(X509Read.Slice(root, whole), alg, X509Read.Slice(root, bits));
    }

    /// <summary>The public key of a BCL key object (RSA, ECDsa, MLDsa and so on).</summary>
    public static PublicKeyInfo FromAsymmetricAlgorithm(AsymmetricAlgorithm key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Parse(key.ExportSubjectPublicKeyInfo());
    }

    /// <summary>The public key of a certificate's key pair for an RSA key (also usable as the key of an RSA-PSS or RSA-OAEP certificate).</summary>
    /// <exception cref="CryptographicException">The key is not an RSA key or cannot be loaded.</exception>
    public RSA ToRsa()
    {
        if (KeyAlgorithm is not (KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss or KeyAlgorithm.RsaOaep))
        {
            throw new CryptographicException("The key is not an RSA key.");
        }

        // The key bits are an RSAPublicKey whatever the algorithm identifier says, so one path serves all three RSA key types.
        try
        {
            var r = new Asn1Reader(KeyBits.Span, Asn1Rules.Ber);
            Asn1Reader s = r.ReadSequence();
            byte[] n = s.ReadUnsignedIntegerBytes().ToArray();
            byte[] e = s.ReadUnsignedIntegerBytes().ToArray();
            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = Trim(n), Exponent = Trim(e) });
            return rsa;
        }
        catch (Asn1ParseException ex)
        {
            throw new CryptographicException("The RSA public key is malformed.", ex);
        }
    }

    private static byte[] Trim(byte[] v)
    {
        int i = 0;
        while (i < v.Length - 1 && v[i] == 0)
        {
            i++;
        }

        return v[i..];
    }

    /// <summary>The key as a BCL <see cref="ECDsa"/> (verification and key agreement use the same import).</summary>
    /// <exception cref="CryptographicException">The key is not a valid EC key.</exception>
    /// <exception cref="NotSupportedException">The platform does not have the key's curve.</exception>
    public ECDsa ToECDsa()
    {
        var ec = ECDsa.Create();
        try
        {
            ec.ImportSubjectPublicKeyInfo(Encoded.Span, out _);
            return ec;
        }
        catch
        {
            ec.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Checks <paramref name="signature"/> over <paramref name="data"/> made with this key under <paramref name="signatureAlgorithm"/>.
    /// RSA and ECDSA use the platform; Ed25519 and Ed448 use the library's primitives; ML-DSA and SLH-DSA use the platform where it has them.
    /// Never throws for bad data: the result says what was wrong.
    /// </summary>
    /// <param name="signatureAlgorithm">The identifier from the signed structure.</param>
    /// <param name="data">The signed octets exactly as received (for a certificate, the encoded <c>tbsCertificate</c>).</param>
    /// <param name="signature">The signature value octets (the BIT STRING content).</param>
    public SignatureVerification VerifySignature(AlgorithmIdentifier signatureAlgorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(signatureAlgorithm);
        return SignatureAlgorithms.Verify(this, signatureAlgorithm, data, signature);
    }

    /// <inheritdoc/>
    public bool Equals(PublicKeyInfo? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as PublicKeyInfo);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }

    /// <inheritdoc/>
    public override string ToString() => KeySizeBits > 0 ? $"{Algorithm.Name} {KeySizeBits}-bit" : Algorithm.Name;
}
