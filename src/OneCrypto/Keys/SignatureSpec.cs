using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto.Keys;

/// <summary>The signature family of a <see cref="SignatureSpec"/>.</summary>
public enum SignatureKind
{
    /// <summary>RSASSA-PKCS1-v1_5 (RFC 8017 §8.2); the hash is part of the scheme.</summary>
    RsaPkcs1 = 1,
    /// <summary>RSASSA-PSS (RFC 8017 §8.1) with MGF1 on the same hash and a salt as long as the digest.</summary>
    RsaPss = 2,
    /// <summary>ECDSA (FIPS 186-5 §6.4) over a digest, written as DER (RFC 3279 §2.2.3) or as fixed-width <c>r || s</c> (IEEE P1363).</summary>
    Ecdsa = 3,
    /// <summary>Ed25519 over the message (RFC 8032 §5.1).</summary>
    Ed25519 = 4,
    /// <summary>Ed448 over the message with a context, empty by default (RFC 8032 §5.2).</summary>
    Ed448 = 5,
    /// <summary>ML-DSA over the message with a context, empty by default (FIPS 204 §5.2). The parameter set follows the key.</summary>
    MlDsa = 6,
}

/// <summary>How a signature is encoded on the wire.</summary>
public enum EcdsaSignatureFormat
{
    /// <summary>A DER SEQUENCE of two INTEGERs (RFC 3279 §2.2.3), as X.509, CMS and OpenPGP-in-CMS carry it.</summary>
    Der = 0,
    /// <summary>The fixed-width big-endian <c>r || s</c> (IEEE P1363), as JOSE, SSH and raw protocols carry it.</summary>
    Rfc4754 = 1,
}

/// <summary>
/// Everything that fixes how a signature is made and checked, apart from the key: the family, the hash, the ECDSA encoding and the context.
/// Immutable. The encodings (PKCS #1 versus PSS, DER versus P1363, EdDSA over the message) are decided here once, so every backend and every
/// two-phase state agrees on them.
/// </summary>
public sealed class SignatureSpec : IEquatable<SignatureSpec>
{
    private readonly byte[] _context;

    private SignatureSpec(SignatureKind kind, HashAlgorithmName hash, EcdsaSignatureFormat format, byte[] context)
    {
        Kind = kind;
        Hash = hash;
        Format = format;
        _context = context;
    }

    /// <summary>The signature family.</summary>
    public SignatureKind Kind { get; }

    /// <summary>The hash the scheme applies to the data: set for RSA and ECDSA, empty (<c>default</c>) for EdDSA and ML-DSA, which sign the message.</summary>
    public HashAlgorithmName Hash { get; }

    /// <summary>The ECDSA signature encoding; <see cref="EcdsaSignatureFormat.Der"/> for every other family.</summary>
    public EcdsaSignatureFormat Format { get; }

    /// <summary>The context string for Ed448 and ML-DSA; empty otherwise and by default.</summary>
    public ReadOnlySpan<byte> Context => _context;

    /// <summary>True when the scheme signs a digest of the data that a signer can be handed instead of the data (RSA and ECDSA).</summary>
    public bool SignsDigest => Kind is SignatureKind.RsaPkcs1 or SignatureKind.RsaPss or SignatureKind.Ecdsa;

    /// <summary>RSASSA-PKCS1-v1_5 with <paramref name="hash"/> (SHA-1, SHA-256, SHA-384 or SHA-512).</summary>
    /// <exception cref="ArgumentException">The hash has no PKCS #1 signature identifier.</exception>
    public static SignatureSpec RsaPkcs1(HashAlgorithmName hash)
    {
        _ = HashOid(hash);
        return new(SignatureKind.RsaPkcs1, hash, EcdsaSignatureFormat.Der, []);
    }

    /// <summary>RSASSA-PSS with <paramref name="hash"/>, MGF1 on the same hash and a salt as long as the digest (the only salt the platform signs with).</summary>
    /// <exception cref="ArgumentException">The hash is not SHA-1, SHA-256, SHA-384 or SHA-512.</exception>
    public static SignatureSpec RsaPss(HashAlgorithmName hash)
    {
        _ = HashOid(hash);
        return new(SignatureKind.RsaPss, hash, EcdsaSignatureFormat.Der, []);
    }

    /// <summary>ECDSA over <paramref name="hash"/>, in the given encoding (default DER).</summary>
    public static SignatureSpec Ecdsa(HashAlgorithmName hash, EcdsaSignatureFormat format = EcdsaSignatureFormat.Der)
    {
        _ = HashOid(hash);
        return new(SignatureKind.Ecdsa, hash, format, []);
    }

    /// <summary>Ed25519 (RFC 8032 §5.1.6, pure, no context).</summary>
    public static SignatureSpec Ed25519() => new(SignatureKind.Ed25519, default, EcdsaSignatureFormat.Der, []);

    /// <summary>Ed448 with a context of at most 255 octets (RFC 8032 §5.2.6); empty is what RFC 8410 §3 uses in X.509.</summary>
    /// <exception cref="ArgumentException">The context is longer than 255 octets.</exception>
    public static SignatureSpec Ed448(ReadOnlySpan<byte> context = default)
    {
        if (context.Length > 255)
        {
            throw new ArgumentException("An Ed448 context is at most 255 octets.", nameof(context));
        }

        return new(SignatureKind.Ed448, default, EcdsaSignatureFormat.Der, context.ToArray());
    }

    /// <summary>ML-DSA (the "pure" signing of FIPS 204 Algorithm 2) with a context of at most 255 octets; empty is what RFC 9881 uses in X.509.</summary>
    /// <exception cref="ArgumentException">The context is longer than 255 octets.</exception>
    public static SignatureSpec MlDsa(ReadOnlySpan<byte> context = default)
    {
        if (context.Length > 255)
        {
            throw new ArgumentException("An ML-DSA context is at most 255 octets.", nameof(context));
        }

        return new(SignatureKind.MlDsa, default, EcdsaSignatureFormat.Der, context.ToArray());
    }

    /// <summary>
    /// The spec a key of this kind uses unless told otherwise: RSA gets PKCS #1 v1.5 with SHA-256 (PSS for an RSA-PSS key), ECDSA the hash that matches the
    /// curve (SHA-256, SHA-384, SHA-512), and EdDSA and ML-DSA their only form.
    /// </summary>
    /// <exception cref="ArgumentException">The key cannot sign.</exception>
    public static SignatureSpec DefaultFor(PublicKeyInfo key)
    {
        ArgumentNullException.ThrowIfNull(key);
        switch (key.KeyAlgorithm)
        {
            case KeyAlgorithm.Rsa: return RsaPkcs1(HashAlgorithmName.SHA256);
            case KeyAlgorithm.RsaPss: return RsaPss(HashAlgorithmName.SHA256);
            case KeyAlgorithm.EllipticCurve:
                return Ecdsa(key.KeySizeBits <= 256 ? HashAlgorithmName.SHA256 : key.KeySizeBits <= 384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA512);
            case KeyAlgorithm.Ed25519: return Ed25519();
            case KeyAlgorithm.Ed448: return Ed448();
            case KeyAlgorithm.MlDsa: return MlDsa();
            default: throw new ArgumentException($"A {key.Algorithm.Name} key has no signature scheme here.", nameof(key));
        }
    }

    /// <summary>
    /// The X.509 <c>signatureAlgorithm</c> for this spec (RFC 3279, 4055, 5758, 8410, 9881), parameters included. The ECDSA format and the context do not
    /// appear in it; X.509 carries DER and an empty context only.
    /// </summary>
    /// <exception cref="NotSupportedException">The spec has no X.509 identifier: a non-DER ECDSA encoding, a non-empty context, or an ML-DSA key's parameter set (use <see cref="ToAlgorithmIdentifier(PublicKeyInfo)"/>).</exception>
    public AlgorithmIdentifier ToAlgorithmIdentifier(PublicKeyInfo? key = null)
    {
        if (Kind is SignatureKind.Ecdsa && Format != EcdsaSignatureFormat.Der)
        {
            throw new NotSupportedException("X.509 carries ECDSA signatures as DER only.");
        }

        if (_context.Length != 0)
        {
            throw new NotSupportedException("X.509 signs with an empty context.");
        }

        switch (Kind)
        {
            case SignatureKind.RsaPkcs1:
                return AlgorithmIdentifier.WithNull(HashOid(Hash) switch
                {
                    KnownOids.Sha1 => KnownOids.Sha1WithRsa,
                    KnownOids.Sha256 => KnownOids.Sha256WithRsa,
                    KnownOids.Sha384 => KnownOids.Sha384WithRsa,
                    _ => KnownOids.Sha512WithRsa,
                });
            case SignatureKind.RsaPss:
                byte[] hashAlg = AlgorithmIdentifier.WithNull(HashOid(Hash)).Encoded.ToArray();
                byte[] mgf = DerWriter.Sequence(DerWriter.Oid(KnownOids.Mgf1), hashAlg);
                byte[] p = DerWriter.Sequence(DerWriter.Context(0, hashAlg), DerWriter.Context(1, mgf), DerWriter.Context(2, DerWriter.SignedInteger(DigestSize(Hash))));
                return AlgorithmIdentifier.Create(KnownOids.RsaPss, p);
            case SignatureKind.Ecdsa:
                return AlgorithmIdentifier.Create(HashOid(Hash) switch
                {
                    KnownOids.Sha1 => KnownOids.EcdsaSha1,
                    KnownOids.Sha256 => KnownOids.EcdsaSha256,
                    KnownOids.Sha384 => KnownOids.EcdsaSha384,
                    _ => KnownOids.EcdsaSha512,
                });
            case SignatureKind.Ed25519: return AlgorithmIdentifier.Create(KnownOids.Ed25519);
            case SignatureKind.Ed448: return AlgorithmIdentifier.Create(KnownOids.Ed448);
            default:
                if (key is null || key.KeyAlgorithm != KeyAlgorithm.MlDsa)
                {
                    throw new NotSupportedException("The ML-DSA identifier follows the key's parameter set; pass the public key.");
                }

                return AlgorithmIdentifier.Create(key.Algorithm.Oid);
        }
    }

    /// <summary>True when a key of this kind can verify signatures of this spec (RSA key for RSA specs, an EC key for ECDSA, and so on).</summary>
    public bool FitsKey(PublicKeyInfo key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Kind switch
        {
            SignatureKind.RsaPkcs1 => key.KeyAlgorithm == KeyAlgorithm.Rsa,
            SignatureKind.RsaPss => key.KeyAlgorithm is KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss,
            SignatureKind.Ecdsa => key.KeyAlgorithm == KeyAlgorithm.EllipticCurve,
            SignatureKind.Ed25519 => key.KeyAlgorithm == KeyAlgorithm.Ed25519,
            SignatureKind.Ed448 => key.KeyAlgorithm == KeyAlgorithm.Ed448,
            _ => key.KeyAlgorithm == KeyAlgorithm.MlDsa,
        };
    }

    /// <summary>
    /// Checks a signature over the data with <paramref name="key"/>, under this spec, with the platform's public-key operations (or the verify-only
    /// fallbacks) and the library's curves. Never throws for bad input; the result says what was wrong.
    /// </summary>
    /// <param name="key">The signer's public key.</param>
    /// <param name="data">The signed octets (hashed here for RSA and ECDSA).</param>
    /// <param name="signature">The signature in this spec's encoding.</param>
    public SignatureVerification Verify(PublicKeyInfo key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(key);
        return SignatureGlue.Verify(this, key, data, signature);
    }

    /// <inheritdoc/>
    public bool Equals(SignatureSpec? other) =>
        other is not null && Kind == other.Kind && Hash == other.Hash && Format == other.Format && _context.AsSpan().SequenceEqual(other._context);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as SignatureSpec);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Kind, Hash.Name, Format, _context.Length);

    /// <inheritdoc/>
    public override string ToString() => Kind switch
    {
        SignatureKind.RsaPkcs1 => $"RSASSA-PKCS1-v1_5 {Hash.Name}",
        SignatureKind.RsaPss => $"RSASSA-PSS {Hash.Name}",
        SignatureKind.Ecdsa => $"ECDSA {Hash.Name} ({Format})",
        SignatureKind.Ed25519 => "Ed25519",
        SignatureKind.Ed448 => "Ed448",
        _ => "ML-DSA",
    };

    internal static string HashOid(HashAlgorithmName h) => h.Name switch
    {
        "SHA1" => KnownOids.Sha1,
        "SHA256" => KnownOids.Sha256,
        "SHA384" => KnownOids.Sha384,
        "SHA512" => KnownOids.Sha512,
        _ => throw new ArgumentException("Unsupported hash " + h.Name, nameof(h)),
    };

    internal static int DigestSize(HashAlgorithmName h) => h.Name switch { "SHA1" => 20, "SHA256" => 32, "SHA384" => 48, _ => 64 };

    // The serialised form is used by PreparedSignature.
    internal byte[] Encode() => DerWriter.Sequence(
        DerWriter.SignedInteger((int)Kind),
        DerWriter.Utf8String(Hash.Name ?? string.Empty),
        DerWriter.SignedInteger((int)Format),
        DerWriter.Tlv(0x04, _context));

    internal static SignatureSpec Decode(ref Asn1Reader seq)
    {
        Asn1Reader s = seq.ReadSequence();
        var kind = (SignatureKind)s.ReadInt32();
        string hash = s.ReadCharacterString(12);
        var format = (EcdsaSignatureFormat)s.ReadInt32();
        byte[] ctx = s.ReadOctetStringBytes();
        s.ThrowIfNotEmpty();
        bool digestKind = kind is SignatureKind.RsaPkcs1 or SignatureKind.RsaPss or SignatureKind.Ecdsa;
        bool contextKind = kind is SignatureKind.Ed448 or SignatureKind.MlDsa;

        // One canonical encoding per spec: fields that do not apply to a scheme must be empty, so a state re-encodes to the octets it was read from.
        if (!Enum.IsDefined(kind) || !Enum.IsDefined(format) || ctx.Length > 255
            || (format != EcdsaSignatureFormat.Der && kind != SignatureKind.Ecdsa) || (ctx.Length != 0 && !contextKind) || (hash.Length == 0) == digestKind)
        {
            throw new ArgumentException("The signature spec is not valid.");
        }

        return kind switch
        {
            SignatureKind.RsaPkcs1 => RsaPkcs1(new HashAlgorithmName(hash)),
            SignatureKind.RsaPss => RsaPss(new HashAlgorithmName(hash)),
            SignatureKind.Ecdsa => Ecdsa(new HashAlgorithmName(hash), format),
            SignatureKind.Ed25519 => Ed25519(),
            SignatureKind.Ed448 => Ed448(ctx),
            _ => MlDsa(ctx),
        };
    }
}
