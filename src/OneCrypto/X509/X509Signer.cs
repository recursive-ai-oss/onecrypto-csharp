using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// Signs the structures the PKI builders produce. It pairs a signature algorithm identifier with the signer's public key and produces
/// the signature value. The platform's RSA, ECDSA and ML-DSA keys are wrapped by the <c>From…</c> factories, so a private key never leaves its
/// platform object; other key types implement this class or use <see cref="FromDelegate"/>.
/// </summary>
public abstract class X509Signer
{
    /// <summary>Lets derived classes be created.</summary>
    protected X509Signer()
    {
    }

    /// <summary>The algorithm identifier written into the signed structure, parameters included.</summary>
    public abstract AlgorithmIdentifier SignatureAlgorithm { get; }

    /// <summary>The public key that verifies the signatures.</summary>
    public abstract PublicKeyInfo PublicKey { get; }

    /// <summary>Signs the octets (the encoded to-be-signed structure) and returns the signature value as it goes into the BIT STRING.</summary>
    public abstract byte[] Sign(ReadOnlySpan<byte> data);

    /// <summary>Signs with an RSA key, PKCS #1 v1.5 or RSASSA-PSS (salt as long as the hash, MGF1 on the same hash). The key stays owned by the caller.</summary>
    public static X509Signer FromRsa(RSA key, HashAlgorithmName hash, bool pss = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        string hashOid = HashOid(hash);
        AlgorithmIdentifier alg;
        if (pss)
        {
            int salt = DigestSize(hash);
            byte[] hashAlg = AlgorithmIdentifier.WithNull(hashOid).Encoded.ToArray();
            byte[] mgf = DerWriter.Sequence(DerWriter.Oid(KnownOids.Mgf1), hashAlg);
            byte[] parameters = DerWriter.Sequence(DerWriter.Context(0, hashAlg), DerWriter.Context(1, mgf), DerWriter.Context(2, DerWriter.SignedInteger(salt)));
            alg = AlgorithmIdentifier.Create(KnownOids.RsaPss, parameters);
        }
        else
        {
            string oid = hashOid switch
            {
                KnownOids.Sha1 => KnownOids.Sha1WithRsa,
                KnownOids.Sha224 => KnownOids.Sha224WithRsa,
                KnownOids.Sha256 => KnownOids.Sha256WithRsa,
                KnownOids.Sha384 => KnownOids.Sha384WithRsa,
                KnownOids.Sha512 => KnownOids.Sha512WithRsa,
                _ => throw new ArgumentException("No PKCS #1 v1.5 signature identifier for " + hash.Name, nameof(hash)),
            };
            alg = AlgorithmIdentifier.WithNull(oid);
        }

        return new Platform(alg, PublicKeyInfo.FromAsymmetricAlgorithm(key), d => key.SignData(d, hash, pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1));
    }

    /// <summary>Signs with an ECDSA key (DER signature, RFC 3279). The hash defaults to the one that matches the curve: SHA-256, SHA-384 or SHA-512.</summary>
    public static X509Signer FromECDsa(ECDsa key, HashAlgorithmName? hash = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        PublicKeyInfo pub = PublicKeyInfo.FromAsymmetricAlgorithm(key);
        HashAlgorithmName h = hash ?? (pub.KeySizeBits <= 256 ? HashAlgorithmName.SHA256 : pub.KeySizeBits <= 384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA512);
        string oid = HashOid(h) switch
        {
            KnownOids.Sha1 => KnownOids.EcdsaSha1,
            KnownOids.Sha224 => KnownOids.EcdsaSha224,
            KnownOids.Sha256 => KnownOids.EcdsaSha256,
            KnownOids.Sha384 => KnownOids.EcdsaSha384,
            KnownOids.Sha512 => KnownOids.EcdsaSha512,
            _ => throw new ArgumentException("No ECDSA signature identifier for " + h.Name, nameof(hash)),
        };
        return new Platform(AlgorithmIdentifier.Create(oid), pub, d => key.SignData(d, h, DSASignatureFormat.Rfc3279DerSequence));
    }

    /// <summary>Signs with an ML-DSA key (empty context, RFC 9881). The parameter set follows the key.</summary>
    public static X509Signer FromMLDsa(MLDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        string oid = key.Algorithm.Name switch
        {
            "ML-DSA-44" => KnownOids.MlDsa44,
            "ML-DSA-65" => KnownOids.MlDsa65,
            _ => KnownOids.MlDsa87,
        };
        byte[] spki = DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(oid)), BitString(key.ExportMLDsaPublicKey()));
        return new Platform(AlgorithmIdentifier.Create(oid), PublicKeyInfo.Parse(spki), d => key.SignData(d));
    }

    /// <summary>Signs with a function the caller provides (an HSM, a remote service, an EdDSA key from another source).</summary>
    /// <param name="algorithm">The identifier to write.</param>
    /// <param name="publicKey">The public key of the signing key.</param>
    /// <param name="sign">Produces the signature value for the octets to sign.</param>
    public static X509Signer FromDelegate(AlgorithmIdentifier algorithm, PublicKeyInfo publicKey, Func<byte[], byte[]> sign)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(sign);
        return new Platform(algorithm, publicKey, sign);
    }

    internal static byte[] BitString(ReadOnlySpan<byte> bits)
    {
        var b = new byte[bits.Length + 1];
        bits.CopyTo(b.AsSpan(1));
        return DerWriter.Tlv(0x03, b);
    }

    private static string HashOid(HashAlgorithmName h) => h.Name switch
    {
        "SHA1" => KnownOids.Sha1,
        "SHA224" => KnownOids.Sha224,
        "SHA256" => KnownOids.Sha256,
        "SHA384" => KnownOids.Sha384,
        "SHA512" => KnownOids.Sha512,
        _ => throw new ArgumentException("Unsupported hash " + h.Name, nameof(h)),
    };

    private static int DigestSize(HashAlgorithmName h) => h.Name switch { "SHA1" => 20, "SHA224" => 28, "SHA256" => 32, "SHA384" => 48, _ => 64 };

    private sealed class Platform : X509Signer
    {
        private readonly Func<byte[], byte[]> _sign;

        public Platform(AlgorithmIdentifier alg, PublicKeyInfo key, Func<byte[], byte[]> sign)
        {
            SignatureAlgorithm = alg;
            PublicKey = key;
            _sign = sign;
        }

        public override AlgorithmIdentifier SignatureAlgorithm { get; }

        public override PublicKeyInfo PublicKey { get; }

        public override byte[] Sign(ReadOnlySpan<byte> data) => _sign(data.ToArray());
    }
}

/// <summary>Encoding helpers shared by the builders.</summary>
internal static class BuildHelpers
{
    /// <summary>A Time (RFC 5280 §4.1.2.5): UTCTime through 2049, GeneralizedTime from 2050.</summary>
    public static byte[] Time(DateTimeOffset t)
    {
        DateTimeOffset u = t.ToUniversalTime();
        return u.Year is >= 1950 and <= 2049 ? DerWriter.UtcTime(u) : DerWriter.GeneralizedTime(u);
    }

    public static byte[] Signed(byte[] tbs, X509Signer signer)
    {
        byte[] sig = signer.Sign(tbs);
        return DerWriter.Sequence(tbs, signer.SignatureAlgorithm.Encoded.ToArray(), X509Signer.BitString(sig));
    }

    public static byte[] RandomSerial()
    {
        var b = new byte[20];
        RandomNumberGenerator.Fill(b);
        b[0] &= 0x7F;
        if (b.All(x => x == 0))
        {
            b[19] = 1;
        }

        return b;
    }

    /// <summary>RFC 7093 §2 method 1: the leftmost 160 bits of the SHA-256 of the subjectPublicKey bits.</summary>
    public static byte[] KeyIdentifier(PublicKeyInfo key) => SHA256.HashData(key.KeyBits.Span)[..20];

    public static byte[] Extensions(IEnumerable<Extension> list) => DerWriter.Sequence([.. list.Select(e => e.Encoded.ToArray())]);

    public static byte[] UnsignedInt(ReadOnlySpan<byte> serial) => DerWriter.UnsignedInteger(serial);
}
