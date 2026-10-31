using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;

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

    /// <summary>The key behind the signer when it was made from a key interface; null for a delegate signer.</summary>
    public virtual ISigningKey? Key => null;

    /// <summary>The signature spec behind the signer when it was made from a key interface; null for a delegate signer.</summary>
    public virtual SignatureSpec? Spec => null;

    /// <summary>
    /// Signs with any key behind the key interfaces (in memory, operating system, token or remote). The spec defaults to the key's own default; its
    /// X.509 identifier is written into the structure. The key stays owned by the caller.
    /// </summary>
    /// <exception cref="NotSupportedException">The key does not support the spec, or the spec has no X.509 identifier.</exception>
    public static X509Signer FromKey(ISigningKey key, SignatureSpec? spec = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        SignatureSpec s = spec ?? key.DefaultSpec;
        if (!key.Supports(s))
        {
            throw new NotSupportedException($"The key cannot sign with {s}.");
        }

        return new Platform(s.ToAlgorithmIdentifier(key.PublicKey), key.PublicKey, d => key.Sign(d, s), key, s);
    }

    /// <summary>Signs with an RSA key, PKCS #1 v1.5 or RSASSA-PSS (salt as long as the hash, MGF1 on the same hash). The key stays owned by the caller.</summary>
    public static X509Signer FromRsa(RSA key, HashAlgorithmName hash, bool pss = false) =>
        FromKey(PrivateKey.FromRsa(key), pss ? SignatureSpec.RsaPss(hash) : SignatureSpec.RsaPkcs1(hash));

    /// <summary>Signs with an ECDSA key (DER signature, RFC 3279). The hash defaults to the one that matches the curve: SHA-256, SHA-384 or SHA-512.</summary>
    public static X509Signer FromECDsa(ECDsa key, HashAlgorithmName? hash = null)
    {
        ISigningKey k = PrivateKey.FromECDsa(key);
        return FromKey(k, hash is { } h ? SignatureSpec.Ecdsa(h) : null);
    }

    /// <summary>Signs with an ML-DSA key (empty context, RFC 9881). The parameter set follows the key.</summary>
    public static X509Signer FromMLDsa(MLDsa key) => FromKey(PrivateKey.FromMLDsa(key));

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

    private sealed class Platform : X509Signer
    {
        private readonly Func<byte[], byte[]> _sign;

        public Platform(AlgorithmIdentifier alg, PublicKeyInfo key, Func<byte[], byte[]> sign, ISigningKey? signingKey = null, SignatureSpec? spec = null)
        {
            SignatureAlgorithm = alg;
            PublicKey = key;
            _sign = sign;
            Key = signingKey;
            Spec = spec;
        }

        public override ISigningKey? Key { get; }

        public override SignatureSpec? Spec { get; }

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

/// <summary>Two-phase signing of the signed structures of RFC 5280 (<c>SEQUENCE { tbs, signatureAlgorithm, signatureValue BIT STRING }</c>).</summary>
internal static class X509TwoPhase
{
    /// <summary>Runs a builder with a signer that only records the octets it was asked to sign, then prepares a state over them.</summary>
    public static PreparedSignature Prepare(string purpose, PublicKeyInfo key, SignatureSpec spec, CryptoPolicy policy, DateTimeOffset at, Action<X509Signer> build)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(spec);
        byte[]? tbs = null;
        X509Signer recorder = X509Signer.FromDelegate(spec.ToAlgorithmIdentifier(key), key, d =>
        {
            tbs = d;
            return [0]; // placeholder; the structure built around it is discarded
        });
        build(recorder);
        return PreparedSignature.Prepare(key, spec, tbs ?? throw new InvalidOperationException("The builder did not sign anything."), policy, at, purpose);
    }

    /// <summary>Checks the signature against the state and returns the finished DER.</summary>
    public static byte[] Complete(PreparedSignature prepared, string purpose, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        if (prepared.Purpose != purpose)
        {
            throw new ArgumentException($"The prepared signature is for {prepared.Purpose}, not {purpose}.", nameof(prepared));
        }

        byte[] sig = prepared.Complete(signature);
        return DerWriter.Sequence(prepared.Data.ToArray(), prepared.Spec.ToAlgorithmIdentifier(prepared.PublicKey).Encoded.ToArray(), X509Signer.BitString(sig));
    }
}
