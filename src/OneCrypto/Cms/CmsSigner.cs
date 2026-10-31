using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Tsp;

namespace RecursiveAI.OneCrypto.Cms;

/// <summary>The kind of key a signature request is for.</summary>
internal enum CmsKeyType
{
    /// <summary>An RSA key; the signature value is RSASSA-PKCS1-v1_5 or RSASSA-PSS (RFC 8017 8).</summary>
    Rsa,

    /// <summary>An ECDSA key; the signature value is a DER <c>Ecdsa-Sig-Value</c> or the IEEE P1363 pair r||s.</summary>
    Ecdsa,
}

/// <summary>The RSA signature scheme to use when the signer's key is an RSA key. ECDSA keys ignore it.</summary>
internal enum CmsRsaPadding
{
    /// <summary>RSASSA-PKCS1-v1_5 (RFC 8017 8.2).</summary>
    Pkcs1,

    /// <summary>RSASSA-PSS with the digest also used for MGF1 and a salt as long as the digest (RFC 8017 8.1).</summary>
    Pss,
}

/// <summary>What an external signer is asked to sign: the digest of the signed attributes.</summary>
internal sealed class CmsSignRequest
{
    public CmsSignRequest(ReadOnlyMemory<byte> hash, HashAlgorithmName hashAlgorithm, CmsKeyType keyType, CmsRsaPadding padding)
    {
        Hash = hash;
        HashAlgorithm = hashAlgorithm;
        KeyType = keyType;
        RsaPadding = padding;
    }

    public ReadOnlyMemory<byte> Hash { get; }

    public HashAlgorithmName HashAlgorithm { get; }

    public CmsKeyType KeyType { get; }

    public CmsRsaPadding RsaPadding { get; }
}

/// <summary>Signs a digest and returns the signature value (for keys that cannot leave a token or service).</summary>
internal delegate byte[] CmsExternalSigner(CmsSignRequest request);

/// <summary>An RFC 3161 request handed to the caller's time-stamp authority client.</summary>
internal sealed class CmsTimestampRequest
{
    public CmsTimestampRequest(HashAlgorithmName hashAlgorithm, ReadOnlyMemory<byte> imprint, ReadOnlyMemory<byte> nonce, byte[] requestDer)
    {
        HashAlgorithm = hashAlgorithm;
        MessageImprint = imprint;
        Nonce = nonce;
        RequestDer = requestDer;
    }

    public HashAlgorithmName HashAlgorithm { get; }

    public ReadOnlyMemory<byte> MessageImprint { get; }

    public ReadOnlyMemory<byte> Nonce { get; }

    public ReadOnlyMemory<byte> RequestDer { get; }
}

/// <summary>Sends a time-stamp request and returns the authority's response (or a bare token). The library never opens a connection itself.</summary>
internal delegate byte[] CmsTimestampCallback(CmsTimestampRequest request);

/// <summary>A signer's certificate, the certificates to embed with it, and optionally an external signing function.</summary>
internal sealed class CmsSigningCredential
{
    private CmsSigningCredential(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain, CmsExternalSigner? external)
    {
        Certificate = certificate;
        Chain = chain;
        External = external;
    }

    public X509Certificate2 Certificate { get; }

    public IReadOnlyList<X509Certificate2> Chain { get; }

    public CmsExternalSigner? External { get; }

    public static CmsSigningCredential FromCertificate(X509Certificate2 certificate, IEnumerable<X509Certificate2>? chain = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new CmsSigningCredential(certificate, chain is null ? [] : [.. chain], null);
    }

    public static CmsSigningCredential FromExternalSigner(X509Certificate2 certificate, CmsExternalSigner signer, IEnumerable<X509Certificate2>? chain = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(signer);
        return new CmsSigningCredential(certificate, chain is null ? [] : [.. chain], signer);
    }
}

/// <summary>Why building a signature failed.</summary>
internal enum CmsSigningError
{
    NoPrivateKey = 0,
    UnsupportedAlgorithm,
    SignerFailed,
    TimestampRejected,
}

/// <summary>A signing failure with a machine-readable reason.</summary>
internal sealed class CmsSigningException : Exception
{
    public CmsSigningException(CmsSigningError reason, string message)
        : base(message)
    {
        Reason = reason;
    }

    public CmsSigningException(CmsSigningError reason, string message, Exception? innerException)
        : base(message, innerException)
    {
        Reason = reason;
    }

    public CmsSigningError Reason { get; }
}

/// <summary>
/// Makes the CMS for one signature: signed attributes, the signature value (from a local key or an external signer, always checked
/// with the certificate's public key before use) and the optional time-stamp token. It needs only BCL hashing, RSA and ECDSA.
/// </summary>
internal sealed class CmsSigner
{
    private readonly CmsSigningCredential _credential;
    private readonly int _keyBits;

    private CmsSigner(CmsSigningCredential credential, CmsKeyType keyType, int keyBits, HashAlgorithmName hash, CmsRsaPadding padding, bool cades)
    {
        _credential = credential;
        KeyType = keyType;
        _keyBits = keyBits;
        Hash = hash;
        Padding = padding;
        Cades = cades;
    }

    public CmsKeyType KeyType { get; }

    public HashAlgorithmName Hash { get; }

    public CmsRsaPadding Padding { get; }

    public bool Cades { get; }

    public X509Certificate2 Certificate => _credential.Certificate;

    /// <summary>Checks the credential against the options before anything in the document is touched.</summary>
    public static CmsSigner Create(CmsSigningCredential credential, HashAlgorithmName hash, CmsRsaPadding padding, bool cades)
    {
        if (hash != HashAlgorithmName.SHA256 && hash != HashAlgorithmName.SHA384 && hash != HashAlgorithmName.SHA512)
        {
            throw new CmsSigningException(CmsSigningError.UnsupportedAlgorithm, "The digest must be SHA-256, SHA-384 or SHA-512.");
        }

        X509Certificate2 cert = credential.Certificate;
        // Certificate bytes can be accepted and only fail when read (macOS); find out now, before the document is touched.
        bool readable = CmsSignerVerifier.CertPool.IsUsable(cert);
        foreach (X509Certificate2 c in credential.Chain)
        {
            readable &= CmsSignerVerifier.CertPool.IsUsable(c);
        }

        if (!readable)
        {
            throw new CmsSigningException(CmsSigningError.UnsupportedAlgorithm, "The signer certificate or a chain certificate is damaged and cannot be read.");
        }

        CmsKeyType type;
        int bits;
        using (RSA? rsa = cert.GetRSAPublicKey())
        {
            if (rsa is not null)
            {
                type = CmsKeyType.Rsa;
                bits = rsa.KeySize;
            }
            else
            {
                using ECDsa? ec = cert.GetECDsaPublicKey();
                if (ec is null)
                {
                    throw new CmsSigningException(CmsSigningError.UnsupportedAlgorithm, "Only RSA and ECDSA certificates can sign.");
                }

                type = CmsKeyType.Ecdsa;
                bits = ec.KeySize;
            }
        }

        if (credential.External is null)
        {
            bool usable = false;
            try
            {
                if (cert.HasPrivateKey && type == CmsKeyType.Rsa)
                {
                    using RSA? key = cert.GetRSAPrivateKey();
                    usable = key is not null;
                }
                else if (cert.HasPrivateKey)
                {
                    using ECDsa? key = cert.GetECDsaPrivateKey();
                    usable = key is not null;
                }
            }
            catch (CryptographicException)
            {
                usable = false;
            }

            if (!usable)
            {
                throw new CmsSigningException(CmsSigningError.NoPrivateKey, "The signer certificate has no private key available; supply a certificate with its key or an external signer.");
            }
        }

        return new CmsSigner(credential, type, bits, hash, padding, cades);
    }

    /// <summary>A generous guess of the DER size of the CMS, so that a container can reserve room for it.</summary>
    public int EstimateBytes(bool withTimestamp)
    {
        long total = 1800;
        total += _credential.Certificate.RawData.Length;
        foreach (X509Certificate2 c in _credential.Chain)
        {
            total += c.RawData.Length;
        }

        total += KeyType == CmsKeyType.Rsa ? (_keyBits + 7) / 8 : (2 * ((_keyBits + 7) / 8)) + 16;
        total += withTimestamp ? 8192 : 0;
        return (int)Math.Min(total, 1 << 22);
    }

    /// <summary>
    /// Builds the CMS over <paramref name="contentDigest"/> (the digest of the signed content in <see cref="Hash"/>).
    /// <paramref name="timestamp"/>, when given, is asked for a token over the signature value.
    /// </summary>
    public byte[] Build(byte[] contentDigest, DateTimeOffset signingTime, CmsTimestampCallback? timestamp, CancellationToken ct)
    {
        byte[] attrs = CmsWriter.SignedAttributes(contentDigest, Certificate, Cades, Cades ? null : signingTime);
        byte[] signature = SignAttributes(attrs);
        ct.ThrowIfCancellationRequested();
        byte[]? token = null;
        if (timestamp is not null)
        {
            token = RequestToken(timestamp, SignatureHash(signature), Hash);
        }

        byte[] algorithm = CmsWriter.SignatureAlgorithm(KeyType, Padding, Hash);
        return CmsWriter.SignedData(Hash, Certificate, _credential.Chain, attrs, algorithm, signature, token);
    }

    private byte[] SignatureHash(byte[] signature) => CryptographicOperations.HashData(Hash, signature);

    /// <summary>Gets a token for <paramref name="imprint"/> (computed with <paramref name="hash"/>) and checks it.</summary>
    public static byte[] RequestToken(CmsTimestampCallback callback, byte[] imprint, HashAlgorithmName hash)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(8);
        nonce[0] &= 0x7F;
        nonce[0] |= 0x01;
        byte[] request = Rfc3161.BuildRequest(hash, imprint, nonce);
        byte[] response = callback(new CmsTimestampRequest(hash, imprint, nonce, request))
            ?? throw new CmsSigningException(CmsSigningError.TimestampRejected, "The time-stamp callback returned null.");
        if (!Rfc3161.TryExtractToken(response, hash, imprint, nonce, out byte[] token, out string error))
        {
            throw new CmsSigningException(CmsSigningError.TimestampRejected, error);
        }

        return token;
    }

    private byte[] SignAttributes(byte[] attributes)
    {
        try
        {
            byte[] signature;
            if (_credential.External is { } external)
            {
                byte[] digest = CryptographicOperations.HashData(Hash, attributes);
                byte[] raw = external(new CmsSignRequest(digest, Hash, KeyType, Padding))
                    ?? throw new CmsSigningException(CmsSigningError.SignerFailed, "The external signer returned null.");
                signature = KeyType == CmsKeyType.Ecdsa ? EcdsaToDer(raw) : raw;
            }
            else if (KeyType == CmsKeyType.Rsa)
            {
                using RSA rsa = Certificate.GetRSAPrivateKey()!;
                signature = rsa.SignData(attributes, Hash, ToBcl(Padding));
            }
            else
            {
                using ECDsa ec = Certificate.GetECDsaPrivateKey()!;
                signature = ec.SignData(attributes, Hash, DSASignatureFormat.Rfc3279DerSequence);
            }

            if (!VerifyOwn(attributes, signature))
            {
                throw new CmsSigningException(CmsSigningError.SignerFailed, "The signature value does not verify with the signer certificate's public key.");
            }

            return signature;
        }
        catch (CryptographicException e)
        {
            throw new CmsSigningException(CmsSigningError.SignerFailed, "The signing key failed: " + e.Message, e);
        }
    }

    private bool VerifyOwn(byte[] attributes, byte[] signature)
    {
        try
        {
            if (KeyType == CmsKeyType.Rsa)
            {
                using RSA rsa = Certificate.GetRSAPublicKey()!;
                return rsa.VerifyData(attributes, signature, Hash, ToBcl(Padding));
            }

            using ECDsa ec = Certificate.GetECDsaPublicKey()!;
            return ec.VerifyData(attributes, signature, Hash, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static RSASignaturePadding ToBcl(CmsRsaPadding p) => p == CmsRsaPadding.Pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

    // An external ECDSA signer may return the DER Ecdsa-Sig-Value or the IEEE P1363 pair r||s (as HSMs and PKCS#11 do).
    private byte[] EcdsaToDer(byte[] raw)
    {
        int coordinate = (_keyBits + 7) / 8;
        if (raw.Length == 2 * coordinate)
        {
            return DerWriter.Sequence(DerWriter.UnsignedInteger(raw.AsSpan(0, coordinate)), DerWriter.UnsignedInteger(raw.AsSpan(coordinate)));
        }

        return raw;
    }
}
