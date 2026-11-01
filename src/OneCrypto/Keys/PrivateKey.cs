using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Keys;

/// <summary>
/// Wraps private keys that live in memory or in the operating system behind the key interfaces. BCL keys stay inside their BCL handles: nothing here
/// exports key material. The library's own Ed25519, Ed448, X25519 and X448 keys sit in pinned buffers that are zeroed on dispose. A garbage-collected
/// runtime cannot promise that no other copy of a secret was ever made; this narrows the exposure and does not close it.
/// </summary>
/// <remarks>
/// <para>Ownership: every factory takes <c>ownsKey</c>. When true, disposing the returned key disposes the wrapped key; when false (the default for
/// keys the caller made) the caller still owns it and must keep it alive while the wrapper is in use. Keys obtained from the operating system are always owned.</para>
/// </remarks>
public static class PrivateKey
{
    /// <summary>Wraps an RSA private key: PKCS #1 v1.5 and PSS signatures (SHA-1, SHA-256, SHA-384, SHA-512), PKCS #1 v1.5 and OAEP decryption.</summary>
    public static IRsaKey FromRsa(RSA key, bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new RsaBackend(key, ownsKey);
    }

    /// <summary>Wraps an ECDSA private key (DER or P1363, SHA-1, SHA-256, SHA-384, SHA-512).</summary>
    public static ISigningKey FromECDsa(ECDsa key, bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new EcdsaBackend(key, ownsKey);
    }

    /// <summary>Wraps an ECDH private key: the raw shared secret is the x-coordinate (SEC 1 §3.3.1).</summary>
    public static IAgreementKey FromECDiffieHellman(ECDiffieHellman key, bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new EcdhBackend(key, ownsKey);
    }

    /// <summary>Wraps an ML-DSA private key (FIPS 204). Needs a platform with ML-DSA.</summary>
    public static ISigningKey FromMLDsa(MLDsa key, bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new MlDsaBackend(key, ownsKey);
    }

    /// <summary>Wraps an ML-KEM private key for decapsulation (FIPS 203). Needs a platform with ML-KEM.</summary>
    public static IDecryptionKey FromMLKem(MLKem key, bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new MlKemBackend(key, ownsKey);
    }

    /// <summary>Wraps one of the library's Ed25519 keys.</summary>
    public static ISigningKey FromEd25519(Ed25519PrivateKey key, bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new Ed25519Backend(key, ownsKey);
    }

    /// <summary>Wraps one of the library's Ed448 keys.</summary>
    public static ISigningKey FromEd448(Ed448PrivateKey key, bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new Ed448Backend(key, ownsKey);
    }

    /// <summary>Wraps one of the library's X25519 keys.</summary>
    public static IAgreementKey FromX25519(X25519PrivateKey key, bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new X25519Backend(key, ownsKey);
    }

    /// <summary>Wraps one of the library's X448 keys.</summary>
    public static IAgreementKey FromX448(X448PrivateKey key, bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new X448Backend(key, ownsKey);
    }

    /// <summary>
    /// The private key of a certificate the platform holds (a PFX loaded with its key, or an entry in the user's store or keychain). The key stays in the
    /// platform's handle, and the platform's own PIN or consent prompts, if any, are passed through to the user. The returned key owns its handle.
    /// </summary>
    /// <returns>An <see cref="IRsaKey"/> for RSA, an <see cref="ISigningKey"/> for ECDSA certificates.</returns>
    /// <exception cref="ArgumentException">The certificate has no private key, or its key type is not RSA or ECDSA.</exception>
    /// <exception cref="CryptographicException">The platform refused access to the key.</exception>
    public static IKey FromCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("The certificate has no private key.", nameof(certificate));
        }

        switch (Certificate.FromX509Certificate2(certificate).PublicKey.KeyAlgorithm)
        {
            case KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss:
                return new RsaBackend(certificate.GetRSAPrivateKey() ?? throw NoKey(), true);
            case KeyAlgorithm.EllipticCurve:
                return new EcdsaBackend(certificate.GetECDsaPrivateKey() ?? throw NoKey(), true);
            default:
                throw new ArgumentException("The certificate's key type has no operating-system backend here.", nameof(certificate));
        }
    }

    /// <summary>
    /// The signing key of a certificate the platform holds, typed so it can be assigned to <see cref="CmsSignerSpec.Key"/> or passed to a signing call without a cast.
    /// Everything <see cref="FromCertificate"/> says about the key holds here too: it stays in the platform's handle and the returned key owns it.
    /// </summary>
    /// <returns>An <see cref="IRsaKey"/> (also an <see cref="ISigningKey"/>) for RSA, an <see cref="ISigningKey"/> for ECDSA certificates.</returns>
    /// <exception cref="ArgumentException">The certificate has no private key, or its key type is not RSA or ECDSA.</exception>
    /// <exception cref="CryptographicException">The platform refused access to the key.</exception>
    public static ISigningKey SigningKeyFromCertificate(X509Certificate2 certificate) => (ISigningKey)FromCertificate(certificate);

    /// <summary>
    /// Like <see cref="TryFromStore"/>, typed as <see cref="ISigningKey"/>. Returns false when the store has no such certificate with a key.
    /// </summary>
    public static bool TrySigningKeyFromStore(Certificate certificate, out ISigningKey? key, StoreName storeName = StoreName.My, StoreLocation location = StoreLocation.CurrentUser)
    {
        bool found = TryFromStore(certificate, out IKey? any, storeName, location);
        key = (ISigningKey?)any;
        return found;
    }

    /// <summary>
    /// Finds the certificate in an operating-system store (by comparing its encoding) and returns its private key as <see cref="FromCertificate"/> does.
    /// Returns false when the store has no such certificate with a key. Reads only; never changes the store.
    /// </summary>
    public static bool TryFromStore(Certificate certificate, out IKey? key, StoreName storeName = StoreName.My, StoreLocation location = StoreLocation.CurrentUser)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        key = null;
        using var store = new X509Store(storeName, location);
        try
        {
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        }
        catch (CryptographicException)
        {
            return false; // the store does not exist
        }

        foreach (X509Certificate2 c in store.Certificates)
        {
            if (c.HasPrivateKey && c.RawDataMemory.Span.SequenceEqual(certificate.Encoded.Span))
            {
                try
                {
                    key = FromCertificate(c);
                    return true;
                }
                finally
                {
                    c.Dispose();
                }
            }

            c.Dispose();
        }

        return false;
    }

    private static CryptographicException NoKey() => new("The platform did not give out the certificate's private key.");

    private static PublicKeyInfo Ed(string oid, ReadOnlySpan<byte> pub) =>
        PublicKeyInfo.Parse(DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(oid)), DerWriter.Tlv(0x03, [0, .. pub])));

    // RFC 9881 section 4 and RFC 9935 section 4: the SPKI of an ML-DSA or ML-KEM key is the algorithm identifier with no parameters and the raw public key.
    private static PublicKeyInfo MlPublic(string name, ReadOnlySpan<byte> pub) => Ed(name switch
    {
        "ML-DSA-44" => KnownOids.MlDsa44,
        "ML-DSA-65" => KnownOids.MlDsa65,
        "ML-DSA-87" => KnownOids.MlDsa87,
        "ML-KEM-512" => KnownOids.MlKem512,
        "ML-KEM-768" => KnownOids.MlKem768,
        _ => KnownOids.MlKem1024,
    }, pub);

    private abstract class Backend<T> : IKey
        where T : class
    {
        private readonly bool _owns;
        private int _disposed;

        protected Backend(T key, bool owns, PublicKeyInfo pub, KeyCapabilities caps)
        {
            Key = key;
            _owns = owns;
            PublicKey = pub;
            Capabilities = caps;
        }

        protected T Key { get; }

        public PublicKeyInfo PublicKey { get; }

        public KeyCapabilities Capabilities { get; }

        protected void Live() => ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0 && _owns && Key is IDisposable d)
            {
                d.Dispose();
            }
        }
    }

    private static NotSupportedException NotThis(SignatureSpec spec, string key) => new($"A {key} key cannot sign with {spec}.");

    private static bool Sha(HashAlgorithmName h) => h == HashAlgorithmName.SHA1 || h == HashAlgorithmName.SHA256 || h == HashAlgorithmName.SHA384 || h == HashAlgorithmName.SHA512;

    private sealed class RsaBackend : Backend<RSA>, IRsaKey
    {
        public RsaBackend(RSA key, bool owns)
            : base(key, owns, PublicKeyInfo.FromAsymmetricAlgorithm(key), KeyCapabilities.Sign | KeyCapabilities.Decrypt)
        {
        }

        public SignatureSpec DefaultSpec => SignatureSpec.DefaultFor(PublicKey);

        public bool Supports(SignatureSpec spec) =>
            spec.Kind is SignatureKind.RsaPkcs1 or SignatureKind.RsaPss && Sha(spec.Hash)
            && (PublicKey.KeyAlgorithm != KeyAlgorithm.RsaPss || spec.Kind == SignatureKind.RsaPss);

        public bool Supports(DecryptionSpec spec) =>
            spec.Kind == DecryptionKind.RsaPkcs1 || (spec.Kind == DecryptionKind.RsaOaep && Sha(spec.Hash));

        private static RSASignaturePadding Pad(SignatureSpec s) => s.Kind == SignatureKind.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

        public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec)
        {
            Live();
            return Supports(spec) ? Key.SignData(data, spec.Hash, Pad(spec)) : throw NotThis(spec, "RSA");
        }

        public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec)
        {
            Live();
            if (!Supports(spec))
            {
                throw NotThis(spec, "RSA");
            }

            return digest.Length == SignatureSpec.DigestSize(spec.Hash) ? Key.SignHash(digest.ToArray(), spec.Hash, Pad(spec)) : throw new ArgumentException("The digest length does not match the hash.", nameof(digest));
        }

        public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, DecryptionSpec spec)
        {
            Live();
            if (!Supports(spec))
            {
                throw new NotSupportedException($"An RSA key cannot decrypt with {spec}.");
            }

            return Key.Decrypt(ciphertext, spec.Kind == DecryptionKind.RsaPkcs1 ? RSAEncryptionPadding.Pkcs1 : RSAEncryptionPadding.CreateOaep(spec.Hash));
        }
    }

    private sealed class EcdsaBackend : Backend<ECDsa>, ISigningKey
    {
        public EcdsaBackend(ECDsa key, bool owns)
            : base(key, owns, PublicKeyInfo.FromAsymmetricAlgorithm(key), KeyCapabilities.Sign)
        {
        }

        public SignatureSpec DefaultSpec => SignatureSpec.DefaultFor(PublicKey);

        public bool Supports(SignatureSpec spec) => spec.Kind == SignatureKind.Ecdsa && Sha(spec.Hash);

        private static DSASignatureFormat Fmt(SignatureSpec s) => s.Format == EcdsaSignatureFormat.Der ? DSASignatureFormat.Rfc3279DerSequence : DSASignatureFormat.IeeeP1363FixedFieldConcatenation;

        public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec)
        {
            Live();
            return Supports(spec) ? Key.SignData(data, spec.Hash, Fmt(spec)) : throw NotThis(spec, "ECDSA");
        }

        public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec)
        {
            Live();
            return Supports(spec) ? Key.SignHash(digest, Fmt(spec)) : throw NotThis(spec, "ECDSA");
        }
    }

    private sealed class EcdhBackend : Backend<ECDiffieHellman>, IAgreementKey
    {
        public EcdhBackend(ECDiffieHellman key, bool owns)
            : base(key, owns, PublicKeyInfo.FromAsymmetricAlgorithm(key), KeyCapabilities.Agree)
        {
        }

        public byte[] Agree(PublicKeyInfo peer)
        {
            Live();
            ArgumentNullException.ThrowIfNull(peer);
            if (peer.KeyAlgorithm != KeyAlgorithm.EllipticCurve || peer.CurveOid != PublicKey.CurveOid)
            {
                throw new ArgumentException("The peer's key is not an EC key on the same curve.", nameof(peer));
            }

            try
            {
                using ECDiffieHellman other = Platform.CreateEcdh("ECDH key agreement");
                other.ImportSubjectPublicKeyInfo(peer.Encoded.Span, out _);
                using ECDiffieHellmanPublicKey pub = other.PublicKey;
                return Key.DeriveRawSecretAgreement(pub);
            }
            catch (PlatformNotSupportedException e)
            {
                throw Internal.Platform.CurveNotSupported("ECDH key agreement", e);
            }
        }
    }

    private sealed class MlDsaBackend : Backend<MLDsa>, ISigningKey
    {
        public MlDsaBackend(MLDsa key, bool owns)
            : base(key, owns, MlPublic(key.Algorithm.Name, key.ExportMLDsaPublicKey()), KeyCapabilities.Sign)
        {
        }

        public SignatureSpec DefaultSpec => SignatureSpec.MlDsa();

        public bool Supports(SignatureSpec spec) => spec.Kind == SignatureKind.MlDsa;

        public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec)
        {
            Live();
            if (!Supports(spec))
            {
                throw NotThis(spec, "ML-DSA");
            }

            var sig = new byte[Key.Algorithm.SignatureSizeInBytes];
            Key.SignData(data, sig, spec.Context);
            return sig;
        }

        public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec) => throw new NotSupportedException("ML-DSA signs the message, not a digest.");
    }

    private sealed class MlKemBackend : Backend<MLKem>, IDecryptionKey
    {
        public MlKemBackend(MLKem key, bool owns)
            : base(key, owns, MlPublic(key.Algorithm.Name, key.ExportEncapsulationKey()), KeyCapabilities.Decrypt)
        {
        }

        public bool Supports(DecryptionSpec spec) => spec.Kind == DecryptionKind.MlKem;

        public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, DecryptionSpec spec)
        {
            Live();
            if (!Supports(spec))
            {
                throw new NotSupportedException($"An ML-KEM key cannot decrypt with {spec}.");
            }

            var secret = new byte[Key.Algorithm.SharedSecretSizeInBytes];
            Key.Decapsulate(ciphertext, secret);
            return secret;
        }
    }

    private abstract class EdBackend<T> : Backend<T>, ISigningKey
        where T : class
    {
        private readonly SignatureKind _kind;

        protected EdBackend(T key, bool owns, PublicKeyInfo pub, SignatureKind kind)
            : base(key, owns, pub, KeyCapabilities.Sign)
        {
            _kind = kind;
        }

        public SignatureSpec DefaultSpec => _kind == SignatureKind.Ed25519 ? SignatureSpec.Ed25519() : SignatureSpec.Ed448();

        public bool Supports(SignatureSpec spec) => spec.Kind == _kind;

        public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec) => throw new NotSupportedException("EdDSA signs the message, not a digest.");

        public abstract byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec);
    }

    private sealed class Ed25519Backend : EdBackend<Ed25519PrivateKey>
    {
        public Ed25519Backend(Ed25519PrivateKey key, bool owns)
            : base(key, owns, Ed(KnownOids.Ed25519, key.PublicKey.ToArray()), SignatureKind.Ed25519)
        {
        }

        public override byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec)
        {
            Live();
            if (!Supports(spec))
            {
                throw NotThis(spec, "Ed25519");
            }

            var sig = new byte[Ed25519.SignatureSize];
            return Key.TrySign(data, sig, out _) ? sig : throw new CryptographicException("Ed25519 signing failed.");
        }
    }

    private sealed class Ed448Backend : EdBackend<Ed448PrivateKey>
    {
        public Ed448Backend(Ed448PrivateKey key, bool owns)
            : base(key, owns, Ed(KnownOids.Ed448, key.PublicKey.ToArray()), SignatureKind.Ed448)
        {
        }

        public override byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec)
        {
            Live();
            if (!Supports(spec))
            {
                throw NotThis(spec, "Ed448");
            }

            var sig = new byte[Ed448.SignatureSize];
            return Key.TrySign(data, spec.Context, sig, out _) ? sig : throw new CryptographicException("Ed448 signing failed.");
        }
    }

    private sealed class X25519Backend : Backend<X25519PrivateKey>, IAgreementKey
    {
        public X25519Backend(X25519PrivateKey key, bool owns)
            : base(key, owns, Ed(KnownOids.X25519, key.PublicKey.ToArray()), KeyCapabilities.Agree)
        {
        }

        public byte[] Agree(PublicKeyInfo peer)
        {
            Live();
            ArgumentNullException.ThrowIfNull(peer);
            if (peer.KeyAlgorithm != KeyAlgorithm.X25519 || peer.KeyBits.Length != X25519.KeySize)
            {
                throw new ArgumentException("The peer's key is not an X25519 key.", nameof(peer));
            }

            var secret = new byte[X25519.KeySize];
            return Key.TryDeriveSharedSecret(X25519PublicKey.FromBytes(peer.KeyBits.Span), secret) ? secret : throw new CryptographicException("The X25519 shared secret is all zero (RFC 7748 §6.1).");
        }
    }

    private sealed class X448Backend : Backend<X448PrivateKey>, IAgreementKey
    {
        public X448Backend(X448PrivateKey key, bool owns)
            : base(key, owns, Ed(KnownOids.X448, key.PublicKey.ToArray()), KeyCapabilities.Agree)
        {
        }

        public byte[] Agree(PublicKeyInfo peer)
        {
            Live();
            ArgumentNullException.ThrowIfNull(peer);
            if (peer.KeyAlgorithm != KeyAlgorithm.X448 || peer.KeyBits.Length != X448.KeySize)
            {
                throw new ArgumentException("The peer's key is not an X448 key.", nameof(peer));
            }

            var secret = new byte[X448.KeySize];
            return Key.TryDeriveSharedSecret(X448PublicKey.FromBytes(peer.KeyBits.Span), secret) ? secret : throw new CryptographicException("The X448 shared secret is all zero (RFC 7748 §6.1).");
        }
    }
}
