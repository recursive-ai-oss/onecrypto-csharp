using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// A private key (or secret) that can open recipient infos. The base class is the seam for key backends: a backend overrides only the
/// operations its key supports; each returns null when the key cannot do that or the operation fails, so callers never learn why.
/// </summary>
public abstract class CmsDecryptionKey : IDisposable
{
    /// <summary>Lets derived classes be created.</summary>
    protected CmsDecryptionKey()
    {
    }

    /// <summary>The recipient's certificate, used to pick the recipient infos meant for this key. When null every matching kind is tried.</summary>
    public virtual Certificate? Certificate => null;

    /// <summary>Decrypts a key-transport <c>EncryptedKey</c> (RSA PKCS #1 v1.5 or OAEP, as the algorithm says); null on failure or when this key is not an RSA key.</summary>
    public virtual byte[]? UnwrapKeyTransport(AlgorithmIdentifier keyEncryptionAlgorithm, ReadOnlySpan<byte> encryptedKey) => null;

    /// <summary>Computes the key-agreement secret with the originator's ephemeral public key (ECDH, X25519 or X448); null on failure or when not applicable.</summary>
    public virtual byte[]? DeriveAgreementSecret(PublicKeyInfo originator) => null;

    /// <summary>Decapsulates a KEM ciphertext (ML-KEM); null on failure or when not applicable.</summary>
    public virtual byte[]? Decapsulate(AlgorithmIdentifier kem, ReadOnlySpan<byte> ciphertext) => null;

    /// <summary>The shared key-encryption key named by <paramref name="keyIdentifier"/>, or null when this object does not hold it.</summary>
    public virtual byte[]? GetKeyEncryptionKey(ReadOnlySpan<byte> keyIdentifier) => null;

    /// <summary>Derives a PBKDF2 key from the password, or null when this object is not a password.</summary>
    public virtual byte[]? DerivePasswordKey(ReadOnlySpan<byte> salt, int iterations, HashAlgorithmName prf, int length) => null;

    /// <summary>Releases the key material.</summary>
    protected virtual void Dispose(bool disposing)
    {
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>An RSA key; the key stays owned by the caller.</summary>
    public static CmsDecryptionKey FromRsa(RSA key, Certificate? certificate = null) => new RsaKey(key, certificate);

    /// <summary>An ECDH key on a NIST or Brainpool curve; the key stays owned by the caller.</summary>
    public static CmsDecryptionKey FromECDiffieHellman(ECDiffieHellman key, Certificate? certificate = null) => new EcdhKey(key, certificate);

    /// <summary>An X25519 private key (32 octets); the octets are copied.</summary>
    public static CmsDecryptionKey FromX25519(ReadOnlySpan<byte> privateKey, Certificate? certificate = null) => new XKey(privateKey, false, certificate);

    /// <summary>An X448 private key (56 octets); the octets are copied.</summary>
    public static CmsDecryptionKey FromX448(ReadOnlySpan<byte> privateKey, Certificate? certificate = null) => new XKey(privateKey, true, certificate);

    /// <summary>An ML-KEM private key; the key stays owned by the caller.</summary>
    public static CmsDecryptionKey FromMLKem(MLKem key, Certificate? certificate = null) => new MlKemKey(key, certificate);

    /// <summary>A symmetric key-encryption key and the identifier senders name it by.</summary>
    public static CmsDecryptionKey FromKeyEncryptionKey(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> keyIdentifier) => new KekKey(kek, keyIdentifier);

    /// <summary>A password (UTF-8) for password recipient infos.</summary>
    public static CmsDecryptionKey FromPassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return new PasswordKey(System.Text.Encoding.UTF8.GetBytes(password));
    }

    private abstract class WithCertificate : CmsDecryptionKey
    {
        private readonly Certificate? _cert;

        protected WithCertificate(Certificate? cert) => _cert = cert;

        public override Certificate? Certificate => _cert;
    }

    private sealed class RsaKey : WithCertificate
    {
        private readonly RSA _key;

        public RsaKey(RSA key, Certificate? cert)
            : base(cert)
        {
            ArgumentNullException.ThrowIfNull(key);
            _key = key;
        }

        public override byte[]? UnwrapKeyTransport(AlgorithmIdentifier keyEncryptionAlgorithm, ReadOnlySpan<byte> encryptedKey)
        {
            try
            {
                if (keyEncryptionAlgorithm.Oid == KnownOids.RsaEncryption)
                {
                    return _key.Decrypt(encryptedKey, RSAEncryptionPadding.Pkcs1);
                }

                if (keyEncryptionAlgorithm.Oid == KnownOids.RsaOaep && OaepPadding(keyEncryptionAlgorithm) is { } padding)
                {
                    return _key.Decrypt(encryptedKey, padding);
                }
            }
            catch (CryptographicException)
            {
                // Padding errors are folded into "no key" so the caller cannot tell which check failed (RFC 3218 §2.3).
            }

            return null;
        }
    }

    internal static RSAEncryptionPadding? OaepPadding(AlgorithmIdentifier alg)
    {
        string hash = KnownOids.Sha1, mgfHash = KnownOids.Sha1;
        try
        {
            if (!alg.Parameters.IsEmpty)
            {
                var r = new Asn1Reader(alg.Parameters.Span, Asn1Rules.Ber);
                Asn1Reader s = r.ReadSequence();
                if (s.HasData && s.PeekTag() == Asn1Tag.Context(0))
                {
                    Asn1Reader w = s.ReadSequence(Asn1Tag.Context(0, true));
                    hash = AlgorithmIdentifier.Parse(w.ReadEncodedValue().ToArray()).Oid;
                }

                if (s.HasData && s.PeekTag() == Asn1Tag.Context(1))
                {
                    Asn1Reader w = s.ReadSequence(Asn1Tag.Context(1, true));
                    AlgorithmIdentifier mgf = AlgorithmIdentifier.Parse(w.ReadEncodedValue().ToArray());
                    mgfHash = mgf.Oid == KnownOids.Mgf1 ? AlgorithmIdentifier.Parse(mgf.Parameters).Oid : string.Empty;
                }

                if (s.HasData && s.PeekTag() == Asn1Tag.Context(2))
                {
                    // pSourceFunc: only the empty label is available on the platform.
                    Asn1Reader w = s.ReadSequence(Asn1Tag.Context(2, true));
                    AlgorithmIdentifier src = AlgorithmIdentifier.Parse(w.ReadEncodedValue().ToArray());
                    if (src.Oid != "1.2.840.113549.1.1.9")
                    {
                        return null;
                    }

                    var label = new Asn1Reader(src.Parameters.Span, Asn1Rules.Ber);
                    if (label.ReadOctetString().Length != 0)
                    {
                        return null;
                    }
                }
            }
        }
        catch (Exception e) when (e is Asn1ParseException or X509ParseException)
        {
            return null;
        }

        // The platform pairs MGF1 with the same hash as the label hash.
        if (hash != mgfHash)
        {
            return null;
        }

        return hash switch
        {
            KnownOids.Sha1 => RSAEncryptionPadding.OaepSHA1,
            KnownOids.Sha256 => RSAEncryptionPadding.OaepSHA256,
            KnownOids.Sha384 => RSAEncryptionPadding.OaepSHA384,
            KnownOids.Sha512 => RSAEncryptionPadding.OaepSHA512,
            _ => null,
        };
    }

    private sealed class EcdhKey : WithCertificate
    {
        private readonly ECDiffieHellman _key;

        public EcdhKey(ECDiffieHellman key, Certificate? cert)
            : base(cert)
        {
            ArgumentNullException.ThrowIfNull(key);
            _key = key;
        }

        public override byte[]? DeriveAgreementSecret(PublicKeyInfo originator)
        {
            try
            {
                if (originator.KeyAlgorithm != KeyAlgorithm.EllipticCurve)
                {
                    return null;
                }

                using ECDiffieHellman peer = ECDiffieHellman.Create();
                peer.ImportSubjectPublicKeyInfo(originator.Encoded.Span, out _);
                return _key.DeriveRawSecretAgreement(peer.PublicKey);
            }
            catch (CryptographicException)
            {
                return null;
            }
        }
    }

    private sealed class XKey : WithCertificate
    {
        private readonly PinnedSecret _key;
        private readonly bool _x448;

        public XKey(ReadOnlySpan<byte> key, bool x448, Certificate? cert)
            : base(cert)
        {
            if (key.Length != (x448 ? 56 : 32))
            {
                throw new ArgumentException("The private key has the wrong length.", nameof(key));
            }

            _key = new PinnedSecret(key);
            _x448 = x448;
        }

        public override byte[]? DeriveAgreementSecret(PublicKeyInfo originator)
        {
            if (originator.KeyAlgorithm != (_x448 ? KeyAlgorithm.X448 : KeyAlgorithm.X25519))
            {
                return null;
            }

            ReadOnlySpan<byte> peer = originator.KeyBits.Span;
            byte[] z = new byte[_x448 ? 56 : 32];
            if (peer.Length != z.Length)
            {
                return null;
            }

            bool ok = _x448 ? X448.TryDeriveSharedSecret(_key.ReadOnlySpan, peer, z) : X25519.TryDeriveSharedSecret(_key.ReadOnlySpan, peer, z);
            return ok ? z : null;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _key.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private sealed class MlKemKey : WithCertificate
    {
        private readonly MLKem _key;

        public MlKemKey(MLKem key, Certificate? cert)
            : base(cert)
        {
            ArgumentNullException.ThrowIfNull(key);
            _key = key;
        }

        public override byte[]? Decapsulate(AlgorithmIdentifier kem, ReadOnlySpan<byte> ciphertext)
        {
            try
            {
                string oid = _key.Algorithm.Name switch { "ML-KEM-512" => KnownOids.MlKem512, "ML-KEM-768" => KnownOids.MlKem768, _ => KnownOids.MlKem1024 };
                return kem.Oid == oid ? _key.Decapsulate(ciphertext.ToArray()) : null;
            }
            catch (CryptographicException)
            {
                return null;
            }
        }
    }

    private sealed class KekKey : CmsDecryptionKey
    {
        private readonly PinnedSecret _kek;
        private readonly byte[] _id;

        public KekKey(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> id)
        {
            _kek = new PinnedSecret(kek);
            _id = id.ToArray();
        }

        public override byte[]? GetKeyEncryptionKey(ReadOnlySpan<byte> keyIdentifier) => keyIdentifier.SequenceEqual(_id) ? _kek.ReadOnlySpan.ToArray() : null;

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _kek.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private sealed class PasswordKey : CmsDecryptionKey
    {
        private readonly PinnedSecret _password;

        public PasswordKey(byte[] password)
        {
            _password = new PinnedSecret(password);
            CryptographicOperations.ZeroMemory(password);
        }

        public override byte[]? DerivePasswordKey(ReadOnlySpan<byte> salt, int iterations, HashAlgorithmName prf, int length) =>
            Rfc2898DeriveBytes.Pbkdf2(_password.ReadOnlySpan, salt, iterations, prf, length);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _password.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}

/// <summary>How RSA key transport encrypts the content-encryption key.</summary>
public enum KeyTransportScheme
{
    /// <summary>RSAES-OAEP with SHA-256 and MGF1-SHA-256 (RFC 8017 §7.1, RFC 3560). The default.</summary>
    OaepSha256,

    /// <summary>RSAES-OAEP with SHA-1.</summary>
    OaepSha1,

    /// <summary>RSAES-OAEP with SHA-384.</summary>
    OaepSha384,

    /// <summary>RSAES-OAEP with SHA-512.</summary>
    OaepSha512,

    /// <summary>RSAES-PKCS1-v1_5 (RFC 8017 §7.2). Legacy: it can be read, but writing it needs <see cref="CmsEncryptOptions.AllowLegacy"/>.</summary>
    Pkcs1V15,
}

/// <summary>
/// One recipient of an encrypted message: the way the content-encryption key reaches them. Use the factory methods; the key-transport,
/// key-agreement, key-encryption-key, password and KEM forms are all here.
/// </summary>
public abstract class CmsRecipient
{
    private protected CmsRecipient()
    {
    }

    /// <summary>The structure's version in a RecipientInfo, which feeds the message version.</summary>
    internal abstract int Version { get; }

    internal virtual bool IsLegacy => false;

    /// <summary>Wraps <paramref name="cek"/> for this recipient and returns the RecipientInfo element.</summary>
    internal abstract byte[] Build(ReadOnlySpan<byte> cek);

    /// <summary>RSA key transport to the certificate's key.</summary>
    public static CmsRecipient KeyTransport(Certificate certificate, KeyTransportScheme scheme = KeyTransportScheme.OaepSha256, CmsIdentifierKind identifier = CmsIdentifierKind.IssuerAndSerialNumber)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new KeyTransportRecipient(certificate, scheme, identifier);
    }

    /// <summary>Ephemeral-static key agreement with the certificate's EC (P-256, P-384, P-521), X25519 or X448 key; the key-encryption key is AES key wrap.</summary>
    public static CmsRecipient KeyAgreement(Certificate certificate, CmsIdentifierKind identifier = CmsIdentifierKind.IssuerAndSerialNumber)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new KeyAgreementRecipient(certificate, identifier);
    }

    /// <summary>A shared key-encryption key (16, 24 or 32 octets) known by <paramref name="keyIdentifier"/>.</summary>
    public static CmsRecipient KeyEncryptionKey(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> keyIdentifier)
    {
        _ = CmsCiphers.WrapOid(kek.Length);
        return new KekRecipient(kek.ToArray(), keyIdentifier.ToArray());
    }

    /// <summary>A password: PBKDF2-HMAC-SHA-256 derives the key-encryption key (RFC 3211, RFC 8018).</summary>
    /// <param name="password">The password; it is encoded as UTF-8.</param>
    /// <param name="iterations">PBKDF2 iterations (default 600,000).</param>
    public static CmsRecipient Password(string password, int iterations = 600_000)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1000);
        return new PasswordRecipient(System.Text.Encoding.UTF8.GetBytes(password), iterations);
    }

    /// <summary>An ML-KEM recipient (RFC 9629, RFC 9936): the certificate carries an ML-KEM public key. KEK derivation is HKDF-SHA-256 and the key wrap AES-256.</summary>
    public static CmsRecipient Kem(Certificate certificate, CmsIdentifierKind identifier = CmsIdentifierKind.IssuerAndSerialNumber)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new KemRecipient(certificate, identifier);
    }

    private static byte[] Octets(byte[] v) => DerWriter.OctetString(v);

    private sealed class KeyTransportRecipient : CmsRecipient
    {
        private readonly Certificate _cert;
        private readonly KeyTransportScheme _scheme;
        private readonly CmsIdentifierKind _kind;

        public KeyTransportRecipient(Certificate cert, KeyTransportScheme scheme, CmsIdentifierKind kind)
        {
            _cert = cert;
            _scheme = scheme;
            _kind = kind;
        }

        internal override int Version => _kind == CmsIdentifierKind.SubjectKeyIdentifier ? 2 : 0;

        internal override bool IsLegacy => _scheme == KeyTransportScheme.Pkcs1V15;

        internal override byte[] Build(ReadOnlySpan<byte> cek)
        {
            if (_cert.PublicKey.KeyAlgorithm is not (KeyAlgorithm.Rsa or KeyAlgorithm.RsaOaep))
            {
                throw new ArgumentException("Key transport needs an RSA certificate.");
            }

            using RSA rsa = _cert.PublicKey.ToRsa();
            AlgorithmIdentifier alg;
            byte[] encrypted;
            if (_scheme == KeyTransportScheme.Pkcs1V15)
            {
                alg = AlgorithmIdentifier.WithNull(KnownOids.RsaEncryption);
                encrypted = rsa.Encrypt(cek, RSAEncryptionPadding.Pkcs1);
            }
            else
            {
                (string hashOid, RSAEncryptionPadding padding) = _scheme switch
                {
                    KeyTransportScheme.OaepSha1 => (KnownOids.Sha1, RSAEncryptionPadding.OaepSHA1),
                    KeyTransportScheme.OaepSha384 => (KnownOids.Sha384, RSAEncryptionPadding.OaepSHA384),
                    KeyTransportScheme.OaepSha512 => (KnownOids.Sha512, RSAEncryptionPadding.OaepSHA512),
                    _ => (KnownOids.Sha256, RSAEncryptionPadding.OaepSHA256),
                };
                // RFC 4055 §4.1: RSAES-OAEP-params with the hash and MGF1 on the same hash; the label is the default (empty).
                byte[] hash = AlgorithmIdentifier.WithNull(hashOid).Encoded.ToArray();
                byte[] mgf = DerWriter.Sequence(DerWriter.Oid(KnownOids.Mgf1), hash);
                alg = AlgorithmIdentifier.Create(KnownOids.RsaOaep, DerWriter.Sequence(DerWriter.Context(0, hash), DerWriter.Context(1, mgf)));
                encrypted = rsa.Encrypt(cek, padding);
            }

            return DerWriter.Sequence(DerWriter.SignedInteger(Version), CmsIdentifier.ForCertificate(_cert, _kind).Encoded.ToArray(), alg.Encoded.ToArray(), Octets(encrypted));
        }
    }

    private sealed class KeyAgreementRecipient : CmsRecipient
    {
        private readonly Certificate _cert;
        private readonly CmsIdentifierKind _kind;

        public KeyAgreementRecipient(Certificate cert, CmsIdentifierKind kind)
        {
            _cert = cert;
            _kind = kind;
        }

        internal override int Version => 3;

        internal override byte[] Build(ReadOnlySpan<byte> cek)
        {
            PublicKeyInfo pub = _cert.PublicKey;
            byte[] z;
            byte[] originatorSpki;
            string scheme;
            switch (pub.KeyAlgorithm)
            {
                case KeyAlgorithm.EllipticCurve:
                    {
                        // RFC 5753 §7.1.1: the KDF hash follows the curve's strength.
                        scheme = pub.KeySizeBits <= 256 ? CmsOids.StdDhSha256Kdf : pub.KeySizeBits <= 384 ? CmsOids.StdDhSha384Kdf : CmsOids.StdDhSha512Kdf;
                        using ECDiffieHellman peer = ECDiffieHellman.Create();
                        peer.ImportSubjectPublicKeyInfo(pub.Encoded.Span, out _);
                        using ECDiffieHellman eph = ECDiffieHellman.Create(peer.ExportParameters(false).Curve);
                        z = eph.DeriveRawSecretAgreement(peer.PublicKey);
                        originatorSpki = eph.ExportSubjectPublicKeyInfo();
                        break;
                    }

                case KeyAlgorithm.X25519:
                    {
                        scheme = CmsOids.StdDhHkdfSha256;
                        byte[] priv = RandomNumberGenerator.GetBytes(32);
                        byte[] ours = new byte[32];
                        X25519.DerivePublicKey(priv, ours);
                        z = new byte[32];
                        if (!X25519.TryDeriveSharedSecret(priv, pub.KeyBits.Span, z))
                        {
                            throw new CryptographicException("The recipient's X25519 key is a low-order point.");
                        }

                        CryptographicOperations.ZeroMemory(priv);
                        originatorSpki = DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(KnownOids.X25519)), X509Signer.BitString(ours));
                        break;
                    }

                case KeyAlgorithm.X448:
                    {
                        scheme = CmsOids.StdDhHkdfSha512;
                        byte[] priv = RandomNumberGenerator.GetBytes(56);
                        byte[] ours = new byte[56];
                        X448.DerivePublicKey(priv, ours);
                        z = new byte[56];
                        if (!X448.TryDeriveSharedSecret(priv, pub.KeyBits.Span, z))
                        {
                            throw new CryptographicException("The recipient's X448 key is a low-order point.");
                        }

                        CryptographicOperations.ZeroMemory(priv);
                        originatorSpki = DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(KnownOids.X448)), X509Signer.BitString(ours));
                        break;
                    }

                default:
                    throw new ArgumentException("Key agreement needs an EC, X25519 or X448 certificate.");
            }

            AlgorithmIdentifier wrap = AlgorithmIdentifier.Create(CmsCiphers.WrapOid(cek.Length));
            byte[] kek = CmsCiphers.AgreementKek(scheme, z, wrap, default, cek.Length);
            byte[] wrapped = CmsCiphers.AesWrap(kek, cek);
            CryptographicOperations.ZeroMemory(kek);
            CryptographicOperations.ZeroMemory(z);

            byte[] rid = _kind == CmsIdentifierKind.SubjectKeyIdentifier
                ? DerWriter.Context(0, Octets(_cert.SubjectKeyIdentifier!.KeyIdentifier.ToArray()))
                : CmsIdentifier.ForCertificate(_cert).Encoded.ToArray();
            byte[] schemeAlg = AlgorithmIdentifier.Create(scheme, wrap.Encoded).Encoded.ToArray();
            return DerWriter.Context(1, DerWriter.SignedInteger(3), DerWriter.Context(0, DerWriter.Retag(originatorSpki, 0xA1)), schemeAlg, DerWriter.Sequence(DerWriter.Sequence(rid, Octets(wrapped))));
        }
    }

    private sealed class KekRecipient : CmsRecipient
    {
        private readonly byte[] _kek;
        private readonly byte[] _id;

        public KekRecipient(byte[] kek, byte[] id)
        {
            _kek = kek;
            _id = id;
        }

        internal override int Version => 4;

        internal override byte[] Build(ReadOnlySpan<byte> cek) => DerWriter.Context(2,
            DerWriter.SignedInteger(4),
            DerWriter.Sequence(Octets(_id)),
            DerWriter.Sequence(DerWriter.Oid(CmsCiphers.WrapOid(_kek.Length))),
            Octets(CmsCiphers.AesWrap(_kek, cek)));
    }

    private sealed class PasswordRecipient : CmsRecipient
    {
        private readonly byte[] _password;
        private readonly int _iterations;

        public PasswordRecipient(byte[] password, int iterations)
        {
            _password = password;
            _iterations = iterations;
        }

        internal override int Version => 0;

        internal override byte[] Build(ReadOnlySpan<byte> cek)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] iv = RandomNumberGenerator.GetBytes(16);
            byte[] kek = Rfc2898DeriveBytes.Pbkdf2(_password, salt, _iterations, HashAlgorithmName.SHA256, 32);
            byte[] wrapped = CmsCiphers.Rfc3211Wrap(kek, iv, cek);
            CryptographicOperations.ZeroMemory(kek);
            byte[] pbkdf2 = DerWriter.Sequence(Octets(salt), DerWriter.SignedInteger(_iterations), AlgorithmIdentifier.WithNull(CmsOids.HmacSha256).Encoded.ToArray());
            byte[] kdf = DerWriter.Sequence(DerWriter.Oid(CmsOids.Pbkdf2), pbkdf2);
            byte[] cbc = AlgorithmIdentifier.Create(CmsOids.Aes256Cbc, Octets(iv)).Encoded.ToArray();
            byte[] kea = DerWriter.Sequence(DerWriter.Oid(CmsOids.PwriKek), cbc);
            return DerWriter.Context(3, DerWriter.SignedInteger(0), DerWriter.Retag(kdf, 0xA0), kea, Octets(wrapped));
        }
    }

    private sealed class KemRecipient : CmsRecipient
    {
        private readonly Certificate _cert;
        private readonly CmsIdentifierKind _kind;

        public KemRecipient(Certificate cert, CmsIdentifierKind kind)
        {
            _cert = cert;
            _kind = kind;
        }

        internal override int Version => 0;

        internal override byte[] Build(ReadOnlySpan<byte> cek)
        {
            if (_cert.PublicKey.KeyAlgorithm != KeyAlgorithm.MlKem)
            {
                throw new ArgumentException("The certificate does not carry an ML-KEM key.");
            }

            if (!MLKem.IsSupported)
            {
                throw new PlatformNotSupportedException("ML-KEM is not available on this platform.");
            }

#pragma warning disable SYSLIB5006 // The platform ML-KEM key import is experimental; this is the only file that touches it, and results say preview.
            using MLKem kem = MLKem.ImportSubjectPublicKeyInfo(_cert.PublicKey.Encoded.Span);
#pragma warning restore SYSLIB5006
            kem.Encapsulate(out byte[] ciphertext, out byte[] secret);
            AlgorithmIdentifier wrap = AlgorithmIdentifier.Create(CmsOids.Aes256Wrap);
            byte[] kek = CmsCiphers.KemKek(CmsOids.HkdfSha256, secret, wrap, 32, default);
            byte[] wrapped = CmsCiphers.AesWrap(kek, cek);
            CryptographicOperations.ZeroMemory(kek);
            CryptographicOperations.ZeroMemory(secret);
            byte[] body = DerWriter.Sequence(
                DerWriter.SignedInteger(0),
                CmsIdentifier.ForCertificate(_cert, _kind).Encoded.ToArray(),
                AlgorithmIdentifier.Create(_cert.PublicKey.Algorithm.Oid).Encoded.ToArray(),
                Octets(ciphertext),
                AlgorithmIdentifier.Create(CmsOids.HkdfSha256).Encoded.ToArray(),
                DerWriter.SignedInteger(32),
                wrap.Encoded.ToArray(),
                Octets(wrapped));
            return DerWriter.Context(4, DerWriter.Oid(CmsOids.OriKem), body);
        }
    }
}
