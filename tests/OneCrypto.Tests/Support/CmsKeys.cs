using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Support;

/// <summary>The signature kinds the CMS tests run through.</summary>
public enum SigKind
{
    Rsa,
    RsaPss,
    P256,
    P384,
    P521,
    Ed25519,
    Ed448,
    MlDsa65,
}

/// <summary>A generated signing key with a self-signed certificate. The keys exist only inside the test process (and the openssl files a test writes).</summary>
internal sealed class SignerKit
{
    public SignerKit(SigKind kind, Certificate certificate, X509Signer signer, string pkcs8Pem)
    {
        Kind = kind;
        Certificate = certificate;
        Signer = signer;
        Pkcs8Pem = pkcs8Pem;
    }

    public SigKind Kind { get; }

    public Certificate Certificate { get; }

    public X509Signer Signer { get; }

    /// <summary>The private key as PKCS #8 PEM, for handing to openssl.</summary>
    public string Pkcs8Pem { get; }

    public CmsSignerSpec Spec(Action<CmsSignerSpecBuilder>? tweak = null)
    {
        var b = new CmsSignerSpecBuilder();
        tweak?.Invoke(b);
        return new CmsSignerSpec
        {
            Certificate = Certificate,
            Signer = Signer,
            Identifier = b.Identifier,
            DigestAlgorithm = b.DigestAlgorithm,
            SignedAttributes = b.SignedAttributes,
            SigningTime = b.SigningTime,
            SigningCertificate = b.SigningCertificate,
            AdditionalSignedAttributes = b.AdditionalSignedAttributes,
            UnsignedAttributes = b.UnsignedAttributes,
        };
    }
}

/// <summary>Mutable stand-in for the init-only <see cref="CmsSignerSpec"/> so tests can tweak one field.</summary>
internal sealed class CmsSignerSpecBuilder
{
    public CmsIdentifierKind Identifier { get; set; } = CmsIdentifierKind.IssuerAndSerialNumber;

    public string? DigestAlgorithm { get; set; }

    public bool SignedAttributes { get; set; } = true;

    public DateTimeOffset? SigningTime { get; set; } = CmsKeys.SigningTime;

    public EssSigningCertificate SigningCertificate { get; set; } = EssSigningCertificate.V2;

    public IReadOnlyList<CmsAttributeEntry> AdditionalSignedAttributes { get; set; } = [];

    public IReadOnlyList<CmsAttributeEntry> UnsignedAttributes { get; set; } = [];
}

internal static class CmsKeys
{
    public static readonly DateTimeOffset SigningTime = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    private static readonly Dictionary<SigKind, SignerKit> Cache = [];

    public static bool IsAvailable(SigKind k) => k != SigKind.MlDsa65 || MLDsa.IsSupported;

    public static SignerKit Get(SigKind kind)
    {
        lock (Cache)
        {
            if (!Cache.TryGetValue(kind, out SignerKit? kit))
            {
                kit = Create(kind);
                Cache[kind] = kit;
            }

            return kit;
        }
    }

    public static Certificate SelfSigned(string cn, X509Signer signer, KeyUsages usages = KeyUsages.DigitalSignature | KeyUsages.NonRepudiation, IEnumerable<string>? eku = null, RecursiveAI.OneCrypto.Policy.CryptoPolicy? policy = null)
    {
        var ext = new List<Extension>
        {
            Extension.Create(new BasicConstraints(false, null), critical: true),
            Extension.Create(new KeyUsageExtension(usages), critical: true),
        };
        if (eku is not null)
        {
            ext.Add(Extension.Create(new ExtendedKeyUsage([.. eku]), critical: false));
        }

        return CertificateBuilder.CreateSelfSigned(
            new CertificateOptions
            {
                Subject = DistinguishedName.Create((KnownOids.Organization, "OneCrypto Tests"), (KnownOids.CommonName, cn)),
                NotBefore = SigningTime.AddYears(-1),
                NotAfter = SigningTime.AddYears(5),
                Extensions = ext,
            },
            signer,
            policy);
    }

    private static string PemLabel(string label, byte[] der) =>
        $"-----BEGIN {label}-----\n{Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)}\n-----END {label}-----\n";

    private static SignerKit Create(SigKind kind)
    {
        switch (kind)
        {
            case SigKind.Rsa:
            case SigKind.RsaPss:
                {
                    var rsa = RSA.Create(2048);
                    X509Signer s = X509Signer.FromRsa(rsa, HashAlgorithmName.SHA256, pss: kind == SigKind.RsaPss);
                    return new SignerKit(kind, SelfSigned("Rita " + kind, s), s, rsa.ExportPkcs8PrivateKeyPem());
                }

            case SigKind.P256:
            case SigKind.P384:
            case SigKind.P521:
                {
                    var ec = ECDsa.Create(kind == SigKind.P256 ? ECCurve.NamedCurves.nistP256 : kind == SigKind.P384 ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP521);
                    X509Signer s = X509Signer.FromECDsa(ec);
                    return new SignerKit(kind, SelfSigned("Edna " + kind, s), s, ec.ExportPkcs8PrivateKeyPem());
                }

            case SigKind.MlDsa65:
                {
                    var ml = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                    X509Signer s = X509Signer.FromMLDsa(ml);
                    // RFC 9881 §6: the seed-only private key form, which the platform exports and openssl reads.
                    byte[] pkcs8 = [.. Convert.FromHexString("3034020100300b06096086480165030403120422802" + "0"), .. ml.ExportMLDsaPrivateSeed()];
                    return new SignerKit(kind, SelfSigned("Mia MLDSA", s), s, PemLabel("PRIVATE KEY", pkcs8));
                }

            case SigKind.Ed25519:
                {
                    byte[] seed = RandomNumberGenerator.GetBytes(32);
                    byte[] pub = new byte[32];
                    Ed25519.DerivePublicKey(seed, pub);
                    X509Signer s = X509Signer.FromDelegate(AlgorithmIdentifier.Create(KnownOids.Ed25519), SpkiOf(KnownOids.Ed25519, pub), m =>
                    {
                        byte[] sig = new byte[64];
                        Ed25519.TrySign(seed, m, sig, out _);
                        return sig;
                    });
                    byte[] pkcs8 = [.. Convert.FromHexString("302e020100300506032b657004220420"), .. seed];
                    return new SignerKit(kind, SelfSigned("Edgar Ed25519", s), s, PemLabel("PRIVATE KEY", pkcs8));
                }

            default:
                {
                    byte[] seed = RandomNumberGenerator.GetBytes(57);
                    byte[] pub = new byte[57];
                    Ed448.DerivePublicKey(seed, pub);
                    X509Signer s = X509Signer.FromDelegate(AlgorithmIdentifier.Create(KnownOids.Ed448), SpkiOf(KnownOids.Ed448, pub), m =>
                    {
                        byte[] sig = new byte[114];
                        Ed448.TrySign(seed, m, default, sig, out _);
                        return sig;
                    });
                    byte[] pkcs8 = [.. Convert.FromHexString("3047020100300506032b6571043b0439"), .. seed];
                    return new SignerKit(kind, SelfSigned("Edith Ed448", s), s, PemLabel("PRIVATE KEY", pkcs8));
                }
        }
    }

    private static PublicKeyInfo SpkiOf(string oid, byte[] key) =>
        PublicKeyInfo.Parse(DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(oid)), [0x03, (byte)(key.Length + 1), 0, .. key]));
}
