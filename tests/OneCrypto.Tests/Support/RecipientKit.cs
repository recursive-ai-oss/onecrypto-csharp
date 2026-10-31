using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Support;

/// <summary>The kinds of recipient key the encryption tests cover.</summary>
public enum RecipKind
{
    Rsa,
    P256,
    P384,
    X25519,
    X448,
    MlKem768,
}

/// <summary>A recipient's certificate with its private key in the forms the tests need.</summary>
internal sealed class RecipientKit
{
    private static readonly Dictionary<RecipKind, RecipientKit> Cache = [];

    private readonly Func<CmsDecryptionKey> _open;

    private RecipientKit(RecipKind kind, Certificate cert, Func<CmsDecryptionKey> open, string pkcs8Pem)
    {
        Kind = kind;
        Certificate = cert;
        _open = open;
        Pkcs8Pem = pkcs8Pem;
    }

    public RecipKind Kind { get; }

    public Certificate Certificate { get; }

    public string Pkcs8Pem { get; }

    public CmsDecryptionKey Key() => _open();

    public static bool IsAvailable(RecipKind k) => k != RecipKind.MlKem768 || MLKem.IsSupported;

    public static RecipientKit Get(RecipKind kind)
    {
        lock (Cache)
        {
            if (!Cache.TryGetValue(kind, out RecipientKit? kit))
            {
                kit = Create(kind);
                Cache[kind] = kit;
            }

            return kit;
        }
    }

    private static Certificate Issue(string cn, PublicKeyInfo key, KeyUsages usages)
    {
        SignerKit issuer = CmsKeys.Get(SigKind.P256);
        return CertificateBuilder.Create(
            new CertificateOptions
            {
                Subject = DistinguishedName.Create((KnownOids.Organization, "OneCrypto Tests"), (KnownOids.CommonName, cn)),
                PublicKey = key,
                NotBefore = CmsKeys.SigningTime.AddYears(-1),
                NotAfter = CmsKeys.SigningTime.AddYears(5),
                Extensions = [Extension.Create(new BasicConstraints(false, null), critical: true), Extension.Create(new KeyUsageExtension(usages), critical: true)],
            },
            issuer.Certificate,
            issuer.Signer);
    }

    private static string Pem(byte[] der) =>
        $"-----BEGIN PRIVATE KEY-----\n{Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)}\n-----END PRIVATE KEY-----\n";

    private static PublicKeyInfo Spki(string oid, byte[] key) =>
        PublicKeyInfo.Parse(DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(oid)), [0x03, (byte)(key.Length + 1), 0, .. key]));

    private static RecipientKit Create(RecipKind kind)
    {
        switch (kind)
        {
            case RecipKind.Rsa:
                {
                    var rsa = RSA.Create(2048);
                    Certificate c = Issue("Rita Recipient", PublicKeyInfo.Parse(rsa.ExportSubjectPublicKeyInfo()), KeyUsages.KeyEncipherment | KeyUsages.DataEncipherment);
                    return new RecipientKit(kind, c, () => CmsDecryptionKey.FromRsa(rsa, c), rsa.ExportPkcs8PrivateKeyPem());
                }

            case RecipKind.P256:
            case RecipKind.P384:
                {
                    var ec = ECDiffieHellman.Create(kind == RecipKind.P256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
                    Certificate c = Issue("Edna Recipient " + kind, PublicKeyInfo.Parse(ec.ExportSubjectPublicKeyInfo()), KeyUsages.KeyAgreement);
                    return new RecipientKit(kind, c, () => CmsDecryptionKey.FromECDiffieHellman(ec, c), ec.ExportPkcs8PrivateKeyPem());
                }

            case RecipKind.X25519:
                {
                    byte[] priv = RandomNumberGenerator.GetBytes(32);
                    byte[] pub = new byte[32];
                    X25519.DerivePublicKey(priv, pub);
                    Certificate c = Issue("Xavier Recipient", Spki(KnownOids.X25519, pub), KeyUsages.KeyAgreement);
                    return new RecipientKit(kind, c, () => CmsDecryptionKey.FromX25519(priv, c), Pem([.. Convert.FromHexString("302e020100300506032b656e04220420"), .. priv]));
                }

            case RecipKind.X448:
                {
                    byte[] priv = RandomNumberGenerator.GetBytes(56);
                    byte[] pub = new byte[56];
                    X448.DerivePublicKey(priv, pub);
                    Certificate c = Issue("Xena Recipient", Spki(KnownOids.X448, pub), KeyUsages.KeyAgreement);
                    return new RecipientKit(kind, c, () => CmsDecryptionKey.FromX448(priv, c), Pem([.. Convert.FromHexString("3046020100300506032b656f043a0438"), .. priv]));
                }

            default:
                {
#pragma warning disable SYSLIB5006 // ML-KEM key import and export are experimental in the platform; the tests use them to build keys.
                    var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
                    Certificate c = Issue("Mia Recipient", PublicKeyInfo.Parse(kem.ExportSubjectPublicKeyInfo()), KeyUsages.KeyEncipherment);
                    // RFC 9935: the seed-only private key form.
                    byte[] pkcs8 = [.. Convert.FromHexString("3054020100300b0609608648016503040402" + "04428040"), .. kem.ExportPrivateSeed()];
#pragma warning restore SYSLIB5006
                    return new RecipientKit(kind, c, () => CmsDecryptionKey.FromMLKem(kem, c), Pem(pkcs8));
                }
        }
    }
}
