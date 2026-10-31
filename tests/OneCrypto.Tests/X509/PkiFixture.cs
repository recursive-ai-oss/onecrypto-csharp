using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.X509;

/// <summary>A key kind the tests build chains with.</summary>
public enum KeyKind
{
    Rsa2048,
    RsaPss,
    EcP256,
    EcP384,
    MlDsa65,
}

/// <summary>Generated test keys and the certificates built from them. The keys exist only inside the test process.</summary>
internal sealed class TestKey : IDisposable
{
    private readonly IDisposable _key;

    public TestKey(KeyKind kind)
    {
        Kind = kind;
        switch (kind)
        {
            case KeyKind.Rsa2048:
            case KeyKind.RsaPss:
                var rsa = RSA.Create(2048);
                _key = rsa;
                Signer = X509Signer.FromRsa(rsa, HashAlgorithmName.SHA256, pss: kind == KeyKind.RsaPss);
                break;
            case KeyKind.EcP256:
                var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                _key = p256;
                Signer = X509Signer.FromECDsa(p256);
                break;
            case KeyKind.EcP384:
                var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
                _key = p384;
                Signer = X509Signer.FromECDsa(p384);
                break;
            default:
                var ml = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                _key = ml;
                Signer = X509Signer.FromMLDsa(ml);
                break;
        }
    }

    public KeyKind Kind { get; }

    /// <summary>The ECDSA key when this is an EC kind (so a test can hand it to openssl), otherwise null.</summary>
    public ECDsa? Ec => _key as ECDsa;

    public X509Signer Signer { get; }


    public static bool IsAvailable(KeyKind k) => k != KeyKind.MlDsa65 || MLDsa.IsSupported;

    public void Dispose() => _key.Dispose();
}

internal static class Pki
{
    public static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    public static Certificate Root(TestKey key, string cn = "Test Root CA") => CertificateBuilder.CreateSelfSigned(
        new CertificateOptions
        {
            Subject = DistinguishedName.Create((KnownOids.Organization, "OneCrypto Tests"), (KnownOids.CommonName, cn)),
            NotBefore = Now.AddDays(-1),
            NotAfter = Now.AddYears(10),
            Extensions =
            [
                Extension.Create(new BasicConstraints(true, null), critical: true),
                Extension.Create(new KeyUsageExtension(KeyUsages.KeyCertSign | KeyUsages.CrlSign), critical: true),
            ],
        },
        key.Signer);

    public static Certificate Leaf(TestKey subject, Certificate issuer, TestKey issuerKey, string cn = "leaf.example.test") => CertificateBuilder.Create(
        new CertificateOptions
        {
            Subject = DistinguishedName.Create((KnownOids.CommonName, cn)),
            PublicKey = subject.Signer.PublicKey,
            NotBefore = Now.AddDays(-1),
            NotAfter = Now.AddYears(1),
            Extensions =
            [
                Extension.Create(new BasicConstraints(false, null), critical: true),
                Extension.Create(new KeyUsageExtension(KeyUsages.DigitalSignature), critical: true),
                Extension.Create(new ExtendedKeyUsage([KnownOids.ServerAuth, KnownOids.ClientAuth]), critical: false),
                Extension.Create(new SubjectAlternativeName([GeneralName.Dns(cn), GeneralName.Email("ops@example.test"), GeneralName.FromIPAddress([192, 0, 2, 7])]), critical: false),
            ],
        },
        issuer,
        issuerKey.Signer);
}
