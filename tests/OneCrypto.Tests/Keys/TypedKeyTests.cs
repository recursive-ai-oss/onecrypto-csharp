using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Keys;

public class TypedKeyTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void AKeyFromACertificateGoesIntoASignerSpecWithoutACast()
    {
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=typed.test", ec, HashAlgorithmName.SHA256);
        using X509Certificate2 pfx = req.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(5));
        Certificate cert = Certificate.FromX509Certificate2(pfx);

        using ISigningKey key = PrivateKey.SigningKeyFromCertificate(pfx);
        var spec = new CmsSignerSpec { Certificate = cert, Key = key, SigningTime = Now };
        SignedData sd = SignedData.Create("hello"u8, [spec]);
        Assert.True(sd.Verify(new SignedDataVerifyOptions { ReferenceTime = Now }).Signers[0].IsValid);
    }

    [Fact]
    public void ARsaCertificateGivesAKeyThatIsAlsoAnRsaKey()
    {
        using RSA rsa = RSA.Create(2048);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=typed-rsa.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 pfx = req.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(5));
        using ISigningKey key = PrivateKey.SigningKeyFromCertificate(pfx);
        Assert.IsAssignableFrom<IRsaKey>(key);
        Assert.False(PrivateKey.TrySigningKeyFromStore(Certificate.FromX509Certificate2(pfx), out ISigningKey? none, StoreName.My, StoreLocation.CurrentUser) && none is null);
        none?.Dispose();
    }
}
