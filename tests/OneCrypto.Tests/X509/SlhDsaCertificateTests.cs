using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;

namespace OneCrypto.Tests.X509;

public class SlhDsaCertificateTests
{
    [Theory]
    [InlineData("SLH-DSA-SHA2-128f")]
    [InlineData("SLH-DSA-SHAKE-192f")]
    public void OpenSslSlhDsaCertificatesVerifyAsPreviewAndTamperedOnesAreRejected(string alg)
    {
        OpenSslTool.RequireOrSkip();
        Assert.SkipUnless(OpenSslTool.Has(alg), "openssl lacks the algorithm");
        string dir = OpenSslTool.TempDir("slh");
        string key = Path.Combine(dir, alg + ".key");
        string pem = Path.Combine(dir, alg + ".pem");
        Assert.Equal(0, OpenSslTool.Run("genpkey", "-algorithm", alg, "-out", key).Code);
        Assert.Equal(0, OpenSslTool.Run("req", "-x509", "-new", "-key", key, "-subj", "/CN=slh", "-days", "30", "-out", pem).Code);
        Certificate cert = Certificate.FromPem(File.ReadAllText(pem));
        SignatureVerification v = cert.VerifySignature(cert.PublicKey);
        if (!PlatformHasSlhDsa())
        {
            Assert.Equal(SignatureStatus.AlgorithmNotSupported, v.Status);
            return;
        }

        Assert.True(v.IsValid, v.Reason);
        Assert.Contains("preview", v.Reference, StringComparison.Ordinal);
        byte[] bad = cert.Encoded.ToArray();
        bad[^5] ^= 1;
        Assert.Equal(SignatureStatus.Invalid, Certificate.Parse(bad).VerifySignature(cert.PublicKey).Status);
        bad = cert.Encoded.ToArray();
        bad[40] ^= 1; // inside the signed part
        Assert.False(Certificate.TryParse(bad, out Certificate? c) && c!.VerifySignature(cert.PublicKey).IsValid);
    }

#pragma warning disable SYSLIB5006 // Only asks whether the experimental platform type exists.
    private static bool PlatformHasSlhDsa() => SlhDsa.IsSupported;
#pragma warning restore SYSLIB5006
}
