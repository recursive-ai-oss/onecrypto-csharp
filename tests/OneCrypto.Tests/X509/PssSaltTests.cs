using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;

namespace OneCrypto.Tests.X509;

/// <summary>RSASSA-PSS certificates whose salt is not the digest length, or whose MGF1 hash differs from the signature hash, made by openssl.</summary>
public class PssSaltTests
{
    [Theory]
    [InlineData("sha384", "32", "sha384")]
    [InlineData("sha256", "20", "sha256")]
    [InlineData("sha256", "0", "sha256")]
    [InlineData("sha512", "64", "sha512")]
    [InlineData("sha384", "48", "sha256")]
    public void NonDefaultPssParametersVerify(string hash, string salt, string mgf)
    {
        OpenSslTool.RequireOrSkip();
        string dir = OpenSslTool.TempDir("pss-" + hash + salt + mgf);
        File.WriteAllText(Path.Combine(dir, "req.cnf"), "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=pss salt test\n");
        (int code, string output) = OpenSslTool.RunIn(dir, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem", "-days", "2", "-config", "req.cnf",
            "-" + hash, "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:" + salt, "-sigopt", "rsa_mgf1_md:" + mgf);
        Assert.True(code == 0, output);
        Certificate cert = Certificate.FromPem(File.ReadAllText(Path.Combine(dir, "c.pem")));
        Assert.Equal(KnownOids.RsaPss, cert.SignatureAlgorithm.Oid);
        SignatureVerification v = cert.VerifySignature(cert);
        Assert.True(v.IsValid, v.Reason);

        // One flipped bit in the signed part is caught.
        byte[] der = cert.Encoded.ToArray();
        der[40] ^= 1;
        if (Certificate.TryParse(der, out Certificate? bad))
        {
            Assert.False(bad!.VerifySignature(cert.PublicKey).IsValid);
        }
    }
}
