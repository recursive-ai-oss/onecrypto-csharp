using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Pkcs;

namespace OneCrypto.Tests.Pkcs;

public class PqKeyTests
{
    [Fact]
    public void MLDsaAndMLKemKeysRoundTrip()
    {
        Assert.SkipUnless(MLDsa.IsSupported && MLKem.IsSupported, "the platform has no ML-DSA/ML-KEM");
        using MLDsa dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using PrivateKeyInfo k = PrivateKeyInfo.FromMLDsa(dsa);
        Assert.Equal(KeyAlgorithm.MlDsa, k.KeyAlgorithm);
        using MLDsa back = k.ToMLDsa();
        byte[] sig = back.SignData(new byte[] { 1, 2 });
        Assert.True(dsa.VerifyData(new byte[] { 1, 2 }, sig));
        Assert.Equal(KeyAlgorithm.MlDsa, k.GetPublicKey().KeyAlgorithm);

        using MLKem kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        using PrivateKeyInfo kk = PrivateKeyInfo.FromMLKem(kem);
        using MLKem kb = kk.ToMLKem();
        kem.Encapsulate(out byte[] ct, out byte[] secret);
        Assert.Equal(secret, kb.Decapsulate(ct));
    }

    [Theory]
    [InlineData("ML-DSA-65")]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void OpenSslPostQuantumKeysLoad(string algorithm)
    {
        OpenSslTool.RequireOrSkip();
        Assert.SkipUnless(OpenSslTool.Has(algorithm) && MLDsa.IsSupported && MLKem.IsSupported, "openssl or the platform lacks " + algorithm);
        string dir = ToolRunner.TempDir("pkcs8-pq");
        string key = Path.Combine(dir, "k.pem");
        Assert.Equal(0, OpenSslTool.Run("genpkey", "-algorithm", algorithm, "-out", key).Code);
        string spki = OpenSslTool.Run("pkey", "-in", key, "-pubout").Output.Replace("\r", string.Empty, StringComparison.Ordinal).Trim();
        using PrivateKeyInfo k = PrivateKeyInfo.FromPem(File.ReadAllText(key));
        Assert.Equal(spki, RecursiveAI.OneCrypto.Pem.PemCodec.Write("PUBLIC KEY", k.GetPublicKey().Encoded.Span).Trim());
    }
}
