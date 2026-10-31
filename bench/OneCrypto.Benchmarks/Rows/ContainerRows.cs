using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Pkcs;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Pkcs;

namespace OneCrypto.Benchmarks;

/// <summary>A key and certificate, and the same material as PKCS#12 and encrypted PKCS#8 files with the profile OpenSSL writes by default (AES-256-CBC, PBKDF2-HMAC-SHA-256, 2048 iterations).</summary>
internal static class ContainerFixture
{
    public const string Password = "bench password";

    public static (byte[] Pfx, byte[] EncryptedPkcs8) Build(string kind)
    {
        using AsymmetricAlgorithm k = kind == "rsa2048" ? RSA.Create(2048) : ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = k is RSA r
            ? new CertificateRequest("CN=bench", r, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            : new CertificateRequest("CN=bench", (ECDsa)k, HashAlgorithmName.SHA256);
        using X509Certificate2 c = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using PrivateKeyInfo key = PrivateKeyInfo.FromAsymmetricAlgorithm(k);
        var pbe = new Pbes2Options { Iterations = 2048 };
        byte[] pfx = Pkcs12File.Create(key, Certificate.FromX509Certificate2(c), null, Password, "bench", new Pkcs12WriteOptions { Encryption = pbe, MacIterations = 2048 }).Encoded.ToArray();
        return (pfx, key.Encrypt(Password, pbe).Encoded.ToArray());
    }
}

/// <summary>
/// Load a PKCS#12 file: check the MAC, decrypt, and read the key and certificate. BouncyCastle's Pkcs12Store is the managed
/// comparator; the platform's X509CertificateLoader.LoadPkcs12 is native-backed and reported.
/// </summary>
[BenchmarkCategory("pkcs12-load")]
public class Pkcs12LoadRows
{
    private byte[] _pfx = [];

    /// <summary>Key type in the file.</summary>
    [Params("ec-p256", "rsa2048")]
    public string Kind { get; set; } = "ec-p256";

    [GlobalSetup]
    public void Setup() => _pfx = ContainerFixture.Build(Kind).Pfx;

    [Benchmark]
    public int Ours()
    {
        using Pkcs12Contents c = Pkcs12File.Parse(_pfx).Open(ContainerFixture.Password);
        return c.Certificates.Count + c.PrivateKeys[0].PrivateKey.Length;
    }

    [Benchmark]
    public int BouncyCastle()
    {
        var store = new Pkcs12StoreBuilder().Build();
        using var ms = new MemoryStream(_pfx);
        store.Load(ms, ContainerFixture.Password.ToCharArray());
        int n = 0;
        foreach (string alias in store.Aliases)
        {
            n += store.IsKeyEntry(alias) ? store.GetKey(alias).Key.GetHashCode() & 1 : 0;
            n += store.GetCertificate(alias) is null ? 0 : 1;
        }

        return n;
    }

    [Benchmark]
    [BenchmarkCategory("native")]
    public int X509CertificateLoaderLoadPkcs12()
    {
        using X509Certificate2 c = X509CertificateLoader.LoadPkcs12(_pfx, ContainerFixture.Password);
        return c.HasPrivateKey ? 1 : 0;
    }
}

/// <summary>Decrypt an encrypted PKCS#8 key and read it. BouncyCastle is the managed comparator; the platform's import call is reported.</summary>
[BenchmarkCategory("pkcs8-decrypt")]
public class Pkcs8DecryptRows
{
    private byte[] _enc = [];

    /// <summary>Key type in the file.</summary>
    [Params("ec-p256", "rsa2048")]
    public string Kind { get; set; } = "ec-p256";

    [GlobalSetup]
    public void Setup() => _enc = ContainerFixture.Build(Kind).EncryptedPkcs8;

    [Benchmark]
    public int Ours()
    {
        using PrivateKeyInfo k = EncryptedPrivateKeyInfo.Parse(_enc).Decrypt(ContainerFixture.Password);
        return k.PrivateKey.Length;
    }

    [Benchmark]
    public int BouncyCastle()
    {
        var info = Org.BouncyCastle.Asn1.Pkcs.EncryptedPrivateKeyInfo.GetInstance(_enc);
        Org.BouncyCastle.Asn1.Pkcs.PrivateKeyInfo pk = PrivateKeyInfoFactory.CreatePrivateKeyInfo(ContainerFixture.Password.ToCharArray(), info);
        return pk.PrivateKey.GetOctets().Length;
    }

    [Benchmark]
    [BenchmarkCategory("native")]
    public int ImportEncryptedPkcs8PrivateKey()
    {
        if (Kind == "rsa2048")
        {
            using var rsa = RSA.Create();
            rsa.ImportEncryptedPkcs8PrivateKey(ContainerFixture.Password, _enc, out _);
            return rsa.KeySize;
        }

        using var ec = ECDsa.Create();
        ec.ImportEncryptedPkcs8PrivateKey(ContainerFixture.Password, _enc, out _);
        return ec.KeySize;
    }
}
