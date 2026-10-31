using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.X509;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Benchmarks;

/// <summary>Builds the certificates the X.509 rows read: one root and one end-entity certificate per key type.</summary>
internal static class CertificateFixture
{
    public static (byte[] Leaf, byte[] Root) Build(string kind)
    {
        DateTimeOffset now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        using AsymmetricAlgorithm rootKey = kind == "rsa2048" ? RSA.Create(2048) : ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using AsymmetricAlgorithm leafKey = kind == "rsa2048" ? RSA.Create(2048) : ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Signer Signer(AsymmetricAlgorithm k) => k is RSA r ? X509Signer.FromRsa(r, HashAlgorithmName.SHA256) : X509Signer.FromECDsa((ECDsa)k);
        Certificate root = CertificateBuilder.CreateSelfSigned(
            new CertificateOptions
            {
                Subject = DistinguishedName.Create((KnownOids.Country, "US"), (KnownOids.Organization, "Bench Org"), (KnownOids.CommonName, "Bench Root")),
                NotBefore = now,
                NotAfter = now.AddYears(10),
                Extensions = [Extension.Create(new BasicConstraints(true), true), Extension.Create(new KeyUsageExtension(KeyUsages.KeyCertSign), true)],
            },
            Signer(rootKey));
        Certificate leaf = CertificateBuilder.Create(
            new CertificateOptions
            {
                Subject = DistinguishedName.Create((KnownOids.Country, "US"), (KnownOids.Organization, "Bench Org"), (KnownOids.CommonName, "bench.example.test")),
                PublicKey = Signer(leafKey).PublicKey,
                NotBefore = now,
                NotAfter = now.AddYears(1),
                Extensions =
                [
                    Extension.Create(new BasicConstraints(false), true),
                    Extension.Create(new KeyUsageExtension(KeyUsages.DigitalSignature), true),
                    Extension.Create(new ExtendedKeyUsage([KnownOids.ServerAuth]), false),
                    Extension.Create(new SubjectAlternativeName([GeneralName.Dns("bench.example.test"), GeneralName.Dns("www.bench.example.test")]), false),
                    Extension.Create(new AuthorityInfoAccess([new AccessDescription(KnownOids.AdOcsp, GeneralName.FromUri("http://ocsp.example.test"))]), false),
                ],
            },
            root,
            Signer(rootKey));
        return (leaf.Encoded.ToArray(), root.Encoded.ToArray());
    }
}

/// <summary>
/// Certificate parse against BouncyCastle (managed gate) and the platform's X509Certificate2 (native-backed, reported). All three
/// read the same bytes and then read the same fields: subject and issuer as text, serial, validity and the extension count.
/// </summary>
[BenchmarkCategory("x509-parse")]
public class CertificateParseRows
{
    private byte[] _leaf = [];
    private readonly X509CertificateParser _bc = new();

    /// <summary>Key type of the certificate.</summary>
    [Params("ec-p256", "rsa2048")]
    public string Kind { get; set; } = "ec-p256";

    [GlobalSetup]
    public void Setup() => _leaf = CertificateFixture.Build(Kind).Leaf;

    [Benchmark]
    public int Ours()
    {
        var c = Certificate.Parse(new ReadOnlyMemory<byte>(_leaf));
        return c.Subject.ToString().Length + c.Issuer.ToString().Length + c.SerialNumber.Length + c.NotBefore.Year + c.NotAfter.Year + c.Extensions.Count;
    }

    [Benchmark]
    public int BouncyCastle()
    {
        Org.BouncyCastle.X509.X509Certificate c = _bc.ReadCertificate(_leaf);
        return c.SubjectDN.ToString().Length + c.IssuerDN.ToString().Length + c.SerialNumber.ToByteArray().Length + c.NotBefore.Year + c.NotAfter.Year
            + c.GetCriticalExtensionOids().Count + c.GetNonCriticalExtensionOids().Count;
    }

    [Benchmark]
    [BenchmarkCategory("native")]
    public int X509Certificate2Loader()
    {
        using X509Certificate2 c = X509CertificateLoader.LoadCertificate(_leaf);
        return c.Subject.Length + c.Issuer.Length + c.SerialNumberBytes.Length + c.NotBefore.Year + c.NotAfter.Year + c.Extensions.Count;
    }
}

/// <summary>
/// Parse and check the certificate's signature with the issuer's key. BouncyCastle is the managed comparator. The platform has no call
/// that checks a certificate signature, so the native-backed row is what a caller writes on it: System.Formats.Asn1 to cut out the
/// signed bytes and the algorithm's key object to check them.
/// </summary>
[BenchmarkCategory("x509-verify")]
public class CertificateVerifyRows
{
    private byte[] _leaf = [];
    private byte[] _root = [];
    private readonly X509CertificateParser _bc = new();
    private PublicKeyInfo _rootKey = null!;
    private Org.BouncyCastle.Crypto.AsymmetricKeyParameter _bcKey = null!;

    /// <summary>Key type of both certificates.</summary>
    [Params("ec-p256", "rsa2048")]
    public string Kind { get; set; } = "ec-p256";

    [GlobalSetup]
    public void Setup()
    {
        (_leaf, _root) = CertificateFixture.Build(Kind);
        _rootKey = Certificate.Parse(new ReadOnlyMemory<byte>(_root)).PublicKey;
        _bcKey = _bc.ReadCertificate(_root).GetPublicKey();
    }

    [Benchmark]
    public bool Ours() => Certificate.Parse(new ReadOnlyMemory<byte>(_leaf)).VerifySignature(_rootKey).IsValid;

    [Benchmark]
    public bool BouncyCastle()
    {
        _bc.ReadCertificate(_leaf).Verify(_bcKey);
        return true;
    }

    [Benchmark]
    [BenchmarkCategory("native")]
    public bool PlatformByHand()
    {
        var outer = new AsnReader(_leaf, AsnEncodingRules.DER).ReadSequence();
        ReadOnlyMemory<byte> tbs = outer.ReadEncodedValue();
        outer.ReadSequence();
        outer.TryReadPrimitiveBitString(out _, out ReadOnlyMemory<byte> sig);
        if (Kind == "rsa2048")
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(_rootKey.Encoded.Span, out _);
            return rsa.VerifyData(tbs.Span, sig.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        using var ec = ECDsa.Create();
        ec.ImportSubjectPublicKeyInfo(_rootKey.Encoded.Span, out _);
        return ec.VerifyData(tbs.Span, sig.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }
}
