using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Benchmarks;

/// <summary>A CA, a time-stamping certificate and the matching keys, for the issuer-side rows.</summary>
internal sealed class IssuerRig
{
    public static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    public IssuerRig(string kind)
    {
        CaKey = Make(kind, out X509Signer caSigner);
        Ca = CertificateAuthority.CreateRoot(DistinguishedName.Create((KnownOids.CommonName, "Bench CA")), caSigner, Now.AddDays(-30), TimeSpan.FromDays(3650));
        TsaKey = Make(kind, out X509Signer tsaSigner);
        Tsa = Ca.Issue(tsaSigner.PublicKey, DistinguishedName.Create((KnownOids.CommonName, "Bench TSA")), new CertificateIssueOptions { Profile = CertificateProfile.TimeStamping, NotBefore = Now.AddDays(-1) });
        TsaSigner = tsaSigner;
        CaSigner = caSigner;
        Leaf = Ca.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(ECDsa.Create(ECCurve.NamedCurves.nistP256)), DistinguishedName.Create((KnownOids.CommonName, "Bench leaf")),
            new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = Now.AddDays(-1) });
    }

    public AsymmetricAlgorithm CaKey { get; }

    public AsymmetricAlgorithm TsaKey { get; }

    public CertificateAuthority Ca { get; }

    public Certificate Tsa { get; }

    public Certificate Leaf { get; }

    public X509Signer TsaSigner { get; }

    public X509Signer CaSigner { get; }

    private static AsymmetricAlgorithm Make(string kind, out X509Signer signer)
    {
        if (kind == "rsa2048")
        {
            RSA rsa = RSA.Create(2048);
            signer = X509Signer.FromRsa(rsa, HashAlgorithmName.SHA256);
            return rsa;
        }

        ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        signer = X509Signer.FromECDsa(ec);
        return ec;
    }
}

/// <summary>Time-stamp tokens issued per second by the authority handler (our own row: no managed library offers a handler to compare with).</summary>
[BenchmarkCategory("tsa-issue")]
public class TsaIssueRows
{
    private TimeStampAuthority _tsa = null!;
    private byte[] _request = [];

    /// <summary>The key type of the authority.</summary>
    [Params("rsa2048", "p256")]
    public string Kind { get; set; } = string.Empty;

    [GlobalSetup]
    public void Setup()
    {
        var rig = new IssuerRig(Kind);
        _tsa = new TimeStampAuthority(new TimeStampAuthorityOptions { Certificate = rig.Tsa, Signer = rig.TsaSigner, DefaultPolicy = "1.2.3.4.1", Accuracy = new TimeStampAccuracy(1) }, new CounterTimeStampSerialSource());
        _request = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData("bench"u8), Nonce = TimeStampRequest.NewNonce() }).Encoded.ToArray();
    }

    [Benchmark]
    public TimeStampResponse Ours() => _tsa.Handle(_request, IssuerRig.Now);
}

/// <summary>OCSP responses issued per second by the responder handler (our own row).</summary>
[BenchmarkCategory("ocsp-issue")]
public class OcspIssueRows
{
    private OcspResponder _responder = null!;
    private byte[] _request = [];

    /// <summary>The key type of the CA that signs the responses.</summary>
    [Params("rsa2048", "p256")]
    public string Kind { get; set; } = string.Empty;

    [GlobalSetup]
    public void Setup()
    {
        var rig = new IssuerRig(Kind);
        var source = new InMemoryRevocationSource(TimeSpan.FromHours(1));
        source.SetGood(rig.Leaf.SerialNumber.Span);
        _responder = new OcspResponder(new OcspResponderOptions { Issuer = rig.Ca.Certificate, ResponderCertificate = rig.Ca.Certificate, Signer = rig.CaSigner, Source = source });
        _request = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [OcspCertId.Create(rig.Leaf, rig.Ca.Certificate)], Nonce = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 } }).Encoded.ToArray();
    }

    [Benchmark]
    public OcspResponse Ours() => _responder.Handle(_request, IssuerRig.Now);
}

/// <summary>
/// Checking a time-stamp response against its request: status, imprint, nonce, signer binding and certificate rules, and the signature. BouncyCastle's
/// <c>TimeStampResponse.Validate</c> and <c>TimeStampToken.Validate</c> do the same job.
/// </summary>
[BenchmarkCategory("tsa-verify")]
public class TsaVerifyRows
{
    private TimeStampRequest _request = null!;
    private byte[] _response = [];
    private Org.BouncyCastle.Tsp.TimeStampRequest _bcRequest = null!;
    private Org.BouncyCastle.X509.X509Certificate _bcCert = null!;

    /// <summary>The key type of the authority.</summary>
    [Params("rsa2048", "p256")]
    public string Kind { get; set; } = string.Empty;

    [GlobalSetup]
    public void Setup()
    {
        var rig = new IssuerRig(Kind);
        var tsa = new TimeStampAuthority(new TimeStampAuthorityOptions { Certificate = rig.Tsa, Signer = rig.TsaSigner, DefaultPolicy = "1.2.3.4.1" }, new CounterTimeStampSerialSource());
        _request = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData("bench"u8), Nonce = TimeStampRequest.NewNonce() });
        _response = tsa.Handle(_request.Encoded, IssuerRig.Now).Encoded.ToArray();
        _bcRequest = new Org.BouncyCastle.Tsp.TimeStampRequest(_request.Encoded.ToArray());
        _bcCert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(rig.Tsa.Encoded.ToArray());
    }

    [Benchmark]
    public bool Ours() => TimeStampVerifier.Verify(_request, _response).IsValid;

    [Benchmark]
    public bool BouncyCastle()
    {
        var response = new Org.BouncyCastle.Tsp.TimeStampResponse(_response);
        response.Validate(_bcRequest);
        response.TimeStampToken.Validate(_bcCert);
        return true;
    }
}
