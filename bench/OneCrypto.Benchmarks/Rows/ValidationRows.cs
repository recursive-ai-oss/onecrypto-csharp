using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using BcAnchor = Org.BouncyCastle.Pkix.TrustAnchor;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Benchmarks;

/// <summary>
/// Certificate parsing plus path validation of a chain at a fixed instant, with the same work for each library: read the DER of every
/// certificate (and CRL), build the path from an unordered pool, check signatures, validity, basic constraints and key usage, and (for
/// the CRL rows) check revocation. The platform chain engine, offline, cannot take CRLs through its API, so its CRL row validates without revocation.
/// </summary>
[MemoryDiagnoser]
[BenchmarkCategory("x509-validate")]
public class ValidationRows
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private byte[][] _certs = []; // root first, target last
    private byte[][] _crls = [];

    /// <summary>The chain: three certificates, or six with a CRL from every issuing CA.</summary>
    [Params("chain3", "chain6-crl")]
    public string Shape { get; set; } = "chain3";

    [GlobalSetup]
    public void Setup()
    {
        int n = Shape == "chain3" ? 3 : 6;
        var certs = new List<Certificate>();
        var crls = new List<CertificateRevocationList>();
        var keys = new List<ECDsa>();
        X509Signer? prevSigner = null;
        Certificate? prev = null;
        for (int i = 0; i < n; i++)
        {
            ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            keys.Add(key);
            X509Signer signer = X509Signer.FromECDsa(key);
            bool ca = i < n - 1;
            List<Extension> ext = ca
                ? [Extension.Create(new BasicConstraints(true), true), Extension.Create(new KeyUsageExtension(KeyUsages.KeyCertSign | KeyUsages.CrlSign), true)]
                : [Extension.Create(new BasicConstraints(false), true), Extension.Create(new KeyUsageExtension(KeyUsages.DigitalSignature), true), Extension.Create(new SubjectAlternativeName([GeneralName.Dns("bench.example.test")]), false)];
            var o = new CertificateOptions
            {
                Subject = DistinguishedName.Create((KnownOids.Organization, "Bench"), (KnownOids.CommonName, i == 0 ? "Bench Root" : ca ? "Bench CA " + i : "bench.example.test")),
                PublicKey = signer.PublicKey,
                NotBefore = Now.AddYears(-1),
                NotAfter = Now.AddYears(5),
                Extensions = ext,
            };
            Certificate c = prev is null ? CertificateBuilder.CreateSelfSigned(o, signer) : CertificateBuilder.Create(o, prev, prevSigner!);
            if (Shape != "chain3" && prev is not null)
            {
                crls.Add(RevocationListBuilder.Create(new RevocationListOptions { ThisUpdate = Now.AddDays(-1), NextUpdate = Now.AddDays(30), Number = 1 }, prevSigner!, prev));
            }

            certs.Add(c);
            prev = c;
            prevSigner = signer;
        }

        _certs = [.. certs.Select(c => c.Encoded.ToArray())];
        _crls = [.. crls.Select(c => c.Encoded.ToArray())];
        foreach (ECDsa k in keys)
        {
            k.Dispose();
        }
    }

    [Benchmark]
    public bool Ours()
    {
        var parsed = _certs.Select(b => Certificate.Parse(new ReadOnlyMemory<byte>(b))).ToList();
        var crls = _crls.Select(b => CertificateRevocationList.Parse(new ReadOnlyMemory<byte>(b))).ToList();
        ValidationReport r = PathValidator.Validate(parsed[^1], new ValidationOptions
        {
            TrustAnchors = [RecursiveAI.OneCrypto.Validation.TrustAnchor.FromCertificate(parsed[0])],
            Intermediates = parsed.Skip(1).Take(parsed.Count - 2).Reverse().ToList(),
            ReferenceTime = Now,
            Revocation = crls.Count > 0 ? new RevocationData { Crls = crls } : null,
            RevocationRequired = crls.Count > 0 ? RevocationScope.AllCertificates : RevocationScope.None,
            UnknownRevocationIsFatal = crls.Count > 0,
        });
        return r.IsValid;
    }

    [Benchmark]
    [BenchmarkCategory("native")]
    public bool X509ChainOffline()
    {
        using X509Certificate2 root = X509CertificateLoader.LoadCertificate(_certs[0]);
        using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(_certs[^1]);
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.VerificationTime = Now.UtcDateTime;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        for (int i = _certs.Length - 2; i >= 1; i--)
        {
            chain.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(_certs[i]));
        }

        bool ok = chain.Build(leaf);
        foreach (X509Certificate2 c in chain.ChainPolicy.ExtraStore)
        {
            c.Dispose();
        }

        return ok;
    }

    [Benchmark]
    public bool BouncyCastle()
    {
        var parser = new Org.BouncyCastle.X509.X509CertificateParser();
        var certs = _certs.Select(b => parser.ReadCertificate(b)).ToList();
        var crlParser = new Org.BouncyCastle.X509.X509CrlParser();
        var crls = _crls.Select(b => crlParser.ReadCrl(b)).ToList();
        var anchors = new HashSet<BcAnchor> { new BcAnchor(certs[0], null) };
        var path = new PkixCertPath(certs.Skip(1).Reverse().ToList());
        var p = new PkixParameters(anchors)
        {
            IsRevocationEnabled = crls.Count > 0,
            Date = Now.UtcDateTime,
        };
        if (crls.Count > 0)
        {
            p.AddStoreCrl(CollectionUtilities.CreateStore(crls));
        }

        try
        {
            new PkixCertPathValidator().Validate(path, p);
            return true;
        }
        catch (PkixCertPathValidatorException)
        {
            return false;
        }
    }
}
