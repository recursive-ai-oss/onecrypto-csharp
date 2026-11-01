using System.Numerics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Online.Tests;

/// <summary>
/// A root, an intermediate and some leaves built with the library, served by a <see cref="FakeNetwork"/> as an OCSP responder, CRL and issuer-certificate hosts
/// and a time-stamp authority. Every certificate names those hosts, so a validation that is allowed to fetch finds everything it needs.
/// </summary>
internal sealed class World
{
    public static readonly DateTimeOffset T0 = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>The instant everything is judged at.</summary>
    public static readonly DateTimeOffset Now = T0.AddHours(1);

    private static readonly Lazy<World> Shared = new(() => new World());

    public static World Get() => Shared.Value;

    private readonly Dictionary<string, Func<TransportRequest, Reply>> _routes = [];

    private World()
    {
        RootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Root = CertificateAuthority.CreateRoot(Name("Online Test Root"), X509Signer.FromECDsa(RootKey), T0.AddDays(-30), TimeSpan.FromDays(3650), new CertificateAuthorityOptions
        {
            OcspUrls = ["http://ocsp.root.test/"],
            CaIssuersUrls = ["http://pki.test/root.crt"],
            CrlUrls = ["http://pki.test/root.crl"],
        });
        InterKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Certificate inter = Root.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(InterKey), Name("Online Test Intermediate"),
            new CertificateIssueOptions { Profile = CertificateProfile.Intermediate, NotBefore = T0.AddDays(-20), Validity = TimeSpan.FromDays(1800) });
        Intermediate = new CertificateAuthority(inter, X509Signer.FromECDsa(InterKey), new CertificateAuthorityOptions
        {
            OcspUrls = ["http://ocsp.test/"],
            CaIssuersUrls = ["http://pki.test/inter.crt"],
            CrlUrls = ["http://pki.test/inter.crl"],
        });
        LeafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Good = Leaf("good.test");
        Revoked = Leaf("revoked.test");
        Unlisted = Leaf("unlisted.test");

        OcspStatus = new InMemoryRevocationSource(TimeSpan.FromDays(1));
        OcspStatus.SetGood(Good.SerialNumber.Span);
        OcspStatus.SetRevoked(Revoked.SerialNumber.Span, T0.AddMinutes(30), RevocationReason.KeyCompromise);
        Responder = new OcspResponder(new OcspResponderOptions { Issuer = Intermediate.Certificate, ResponderCertificate = Intermediate.Certificate, Signer = X509Signer.FromECDsa(InterKey), Source = OcspStatus });
        var rootStatus = new InMemoryRevocationSource(TimeSpan.FromDays(1));
        rootStatus.SetGood(Intermediate.Certificate.SerialNumber.Span);
        RootResponder = new OcspResponder(new OcspResponderOptions { Issuer = Root.Certificate, ResponderCertificate = Root.Certificate, Signer = X509Signer.FromECDsa(RootKey), Source = rootStatus });

        InterCrl = Intermediate.IssueCrl(new CrlIssueOptions
        {
            ThisUpdate = T0,
            NextUpdate = T0.AddDays(7),
            Number = 5,
            Revoked = [new RevokedCertificateInfo(Revoked.SerialNumberValue, T0.AddMinutes(30), RevocationReason.KeyCompromise, T0.AddMinutes(10))],
            DistributionPointUrl = "http://pki.test/inter.crl",
        });
        RootCrl = Root.IssueCrl(new CrlIssueOptions { ThisUpdate = T0, NextUpdate = T0.AddDays(7), Number = 2, DistributionPointUrl = "http://pki.test/root.crl" });

        TsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        TsaCertificate = Intermediate.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(TsaKey), Name("Online Test TSA"),
            new CertificateIssueOptions { Profile = CertificateProfile.TimeStamping, NotBefore = T0.AddDays(-1) });
        Tsa = new TimeStampAuthority(new TimeStampAuthorityOptions
        {
            Certificate = TsaCertificate,
            Signer = X509Signer.FromECDsa(TsaKey),
            DefaultPolicy = TsaPolicy,
            AcceptedPolicies = ["1.2.3.4.5"],
            ChainCertificates = [Intermediate.Certificate],
        }, new CounterTimeStampSerialSource());
        Route("http://tsa.test/", r => Reply.Ok(Tsa.Handle(r.Body, Now).Encoded.ToArray(), "application/timestamp-reply"));
        Route("http://pki.test/root.crt", _ => Reply.Ok(Root.Certificate.Encoded.ToArray(), "application/pkix-cert", ("Cache-Control", "max-age=86400")));
        Route("http://pki.test/inter.crt", _ => Reply.Ok(Intermediate.Certificate.Encoded.ToArray(), "application/pkix-cert", ("Cache-Control", "max-age=86400")));
        Route("http://pki.test/root.crl", _ => Reply.Ok(RootCrl.Encoded.ToArray(), "application/pkix-crl", ("Cache-Control", "max-age=3600")));
        Route("http://pki.test/inter.crl", _ => Reply.Ok(InterCrl.Encoded.ToArray(), "application/pkix-crl", ("Cache-Control", "max-age=3600")));
        Route("http://ocsp.test/", r => ServeOcspFor(Responder, r));
        Route("http://ocsp.root.test/", r => ServeOcspFor(RootResponder, r));
    }

    public const string TsaPolicy = "1.2.3.4.1";

    public ECDsa TsaKey { get; }

    public Certificate TsaCertificate { get; }

    public TimeStampAuthority Tsa { get; }

    public ECDsa RootKey { get; }

    public ECDsa InterKey { get; }

    public ECDsa LeafKey { get; }

    public CertificateAuthority Root { get; }

    public CertificateAuthority Intermediate { get; }

    public Certificate Good { get; }

    public Certificate Revoked { get; }

    /// <summary>Good in no list: the responder has never heard of it.</summary>
    public Certificate Unlisted { get; }

    public InMemoryRevocationSource OcspStatus { get; }

    public OcspResponder Responder { get; }

    public OcspResponder RootResponder { get; }

    public CertificateRevocationList InterCrl { get; }

    public CertificateRevocationList RootCrl { get; }

    private static DistinguishedName Name(string cn) => DistinguishedName.Create((KnownOids.Organization, "OneCrypto Online Tests"), (KnownOids.CommonName, cn));

    private Certificate Leaf(string host) => Intermediate.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(LeafKey), Name(host),
        new CertificateIssueOptions { Profile = CertificateProfile.TlsServer, NotBefore = T0.AddDays(-1), SubjectAlternativeNames = [GeneralName.Dns(host)] });

    public void Route(string url, Func<TransportRequest, Reply> handler) => _routes[url] = handler;

    /// <summary>A network that serves this world; a test may add or replace routes first with <paramref name="more"/>.</summary>
    public FakeNetwork Network(Dictionary<string, Func<TransportRequest, Reply>>? more = null) => new(r =>
    {
        string url = r.Uri.AbsoluteUri;
        if (more is not null && more.TryGetValue(url, out Func<TransportRequest, Reply>? o))
        {
            return o(r);
        }

        if (_routes.TryGetValue(url, out Func<TransportRequest, Reply>? h))
        {
            return h(r);
        }

        // An OCSP GET carries the request in the path.
        foreach (KeyValuePair<string, Func<TransportRequest, Reply>> kv in _routes)
        {
            if (kv.Key.EndsWith('/') && url.StartsWith(kv.Key, StringComparison.Ordinal))
            {
                return kv.Value(r);
            }
        }

        return Reply.Code(404);
    });

    /// <summary>Decodes the request from a POST body or the Base64 tail of a GET and has the responder answer it at <see cref="Now"/>.</summary>
    public static Reply ServeOcspFor(OcspResponder responder, TransportRequest r)
    {
        byte[] request;
        if (r.Method == "POST")
        {
            request = r.Body.ToArray();
        }
        else
        {
            string path = r.Uri.AbsolutePath;
            string tail = Uri.UnescapeDataString(path[(path.LastIndexOf('/') + 1)..]);
            request = Convert.FromBase64String(tail);
        }

        OcspResponse response = responder.Handle(request, Now);
        return Reply.Ok(response.Encoded.ToArray(), "application/ocsp-response", ("Cache-Control", "max-age=3600"));
    }
}
