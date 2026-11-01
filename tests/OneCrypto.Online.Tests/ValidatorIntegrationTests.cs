using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Validation;
using RevocationStatus = RecursiveAI.OneCrypto.Validation.RevocationStatus;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Online.Tests;

/// <summary>PathValidator.ValidateAsync with the online sources, against a world served by a fake network.</summary>
public class ValidatorIntegrationTests
{
    private static World W => World.Get();

    private static Fetcher Fetch(ITransport net) => new(net, new FetchOptions { Cache = new MemoryFetchCache() });

    private static ValidationOptions Options(IEnumerable<Certificate>? pool = null, RevocationScope scope = RevocationScope.AllCertificates, ICertificateSource? cs = null, IRevocationSource? rs = null) => new()
    {
        TrustAnchors = [TrustAnchor.FromCertificate(W.Root.Certificate)],
        Intermediates = [.. pool ?? []],
        ReferenceTime = World.Now,
        RevocationRequired = scope,
        CertificateSource = cs,
        RevocationSource = rs,
    };

    [Fact]
    public async Task WithoutSourcesNothingIsFetchedAndRevocationStaysUnknown()
    {
        FakeNetwork net = W.Network();
        ValidationReport r = await PathValidator.ValidateAsync(W.Good, Options([W.Intermediate.Certificate]));
        Assert.Empty(net.Requests);
        Assert.Equal(ValidationVerdict.Indeterminate, r.Verdict);
        Assert.Equal(RevocationStatus.Unknown, r.RevocationSummary);
    }

    [Fact]
    public async Task WithTheSourcesTheChainIsCompletedAndRevocationIsGood()
    {
        FakeNetwork net = W.Network();
        Fetcher f = Fetch(net);
        var revocation = new OnlineRevocationSource(f, new OnlineRevocationOptions { ReferenceTime = World.Now });
        var issuers = new OnlineCertificateSource(f);

        // The intermediate is not in the pool: the leaf's caIssuers location supplies it.
        ValidationReport r = await PathValidator.ValidateAsync(W.Good, Options(cs: issuers, rs: revocation));
        Assert.True(r.IsValid, r.ToString());
        Assert.Equal(RevocationStatus.Good, r.RevocationSummary);
        Assert.All(r.SelectedPath!.Certificates, c => Assert.Equal(RevocationStatus.Good, c.Revocation.Status));
        Assert.Contains(net.Requests, q => q.Uri.AbsoluteUri == "http://pki.test/inter.crt");
        Assert.Contains(revocation.Attempts, a => a.Kind == "ocsp" && a.Succeeded);
        Assert.Contains(issuers.Attempts, a => a.Kind == "aia" && a.Succeeded);
    }

    [Fact]
    public async Task ARevokedLeafIsInvalidThroughOcsp()
    {
        FakeNetwork net = W.Network();
        Fetcher f = Fetch(net);
        ValidationReport r = await PathValidator.ValidateAsync(W.Revoked, Options([W.Intermediate.Certificate], rs: new OnlineRevocationSource(f, new OnlineRevocationOptions { ReferenceTime = World.Now })));
        Assert.Equal(ValidationVerdict.Invalid, r.Verdict);
        Assert.Equal(RevocationStatus.Revoked, r.RevocationSummary);
    }

    [Fact]
    public async Task ARevokedLeafIsInvalidThroughTheCrlToo()
    {
        FakeNetwork net = W.Network();
        var source = new OnlineRevocationSource(Fetch(net), new OnlineRevocationOptions { Preference = RevocationPreference.CrlThenOcsp, ReferenceTime = World.Now });
        ValidationReport r = await PathValidator.ValidateAsync(W.Revoked, Options([W.Intermediate.Certificate], rs: source));
        Assert.Equal(ValidationVerdict.Invalid, r.Verdict);
        Assert.DoesNotContain(net.Requests, q => q.Uri.Host == "ocsp.test");
        Assert.Contains(source.Attempts, a => a.Kind == "crl" && a.Succeeded);

        FakeNetwork net2 = W.Network();
        var good = await PathValidator.ValidateAsync(W.Good, Options([W.Intermediate.Certificate], rs: new OnlineRevocationSource(Fetch(net2), new OnlineRevocationOptions { Preference = RevocationPreference.CrlThenOcsp, ReferenceTime = World.Now })));
        Assert.True(good.IsValid, good.ToString());
        Assert.DoesNotContain(net2.Requests, q => q.Uri.Host == "ocsp.test");
    }

    [Fact]
    public async Task OcspThenCrlStopsAtTheFirstAnswerAndBothAsksForBoth()
    {
        FakeNetwork net = W.Network();
        await PathValidator.ValidateAsync(W.Good, Options([W.Intermediate.Certificate], scope: RevocationScope.EndEntity, rs: new OnlineRevocationSource(Fetch(net), new OnlineRevocationOptions { ReferenceTime = World.Now })));
        Assert.DoesNotContain(net.Requests, q => q.Uri.Host == "pki.test");

        FakeNetwork net2 = W.Network();
        await PathValidator.ValidateAsync(W.Good, Options([W.Intermediate.Certificate], scope: RevocationScope.EndEntity, rs: new OnlineRevocationSource(Fetch(net2), new OnlineRevocationOptions { Preference = RevocationPreference.Both, ReferenceTime = World.Now })));
        Assert.Contains(net2.Requests, q => q.Uri.Host == "pki.test" && q.Uri.AbsolutePath == "/inter.crl");
        Assert.Contains(net2.Requests, q => q.Uri.Host == "ocsp.test");
    }

    [Fact]
    public async Task AnUnknownOcspStatusFallsBackToTheCrl()
    {
        FakeNetwork net = W.Network();
        var source = new OnlineRevocationSource(Fetch(net), new OnlineRevocationOptions { ReferenceTime = World.Now });
        ValidationReport r = await PathValidator.ValidateAsync(W.Unlisted, Options([W.Intermediate.Certificate], scope: RevocationScope.EndEntity, rs: source));
        Assert.Contains(source.Attempts, a => a.Kind == "crl");
        Assert.True(r.IsValid, r.ToString());
    }

    [Fact]
    public async Task AnUnreachableResponderLeavesRevocationUnknownAndSaysWhy()
    {
        var net = new StreamNetwork((_, _) => throw new TransportException(TransportFailure.Connect, "connection refused"));
        var source = new OnlineRevocationSource(Fetch(net), new OnlineRevocationOptions { ReferenceTime = World.Now });
        ValidationReport r = await PathValidator.ValidateAsync(W.Good, Options([W.Intermediate.Certificate], scope: RevocationScope.EndEntity, rs: source));
        Assert.Equal(ValidationVerdict.Indeterminate, r.Verdict);
        Assert.Equal(RevocationStatus.Unknown, r.RevocationSummary);
        Assert.Contains(source.Attempts, a => !a.Succeeded && a.Detail.Contains("connection refused", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CertificateSuppliedAddressesInsideTheNetworkAreNeverContacted()
    {
        // A CA whose certificates point at the cloud metadata address, a loopback port and a private host.
        var hostile = new CertificateAuthority(W.Intermediate.Certificate, X509Signer.FromECDsa(W.InterKey), new CertificateAuthorityOptions
        {
            OcspUrls = ["http://169.254.169.254/ocsp"],
            CrlUrls = ["http://127.0.0.1:9/ca.crl", "http://[::1]/ca.crl"],
            CaIssuersUrls = ["http://10.0.0.5/ca.crt"],
        });
        Certificate leaf = hostile.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(W.LeafKey), DistinguishedName.Create((KnownOids.CommonName, "hostile.test")),
            new CertificateIssueOptions { Profile = CertificateProfile.TlsServer, NotBefore = World.T0.AddDays(-1), SubjectAlternativeNames = [GeneralName.Dns("hostile.test")] });
        var net = new FakeNetwork(_ => Reply.Code(200));
        Fetcher f = Fetch(net);
        var revocation = new OnlineRevocationSource(f, new OnlineRevocationOptions { ReferenceTime = World.Now, Preference = RevocationPreference.Both });
        var issuers = new OnlineCertificateSource(f);
        ValidationReport noPath = await PathValidator.ValidateAsync(leaf, Options(scope: RevocationScope.EndEntity, cs: issuers));
        Assert.False(noPath.IsValid);
        Assert.NotEmpty(issuers.Attempts);
        Assert.All(issuers.Attempts, a => Assert.False(a.Succeeded));
        Assert.Contains(issuers.Attempts, a => a.Detail.Contains("10.0.0.5", StringComparison.Ordinal));

        ValidationReport r = await PathValidator.ValidateAsync(leaf, Options([W.Intermediate.Certificate], scope: RevocationScope.EndEntity, rs: revocation));
        Assert.Equal(ValidationVerdict.Indeterminate, r.Verdict);
        Assert.NotEmpty(revocation.Attempts);
        Assert.All(revocation.Attempts, a => Assert.False(a.Succeeded));
        Assert.Contains(revocation.Attempts, a => a.Detail.Contains("169.254.169.254", StringComparison.Ordinal));
        Assert.Empty(net.Requests);
    }

    [Fact]
    public async Task AnIssuerWithTheWrongNameIsNotAddedToThePool()
    {
        FakeNetwork net = W.Network(new() { ["http://pki.test/inter.crt"] = _ => Reply.Ok(W.Good.Encoded.ToArray(), "application/pkix-cert") });
        var issuers = new OnlineCertificateSource(Fetch(net));
        IReadOnlyList<Certificate> found = await issuers.FindIssuersAsync(W.Good, ["http://pki.test/inter.crt"], CancellationToken.None);
        Assert.Empty(found);
    }

    [Fact]
    public async Task CancellationReachesTheFetch()
    {
        var net = new StreamNetwork((_, ct) => throw new OperationCanceledException(ct));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var source = new OnlineRevocationSource(Fetch(net), new OnlineRevocationOptions { ReferenceTime = World.Now });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await PathValidator.ValidateAsync(W.Good, Options([W.Intermediate.Certificate], rs: source), cts.Token));
    }

    [Fact]
    public async Task ReplayOfARecordedWorldValidatesWithoutTheNetwork()
    {
        // Record the world once through the recording transport, then validate again from the recording alone.
        FakeNetwork live = W.Network();
        var rec = new RecordingTransport(live);
        Fetcher f = Fetch(rec);
        ValidationReport first = await PathValidator.ValidateAsync(W.Good, Options(cs: new OnlineCertificateSource(f), rs: new OnlineRevocationSource(f, new OnlineRevocationOptions { ReferenceTime = World.Now, Preference = RevocationPreference.Both })));
        Assert.True(first.IsValid, first.ToString());

        ExchangeLog log = ExchangeLog.Parse(rec.Log.ToJson());
        var replay = new ReplayTransport(log);
        Fetcher rf = Fetch(replay);
        ValidationReport again = await PathValidator.ValidateAsync(W.Good, Options(cs: new OnlineCertificateSource(rf), rs: new OnlineRevocationSource(rf, new OnlineRevocationOptions { ReferenceTime = World.Now, Preference = RevocationPreference.Both })));
        Assert.True(again.IsValid, again.ToString());
        Assert.Equal(RevocationStatus.Good, again.RevocationSummary);
        _ = SHA256.HashData([]);
    }
}
