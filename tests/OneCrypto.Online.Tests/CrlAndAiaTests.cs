using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Online.Tests;

public class CrlClientTests
{
    private static World W => World.Get();

    private static CrlClient Client(ITransport net, TimeProvider? time = null) => new(new Fetcher(net, new FetchOptions { Cache = new MemoryFetchCache(), Time = time ?? TimeProvider.System }));

    private static CrlFetchOptions At(DateTimeOffset t) => new() { ReferenceTime = t };

    [Fact]
    public async Task ACrlIsFetchedParsedAndJudgedAtTheReferenceTime()
    {
        FakeNetwork net = W.Network();
        CrlFetchResult r = await Client(net).FetchAsync(new Uri("http://pki.test/inter.crl"), At(World.Now));
        Assert.Equal(CrlOutcome.Fetched, r.Outcome);
        Assert.Equal(CrlCurrency.Current, r.Currency);
        Assert.Equal(W.InterCrl.Encoded.ToArray(), r.Crl!.Encoded.ToArray());
        Assert.NotNull(r.Crl.Find(W.Revoked.SerialNumber.Span));

        Assert.Equal(CrlCurrency.Expired, (await Client(net).FetchAsync(new Uri("http://pki.test/inter.crl"), At(World.T0.AddDays(8)))).Currency);
        Assert.Equal(CrlCurrency.NotYetValid, (await Client(net).FetchAsync(new Uri("http://pki.test/inter.crl"), At(World.T0.AddDays(-1)))).Currency);
    }

    [Fact]
    public async Task TheCertificatesDistributionPointIsFollowed()
    {
        FakeNetwork net = W.Network();
        IReadOnlyList<CrlFetchResult> r = await Client(net).FetchForAsync(W.Good, At(World.Now));
        Assert.Single(r);
        Assert.Equal("http://pki.test/inter.crl", r[0].Uri.AbsoluteUri);
        Assert.Equal(CrlOutcome.Fetched, r[0].Outcome);
    }

    [Fact]
    public async Task APemCrlIsAccepted()
    {
        var net = new FakeNetwork(_ => Reply.Ok(Encoding.ASCII.GetBytes(W.InterCrl.ToPem()), "application/x-pem-file"));
        CrlFetchResult r = await Client(net).FetchAsync(new Uri("http://pki.test/inter.crl"), At(World.Now));
        Assert.Equal(CrlOutcome.Fetched, r.Outcome);
    }

    [Theory]
    [InlineData("ldap://ldap.test/cn=CA?certificateRevocationList")]
    [InlineData("ftp://ftp.test/ca.crl")]
    public async Task LdapAndFtpLocationsAreSkippedNotFetched(string url)
    {
        var net = new FakeNetwork(_ => Reply.Code(500));
        CrlFetchResult r = await Client(net).FetchAsync(new Uri(url), At(World.Now));
        Assert.Equal(CrlOutcome.SchemeNotSupported, r.Outcome);
        Assert.Empty(net.Requests);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a crl")]
    [InlineData("-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n")]
    public async Task GarbageIsMalformed(string body)
    {
        var net = new FakeNetwork(_ => Reply.Ok(Encoding.ASCII.GetBytes(body), "application/pkix-crl"));
        Assert.Equal(CrlOutcome.Malformed, (await Client(net).FetchAsync(new Uri("http://pki.test/x.crl"), At(World.Now))).Outcome);
    }

    [Fact]
    public async Task FailuresAreTypedAndTheSizeLimitHolds()
    {
        Assert.Equal(CrlOutcome.FetchFailed, (await Client(new FakeNetwork(_ => Reply.Code(404))).FetchAsync(new Uri("http://pki.test/x.crl"), At(World.Now))).Outcome);
        var big = new FakeNetwork(_ => Reply.Ok(new byte[3000], "application/pkix-crl"));
        CrlFetchResult r = await Client(big).FetchAsync(new Uri("http://pki.test/x.crl"), new CrlFetchOptions { ReferenceTime = World.Now, MaxResponseBytes = 2048 });
        Assert.Equal(CrlOutcome.FetchFailed, r.Outcome);
        Assert.Equal(FetchOutcome.ResponseTooLarge, r.Fetch!.Outcome);
    }

    [Fact]
    public async Task ACrlAddressFromACertificateGetsTheAddressGuard()
    {
        var net = new FakeNetwork(_ => Reply.Ok(W.InterCrl.Encoded.ToArray(), "application/pkix-crl"));
        CrlFetchResult r = await Client(net).FetchAsync(new Uri("http://192.168.0.7/ca.crl"), At(World.Now));
        Assert.Equal(FetchOutcome.AddressBlocked, r.Fetch!.Outcome);
        Assert.Empty(net.Requests);
        Assert.Equal(CrlOutcome.Fetched, (await Client(net).FetchAsync(new Uri("http://192.168.0.7/ca.crl"), new CrlFetchOptions { ReferenceTime = World.Now, Origin = UrlOrigin.Caller })).Outcome);
    }

    [Fact]
    public async Task ACachedCrlIsReusedWhileCurrentAndReplacedOnceItIsNot()
    {
        FakeNetwork net = W.Network();
        CrlClient c = Client(net);
        await c.FetchAsync(new Uri("http://pki.test/inter.crl"), At(World.Now));
        Assert.True((await c.FetchAsync(new Uri("http://pki.test/inter.crl"), At(World.Now))).Fetch!.FromCache);
        Assert.Single(net.Requests);

        // Past nextUpdate the stored copy is useless for this question, so the server is asked again.
        CrlFetchResult later = await c.FetchAsync(new Uri("http://pki.test/inter.crl"), At(World.T0.AddDays(9)));
        Assert.False(later.Fetch!.FromCache);
        Assert.Equal(CrlCurrency.Expired, later.Currency);
        Assert.Equal(2, net.Requests.Count);
    }

    [Fact]
    public async Task ACurrentCrlOutlivesAnUnreachableServer()
    {
        bool down = false;
        var net = new StreamNetwork((_, _) => down
            ? throw new TransportException(TransportFailure.Connect, "refused")
            : new TransportResponse(200, [new("Cache-Control", "max-age=1")], new MemoryStream(W.InterCrl.Encoded.ToArray())));
        var clock = new TestClock(new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));
        CrlClient c = Client(net, clock);
        await c.FetchAsync(new Uri("http://pki.test/inter.crl"), At(World.Now));
        clock.Advance(TimeSpan.FromHours(2));
        down = true;
        CrlFetchResult r = await c.FetchAsync(new Uri("http://pki.test/inter.crl"), At(World.Now));
        Assert.Equal(CrlOutcome.Fetched, r.Outcome);
        Assert.True(r.Fetch!.Stale);

        // Not once it has expired at the reference time.
        CrlFetchResult expired = await c.FetchAsync(new Uri("http://pki.test/inter.crl"), At(World.T0.AddDays(30)));
        Assert.Equal(CrlOutcome.FetchFailed, expired.Outcome);
    }

    [Fact]
    public async Task DeltaCrlsNamedByFreshestCrlAreFetchedToo()
    {
        CertificateAuthority ca = W.Intermediate;
        CertificateRevocationList baseCrl = ca.IssueCrl(new CrlIssueOptions
        {
            ThisUpdate = World.T0,
            NextUpdate = World.T0.AddDays(7),
            Number = 10,
            DistributionPointUrl = "http://pki.test/base.crl",
            DeltaCrlUrl = "http://pki.test/delta.crl",
        });
        CertificateRevocationList delta = ca.IssueCrl(new CrlIssueOptions
        {
            ThisUpdate = World.T0.AddHours(1),
            NextUpdate = World.T0.AddDays(1),
            Number = 11,
            DeltaBaseNumber = 10,
            Revoked = [new RevokedCertificateInfo(W.Revoked.SerialNumberValue, World.T0.AddMinutes(30), RevocationReason.KeyCompromise)],
        });
        FakeNetwork net = W.Network(new()
        {
            ["http://pki.test/base.crl"] = _ => Reply.Ok(baseCrl.Encoded.ToArray(), "application/pkix-crl"),
            ["http://pki.test/delta.crl"] = _ => Reply.Ok(delta.Encoded.ToArray(), "application/pkix-crl"),
        });
        IReadOnlyList<CrlFetchResult> r = await Client(net).FetchForAsync(["http://pki.test/base.crl"], W.Good, At(World.Now));
        Assert.Equal(2, r.Count);
        Assert.False(r[0].Crl!.IsDelta);
        Assert.True(r[1].Crl!.IsDelta);

        net.Requests.Clear();
        IReadOnlyList<CrlFetchResult> noDelta = await Client(net).FetchForAsync(["http://pki.test/base.crl"], W.Good, new CrlFetchOptions { ReferenceTime = World.Now, FetchDeltas = false });
        Assert.Single(noDelta);
        Assert.DoesNotContain(net.Requests, q => q.Uri.AbsoluteUri.EndsWith("delta.crl", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheNumberOfLocationsTriedIsBounded()
    {
        var net = new FakeNetwork(_ => Reply.Code(404));
        string[] many = [.. Enumerable.Range(0, 50).Select(i => $"http://pki.test/{i}.crl")];
        IReadOnlyList<CrlFetchResult> r = await Client(net).FetchForAsync(many, W.Good, new CrlFetchOptions { ReferenceTime = World.Now, MaxLocations = 3 });
        Assert.Equal(3, r.Count);
    }
}

public class AiaClientTests
{
    private static World W => World.Get();

    private static AiaClient Client(ITransport net) => new(new Fetcher(net, new FetchOptions { Cache = new MemoryFetchCache() }));

    private static byte[] Tlv(byte tag, params byte[][] parts)
    {
        byte[] content = [.. parts.SelectMany(p => p)];
        byte[] len = content.Length < 128 ? [(byte)content.Length] : content.Length < 256 ? [0x81, (byte)content.Length] : [0x82, (byte)(content.Length >> 8), (byte)content.Length];
        return [tag, .. len, .. content];
    }

    /// <summary>A degenerate SignedData (RFC 5652 §5.1) that only carries certificates, as CAs publish for application/pkcs7-mime.</summary>
    internal static byte[] CertsOnly(params Certificate[] certs)
    {
        byte[] signedDataOid = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
        byte[] dataOid = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
        byte[] signedData = Tlv(0x30, [0x02, 0x01, 0x01], Tlv(0x31), Tlv(0x30, dataOid), Tlv(0xA0, [.. certs.Select(c => c.Encoded.ToArray())]), Tlv(0x31));
        return Tlv(0x30, signedDataOid, Tlv(0xA0, signedData));
    }

    [Fact]
    public async Task ASingleDerCertificateIsReadFromACertificateLocation()
    {
        FakeNetwork net = W.Network();
        IReadOnlyList<AiaFetchResult> r = await Client(net).FetchIssuersAsync(W.Good);
        Assert.Single(r);
        Assert.Equal(AiaOutcome.Fetched, r[0].Outcome);
        Assert.Equal(W.Intermediate.Certificate.Encoded.ToArray(), r[0].Certificates.Single().Encoded.ToArray());
    }

    [Fact]
    public async Task APemCertificateAndACertsOnlyMessageAreAccepted()
    {
        var pem = new FakeNetwork(_ => Reply.Ok(Encoding.ASCII.GetBytes(W.Intermediate.Certificate.ToPem() + W.Root.Certificate.ToPem()), "application/x-pem-file"));
        AiaFetchResult p = await Client(pem).FetchAsync(new Uri("http://pki.test/x"));
        Assert.Equal(2, p.Certificates.Count);

        var p7c = new FakeNetwork(_ => Reply.Ok(CertsOnly(W.Intermediate.Certificate, W.Root.Certificate), "application/pkcs7-mime"));
        AiaFetchResult m = await Client(p7c).FetchAsync(new Uri("http://pki.test/x.p7c"));
        Assert.Equal(AiaOutcome.Fetched, m.Outcome);
        Assert.Equal(2, m.Certificates.Count);
        Assert.Equal(W.Root.Certificate.Encoded.ToArray(), m.Certificates[1].Encoded.ToArray());
    }

    [Fact]
    public async Task TheNumberOfCertificatesTakenFromOneResponseIsBounded()
    {
        var p7c = new FakeNetwork(_ => Reply.Ok(CertsOnly(W.Intermediate.Certificate, W.Root.Certificate, W.Good), "application/pkcs7-mime"));
        AiaFetchResult m = await Client(p7c).FetchAsync(new Uri("http://pki.test/x.p7c"), new AiaFetchOptions { MaxCertificatesPerResponse = 2 });
        Assert.Equal(2, m.Certificates.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData("<html>not found</html>")]
    [InlineData("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")]
    public async Task GarbageIsMalformed(string body)
    {
        var net = new FakeNetwork(_ => Reply.Ok(Encoding.ASCII.GetBytes(body), "application/pkix-cert"));
        Assert.Equal(AiaOutcome.Malformed, (await Client(net).FetchAsync(new Uri("http://pki.test/x"))).Outcome);
    }

    [Fact]
    public async Task NonHttpLocationsAndPrivateAddressesAreNotFetched()
    {
        var net = new FakeNetwork(_ => Reply.Ok(W.Intermediate.Certificate.Encoded.ToArray(), "application/pkix-cert"));
        Assert.Equal(AiaOutcome.SchemeNotSupported, (await Client(net).FetchAsync(new Uri("ldap://ldap.test/cn=CA"))).Outcome);
        AiaFetchResult r = await Client(net).FetchAsync(new Uri("http://127.0.0.1/ca.crt"));
        Assert.Equal(AiaOutcome.FetchFailed, r.Outcome);
        Assert.Equal(FetchOutcome.AddressBlocked, r.Fetch!.Outcome);
        Assert.Empty(net.Requests);
    }

    [Fact]
    public async Task IssuerCertificatesAreCached()
    {
        FakeNetwork net = W.Network();
        AiaClient c = Client(net);
        await c.FetchIssuersAsync(W.Good);
        AiaFetchResult again = (await c.FetchIssuersAsync(W.Good)).Single();
        Assert.True(again.Fetch!.FromCache);
        Assert.Single(net.Requests);
    }

    [Fact]
    public async Task TheNumberOfLocationsTriedIsBounded()
    {
        var net = new FakeNetwork(_ => Reply.Code(404));
        IReadOnlyList<AiaFetchResult> r = await Client(net).FetchIssuersAsync(Enumerable.Range(0, 20).Select(i => $"http://pki.test/{i}.crt"), new AiaFetchOptions { MaxLocations = 2 });
        Assert.Equal(2, r.Count);
    }
}
