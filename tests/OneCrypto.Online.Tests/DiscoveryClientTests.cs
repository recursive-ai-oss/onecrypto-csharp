using System.Text;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Online;

namespace OneCrypto.Online.Tests;

/// <summary>
/// WKD, HKP and VKS clients. The scenarios against public services run from recorded exchanges in <c>testdata/online</c>; with
/// <c>ONECRYPTO_ONLINE_LIVE=1</c> the same scenarios run against the services (never in CI), and with <c>ONECRYPTO_ONLINE_RECORD=&lt;directory&gt;</c> as well they write fresh recordings.
/// </summary>
public class DiscoveryClientTests
{
    internal static readonly byte[] WiktorFingerprint = Convert.FromHexString("653909A2F0E37C106F5FAF546C8857E0D8E8F074");

    private static string Data(string name) => Path.Combine(TestFiles.TestData, "online", name + ".exchanges.json");

    private static bool Live => Environment.GetEnvironmentVariable("ONECRYPTO_ONLINE_LIVE") == "1";

    private static string? RecordDir => Environment.GetEnvironmentVariable("ONECRYPTO_ONLINE_RECORD");

    /// <summary>A transport whose name lookups for chosen hosts fail, as for a sub-domain that does not exist.</summary>
    private sealed class MissingHosts : ITransport
    {
        private readonly ITransport _inner;
        private readonly Func<string, bool> _missing;

        public MissingHosts(ITransport inner, Func<string, bool> missing)
        {
            _inner = inner;
            _missing = missing;
        }

        public ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken) =>
            _missing(request.Uri.Host) ? throw new TransportException(TransportFailure.NameResolution, $"the name {request.Uri.Host} did not resolve") : _inner.SendAsync(request, cancellationToken);
    }

    private static ReplayTransport Replay(string name) => new(ExchangeLog.Parse(File.ReadAllBytes(Data(name))));

    private static Fetcher FetcherFor(ITransport t, FetchOptions? o = null) => new(t, o ?? new FetchOptions { Cache = null });

    /// <summary>Runs a scenario from its recording, or live (recording when asked).</summary>
    private static async Task Run(string name, bool live, Func<ITransport, Task> scenario)
    {
        if (!live)
        {
            await scenario(Replay(name));
            return;
        }

        Assert.SkipUnless(Live, "set ONECRYPTO_ONLINE_LIVE=1 to talk to the public services");
        var rec = new RecordingTransport(new HttpTransport());
        await scenario(rec);
        if (RecordDir is not null)
        {
            Directory.CreateDirectory(RecordDir);
            await File.WriteAllBytesAsync(Path.Combine(RecordDir, name + ".exchanges.json"), rec.Log.ToJson());
        }
    }

    // ---- WKD addresses and policy (no network)

    [Fact]
    public void WkdUrlsMatchTheDraftExamples()
    {
        // draft-koch-openpgp-webkey-service §3.1 gives both URLs for Joe.Doe@Example.ORG.
        var a = WkdAddress.Parse("Joe.Doe@Example.ORG");
        Assert.Equal("iy9q119eutrkn8s1mk4r39qejnbu3n5q", a.Hash);
        Assert.Equal("example.org", a.Domain);
        Assert.Equal("https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe", a.KeyUri(WkdMethod.Advanced).AbsoluteUri);
        Assert.Equal("https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe", a.KeyUri(WkdMethod.Direct).AbsoluteUri);
        Assert.Equal("https://openpgpkey.example.org/.well-known/openpgpkey/example.org/policy", a.PolicyUri(WkdMethod.Advanced).AbsoluteUri);
        Assert.Equal("https://example.org/.well-known/openpgpkey/submission-address", a.SubmissionAddressUri(WkdMethod.Direct).AbsoluteUri);
    }

    [Fact]
    public void WkdHashLowersOnlyAsciiAndEscapesTheLocalPartAsWritten()
    {
        Assert.Equal(WkdAddress.HashLocalPart("joe.doe"), WkdAddress.HashLocalPart("JOE.Doe"));
        Assert.NotEqual(WkdAddress.HashLocalPart("\u00c9mile"), WkdAddress.HashLocalPart("\u00e9mile"));
        var a = WkdAddress.Parse("Jo+e.\u00c9@B\u00fccher.example");
        Assert.Equal("xn--bcher-kva.example", a.Domain);
        Assert.EndsWith("?l=Jo%2Be.%C3%89", a.KeyUri(WkdMethod.Direct).AbsoluteUri, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("nobody")]
    [InlineData("@example.org")]
    [InlineData("a@")]
    [InlineData("a b@example.org")]
    [InlineData("a@exa mple.org")]
    [InlineData("a@-example.org")]
    [InlineData("a@exa_mple.org")]
    [InlineData("a@example.org/../x")]
    [InlineData("a@[127.0.0.1]")]
    public void WkdRejectsAddressesThatCannotNameAnEntry(string address)
    {
        Assert.False(WkdAddress.TryParse(address, out _));
    }

    [Fact]
    public void AVeryLongLocalPartIsRefused()
    {
        Assert.False(WkdAddress.TryParse(new string('a', 65) + "@example.org", out _));
        Assert.True(WkdAddress.TryParse(new string('a', 64) + "@example.org", out _));
    }

    [Fact]
    public void PolicyKeywordsAreReadCaseInsensitivelyAndJunkIsCounted()
    {
        var p = WkdPolicy.Parse("# comment\r\nMailbox-Only\r\n\r\nprotocol-version: 3\nsubmission-address:  key-submission@example.org \nexample.org_custom: x\n9bad\nno good\n");
        Assert.True(p.MailboxOnly);
        Assert.False(p.AuthSubmit);
        Assert.Equal(3, p.ProtocolVersion);
        Assert.Equal("key-submission@example.org", p.SubmissionAddress);
        Assert.Equal("x", p.Flags["example.org_custom"]);
        Assert.Equal(2, p.IgnoredLines);
        Assert.Empty(WkdPolicy.Parse(string.Empty).Flags);
    }

    // ---- WKD against recordings of a domain that publishes both ways (fifthhorseman.net, dkg@)

    private static async Task DkgBothMethods(ITransport t)
    {
        var client = new WkdClient(FetcherFor(t));
        WkdLookupResult adv = await client.LookupAsync("dkg@fifthhorseman.net");
        Assert.True(adv.IsSuccess, adv.Reason);
        Assert.Equal(WkdMethod.Advanced, adv.Method);
        Assert.Single(adv.Attempts);
        Assert.Contains("openpgpkey.fifthhorseman.net/.well-known/openpgpkey/fifthhorseman.net/hu/", adv.Uri!.AbsoluteUri, StringComparison.Ordinal);
        Assert.True(adv.Body.Length > 1000);

        // A name that does not resolve for the openpgpkey sub-domain sends the client to the direct method.
        var noAdv = new WkdClient(FetcherFor(new MissingHosts(t, h => h.StartsWith("openpgpkey.", StringComparison.Ordinal))));
        WkdLookupResult direct = await noAdv.LookupAsync("dkg@fifthhorseman.net");
        Assert.True(direct.IsSuccess, direct.Reason);
        Assert.Equal(WkdMethod.Direct, direct.Method);
        Assert.Equal(2, direct.Attempts.Count);
        Assert.Equal(KeyFetchOutcome.FetchFailed, direct.Attempts[0].Value.Outcome);
        Assert.Equal(TransportFailure.NameResolution, direct.Attempts[0].Value.Fetch!.TransportFailure);

        WkdPolicyResult policy = await client.GetPolicyAsync("dkg@fifthhorseman.net");
        Assert.Equal(WkdPolicyOutcome.Present, policy.Outcome);
        Assert.Equal(WkdMethod.Advanced, policy.Method);
        WkdPolicyResult directPolicy = await noAdv.GetPolicyAsync("fifthhorseman.net");
        Assert.Equal(WkdPolicyOutcome.Present, directPolicy.Outcome);
        Assert.Equal(WkdMethod.Direct, directPolicy.Method);

        // The submission-address file is read-only here; this domain may not publish one.
        WkdSubmissionAddressResult sub = await client.GetSubmissionAddressAsync("fifthhorseman.net");
        Assert.True(sub.Outcome is KeyFetchOutcome.Found or KeyFetchOutcome.NotFound, sub.Reason);
    }

    [Fact]
    public Task WkdAdvancedAndDirectFromRecording() => Run("wkd-dkg", false, DkgBothMethods);

    [Fact]
    public Task WkdAdvancedAndDirectLive() => Run("wkd-dkg", true, DkgBothMethods);

    // ---- WKD: a missing policy (wiktor.eu has no openpgpkey sub-domain and no policy file) and a 404 (info@fsfe.org)

    private static async Task MissingPolicy(ITransport t)
    {
        var client = new WkdClient(FetcherFor(new MissingHosts(t, h => h.StartsWith("openpgpkey.", StringComparison.Ordinal))));
        WkdPolicyResult p = await client.GetPolicyAsync("wkd@wiktor.eu");
        Assert.Equal(WkdPolicyOutcome.Missing, p.Outcome);
        Assert.Equal(WkdMethod.Direct, p.Method);
        Assert.Equal(404, p.Fetch!.StatusCode);

        WkdLookupResult key = await client.LookupAsync("wkd@wiktor.eu", new WkdOptions { RequirePolicy = true });
        Assert.Equal(KeyFetchOutcome.PolicyMissing, key.Outcome);
        Assert.Empty(key.Attempts);
    }

    [Fact]
    public Task WkdMissingPolicyFromRecording() => Run("wkd-missing-policy", false, MissingPolicy);

    [Fact]
    public Task WkdMissingPolicyLive() => Run("wkd-missing-policy", true, MissingPolicy);

    private static async Task NoSuchKey(ITransport t)
    {
        var client = new WkdClient(FetcherFor(t));
        WkdLookupResult r = await client.LookupAsync("info@fsfe.org");
        Assert.Equal(KeyFetchOutcome.NotFound, r.Outcome);
        Assert.Equal(404, r.Fetch!.StatusCode);

        // A 404 from the advanced host is an answer: the direct method is not tried.
        Assert.Single(r.Attempts);
        Assert.Equal(WkdMethod.Advanced, r.Method);
    }

    [Fact]
    public Task WkdNotFoundFromRecording() => Run("wkd-not-found", false, NoSuchKey);

    [Fact]
    public Task WkdNotFoundLive() => Run("wkd-not-found", true, NoSuchKey);

    [Fact]
    public async Task WkdOversizeAnswerIsRefused()
    {
        ReplayTransport t = Replay("wkd-dkg");
        var client = new WkdClient(FetcherFor(t));
        WkdLookupResult r = await client.LookupAsync("dkg@fifthhorseman.net", new WkdOptions { MaxResponseBytes = 2000 });
        Assert.Equal(KeyFetchOutcome.FetchFailed, r.Outcome);
        Assert.Equal(FetchOutcome.ResponseTooLarge, r.Fetch!.Outcome);
        Assert.True(r.Body.IsEmpty);
    }

    // ---- WKD with a server that redirects, refuses or misbehaves (hand-made exchanges)

    private static string AdvUri(string address) => WkdAddress.Parse(address).KeyUri(WkdMethod.Advanced).AbsoluteUri;

    private static ExchangeLog Log(params RecordedExchange[] e) => new() { Exchanges = [.. e] };

    private static RecordedExchange Ex(string uri, int status, byte[]? body = null, params (string, string)[] headers) => new()
    {
        Uri = uri,
        Status = status,
        Body = body ?? [],
        Headers = [.. headers.Select(h => new RecordedHeader { Name = h.Item1, Value = h.Item2 })],
    };

    [Fact]
    public async Task WkdFollowsAnHttpsRedirectToAnotherHost()
    {
        byte[] key = [0x99, 0x01, 0x02];
        var t = new ReplayTransport(Log(
            Ex(AdvUri("a@example.org"), 302, null, ("Location", "https://keys.example.net/dir/a")),
            Ex("https://keys.example.net/dir/a", 200, key)));
        WkdLookupResult r = await new WkdClient(FetcherFor(t)).LookupAsync("a@example.org");
        Assert.True(r.IsSuccess, r.Reason);
        Assert.Equal(key, r.Body.ToArray());
        Assert.Equal("keys.example.net", r.Uri!.Host);
        Assert.Single(r.Fetch!.Redirects);
    }

    [Theory]
    [InlineData("http://keys.example.net/a", FetchOutcome.RedirectRejected)]
    [InlineData("https://127.0.0.1/a", FetchOutcome.AddressBlocked)]
    [InlineData("https://192.168.1.10/a", FetchOutcome.AddressBlocked)]
    [InlineData("https://user:pw@keys.example.net/a", FetchOutcome.UserInfoNotAllowed)]
    public async Task WkdRefusesRedirectsOffHttpsOrIntoPrivateRanges(string location, FetchOutcome expected)
    {
        var t = new ReplayTransport(Log(Ex(AdvUri("a@example.org"), 301, null, ("Location", location))));
        WkdLookupResult r = await new WkdClient(FetcherFor(t)).LookupAsync("a@example.org");
        Assert.Equal(KeyFetchOutcome.FetchFailed, r.Outcome);
        Assert.Equal(expected, r.Fetch!.Outcome);
        Assert.Single(t.Requests);
    }

    [Theory]
    [InlineData("a@localhost")]
    [InlineData("a@mail.localhost")]
    [InlineData("a@127.0.0.1")]
    [InlineData("a@10.1.2.3")]
    public async Task WkdDoesNotLetAnAddressPointTheClientAtThePrivateNetwork(string address)
    {
        // The domain of an address comes from a message: a loopback or private name is refused before any request is sent, and a name that does not resolve is the only trigger for the direct method.
        var net = new FakeNetwork(_ => Reply.Ok([1], "application/octet-stream"));
        var transport = new MissingHosts(net, h => h.StartsWith("openpgpkey.", StringComparison.Ordinal));
        WkdLookupResult r = await new WkdClient(FetcherFor(transport)).LookupAsync(address);
        Assert.False(r.IsSuccess);
        Assert.Empty(net.Requests);
    }

    [Fact]
    public async Task WkdNeverAnswersAnAuthenticationChallenge()
    {
        var t = new ReplayTransport(Log(Ex(AdvUri("a@example.org"), 401, null, ("WWW-Authenticate", "Basic realm=\"mail\""))));
        WkdLookupResult r = await new WkdClient(FetcherFor(t)).LookupAsync("a@example.org");
        Assert.Equal(KeyFetchOutcome.Unauthorized, r.Outcome);
        Assert.Single(t.Requests);
    }

    [Fact]
    public async Task WkdFallsBackOnlyWhenTheSubdomainDoesNotExist()
    {
        var adv = AdvUri("a@example.org");
        byte[] key = [0x99, 0x01];
        var direct = WkdAddress.Parse("a@example.org").KeyUri(WkdMethod.Direct).AbsoluteUri;

        // A host that is down is not a host that does not exist.
        var down = new FakeNetwork(r => r.Uri.Host.StartsWith("openpgpkey.", StringComparison.Ordinal) ? throw new TransportException(TransportFailure.Connect, "refused") : Reply.Ok(key, "application/octet-stream"));
        WkdLookupResult a = await new WkdClient(FetcherFor(down)).LookupAsync("a@example.org");
        Assert.Equal(KeyFetchOutcome.FetchFailed, a.Outcome);
        Assert.Single(a.Attempts);

        // A 404 is an answer too, unless the caller asks for the lenient fallback.
        var notFound = new FakeNetwork(r => r.Uri.AbsoluteUri == adv ? Reply.Code(404) : Reply.Ok(key, "application/octet-stream"));
        Assert.Equal(KeyFetchOutcome.NotFound, (await new WkdClient(FetcherFor(notFound)).LookupAsync("a@example.org")).Outcome);
        WkdLookupResult lenient = await new WkdClient(FetcherFor(notFound)).LookupAsync("a@example.org", new WkdOptions { FallbackOnAnyAdvancedFailure = true });
        Assert.True(lenient.IsSuccess);
        Assert.Equal(direct, lenient.Uri!.AbsoluteUri);
    }

    [Fact]
    public async Task WkdEmptyAnswerAndBadAddressesSendNothingOrReportThem()
    {
        var t = new FakeNetwork(_ => Reply.Ok([], "application/octet-stream"));
        var client = new WkdClient(FetcherFor(t));
        Assert.Equal(KeyFetchOutcome.EmptyResponse, (await client.LookupAsync("a@example.org")).Outcome);
        t.Requests.Clear();
        Assert.Equal(KeyFetchOutcome.InvalidQuery, (await client.LookupAsync("not an address")).Outcome);
        Assert.Empty(t.Requests);
    }

    [Fact]
    public void ConstructingClientsFetchesNothing()
    {
        var t = new FakeNetwork(_ => Reply.Code(500));
        var f = FetcherFor(t);
        _ = new WkdClient(f);
        _ = new HkpClient(f, HkpServer.Parse("hkps://keys.example.org"));
        _ = new VksClient(f);
        Assert.Empty(t.Requests);
    }

    [Fact]
    public async Task WkdHonoursCancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var client = new WkdClient(FetcherFor(new FakeNetwork(_ => Reply.Ok([1], "x/y"))));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await client.LookupAsync("a@example.org", null, cts.Token));
    }

    [Fact]
    public async Task WkdSubmissionAddressMustBeOneLine()
    {
        string uri = WkdAddress.Parse("x@example.org").SubmissionAddressUri(WkdMethod.Advanced).AbsoluteUri;
        async Task<WkdSubmissionAddressResult> Ask(string body) => await new WkdClient(FetcherFor(new FakeNetwork(r => r.Uri.AbsoluteUri == uri ? Reply.Ok(Encoding.ASCII.GetBytes(body), "text/plain") : Reply.Code(404)))).GetSubmissionAddressAsync("example.org");

        WkdSubmissionAddressResult ok = await Ask("key-submission-example.org@directory.example.org\r\n");
        Assert.Equal("key-submission-example.org@directory.example.org", ok.Address);
        Assert.Null((await Ask("one@example.org\ntwo@example.org\n")).Address);
        Assert.Null((await Ask("not an address\n")).Address);
    }

    // ---- HKP and VKS against keys.openpgp.org (Wiktor Kwapisiewicz's published key)

    private static async Task HkpScenario(ITransport t)
    {
        var client = new HkpClient(FetcherFor(t), HkpServer.Parse("hkps://keys.openpgp.org"));
        string fpr = HkpSearch.Fingerprint(WiktorFingerprint);

        KeyFetchResult get = await client.GetAsync(fpr);
        Assert.True(get.IsSuccess, get.Reason);
        Assert.Equal("application/pgp-keys", get.Fetch!.ContentType);
        Assert.StartsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----", Encoding.ASCII.GetString(get.Body.Span[..40]), StringComparison.Ordinal);

        HkpIndexResult index = await client.IndexAsync(fpr);
        Assert.True(index.Result.IsSuccess, index.Result.Reason);
        Assert.NotNull(index.Index);
        HkpIndexEntry e = Assert.Single(index.Index!.Entries);
        Assert.Equal(Convert.ToHexString(WiktorFingerprint), e.KeyId);
        Assert.True(e.IsFingerprint);
        Assert.Contains(e.UserIds, u => u.Text.Contains("wiktor@", StringComparison.Ordinal));

        // This service does not do vindex.
        HkpIndexResult v = await client.VerboseIndexAsync(fpr);
        Assert.False(v.Result.IsSuccess);

        KeyFetchResult none = await client.GetAsync("0x" + new string('A', 40));
        Assert.Equal(KeyFetchOutcome.NotFound, none.Outcome);
    }

    [Fact]
    public Task HkpFromRecording() => Run("hkp-keys-openpgp-org", false, HkpScenario);

    [Fact]
    public Task HkpLive() => Run("hkp-keys-openpgp-org", true, HkpScenario);

    private static async Task VksScenario(ITransport t)
    {
        var client = new VksClient(FetcherFor(t));
        string fpr = Convert.ToHexString(WiktorFingerprint);

        KeyFetchResult byFpr = await client.ByFingerprintAsync(fpr.ToLowerInvariant());
        Assert.True(byFpr.IsSuccess, byFpr.Reason);
        Assert.EndsWith("/vks/v1/by-fingerprint/" + fpr, byFpr.Uri!.AbsoluteUri, StringComparison.Ordinal);

        KeyFetchResult byId = await client.ByKeyIdAsync(fpr[^16..]);
        Assert.True(byId.IsSuccess, byId.Reason);

        KeyFetchResult byMail = await client.ByEmailAsync("wiktor@archlinux.org");
        Assert.True(byMail.IsSuccess, byMail.Reason);
        Assert.EndsWith("/vks/v1/by-email/wiktor%40archlinux.org", byMail.Uri!.AbsoluteUri, StringComparison.Ordinal);

        KeyFetchResult none = await client.ByFingerprintAsync(new string('B', 40));
        Assert.Equal(KeyFetchOutcome.NotFound, none.Outcome);
    }

    [Fact]
    public Task VksFromRecording() => Run("vks-keys-openpgp-org", false, VksScenario);

    [Fact]
    public Task VksLive() => Run("vks-keys-openpgp-org", true, VksScenario);

    // ---- VKS and HKP details that need no service

    [Fact]
    public async Task VksChecksItsInputBeforeSendingAnything()
    {
        var t = new FakeNetwork(_ => Reply.Code(500));
        var c = new VksClient(FetcherFor(t));
        Assert.Equal(KeyFetchOutcome.InvalidQuery, (await c.ByFingerprintAsync("1234")).Outcome);
        Assert.Equal(KeyFetchOutcome.InvalidQuery, (await c.ByFingerprintAsync(new string('G', 40))).Outcome);
        Assert.Equal(KeyFetchOutcome.InvalidQuery, (await c.ByKeyIdAsync("0x1234567890ABCDEF")).Outcome);
        Assert.Equal(KeyFetchOutcome.InvalidQuery, (await c.ByEmailAsync("a b@example.org")).Outcome);
        Assert.Empty(t.Requests);
    }

    [Fact]
    public async Task VksEmailInThePathIsEscapedSoItCannotChangeTheRoute()
    {
        var t = new FakeNetwork(_ => Reply.Code(404));
        await new VksClient(FetcherFor(t)).ByEmailAsync("a/b?c#d@example.org");
        Assert.Equal("https://keys.openpgp.org/vks/v1/by-email/a%2Fb%3Fc%23d%40example.org", Assert.Single(t.Requests).Uri.AbsoluteUri);
    }

    [Fact]
    public async Task VksUploadAndVerificationParseTheServersReport()
    {
        var t = new FakeNetwork(r =>
        {
            string body = Encoding.UTF8.GetString(r.Body.Span);
            return r.Uri.AbsolutePath switch
            {
                "/vks/v1/upload" => Reply.Ok(Encoding.UTF8.GetBytes($$"""{"key_fpr":"{{new string('a', 40)}}","status":{"a@example.org":"unpublished","b@example.org":"pending","c@example.org":"odd"},"token":"tok-1"}"""), "application/json"),
                "/vks/v1/request-verify" => body.Contains("tok-1", StringComparison.Ordinal) && body.Contains("\"locale\":[\"de_CH\"]", StringComparison.Ordinal)
                    ? Reply.Ok(Encoding.UTF8.GetBytes($$"""{"key_fpr":"{{new string('A', 40)}}","status":{"a@example.org":"pending"},"token":"tok-2"}"""), "application/json")
                    : Reply.Code(400),
                _ => Reply.Code(404),
            };
        });
        var c = new VksClient(FetcherFor(t));
        VksUploadResult up = await c.UploadAsync("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n");
        Assert.True(up.IsSuccess, up.Reason);
        Assert.Equal(new string('A', 40), up.Fingerprint);
        Assert.Equal("tok-1", up.Token);
        Assert.Equal(VksEmailStatus.Unpublished, up.Status["a@example.org"]);
        Assert.Equal(VksEmailStatus.Pending, up.Status["b@example.org"]);
        Assert.Equal(VksEmailStatus.Unknown, up.Status["c@example.org"]);
        Assert.Contains(t.Requests, r => r.Method == "POST" && r.Headers.Any(h => h.Key == "Content-Type" && h.Value == "application/json"));

        VksUploadResult ver = await c.RequestVerifyAsync("tok-1", ["a@example.org"], ["de_CH"]);
        Assert.True(ver.IsSuccess, ver.Reason);
        Assert.Equal(VksEmailStatus.Pending, ver.Status["a@example.org"]);
    }

    [Fact]
    public async Task VksUploadRefusesSecretKeysAndReportsRejections()
    {
        var t = new FakeNetwork(_ => Reply.Code(503));
        var c = new VksClient(FetcherFor(t));
        Assert.Equal(KeyUploadOutcome.InvalidInput, (await c.UploadAsync("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nAA\n-----END PGP PRIVATE KEY BLOCK-----")).Outcome);
        Assert.Equal(KeyUploadOutcome.InvalidInput, (await c.UploadAsync("  ")).Outcome);
        Assert.Empty(t.Requests);
        Assert.Equal(KeyUploadOutcome.FetchFailed, (await c.UploadAsync("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAA\n-----END PGP PUBLIC KEY BLOCK-----")).Outcome);
        Assert.Equal(KeyUploadOutcome.InvalidInput, (await c.RequestVerifyAsync("", ["a@example.org"])).Outcome);

        var junk = new FakeNetwork(_ => Reply.Ok("not json"u8.ToArray(), "application/json"));
        Assert.Equal(KeyUploadOutcome.FetchFailed, (await new VksClient(FetcherFor(junk)).UploadAsync("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAA\n-----END PGP PUBLIC KEY BLOCK-----")).Outcome);
    }

    [Fact]
    public async Task RateLimitCarriesRetryAfter()
    {
        var t = new FakeNetwork(_ => new Reply(429, [], ("Retry-After", "60")));
        KeyFetchResult r = await new VksClient(FetcherFor(t)).ByEmailAsync("a@example.org");
        Assert.Equal(KeyFetchOutcome.RateLimited, r.Outcome);
        Assert.Equal(TimeSpan.FromSeconds(60), r.RetryAfter);

        var huge = new FakeNetwork(_ => new Reply(429, [], ("Retry-After", "99999999")));
        Assert.Equal(TimeSpan.FromDays(1), (await new VksClient(FetcherFor(huge)).ByEmailAsync("a@example.org")).RetryAfter);
    }

    [Fact]
    public async Task HkpUploadIsFormEncodedAndOnlyWhenAsked()
    {
        var t = new FakeNetwork(_ => Reply.Ok("Key block added"u8.ToArray(), "text/plain"));
        var c = new HkpClient(FetcherFor(t), HkpServer.Parse("hkp://keys.example.org"));
        Assert.Empty(t.Requests);
        string armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAb+/=\n-----END PGP PUBLIC KEY BLOCK-----\n";
        KeyUploadResult r = await c.UploadAsync(armor);
        Assert.True(r.IsSuccess);
        TransportRequest req = Assert.Single(t.Requests);
        Assert.Equal("POST", req.Method);
        Assert.Equal("http://keys.example.org:11371/pks/add", req.Uri.AbsoluteUri);
        Assert.Contains(req.Headers, h => h.Key == "Content-Type" && h.Value == "application/x-www-form-urlencoded");
        Assert.Equal("keytext=-----BEGIN+PGP+PUBLIC+KEY+BLOCK-----%0A%0AAb%2B%2F%3D%0A-----END+PGP+PUBLIC+KEY+BLOCK-----%0A", Encoding.ASCII.GetString(req.Body.Span));

        Assert.Equal(KeyUploadOutcome.InvalidInput, (await c.UploadAsync("-----BEGIN PGP PRIVATE KEY BLOCK-----\n")).Outcome);
        Assert.Equal(KeyUploadOutcome.Rejected, (await new HkpClient(FetcherFor(new FakeNetwork(_ => Reply.Code(422))), HkpServer.Parse("keys.example.org")).UploadAsync(armor)).Outcome);
        Assert.Equal(KeyUploadOutcome.NotAccepted, (await new HkpClient(FetcherFor(new FakeNetwork(_ => Reply.Code(403))), HkpServer.Parse("keys.example.org")).UploadAsync(armor)).Outcome);
    }

    [Fact]
    public async Task HkpLookupUrlsAndServerAddresses()
    {
        var t = new FakeNetwork(_ => Reply.Ok("x"u8.ToArray(), "text/plain"));
        var c = new HkpClient(FetcherFor(t), HkpServer.Parse("hkps://keys.example.org"));
        await c.GetAsync("a b&c=d");
        await c.IndexAsync("0x" + new string('A', 16));
        Assert.Equal("https://keys.example.org/pks/lookup?op=get&options=mr&fingerprint=on&search=a%20b%26c%3Dd", t.Requests[0].Uri.AbsoluteUri);
        Assert.Contains("op=index&options=mr", t.Requests[1].Uri.AbsoluteUri, StringComparison.Ordinal);

        Assert.Equal("https://keys.example.org/", HkpServer.Parse("keys.example.org").BaseUri.AbsoluteUri);
        Assert.Equal("http://k.example:11371/", HkpServer.Parse("hkp://k.example").BaseUri.AbsoluteUri);
        Assert.Equal("http://k.example:8080/", HkpServer.Parse("http://k.example:8080").BaseUri.AbsoluteUri);
        Assert.False(HkpServer.TryParse("ftp://k.example", out _));
        Assert.False(HkpServer.TryParse("https://k.example/pks", out _));
        Assert.False(HkpServer.TryParse("https://user@k.example", out _));
        Assert.Equal(KeyFetchOutcome.InvalidQuery, (await c.GetAsync(" ")).Outcome);
        Assert.Throws<ArgumentException>(() => HkpSearch.Fingerprint(new byte[19]));
    }

    [Theory]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("[::1%25eth0]")]
    [InlineData("a b")]
    [InlineData("hkps://")]
    public void HkpServerAddressesThatCannotBeRebuiltAreRefusedNotThrown(string value)
    {
        // Found by fuzzing: a host the URI parser accepts but cannot rebuild as an authority.
        _ = HkpServer.TryParse(value, out _);
    }

    [Fact]
    public async Task HkpAndVksWorkOverARealSocketAgainstALocalKeyserver()
    {
        // A caller-written server address may be on the loopback interface; only what the server redirects to is address-checked.
        string stored = string.Empty;
        using var server = new TestServer((line, headers, body) =>
        {
            if (line.StartsWith("POST /pks/add", StringComparison.Ordinal))
            {
                stored = Encoding.ASCII.GetString(body) + "|" + headers.GetValueOrDefault("content-type", string.Empty);
                return TestServer.Response(200, "OK", "Key block added to key server database."u8.ToArray(), "Content-Type: text/plain");
            }

            if (line.Contains("op=index", StringComparison.Ordinal))
            {
                return TestServer.Response(200, "OK", "info:1:1\r\npub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:22:256:1500000000::\r\nuid:Alice:::\r\n"u8.ToArray(), "Content-Type: text/plain");
            }

            if (line.StartsWith("GET /vks/v1/by-email/", StringComparison.Ordinal))
            {
                return TestServer.Response(200, "OK", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAA==\n-----END PGP PUBLIC KEY BLOCK-----\n"u8.ToArray(), "Content-Type: application/pgp-keys");
            }

            return line.Contains("op=get", StringComparison.Ordinal)
                ? TestServer.Response(200, "OK", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAA==\n-----END PGP PUBLIC KEY BLOCK-----\n"u8.ToArray(), "Content-Type: application/pgp-keys")
                : TestServer.Response(404, "Not Found", []);
        });
        using var transport = new HttpTransport();
        var fetcher = FetcherFor(transport);
        var hkp = new HkpClient(fetcher, HkpServer.Parse($"http://127.0.0.1:{server.Port}"));

        KeyFetchResult got = await hkp.GetAsync("0x" + new string('A', 40));
        Assert.True(got.IsSuccess, got.Reason);
        Assert.Equal("application/pgp-keys", got.Fetch!.ContentType);
        HkpIndexResult index = await hkp.IndexAsync("alice");
        Assert.Equal("Alice", index.Index!.Entries[0].UserIds[0].Text);
        KeyUploadResult up = await hkp.UploadAsync("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAA==\n-----END PGP PUBLIC KEY BLOCK-----\n");
        Assert.True(up.IsSuccess, up.Reason);
        Assert.StartsWith("keytext=-----BEGIN+PGP+PUBLIC+KEY+BLOCK-----%0A%0AAA%3D%3D%0A", stored, StringComparison.Ordinal);
        Assert.EndsWith("|application/x-www-form-urlencoded", stored, StringComparison.Ordinal);

        KeyFetchResult mail = await new VksClient(fetcher, new Uri($"http://127.0.0.1:{server.Port}")).ByEmailAsync("a@example.org");
        Assert.True(mail.IsSuccess, mail.Reason);
    }

    [Fact]
    public async Task AWkdDomainThatResolvesToTheLoopbackIsBlockedWhenConnecting()
    {
        // DNS names under the control of a message sender must not reach the local machine, whatever the name looks like.
        var resolver = new TestResolver(("openpgpkey.evil.test", "127.0.0.1"), ("evil.test", "127.0.0.1"));
        using var transport = new HttpTransport(new HttpTransportOptions { Resolver = resolver });
        WkdLookupResult r = await new WkdClient(FetcherFor(transport)).LookupAsync("a@evil.test");
        Assert.Equal(KeyFetchOutcome.FetchFailed, r.Outcome);
        Assert.Equal(FetchOutcome.AddressBlocked, r.Fetch!.Outcome);
        Assert.Single(r.Attempts);
    }

    [Fact]
    public async Task HkpHtmlAnswerIsNotAnIndex()
    {
        var t = new FakeNetwork(_ => Reply.Ok("<html><body>Search results</body></html>"u8.ToArray(), "text/html"));
        HkpIndexResult r = await new HkpClient(FetcherFor(t), HkpServer.Parse("keys.example.org")).IndexAsync("x");
        Assert.Null(r.Index);
        Assert.False(r.Result.IsSuccess);
    }

    // ---- The index format

    [Fact]
    public void IndexParsesTheDraftsRecords()
    {
        string text = "info:1:2\r\npub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:22:256:1500000000:1600000000:r\r\nuid:Alice%20%3Calice%40example.org%3E %3A%25:1500000001::\r\nuid:%C3%89mile:1500000002:1700000000:e\r\npub:0123456789ABCDEF:1:3072:1400000000::\r\nuid:Bob%E2\r\nsub:XX:1:1\r\ntru:::\r\n";
        Assert.True(HkpIndex.TryParse(Encoding.UTF8.GetBytes(text), out HkpIndex? i));
        Assert.Equal(1, i!.Version);
        Assert.Equal(2, i.DeclaredCount);
        Assert.Equal(2, i.Entries.Count);
        HkpIndexEntry a = i.Entries[0];
        Assert.True(a.IsFingerprint);
        Assert.True(a.IsRevoked);
        Assert.Equal(22, a.Algorithm);
        Assert.Equal(256, a.Bits);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1500000000), a.Created);
        Assert.Equal("Alice <alice@example.org> :%", a.UserIds[0].Text);
        Assert.Null(a.UserIds[0].Expires);
        Assert.Equal("\u00c9mile", a.UserIds[1].Text);
        Assert.True(a.UserIds[1].IsExpired);
        Assert.False(i.Entries[1].IsFingerprint);
        Assert.Null(i.Entries[1].Expires);
        Assert.Contains('\uFFFD', i.Entries[1].UserIds[0].Text);
    }

    [Fact]
    public void IndexToleratesWhatTheDraftLeavesOpenAndRefusesWhatIsNotAnIndex()
    {
        Assert.True(HkpIndex.TryParse("info:1:0\n"u8, out HkpIndex? empty));
        Assert.Empty(empty!.Entries);
        Assert.True(HkpIndex.TryParse("pub:AAAAAAAAAAAAAAAA\n"u8, out HkpIndex? bare));
        Assert.Single(bare!.Entries);
        Assert.True(HkpIndex.TryParse("pub:nothex!:1:2:3:4:\nuid:orphan\npub:BBBBBBBBBBBBBBBB:x:y:z:\n"u8, out HkpIndex? odd));
        Assert.Single(odd!.Entries);
        Assert.Null(odd.Entries[0].Algorithm);
        Assert.False(HkpIndex.TryParse(""u8, out _));
        Assert.False(HkpIndex.TryParse("<html>pub:AAAA</html>"u8, out _));
        Assert.False(HkpIndex.TryParse([0xFF, 0xFE, 0x00], out _));
        Assert.Throws<FormatException>(() => HkpIndex.Parse("nothing"u8));
    }

    [Fact]
    public void IndexBoundsWhatAHostileServerCanInflate()
    {
        var sb = new StringBuilder("info:1:99999\n");
        for (int i = 0; i < HkpIndex.MaxEntries + 5; i++)
        {
            sb.Append("pub:").Append(i.ToString("X16", System.Globalization.CultureInfo.InvariantCulture)).Append(":1:1:1:1:\n");
        }

        Assert.True(HkpIndex.TryParse(Encoding.ASCII.GetBytes(sb.ToString()), out HkpIndex? big));
        Assert.Equal(HkpIndex.MaxEntries, big!.Entries.Count);
        Assert.True(big.Truncated);

        var uids = new StringBuilder("pub:AAAAAAAAAAAAAAAA\n");
        for (int i = 0; i < HkpIndex.MaxUserIdsPerEntry + 3; i++)
        {
            uids.Append("uid:u\n");
        }

        Assert.True(HkpIndex.TryParse(Encoding.ASCII.GetBytes(uids.ToString()), out HkpIndex? many));
        Assert.Equal(HkpIndex.MaxUserIdsPerEntry, many!.Entries[0].UserIds.Count);

        // A single enormous line and a very long percent-escape run are skipped or decoded in linear time.
        string line = "pub:AAAAAAAAAAAAAAAA\nuid:" + string.Concat(Enumerable.Repeat("%C3", 30000)) + "\n";
        Assert.True(HkpIndex.TryParse(Encoding.ASCII.GetBytes(line), out HkpIndex? run));
        Assert.Single(run!.Entries);
        Assert.True(HkpIndex.TryParse(Encoding.ASCII.GetBytes("pub:AAAAAAAAAAAAAAAA\nuid:" + new string('x', 70000) + "\n"), out HkpIndex? longLine));
        Assert.Empty(longLine!.Entries[0].UserIds);
    }
}
