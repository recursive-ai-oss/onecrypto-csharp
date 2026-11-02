using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Online.Csc;

namespace OneCrypto.Online.Tests.Csc;

/// <summary>The guards of the library's fetcher on CSC URLs, malformed answers, and the promise that no credential shows up where it should not.</summary>
public class CscGuardTests
{
    private const string Secret = "tok-SECRET-0123456789";

    private static CscClient Client(ITransport net, CscClientOptions? options = null, FetchOptions? fetch = null, Uri? baseUri = null) =>
        new(new Fetcher(net, fetch ?? new FetchOptions { Cache = null }), baseUri ?? CscRig.Base, new CscStaticTokenSource(new CscAccessToken(Secret)), options);

    private static Reply Json(string json, int status = 200) => new(status, Encoding.UTF8.GetBytes(json), ("Content-Type", "application/json"));

    [Fact]
    public async Task ARedirectIsNeverFollowedBecauseTheRequestCarriesACredential()
    {
        var rig = new CscRig();
        rig.Transport.RedirectTo = "http://169.254.169.254/latest/meta-data/";
        CscResult<CscCredentialList> r = await rig.Client.ListCredentialsAsync();
        Assert.Equal(CscOutcome.TransportFailed, r.Outcome);
        Assert.Equal(FetchOutcome.TooManyRedirects, r.Fetch!.Outcome);
        Assert.Single(rig.Transport.Requests);
    }

    [Fact]
    public async Task TheResponseSizeLimitApplies()
    {
        var rig = new CscRig(options: new CscClientOptions { MaxResponseBytes = 64 });
        CscResult<CscServiceInfo> r = await rig.Client.InfoAsync();
        Assert.Equal(CscOutcome.TransportFailed, r.Outcome);
        Assert.Equal(FetchOutcome.ResponseTooLarge, r.Fetch!.Outcome);
    }

    [Fact]
    public async Task AUrlFromOutsideCannotReachALoopbackOrPrivateAddress()
    {
        foreach (string host in new[] { "127.0.0.1", "10.1.2.3", "169.254.169.254", "[::1]", "localhost" })
        {
            var net = new FakeNetwork(_ => Json("{}"));
            CscClient c = Client(net, new CscClientOptions { Origin = UrlOrigin.Certificate }, baseUri: new Uri($"https://{host}/csc/v2/"));
            CscResult<CscServiceInfo> r = await c.InfoAsync();
            Assert.Equal(CscOutcome.TransportFailed, r.Outcome);
            Assert.Equal(FetchOutcome.AddressBlocked, r.Fetch!.Outcome);
            Assert.Empty(net.Requests);
        }
    }

    [Fact]
    public async Task ACallerWrittenUrlMayBeLocalButItsRequestsAskForNoAddressGuard()
    {
        var net = new FakeNetwork(_ => Json("{\"specs\":\"2.2.0.0\",\"name\":\"local\"}"));
        CscResult<CscServiceInfo> r = await Client(net, baseUri: new Uri("http://127.0.0.1:8080/csc/v2/")).InfoAsync();
        Assert.True(r.IsSuccess, r.Reason);
        Assert.Null(net.Requests.Single().Guard);
    }

    [Theory]
    [InlineData("ftp://csc.test/")]
    [InlineData("file:///etc/")]
    [InlineData("https://user:pw@csc.test/")]
    [InlineData("/relative/")]
    public void OnlyAbsoluteHttpUrlsWithoutUserInformationAreAccepted(string url)
    {
        var fetcher = new Fetcher(new FakeNetwork(_ => Json("{}")));
        Assert.Throws<ArgumentException>(() => new CscClient(fetcher, new Uri(url, UriKind.RelativeOrAbsolute)));
    }

    [Fact]
    public async Task ConstructingAndNeverCallingDoesNoIo()
    {
        var net = new FakeNetwork(_ => Json("{}"));
        _ = Client(net);
        _ = new CscClientCredentialsTokenSource(new Fetcher(net), new Uri("https://csc.test/oauth2/token"), "a", "b");
        await Task.Yield();
        Assert.Empty(net.Requests);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("[1,2,3]")]
    [InlineData("{\"specs\":5,\"name\":\"x\"}")]
    [InlineData("{\"name\":\"x\"}")]
    [InlineData("{\"specs\":\"2.2.0.0\",\"name\":\"x\",\"authType\":\"basic\"}")]
    [InlineData("{\"specs\":\"2.2.0.0\",\"name\":\"x\",\"signAlgorithms\":[]}")]
    public async Task AMalformedInfoAnswerIsReportedNotThrown(string body)
    {
        var net = new FakeNetwork(_ => Json(body));
        CscResult<CscServiceInfo> r = await Client(net).InfoAsync();
        Assert.Equal(CscOutcome.MalformedResponse, r.Outcome);
        Assert.NotEmpty(r.Reason);
    }

    [Fact]
    public async Task AStringThatIsNotValidUtf8IsMalformedNotAnException()
    {
        // Found by the fuzz target: the JSON reader checks structure but transcodes a string only when it is read.
        byte[] body = [.. Encoding.UTF8.GetBytes("{\"specs\":\"2.2.0.0\",\"name\":\"s\",\"authType\":[\"oauth2cod"), 0xE5, .. Encoding.UTF8.GetBytes("\"]}")];
        var net = new FakeNetwork(_ => new Reply(200, body, ("Content-Type", "application/json")));
        Assert.Equal(CscOutcome.MalformedResponse, (await Client(net).InfoAsync()).Outcome);
        var error = new FakeNetwork(_ => new Reply(400, [.. Encoding.UTF8.GetBytes("{\"error\":\"x"), 0xE5, .. Encoding.UTF8.GetBytes("\"}")]));
        Assert.Equal(CscOutcome.ServiceError, (await Client(error).ListCredentialsAsync()).Outcome);
    }

    [Fact]
    public async Task HostileJsonIsBoundedAndReportedAsMalformed()
    {
        string deep = string.Concat(Enumerable.Repeat("{\"a\":", 500)) + "1" + new string('}', 500);
        var many = new StringBuilder("{\"credentialIDs\":[");
        for (int i = 0; i < 5000; i++)
        {
            many.Append(i == 0 ? "\"a\"" : ",\"a\"");
        }

        many.Append("]}");
        foreach (string body in new[] { deep, many.ToString(), "{\"credentialIDs\":[\"" + new string('x', 100_000) + "\"]}" })
        {
            var net = new FakeNetwork(_ => Json(body));
            CscResult<CscCredentialList> r = await Client(net).ListCredentialsAsync();
            Assert.Equal(CscOutcome.MalformedResponse, r.Outcome);
        }
    }

    [Theory]
    [InlineData("{\"credentialIDs\":[],\"credentialInfos\":[1]}")]
    [InlineData("{\"credentialInfos\":[\"x\",null,[]]}")]
    [InlineData("{\"credentialIDs\":{}}")]
    public async Task ACredentialListWithTheWrongShapeIsMalformed(string body)
    {
        // The first form was found by the fuzz target: an element that is not an object.
        var net = new FakeNetwork(_ => Json(body));
        Assert.Equal(CscOutcome.MalformedResponse, (await Client(net).ListCredentialsAsync()).Outcome);
    }

    [Theory]
    [InlineData("{\"key\":{\"status\":\"enabled\",\"algo\":[],\"len\":2048},\"auth\":{\"mode\":\"telepathy\"}}")]
    [InlineData("{\"key\":{\"status\":\"enabled\",\"algo\":[],\"len\":2048},\"cert\":{\"certificates\":[\"!!notbase64!!\"]},\"auth\":{\"mode\":\"explicit\"}}")]
    [InlineData("{\"key\":{\"status\":\"enabled\",\"algo\":[],\"len\":2048},\"auth\":{\"mode\":\"explicit\"},\"SCAL\":\"3\"}")]
    [InlineData("{\"key\":{\"status\":\"enabled\",\"algo\":[],\"len\":2048},\"auth\":{\"mode\":\"explicit\"},\"multisign\":0}")]
    [InlineData("{\"auth\":{\"mode\":\"explicit\"}}")]
    public async Task AMalformedCredentialDescriptionIsRefused(string body)
    {
        var net = new FakeNetwork(_ => Json(body));
        CscResult<CscCredentialInfo> r = await Client(net).GetCredentialInfoAsync("C1");
        Assert.Equal(CscOutcome.MalformedResponse, r.Outcome);
    }

    [Fact]
    public async Task ACredentialWhoseCertificateDoesNotDecodeCannotBeOpened()
    {
        var net = new FakeNetwork(_ => Json("{\"key\":{\"status\":\"enabled\",\"algo\":[],\"len\":2048},\"cert\":{\"certificates\":[\"AAAA\"]},\"auth\":{\"mode\":\"explicit\"}}"));
        Assert.Equal(CscOutcome.MalformedResponse, (await Client(net).OpenSigningKeyAsync("C1")).Outcome);
        net = new FakeNetwork(_ => Json("{\"key\":{\"status\":\"enabled\",\"algo\":[],\"len\":2048},\"cert\":{\"certificates\":[]},\"auth\":{\"mode\":\"explicit\"}}"));
        Assert.Equal(CscOutcome.MalformedResponse, (await Client(net).OpenSigningKeyAsync("C1")).Outcome);
    }

    [Fact]
    public async Task ACredentialWhoseKeyCannotSignADigestIsRefused()
    {
        // Found by the fuzz target: a certificate key with no digest signature scheme must not reach the key constructor.
        using var ed = RecursiveAI.OneCrypto.Keys.PrivateKey.FromEd25519(RecursiveAI.OneCrypto.Primitives.Ed25519PrivateKey.Generate(), ownsKey: true);
        Certificate cert = World.Get().Intermediate.Issue(ed.PublicKey, DistinguishedName.Create((KnownOids.CommonName, "EdDSA credential")),
            new RecursiveAI.OneCrypto.Issuance.CertificateIssueOptions { Profile = RecursiveAI.OneCrypto.Issuance.CertificateProfile.SMime, NotBefore = World.T0.AddDays(-1), SubjectAlternativeNames = [GeneralName.Email("e@example.test")] });
        var net = new FakeNetwork(_ => Json("{\"key\":{\"status\":\"enabled\",\"algo\":[],\"len\":256},\"cert\":{\"certificates\":[\"" + Convert.ToBase64String(cert.Encoded.Span) + "\"]},\"auth\":{\"mode\":\"explicit\"}}"));
        Assert.Equal(CscOutcome.CredentialUnusable, (await Client(net).OpenSigningKeyAsync("C1")).Outcome);
    }

    [Fact]
    public async Task WrongSignatureCountsAndEmptyAnswersAreMalformed()
    {
        foreach (string body in new[] { "{\"signatures\":[]}", "{\"signatures\":[\"AAAA\",\"AAAA\"]}", "{}", "{\"signatures\":[\"@@@\"]}" })
        {
            var net = new FakeNetwork(_ => Json(body));
            CscResult<IReadOnlyList<byte[]>> r = await Client(net).SignHashAsync("C1", "sad", [new byte[32]], KnownOids.Sha256, KnownOids.Sha256WithRsa);
            Assert.Equal(CscOutcome.MalformedResponse, r.Outcome);
        }
    }

    [Fact]
    public async Task AnAcceptedAuthorizationWithoutAHandleOrSadIsMalformedAndA202IsPending()
    {
        var bad = new FakeNetwork(_ => Json("{}"));
        Assert.Equal(CscOutcome.MalformedResponse, (await Client(bad).AuthorizeAsync("C1", [new byte[32]], KnownOids.Sha256)).Outcome);
        var pending = new FakeNetwork(_ => Json("{\"handle\":\"h-1\"}", 202));
        CscResult<CscAuthorization> r = await Client(pending).AuthorizeAsync("C1", [new byte[32]], KnownOids.Sha256);
        Assert.Equal(CscOutcome.AuthorizationPending, r.Outcome);
        Assert.Equal("h-1", r.Value!.PendingHandle);
        Assert.Null(r.Value.Sad);
    }

    [Fact]
    public async Task AnErrorWithoutAUsableBodyIsStillAnOutcome()
    {
        foreach (Reply reply in new[] { new Reply(500, []), new Reply(400, new byte[300_000]), new Reply(502, "<html>bad gateway</html>"u8.ToArray()), Json("{\"error\":5}", 400) })
        {
            var net = new FakeNetwork(_ => reply);
            CscResult<CscCredentialList> r = await Client(net).ListCredentialsAsync();
            Assert.Equal(CscOutcome.ServiceError, r.Outcome);
            Assert.Equal(reply.Status, r.StatusCode);
        }
    }

    [Fact]
    public async Task NoCredentialAppearsInAnyReasonErrorOrExceptionEvenWhenTheServiceEchoesIt()
    {
        const string pin = "424242";
        const string sad = "SAD-VALUE-98765";
        var echo = new FakeNetwork(r => Json($"{{\"error\":\"invalid_request\",\"error_description\":\"bad {Secret} pin {pin} sad {sad}\\u0007\"}}", 400));
        CscClient client = Client(echo);

        var all = new List<string>();
        CscResult<CscAuthorization> a = await client.AuthorizeAsync("C1", [new byte[32]], KnownOids.Sha256, [new CscAuthObject("PIN", pin)]);
        all.Add(a.Reason);
        all.Add(a.Error ?? string.Empty);
        all.Add(a.Fetch!.Reason);
        CscResult<IReadOnlyList<byte[]>> s = await client.SignHashAsync("C1", sad, [new byte[32]], KnownOids.Sha256, KnownOids.Sha256WithRsa);
        all.Add(s.Reason);
        all.Add(s.Error ?? string.Empty);
        all.Add(string.Join(' ', s.Fetch!.Headers.Select(h => h.Value)));
        all.Add(new CscAuthObject("PIN", pin).ToString());
        all.Add(new CscAccessToken(Secret).ToString());
        all.Add(new CscAuthorization(sad, 5, null).ToString());

        // Each call scrubs the secrets it sent: the token in both, the PIN in the authorization, the SAD in the signing call.
        Assert.DoesNotContain(Secret, string.Join('\n', all), StringComparison.Ordinal);
        Assert.DoesNotContain(pin, string.Join('\n', all.Take(3)), StringComparison.Ordinal);
        Assert.DoesNotContain(sad, string.Join('\n', all.Skip(3).Take(3)), StringComparison.Ordinal);
        Assert.DoesNotContain(pin, all[6], StringComparison.Ordinal);
        Assert.DoesNotContain(sad, all[8], StringComparison.Ordinal);
        Assert.Contains("[redacted]", a.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain('\u0007', a.Reason);
    }

    [Fact]
    public async Task ASigningFailureCarriesNoCredentialInItsMessageOrItsToString()
    {
        var rig = new CscRig();
        rig.Server.Add(CscRig.Credential("C1", "rsa"));
        using CscSigningKey key = (await rig.Client.OpenSigningKeyAsync("C1", CscRig.WithPin("999999"))).Value!;
        CscSigningException ex = await Assert.ThrowsAsync<CscSigningException>(async () => await key.SignDigestAsync(new byte[32], key.DefaultSpec));
        string text = ex.ToString() + ex.Message;
        Assert.DoesNotContain("999999", text, StringComparison.Ordinal);
        Assert.DoesNotContain(rig.Token, text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARecordingOfAFullSigningFlowHoldsNeitherTheTokenNorThePin()
    {
        var rig = new CscRig(deterministic: true);
        var recorder = new RecordingTransport(rig.Transport);
        var client = new CscClient(new Fetcher(recorder, new FetchOptions { Cache = null, Time = rig.Clock }), CscRig.Base, new CscStaticTokenSource(new CscAccessToken(rig.Token)));
        rig.Server.Add(CscRig.Credential("C1", "rsa", pin: "135790"));
        using CscSigningKey key = (await client.OpenSigningKeyAsync("C1", CscRig.WithPin("135790"))).Value!;
        _ = await key.SignDigestAsync(CscRig.Digest("x", System.Security.Cryptography.HashAlgorithmName.SHA256), key.DefaultSpec);

        string json = Encoding.UTF8.GetString(recorder.Log.ToJson());
        Assert.Equal(3, recorder.Log.Exchanges.Count);
        Assert.DoesNotContain(rig.Token, json, StringComparison.Ordinal);
        Assert.DoesNotContain("135790", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Bearer", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EveryRequestIsAPostOfJsonWithTheBearerOnlyWhereAuthorizationIsNeeded()
    {
        var rig = new CscRig();
        rig.Server.Add(CscRig.Credential("C1", "rsa"));
        _ = await rig.Client.InfoAsync();
        _ = await rig.Client.GetCredentialInfoAsync("C1");
        Assert.All(rig.Transport.Requests, q =>
        {
            Assert.Equal("POST", q.Method);
            Assert.Contains(q.Headers, h => h.Key == "Content-Type" && h.Value == "application/json");
        });
        Assert.DoesNotContain(rig.Transport.Requests[0].Headers, h => h.Key == "Authorization");
        Assert.Equal("Bearer " + rig.Token, rig.Transport.Requests[1].Headers.Single(h => h.Key == "Authorization").Value);
        Assert.Equal("https://csc.test/csc/v2/credentials/info", rig.Transport.Requests[1].Uri.AbsoluteUri);
    }

    [Fact]
    public async Task CancellationIsHonoured()
    {
        var rig = new CscRig();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await rig.Client.InfoAsync(null, cts.Token));
    }
}
