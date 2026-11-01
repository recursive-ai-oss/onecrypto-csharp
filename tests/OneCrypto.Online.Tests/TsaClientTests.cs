using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;

namespace OneCrypto.Online.Tests;

public class TsaClientTests
{
    private static readonly byte[] Document = "a document to time-stamp"u8.ToArray();
    private static readonly Uri Authority = new("http://tsa.test/");
    private static World W => World.Get();

    private static TsaClient Client(ITransport net) => new(new Fetcher(net, new FetchOptions { Cache = null }));

    private static TimestampRequestOptions Verifying() => new()
    {
        Verify = new TimeStampVerifyOptions { TrustAnchors = [TrustAnchor.FromCertificate(W.Root.Certificate)], ExtraCertificates = [W.Intermediate.Certificate], ReferenceTime = World.Now },
    };

    [Fact]
    public async Task AGrantedStampIsCheckedAgainstTheRequestAndChainsToTheAnchor()
    {
        FakeNetwork net = W.Network();
        TimestampResult r = await Client(net).StampAsync(Authority, Document, HashAlgorithmName.SHA256, Verifying());
        Assert.True(r.IsGranted, r.Reason);
        Assert.True(r.ContentTypeMatched);
        Assert.Equal(World.Now, r.Report!.GenTime);
        Assert.Equal(TimestampOutcome.Granted, r.Outcome);
        Assert.False(r.Token.IsEmpty);
        Assert.Equal("passed", r.Report.Find("nonce")!.Status.ToString().ToLowerInvariant());
        Assert.Equal("passed", r.Report.Find("message-imprint")!.Status.ToString().ToLowerInvariant());
        Assert.Contains("chains to a supplied anchor", r.Report.Find("trust")!.Reason, StringComparison.Ordinal);

        TransportRequest sent = net.Requests.Single();
        Assert.Equal("POST", sent.Method);
        Assert.Contains(sent.Headers, h => h.Key == "Content-Type" && h.Value == "application/timestamp-query");
        Assert.Contains(sent.Headers, h => h.Key == "Accept" && h.Value == "application/timestamp-reply");
        Assert.True(r.Request!.HasNonce);
        Assert.Equal(SHA256.HashData(Document), r.Request.MessageImprint.ToArray());
    }

    [Fact]
    public async Task EachRequestCarriesAFreshNonce()
    {
        FakeNetwork net = W.Network();
        TsaClient c = Client(net);
        TimestampResult a = await c.StampAsync(Authority, Document, HashAlgorithmName.SHA256);
        TimestampResult b = await c.StampAsync(Authority, Document, HashAlgorithmName.SHA256);
        Assert.NotEqual(a.Request!.Nonce.ToArray(), b.Request!.Nonce.ToArray());
    }

    [Fact]
    public async Task AReplayedOldResponseFailsTheNonceCheck()
    {
        // The authority's answer to a different request (a different nonce) is what an attacker in the path would replay.
        byte[] old = W.Tsa.Handle(TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData(Document), Nonce = TimeStampRequest.NewNonce() }).Encoded, World.Now).Encoded.ToArray();
        var net = new FakeNetwork(_ => Reply.Ok(old, "application/timestamp-reply"));
        TimestampResult r = await Client(net).StampAsync(Authority, Document, HashAlgorithmName.SHA256);
        Assert.Equal(TimestampOutcome.InvalidToken, r.Outcome);
        Assert.Contains("nonce", r.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAnswerForOtherDataFailsTheImprintCheck()
    {
        var net = new FakeNetwork(req =>
        {
            // Answer a request for different data, keeping the nonce.
            TimeStampRequest asked = TimeStampRequest.Parse(req.Body);
            byte[] other = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData("other"u8), Nonce = asked.Nonce }).Encoded.ToArray();
            return Reply.Ok(W.Tsa.Handle(other, World.Now).Encoded.ToArray(), "application/timestamp-reply");
        });
        TimestampResult r = await Client(net).StampAsync(Authority, Document, HashAlgorithmName.SHA256);
        Assert.Equal(TimestampOutcome.InvalidToken, r.Outcome);
        Assert.Contains("message-imprint", r.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARejectionCarriesTheAuthoritysStatus()
    {
        FakeNetwork net = W.Network();
        TimestampResult r = await Client(net).StampAsync(Authority, Document, HashAlgorithmName.SHA256, new TimestampRequestOptions { Policy = "1.9.9.9" });
        Assert.Equal(TimestampOutcome.Rejected, r.Outcome);
        Assert.NotNull(r.Response);
        Assert.False(r.Response.IsGranted);
        Assert.True(r.Token.IsEmpty);
    }

    [Fact]
    public async Task AnAcceptedPolicyComesBackAsRequested()
    {
        FakeNetwork net = W.Network();
        TimestampResult r = await Client(net).StampAsync(Authority, Document, HashAlgorithmName.SHA256, new TimestampRequestOptions { Policy = "1.2.3.4.5" });
        Assert.True(r.IsGranted, r.Reason);
        Assert.Equal("1.2.3.4.5", r.Report!.Info!.Policy);
    }

    [Fact]
    public async Task ADifferentPolicyThanAskedIsReported()
    {
        // An authority that ignores reqPolicy and stamps under its default.
        var net = new FakeNetwork(req =>
        {
            TimeStampRequest asked = TimeStampRequest.Parse(req.Body);
            byte[] plain = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = asked.MessageImprint, Nonce = asked.Nonce }).Encoded.ToArray();
            return Reply.Ok(W.Tsa.Handle(plain, World.Now).Encoded.ToArray(), "application/timestamp-reply");
        });
        TimestampResult r = await Client(net).StampAsync(Authority, Document, HashAlgorithmName.SHA256, new TimestampRequestOptions { Policy = "1.2.3.4.5" });
        Assert.Equal(TimestampOutcome.InvalidToken, r.Outcome);
        Assert.Contains("policy-id", r.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AWrongContentTypeIsReportedAndTheDerDecides()
    {
        var net = new FakeNetwork(req => Reply.Ok(W.Tsa.Handle(req.Body, World.Now).Encoded.ToArray(), "application/octet-stream"));
        TimestampResult r = await Client(net).StampAsync(Authority, Document, HashAlgorithmName.SHA256);
        Assert.True(r.IsGranted);
        Assert.False(r.ContentTypeMatched);
    }

    [Theory]
    [InlineData("")]
    [InlineData("<html>Bad gateway</html>")]
    [InlineData("0\u0003\u0002\u0001\u0001")]
    public async Task ABodyThatIsNotAResponseIsMalformed(string body)
    {
        var net = new FakeNetwork(_ => Reply.Ok(System.Text.Encoding.Latin1.GetBytes(body), "application/timestamp-reply"));
        TimestampResult r = await Client(net).StampAsync(Authority, Document, HashAlgorithmName.SHA256);
        Assert.False(r.IsGranted);
        Assert.True(r.Outcome is TimestampOutcome.MalformedResponse or TimestampOutcome.InvalidToken, r.Outcome.ToString());
    }

    [Fact]
    public async Task TransportAndHttpFailuresAreFetchFailures()
    {
        TimestampResult http = await Client(new FakeNetwork(_ => Reply.Code(503))).StampAsync(Authority, Document, HashAlgorithmName.SHA256);
        Assert.Equal(TimestampOutcome.FetchFailed, http.Outcome);
        Assert.Equal(FetchOutcome.HttpStatus, http.Fetch.Outcome);

        var down = new StreamNetwork((_, _) => throw new TransportException(TransportFailure.Connect, "refused"));
        Assert.Equal(TimestampOutcome.FetchFailed, (await Client(down).StampAsync(Authority, Document, HashAlgorithmName.SHA256)).Outcome);
    }

    [Fact]
    public async Task ACallerSuppliedPrivateAuthorityIsAllowedAndACertificateSuppliedOneIsNot()
    {
        FakeNetwork net = W.Network(new() { ["http://10.1.2.3/tsa"] = r => Reply.Ok(W.Tsa.Handle(r.Body, World.Now).Encoded.ToArray(), "application/timestamp-reply") });
        Assert.True((await Client(net).StampAsync(new Uri("http://10.1.2.3/tsa"), Document, HashAlgorithmName.SHA256)).IsGranted);
        TimestampResult blocked = await Client(net).StampAsync(new Uri("http://10.1.2.3/tsa"), Document, HashAlgorithmName.SHA256, new TimestampRequestOptions { Origin = UrlOrigin.Certificate });
        Assert.Equal(TimestampOutcome.FetchFailed, blocked.Outcome);
        Assert.Equal(FetchOutcome.AddressBlocked, blocked.Fetch.Outcome);
    }

    [Fact]
    public async Task ExtraHeadersAreSentAndAnOversizedAnswerIsRefused()
    {
        FakeNetwork net = W.Network();
        await Client(net).StampAsync(Authority, Document, HashAlgorithmName.SHA256, new TimestampRequestOptions { Headers = [new("X-Api-Key", "k")] });
        Assert.Contains(net.Requests[0].Headers, h => h.Key == "X-Api-Key");

        var huge = new FakeNetwork(_ => Reply.Ok(new byte[2 << 20], "application/timestamp-reply"));
        Assert.Equal(FetchOutcome.ResponseTooLarge, (await Client(huge).StampAsync(Authority, Document, HashAlgorithmName.SHA256)).Fetch.Outcome);
    }

    [Fact]
    public async Task ABoundClientIsATimestampFunctionForACallerThatBuildsTheRequest()
    {
        FakeNetwork net = W.Network();
        var tsa = new TsaClient(new Fetcher(net, new FetchOptions { Cache = null }), Authority, new TimestampRequestOptions { Headers = [new("X-Api-Key", "k")] });

        // The shape the PDF bridge's time-stamp function has: (request, token) -> DER of the reply.
        Func<TimeStampRequest, CancellationToken, ValueTask<byte[]>> function = tsa.GetTimestampAsync;
        TimeStampRequest request = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData(Document), Nonce = TimeStampRequest.NewNonce() });
        byte[] reply = await function(request, CancellationToken.None);

        TimeStampReport report = TimeStampVerifier.Verify(request, reply, Verifying().Verify);
        Assert.True(report.IsValid, string.Join("; ", report.Checks.Select(static c => c.Rule + ": " + c.Reason)));
        Assert.Contains(net.Requests.Single().Headers, h => h.Key == "X-Api-Key");

        // A client made without an authority says what to do; a dead network is a transport error, not an empty answer.
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await Client(net).GetTimestampAsync(request));
        var dead = new TsaClient(new Fetcher(new FakeNetwork(_ => Reply.Code(503)), new FetchOptions { Cache = null }), Authority);
        await Assert.ThrowsAsync<TransportException>(async () => await dead.GetTimestampAsync(request));
    }

    [Fact]
    public async Task ADigestCanBeStampedDirectly()
    {
        FakeNetwork net = W.Network();
        byte[] digest = SHA384.HashData(Document);
        TimestampResult r = await Client(net).StampDigestAsync(Authority, digest, HashAlgorithmName.SHA384);
        Assert.True(r.IsGranted, r.Reason);
        Assert.Equal(digest, r.Request!.MessageImprint.ToArray());
        Assert.Throws<ArgumentException>(() => Client(net).StampAsync(Authority, Document, HashAlgorithmName.MD5).AsTask().GetAwaiter().GetResult());
    }
}
