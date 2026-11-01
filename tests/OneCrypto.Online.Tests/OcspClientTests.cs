using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Online.Tests;

public class OcspClientTests
{
    private static World W => World.Get();

    private static OcspClient Client(ITransport net) => new(new Fetcher(net, new FetchOptions { Cache = new MemoryFetchCache() }));

    private static OcspQueryOptions Opts() => new() { ReferenceTime = World.Now };

    [Fact]
    public async Task GoodRevokedAndUnknownAreReportedAsTheResponderSaidThem()
    {
        FakeNetwork net = W.Network();
        OcspClient c = Client(net);
        OcspQueryResult good = await c.QueryAsync(W.Good, W.Intermediate.Certificate, Opts());
        Assert.Equal(OcspOutcome.Answered, good.Outcome);
        Assert.Equal(OcspCertStatus.Good, good.Answer!.Status);

        OcspQueryResult revoked = await c.QueryAsync(W.Revoked, W.Intermediate.Certificate, Opts());
        Assert.Equal(OcspCertStatus.Revoked, revoked.Answer!.Status);
        Assert.Equal(RevocationReason.KeyCompromise, revoked.Answer.RevocationReason);

        OcspQueryResult unknown = await c.QueryAsync(W.Unlisted, W.Intermediate.Certificate, Opts());
        Assert.Equal(OcspCertStatus.Unknown, unknown.Answer!.Status);
    }

    [Fact]
    public async Task ASmallRequestGoesAsAGetWithTheBase64AppendedPerRfc6960()
    {
        FakeNetwork net = W.Network();
        OcspQueryResult r = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, Opts());
        Assert.True(r.Outcome == OcspOutcome.Answered, r.Reason);
        TransportRequest sent = net.Requests.Single();
        Assert.Equal("GET", sent.Method);
        Assert.StartsWith("http://ocsp.test/", sent.Uri.AbsoluteUri, StringComparison.Ordinal);
        string tail = sent.Uri.AbsoluteUri["http://ocsp.test/".Length..];
        Assert.DoesNotContain('+', tail);
        Assert.Equal(r.Request!.Encoded.ToArray(), Convert.FromBase64String(Uri.UnescapeDataString(tail)));
        Assert.DoesNotContain(net.Requests, q => q.Method == "POST");
    }

    [Fact]
    public async Task AResponderUrlWithoutATrailingSlashGetsOne()
    {
        FakeNetwork net = W.Network();
        OcspQueryResult r = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, new OcspQueryOptions { ResponderUri = new Uri("http://ocsp.test"), ReferenceTime = World.Now });
        Assert.Equal(OcspOutcome.Answered, r.Outcome);
        Assert.StartsWith("http://ocsp.test/", net.Requests[0].Uri.AbsoluteUri, StringComparison.Ordinal);
        Assert.True(net.Requests[0].Uri.AbsoluteUri.Length > "http://ocsp.test/".Length);
    }

    [Fact]
    public async Task PostSendsTheRequestAsTheBodyWithTheRightContentType()
    {
        FakeNetwork net = W.Network();
        OcspQueryResult r = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, new OcspQueryOptions { Method = OcspHttpMethod.Post, ReferenceTime = World.Now });
        Assert.Equal(OcspOutcome.Answered, r.Outcome);
        TransportRequest sent = net.Requests.Single();
        Assert.Equal("POST", sent.Method);
        Assert.Equal("http://ocsp.test/", sent.Uri.AbsoluteUri);
        Assert.Contains(sent.Headers, h => h.Key == "Content-Type" && h.Value == "application/ocsp-request");
        Assert.Equal(r.Request!.Encoded.ToArray(), sent.Body.ToArray());
    }

    [Fact]
    public async Task AGetThatTheResponderRefusesIsRepeatedAsAPost()
    {
        var net = new FakeNetwork(r => r.Method == "GET" ? Reply.Code(405) : World.ServeOcspFor(W.Responder, r));
        OcspQueryResult res = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, Opts());
        Assert.Equal(OcspOutcome.Answered, res.Outcome);
        Assert.Equal(["GET", "POST"], net.Requests.Select(q => q.Method).ToArray());
    }

    [Fact]
    public async Task AnExplicitGetIsNotRetriedAsAPost()
    {
        var net = new FakeNetwork(r => Reply.Code(405));
        OcspQueryResult res = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, new OcspQueryOptions { Method = OcspHttpMethod.Get, ReferenceTime = World.Now, ResponderUri = new Uri("http://ocsp.test/") });
        Assert.Equal(OcspOutcome.FetchFailed, res.Outcome);
        Assert.Single(net.Requests);
    }

    [Fact]
    public async Task ANonceIsSentAndEchoed()
    {
        FakeNetwork net = W.Network();
        OcspQueryResult r = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, new OcspQueryOptions { UseNonce = true, RequireNonce = true, ReferenceTime = World.Now });
        Assert.Equal(OcspOutcome.Answered, r.Outcome);
        Assert.Equal(OcspNonceStatus.Matched, r.Nonce);
        Assert.Equal("POST", net.Requests[0].Method);
        Assert.NotNull(r.Request!.Nonce);
    }

    [Fact]
    public async Task AWrongNonceFailsAndAMissingOneFailsOnlyWhenRequired()
    {
        // An answer to another request (another nonce) is what a replay looks like.
        OcspRequest other = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [OcspCertId.Create(W.Good, W.Intermediate.Certificate)], Nonce = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 } });
        byte[] replay = W.Responder.Handle(other.Encoded, World.Now).Encoded.ToArray();
        var net = new FakeNetwork(_ => Reply.Ok(replay, "application/ocsp-response"));
        OcspQueryResult wrong = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, new OcspQueryOptions { UseNonce = true, ReferenceTime = World.Now });
        Assert.Equal(OcspOutcome.NonceMismatch, wrong.Outcome);
        Assert.Equal(OcspNonceStatus.Mismatched, wrong.Nonce);

        OcspRequest noNonce = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [OcspCertId.Create(W.Good, W.Intermediate.Certificate)] });
        byte[] without = W.Responder.Handle(noNonce.Encoded, World.Now).Encoded.ToArray();
        var net2 = new FakeNetwork(_ => Reply.Ok(without, "application/ocsp-response"));
        OcspQueryResult lenient = await Client(net2).QueryAsync(W.Good, W.Intermediate.Certificate, new OcspQueryOptions { UseNonce = true, ReferenceTime = World.Now });
        Assert.Equal(OcspOutcome.Answered, lenient.Outcome);
        Assert.Equal(OcspNonceStatus.Missing, lenient.Nonce);
        OcspQueryResult strict = await Client(net2).QueryAsync(W.Good, W.Intermediate.Certificate, new OcspQueryOptions { UseNonce = true, RequireNonce = true, ReferenceTime = World.Now });
        Assert.Equal(OcspOutcome.NonceMismatch, strict.Outcome);
    }

    [Fact]
    public async Task AnAnswerForAnotherCertificateIsRefused()
    {
        OcspRequest other = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [OcspCertId.Create(W.Revoked, W.Intermediate.Certificate)] });
        byte[] answer = W.Responder.Handle(other.Encoded, World.Now).Encoded.ToArray();
        var net = new FakeNetwork(_ => Reply.Ok(answer, "application/ocsp-response"));
        OcspQueryResult r = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, Opts());
        Assert.Equal(OcspOutcome.CertIdMismatch, r.Outcome);
        Assert.Null(r.Answer);
    }

    [Theory]
    [InlineData(1, OcspResponseStatus.MalformedRequest)]
    [InlineData(2, OcspResponseStatus.InternalError)]
    [InlineData(3, OcspResponseStatus.TryLater)]
    [InlineData(5, OcspResponseStatus.SigRequired)]
    [InlineData(6, OcspResponseStatus.Unauthorized)]
    public async Task ResponderErrorsAreTypedWithTheirStatus(byte code, OcspResponseStatus expected)
    {
        var net = new FakeNetwork(_ => Reply.Ok([0x30, 0x03, 0x0A, 0x01, code], "application/ocsp-response"));
        OcspQueryResult r = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, Opts());
        Assert.Equal(OcspOutcome.ResponderError, r.Outcome);
        Assert.Equal(expected, r.Response!.Status);
        Assert.Contains(expected.ToString(), r.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("<html>")]
    [InlineData("0\u0003\n\u0001")]
    public async Task GarbageIsMalformed(string body)
    {
        var net = new FakeNetwork(_ => Reply.Ok(System.Text.Encoding.Latin1.GetBytes(body), "application/ocsp-response"));
        OcspQueryResult r = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, Opts());
        Assert.Equal(OcspOutcome.MalformedResponse, r.Outcome);
    }

    [Fact]
    public async Task AWellFramedResponseWithAMalformedBasicResponseIsMalformedNotAnException()
    {
        // OCSPResponse { successful, [0] { id-pkix-ocsp-basic, OCTET STRING { a SEQUENCE claiming more bytes than the string holds } } }
        byte[] oid = [0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
        byte[] inner = [0x30, 0x7F, 0x01, 0x02];
        byte[] octets = [0x04, (byte)inner.Length, .. inner];
        byte[] responseBytes = [0x30, (byte)(oid.Length + octets.Length), .. oid, .. octets];
        byte[] tagged = [0xA0, (byte)responseBytes.Length, .. responseBytes];
        byte[] body = [0x30, (byte)(3 + tagged.Length), 0x0A, 0x01, 0x00, .. tagged];
        var net = new FakeNetwork(_ => Reply.Ok(body, "application/ocsp-response"));
        OcspQueryResult r = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, Opts());
        Assert.Equal(OcspOutcome.MalformedResponse, r.Outcome);
    }

    [Fact]
    public async Task ACertificateWithNoResponderSaysSo()
    {
        var net = new FakeNetwork(_ => Reply.Code(500));
        OcspQueryResult r = await Client(net).QueryAsync(W.Root.Certificate, W.Root.Certificate, Opts());
        Assert.Equal(OcspOutcome.NoResponder, r.Outcome);
        Assert.Empty(net.Requests);
    }

    [Fact]
    public async Task AResponderAddressFromACertificateGetsTheAddressGuard()
    {
        var net = new FakeNetwork(_ => Reply.Code(500));
        OcspQueryResult r = await Client(net).QueryAsync(W.Good, W.Intermediate.Certificate, new OcspQueryOptions { ResponderUri = new Uri("http://169.254.169.254/ocsp"), Origin = UrlOrigin.Certificate, ReferenceTime = World.Now });
        Assert.Equal(OcspOutcome.FetchFailed, r.Outcome);
        Assert.Equal(FetchOutcome.AddressBlocked, r.Fetch!.Outcome);
        Assert.Empty(net.Requests);
    }

    [Fact]
    public async Task AnAnswerIsReusedWhileItIsCurrentAtTheReferenceTime()
    {
        FakeNetwork net = W.Network();
        OcspClient c = Client(net);
        await c.QueryAsync(W.Good, W.Intermediate.Certificate, Opts());
        OcspQueryResult second = await c.QueryAsync(W.Good, W.Intermediate.Certificate, Opts());
        Assert.True(second.FromCache);
        Assert.Single(net.Requests);

        // A different certificate is a different question.
        await c.QueryAsync(W.Revoked, W.Intermediate.Certificate, Opts());
        Assert.Equal(2, net.Requests.Count);

        // At a time past nextUpdate the stored answer is not good enough and the responder is asked again.
        OcspQueryResult later = await c.QueryAsync(W.Good, W.Intermediate.Certificate, new OcspQueryOptions { ReferenceTime = World.Now.AddDays(3) });
        Assert.False(later.FromCache);
        Assert.Equal(3, net.Requests.Count);

        // And before thisUpdate it is not reused either.
        OcspQueryResult earlier = await c.QueryAsync(W.Good, W.Intermediate.Certificate, new OcspQueryOptions { ReferenceTime = World.Now.AddDays(-3) });
        Assert.False(earlier.FromCache);
    }

    [Fact]
    public async Task APostAnswerIsCachedByContentAndANonceNeverIs()
    {
        FakeNetwork net = W.Network();
        OcspClient c = Client(net);
        var post = new OcspQueryOptions { Method = OcspHttpMethod.Post, ReferenceTime = World.Now };
        await c.QueryAsync(W.Good, W.Intermediate.Certificate, post);
        Assert.True((await c.QueryAsync(W.Good, W.Intermediate.Certificate, post)).FromCache);
        Assert.Single(net.Requests);

        var nonce = new OcspQueryOptions { UseNonce = true, ReferenceTime = World.Now };
        await c.QueryAsync(W.Good, W.Intermediate.Certificate, nonce);
        await c.QueryAsync(W.Good, W.Intermediate.Certificate, nonce);
        Assert.Equal(3, net.Requests.Count);
    }

    [Fact]
    public async Task CachingCanBeSwitchedOff()
    {
        FakeNetwork net = W.Network();
        OcspClient c = Client(net);
        var o = new OcspQueryOptions { UseCache = false, ReferenceTime = World.Now };
        await c.QueryAsync(W.Good, W.Intermediate.Certificate, o);
        await c.QueryAsync(W.Good, W.Intermediate.Certificate, o);
        Assert.Equal(2, net.Requests.Count);
    }
}
