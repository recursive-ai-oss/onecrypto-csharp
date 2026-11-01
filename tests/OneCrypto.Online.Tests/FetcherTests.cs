using System.Text;
using RecursiveAI.OneCrypto.Online;

namespace OneCrypto.Online.Tests;

public class FetcherTests
{
    private static readonly byte[] Data = Encoding.ASCII.GetBytes("hello");

    private static Fetcher Make(ITransport t, Action<FetchOptions>? _ = null, FetchOptions? o = null) => new(t, o ?? new FetchOptions { Cache = null });

    private static FetchRequest Get(string url, UrlOrigin origin = UrlOrigin.Caller) => new() { Uri = new Uri(url), Origin = origin };

    [Fact]
    public async Task AnOrdinaryGetReturnsTheBody()
    {
        var net = new FakeNetwork(_ => Reply.Ok(Data, "text/plain; charset=utf-8"));
        FetchResult r = await Make(net).FetchAsync(Get("http://example.test/x"));
        Assert.True(r.IsSuccess);
        Assert.Equal(Data, r.Body.ToArray());
        Assert.Equal("text/plain", r.ContentType);
        Assert.Equal(200, r.StatusCode);
    }

    [Theory]
    [InlineData("ftp://example.test/x")]
    [InlineData("file:///etc/passwd")]
    [InlineData("ldap://example.test/cn=x")]
    [InlineData("gopher://example.test/")]
    [InlineData("data:text/plain,hi")]
    public async Task OnlyHttpAndHttpsAreFetched(string url)
    {
        var net = new FakeNetwork(_ => Reply.Ok(Data, "text/plain"));
        FetchResult r = await Make(net).FetchAsync(Get(url));
        Assert.Equal(FetchOutcome.SchemeNotAllowed, r.Outcome);
        Assert.Empty(net.Requests);
    }

    [Fact]
    public async Task UserInformationIsRefused()
    {
        var net = new FakeNetwork(_ => Reply.Ok(Data, "text/plain"));
        FetchResult r = await Make(net).FetchAsync(Get("http://user:pw@example.test/"));
        Assert.Equal(FetchOutcome.UserInfoNotAllowed, r.Outcome);
        Assert.Empty(net.Requests);
    }

    [Theory]
    [InlineData("http://127.0.0.1/crl")]
    [InlineData("http://[::1]/crl")]
    [InlineData("http://10.0.0.1/crl")]
    [InlineData("http://localhost/crl")]
    [InlineData("http://[::ffff:192.168.1.1]/crl")]
    [InlineData("http://169.254.169.254/latest")]
    public async Task ACertificateSuppliedUrlCannotNameAPrivateAddress(string url)
    {
        var net = new FakeNetwork(_ => Reply.Ok(Data, "text/plain"));
        FetchResult r = await Make(net).FetchAsync(Get(url, UrlOrigin.Certificate));
        Assert.Equal(FetchOutcome.AddressBlocked, r.Outcome);
        Assert.NotEmpty(r.Reason);
        Assert.Empty(net.Requests);
    }

    [Fact]
    public async Task ACallerWrittenUrlMayNameAPrivateAddressButAskTheTransportToGuardNothing()
    {
        var net = new FakeNetwork(_ => Reply.Ok(Data, "text/plain"));
        FetchResult r = await Make(net).FetchAsync(Get("http://10.0.0.1/tsa"));
        Assert.True(r.IsSuccess);
        Assert.Null(net.Requests[0].Guard);

        FetchResult c = await Make(net).FetchAsync(Get("http://example.test/crl", UrlOrigin.Certificate));
        Assert.True(c.IsSuccess);
        Assert.NotNull(net.Requests[1].Guard);
    }

    [Fact]
    public async Task ARedirectToAPrivateAddressIsRefusedEvenForACallerWrittenUrl()
    {
        var net = new FakeNetwork(r => r.Uri.Host == "example.test" ? Reply.Redirect("http://169.254.169.254/latest/meta-data/") : Reply.Ok(Data, "text/plain"));
        FetchResult r = await Make(net).FetchAsync(Get("http://example.test/"));
        Assert.Equal(FetchOutcome.AddressBlocked, r.Outcome);
        Assert.Single(net.Requests);
        Assert.Equal("http://169.254.169.254/latest/meta-data/", r.FinalUri.AbsoluteUri);
    }

    [Fact]
    public async Task RedirectsAreFollowedUpToTheLimit()
    {
        int n = 0;
        var net = new FakeNetwork(r => r.Uri.AbsolutePath.StartsWith("/end", StringComparison.Ordinal) ? Reply.Ok(Data, "text/plain") : Reply.Redirect($"/hop{++n}"));
        var f = new Fetcher(net, new FetchOptions { Cache = null, MaxRedirects = 3 });
        FetchResult r = await f.FetchAsync(Get("http://example.test/start"));
        Assert.Equal(FetchOutcome.TooManyRedirects, r.Outcome);
        Assert.Equal(4, net.Requests.Count);

        var net2 = new FakeNetwork(r => r.Uri.AbsolutePath == "/start" ? Reply.Redirect("/a") : r.Uri.AbsolutePath == "/a" ? Reply.Redirect("/end") : Reply.Ok(Data, "text/plain"));
        FetchResult ok = await new Fetcher(net2, new FetchOptions { Cache = null, MaxRedirects = 3 }).FetchAsync(Get("http://example.test/start"));
        Assert.True(ok.IsSuccess);
        Assert.Equal(2, ok.Redirects.Count);
        Assert.Equal("http://example.test/end", ok.FinalUri.AbsoluteUri);
    }

    [Fact]
    public async Task ARedirectLoopStops()
    {
        var net = new FakeNetwork(r => Reply.Redirect(r.Uri.AbsolutePath == "/a" ? "/b" : "/a"));
        FetchResult r = await Make(net).FetchAsync(Get("http://example.test/a"));
        Assert.Equal(FetchOutcome.RedirectRejected, r.Outcome);
    }

    [Theory]
    [InlineData("ftp://example.test/x")]
    [InlineData("file:///etc/passwd")]
    [InlineData("http://user:pw@other.test/")]
    public async Task ARedirectToAForbiddenSchemeOrUserInfoIsRefused(string target)
    {
        var net = new FakeNetwork(r => r.Uri.Host == "example.test" ? Reply.Redirect(target) : Reply.Ok(Data, "text/plain"));
        FetchResult r = await Make(net).FetchAsync(Get("http://example.test/"));
        Assert.True(r.Outcome is FetchOutcome.SchemeNotAllowed or FetchOutcome.UserInfoNotAllowed, r.Outcome.ToString());
    }

    [Fact]
    public async Task HttpsToHttpIsNotFollowed()
    {
        var net = new FakeNetwork(r => r.Uri.Scheme == "https" ? Reply.Redirect("http://example.test/plain") : Reply.Ok(Data, "text/plain"));
        FetchResult r = await Make(net).FetchAsync(Get("https://example.test/"));
        Assert.Equal(FetchOutcome.RedirectRejected, r.Outcome);
        Assert.Single(net.Requests);
    }

    [Fact]
    public async Task ACrossHostRedirectDropsTheCallersHeaders()
    {
        var net = new FakeNetwork(r => r.Uri.Host == "a.test" ? Reply.Redirect("http://b.test/") : Reply.Ok(Data, "text/plain"));
        await Make(net).FetchAsync(new FetchRequest
        {
            Uri = new Uri("http://a.test/"),
            Headers = [new("Authorization", "Bearer secret"), new("X-Api-Key", "k"), new("Accept", "text/plain")],
        });
        Assert.Contains(net.Requests[0].Headers, h => h.Key == "Authorization");
        Assert.DoesNotContain(net.Requests[1].Headers, h => h.Key is "Authorization" or "X-Api-Key");
        Assert.Contains(net.Requests[1].Headers, h => h.Key == "Accept");
    }

    [Fact]
    public async Task APostBecomesAnEmptyGetOnA302ButStaysAPostOn307()
    {
        var net = new FakeNetwork(r => r.Uri.AbsolutePath == "/first" ? Reply.Redirect("/second", 302) : r.Uri.AbsolutePath == "/p" ? Reply.Redirect("/q", 307) : Reply.Ok(Data, "text/plain"));
        await Make(net).FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/first"), Method = "POST", Body = Data, Headers = [new("Content-Type", "application/x")] });
        Assert.Equal("GET", net.Requests[1].Method);
        Assert.True(net.Requests[1].Body.IsEmpty);

        var net2 = new FakeNetwork(r => r.Uri.AbsolutePath == "/p" ? Reply.Redirect("/q", 307) : Reply.Ok(Data, "text/plain"));
        await Make(net2).FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/p"), Method = "POST", Body = Data });
        Assert.Equal("POST", net2.Requests[1].Method);
        Assert.Equal(Data, net2.Requests[1].Body.ToArray());
    }

    [Fact]
    public async Task ARedirectWithoutALocationIsRejected()
    {
        var net = new FakeNetwork(_ => new Reply(302, []));
        Assert.Equal(FetchOutcome.RedirectRejected, (await Make(net).FetchAsync(Get("http://example.test/"))).Outcome);
    }

    [Fact]
    public async Task ADeclaredLengthOverTheLimitIsRefusedBeforeReading()
    {
        var net = new FakeNetwork(_ => new Reply(200, new byte[10], ("Content-Length", "999999999")));
        var f = new Fetcher(net, new FetchOptions { Cache = null, MaxResponseBytes = 1000 });
        FetchResult r = await f.FetchAsync(Get("http://example.test/"));
        Assert.Equal(FetchOutcome.ResponseTooLarge, r.Outcome);
    }

    [Fact]
    public async Task AnUndeclaredBodyIsCutOffAtTheLimit()
    {
        var net = new FakeNetwork(_ => Reply.Ok(new byte[5000], "x/y"));
        var f = new Fetcher(net, new FetchOptions { Cache = null, MaxResponseBytes = 4096 });
        Assert.Equal(FetchOutcome.ResponseTooLarge, (await f.FetchAsync(Get("http://example.test/"))).Outcome);
        Assert.True((await f.FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/"), MaxResponseBytes = 8000 })).IsSuccess);
    }

    [Fact]
    public async Task ALyingContentLengthIsATruncatedBody()
    {
        var net = new FakeNetwork(_ => new Reply(200, new byte[10], ("Content-Length", "50")));
        FetchResult r = await Make(net).FetchAsync(Get("http://example.test/"));
        Assert.Equal(FetchOutcome.TruncatedBody, r.Outcome);
    }

    [Fact]
    public async Task ABrokenConnectionMidBodyIsATruncatedBody()
    {
        var net = new StreamNetwork((_, _) => new TransportResponse(200, [], new StallingStream(new byte[100], fail: true)));
        Assert.Equal(FetchOutcome.TruncatedBody, (await Make(net).FetchAsync(Get("http://example.test/"))).Outcome);
    }

    [Fact]
    public async Task AStalledBodyHitsTheTimeLimit()
    {
        var net = new StreamNetwork((_, _) => new TransportResponse(200, [], new StallingStream(new byte[100], fail: false)));
        var f = new Fetcher(net, new FetchOptions { Cache = null, Timeout = TimeSpan.FromMilliseconds(200) });
        FetchResult r = await f.FetchAsync(Get("http://example.test/"));
        Assert.Equal(FetchOutcome.Timeout, r.Outcome);
    }

    [Fact]
    public async Task ATransportThatNeverAnswersHitsTheTimeLimit()
    {
        var net = new HangingTransport();
        var f = new Fetcher(net, new FetchOptions { Cache = null, Timeout = TimeSpan.FromMilliseconds(200) });
        Assert.Equal(FetchOutcome.Timeout, (await f.FetchAsync(Get("http://example.test/"))).Outcome);
        Assert.Equal(FetchOutcome.Timeout, (await f.FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/"), Timeout = TimeSpan.FromMilliseconds(50) })).Outcome);
    }

    [Fact]
    public async Task TheCallersCancellationIsAnOperationCanceledNotATimeout()
    {
        using var cts = new CancellationTokenSource();
        var f = new Fetcher(new HangingTransport(), new FetchOptions { Cache = null, Timeout = TimeSpan.FromSeconds(30) });
        Task<FetchResult> t = f.FetchAsync(Get("http://example.test/"), cts.Token).AsTask();
        cts.CancelAfter(100);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => t);
    }

    [Fact]
    public async Task HttpErrorsAndTransportFailuresAreTypedResults()
    {
        Assert.Equal(FetchOutcome.HttpStatus, (await Make(new FakeNetwork(_ => Reply.Code(500))).FetchAsync(Get("http://example.test/"))).Outcome);
        Assert.Equal(FetchOutcome.HttpStatus, (await Make(new FakeNetwork(_ => Reply.Code(404))).FetchAsync(Get("http://example.test/"))).Outcome);

        var failing = new StreamNetwork((_, _) => throw new TransportException(TransportFailure.NameResolution, "no such host"));
        FetchResult r = await Make(failing).FetchAsync(Get("http://example.test/"));
        Assert.Equal(FetchOutcome.NetworkError, r.Outcome);
        Assert.Contains("no such host", r.Reason, StringComparison.Ordinal);

        var blocked = new StreamNetwork((_, _) => throw new TransportException(TransportFailure.AddressBlocked, "evil.test resolves to 10.0.0.1"));
        Assert.Equal(FetchOutcome.AddressBlocked, (await Make(blocked).FetchAsync(Get("http://evil.test/"))).Outcome);

        var odd = new StreamNetwork((_, _) => throw new HttpRequestException("boom"));
        Assert.Equal(FetchOutcome.NetworkError, (await Make(odd).FetchAsync(Get("http://example.test/"))).Outcome);
    }

    [Fact]
    public async Task UnsupportedMethodsAreRefused()
    {
        var net = new FakeNetwork(_ => Reply.Ok(Data, "x/y"));
        FetchResult r = await Make(net).FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/"), Method = "DELETE" });
        Assert.False(r.IsSuccess);
        Assert.Empty(net.Requests);
    }

    private sealed class HangingTransport : ITransport
    {
        public async ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException();
        }
    }
}
