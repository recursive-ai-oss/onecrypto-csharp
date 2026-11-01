using System.Net;
using System.Text;
using RecursiveAI.OneCrypto.Online;

namespace OneCrypto.Online.Tests;

/// <summary>The default transport against a real socket on the loopback interface.</summary>
public class HttpTransportTests
{
    private static readonly byte[] Data = Encoding.ASCII.GetBytes("payload");

    private static NetworkGuard Loopback => new() { AllowedNetworks = [IPNetwork.Parse("127.0.0.1/32")] };

    private static Fetcher Make(HttpTransport t, NetworkGuard? guard = null, TimeSpan? timeout = null, long? max = null, int redirects = 3) =>
        new(t, new FetchOptions { Cache = null, Guard = guard ?? NetworkGuard.Default, Timeout = timeout ?? TimeSpan.FromSeconds(10), MaxResponseBytes = max ?? (1 << 20), MaxRedirects = redirects });

    [Fact]
    public async Task GetAndPostRoundTripOverARealSocket()
    {
        using var server = new TestServer((line, headers, body) => line.StartsWith("POST", StringComparison.Ordinal)
            ? TestServer.Response(200, "OK", body, "Content-Type: echo/post")
            : TestServer.Response(200, "OK", Data, "Content-Type: text/plain"));
        using var transport = new HttpTransport();
        Fetcher f = Make(transport);
        FetchResult g = await f.FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{server.Port}/a") });
        Assert.True(g.IsSuccess, g.Reason);
        Assert.Equal(Data, g.Body.ToArray());
        FetchResult p = await f.FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{server.Port}/b"), Method = "POST", Body = new byte[] { 1, 2, 3 }, Headers = [new("Content-Type", "application/x-test")] });
        Assert.Equal(new byte[] { 1, 2, 3 }, p.Body.ToArray());
        Assert.Equal("echo/post", p.ContentType);
    }

    [Fact]
    public async Task ACertificateSuppliedLoopbackUrlIsBlockedBeforeAnyConnection()
    {
        using var server = new TestServer((_, _, _) => TestServer.Response(200, "OK", Data));
        using var transport = new HttpTransport();
        FetchResult r = await Make(transport).FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{server.Port}/"), Origin = UrlOrigin.Certificate });
        Assert.Equal(FetchOutcome.AddressBlocked, r.Outcome);
        Assert.Equal(0, server.Accepted);
    }

    [Fact]
    public async Task ANameThatResolvesToAPrivateAddressIsBlockedAtConnectTime()
    {
        using var server = new TestServer((_, _, _) => TestServer.Response(200, "OK", Data));
        var resolver = new TestResolver(("ca.example.test", "127.0.0.1"));
        using var transport = new HttpTransport(new HttpTransportOptions { Resolver = resolver });
        FetchResult r = await Make(transport).FetchAsync(new FetchRequest { Uri = new Uri($"http://ca.example.test:{server.Port}/"), Origin = UrlOrigin.Certificate });
        Assert.Equal(FetchOutcome.AddressBlocked, r.Outcome);
        Assert.Contains("127.0.0.1", r.Reason, StringComparison.Ordinal);
        Assert.Equal(0, server.Accepted);
        Assert.Equal(1, resolver.Calls);
    }

    [Fact]
    public async Task OneBlockedAnswerAmongPublicOnesRefusesTheConnection()
    {
        using var server = new TestServer((_, _, _) => TestServer.Response(200, "OK", Data));
        var resolver = new TestResolver(("mixed.test", "8.8.8.8"), ("mixed.test", "127.0.0.1"));
        using var transport = new HttpTransport(new HttpTransportOptions { Resolver = resolver });
        FetchResult r = await Make(transport).FetchAsync(new FetchRequest { Uri = new Uri($"http://mixed.test:{server.Port}/"), Origin = UrlOrigin.Certificate });
        Assert.Equal(FetchOutcome.AddressBlocked, r.Outcome);
        Assert.Equal(0, server.Accepted);
    }

    [Fact]
    public async Task ARebindingNameIsJudgedByTheAddressActuallyUsed()
    {
        // First answer public, later answers loopback. The connection uses the one lookup it made; the second answer is never consulted,
        // so the server on loopback is not reached, whichever answer comes first.
        using var server = new TestServer((_, _, _) => TestServer.Response(200, "OK", Data));
        var resolver = new TestResolver((_, n) => n == 1 ? [IPAddress.Parse("192.0.2.1")] : [IPAddress.Loopback]);
        using var transport = new HttpTransport(new HttpTransportOptions { Resolver = resolver });
        FetchResult r = await Make(transport).FetchAsync(new FetchRequest { Uri = new Uri($"http://rebind.test:{server.Port}/"), Origin = UrlOrigin.Certificate });
        Assert.Equal(FetchOutcome.AddressBlocked, r.Outcome);
        Assert.Equal(0, server.Accepted);

        // Answer public-then-loopback with the public one allowed: still one lookup per connection, and the connect goes where the check looked.
        var resolver2 = new TestResolver((_, n) => n == 1 ? [IPAddress.Loopback] : [IPAddress.Parse("10.9.9.9")]);
        using var transport2 = new HttpTransport(new HttpTransportOptions { Resolver = resolver2 });
        FetchResult ok = await Make(transport2, Loopback).FetchAsync(new FetchRequest { Uri = new Uri($"http://rebind.test:{server.Port}/"), Origin = UrlOrigin.Certificate });
        Assert.True(ok.IsSuccess, ok.Reason);
        Assert.Equal(1, resolver2.Calls);
        Assert.Equal(1, server.Accepted);
    }

    [Fact]
    public async Task AnAllowedNetworkLetsACertificateUrlReachAnInternalResponder()
    {
        using var server = new TestServer((_, _, _) => TestServer.Response(200, "OK", Data));
        var resolver = new TestResolver(("ocsp.corp.test", "127.0.0.1"));
        using var transport = new HttpTransport(new HttpTransportOptions { Resolver = resolver });
        FetchResult r = await Make(transport, Loopback).FetchAsync(new FetchRequest { Uri = new Uri($"http://ocsp.corp.test:{server.Port}/"), Origin = UrlOrigin.Certificate });
        Assert.True(r.IsSuccess, r.Reason);
    }

    [Fact]
    public async Task ARedirectFromAnAllowedHostToAPrivateNameIsBlocked()
    {
        using var other = new TestServer((_, _, _) => TestServer.Response(200, "OK", Data));
        using var first = new TestServer((_, _, _) => TestServer.Response(302, "Found", [], $"Location: http://inner.test:{other.Port}/secret"));
        var resolver = new TestResolver(("outer.test", "127.0.0.1"), ("inner.test", "127.0.0.2"));
        using var transport = new HttpTransport(new HttpTransportOptions { Resolver = resolver });
        FetchResult r = await Make(transport, Loopback).FetchAsync(new FetchRequest { Uri = new Uri($"http://outer.test:{first.Port}/"), Origin = UrlOrigin.Certificate });
        Assert.Equal(FetchOutcome.AddressBlocked, r.Outcome);
        Assert.Equal(1, first.Accepted);
        Assert.Equal(0, other.Accepted);
        Assert.Single(r.Redirects);
    }

    [Fact]
    public async Task ARedirectFromACallerUrlIsGuardedEvenThoughTheFirstRequestIsNot()
    {
        using var other = new TestServer((_, _, _) => TestServer.Response(200, "OK", Data));
        using var first = new TestServer((_, _, _) => TestServer.Response(307, "Temporary Redirect", [], $"Location: http://127.0.0.1:{other.Port}/"));
        using var transport = new HttpTransport();
        FetchResult r = await Make(transport).FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{first.Port}/") });
        Assert.Equal(FetchOutcome.AddressBlocked, r.Outcome);
        Assert.Equal(0, other.Accepted);
    }

    [Fact]
    public async Task RedirectsAreFollowedWithinTheLimitOverTheWire()
    {
        using var server = new TestServer((line, _, _) => line.Contains("/end", StringComparison.Ordinal)
            ? TestServer.Response(200, "OK", Data)
            : TestServer.Response(301, "Moved", [], "Location: /end"));
        using var transport = new HttpTransport();
        FetchResult r = await Make(transport, NetworkGuard.AllowAll).FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{server.Port}/start") });
        Assert.True(r.IsSuccess, r.Reason);
        Assert.Single(r.Redirects);

        int hops = 0;
        using var loop = new TestServer((_, _, _) => TestServer.Response(302, "Found", [], "Location: /n" + Interlocked.Increment(ref hops)));
        FetchResult many = await Make(transport, NetworkGuard.AllowAll, redirects: 2).FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{loop.Port}/a") });
        Assert.Equal(FetchOutcome.TooManyRedirects, many.Outcome);
    }

    [Fact]
    public async Task ABodyLongerThanTheLimitIsRefusedOverTheWire()
    {
        using var server = new TestServer((_, _, _) => TestServer.Response(200, "OK", new byte[10_000]));
        using var transport = new HttpTransport();
        FetchResult r = await Make(transport, max: 1000).FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{server.Port}/") });
        Assert.Equal(FetchOutcome.ResponseTooLarge, r.Outcome);
    }

    [Fact]
    public async Task AServerThatStopsMidBodyIsATruncatedBody()
    {
        using var server = new TestServer((_, _, _) => Encoding.Latin1.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\nshort"));
        using var transport = new HttpTransport();
        FetchResult r = await Make(transport).FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{server.Port}/") });
        Assert.Equal(FetchOutcome.TruncatedBody, r.Outcome);
    }

    [Fact]
    public async Task ASilentServerHitsTheTimeLimit()
    {
        using var server = new TestServer((_, _, _) =>
        {
            Thread.Sleep(3000);
            return null;
        });
        using var transport = new HttpTransport();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        FetchResult r = await Make(transport, timeout: TimeSpan.FromMilliseconds(400)).FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{server.Port}/") });
        Assert.Equal(FetchOutcome.Timeout, r.Outcome);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2.5));
    }

    [Fact]
    public async Task AClosedPortAndAnUnknownNameAreNetworkErrors()
    {
        int port;
        using (var s = new TestServer((_, _, _) => null))
        {
            port = s.Port;
        }

        using var transport = new HttpTransport(new HttpTransportOptions { Resolver = new TestResolver() });
        Assert.Equal(FetchOutcome.NetworkError, (await Make(transport).FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{port}/") })).Outcome);
        FetchResult nx = await Make(transport).FetchAsync(new FetchRequest { Uri = new Uri("http://nonexistent.invalid/"), Origin = UrlOrigin.Certificate });
        Assert.Equal(FetchOutcome.NetworkError, nx.Outcome);
    }

    [Fact]
    public async Task RecordedExchangesReplayWithoutTheServer()
    {
        var log = new ExchangeLog();
        int port;
        using (var server = new TestServer((line, _, body) => TestServer.Response(200, "OK", line.StartsWith("POST", StringComparison.Ordinal) ? body : Data, "Content-Type: application/x-test")))
        using (var inner = new HttpTransport())
        {
            var rec = new RecordingTransport(inner);
            var f = new Fetcher(rec, new FetchOptions { Cache = null });
            await f.FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{server.Port}/g") });
            await f.FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{server.Port}/p"), Method = "POST", Body = new byte[] { 9, 8 } });
            log = ExchangeLog.Parse(rec.Log.ToJson());
            Assert.Equal(2, log.Exchanges.Count);
            Assert.All(log.Exchanges, e => Assert.NotNull(e.RecordedAt));
            port = server.Port;
        }

        var replay = new ReplayTransport(log);
        var rf = new Fetcher(replay, new FetchOptions { Cache = null });
        FetchResult g = await rf.FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{port}/g") });
        Assert.Equal(Data, g.Body.ToArray());
        FetchResult p = await rf.FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{port}/p"), Method = "POST", Body = new byte[] { 9, 8 } });
        Assert.Equal(new byte[] { 9, 8 }, p.Body.ToArray());

        FetchResult wrongBody = await rf.FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{port}/p"), Method = "POST", Body = new byte[] { 1 } });
        Assert.Equal(FetchOutcome.NetworkError, wrongBody.Outcome);
        Assert.Contains("no recorded exchange", wrongBody.Reason, StringComparison.Ordinal);
        Assert.Equal(FetchOutcome.NetworkError, (await rf.FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{port}/other") })).Outcome);

        var loose = new Fetcher(new ReplayTransport(log, new ReplayOptions { MatchBody = false }), new FetchOptions { Cache = null });
        Assert.True((await loose.FetchAsync(new FetchRequest { Uri = new Uri($"http://127.0.0.1:{port}/p"), Method = "POST", Body = new byte[] { 1 } })).IsSuccess);
    }
}
