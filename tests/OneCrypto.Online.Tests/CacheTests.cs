using System.Text;
using RecursiveAI.OneCrypto.Online;

namespace OneCrypto.Online.Tests;

internal sealed class TestClock : TimeProvider
{
    private DateTimeOffset _now;

    public TestClock(DateTimeOffset start) => _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

public class CacheTests
{
    private static readonly DateTimeOffset Start = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Body = Encoding.ASCII.GetBytes("v1");

    private static string Http(DateTimeOffset t) => t.ToString("R", System.Globalization.CultureInfo.InvariantCulture);

    private static (Fetcher Fetcher, TestClock Clock) Make(ITransport net)
    {
        var clock = new TestClock(Start);
        return (new Fetcher(net, new FetchOptions { Time = clock, Cache = new MemoryFetchCache() }), clock);
    }

    private static FetchRequest Req(string url = "http://example.test/x", Func<ReadOnlyMemory<byte>, bool>? reusable = null) =>
        new() { Uri = new Uri(url), Cache = FetchCacheMode.Http, IsReusable = reusable };

    [Fact]
    public async Task AFreshResponseIsServedWithoutAskingAgain()
    {
        var net = new FakeNetwork(_ => Reply.Ok(Body, "x/y", ("Date", Http(Start)), ("Cache-Control", "max-age=600")));
        (Fetcher f, TestClock clock) = Make(net);
        Assert.False((await f.FetchAsync(Req())).FromCache);
        clock.Advance(TimeSpan.FromSeconds(599));
        FetchResult second = await f.FetchAsync(Req());
        Assert.True(second.FromCache);
        Assert.Single(net.Requests);

        clock.Advance(TimeSpan.FromSeconds(2));
        FetchResult third = await f.FetchAsync(Req());
        Assert.False(third.FromCache);
        Assert.Equal(2, net.Requests.Count);
    }

    [Fact]
    public async Task TheAgeHeaderAndAnOldDateShortenFreshness()
    {
        var net = new FakeNetwork(_ => Reply.Ok(Body, "x/y", ("Date", Http(Start.AddSeconds(-500))), ("Cache-Control", "max-age=600")));
        (Fetcher f, TestClock clock) = Make(net);
        await f.FetchAsync(Req());
        clock.Advance(TimeSpan.FromSeconds(50));
        Assert.True((await f.FetchAsync(Req())).FromCache);
        clock.Advance(TimeSpan.FromSeconds(60));
        Assert.False((await f.FetchAsync(Req())).FromCache);

        var net2 = new FakeNetwork(_ => Reply.Ok(Body, "x/y", ("Age", "590"), ("Cache-Control", "max-age=600")));
        (Fetcher f2, TestClock c2) = Make(net2);
        await f2.FetchAsync(Req());
        c2.Advance(TimeSpan.FromSeconds(5));
        Assert.True((await f2.FetchAsync(Req())).FromCache);
        c2.Advance(TimeSpan.FromSeconds(10));
        Assert.False((await f2.FetchAsync(Req())).FromCache);
    }

    [Fact]
    public async Task ExpiresIsUsedWithoutMaxAgeAndMaxAgeWins()
    {
        var net = new FakeNetwork(_ => Reply.Ok(Body, "x/y", ("Date", Http(Start)), ("Expires", Http(Start.AddMinutes(10)))));
        (Fetcher f, TestClock clock) = Make(net);
        await f.FetchAsync(Req());
        clock.Advance(TimeSpan.FromMinutes(9));
        Assert.True((await f.FetchAsync(Req())).FromCache);

        var net2 = new FakeNetwork(_ => Reply.Ok(Body, "x/y", ("Date", Http(Start)), ("Expires", Http(Start.AddDays(1))), ("Cache-Control", "max-age=60")));
        (Fetcher f2, TestClock c2) = Make(net2);
        await f2.FetchAsync(Req());
        c2.Advance(TimeSpan.FromMinutes(2));
        Assert.False((await f2.FetchAsync(Req())).FromCache);
    }

    [Theory]
    [InlineData("no-store")]
    [InlineData("no-cache")]
    [InlineData("max-age=0")]
    public async Task ResponsesThatForbidReuseAreNotReused(string directive)
    {
        var net = new FakeNetwork(_ => Reply.Ok(Body, "x/y", ("Date", Http(Start)), ("Cache-Control", directive)));
        (Fetcher f, _) = Make(net);
        await f.FetchAsync(Req());
        Assert.False((await f.FetchAsync(Req())).FromCache);
        Assert.Equal(2, net.Requests.Count);
    }

    [Fact]
    public async Task AStaleResponseIsRevalidatedWithTheEntityTagAndA304RenewsIt()
    {
        int n = 0;
        var net = new FakeNetwork(r =>
        {
            n++;
            return r.Headers.Any(h => h.Key == "If-None-Match" && h.Value == "\"abc\"")
                ? new Reply(304, [], ("Cache-Control", "max-age=600"), ("Date", Http(Start.AddMinutes(11))))
                : Reply.Ok(Body, "x/y", ("Date", Http(Start)), ("Cache-Control", "max-age=600"), ("ETag", "\"abc\""));
        });
        (Fetcher f, TestClock clock) = Make(net);
        await f.FetchAsync(Req());
        clock.Advance(TimeSpan.FromMinutes(11));
        FetchResult r = await f.FetchAsync(Req());
        Assert.True(r.IsSuccess);
        Assert.True(r.Revalidated);
        Assert.Equal(Body, r.Body.ToArray());
        Assert.Equal(2, n);

        // The 304 renewed the lifetime: the next ask, a little later, needs no request.
        clock.Advance(TimeSpan.FromMinutes(5));
        Assert.True((await f.FetchAsync(Req())).FromCache);
        Assert.Equal(2, n);
    }

    [Fact]
    public async Task LastModifiedIsUsedWhenThereIsNoEntityTag()
    {
        var net = new FakeNetwork(r => r.Headers.Any(h => h.Key == "If-Modified-Since") ? new Reply(304, []) : Reply.Ok(Body, "x/y", ("Date", Http(Start)), ("Last-Modified", Http(Start.AddDays(-10))), ("Cache-Control", "max-age=60")));
        (Fetcher f, TestClock clock) = Make(net);
        await f.FetchAsync(Req());
        clock.Advance(TimeSpan.FromMinutes(5));
        Assert.True((await f.FetchAsync(Req())).Revalidated);
    }

    [Fact]
    public async Task AStoredBodyThatTheCallerRejectsIsFetchedAgainWithoutValidators()
    {
        int version = 0;
        var net = new FakeNetwork(r =>
        {
            version++;
            return Reply.Ok(Encoding.ASCII.GetBytes("v" + version), "x/y", ("Date", Http(Start)), ("Cache-Control", "max-age=3600"), ("ETag", "\"e" + version + "\""));
        });
        (Fetcher f, _) = Make(net);
        Assert.Equal("v1", Encoding.ASCII.GetString((await f.FetchAsync(Req())).Body.Span));

        // Fresh by HTTP, but the content says it is out of date for this question.
        FetchResult r = await f.FetchAsync(Req(reusable: b => Encoding.ASCII.GetString(b.Span) != "v1"));
        Assert.Equal("v2", Encoding.ASCII.GetString(r.Body.Span));
        Assert.False(r.FromCache);
        Assert.DoesNotContain(net.Requests[1].Headers, h => h.Key == "If-None-Match");
    }

    [Fact]
    public async Task AStaleCopyIsServedWhenTheServerIsDownAndTheContentIsStillGood()
    {
        bool down = false;
        var net = new StreamNetwork((_, _) => down
            ? throw new TransportException(TransportFailure.Connect, "refused")
            : new TransportResponse(200, [new("Date", Http(Start)), new("Cache-Control", "max-age=60")], new MemoryStream(Body)));
        (Fetcher f, TestClock clock) = Make(net);
        await f.FetchAsync(Req());
        clock.Advance(TimeSpan.FromHours(1));
        down = true;

        Assert.Equal(FetchOutcome.NetworkError, (await f.FetchAsync(Req())).Outcome);
        FetchResult stale = await f.FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/x"), Cache = FetchCacheMode.Http, ServeStaleOnError = true });
        Assert.True(stale.IsSuccess);
        Assert.True(stale.Stale);
        Assert.True(stale.FromCache);

        FetchResult refused = await f.FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/x"), Cache = FetchCacheMode.Http, ServeStaleOnError = true, IsReusable = _ => false });
        Assert.Equal(FetchOutcome.NetworkError, refused.Outcome);
    }

    [Fact]
    public async Task MustRevalidateForbidsServingStale()
    {
        bool down = false;
        var net = new StreamNetwork((_, _) => down
            ? throw new TransportException(TransportFailure.Connect, "refused")
            : new TransportResponse(200, [new("Date", Http(Start)), new("Cache-Control", "max-age=60, must-revalidate")], new MemoryStream(Body)));
        (Fetcher f, TestClock clock) = Make(net);
        await f.FetchAsync(Req());
        clock.Advance(TimeSpan.FromHours(1));
        down = true;
        FetchResult r = await f.FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/x"), Cache = FetchCacheMode.Http, ServeStaleOnError = true });
        Assert.False(r.IsSuccess);
    }

    [Fact]
    public async Task ContentModeReusesAPostExchangeExactlyWhileTheCallerAccepts()
    {
        var net = new FakeNetwork(_ => Reply.Ok(Body, "x/y"));
        (Fetcher f, _) = Make(net);
        bool good = true;
        FetchRequest Post(byte[] body) => new() { Uri = new Uri("http://ocsp.test/"), Method = "POST", Body = body, Cache = FetchCacheMode.Content, IsReusable = _ => good };

        await f.FetchAsync(Post([1, 2]));
        Assert.True((await f.FetchAsync(Post([1, 2]))).FromCache);
        Assert.False((await f.FetchAsync(Post([1, 3]))).FromCache);
        good = false;
        Assert.False((await f.FetchAsync(Post([1, 2]))).FromCache);
        Assert.Equal(3, net.Requests.Count);
    }

    [Fact]
    public async Task ContentModeDoesNotStoreABodyTheCallerAlreadyRejects()
    {
        var net = new FakeNetwork(_ => Reply.Ok(Body, "x/y"));
        var cache = new MemoryFetchCache();
        var f = new Fetcher(net, new FetchOptions { Cache = cache });
        await f.FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/"), Cache = FetchCacheMode.Content, IsReusable = _ => false });
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public async Task OnlyOkResponsesAreStoredAndErrorsDoNotReplaceGoodCopies()
    {
        int n = 0;
        var net = new FakeNetwork(_ => ++n == 1 ? Reply.Ok(Body, "x/y", ("Date", Http(Start)), ("Cache-Control", "max-age=10")) : Reply.Code(500));
        (Fetcher f, TestClock clock) = Make(net);
        await f.FetchAsync(Req());
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(FetchOutcome.HttpStatus, (await f.FetchAsync(Req())).Outcome);
        FetchResult stale = await f.FetchAsync(new FetchRequest { Uri = new Uri("http://example.test/x"), Cache = FetchCacheMode.Http, ServeStaleOnError = true });
        Assert.True(stale.Stale);
    }

    [Fact]
    public void TheMemoryCacheStaysWithinItsBounds()
    {
        var c = new MemoryFetchCache(maxBytes: 100, maxEntries: 3);
        for (int i = 0; i < 6; i++)
        {
            c.Put("k" + i, new CacheEntry(200, [], new byte[40], Start.AddSeconds(i), TimeSpan.Zero, TimeSpan.FromHours(1), false, null, null));
        }

        Assert.True(c.Count <= 2);
        Assert.True(c.TryGet("k5", out _));
        Assert.False(c.TryGet("k0", out _));
        c.Put("big", new CacheEntry(200, [], new byte[101], Start, TimeSpan.Zero, TimeSpan.FromHours(1), false, null, null));
        Assert.False(c.TryGet("big", out _));
    }

    [Theory]
    [InlineData("max-age=60", 60L, false, false)]
    [InlineData("Max-Age=\"60\"", 60L, false, false)]
    [InlineData("public, max-age=5, no-cache", 5L, true, false)]
    [InlineData("no-store", null, false, true)]
    [InlineData("max-age=-1", null, false, false)]
    [InlineData("max-age=abc", null, false, false)]
    [InlineData("max-age=99999999999999999999999", null, false, false)]
    [InlineData("", null, false, false)]
    [InlineData(",,, ,=,", null, false, false)]
    [InlineData("no-cache=\"Set-Cookie\", max-age=9", 9L, true, false)]
    public void CacheControlParsesLeniently(string value, long? maxAge, bool noCache, bool noStore)
    {
        CacheControl cc = CacheControl.Parse(value);
        Assert.Equal(maxAge, cc.MaxAge);
        Assert.Equal(noCache, cc.NoCache);
        Assert.Equal(noStore, cc.NoStore);
    }
}
