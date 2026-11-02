using System.Globalization;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>Where a URL came from, which decides how far the fetcher trusts it.</summary>
public enum UrlOrigin
{
    /// <summary>The caller wrote the URL in code or configuration (a TSA address, a responder address). The address guard is not applied to the first request; it is applied to every redirect.</summary>
    Caller = 0,

    /// <summary>The URL came out of a certificate, a CRL or a message (authorityInfoAccess, cRLDistributionPoints, an OCSP location). Whoever made that object chose it, so the address guard applies from the first request.</summary>
    Certificate = 1,
}

/// <summary>How a request uses the cache.</summary>
public enum FetchCacheMode
{
    /// <summary>The cache is not read or written.</summary>
    None = 0,

    /// <summary>RFC 9111 for a GET: reuse a fresh stored response, revalidate a stale one with <c>If-None-Match</c> / <c>If-Modified-Since</c>, honour <c>no-store</c> and <c>no-cache</c>. The request's <see cref="FetchRequest.IsReusable"/> check also has to accept the stored body.</summary>
    Http = 1,

    /// <summary>The stored body is reused exactly while <see cref="FetchRequest.IsReusable"/> accepts it, whatever the HTTP headers said. For responses whose own content states how long they are good for (a CRL, an OCSP response) and for POST exchanges.</summary>
    Content = 2,
}

/// <summary>How a fetch ended.</summary>
public enum FetchOutcome
{
    /// <summary>A 2xx response with a body within the limits (or a cached copy).</summary>
    Ok = 0,

    /// <summary>The server answered with a status other than success.</summary>
    HttpStatus = 1,

    /// <summary>The URL was not an absolute <c>http</c> or <c>https</c> URL.</summary>
    SchemeNotAllowed = 2,

    /// <summary>The URL carries user information (<c>user:password@</c>), which is never sent or followed.</summary>
    UserInfoNotAllowed = 3,

    /// <summary>The address, or the name <c>localhost</c>, is in a range <see cref="NetworkGuard"/> blocks.</summary>
    AddressBlocked = 4,

    /// <summary>More redirects than <see cref="FetchOptions.MaxRedirects"/>.</summary>
    TooManyRedirects = 5,

    /// <summary>A redirect that is malformed, loops, leaves the allowed schemes or downgrades https to http.</summary>
    RedirectRejected = 6,

    /// <summary>The body is larger than the limit.</summary>
    ResponseTooLarge = 7,

    /// <summary>The time limit passed.</summary>
    Timeout = 8,

    /// <summary>The name did not resolve, the connection failed, or TLS failed.</summary>
    NetworkError = 9,

    /// <summary>The body was shorter than its declared length or the connection broke while reading it.</summary>
    TruncatedBody = 10,
}

/// <summary>A request for <see cref="Fetcher"/>.</summary>
public sealed class FetchRequest
{
    /// <summary>The absolute URL.</summary>
    public required Uri Uri { get; init; }

    /// <summary><c>GET</c> (default) or <c>POST</c>.</summary>
    public string Method { get; init; } = "GET";

    /// <summary>The request body for POST.</summary>
    public ReadOnlyMemory<byte> Body { get; init; }

    /// <summary>Extra request headers. They are dropped when a redirect leaves the original host.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; } = [];

    /// <summary>Where the URL came from (default <see cref="UrlOrigin.Caller"/>).</summary>
    public UrlOrigin Origin { get; init; }

    /// <summary>The cache use (default <see cref="FetchCacheMode.None"/>).</summary>
    public FetchCacheMode Cache { get; init; }

    /// <summary>Overrides <see cref="FetchOptions.MaxResponseBytes"/> for this request.</summary>
    public long? MaxResponseBytes { get; init; }

    /// <summary>Overrides <see cref="FetchOptions.Timeout"/> for this request.</summary>
    public TimeSpan? Timeout { get; init; }

    /// <summary>
    /// Says whether a stored body may still be used. A CRL client passes "its <c>thisUpdate</c> is not after the reference time and its <c>nextUpdate</c> is not before it",
    /// an OCSP client the same for the single response. Null accepts any stored body.
    /// </summary>
    public Func<ReadOnlyMemory<byte>, bool>? IsReusable { get; init; }

    /// <summary>When the network fails and a stored body that <see cref="IsReusable"/> accepts exists, return it marked <see cref="FetchResult.Stale"/> (default false).</summary>
    public bool ServeStaleOnError { get; init; }
}

/// <summary>Limits and shared parts of a <see cref="Fetcher"/>.</summary>
public sealed class FetchOptions
{
    /// <summary>The address rules (default <see cref="NetworkGuard.Default"/>).</summary>
    public NetworkGuard Guard { get; init; } = NetworkGuard.Default;

    /// <summary>The longest a request may take from start to the last body byte (default 20 seconds).</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>The largest response body accepted (default 4 MiB). The clients raise it for CRLs.</summary>
    public long MaxResponseBytes { get; init; } = 4L << 20;

    /// <summary>The most redirects followed (default 3). Each hop is checked like a new request.</summary>
    public int MaxRedirects { get; init; } = 3;

    /// <summary>The cache; null for none (default: a new <see cref="MemoryFetchCache"/>).</summary>
    public IFetchCache? Cache { get; init; } = new MemoryFetchCache();

    /// <summary>The clock for HTTP freshness and ages (default the system clock). Freshness of CRL and OCSP content is judged at the reference time the caller gives, not by this.</summary>
    public TimeProvider Time { get; init; } = TimeProvider.System;

    /// <summary>The freshness given to a stored response with no caching information at all (default zero: always ask).</summary>
    public TimeSpan DefaultFreshness { get; init; } = TimeSpan.Zero;

    /// <summary>The longest freshness taken from a response (default 30 days).</summary>
    public TimeSpan MaxFreshness { get; init; } = TimeSpan.FromDays(30);
}

/// <summary>What a fetch produced. A failure is an <see cref="Outcome"/> with its <see cref="Reason"/>, never an exception.</summary>
public sealed class FetchResult
{
    internal FetchResult(FetchOutcome outcome, string reason, Uri uri)
    {
        Outcome = outcome;
        Reason = reason;
        RequestedUri = uri;
        FinalUri = uri;
    }

    /// <summary>How the fetch ended.</summary>
    public FetchOutcome Outcome { get; internal set; }

    /// <summary>A sentence saying why, for logs and reports. Empty on success.</summary>
    public string Reason { get; internal set; }

    /// <summary>True when <see cref="Outcome"/> is <see cref="FetchOutcome.Ok"/>.</summary>
    public bool IsSuccess => Outcome == FetchOutcome.Ok;

    /// <summary>The URL asked for.</summary>
    public Uri RequestedUri { get; }

    /// <summary>The URL of the last request made (after redirects).</summary>
    public Uri FinalUri { get; internal set; }

    /// <summary>For a <see cref="FetchOutcome.NetworkError"/> or <see cref="FetchOutcome.AddressBlocked"/> raised by the transport, what the transport reported (for example <see cref="TransportFailure.NameResolution"/>); otherwise null.</summary>
    public TransportFailure? TransportFailure { get; internal set; }

    /// <summary>The last HTTP status received, if any.</summary>
    public int? StatusCode { get; internal set; }

    /// <summary>The response headers of the last response.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; internal set; } = [];

    /// <summary>The body (empty unless <see cref="IsSuccess"/>).</summary>
    public ReadOnlyMemory<byte> Body { get; internal set; }

    /// <summary>The <c>Content-Type</c> media type without parameters, lower case, or empty.</summary>
    public string ContentType => MediaType(HeaderLookup.First(Headers, "Content-Type"));

    /// <summary>The URLs followed, in order.</summary>
    public IReadOnlyList<Uri> Redirects { get; internal set; } = [];

    /// <summary>True when the body came from the cache without asking the server.</summary>
    public bool FromCache { get; internal set; }

    /// <summary>True when a cached body was used after the server could not be reached (<see cref="FetchRequest.ServeStaleOnError"/>).</summary>
    public bool Stale { get; internal set; }

    /// <summary>True when a stored response was confirmed by a 304 answer.</summary>
    public bool Revalidated { get; internal set; }

    internal static string MediaType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            return string.Empty;
        }

        int semi = contentType.IndexOf(';', StringComparison.Ordinal);
        return (semi < 0 ? contentType : contentType[..semi]).Trim().ToLowerInvariant();
    }
}

/// <summary>
/// Fetches over a <see cref="ITransport"/> with the guards on: only <c>http</c> and <c>https</c>, no user information, the <see cref="NetworkGuard"/> on every hop,
/// a time limit that covers reading the body, a size limit enforced while reading, a redirect limit, and an RFC 9111 cache. Nothing is fetched except what a call
/// asks for. No call throws for a network reason: the answer is a <see cref="FetchResult"/> whose <see cref="FetchResult.Outcome"/> says what happened. Only
/// cancellation through the caller's token surfaces as <see cref="OperationCanceledException"/>.
/// </summary>
public sealed class Fetcher
{
    private readonly ITransport _transport;

    /// <summary>Creates a fetcher.</summary>
    /// <param name="transport">The transport; null for a new <see cref="HttpTransport"/>.</param>
    /// <param name="options">The limits; null for the defaults.</param>
    public Fetcher(ITransport? transport = null, FetchOptions? options = null)
    {
        _transport = transport ?? new HttpTransport();
        Options = options ?? new FetchOptions();
    }

    /// <summary>The limits in force.</summary>
    public FetchOptions Options { get; }

    /// <summary>Fetches a URL.</summary>
    /// <param name="request">What to fetch.</param>
    /// <param name="cancellationToken">Cancels the fetch.</param>
    /// <returns>The result; see <see cref="FetchOutcome"/>.</returns>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public async ValueTask<FetchResult> FetchAsync(FetchRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var result = new FetchResult(FetchOutcome.NetworkError, "not started", request.Uri);
        string method = request.Method.ToUpperInvariant();
        if (method is not ("GET" or "POST"))
        {
            result.Outcome = FetchOutcome.SchemeNotAllowed;
            result.Reason = $"method {request.Method} is not supported";
            return result;
        }

        TimeSpan timeout = request.Timeout ?? Options.Timeout;
        long maxBytes = request.MaxResponseBytes ?? Options.MaxResponseBytes;
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        CancellationToken token = timeoutSource.Token;

        var redirects = new List<Uri>();
        Uri current = request.Uri;
        ReadOnlyMemory<byte> body = method == "POST" ? request.Body : default;
        IReadOnlyList<KeyValuePair<string, string>> headers = request.Headers;
        UrlOrigin origin = request.Origin;
        string cacheKey = string.Empty;
        CacheEntry? stored = null;

        for (int hop = 0; ; hop++)
        {
            result.FinalUri = current;
            if (Check(current, origin) is { } refusal)
            {
                result.Outcome = refusal.Outcome;
                result.Reason = refusal.Reason;
                result.Redirects = redirects;
                return result;
            }

            bool useCache = request.Cache != FetchCacheMode.None && Options.Cache is not null && (request.Cache == FetchCacheMode.Content || method == "GET");
            if (useCache)
            {
                cacheKey = HttpCaching.Key(method, current, body.Span);
            }

            var sendHeaders = headers;
            stored = null;
            if (useCache && Options.Cache!.TryGet(cacheKey, out stored) && stored is not null)
            {
                bool reusable = request.IsReusable?.Invoke(stored.Body) ?? true;
                DateTimeOffset now = Options.Time.GetUtcNow();
                bool fresh = request.Cache == FetchCacheMode.Content || stored.IsFresh(now);
                if (reusable && fresh)
                {
                    result.Outcome = FetchOutcome.Ok;
                    result.Reason = string.Empty;
                    result.StatusCode = stored.StatusCode;
                    result.Headers = stored.Headers;
                    result.Body = stored.Body;
                    result.FromCache = true;
                    result.Redirects = redirects;
                    return result;
                }

                if (!reusable)
                {
                    // The stored body says it is out of date for this question: ask again without validators, a 304 could not help.
                    stored = null;
                }
                else if (request.Cache == FetchCacheMode.Http && (stored.ETag is not null || stored.LastModified is not null))
                {
                    var conditional = new List<KeyValuePair<string, string>>(headers);
                    if (stored.ETag is not null)
                    {
                        conditional.Add(new("If-None-Match", stored.ETag));
                    }
                    else if (stored.LastModified is not null)
                    {
                        conditional.Add(new("If-Modified-Since", stored.LastModified));
                    }

                    sendHeaders = conditional;
                }
                else
                {
                    stored = null;
                }
            }
            else
            {
                stored = null;
            }

            var tr = new TransportRequest
            {
                Method = method,
                Uri = current,
                Headers = sendHeaders,
                Body = body,
                Guard = origin == UrlOrigin.Certificate ? Options.Guard : null,
            };

            TransportResponse response;
            try
            {
                response = await _transport.SendAsync(tr, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return Fail(result, FetchOutcome.Timeout, $"no answer within {timeout.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)} s", redirects, request, cacheKey, useCache);
            }
            catch (TransportException ex)
            {
                result.TransportFailure = ex.Failure;
                FetchOutcome o = ex.Failure == TransportFailure.AddressBlocked ? FetchOutcome.AddressBlocked : FetchOutcome.NetworkError;
                return Fail(result, o, ex.Message, redirects, request, cacheKey, useCache && o == FetchOutcome.NetworkError);
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or System.Net.Sockets.SocketException or InvalidOperationException or NotSupportedException or UriFormatException or System.Security.Authentication.AuthenticationException)
            {
                // A transport that follows the contract throws TransportException; these are the BCL's own network failures from one that does not.
                return Fail(result, FetchOutcome.NetworkError, ex.Message, redirects, request, cacheKey, useCache);
            }

            using (response)
            {
                result.StatusCode = response.StatusCode;
                result.Headers = response.Headers;

                if (response.StatusCode is 301 or 302 or 303 or 307 or 308)
                {
                    string? location = response.Header("Location");
                    if (hop >= Options.MaxRedirects)
                    {
                        return Done(result, FetchOutcome.TooManyRedirects, $"more than {Options.MaxRedirects} redirects", redirects);
                    }

                    if (location is null || location.Length > 8192 || !Uri.TryCreate(current, location, out Uri? next))
                    {
                        return Done(result, FetchOutcome.RedirectRejected, "the redirect has no usable Location", redirects);
                    }

                    if (current.Scheme == Uri.UriSchemeHttps && next.Scheme == Uri.UriSchemeHttp)
                    {
                        return Done(result, FetchOutcome.RedirectRejected, "a redirect from https to http is refused", redirects);
                    }

                    if (next.Equals(current) || redirects.Contains(next))
                    {
                        return Done(result, FetchOutcome.RedirectRejected, "redirect loop", redirects);
                    }

                    redirects.Add(next);
                    if (!string.Equals(next.Host, current.Host, StringComparison.OrdinalIgnoreCase) || next.Port != current.Port)
                    {
                        // Credentials and API keys stay with the host they were meant for.
                        headers = [.. headers.Where(h => h.Key.Equals("Accept", StringComparison.OrdinalIgnoreCase) || h.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))];
                    }

                    if (response.StatusCode is 301 or 302 or 303 && method == "POST")
                    {
                        // RFC 9110 §15.4: these statuses let the client turn a POST into a GET, and a GET has no body.
                        method = "GET";
                        body = default;
                        headers = [.. headers.Where(h => !h.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))];
                    }

                    // A server chose this address, not the caller: from here on the guard applies to everything.
                    origin = UrlOrigin.Certificate;
                    current = next;
                    continue;
                }

                if (response.StatusCode == 304 && stored is not null)
                {
                    // RFC 9111 §4.3.4: the stored response is current again; take the new freshness information from this one.
                    DateTimeOffset now = Options.Time.GetUtcNow();
                    var merged = new List<KeyValuePair<string, string>>(stored.Headers.Where(h => !response.Headers.Any(n => n.Key.Equals(h.Key, StringComparison.OrdinalIgnoreCase))));
                    merged.AddRange(response.Headers);
                    CacheEntry? renewed = HttpCaching.Store(200, merged, stored.Body, now, Options.DefaultFreshness, Options.MaxFreshness);
                    if (renewed is not null && (request.IsReusable?.Invoke(stored.Body) ?? true))
                    {
                        Options.Cache!.Put(cacheKey, renewed);
                        result.Outcome = FetchOutcome.Ok;
                        result.Reason = string.Empty;
                        result.Headers = renewed.Headers;
                        result.Body = stored.Body;
                        result.FromCache = true;
                        result.Revalidated = true;
                        result.Redirects = redirects;
                        return result;
                    }

                    Options.Cache!.Remove(cacheKey);
                    return Done(result, FetchOutcome.HttpStatus, "a 304 answer confirmed a stored response that can no longer be used", redirects);
                }

                if (response.StatusCode is < 200 or > 299)
                {
                    return Fail(result, FetchOutcome.HttpStatus, $"the server answered {response.StatusCode}", redirects, request, cacheKey, useCache && response.StatusCode >= 500);
                }

                string? declared = response.Header("Content-Length");
                if (declared is not null && long.TryParse(declared, NumberStyles.None, CultureInfo.InvariantCulture, out long length) && length > maxBytes)
                {
                    return Done(result, FetchOutcome.ResponseTooLarge, $"the response declares {length} bytes, the limit is {maxBytes}", redirects);
                }

                byte[]? data;
                try
                {
                    data = await ReadBodyAsync(response.Body, maxBytes, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    return Fail(result, FetchOutcome.Timeout, $"the body was not complete within {timeout.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)} s", redirects, request, cacheKey, useCache);
                }
                catch (Exception ex) when (ex is IOException or HttpRequestException or InvalidOperationException or NotSupportedException)
                {
                    return Fail(result, FetchOutcome.TruncatedBody, ex.Message, redirects, request, cacheKey, useCache);
                }

                if (data is null)
                {
                    return Done(result, FetchOutcome.ResponseTooLarge, $"the response is longer than {maxBytes} bytes", redirects);
                }

                if (declared is not null && long.TryParse(declared, NumberStyles.None, CultureInfo.InvariantCulture, out long want) && want != data.Length && response.StatusCode != 204)
                {
                    return Fail(result, FetchOutcome.TruncatedBody, $"the response declares {want} bytes and delivered {data.Length}", redirects, request, cacheKey, useCache);
                }

                result.Outcome = FetchOutcome.Ok;
                result.Reason = string.Empty;
                result.Body = data;
                result.Redirects = redirects;
                if (useCache && !(request.Cache == FetchCacheMode.Content && request.IsReusable is { } check && !check(data)))
                {
                    StoreResponse(request, cacheKey, response, data);
                }

                return result;
            }
        }
    }

    private void StoreResponse(FetchRequest request, string key, TransportResponse response, byte[] data)
    {
        DateTimeOffset now = Options.Time.GetUtcNow();
        if (request.Cache == FetchCacheMode.Content)
        {
            // The content states its own lifetime; HTTP headers only matter if they forbid storing.
            if (CacheControl.Parse(HeaderLookup.Joined(response.Headers, "Cache-Control")).NoStore)
            {
                return;
            }

            Options.Cache!.Put(key, new CacheEntry(response.StatusCode, response.Headers, data, now, TimeSpan.Zero, TimeSpan.MaxValue, false, null, null));
            return;
        }

        CacheEntry? entry = HttpCaching.Store(response.StatusCode, response.Headers, data, now, Options.DefaultFreshness, Options.MaxFreshness);
        if (entry is not null)
        {
            Options.Cache!.Put(key, entry);
        }
        else
        {
            Options.Cache!.Remove(key);
        }
    }

    private FetchResult Fail(FetchResult result, FetchOutcome outcome, string reason, List<Uri> redirects, FetchRequest request, string cacheKey, bool mayServeStale)
    {
        if (mayServeStale && request.ServeStaleOnError && Options.Cache is { } cache && cache.TryGet(cacheKey, out CacheEntry? e) && e is not null && (request.IsReusable?.Invoke(e.Body) ?? true)
            && !e.MustRevalidate)
        {
            result.Outcome = FetchOutcome.Ok;
            result.Reason = string.Empty;
            result.Body = e.Body;
            result.Headers = e.Headers;
            result.StatusCode = e.StatusCode;
            result.FromCache = true;
            result.Stale = true;
            result.Redirects = redirects;
            return result;
        }

        return Done(result, outcome, reason, redirects);
    }

    private static FetchResult Done(FetchResult result, FetchOutcome outcome, string reason, List<Uri> redirects)
    {
        result.Outcome = outcome;
        result.Reason = reason;
        result.Redirects = redirects;
        return result;
    }

    private (FetchOutcome Outcome, string Reason)? Check(Uri uri, UrlOrigin origin)
    {
        if (!uri.IsAbsoluteUri || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return (FetchOutcome.SchemeNotAllowed, $"only http and https URLs are fetched, not {(uri.IsAbsoluteUri ? uri.Scheme : "a relative reference")}");
        }

        if (uri.UserInfo.Length > 0)
        {
            return (FetchOutcome.UserInfoNotAllowed, "URLs with user information are not fetched");
        }

        if (uri.Host.Length == 0)
        {
            return (FetchOutcome.SchemeNotAllowed, "the URL has no host");
        }

        // The first request of a caller-written URL is trusted; certificate-supplied URLs and every redirect hop (which is marked Certificate) must pass the literal checks here and the address check in the transport.
        if (origin == UrlOrigin.Certificate && Options.Guard.CheckLiteral(uri) is { } why)
        {
            return (FetchOutcome.AddressBlocked, $"{uri.Host} is {why}");
        }

        return null;
    }

    /// <summary>Reads at most <paramref name="max"/> bytes; null when the body is longer.</summary>
    private static async ValueTask<byte[]?> ReadBodyAsync(Stream body, long max, CancellationToken token)
    {
        using var ms = new MemoryStream();
        byte[] buffer = new byte[16 * 1024];
        while (true)
        {
            int n = await body.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false);
            if (n == 0)
            {
                return ms.ToArray();
            }

            if (ms.Length + n > max)
            {
                return null;
            }

            ms.Write(buffer, 0, n);
        }
    }
}
