using System.Globalization;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>How a request for OpenPGP certificates (Web Key Directory, keyserver) ended.</summary>
public enum KeyFetchOutcome
{
    /// <summary>The server answered with certificate data. The data is untrusted: nothing has checked that it is a certificate, or whose.</summary>
    Found = 0,

    /// <summary>No certificate is published for the query (404).</summary>
    NotFound = 1,

    /// <summary>The data was deleted on purpose and will not come back (410).</summary>
    Gone = 2,

    /// <summary>The server limits the request rate (429); <see cref="KeyFetchResult.RetryAfter"/> says when to try again, if it said.</summary>
    RateLimited = 3,

    /// <summary>The server does not implement the operation (501).</summary>
    NotImplemented = 4,

    /// <summary>The server forbids the operation (403).</summary>
    Forbidden = 5,

    /// <summary>The server asked for authentication (401). Public key data needs none, so the challenge is never answered.</summary>
    Unauthorized = 6,

    /// <summary>The answer was successful but empty.</summary>
    EmptyResponse = 7,

    /// <summary>The request could not be completed: a network failure, a refused address, a limit, a redirect that is not allowed, or another HTTP status. <see cref="KeyFetchResult.Fetch"/> has the detail.</summary>
    FetchFailed = 8,

    /// <summary>The query itself is not valid (a malformed address, fingerprint or key ID), so nothing was sent.</summary>
    InvalidQuery = 9,

    /// <summary>A Web Key Directory policy file was required and the domain serves none.</summary>
    PolicyMissing = 10,
}

/// <summary>What a Web Key Directory or keyserver lookup returned, still as bytes.</summary>
/// <remarks>
/// <see cref="Body"/> is exactly what the server sent: binary packets, an ASCII-armored block, or armor inside other text. This package has no OpenPGP types;
/// hand the bytes to <c>RecursiveAI.OneCrypto.OpenPgp.KeyDiscovery</c>, which finds the certificates, drops what the query did not ask for and never trusts what the server claims.
/// </remarks>
public class KeyFetchResult
{
    internal KeyFetchResult(KeyFetchOutcome outcome, string reason, Uri? uri, FetchResult? fetch, ReadOnlyMemory<byte> body = default, TimeSpan? retryAfter = null)
    {
        Outcome = outcome;
        Reason = reason;
        Uri = uri;
        Fetch = fetch;
        Body = body;
        RetryAfter = retryAfter;
    }

    /// <summary>How the request ended.</summary>
    public KeyFetchOutcome Outcome { get; }

    /// <summary>True when <see cref="Outcome"/> is <see cref="KeyFetchOutcome.Found"/>.</summary>
    public bool IsSuccess => Outcome == KeyFetchOutcome.Found;

    /// <summary>A sentence saying why, empty on success.</summary>
    public string Reason { get; }

    /// <summary>The URL of the request (null when nothing was sent).</summary>
    public Uri? Uri { get; }

    /// <summary>The HTTP exchange, for the status code, headers and redirects (null when nothing was sent).</summary>
    public FetchResult? Fetch { get; }

    /// <summary>The response body; empty unless <see cref="IsSuccess"/>.</summary>
    public ReadOnlyMemory<byte> Body { get; }

    /// <summary>How long the server asked the client to wait (<c>Retry-After</c>) when <see cref="Outcome"/> is <see cref="KeyFetchOutcome.RateLimited"/>; null if it did not say.</summary>
    public TimeSpan? RetryAfter { get; }

    internal static KeyFetchResult Invalid(string reason) => new(KeyFetchOutcome.InvalidQuery, reason, null, null);

    internal static KeyFetchResult From(FetchResult fetch, TimeProvider time)
    {
        if (fetch.IsSuccess)
        {
            return fetch.Body.IsEmpty
                ? new KeyFetchResult(KeyFetchOutcome.EmptyResponse, "the server answered with an empty body", fetch.FinalUri, fetch)
                : new KeyFetchResult(KeyFetchOutcome.Found, string.Empty, fetch.FinalUri, fetch, fetch.Body);
        }

        KeyFetchOutcome outcome = KeyFetchOutcome.FetchFailed;
        TimeSpan? retry = null;
        if (fetch.Outcome == FetchOutcome.HttpStatus)
        {
            outcome = fetch.StatusCode switch
            {
                404 => KeyFetchOutcome.NotFound,
                410 => KeyFetchOutcome.Gone,
                429 => KeyFetchOutcome.RateLimited,
                501 => KeyFetchOutcome.NotImplemented,
                403 => KeyFetchOutcome.Forbidden,
                401 => KeyFetchOutcome.Unauthorized,
                _ => KeyFetchOutcome.FetchFailed,
            };
            if (outcome == KeyFetchOutcome.RateLimited)
            {
                retry = ParseRetryAfter(HeaderLookup.First(fetch.Headers, "Retry-After"), time);
            }
        }

        return new KeyFetchResult(outcome, fetch.Reason, fetch.FinalUri, fetch, default, retry);
    }

    // RFC 9110 §10.2.3: a number of seconds or an HTTP date. A hostile value cannot make the client wait longer than a day.
    private static TimeSpan? ParseRetryAfter(string? value, TimeProvider time)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        TimeSpan cap = TimeSpan.FromDays(1);
        if (long.TryParse(value.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long seconds))
        {
            return seconds >= cap.TotalSeconds ? cap : TimeSpan.FromSeconds(seconds);
        }

        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset at))
        {
            TimeSpan wait = at - time.GetUtcNow();
            return wait < TimeSpan.Zero ? TimeSpan.Zero : wait > cap ? cap : wait;
        }

        return null;
    }
}
