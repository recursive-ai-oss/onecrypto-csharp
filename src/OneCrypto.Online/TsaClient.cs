using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Tsp;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>How a time-stamp request ended.</summary>
public enum TimestampOutcome
{
    /// <summary>The authority granted the request and every check of <see cref="TimeStampVerifier"/> passed (nonce, imprint, token structure and signature, algorithm policy; trust only if anchors were supplied).</summary>
    Granted = 0,

    /// <summary>The authority answered with a rejection status (RFC 3161 §2.4.2); <see cref="TimestampResult.Response"/> says which.</summary>
    Rejected = 1,

    /// <summary>The authority answered, but the token fails a check (imprint, nonce, requested policy, signature, algorithm policy); <see cref="TimestampResult.Report"/> lists them.</summary>
    InvalidToken = 2,

    /// <summary>The body was not a time-stamp response at all.</summary>
    MalformedResponse = 3,

    /// <summary>The request never got an answer; <see cref="TimestampResult.Fetch"/> has the reason.</summary>
    FetchFailed = 4,
}

/// <summary>Choices for <see cref="TsaClient"/>.</summary>
public sealed class TimestampRequestOptions
{
    /// <summary>The policy to ask for (<c>reqPolicy</c>), an object identifier; null lets the authority choose.</summary>
    public string? Policy { get; init; }

    /// <summary>Send a nonce (default true; RFC 3161 §2.4.1 recommends it, and without one a replayed old response would pass).</summary>
    public bool UseNonce { get; init; } = true;

    /// <summary>A fixed nonce to send instead of a random one, so a recorded exchange can be replayed. Never reuse one against a real authority: a repeated nonce lets an old response pass for a new one. Ignored when <see cref="UseNonce"/> is false.</summary>
    public ReadOnlyMemory<byte> Nonce { get; init; }

    /// <summary>Ask for the authority's certificate in the token (default true).</summary>
    public bool CertReq { get; init; } = true;

    /// <summary>How the response is checked: policy, trust anchors, extra certificates, reference time. Null means the defaults of <see cref="TimeStampVerifier"/>.</summary>
    public TimeStampVerifyOptions? Verify { get; init; }

    /// <summary>Extra request headers, for example an API key some authorities require. They are dropped if a redirect leaves the host.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; } = [];

    /// <summary>Where the URL came from (default <see cref="UrlOrigin.Caller"/>).</summary>
    public UrlOrigin Origin { get; init; }
}

/// <summary>What asking an authority for a time-stamp produced.</summary>
public sealed class TimestampResult
{
    internal TimestampResult(TimestampOutcome outcome, string reason, TimeStampRequest? request, FetchResult fetch, TimeStampResponse? response, TimeStampReport? report, bool contentTypeMatched)
    {
        Outcome = outcome;
        Reason = reason;
        Request = request;
        Fetch = fetch;
        Response = response;
        Report = report;
        ContentTypeMatched = contentTypeMatched;
    }

    /// <summary>How it ended.</summary>
    public TimestampOutcome Outcome { get; }

    /// <summary>A sentence saying why, empty when granted.</summary>
    public string Reason { get; }

    /// <summary>The request that was sent (null if it could not be built).</summary>
    public TimeStampRequest? Request { get; }

    /// <summary>The HTTP exchange.</summary>
    public FetchResult Fetch { get; }

    /// <summary>The parsed response, when the body parsed.</summary>
    public TimeStampResponse? Response { get; }

    /// <summary>The per-rule check of the response against the request.</summary>
    public TimeStampReport? Report { get; }

    /// <summary>True when the reply came with <c>Content-Type: application/timestamp-reply</c> (RFC 3161 §3.4). A different type is reported here and not treated as an error, because the DER decides, and some authorities label it wrongly.</summary>
    public bool ContentTypeMatched { get; }

    /// <summary>True when <see cref="Outcome"/> is <see cref="TimestampOutcome.Granted"/>.</summary>
    public bool IsGranted => Outcome == TimestampOutcome.Granted;

    /// <summary>The time-stamp token (a CMS ContentInfo) to embed in a signature, when granted.</summary>
    public ReadOnlyMemory<byte> Token => IsGranted && Response is not null ? Response.TokenEncoded : default;
}

/// <summary>
/// An RFC 3161 time-stamp client over HTTP (§3.4: POST of the <c>application/timestamp-query</c> request, <c>application/timestamp-reply</c> back). The answer is checked
/// with core's <see cref="TimeStampVerifier"/> against the request that was sent: nonce, message imprint, token signature, algorithm policy and, when trust anchors are
/// given, the authority's certificate chain at the token's time.
/// </summary>
public sealed class TsaClient
{
    private readonly Fetcher _fetcher;
    private readonly Uri? _authority;
    private readonly TimestampRequestOptions? _options;

    /// <summary>Creates a client.</summary>
    /// <param name="fetcher">The fetcher that carries the requests.</param>
    public TsaClient(Fetcher fetcher)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
    }

    /// <summary>
    /// Creates a client bound to one authority, so that <see cref="GetTimestampAsync"/> can be handed to code that wants a time-stamp function
    /// (for example <c>PadesSignOptions.Timestamp</c> in the <c>.Pdf</c> package) without a wrapper.
    /// </summary>
    /// <param name="fetcher">The fetcher that carries the requests.</param>
    /// <param name="authority">The authority's URL.</param>
    /// <param name="options">Headers and URL origin for the requests; the request itself comes from the caller of <see cref="GetTimestampAsync"/>. Null for the defaults.</param>
    public TsaClient(Fetcher fetcher, Uri authority, TimestampRequestOptions? options = null)
        : this(fetcher)
    {
        _authority = authority ?? throw new ArgumentNullException(nameof(authority));
        _options = options;
    }

    /// <summary>The authority this client is bound to, or null for a client made with <see cref="TsaClient(Fetcher)"/>.</summary>
    public Uri? Authority => _authority;

    /// <summary>
    /// Sends a time-stamp request the caller built to the bound authority and returns the DER of its answer, ready to be embedded or checked by the caller.
    /// The signature fits <c>PadesTimestampFunction</c>, so <c>Timestamp = tsa.GetTimestampAsync</c> needs no hand-written HTTP.
    /// </summary>
    /// <remarks>
    /// The answer is returned as received when the authority replied at all, including a rejection: the caller checks it against its request (the PDF bridge
    /// does, and reports the reason). Use <see cref="StampAsync"/> when you want this client to run the checks and classify the outcome.
    /// </remarks>
    /// <param name="request">The request; it is sent as built, with its nonce and imprint.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The body of the reply.</returns>
    /// <exception cref="InvalidOperationException">The client was made without an authority.</exception>
    /// <exception cref="TransportException">The request got no answer (network failure, blocked address, size or redirect limit, non-success status); the message has the reason.</exception>
    public async ValueTask<byte[]> GetTimestampAsync(TimeStampRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        Uri authority = _authority ?? throw new InvalidOperationException("This TsaClient has no authority. Create it with TsaClient(fetcher, authority) to use GetTimestampAsync.");
        TimestampRequestOptions options = _options ?? new TimestampRequestOptions();
        var headers = new List<KeyValuePair<string, string>>
        {
            new("Content-Type", "application/timestamp-query"),
            new("Accept", "application/timestamp-reply"),
        };
        headers.AddRange(options.Headers);
        FetchResult fetch = await _fetcher.FetchAsync(new FetchRequest
        {
            Uri = authority,
            Method = "POST",
            Body = request.Encoded,
            Headers = headers,
            Origin = options.Origin,
            MaxResponseBytes = 1L << 20,
        }, cancellationToken).ConfigureAwait(false);
        if (!fetch.IsSuccess)
        {
            throw new TransportException($"The time-stamp request to {authority} failed: {fetch.Reason}");
        }

        return fetch.Body.ToArray();
    }

    /// <summary>Time-stamps a message by hashing it first.</summary>
    /// <param name="authority">The authority's URL.</param>
    /// <param name="data">The data to stamp.</param>
    /// <param name="hash">The hash algorithm (SHA-256, SHA-384 or SHA-512).</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public ValueTask<TimestampResult> StampAsync(Uri authority, ReadOnlyMemory<byte> data, HashAlgorithmName hash, TimestampRequestOptions? options = null, CancellationToken cancellationToken = default) =>
        StampDigestAsync(authority, HashData(hash, data.Span), hash, options, cancellationToken);

    /// <summary>Time-stamps a digest the caller computed.</summary>
    /// <param name="authority">The authority's URL.</param>
    /// <param name="digest">The message imprint.</param>
    /// <param name="hash">The algorithm that made it.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async ValueTask<TimestampResult> StampDigestAsync(Uri authority, ReadOnlyMemory<byte> digest, HashAlgorithmName hash, TimestampRequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        options ??= new TimestampRequestOptions();
        TimeStampRequest request = TimeStampRequest.Create(new TimeStampRequestOptions
        {
            Hash = hash,
            MessageImprint = digest,
            Policy = options.Policy,
            Nonce = !options.UseNonce ? default : options.Nonce.IsEmpty ? TimeStampRequest.NewNonce() : options.Nonce,
            CertReq = options.CertReq,
        });

        var headers = new List<KeyValuePair<string, string>>
        {
            new("Content-Type", "application/timestamp-query"),
            new("Accept", "application/timestamp-reply"),
        };
        headers.AddRange(options.Headers);
        FetchResult fetch = await _fetcher.FetchAsync(new FetchRequest
        {
            Uri = authority,
            Method = "POST",
            Body = request.Encoded,
            Headers = headers,
            Origin = options.Origin,
            MaxResponseBytes = 1L << 20,
        }, cancellationToken).ConfigureAwait(false);
        return Interpret(request, fetch, options);
    }

    /// <summary>Turns the HTTP answer into a result. Public so a caller with its own transport can reuse the checks.</summary>
    /// <param name="request">The request that was sent.</param>
    /// <param name="fetch">What came back.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    public static TimestampResult Interpret(TimeStampRequest request, FetchResult fetch, TimestampRequestOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(fetch);
        if (!fetch.IsSuccess)
        {
            return new TimestampResult(TimestampOutcome.FetchFailed, fetch.Reason, request, fetch, null, null, false);
        }

        bool typeOk = fetch.ContentType == "application/timestamp-reply";
        if (!TimeStampResponse.TryParse(fetch.Body, out TimeStampResponse? response) || response is null)
        {
            // Some authorities answer with a bare token; the verifier accepts that form and says so in its report.
            TimeStampReport bare = TimeStampVerifier.Verify(request, fetch.Body, options?.Verify);
            return bare.Response is null && bare.Token is null
                ? new TimestampResult(TimestampOutcome.MalformedResponse, "the body is not a time-stamp response", request, fetch, null, bare, typeOk)
                : Classify(request, fetch, bare, typeOk);
        }

        return Classify(request, fetch, TimeStampVerifier.Verify(request, fetch.Body, options?.Verify), typeOk);
    }

    private static TimestampResult Classify(TimeStampRequest request, FetchResult fetch, TimeStampReport report, bool typeOk)
    {
        TimeStampResponse? response = report.Response;
        if (response is not null && !response.IsGranted)
        {
            string strings = response.StatusStrings.Count > 0 ? ": " + string.Join("; ", response.StatusStrings) : string.Empty;
            return new TimestampResult(TimestampOutcome.Rejected, $"the authority answered {response.Status} (failure info {response.FailureInfo}){strings}", request, fetch, response, report, typeOk);
        }

        if (!report.IsValid)
        {
            CmsFirstFailure(report, out string why);
            return new TimestampResult(TimestampOutcome.InvalidToken, why, request, fetch, response, report, typeOk);
        }

        return new TimestampResult(TimestampOutcome.Granted, string.Empty, request, fetch, response, report, typeOk);
    }

    private static void CmsFirstFailure(TimeStampReport report, out string why)
    {
        foreach (var c in report.Checks)
        {
            if (c.Status is RecursiveAI.OneCrypto.CmsCheckStatus.Failed or RecursiveAI.OneCrypto.CmsCheckStatus.Unsupported)
            {
                why = $"{c.Rule}: {c.Reason}";
                return;
            }
        }

        why = "the token failed a check";
    }

    private static byte[] HashData(HashAlgorithmName hash, ReadOnlySpan<byte> data)
    {
        if (hash == HashAlgorithmName.SHA256)
        {
            return SHA256.HashData(data);
        }

        if (hash == HashAlgorithmName.SHA384)
        {
            return SHA384.HashData(data);
        }

        if (hash == HashAlgorithmName.SHA512)
        {
            return SHA512.HashData(data);
        }

        throw new ArgumentException($"{hash.Name} is not a hash a time-stamp request can name", nameof(hash));
    }
}
