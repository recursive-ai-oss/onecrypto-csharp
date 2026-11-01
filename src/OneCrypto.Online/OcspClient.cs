using System.Security.Cryptography;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>How an OCSP query ended.</summary>
public enum OcspOutcome
{
    /// <summary>The responder gave a successful basic response that answers for the certificate asked about. Whether its signature and signer are acceptable is for <see cref="Validation.PathValidator"/>; the client does not decide trust.</summary>
    Answered = 0,

    /// <summary>The responder answered with an error status (malformed request, internal error, try later, signature required, unauthorized; RFC 6960 §2.3).</summary>
    ResponderError = 1,

    /// <summary>The request got no answer; <see cref="OcspQueryResult.Fetch"/> has the reason.</summary>
    FetchFailed = 2,

    /// <summary>The body is not an OCSP response.</summary>
    MalformedResponse = 3,

    /// <summary>A successful response of a type other than <c>id-pkix-ocsp-basic</c>.</summary>
    UnsupportedResponseType = 4,

    /// <summary>The response does not contain an answer for the certificate asked about.</summary>
    CertIdMismatch = 5,

    /// <summary>The response carries a nonce that is not the one sent (RFC 8954 §2.2), or none when one was required.</summary>
    NonceMismatch = 6,

    /// <summary>The certificate names no OCSP responder and the caller gave none.</summary>
    NoResponder = 7,
}

/// <summary>What happened to the nonce (RFC 8954).</summary>
public enum OcspNonceStatus
{
    /// <summary>No nonce was sent.</summary>
    NotSent = 0,

    /// <summary>The response echoed the nonce.</summary>
    Matched = 1,

    /// <summary>The response has no nonce although one was sent; allowed unless <see cref="OcspQueryOptions.RequireNonce"/>.</summary>
    Missing = 2,

    /// <summary>The response has a different nonce.</summary>
    Mismatched = 3,
}

/// <summary>How the request travels.</summary>
public enum OcspHttpMethod
{
    /// <summary>GET when the request is small and has no nonce (RFC 5019 §5, which caches can serve), POST otherwise; a GET that gets an HTTP error is repeated as POST.</summary>
    Auto = 0,

    /// <summary>POST of <c>application/ocsp-request</c> (RFC 6960 Appendix A.1).</summary>
    Post = 1,

    /// <summary>GET of the Base64 request appended to the responder URL (RFC 6960 Appendix A.1). A request too long for a URL is sent anyway.</summary>
    Get = 2,
}

/// <summary>Choices for <see cref="OcspClient"/>.</summary>
public sealed class OcspQueryOptions
{
    /// <summary>The responder to ask; null means the first <c>id-ad-ocsp</c> <c>http</c>/<c>https</c> location in the certificate. A responder named here counts as written by the caller; one taken from the certificate gets the address guard.</summary>
    public Uri? ResponderUri { get; init; }

    /// <summary>Where the responder URL came from. Null (default) means <see cref="UrlOrigin.Caller"/> for <see cref="ResponderUri"/> and <see cref="UrlOrigin.Certificate"/> for a location read from the certificate.</summary>
    public UrlOrigin? Origin { get; init; }

    /// <summary>Send a nonce (RFC 8954). Default false: public responders mostly ignore it, and a request without one can be cached and answered from a pre-produced response (RFC 5019).</summary>
    public bool UseNonce { get; init; }

    /// <summary>Fail when a nonce was sent and the response does not echo it (default false, as RFC 8954 §2.2 allows).</summary>
    public bool RequireNonce { get; init; }

    /// <summary>How to send the request (default <see cref="OcspHttpMethod.Auto"/>).</summary>
    public OcspHttpMethod Method { get; init; }

    /// <summary>The hash for the CertID (default SHA-1, which every responder must accept, RFC 6960 §4.3).</summary>
    public HashAlgorithmName? CertIdHash { get; init; }

    /// <summary>The instant a cached response is judged at: it is reused only if <c>thisUpdate</c> is not later and <c>nextUpdate</c> not earlier. Null means the fetcher's clock.</summary>
    public DateTimeOffset? ReferenceTime { get; init; }

    /// <summary>Use and fill the cache (default true; a request with a nonce never is).</summary>
    public bool UseCache { get; init; } = true;

    /// <summary>How long a response without <c>nextUpdate</c> is reused (default seven days, as the validator treats it).</summary>
    public TimeSpan MaxAgeWithoutNextUpdate { get; init; } = TimeSpan.FromDays(7);

    /// <summary>The largest response accepted (default 1 MiB).</summary>
    public long MaxResponseBytes { get; init; } = 1L << 20;
}

/// <summary>What an OCSP query produced.</summary>
public sealed class OcspQueryResult
{
    internal OcspQueryResult(OcspOutcome outcome, string reason, FetchResult? fetch, OcspRequest? request)
    {
        Outcome = outcome;
        Reason = reason;
        Fetch = fetch;
        Request = request;
    }

    /// <summary>How it ended.</summary>
    public OcspOutcome Outcome { get; }

    /// <summary>A sentence saying why, empty when answered.</summary>
    public string Reason { get; }

    /// <summary>The HTTP exchange (null when no request was made).</summary>
    public FetchResult? Fetch { get; }

    /// <summary>The request that was sent.</summary>
    public OcspRequest? Request { get; }

    /// <summary>The outer response, when the body parsed.</summary>
    public OcspResponse? Response { get; internal set; }

    /// <summary>The basic response, when the responder answered successfully.</summary>
    public OcspBasicResponse? Basic { get; internal set; }

    /// <summary>The answer about the certificate asked for, when <see cref="Outcome"/> is <see cref="OcspOutcome.Answered"/>. It is what the responder says; it is not verified.</summary>
    public OcspSingleResponse? Answer { get; internal set; }

    /// <summary>The nonce result.</summary>
    public OcspNonceStatus Nonce { get; internal set; }

    /// <summary>True when the answer came from the cache.</summary>
    public bool FromCache => Fetch?.FromCache == true;
}

/// <summary>
/// An OCSP client (RFC 6960 Appendix A over HTTP, with the GET form of RFC 5019). It builds the request with core's builder, sends it through the
/// <see cref="Fetcher"/>, and checks that the reply is a successful basic response that answers for the certificate asked about and echoes the nonce if one was
/// sent. It does not verify the signature or decide who may sign: give the response to <see cref="Validation.PathValidator"/>, which does.
/// </summary>
public sealed class OcspClient
{
    private readonly Fetcher _fetcher;

    /// <summary>Creates a client.</summary>
    /// <param name="fetcher">The fetcher that carries the requests.</param>
    public OcspClient(Fetcher fetcher)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
    }

    /// <summary>Asks a responder about a certificate.</summary>
    /// <param name="certificate">The certificate whose status is wanted.</param>
    /// <param name="issuer">Its issuer.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async ValueTask<OcspQueryResult> QueryAsync(Certificate certificate, Certificate issuer, OcspQueryOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);
        options ??= new OcspQueryOptions();
        UrlOrigin origin = options.Origin ?? (options.ResponderUri is null ? UrlOrigin.Certificate : UrlOrigin.Caller);
        Uri? responder = options.ResponderUri ?? ResponderFrom(certificate);
        if (responder is null)
        {
            return new OcspQueryResult(OcspOutcome.NoResponder, "the certificate names no http or https OCSP responder", null, null);
        }

        OcspCertId id = OcspCertId.Create(certificate, issuer, options.CertIdHash);
        OcspRequest request = OcspRequestBuilder.Create(new OcspRequestOptions
        {
            Requests = [id],
            Nonce = options.UseNonce ? RandomNumberGenerator.GetBytes(32) : default,
        });

        bool cache = options.UseCache && !options.UseNonce;
        DateTimeOffset at = options.ReferenceTime ?? _fetcher.Options.Time.GetUtcNow();
        Func<ReadOnlyMemory<byte>, bool> reusable = body => CoversAt(body, id, at, options.MaxAgeWithoutNextUpdate);

        bool get = options.Method == OcspHttpMethod.Get || (options.Method == OcspHttpMethod.Auto && !options.UseNonce && request.Encoded.Length <= 255);
        FetchResult? fetch = null;
        if (get)
        {
            fetch = await _fetcher.FetchAsync(new FetchRequest
            {
                Uri = GetUri(responder, request.Encoded.Span),
                Origin = origin,
                Headers = [new("Accept", "application/ocsp-response")],
                Cache = cache ? FetchCacheMode.Http : FetchCacheMode.None,
                IsReusable = reusable,
                MaxResponseBytes = options.MaxResponseBytes,
            }, cancellationToken).ConfigureAwait(false);
            if (options.Method == OcspHttpMethod.Auto && fetch.Outcome == FetchOutcome.HttpStatus)
            {
                // Not every responder serves GET; RFC 6960 requires POST, so ask again that way.
                fetch = null;
            }
        }

        if (fetch is null)
        {
            fetch = await _fetcher.FetchAsync(new FetchRequest
            {
                Uri = responder,
                Method = "POST",
                Body = request.Encoded,
                Origin = origin,
                Headers = [new("Content-Type", "application/ocsp-request"), new("Accept", "application/ocsp-response")],
                Cache = cache ? FetchCacheMode.Content : FetchCacheMode.None,
                IsReusable = reusable,
                MaxResponseBytes = options.MaxResponseBytes,
            }, cancellationToken).ConfigureAwait(false);
        }

        return Interpret(request, id, fetch, options);
    }

    /// <summary>Checks the HTTP answer against the request. Public so a caller with its own transport can reuse the checks.</summary>
    /// <param name="request">The request that was sent.</param>
    /// <param name="certId">The CertID it asked about.</param>
    /// <param name="fetch">What came back.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    public static OcspQueryResult Interpret(OcspRequest request, OcspCertId certId, FetchResult fetch, OcspQueryOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(certId);
        ArgumentNullException.ThrowIfNull(fetch);
        if (!fetch.IsSuccess)
        {
            return new OcspQueryResult(OcspOutcome.FetchFailed, fetch.Reason, fetch, request);
        }

        if (!OcspResponse.TryParse(fetch.Body, out OcspResponse? response) || response is null)
        {
            return new OcspQueryResult(OcspOutcome.MalformedResponse, "the body is not an OCSP response", fetch, request);
        }

        if (response.Status != OcspResponseStatus.Successful)
        {
            return new OcspQueryResult(OcspOutcome.ResponderError, $"the responder answered {response.Status} (RFC 6960 §2.3)", fetch, request) { Response = response };
        }

        if (response.ResponseType != KnownOids.OcspBasic)
        {
            return new OcspQueryResult(OcspOutcome.UnsupportedResponseType, $"the response type {response.ResponseType} is not id-pkix-ocsp-basic", fetch, request) { Response = response };
        }

        // The inner structures decode lazily over the received bytes, so a malformed one surfaces here, on first use.
        OcspBasicResponse? basic;
        OcspSingleResponse? single;
        ReadOnlyMemory<byte>? sent = request.Nonce;
        ReadOnlyMemory<byte>? got;
        try
        {
            basic = response.BasicResponse;
            single = basic?.Responses.FirstOrDefault(s => s.CertId.Equals(certId));
            got = basic?.Nonce;
        }
        catch (X509ParseException ex)
        {
            return new OcspQueryResult(OcspOutcome.MalformedResponse, "the basic response is malformed: " + ex.Message, fetch, request) { Response = response };
        }

        if (basic is null)
        {
            return new OcspQueryResult(OcspOutcome.MalformedResponse, "the basic response is malformed", fetch, request) { Response = response };
        }

        var result = new OcspQueryResult(OcspOutcome.Answered, string.Empty, fetch, request) { Response = response, Basic = basic };
        if (sent is null)
        {
            result.Nonce = OcspNonceStatus.NotSent;
        }
        else if (got is null)
        {
            result.Nonce = OcspNonceStatus.Missing;
        }
        else
        {
            result.Nonce = got.Value.Span.SequenceEqual(sent.Value.Span) ? OcspNonceStatus.Matched : OcspNonceStatus.Mismatched;
        }

        if (result.Nonce == OcspNonceStatus.Mismatched || (result.Nonce == OcspNonceStatus.Missing && options?.RequireNonce == true))
        {
            return Rebuild(result, OcspOutcome.NonceMismatch, result.Nonce == OcspNonceStatus.Missing ? "the response does not echo the nonce (RFC 8954 §2.2)" : "the response carries a different nonce (RFC 8954 §2.2)");
        }

        if (single is null)
        {
            return Rebuild(result, OcspOutcome.CertIdMismatch, "the response has no answer for the certificate asked about (RFC 6960 §4.2.2.3)");
        }

        result.Answer = single;
        return result;
    }

    private static OcspQueryResult Rebuild(OcspQueryResult from, OcspOutcome outcome, string reason) =>
        new(outcome, reason, from.Fetch, from.Request) { Response = from.Response, Basic = from.Basic, Nonce = from.Nonce };

    /// <summary>The first http(s) OCSP location of a certificate.</summary>
    internal static Uri? ResponderFrom(Certificate certificate)
    {
        try
        {
            foreach (string s in certificate.Extensions.Get<AuthorityInfoAccess>()?.UrisFor(KnownOids.AdOcsp) ?? [])
            {
                if (Uri.TryCreate(s, UriKind.Absolute, out Uri? u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
                {
                    return u;
                }
            }
        }
        catch (X509ParseException)
        {
            // A certificate with a malformed authorityInfoAccess names no responder.
        }

        return null;
    }

    /// <summary>RFC 6960 Appendix A.1: the responder URL, a slash, and the percent-encoded Base64 of the DER request.</summary>
    internal static Uri GetUri(Uri responder, ReadOnlySpan<byte> request)
    {
        string b = responder.AbsoluteUri;
        string path = b.EndsWith('/') ? b : b + "/";
        return new Uri(path + Uri.EscapeDataString(Convert.ToBase64String(request)));
    }

    /// <summary>Whether a stored response answers for the certificate at the instant <paramref name="at"/> (RFC 6960 §4.2.2.1 thisUpdate / nextUpdate).</summary>
    internal static bool CoversAt(ReadOnlyMemory<byte> body, OcspCertId id, DateTimeOffset at, TimeSpan maxAgeWithoutNext)
    {
        if (!OcspResponse.TryParse(body, out OcspResponse? r) || r is null || r.Status != OcspResponseStatus.Successful)
        {
            return false;
        }

        try
        {
            OcspSingleResponse? s = r.BasicResponse?.Responses.FirstOrDefault(x => x.CertId.Equals(id));
            return s is not null && s.ThisUpdate <= at && at <= (s.NextUpdate ?? s.ThisUpdate + maxAgeWithoutNext);
        }
        catch (X509ParseException)
        {
            return false;
        }
    }
}
