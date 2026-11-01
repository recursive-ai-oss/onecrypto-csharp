using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>How fetching one CRL ended.</summary>
public enum CrlOutcome
{
    /// <summary>A CRL was fetched and parsed.</summary>
    Fetched = 0,

    /// <summary>The fetch failed; <see cref="CrlFetchResult.Fetch"/> has the reason.</summary>
    FetchFailed = 1,

    /// <summary>The body is not a CRL (DER or PEM).</summary>
    Malformed = 2,

    /// <summary>The location is not an <c>http</c> or <c>https</c> URL (LDAP and FTP are not fetched).</summary>
    SchemeNotSupported = 3,
}

/// <summary>Whether a CRL is current at the reference time (RFC 5280 §5.1.2.4, §5.1.2.5).</summary>
public enum CrlCurrency
{
    /// <summary><c>thisUpdate</c> is not after the time and <c>nextUpdate</c> is not before it.</summary>
    Current = 0,

    /// <summary><c>thisUpdate</c> is after the time.</summary>
    NotYetValid = 1,

    /// <summary><c>nextUpdate</c> is before the time.</summary>
    Expired = 2,

    /// <summary>The CRL has no <c>nextUpdate</c>, which RFC 5280 requires of conforming issuers.</summary>
    NoNextUpdate = 3,
}

/// <summary>Choices for <see cref="CrlClient"/>.</summary>
public sealed class CrlFetchOptions
{
    /// <summary>The instant the CRL's validity is judged at (also decides whether a cached copy is reused). Null means the fetcher's clock.</summary>
    public DateTimeOffset? ReferenceTime { get; init; }

    /// <summary>Use and fill the cache (default true). A cached CRL is reused only while HTTP freshness allows and it is current at <see cref="ReferenceTime"/>.</summary>
    public bool UseCache { get; init; } = true;

    /// <summary>Use a stored CRL that is still current when the server cannot be reached (default true; a CRL is valid until its <c>nextUpdate</c> whether or not the server is up).</summary>
    public bool ServeStaleOnError { get; init; } = true;

    /// <summary>The largest CRL accepted (default 32 MiB).</summary>
    public long MaxResponseBytes { get; init; } = 32L << 20;

    /// <summary>Also fetch delta CRLs named by <c>freshestCRL</c> (RFC 5280 §5.2.6; default true).</summary>
    public bool FetchDeltas { get; init; } = true;

    /// <summary>The most locations tried per certificate (default 8).</summary>
    public int MaxLocations { get; init; } = 8;

    /// <summary>Where the URL came from (default <see cref="UrlOrigin.Certificate"/>, the address guard on). Set to <see cref="UrlOrigin.Caller"/> for a CRL address you wrote yourself.</summary>
    public UrlOrigin Origin { get; init; } = UrlOrigin.Certificate;
}

/// <summary>One fetched CRL and how it went.</summary>
public sealed class CrlFetchResult
{
    internal CrlFetchResult(Uri uri, CrlOutcome outcome, string reason, FetchResult? fetch, CertificateRevocationList? crl, CrlCurrency currency)
    {
        Uri = uri;
        Outcome = outcome;
        Reason = reason;
        Fetch = fetch;
        Crl = crl;
        Currency = currency;
    }

    /// <summary>The location tried.</summary>
    public Uri Uri { get; }

    /// <summary>How it ended.</summary>
    public CrlOutcome Outcome { get; }

    /// <summary>A sentence saying why, empty on success.</summary>
    public string Reason { get; }

    /// <summary>The HTTP exchange (null when nothing was fetched).</summary>
    public FetchResult? Fetch { get; }

    /// <summary>The CRL, when fetched. Its signature is not checked here; the validator does that.</summary>
    public CertificateRevocationList? Crl { get; }

    /// <summary>Whether the CRL is current at the reference time.</summary>
    public CrlCurrency Currency { get; }
}

/// <summary>A CRL client: fetches CRLs from the locations a certificate names (RFC 5280 §4.2.1.13) and the delta CRLs its <c>freshestCRL</c> names (§5.2.6).</summary>
public sealed class CrlClient
{
    private readonly Fetcher _fetcher;

    /// <summary>Creates a client.</summary>
    /// <param name="fetcher">The fetcher that carries the requests.</param>
    public CrlClient(Fetcher fetcher)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
    }

    /// <summary>Fetches one CRL.</summary>
    /// <param name="location">The URL.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async ValueTask<CrlFetchResult> FetchAsync(Uri location, CrlFetchOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(location);
        options ??= new CrlFetchOptions();
        if (location.Scheme != Uri.UriSchemeHttp && location.Scheme != Uri.UriSchemeHttps)
        {
            return new CrlFetchResult(location, CrlOutcome.SchemeNotSupported, $"{location.Scheme} locations are not fetched", null, null, CrlCurrency.Current);
        }

        DateTimeOffset at = options.ReferenceTime ?? _fetcher.Options.Time.GetUtcNow();
        FetchResult fetch = await _fetcher.FetchAsync(new FetchRequest
        {
            Uri = location,
            Origin = options.Origin,
            Headers = [new("Accept", "application/pkix-crl")],
            Cache = options.UseCache ? FetchCacheMode.Http : FetchCacheMode.None,
            IsReusable = body => TryParse(body.Span, out CertificateRevocationList? c) && c is not null && CurrencyAt(c, at) == CrlCurrency.Current,
            ServeStaleOnError = options.ServeStaleOnError,
            MaxResponseBytes = options.MaxResponseBytes,
        }, cancellationToken).ConfigureAwait(false);
        return Interpret(location, fetch, at);
    }

    /// <summary>Fetches the complete CRLs and delta CRLs for a certificate: its distribution points, then the <c>freshestCRL</c> locations of the certificate and of each complete CRL.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the requests.</param>
    /// <returns>Every attempt, complete CRLs first.</returns>
    public async ValueTask<IReadOnlyList<CrlFetchResult>> FetchForAsync(Certificate certificate, CrlFetchOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        options ??= new CrlFetchOptions();
        IEnumerable<string> complete;
        IEnumerable<string> deltas;
        try
        {
            complete = [.. DistributionUris(certificate.Extensions.Get<CrlDistributionPoints>()?.Points)];
            deltas = [.. DeltaUris(certificate)];
        }
        catch (X509ParseException)
        {
            return [];
        }

        return await FetchSetAsync(complete, deltas, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Fetches the complete CRLs at the given locations and then the delta CRLs the certificate and those CRLs name.</summary>
    /// <param name="locations">The <c>cRLDistributionPoints</c> locations.</param>
    /// <param name="certificate">The certificate whose <c>freshestCRL</c> names more locations.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the requests.</param>
    public async ValueTask<IReadOnlyList<CrlFetchResult>> FetchForAsync(IEnumerable<string> locations, Certificate certificate, CrlFetchOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(locations);
        ArgumentNullException.ThrowIfNull(certificate);
        options ??= new CrlFetchOptions();
        IEnumerable<string> deltas;
        try
        {
            deltas = [.. DeltaUris(certificate)];
        }
        catch (X509ParseException)
        {
            deltas = [];
        }

        return await FetchSetAsync(locations, deltas, options, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<IReadOnlyList<CrlFetchResult>> FetchSetAsync(IEnumerable<string> complete, IEnumerable<string> certificateDeltas, CrlFetchOptions options, CancellationToken cancellationToken)
    {
        var results = new List<CrlFetchResult>();
        var tried = new HashSet<string>(StringComparer.Ordinal);
        var deltas = new List<string>(certificateDeltas);
        foreach (string s in complete.Take(options.MaxLocations))
        {
            if (!Uri.TryCreate(s, UriKind.Absolute, out Uri? u) || !tried.Add(u.AbsoluteUri))
            {
                continue;
            }

            CrlFetchResult r = await FetchAsync(u, options, cancellationToken).ConfigureAwait(false);
            results.Add(r);
            if (r.Crl is { IsDelta: false } crl && crl.Extensions.Get<FreshestCrl>() is { } f)
            {
                deltas.AddRange(DistributionUris(f.Points));
            }
        }

        if (options.FetchDeltas)
        {
            foreach (string s in deltas.Take(options.MaxLocations))
            {
                if (!Uri.TryCreate(s, UriKind.Absolute, out Uri? u) || !tried.Add(u.AbsoluteUri))
                {
                    continue;
                }

                CrlFetchResult r = await FetchAsync(u, options, cancellationToken).ConfigureAwait(false);
                results.Add(r);
            }
        }

        return results;
    }

    /// <summary>Turns the HTTP answer into a result. Public so a caller with its own transport can reuse the checks.</summary>
    /// <param name="location">The URL asked.</param>
    /// <param name="fetch">What came back.</param>
    /// <param name="at">The reference time.</param>
    public static CrlFetchResult Interpret(Uri location, FetchResult fetch, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(fetch);
        if (!fetch.IsSuccess)
        {
            return new CrlFetchResult(location, CrlOutcome.FetchFailed, fetch.Reason, fetch, null, CrlCurrency.Current);
        }

        if (!TryParse(fetch.Body.Span, out CertificateRevocationList? crl) || crl is null)
        {
            return new CrlFetchResult(location, CrlOutcome.Malformed, "the body is not a CRL", fetch, null, CrlCurrency.Current);
        }

        return new CrlFetchResult(location, CrlOutcome.Fetched, string.Empty, fetch, crl, CurrencyAt(crl, at));
    }

    internal static CrlCurrency CurrencyAt(CertificateRevocationList crl, DateTimeOffset at)
    {
        if (crl.ThisUpdate > at)
        {
            return CrlCurrency.NotYetValid;
        }

        if (crl.NextUpdate is not { } next)
        {
            return CrlCurrency.NoNextUpdate;
        }

        return next < at ? CrlCurrency.Expired : CrlCurrency.Current;
    }

    /// <summary>Accepts a DER CRL, or a PEM one (some servers publish that).</summary>
    internal static bool TryParse(ReadOnlySpan<byte> body, out CertificateRevocationList? crl)
    {
        if (CertificateRevocationList.TryParse(body.ToArray(), out crl))
        {
            return ExtensionsDecode(ref crl);
        }

        if (body.Length > 10 && body[0] == (byte)'-' && body.Length < (64 << 20))
        {
            try
            {
                crl = CertificateRevocationList.FromPem(System.Text.Encoding.ASCII.GetString(body));
                return ExtensionsDecode(ref crl);
            }
            catch (Exception ex) when (ex is FormatException)
            {
                crl = null;
                return false;
            }
        }

        crl = null;
        return false;
    }

    /// <summary>Extensions decode lazily; a list whose extensions are malformed is rejected here rather than when the validator first asks for one.</summary>
    private static bool ExtensionsDecode(ref CertificateRevocationList? crl)
    {
        try
        {
            _ = crl!.Extensions;
            return true;
        }
        catch (X509ParseException)
        {
            crl = null;
            return false;
        }
    }

    private static IEnumerable<string> DistributionUris(IEnumerable<DistributionPoint>? points) =>
        points?.Select(p => p.Name?.FullName).Where(n => n is not null).SelectMany(n => n!).Where(n => n.Kind == GeneralNameKind.Uri).Select(n => n.Value!) ?? [];

    private static IEnumerable<string> DeltaUris(Certificate certificate) => DistributionUris(certificate.Extensions.Get<FreshestCrl>()?.Points);
}
