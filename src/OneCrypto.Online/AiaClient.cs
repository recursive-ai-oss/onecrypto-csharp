using System.Text;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>How fetching one caIssuers location ended.</summary>
public enum AiaOutcome
{
    /// <summary>At least one certificate was read.</summary>
    Fetched = 0,

    /// <summary>The fetch failed; <see cref="AiaFetchResult.Fetch"/> has the reason.</summary>
    FetchFailed = 1,

    /// <summary>The body is neither a certificate, a PEM certificate, nor a certs-only CMS message.</summary>
    Malformed = 2,

    /// <summary>The location is not an <c>http</c> or <c>https</c> URL.</summary>
    SchemeNotSupported = 3,
}

/// <summary>One caIssuers location and what it gave.</summary>
public sealed class AiaFetchResult
{
    internal AiaFetchResult(Uri uri, AiaOutcome outcome, string reason, FetchResult? fetch, IReadOnlyList<Certificate> certificates)
    {
        Uri = uri;
        Outcome = outcome;
        Reason = reason;
        Fetch = fetch;
        Certificates = certificates;
    }

    /// <summary>The location tried.</summary>
    public Uri Uri { get; }

    /// <summary>How it ended.</summary>
    public AiaOutcome Outcome { get; }

    /// <summary>A sentence saying why, empty on success.</summary>
    public string Reason { get; }

    /// <summary>The HTTP exchange.</summary>
    public FetchResult? Fetch { get; }

    /// <summary>The certificates found, in the order received.</summary>
    public IReadOnlyList<Certificate> Certificates { get; }
}

/// <summary>Choices for <see cref="AiaClient"/>.</summary>
public sealed class AiaFetchOptions
{
    /// <summary>The most locations tried per certificate (default 4).</summary>
    public int MaxLocations { get; init; } = 4;

    /// <summary>The most certificates taken from one response (default 32).</summary>
    public int MaxCertificatesPerResponse { get; init; } = 32;

    /// <summary>The largest response accepted (default 1 MiB).</summary>
    public long MaxResponseBytes { get; init; } = 1L << 20;

    /// <summary>Use and fill the cache (default true; issuer certificates are usually cacheable for a long time).</summary>
    public bool UseCache { get; init; } = true;

    /// <summary>Where the URL came from (default <see cref="UrlOrigin.Certificate"/>, the address guard on).</summary>
    public UrlOrigin Origin { get; init; } = UrlOrigin.Certificate;
}

/// <summary>
/// Fetches the certificates behind an <c>authorityInfoAccess</c> <c>caIssuers</c> location (RFC 5280 §4.2.2.1): a single DER certificate, a PEM certificate, or a
/// certs-only CMS message (<c>application/pkcs7-mime</c>, the "degenerate" SignedData of RFC 5652 §5.1). What comes back is untrusted input for the path builder;
/// nothing is checked here beyond that it parses.
/// </summary>
public sealed class AiaClient
{
    private readonly Fetcher _fetcher;

    /// <summary>Creates a client.</summary>
    /// <param name="fetcher">The fetcher that carries the requests.</param>
    public AiaClient(Fetcher fetcher)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
    }

    /// <summary>Fetches one location.</summary>
    /// <param name="location">The URL.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async ValueTask<AiaFetchResult> FetchAsync(Uri location, AiaFetchOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(location);
        options ??= new AiaFetchOptions();
        if (location.Scheme != Uri.UriSchemeHttp && location.Scheme != Uri.UriSchemeHttps)
        {
            return new AiaFetchResult(location, AiaOutcome.SchemeNotSupported, $"{location.Scheme} locations are not fetched", null, []);
        }

        FetchResult fetch = await _fetcher.FetchAsync(new FetchRequest
        {
            Uri = location,
            Origin = options.Origin,
            Headers = [new("Accept", "application/pkix-cert, application/pkcs7-mime")],
            Cache = options.UseCache ? FetchCacheMode.Http : FetchCacheMode.None,
            MaxResponseBytes = options.MaxResponseBytes,
        }, cancellationToken).ConfigureAwait(false);
        return Interpret(location, fetch, options.MaxCertificatesPerResponse);
    }

    /// <summary>Fetches the caIssuers locations of a certificate.</summary>
    /// <param name="certificate">The certificate that lacks its issuer.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the requests.</param>
    /// <returns>One result per location tried.</returns>
    public ValueTask<IReadOnlyList<AiaFetchResult>> FetchIssuersAsync(Certificate certificate, AiaFetchOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        IEnumerable<string> uris = certificate.Extensions.Get<AuthorityInfoAccess>()?.UrisFor(KnownOids.AdCaIssuers) ?? [];
        return FetchIssuersAsync(uris, options, cancellationToken);
    }

    /// <summary>Fetches the given caIssuers locations.</summary>
    /// <param name="locations">The locations as the certificate names them.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the requests.</param>
    public async ValueTask<IReadOnlyList<AiaFetchResult>> FetchIssuersAsync(IEnumerable<string> locations, AiaFetchOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(locations);
        options ??= new AiaFetchOptions();
        var results = new List<AiaFetchResult>();
        var tried = new HashSet<string>(StringComparer.Ordinal);
        foreach (string s in locations.Take(options.MaxLocations))
        {
            if (Uri.TryCreate(s, UriKind.Absolute, out Uri? u) && tried.Add(u.AbsoluteUri))
            {
                results.Add(await FetchAsync(u, options, cancellationToken).ConfigureAwait(false));
            }
        }

        return results;
    }

    /// <summary>Turns the HTTP answer into a result. Public so a caller with its own transport can reuse the checks.</summary>
    /// <param name="location">The URL asked.</param>
    /// <param name="fetch">What came back.</param>
    /// <param name="maxCertificates">The most certificates to keep.</param>
    public static AiaFetchResult Interpret(Uri location, FetchResult fetch, int maxCertificates = 32)
    {
        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(fetch);
        if (!fetch.IsSuccess)
        {
            return new AiaFetchResult(location, AiaOutcome.FetchFailed, fetch.Reason, fetch, []);
        }

        IReadOnlyList<Certificate> certs = ParseCertificates(fetch.Body, maxCertificates);
        return certs.Count == 0
            ? new AiaFetchResult(location, AiaOutcome.Malformed, "the body holds no certificate", fetch, [])
            : new AiaFetchResult(location, AiaOutcome.Fetched, string.Empty, fetch, certs);
    }

    /// <summary>Reads certificates from a DER certificate, a PEM text, or a CMS SignedData with no content.</summary>
    internal static IReadOnlyList<Certificate> ParseCertificates(ReadOnlyMemory<byte> body, int max)
    {
        if (Certificate.TryParse(body, out Certificate? one) && one is not null)
        {
            return [one];
        }

        if (SignedData.TryParse(body, out SignedData? sd) && sd is not null)
        {
            return [.. sd.Certificates.Take(max)];
        }

        if (body.Length > 10 && body.Span[0] == (byte)'-')
        {
            var found = new List<Certificate>();
            try
            {
                string text = Encoding.ASCII.GetString(body.Span);
                int from = 0;
                while (found.Count < max)
                {
                    int begin = text.IndexOf("-----BEGIN ", from, StringComparison.Ordinal);
                    if (begin < 0)
                    {
                        break;
                    }

                    int end = text.IndexOf("-----END ", begin, StringComparison.Ordinal);
                    int close = end < 0 ? -1 : text.IndexOf("-----", end + 9, StringComparison.Ordinal);
                    if (close < 0)
                    {
                        break;
                    }

                    string block = text[begin..(close + 5)];
                    from = close + 5;
                    if (block.StartsWith("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
                    {
                        found.Add(Certificate.FromPem(block));
                    }
                }
            }
            catch (FormatException)
            {
                // A broken block ends the scan; what parsed before it is kept.
            }

            return found;
        }

        return [];
    }
}
