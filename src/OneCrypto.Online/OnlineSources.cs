using System.Collections.Concurrent;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>One thing an online source tried, kept so a report that says "revocation unknown" can say why.</summary>
/// <param name="Kind">"ocsp", "crl" or "aia".</param>
/// <param name="Uri">The location.</param>
/// <param name="Succeeded">Whether it produced usable data.</param>
/// <param name="Detail">The outcome in words: the fetch failure, the responder status, the parse problem.</param>
public sealed record OnlineAttempt(string Kind, Uri Uri, bool Succeeded, string Detail);

/// <summary>Finds missing issuer certificates through <c>caIssuers</c> locations, for <see cref="PathValidator.ValidateAsync"/>.</summary>
/// <remarks>
/// Nothing is fetched until a validation that was given this source asks for it. The locations come from the certificates being validated, so every request has
/// the address guard on. Failures do not throw: the validator simply finds no issuer, and <see cref="Attempts"/> records why.
/// </remarks>
public sealed class OnlineCertificateSource : ICertificateSource
{
    private readonly AiaClient _client;
    private readonly AiaFetchOptions _options;
    private readonly ConcurrentQueue<OnlineAttempt> _attempts = new();

    /// <summary>Creates a source.</summary>
    /// <param name="fetcher">The fetcher that carries the requests.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    public OnlineCertificateSource(Fetcher fetcher, AiaFetchOptions? options = null)
    {
        _client = new AiaClient(fetcher);
        _options = options ?? new AiaFetchOptions();
    }

    /// <summary>What was tried, oldest first.</summary>
    public IReadOnlyCollection<OnlineAttempt> Attempts => _attempts.ToArray();

    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<Certificate>> FindIssuersAsync(Certificate subject, IReadOnlyList<string> caIssuersUris, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(caIssuersUris);
        var found = new List<Certificate>();
        foreach (AiaFetchResult r in await _client.FetchIssuersAsync(caIssuersUris, _options, cancellationToken).ConfigureAwait(false))
        {
            _attempts.Enqueue(new OnlineAttempt("aia", r.Uri, r.Outcome == AiaOutcome.Fetched, r.Outcome == AiaOutcome.Fetched ? $"{r.Certificates.Count} certificate(s)" : r.Reason));

            // Only a certificate whose subject is the subject's issuer can be the next link; anything else is noise from a careless or hostile server.
            found.AddRange(r.Certificates.Where(c => c.Subject.Matches(subject.Issuer)));
        }

        return found;
    }
}

/// <summary>Which revocation data to ask for first.</summary>
public enum RevocationPreference
{
    /// <summary>OCSP first; the CRLs only if OCSP gave no answer for the certificate (an error, a failed fetch, or the status "unknown"). Smallest transfers.</summary>
    OcspThenCrl = 0,

    /// <summary>CRLs first; OCSP only if no CRL could be fetched.</summary>
    CrlThenOcsp = 1,

    /// <summary>Both, always. Most data, and the validator uses whichever it finds usable.</summary>
    Both = 2,
}

/// <summary>Choices for <see cref="OnlineRevocationSource"/>.</summary>
public sealed class OnlineRevocationOptions
{
    /// <summary>The order of the sources (default <see cref="RevocationPreference.OcspThenCrl"/>).</summary>
    public RevocationPreference Preference { get; init; }

    /// <summary>The instant cached data is judged at. It should be the validation's reference time (or its revocation data time). Null means the fetcher's clock.</summary>
    public DateTimeOffset? ReferenceTime { get; init; }

    /// <summary>Send OCSP nonces (default false; see <see cref="OcspQueryOptions.UseNonce"/>).</summary>
    public bool UseOcspNonce { get; init; }

    /// <summary>Fetch delta CRLs (default true).</summary>
    public bool FetchDeltaCrls { get; init; } = true;

    /// <summary>Use and fill the cache (default true).</summary>
    public bool UseCache { get; init; } = true;

    /// <summary>The most locations tried per certificate and kind (default 4).</summary>
    public int MaxLocations { get; init; } = 4;
}

/// <summary>
/// Finds revocation data through OCSP and CRL locations, for <see cref="PathValidator.ValidateAsync"/>. The validator checks signatures, signers and times; this only
/// fetches. Without this source (or with a transport that cannot reach the network) revocation stays <c>Unknown</c>, never <c>Good</c>.
/// </summary>
/// <remarks>
/// Nothing is fetched until a validation that was given this source asks for it. The locations come from the certificates being validated, so every request has
/// the address guard on. Failures do not throw: the validator reports the certificate's revocation as unknown, and <see cref="Attempts"/> records why (a blocked
/// address, a timeout, a responder that said "unauthorized", a browser's cross-origin refusal).
/// </remarks>
public sealed class OnlineRevocationSource : IRevocationSource
{
    private readonly OcspClient _ocsp;
    private readonly CrlClient _crl;
    private readonly OnlineRevocationOptions _options;
    private readonly ConcurrentQueue<OnlineAttempt> _attempts = new();

    /// <summary>Creates a source.</summary>
    /// <param name="fetcher">The fetcher that carries the requests.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    public OnlineRevocationSource(Fetcher fetcher, OnlineRevocationOptions? options = null)
    {
        _ocsp = new OcspClient(fetcher);
        _crl = new CrlClient(fetcher);
        _options = options ?? new OnlineRevocationOptions();
    }

    /// <summary>What was tried, oldest first.</summary>
    public IReadOnlyCollection<OnlineAttempt> Attempts => _attempts.ToArray();

    /// <inheritdoc />
    public async ValueTask<RevocationData> GetRevocationDataAsync(Certificate certificate, Certificate issuer, IReadOnlyList<string> crlUris, IReadOnlyList<string> ocspUris, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(crlUris);
        ArgumentNullException.ThrowIfNull(ocspUris);
        var crls = new List<CertificateRevocationList>();
        var responses = new List<OcspBasicResponse>();

        bool crlFirst = _options.Preference == RevocationPreference.CrlThenOcsp;
        bool gotAny = false;
        for (int step = 0; step < 2; step++)
        {
            bool doOcsp = (step == 0) != crlFirst;
            if (gotAny && _options.Preference != RevocationPreference.Both)
            {
                break;
            }

            if (doOcsp)
            {
                gotAny |= await AskOcspAsync(certificate, issuer, ocspUris, responses, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                gotAny |= await AskCrlAsync(certificate, crlUris, crls, cancellationToken).ConfigureAwait(false);
            }
        }

        return new RevocationData { Crls = crls, OcspResponses = responses };
    }

    private async ValueTask<bool> AskOcspAsync(Certificate certificate, Certificate issuer, IReadOnlyList<string> uris, List<OcspBasicResponse> into, CancellationToken cancellationToken)
    {
        bool any = false;
        foreach (string s in uris.Take(_options.MaxLocations))
        {
            if (!Uri.TryCreate(s, UriKind.Absolute, out Uri? u))
            {
                continue;
            }

            if (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps)
            {
                _attempts.Enqueue(new OnlineAttempt("ocsp", u, false, $"{u.Scheme} locations are not fetched"));
                continue;
            }

            OcspQueryResult r = await _ocsp.QueryAsync(certificate, issuer, new OcspQueryOptions
            {
                ResponderUri = u,
                UseNonce = _options.UseOcspNonce,
                ReferenceTime = _options.ReferenceTime,
                UseCache = _options.UseCache,
                Origin = UrlOrigin.Certificate,
            }, cancellationToken).ConfigureAwait(false);
            bool ok = r.Outcome == OcspOutcome.Answered && r.Basic is not null;
            _attempts.Enqueue(new OnlineAttempt("ocsp", u, ok, ok ? r.Answer!.Status.ToString() : $"{r.Outcome}: {r.Reason}"));
            if (ok)
            {
                into.Add(r.Basic!);

                // "unknown" says the responder has never heard of the certificate; that is no answer for the purpose of skipping the CRLs.
                any |= r.Answer!.Status != OcspCertStatus.Unknown;
                break;
            }
        }

        return any;
    }

    private async ValueTask<bool> AskCrlAsync(Certificate certificate, IReadOnlyList<string> uris, List<CertificateRevocationList> into, CancellationToken cancellationToken)
    {
        bool any = false;
        IReadOnlyList<CrlFetchResult> results = await _crl.FetchForAsync(uris, certificate, new CrlFetchOptions
        {
            ReferenceTime = _options.ReferenceTime,
            UseCache = _options.UseCache,
            FetchDeltas = _options.FetchDeltaCrls,
            MaxLocations = _options.MaxLocations,
        }, cancellationToken).ConfigureAwait(false);
        foreach (CrlFetchResult r in results)
        {
            bool ok = r.Outcome == CrlOutcome.Fetched && r.Crl is not null;
            _attempts.Enqueue(new OnlineAttempt("crl", r.Uri, ok, ok ? (r.Crl!.IsDelta ? "delta CRL, " : "CRL, ") + r.Currency : $"{r.Outcome}: {r.Reason}"));
            if (ok)
            {
                into.Add(r.Crl!);
                any = true;
            }
        }

        return any;
    }
}
