using System.Globalization;
using System.Text;
using System.Text.Json;

namespace RecursiveAI.OneCrypto.Online.Csc;

/// <summary>An OAuth 2.0 access token (RFC 6750 bearer) and when it stops working. The value is a secret: it is never printed, logged or put in an exception.</summary>
public sealed class CscAccessToken
{
    /// <summary>Creates a token.</summary>
    /// <param name="value">The bearer value.</param>
    /// <param name="expiresAt">When it expires, or null when unknown (the service's refusal is then the only signal).</param>
    public CscAccessToken(string value, DateTimeOffset? expiresAt = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        Value = value;
        ExpiresAt = expiresAt;
    }

    /// <summary>The bearer value. Handle like a password.</summary>
    public string Value { get; }

    /// <summary>The instant it expires, if known.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>A fixed text that does not contain the value.</summary>
    public override string ToString() => "CscAccessToken(redacted)";
}

/// <summary>What the caller's token source is asked for when a credential must be authorized through OAuth 2.0 (CSC API §8.2, authorization code with scope <c>credential</c>).</summary>
public sealed class CscCredentialTokenRequest
{
    internal CscCredentialTokenRequest(string credentialId, IReadOnlyList<byte[]> hashes, string hashAlgorithmOid, bool bindsHashes)
    {
        CredentialId = credentialId;
        Hashes = hashes;
        HashAlgorithmOid = hashAlgorithmOid;
        BindsHashes = bindsHashes;
    }

    /// <summary>The credential to authorize.</summary>
    public string CredentialId { get; }

    /// <summary>The digests that will be signed, in order. The token must be bound to them (CSC API §8.2, <c>hashes</c>) when <see cref="BindsHashes"/> is true.</summary>
    public IReadOnlyList<byte[]> Hashes { get; }

    /// <summary>The OID of the hash algorithm that made the digests.</summary>
    public string HashAlgorithmOid { get; }

    /// <summary>True when the credential's SCAL is 2, so the authorization must carry the hashes; for SCAL 1 they are optional and this client still sends them.</summary>
    public bool BindsHashes { get; }

    /// <summary>The number of signatures to authorize (the count of <see cref="Hashes"/>).</summary>
    public int NumSignatures => Hashes.Count;

    /// <summary>
    /// The parameters to add to the <c>oauth2/authorize</c> request for scope <c>credential</c>: <c>credentialID</c>, <c>numSignatures</c>, <c>hashes</c>
    /// (comma-separated base64url, as that endpoint wants them) and <c>hashAlgorithmOID</c>.
    /// </summary>
    public IReadOnlyList<KeyValuePair<string, string>> ToAuthorizeParameters() =>
    [
        new("credentialID", CredentialId),
        new("numSignatures", NumSignatures.ToString(CultureInfo.InvariantCulture)),
        new("hashes", string.Join(',', Hashes.Select(h => Convert.ToBase64String(h).TrimEnd('=').Replace('+', '-').Replace('/', '_')))),
        new("hashAlgorithmOID", HashAlgorithmOid),
    ];
}

/// <summary>
/// Where access tokens come from. The caller supplies it: an authorization-code flow needs a browser and a person, which a library cannot own. Static
/// tokens, a cached client-credentials flow (<see cref="CscClientCredentialsTokenSource"/>) and anything else fit behind it.
/// </summary>
public interface ICscTokenSource
{
    /// <summary>The token for service authorization (scope <c>service</c>).</summary>
    /// <param name="forceRefresh">True when the service refused the token last given (or it has expired): do not return a cached one.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The token, or null when none can be had.</returns>
    ValueTask<CscAccessToken?> GetServiceTokenAsync(bool forceRefresh, CancellationToken cancellationToken);

    /// <summary>
    /// The token for credential authorization when the credential's authorization mode is <c>oauth2code</c>: run the authorization-code flow with scope
    /// <c>credential</c> and the request's parameters, and return the access token it yields. Sources that cannot do this return null.
    /// </summary>
    /// <param name="request">What to authorize.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    ValueTask<CscAccessToken?> GetCredentialTokenAsync(CscCredentialTokenRequest request, CancellationToken cancellationToken) => ValueTask.FromResult<CscAccessToken?>(null);
}

/// <summary>A source that always returns the same service token (for bearer tokens issued out of band, and for tests). It cannot refresh: a refused token is refused again.</summary>
public sealed class CscStaticTokenSource : ICscTokenSource
{
    private readonly CscAccessToken _token;

    /// <summary>Creates the source.</summary>
    /// <param name="token">The service token.</param>
    public CscStaticTokenSource(CscAccessToken token)
    {
        _token = token ?? throw new ArgumentNullException(nameof(token));
    }

    /// <inheritdoc />
    public ValueTask<CscAccessToken?> GetServiceTokenAsync(bool forceRefresh, CancellationToken cancellationToken) =>
        ValueTask.FromResult<CscAccessToken?>(_token);
}

/// <summary>A source made of two functions, for callers that already have their OAuth code.</summary>
public sealed class CscDelegateTokenSource : ICscTokenSource
{
    private readonly Func<bool, CancellationToken, ValueTask<CscAccessToken?>> _service;
    private readonly Func<CscCredentialTokenRequest, CancellationToken, ValueTask<CscAccessToken?>>? _credential;

    /// <summary>Creates the source.</summary>
    /// <param name="service">Returns the service token; its first argument is <c>forceRefresh</c>.</param>
    /// <param name="credential">Returns a credential token for an <c>oauth2code</c> credential; null when the caller only uses explicit authorization.</param>
    public CscDelegateTokenSource(Func<bool, CancellationToken, ValueTask<CscAccessToken?>> service, Func<CscCredentialTokenRequest, CancellationToken, ValueTask<CscAccessToken?>>? credential = null)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _credential = credential;
    }

    /// <inheritdoc />
    public ValueTask<CscAccessToken?> GetServiceTokenAsync(bool forceRefresh, CancellationToken cancellationToken) => _service(forceRefresh, cancellationToken);

    /// <inheritdoc />
    public ValueTask<CscAccessToken?> GetCredentialTokenAsync(CscCredentialTokenRequest request, CancellationToken cancellationToken) =>
        _credential is null ? ValueTask.FromResult<CscAccessToken?>(null) : _credential(request, cancellationToken);
}

/// <summary>
/// The OAuth 2.0 client-credentials flow (RFC 6749 §4.4) against the service's <c>oauth2/token</c> endpoint (CSC API §8.2), for services whose
/// <c>authType</c> includes <c>oauth2client</c>. The token is cached until shortly before it expires. The client secret travels only in the
/// <c>Authorization</c> header of the token request; it is never recorded by <see cref="RecordingTransport"/> (which drops request headers) or put in a result.
/// </summary>
public sealed class CscClientCredentialsTokenSource : ICscTokenSource, IDisposable
{
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(30);
    private readonly Fetcher _fetcher;
    private readonly Uri _tokenEndpoint;
    private readonly string _basic;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private CscAccessToken? _cached;

    /// <summary>Creates the source.</summary>
    /// <param name="fetcher">Carries the request (and applies its limits).</param>
    /// <param name="tokenEndpoint">The absolute <c>http</c>/<c>https</c> URL of the token endpoint.</param>
    /// <param name="clientId">The OAuth client identifier.</param>
    /// <param name="clientSecret">The OAuth client secret.</param>
    public CscClientCredentialsTokenSource(Fetcher fetcher, Uri tokenEndpoint, string clientId, string clientSecret)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _tokenEndpoint = tokenEndpoint ?? throw new ArgumentNullException(nameof(tokenEndpoint));
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        ArgumentException.ThrowIfNullOrEmpty(clientSecret);
        // RFC 6749 §2.3.1: the id and secret are form-urlencoded before they are joined for HTTP Basic.
        _basic = Convert.ToBase64String(Encoding.UTF8.GetBytes(Uri.EscapeDataString(clientId) + ":" + Uri.EscapeDataString(clientSecret)));
    }

    /// <summary>Releases the lock used to serialise token requests.</summary>
    public void Dispose() => _gate.Dispose();

    /// <summary>The scope requested (default <c>service</c>).</summary>
    public string Scope { get; init; } = "service";

    /// <inheritdoc />
    public async ValueTask<CscAccessToken?> GetServiceTokenAsync(bool forceRefresh, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            DateTimeOffset now = _fetcher.Options.Time.GetUtcNow();
            if (!forceRefresh && _cached is { } c && (c.ExpiresAt is null || c.ExpiresAt.Value - Skew > now))
            {
                return c;
            }

            FetchResult r = await _fetcher.FetchAsync(new FetchRequest
            {
                Uri = _tokenEndpoint,
                Method = "POST",
                Body = Encoding.ASCII.GetBytes("grant_type=client_credentials&scope=" + Uri.EscapeDataString(Scope)),
                Headers = [new("Content-Type", "application/x-www-form-urlencoded"), new("Authorization", "Basic " + _basic), new("Accept", "application/json")],
                MaxRedirects = 0,
                MaxResponseBytes = 64 * 1024,
            }, cancellationToken).ConfigureAwait(false);
            _cached = null;
            if (!r.IsSuccess)
            {
                return null;
            }

            try
            {
                using JsonDocument doc = JsonDocument.Parse(r.Body, CscJson.Options);
                JsonElement root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("access_token", out JsonElement t) || t.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(CscJson.Text(t)))
                {
                    return null;
                }

                DateTimeOffset? expires = null;
                if (root.TryGetProperty("expires_in", out JsonElement e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out long seconds) && seconds is > 0 and < 10L * 365 * 86400)
                {
                    expires = now.AddSeconds(seconds);
                }

                _cached = new CscAccessToken(CscJson.Text(t), expires);
                return _cached;
            }
            catch (Exception ex) when (ex is JsonException or CscFormatException)
            {
                return null;
            }
        }
        finally
        {
            _gate.Release();
        }
    }
}
