using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace RecursiveAI.OneCrypto.Online.Csc;

/// <summary>Choices for <see cref="CscClient"/>.</summary>
public sealed class CscClientOptions
{
    /// <summary>
    /// Where the service URL came from (default <see cref="UrlOrigin.Caller"/>: the application's own configuration, so the address guard is not applied to it,
    /// as for a timestamp authority). Use <see cref="UrlOrigin.Certificate"/> to refuse private and loopback addresses for a URL that arrived from outside.
    /// </summary>
    public UrlOrigin Origin { get; init; } = UrlOrigin.Caller;

    /// <summary>The largest response accepted (default 4 MiB; a credential with a long chain is the largest answer).</summary>
    public long MaxResponseBytes { get; init; } = 4L << 20;

    /// <summary>Overrides the fetcher's time limit for each call (default: the fetcher's).</summary>
    public TimeSpan? Timeout { get; init; }
}

/// <summary>
/// A Cloud Signature Consortium API v2.2 client (<c>info</c>, <c>credentials/list</c>, <c>credentials/info</c>, <c>credentials/authorize</c>,
/// <c>signatures/signHash</c>). It sends through a <see cref="Fetcher"/>, so the transport, the size and time limits and the record/replay fixtures are the
/// library's own. Every request is a POST of a JSON object. A redirect is never followed, because every request carries a bearer token or activation
/// data. Constructing the client does no I/O; each method makes its request when called. The methods never throw for a network or service reason: they
/// return a <see cref="CscResult{T}"/>.
/// </summary>
public sealed class CscClient
{
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(10);
    private readonly Fetcher _fetcher;
    private readonly Uri _baseUri;
    private readonly CscClientOptions _options;

    /// <summary>Creates a client.</summary>
    /// <param name="fetcher">Carries the requests.</param>
    /// <param name="baseUri">The service's API base, for example <c>https://service.example/csc/v2/</c>; method names are appended to it.</param>
    /// <param name="tokens">Where access tokens come from; null for a service that needs none (<c>external</c> or TLS-client-certificate authorization).</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <exception cref="ArgumentException">The base URI is not an absolute <c>http</c> or <c>https</c> URL without user information.</exception>
    public CscClient(Fetcher fetcher, Uri baseUri, ICscTokenSource? tokens = null, CscClientOptions? options = null)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        ArgumentNullException.ThrowIfNull(baseUri);
        if (!baseUri.IsAbsoluteUri || (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps) || baseUri.UserInfo.Length != 0)
        {
            throw new ArgumentException("The service address must be an absolute http or https URL without user information.", nameof(baseUri));
        }

        _baseUri = baseUri.AbsoluteUri.EndsWith('/') ? baseUri : new Uri(baseUri.AbsoluteUri + "/");
        Tokens = tokens;
        _options = options ?? new CscClientOptions();
    }

    /// <summary>The token source, if any.</summary>
    public ICscTokenSource? Tokens { get; }

    /// <summary>Asks the service what it is and what it supports (CSC API §11.1). <c>info</c> needs no authorization.</summary>
    /// <param name="language">A preferred language for descriptions (RFC 5646), or null.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public ValueTask<CscResult<CscServiceInfo>> InfoAsync(string? language = null, CancellationToken cancellationToken = default) =>
        CallAsync("info", w =>
        {
            if (language is not null)
            {
                w.WriteString("lang", language);
            }
        }, authorize: false, [], (r, _) => CscJson.ParseInfo(r), cancellationToken);

    /// <summary>Lists the credentials of the authorized user (CSC API §11.6).</summary>
    /// <param name="userId">The user, only for services whose service authorization is not user-specific; null otherwise (the API forbids it then).</param>
    /// <param name="includeInfo">Ask for each credential's description, with the whole certificate chain and the authorization information.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public ValueTask<CscResult<CscCredentialList>> ListCredentialsAsync(string? userId = null, bool includeInfo = false, CancellationToken cancellationToken = default) =>
        CallAsync("credentials/list", w =>
        {
            if (userId is not null)
            {
                w.WriteString("userID", userId);
            }

            if (includeInfo)
            {
                w.WriteBoolean("credentialInfo", true);
                w.WriteString("certificates", "chain");
                w.WriteBoolean("authInfo", true);
            }
        }, authorize: true, [], (r, _) =>
        {
            List<string> ids = CscJson.OptStrings(r, "credentialIDs", 1024);
            var infos = new List<CscCredentialInfo>();
            if (r.TryGetProperty("credentialInfos", out JsonElement arr) && arr.ValueKind == JsonValueKind.Array)
            {
                if (arr.GetArrayLength() > CscJson.MaxItems)
                {
                    throw new CscFormatException("too many credentials");
                }

                foreach (JsonElement e in arr.EnumerateArray())
                {
                    if (e.ValueKind != JsonValueKind.Object)
                    {
                        throw new CscFormatException("a credential description is not an object");
                    }

                    infos.Add(CscJson.ParseCredential(e, CscJson.ReqString(e, "credentialID", 1024)));
                }
            }

            return new CscCredentialList(ids, infos);
        }, cancellationToken);

    /// <summary>Describes one credential, with its certificate chain and authorization mechanism (CSC API §11.7).</summary>
    /// <param name="credentialId">The credential.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public ValueTask<CscResult<CscCredentialInfo>> GetCredentialInfoAsync(string credentialId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(credentialId);
        return CallAsync("credentials/info", w =>
        {
            w.WriteString("credentialID", credentialId);
            w.WriteString("certificates", "chain");
            w.WriteBoolean("authInfo", true);
        }, authorize: true, [], (r, _) => CscJson.ParseCredential(r, credentialId), cancellationToken);
    }

    /// <summary>
    /// Authorizes the use of a credential for explicit authorization and returns the Signature Activation Data (CSC API §11.8). The digests are sent so that the
    /// service can bind the activation data to them: for a SCAL 2 credential that is required, and a signature over other digests is then refused.
    /// </summary>
    /// <param name="credentialId">The credential.</param>
    /// <param name="hashes">The digests to be signed (at most the credential's <c>multisign</c>).</param>
    /// <param name="hashAlgorithmOid">The OID of the hash algorithm that made them.</param>
    /// <param name="authData">The authentication values the credential asks for (PIN, OTP); empty when it asks for none.</param>
    /// <param name="description">A description of the transaction for the user (at most 500 characters), or null.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The authorization. When the service answers 202 the outcome is <see cref="CscOutcome.AuthorizationPending"/> and the value holds the handle.</returns>
    public async ValueTask<CscResult<CscAuthorization>> AuthorizeAsync(string credentialId, IReadOnlyList<byte[]> hashes, string hashAlgorithmOid, IReadOnlyList<CscAuthObject>? authData = null, string? description = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(credentialId);
        ArgumentNullException.ThrowIfNull(hashes);
        ArgumentException.ThrowIfNullOrEmpty(hashAlgorithmOid);
        if (hashes.Count == 0)
        {
            throw new ArgumentException("At least one hash is needed.", nameof(hashes));
        }

        string[] secrets = authData is null ? [] : [.. authData.Select(a => a.Value)];
        CscResult<CscAuthorization> r = await CallAsync("credentials/authorize", w =>
        {
            w.WriteString("credentialID", credentialId);
            w.WriteNumber("numSignatures", hashes.Count);
            w.WritePropertyName("hashes");
            w.WriteStartArray();
            foreach (byte[] h in hashes)
            {
                w.WriteStringValue(Convert.ToBase64String(h));
            }

            w.WriteEndArray();
            w.WriteString("hashAlgorithmOID", hashAlgorithmOid);
            if (authData is { Count: > 0 })
            {
                w.WritePropertyName("authData");
                w.WriteStartArray();
                foreach (CscAuthObject a in authData)
                {
                    w.WriteStartObject();
                    w.WriteString("id", a.Id);
                    w.WriteString("value", a.Value);
                    w.WriteEndObject();
                }

                w.WriteEndArray();
            }

            if (description is not null)
            {
                w.WriteString("description", description);
            }
        }, authorize: true, secrets, (root, status) =>
        {
            if (status == 202)
            {
                return new CscAuthorization(null, null, CscJson.ReqString(root, "handle", 4096));
            }

            return new CscAuthorization(CscJson.ReqString(root, "SAD", 1 << 16), CscJson.OptInt(root, "expiresIn"), null);
        }, cancellationToken).ConfigureAwait(false);

        return r.IsSuccess && r.Value!.PendingHandle is not null
            ? new CscResult<CscAuthorization>(CscOutcome.AuthorizationPending, "the service is still waiting for the authorization to be given out of band (HTTP 202)", r.Value, r.Fetch, null, 202)
            : r;
    }

    /// <summary>Signs digests with a credential (CSC API §11.13).</summary>
    /// <param name="credentialId">The credential.</param>
    /// <param name="sad">The Signature Activation Data from <see cref="AuthorizeAsync"/>, or the credential-scope access token of an <c>oauth2code</c> credential.</param>
    /// <param name="hashes">The digests, in the order the signatures are wanted.</param>
    /// <param name="hashAlgorithmOid">The OID of the hash algorithm that made them.</param>
    /// <param name="signAlgorithmOid">The signature algorithm (<c>signAlgo</c>).</param>
    /// <param name="signAlgorithmParameters">The DER of the algorithm parameters (<c>signAlgoParams</c>, RSASSA-PSS), or null.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The raw signatures in the order of <paramref name="hashes"/>; the count is checked.</returns>
    public ValueTask<CscResult<IReadOnlyList<byte[]>>> SignHashAsync(string credentialId, string sad, IReadOnlyList<byte[]> hashes, string hashAlgorithmOid, string signAlgorithmOid, ReadOnlyMemory<byte> signAlgorithmParameters = default, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(credentialId);
        ArgumentException.ThrowIfNullOrEmpty(sad);
        ArgumentNullException.ThrowIfNull(hashes);
        ArgumentException.ThrowIfNullOrEmpty(signAlgorithmOid);
        if (hashes.Count == 0)
        {
            throw new ArgumentException("At least one hash is needed.", nameof(hashes));
        }

        return CallAsync<IReadOnlyList<byte[]>>("signatures/signHash", w =>
        {
            w.WriteString("credentialID", credentialId);
            w.WriteString("SAD", sad);
            w.WritePropertyName("hashes");
            w.WriteStartArray();
            foreach (byte[] h in hashes)
            {
                w.WriteStringValue(Convert.ToBase64String(h));
            }

            w.WriteEndArray();
            w.WriteString("hashAlgorithmOID", hashAlgorithmOid);
            w.WriteString("signAlgo", signAlgorithmOid);
            if (!signAlgorithmParameters.IsEmpty)
            {
                w.WriteString("signAlgoParams", Convert.ToBase64String(signAlgorithmParameters.Span));
            }
        }, authorize: true, [sad], (r, _) =>
        {
            List<string> sigs = CscJson.OptStrings(r, "signatures", 1 << 16);
            if (sigs.Count != hashes.Count)
            {
                throw new CscFormatException($"the service returned {sigs.Count} signatures for {hashes.Count} hashes");
            }

            return [.. sigs.Select(s => CscJson.Base64(s, "a signature"))];
        }, cancellationToken);
    }

    /// <summary>
    /// Describes a credential and opens it as a signing key: the credential's certificate chain gives the public key, and each signature is authorized and
    /// made remotely (see <see cref="CscSigningKey"/>). The service's own description (<paramref name="service"/>) is optional and only helps pick the
    /// signature algorithm identifier the service lists.
    /// </summary>
    /// <param name="credentialId">The credential.</param>
    /// <param name="options">How authorization data is supplied; null for none (an <c>oauth2code</c> credential, or one that needs no authentication objects).</param>
    /// <param name="service">What <see cref="InfoAsync"/> returned, or null.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async ValueTask<CscResult<CscSigningKey>> OpenSigningKeyAsync(string credentialId, CscKeyOptions? options = null, CscServiceInfo? service = null, CancellationToken cancellationToken = default)
    {
        CscResult<CscCredentialInfo> info = await GetCredentialInfoAsync(credentialId, cancellationToken).ConfigureAwait(false);
        if (!info.IsSuccess)
        {
            return info.As<CscSigningKey>();
        }

        CscCredentialInfo c = info.Value!;
        if (!c.IsKeyEnabled)
        {
            return CscResult<CscSigningKey>.Fail(CscOutcome.CredentialUnusable, "the credential's key is not enabled", info.Fetch);
        }

        if (c.Certificates.Count == 0)
        {
            return CscResult<CscSigningKey>.Fail(CscOutcome.MalformedResponse, "the service returned no certificate for the credential", info.Fetch);
        }

        if (!Certificate.TryParse(c.Certificates[0], out Certificate? cert) || cert is null)
        {
            return CscResult<CscSigningKey>.Fail(CscOutcome.MalformedResponse, "the credential's certificate cannot be decoded", info.Fetch);
        }

        try
        {
            // The service signs digests: only a key a digest signature exists for can be used (RSA, RSA-PSS, ECDSA); any other certificate key is not a credential for this client.
            if (cert.PublicKey.KeyAlgorithm is not (KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss or KeyAlgorithm.EllipticCurve))
            {
                return CscResult<CscSigningKey>.Fail(CscOutcome.CredentialUnusable, $"the credential's key is a {cert.PublicKey.Algorithm.Name} key, which cannot sign a digest through this API", info.Fetch);
            }

            return CscResult<CscSigningKey>.Ok(new CscSigningKey(this, c, cert, cert.PublicKey, options ?? new CscKeyOptions(), service), info.Fetch);
        }
        catch (Exception ex) when (ex is X509ParseException or ArgumentException)
        {
            return CscResult<CscSigningKey>.Fail(CscOutcome.MalformedResponse, "the credential's public key cannot be decoded: " + ex.Message, info.Fetch);
        }
    }

    internal DateTimeOffset Now => _fetcher.Options.Time.GetUtcNow();

    private async ValueTask<CscResult<T>> CallAsync<T>(string method, Action<Utf8JsonWriter> writeBody, bool authorize, string[] secrets, Func<JsonElement, int, T> parse, CancellationToken cancellationToken)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            writeBody(w);
            w.WriteEndObject();
        }

        byte[] body = buffer.WrittenSpan.ToArray();
        bool refresh = false;
        for (int attempt = 0; ; attempt++)
        {
            string? bearer = null;
            if (authorize && Tokens is not null)
            {
                CscAccessToken? token = await Tokens.GetServiceTokenAsync(refresh, cancellationToken).ConfigureAwait(false);
                if (token is not null && token.ExpiresAt is { } expires && expires - Skew <= Now && !refresh)
                {
                    // Expired before it was sent: ask the source for a fresh one rather than send a token the service will refuse.
                    token = await Tokens.GetServiceTokenAsync(true, cancellationToken).ConfigureAwait(false);
                    refresh = true;
                }

                if (token is null || (token.ExpiresAt is { } e2 && e2 <= Now))
                {
                    return CscResult<T>.Fail(CscOutcome.TokenUnavailable, token is null ? "the token source gave no access token" : "the access token has expired and the token source gave no fresh one");
                }

                bearer = token.Value;
            }

            var headers = new List<KeyValuePair<string, string>> { new("Content-Type", "application/json"), new("Accept", "application/json") };
            if (bearer is not null)
            {
                headers.Add(new("Authorization", "Bearer " + bearer));
            }

            FetchResult fetch = await _fetcher.FetchAsync(new FetchRequest
            {
                Uri = new Uri(_baseUri, method),
                Method = "POST",
                Body = body,
                Headers = headers,
                Origin = _options.Origin,
                MaxRedirects = 0,
                KeepErrorBody = true,
                MaxResponseBytes = _options.MaxResponseBytes,
                Timeout = _options.Timeout,
            }, cancellationToken).ConfigureAwait(false);

            string[] hidden = bearer is null ? secrets : [.. secrets, bearer];
            if (!fetch.IsSuccess)
            {
                if (fetch.Outcome != FetchOutcome.HttpStatus)
                {
                    return CscResult<T>.Fail(CscOutcome.TransportFailed, $"{method}: {Scrub(fetch.Reason, hidden)}", fetch);
                }

                (string? error, string? description) = ReadError(fetch.Body);
                bool rejected = fetch.StatusCode == 401 || error is "invalid_token" or "expired_token";
                if (rejected && authorize && Tokens is not null && attempt == 0)
                {
                    refresh = true;
                    continue;
                }

                // Only what the service wrote is scrubbed, so a short secret cannot garble the library's own words.
                string? safeError = error is null ? null : Scrub(error, hidden);
                string text = $"{method}: HTTP {fetch.StatusCode}" + (safeError is null ? string.Empty : ": " + safeError) + (description is null ? string.Empty : " (" + Scrub(description, hidden) + ")");
                return CscResult<T>.Fail(rejected ? CscOutcome.TokenRejected : CscOutcome.ServiceError, text, fetch, safeError);
            }

            try
            {
                JsonElement root = CscJson.Root(fetch.Body);
                return CscResult<T>.Ok(parse(root, fetch.StatusCode ?? 200), fetch);
            }
            catch (Exception ex) when (ex is CscFormatException or InvalidOperationException)
            {
                // JsonElement reports a member read as the wrong kind of value with InvalidOperationException; to the caller that is the same malformed answer.
                return CscResult<T>.Fail(CscOutcome.MalformedResponse, $"{method}: {(ex is CscFormatException ? ex.Message : "a member has an unexpected type")}", fetch);
            }
        }
    }

    private static (string? Error, string? Description) ReadError(ReadOnlyMemory<byte> body)
    {
        if (body.IsEmpty)
        {
            return (null, null);
        }

        try
        {
            JsonElement root = CscJson.Root(body);
            return (CscJson.OptString(root, "error", 128), CscJson.OptString(root, "error_description", 1024));
        }
        catch (CscFormatException)
        {
            return (null, null);
        }
    }

    /// <summary>Makes text from a service or a transport safe to put in a reason: secrets sent in this call are replaced, control characters dropped, the length capped.</summary>
    internal static string Scrub(string text, string[] secrets)
    {
        foreach (string s in secrets)
        {
            if (s.Length > 0)
            {
                text = text.Replace(s, "[redacted]", StringComparison.Ordinal);
            }
        }

        var sb = new StringBuilder(Math.Min(text.Length, 400));
        foreach (char ch in text)
        {
            if (sb.Length >= 400)
            {
                sb.Append('…');
                break;
            }

            sb.Append(char.IsControl(ch) ? ' ' : ch);
        }

        return sb.ToString();
    }
}
