using System.Text.Json;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>What a verifying keyserver says about one email address of an uploaded key.</summary>
public enum VksEmailStatus
{
    /// <summary>The address is on the key but not published and no verification was requested.</summary>
    Unpublished = 0,

    /// <summary>The address is verified and the key can be found by it.</summary>
    Published = 1,

    /// <summary>The address is revoked.</summary>
    Revoked = 2,

    /// <summary>A verification mail was sent and the owner has not answered yet.</summary>
    Pending = 3,

    /// <summary>A status this library does not know.</summary>
    Unknown = 4,
}

/// <summary>The answer to a VKS upload or verification request.</summary>
public sealed class VksUploadResult : KeyUploadResult
{
    internal VksUploadResult(KeyUploadOutcome outcome, string reason, FetchResult? fetch, string? fingerprint = null, string? token = null, IReadOnlyDictionary<string, VksEmailStatus>? status = null, string? serverError = null)
        : base(outcome, reason, fetch)
    {
        Fingerprint = fingerprint;
        Token = token;
        Status = status ?? new Dictionary<string, VksEmailStatus>();
        ServerError = serverError;
    }

    /// <summary>The fingerprint of the uploaded primary key in upper-case hexadecimal, as the server reports it.</summary>
    public string? Fingerprint { get; }

    /// <summary>The opaque token that allows <see cref="VksClient.RequestVerifyAsync"/> for this key. Treat it as a capability: anyone holding it can ask the server to mail the key's addresses.</summary>
    public string? Token { get; }

    /// <summary>The status of each email address on the key.</summary>
    public IReadOnlyDictionary<string, VksEmailStatus> Status { get; }

    /// <summary>The <c>error</c> text of a JSON error answer, if the server sent one.</summary>
    public string? ServerError { get; }
}

/// <summary>
/// A client for the Verifying Keyserver (VKS) interface of keys.openpgp.org (its API documentation, <c>/vks/v1/…</c>): lookup by fingerprint, key ID and
/// email, upload, and the request for verification mail. The server is the caller's choice, so only redirects are address-checked. Nothing is fetched until a
/// method is called, uploads happen only through <see cref="UploadAsync"/>, and nothing is cached.
/// </summary>
/// <remarks>
/// The service rate-limits lookups (about five a second by fingerprint or key ID, one a minute by email address); a refusal is
/// <see cref="KeyFetchOutcome.RateLimited"/> with the server's <c>Retry-After</c>. A lookup by email returns a key only if the owner published that address.
/// What comes back is armored key data for <c>KeyDiscovery</c> to check; the server's word that a key belongs to an address is not taken.
/// </remarks>
public sealed class VksClient
{
    /// <summary>The public service: <c>https://keys.openpgp.org</c>.</summary>
    public static Uri DefaultServer { get; } = new("https://keys.openpgp.org");

    private readonly Fetcher _fetcher;
    private readonly Uri _server;

    /// <summary>Creates a client.</summary>
    /// <param name="fetcher">The fetcher that carries the requests.</param>
    /// <param name="server">The server's base URL (http or https, no path); null for <see cref="DefaultServer"/>.</param>
    public VksClient(Fetcher fetcher, Uri? server = null)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _server = server ?? DefaultServer;
    }

    /// <summary>Fetches the key that has the given primary key or subkey fingerprint.</summary>
    /// <param name="fingerprint">40 or 64 hexadecimal digits, any case, no <c>0x</c>, no spaces.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public ValueTask<KeyFetchResult> ByFingerprintAsync(string fingerprint, CancellationToken cancellationToken = default) =>
        IsHex(fingerprint, 40, 64) ? GetAsync("by-fingerprint/" + fingerprint.ToUpperInvariant(), cancellationToken) : Invalid("a fingerprint is 40 or 64 hexadecimal digits");

    /// <summary>Fetches the key that has the given 64-bit key ID (of the primary key or a subkey).</summary>
    /// <param name="keyId">16 hexadecimal digits, any case, no <c>0x</c>.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public ValueTask<KeyFetchResult> ByKeyIdAsync(string keyId, CancellationToken cancellationToken = default) =>
        IsHex(keyId, 16) ? GetAsync("by-keyid/" + keyId.ToUpperInvariant(), cancellationToken) : Invalid("a key ID is 16 hexadecimal digits");

    /// <summary>Fetches the key published for an email address (exact match only).</summary>
    /// <param name="email">A bare address.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public ValueTask<KeyFetchResult> ByEmailAsync(string email, CancellationToken cancellationToken = default) =>
        IsEmail(email) ? GetAsync("by-email/" + Uri.EscapeDataString(email), cancellationToken) : Invalid("not an email address");

    /// <summary>Uploads a key (<c>POST /vks/v1/upload</c>). Explicit by design: no lookup uploads anything.</summary>
    /// <param name="keytext">The public key, ASCII-armored (or Base64). The server accepts up to 1 MiB and strips everything but public keys, User IDs and signatures. Never pass a secret key.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The server's report of the key's addresses and a token for <see cref="RequestVerifyAsync"/>.</returns>
    public async ValueTask<VksUploadResult> UploadAsync(string keytext, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keytext) || keytext.Length > 1 << 20)
        {
            return new VksUploadResult(KeyUploadOutcome.InvalidInput, "the key text is empty or larger than the service's 1 MiB limit", null);
        }

        if (keytext.Contains("PRIVATE KEY BLOCK", StringComparison.Ordinal))
        {
            return new VksUploadResult(KeyUploadOutcome.InvalidInput, "a private key block is never uploaded", null);
        }

        return await PostAsync("upload", w => w.WriteString("keytext", keytext), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Asks the server to mail a verification link to addresses of an uploaded key (<c>POST /vks/v1/request-verify</c>).</summary>
    /// <param name="token">The token from <see cref="UploadAsync"/>.</param>
    /// <param name="addresses">Bare email addresses of the key (at most 32).</param>
    /// <param name="locales">Preferred languages for the mail, most preferred first; may be empty.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async ValueTask<VksUploadResult> RequestVerifyAsync(string token, IReadOnlyList<string> addresses, IReadOnlyList<string>? locales = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        if (string.IsNullOrEmpty(token) || addresses.Count is 0 or > 32 || addresses.Any(a => !IsEmail(a)))
        {
            return new VksUploadResult(KeyUploadOutcome.InvalidInput, "a token and one to 32 email addresses are required", null);
        }

        return await PostAsync("request-verify", w =>
        {
            w.WriteString("token", token);
            w.WriteStartArray("addresses");
            foreach (string a in addresses)
            {
                w.WriteStringValue(a);
            }

            w.WriteEndArray();
            if (locales is { Count: > 0 })
            {
                w.WriteStartArray("locale");
                foreach (string l in locales)
                {
                    w.WriteStringValue(l);
                }

                w.WriteEndArray();
            }
        }, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<KeyFetchResult> GetAsync(string path, CancellationToken ct)
    {
        FetchResult f = await _fetcher.FetchAsync(new FetchRequest
        {
            Uri = new Uri(_server, "/vks/v1/" + path),
            Origin = UrlOrigin.Caller,
            Headers = [new("Accept", "application/pgp-keys, */*;q=0.1")],
            MaxResponseBytes = 2L << 20,
        }, ct).ConfigureAwait(false);
        return KeyFetchResult.From(f, _fetcher.Options.Time);
    }

    private async ValueTask<VksUploadResult> PostAsync(string endpoint, Action<Utf8JsonWriter> fields, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            fields(w);
            w.WriteEndObject();
        }

        FetchResult f = await _fetcher.FetchAsync(new FetchRequest
        {
            Uri = new Uri(_server, "/vks/v1/" + endpoint),
            Method = "POST",
            Body = ms.ToArray(),
            Headers = [new("Content-Type", "application/json"), new("Accept", "application/json")],
            Origin = UrlOrigin.Caller,
            MaxResponseBytes = 256 * 1024,
        }, ct).ConfigureAwait(false);
        if (!f.IsSuccess)
        {
            return new VksUploadResult(KeyUploadResult.Map(f), f.Reason, f);
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(f.Body, new JsonDocumentOptions { MaxDepth = 8 });
            JsonElement root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return new VksUploadResult(KeyUploadOutcome.FetchFailed, "the answer is not a JSON object", f);
            }

            var status = new Dictionary<string, VksEmailStatus>(StringComparer.Ordinal);
            if (root.TryGetProperty("status", out JsonElement st) && st.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty p in st.EnumerateObject())
                {
                    status[p.Name] = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() switch
                    {
                        "unpublished" => VksEmailStatus.Unpublished,
                        "published" => VksEmailStatus.Published,
                        "revoked" => VksEmailStatus.Revoked,
                        "pending" => VksEmailStatus.Pending,
                        _ => VksEmailStatus.Unknown,
                    }
                    : VksEmailStatus.Unknown;
                }
            }

            string? fpr = Str(root, "key_fpr")?.ToUpperInvariant();
            if (fpr is not null && !(fpr.Length is 40 or 64 && fpr.All(Uri.IsHexDigit)))
            {
                fpr = null;
            }

            return new VksUploadResult(KeyUploadOutcome.Accepted, string.Empty, f, fpr, Str(root, "token"), status);
        }
        catch (JsonException ex)
        {
            return new VksUploadResult(KeyUploadOutcome.FetchFailed, "the answer is not valid JSON: " + ex.Message, f);
        }
    }

    private static string? Str(JsonElement o, string name) => o.TryGetProperty(name, out JsonElement e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;

    private static ValueTask<KeyFetchResult> Invalid(string reason) => ValueTask.FromResult(KeyFetchResult.Invalid(reason));

    private static bool IsHex(string s, params int[] lengths) => s is not null && lengths.Contains(s.Length) && s.All(Uri.IsHexDigit);

    private static bool IsEmail(string s) =>
        !string.IsNullOrEmpty(s) && s.Length <= 254 && s.Count(c => c == '@') == 1 && s[0] != '@' && s[^1] != '@' && !s.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c is '<' or '>');
}
