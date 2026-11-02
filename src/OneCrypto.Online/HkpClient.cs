using System.Globalization;
using System.Text;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>An HTTP Keyserver Protocol server (draft-gallagher-openpgp-hkp): the base of the <c>/pks/</c> paths.</summary>
public sealed class HkpServer
{
    private HkpServer(Uri baseUri)
    {
        BaseUri = baseUri;
    }

    /// <summary>The base URI: scheme, host and port, with no path.</summary>
    public Uri BaseUri { get; }

    /// <summary>
    /// Reads a server address. <c>hkps://host</c> is https on port 443 and <c>hkp://host</c> is http on port 11371 (draft §4); <c>https://</c> and <c>http://</c> are taken as written.
    /// </summary>
    /// <param name="value">The address; a bare host name means <c>hkps://</c>.</param>
    /// <param name="server">The server, or null.</param>
    /// <returns>False when the address has a path, query, user information or another scheme, or no host.</returns>
    public static bool TryParse(string? value, out HkpServer? server)
    {
        server = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string text = value.Trim();
        if (!text.Contains("://", StringComparison.Ordinal))
        {
            text = "hkps://" + text;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out Uri? u) || u.UserInfo.Length > 0 || u.Host.Length == 0 || u.Query.Length > 0 || u.Fragment.Length > 0
            || (u.AbsolutePath != "/" && u.AbsolutePath.Length > 0))
        {
            return false;
        }

        string? scheme = u.Scheme switch
        {
            "hkps" or "https" => Uri.UriSchemeHttps,
            "hkp" or "http" => Uri.UriSchemeHttp,
            _ => null,
        };
        if (scheme is null)
        {
            return false;
        }

        int port = u.Port > 0 ? u.Port : u.Scheme == "hkp" ? 11371 : 443;
        try
        {
            server = new HkpServer(new UriBuilder(scheme, u.Host, port).Uri);
        }
        catch (UriFormatException)
        {
            // A host the parser accepted in one form (a bracketed or scoped address) that cannot be rebuilt as an authority.
            return false;
        }

        return true;
    }

    /// <summary>Reads a server address.</summary>
    /// <param name="value">See <see cref="TryParse"/>.</param>
    /// <exception cref="FormatException">The address is not valid.</exception>
    public static HkpServer Parse(string value) => TryParse(value, out HkpServer? s) ? s! : throw new FormatException("not an HKP server address");
}

/// <summary>Builds the <c>search</c> values for HKP lookups (draft §6.1.7.1).</summary>
public static class HkpSearch
{
    /// <summary>A search for a fingerprint: <c>0x</c> and upper-case hexadecimal.</summary>
    /// <param name="fingerprint">20 (version 4) or 32 (version 6) octets, or 16 for a version 3 key.</param>
    /// <exception cref="ArgumentException">The length is none of those.</exception>
    public static string Fingerprint(ReadOnlySpan<byte> fingerprint) =>
        fingerprint.Length is 16 or 20 or 32 ? "0x" + Convert.ToHexString(fingerprint) : throw new ArgumentException("a fingerprint is 16, 20 or 32 octets", nameof(fingerprint));

    /// <summary>A search for a 64-bit key ID.</summary>
    /// <param name="keyId">Eight octets.</param>
    /// <exception cref="ArgumentException">The length is not eight.</exception>
    public static string KeyId(ReadOnlySpan<byte> keyId) =>
        keyId.Length == 8 ? "0x" + Convert.ToHexString(keyId) : throw new ArgumentException("a key ID is eight octets", nameof(keyId));
}

/// <summary>The answer to a keyserver upload.</summary>
public enum KeyUploadOutcome
{
    /// <summary>The server accepted the request (a 2xx answer). It may still hold the key back, for example until an address is verified.</summary>
    Accepted = 0,

    /// <summary>The server refused the submission as not well formed (422 or 400).</summary>
    Rejected = 1,

    /// <summary>The server does not accept submissions over HTTP (403, 404 or 501).</summary>
    NotAccepted = 2,

    /// <summary>The server limits the request rate (429).</summary>
    RateLimited = 3,

    /// <summary>The request could not be completed; <see cref="KeyUploadResult.Fetch"/> has the detail.</summary>
    FetchFailed = 4,

    /// <summary>The key text is empty or too large to send.</summary>
    InvalidInput = 5,
}

/// <summary>What a key upload ended with.</summary>
public class KeyUploadResult
{
    internal KeyUploadResult(KeyUploadOutcome outcome, string reason, FetchResult? fetch)
    {
        Outcome = outcome;
        Reason = reason;
        Fetch = fetch;
    }

    /// <summary>How it ended.</summary>
    public KeyUploadOutcome Outcome { get; }

    /// <summary>True when <see cref="Outcome"/> is <see cref="KeyUploadOutcome.Accepted"/>.</summary>
    public bool IsSuccess => Outcome == KeyUploadOutcome.Accepted;

    /// <summary>A sentence saying why, empty on success.</summary>
    public string Reason { get; }

    /// <summary>The HTTP exchange; the server's answer body is in <see cref="FetchResult.Body"/>.</summary>
    public FetchResult? Fetch { get; }

    internal static KeyUploadOutcome Map(FetchResult f) => f.IsSuccess ? KeyUploadOutcome.Accepted : f.Outcome == FetchOutcome.HttpStatus
        ? f.StatusCode switch
        {
            422 or 400 or 413 => KeyUploadOutcome.Rejected,
            403 or 404 or 501 => KeyUploadOutcome.NotAccepted,
            429 => KeyUploadOutcome.RateLimited,
            _ => KeyUploadOutcome.FetchFailed,
        }
        : KeyUploadOutcome.FetchFailed;
}

/// <summary>Choices for <see cref="HkpClient"/>.</summary>
public sealed class HkpOptions
{
    /// <summary>The largest response accepted for a key lookup (default 4 MiB).</summary>
    public long MaxKeyResponseBytes { get; init; } = 4L << 20;

    /// <summary>The largest index accepted (default 1 MiB).</summary>
    public long MaxIndexResponseBytes { get; init; } = 1L << 20;

    /// <summary>The largest key text sent by an upload (default 4 MiB).</summary>
    public int MaxUploadBytes { get; init; } = 4 << 20;
}

/// <summary>
/// The legacy lookup and submission API of HKP (draft §6): <c>get</c>, <c>index</c>, <c>vindex</c> and, only when the caller asks, <c>/pks/add</c>. The server is
/// written by the caller, so the address guard applies to redirects but not to the first request. Nothing is fetched until a method is called, and nothing
/// is cached unless the fetcher's request says so (these requests do not).
/// </summary>
/// <remarks>
/// Lookups ask for machine-readable output (<c>options=mr</c>). The response is what the server sent; it is not trusted. Use <c>KeyDiscovery</c> in the OpenPGP
/// package to find the certificates in it and to check that they are the ones asked for. The v2 API of the draft is not implemented.
/// </remarks>
public sealed class HkpClient
{
    private readonly Fetcher _fetcher;
    private readonly HkpServer _server;
    private readonly HkpOptions _options;

    /// <summary>Creates a client for one server.</summary>
    /// <param name="fetcher">The fetcher that carries the requests.</param>
    /// <param name="server">The server.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    public HkpClient(Fetcher fetcher, HkpServer server, HkpOptions? options = null)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _server = server ?? throw new ArgumentNullException(nameof(server));
        _options = options ?? new HkpOptions();
    }

    /// <summary>Fetches the certificates matching <paramref name="search"/> (<c>op=get</c>).</summary>
    /// <param name="search">A fingerprint or key ID from <see cref="HkpSearch"/>, or text from a User ID.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The armored bundle as sent.</returns>
    public async ValueTask<KeyFetchResult> GetAsync(string search, CancellationToken cancellationToken = default)
    {
        if (!ValidSearch(search))
        {
            return KeyFetchResult.Invalid("the search text is empty or longer than 1024 characters");
        }

        FetchResult f = await _fetcher.FetchAsync(LookupRequest("get", search, _options.MaxKeyResponseBytes, "application/pgp-keys, */*;q=0.1"), cancellationToken).ConfigureAwait(false);
        return KeyFetchResult.From(f, _fetcher.Options.Time);
    }

    /// <summary>Lists the certificates matching <paramref name="search"/> (<c>op=index</c>, machine-readable, with fingerprints).</summary>
    /// <param name="search">The search text.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public ValueTask<HkpIndexResult> IndexAsync(string search, CancellationToken cancellationToken = default) => ListAsync("index", search, cancellationToken);

    /// <summary>The verbose listing (<c>op=vindex</c>, deprecated in the draft; many servers treat it as <c>index</c>).</summary>
    /// <param name="search">The search text.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public ValueTask<HkpIndexResult> VerboseIndexAsync(string search, CancellationToken cancellationToken = default) => ListAsync("vindex", search, cancellationToken);

    /// <summary>Submits certificates (<c>POST /pks/add</c>). The caller has to ask for this explicitly; no lookup ever uploads.</summary>
    /// <param name="armoredKeys">An ASCII-armored certificate bundle (draft §6.2, §9). Never pass secret keys.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async ValueTask<KeyUploadResult> UploadAsync(string armoredKeys, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(armoredKeys) || armoredKeys.Length > _options.MaxUploadBytes)
        {
            return new KeyUploadResult(KeyUploadOutcome.InvalidInput, "the key text is empty or too large", null);
        }

        if (armoredKeys.Contains("PRIVATE KEY BLOCK", StringComparison.Ordinal))
        {
            return new KeyUploadResult(KeyUploadOutcome.InvalidInput, "a private key block is never uploaded", null);
        }

        // RFC 1866 §8.2.1 form encoding: unreserved characters as they are, a space as '+', everything else as %XX over UTF-8.
        string form = "keytext=" + Uri.EscapeDataString(armoredKeys).Replace("%20", "+", StringComparison.Ordinal);
        FetchResult f = await _fetcher.FetchAsync(new FetchRequest
        {
            Uri = new Uri(_server.BaseUri, "/pks/add"),
            Method = "POST",
            Body = Encoding.ASCII.GetBytes(form),
            Headers = [new("Content-Type", "application/x-www-form-urlencoded")],
            Origin = UrlOrigin.Caller,
            MaxResponseBytes = 256 * 1024,
        }, cancellationToken).ConfigureAwait(false);
        return new KeyUploadResult(KeyUploadResult.Map(f), f.Reason, f);
    }

    private async ValueTask<HkpIndexResult> ListAsync(string op, string search, CancellationToken ct)
    {
        if (!ValidSearch(search))
        {
            return new HkpIndexResult(KeyFetchResult.Invalid("the search text is empty or longer than 1024 characters"), null);
        }

        FetchResult f = await _fetcher.FetchAsync(LookupRequest(op, search, _options.MaxIndexResponseBytes, "text/plain, */*;q=0.1"), ct).ConfigureAwait(false);
        KeyFetchResult r = KeyFetchResult.From(f, _fetcher.Options.Time);
        HkpIndex? index = null;
        if (r.IsSuccess && !HkpIndex.TryParse(r.Body.Span, out index))
        {
            return new HkpIndexResult(new KeyFetchResult(KeyFetchOutcome.FetchFailed, "the response is not a machine-readable HKP index", r.Uri, f), null);
        }

        return new HkpIndexResult(r, index);
    }

    private FetchRequest LookupRequest(string op, string search, long max, string accept) => new()
    {
        Uri = new Uri(_server.BaseUri, $"/pks/lookup?op={op}&options=mr&fingerprint=on&search={Uri.EscapeDataString(search)}"),
        Origin = UrlOrigin.Caller,
        Headers = [new("Accept", accept)],
        MaxResponseBytes = max,
    };

    private static bool ValidSearch(string search) => !string.IsNullOrWhiteSpace(search) && search.Length <= 1024;
}

/// <summary>An index lookup: the transport result and, when the answer was an index, its records.</summary>
public sealed class HkpIndexResult
{
    internal HkpIndexResult(KeyFetchResult fetch, HkpIndex? index)
    {
        Result = fetch;
        Index = index;
    }

    /// <summary>How the request ended; <see cref="KeyFetchResult.Body"/> is the raw text.</summary>
    public KeyFetchResult Result { get; }

    /// <summary>The parsed index, or null when the request failed or the answer was not a machine-readable index.</summary>
    public HkpIndex? Index { get; }
}

/// <summary>A User ID record of an index (draft §7.3.1).</summary>
/// <param name="Text">The User ID with its percent-encoding removed (invalid UTF-8 shows as replacement characters).</param>
/// <param name="Created">When the self-signature over the User ID was made, if the server said.</param>
/// <param name="Expires">When the User ID expires, if the server said.</param>
/// <param name="Flags">Letters: <c>r</c> revoked, <c>d</c> disabled, <c>e</c> expired.</param>
public sealed record HkpUserIdRecord(string Text, DateTimeOffset? Created, DateTimeOffset? Expires, string Flags)
{
    /// <summary>The server marked the User ID revoked.</summary>
    public bool IsRevoked => Flags.Contains('r', StringComparison.Ordinal);

    /// <summary>The server marked the User ID expired.</summary>
    public bool IsExpired => Flags.Contains('e', StringComparison.Ordinal);
}

/// <summary>A primary-key record of an index with the User IDs after it (draft §7.3.1).</summary>
/// <param name="KeyId">The fingerprint or long key ID in upper-case hexadecimal, without <c>0x</c>.</param>
/// <param name="Algorithm">The public-key algorithm number, if given.</param>
/// <param name="Bits">The key length in bits, if given.</param>
/// <param name="Created">The key creation time, if given.</param>
/// <param name="Expires">The key expiry, if given.</param>
/// <param name="Flags">Letters: <c>r</c> revoked, <c>d</c> disabled, <c>e</c> expired.</param>
/// <param name="UserIds">The User ID records in order.</param>
public sealed record HkpIndexEntry(string KeyId, int? Algorithm, int? Bits, DateTimeOffset? Created, DateTimeOffset? Expires, string Flags, IReadOnlyList<HkpUserIdRecord> UserIds)
{
    /// <summary>True when <see cref="KeyId"/> is a fingerprint (32, 40 or 64 hex digits) rather than a 16-digit key ID.</summary>
    public bool IsFingerprint => KeyId.Length is 32 or 40 or 64;

    /// <summary>The server marked the key revoked.</summary>
    public bool IsRevoked => Flags.Contains('r', StringComparison.Ordinal);
}

/// <summary>
/// A legacy machine-readable index (<c>info</c>, <c>pub</c> and <c>uid</c> records, draft §7.3.1). It is data from a server, so the reader is lenient about
/// everything the draft allows to vary and bounded about everything an attacker could inflate.
/// </summary>
public sealed class HkpIndex
{
    /// <summary>The most key records read; the rest are dropped.</summary>
    public const int MaxEntries = 10_000;

    /// <summary>The most User ID records kept per key.</summary>
    public const int MaxUserIdsPerEntry = 1_000;

    private const int MaxLineLength = 64 * 1024;
    private const int MaxInputLength = 8 << 20;

    private HkpIndex(IReadOnlyList<HkpIndexEntry> entries, int version, int? declaredCount, bool truncated)
    {
        Entries = entries;
        Version = version;
        DeclaredCount = declaredCount;
        Truncated = truncated;
    }

    /// <summary>The key records in order.</summary>
    public IReadOnlyList<HkpIndexEntry> Entries { get; }

    /// <summary>The format version from the <c>info</c> record, 1 when there is none.</summary>
    public int Version { get; }

    /// <summary>The number of certificates the <c>info</c> record claims, if any. It is the server's claim and may not match <see cref="Entries"/>.</summary>
    public int? DeclaredCount { get; }

    /// <summary>True when records were dropped because of <see cref="MaxEntries"/> or <see cref="MaxUserIdsPerEntry"/>.</summary>
    public bool Truncated { get; }

    /// <summary>Reads an index. Never throws.</summary>
    /// <param name="utf8">The response body.</param>
    /// <param name="index">The index when the text has an <c>info</c> or <c>pub</c> record; otherwise null (for example an HTML page from a server that ignored <c>options=mr</c>).</param>
    /// <returns>True when the text is an index (possibly with no keys).</returns>
    public static bool TryParse(ReadOnlySpan<byte> utf8, out HkpIndex? index)
    {
        index = null;
        if (utf8.Length > MaxInputLength)
        {
            return false;
        }

        string text = Encoding.UTF8.GetString(utf8);
        var entries = new List<HkpIndexEntry>();
        var uids = new List<HkpUserIdRecord>();
        string[]? pub = null;
        bool sawRecord = false;
        bool truncated = false;
        int version = 1;
        int? declared = null;

        void Flush()
        {
            if (pub is null)
            {
                return;
            }

            string id = pub[1].Trim().ToUpperInvariant();
            if (id.Length > 0 && id.All(Uri.IsHexDigit))
            {
                if (entries.Count < MaxEntries)
                {
                    entries.Add(new HkpIndexEntry(id, Int(Field(pub, 2)), Int(Field(pub, 3)), Time(Field(pub, 4)), Time(Field(pub, 5)), Letters(Field(pub, 6)), [.. uids]));
                }
                else
                {
                    truncated = true;
                }
            }

            pub = null;
            uids.Clear();
        }

        foreach (string raw in text.Split('\n'))
        {
            if (raw.Length > MaxLineLength)
            {
                continue;
            }

            string line = raw.TrimEnd('\r');
            string[] f = line.Split(':');
            switch (f[0])
            {
                case "info":
                    sawRecord = true;
                    version = Int(Field(f, 1)) ?? 1;
                    declared = Int(Field(f, 2));
                    break;
                case "pub" when f.Length >= 2:
                    sawRecord = true;
                    Flush();
                    pub = f;
                    break;
                case "uid" when f.Length >= 2 && pub is not null:
                    if (uids.Count < MaxUserIdsPerEntry)
                    {
                        uids.Add(new HkpUserIdRecord(PercentDecode(f[1]), Time(Field(f, 2)), Time(Field(f, 3)), Letters(Field(f, 4))));
                    }
                    else
                    {
                        truncated = true;
                    }

                    break;
                default:
                    // sub, tru, uat and anything newer: not needed, skipped (draft §7.3: ignore what is not understood).
                    break;
            }
        }

        Flush();
        if (!sawRecord)
        {
            return false;
        }

        index = new HkpIndex(entries, version, declared, truncated);
        return true;
    }

    /// <summary>Reads an index.</summary>
    /// <param name="utf8">The response body.</param>
    /// <returns>The index.</returns>
    /// <exception cref="FormatException">The text is not a machine-readable index.</exception>
    public static HkpIndex Parse(ReadOnlySpan<byte> utf8) => TryParse(utf8, out HkpIndex? i) ? i! : throw new FormatException("not a machine-readable HKP index");

    private static string Field(string[] f, int i) => i < f.Length ? f[i] : string.Empty;

    private static int? Int(string s) => int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out int n) ? n : null;

    private static string Letters(string s) => new([.. s.Where(char.IsAsciiLetter).Select(char.ToLowerInvariant).Distinct()]);

    // Seconds since 1970; an empty or out-of-range field is "not said".
    private static DateTimeOffset? Time(string s) =>
        long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out long t) && t <= 253402300799L ? DateTimeOffset.FromUnixTimeSeconds(t) : null;

    // RFC 3986 §2.1 over UTF-8. A '%' not followed by two hex digits stays as it is.
    private static string PercentDecode(string s)
    {
        if (!s.Contains('%', StringComparison.Ordinal))
        {
            return s;
        }

        var bytes = new List<byte>(s.Length);
        int i = 0;
        while (i < s.Length)
        {
            if (s[i] == '%' && i + 2 < s.Length && Uri.IsHexDigit(s[i + 1]) && Uri.IsHexDigit(s[i + 2]))
            {
                bytes.Add(Convert.ToByte(s.Substring(i + 1, 2), 16));
                i += 3;
                continue;
            }

            // A run up to the next '%' is encoded whole so surrogate pairs stay together.
            int next = s.IndexOf('%', i + 1);
            if (next < 0)
            {
                next = s.Length;
            }

            bytes.AddRange(Encoding.UTF8.GetBytes(s[i..next]));
            i = next;
        }

        return Encoding.UTF8.GetString([.. bytes]);
    }
}
