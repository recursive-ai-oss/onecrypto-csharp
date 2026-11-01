using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>The two ways of forming a Web Key Directory URL (draft-koch-openpgp-webkey-service §3.1).</summary>
public enum WkdMethod
{
    /// <summary>Under the <c>openpgpkey</c> sub-domain of the mail domain; tried first.</summary>
    Advanced = 0,

    /// <summary>Under the mail domain itself; used only when the <c>openpgpkey</c> sub-domain does not exist.</summary>
    Direct = 1,
}

/// <summary>
/// A mail address as a Web Key Directory sees it: the local part as written, the domain lowercased (and in IDNA form when it has non-ASCII characters), and
/// the hash that names the key file. Building the URLs does no I/O.
/// </summary>
public sealed class WkdAddress
{
    // RFC 6189 §5.1.6 z-base-32 alphabet; 160 bits make exactly 32 characters.
    private const string ZBase32 = "ybndrfg8ejkmcpqxot1uwisza345h769";

    private WkdAddress(string local, string domain)
    {
        LocalPart = local;
        Domain = domain;
        Hash = HashLocalPart(local);
    }

    /// <summary>The local part exactly as given; it goes into the <c>l</c> parameter.</summary>
    public string LocalPart { get; }

    /// <summary>The domain in lower case, in ASCII (IDNA) form.</summary>
    public string Domain { get; }

    /// <summary>The 32-character z-base-32 SHA-1 of the lower-cased local part.</summary>
    public string Hash { get; }

    /// <summary>Reads an address of the form <c>local@domain</c>.</summary>
    /// <param name="address">A bare address (no display name, no angle brackets). The last <c>@</c> separates the parts.</param>
    /// <param name="result">The parsed address, or null.</param>
    /// <returns>False when the address cannot name a directory entry: an empty part, a local part over 64 octets, control characters, or a domain that is not a host name.</returns>
    public static bool TryParse(string? address, out WkdAddress? result)
    {
        result = null;
        if (string.IsNullOrEmpty(address) || address.Length > 320)
        {
            return false;
        }

        int at = address.LastIndexOf('@');
        if (at <= 0 || at == address.Length - 1)
        {
            return false;
        }

        string local = address[..at];
        string domain = address[(at + 1)..].TrimEnd('.');
        if (Encoding.UTF8.GetByteCount(local) > 64 || local.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)) || domain.Length == 0)
        {
            return false;
        }

        if (domain.Any(c => c > 0x7F))
        {
            try
            {
                domain = new IdnMapping().GetAscii(domain);
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        domain = domain.ToLowerInvariant();
        if (domain.Length > 253 || !IsHostName(domain))
        {
            return false;
        }

        result = new WkdAddress(local, domain);
        return true;
    }

    /// <summary>Reads an address.</summary>
    /// <param name="address">A bare address.</param>
    /// <returns>The parsed address.</returns>
    /// <exception cref="FormatException">The address is not valid; see <see cref="TryParse"/>.</exception>
    public static WkdAddress Parse(string address) =>
        TryParse(address, out WkdAddress? r) ? r! : throw new FormatException("not a mail address a Web Key Directory can be asked about");

    /// <summary>The z-base-32 SHA-1 of a local part after mapping upper-case ASCII letters to lower case (non-ASCII characters are left alone).</summary>
    /// <param name="localPart">The local part.</param>
    /// <returns>32 characters.</returns>
    public static string HashLocalPart(string localPart)
    {
        ArgumentNullException.ThrowIfNull(localPart);
        byte[] bytes = Encoding.UTF8.GetBytes(localPart);
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] is >= (byte)'A' and <= (byte)'Z')
            {
                bytes[i] += 32;
            }
        }

        // The hash only maps a name to a fixed-size file name; it protects nothing (draft §5).
#pragma warning disable CA5350 // The directory file name is defined as SHA-1 of the local part (draft §3.1); it names a file and protects nothing.
        byte[] digest = SHA1.HashData(bytes);
#pragma warning restore CA5350
        var sb = new StringBuilder(32);
        int buffer = 0;
        int bits = 0;
        foreach (byte b in digest)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(ZBase32[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        return sb.ToString();
    }

    /// <summary>The URL of the key for this address by one method.</summary>
    /// <param name="method">The method.</param>
    public Uri KeyUri(WkdMethod method) => new(WellKnown(method) + "hu/" + Hash + "?l=" + Uri.EscapeDataString(LocalPart));

    /// <summary>The URL of the policy file of the domain by one method.</summary>
    /// <param name="method">The method.</param>
    public Uri PolicyUri(WkdMethod method) => new(WellKnown(method) + "policy");

    /// <summary>The URL of the submission-address file of the domain by one method.</summary>
    /// <param name="method">The method.</param>
    public Uri SubmissionAddressUri(WkdMethod method) => new(WellKnown(method) + "submission-address");

    internal string WellKnown(WkdMethod method) => method == WkdMethod.Advanced
        ? $"https://openpgpkey.{Domain}/.well-known/openpgpkey/{Domain}/"
        : $"https://{Domain}/.well-known/openpgpkey/";

    private static bool IsHostName(string domain)
    {
        foreach (string label in domain.Split('.'))
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-' || label.Any(c => !(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')))
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>The keywords of a Web Key Directory policy file (draft-koch-openpgp-webkey-service §4.5).</summary>
public sealed class WkdPolicy
{
    internal WkdPolicy(IReadOnlyDictionary<string, string?> flags, int ignoredLines)
    {
        Flags = flags;
        IgnoredLines = ignoredLines;
    }

    /// <summary>Every keyword with its value (null for a keyword without one), keywords in lower case. A keyword given twice keeps its last value.</summary>
    public IReadOnlyDictionary<string, string?> Flags { get; }

    /// <summary>How many non-comment lines were not a keyword and were ignored.</summary>
    public int IgnoredLines { get; }

    /// <summary>The provider accepts only keys whose User ID is a bare mailbox.</summary>
    public bool MailboxOnly => Flags.ContainsKey("mailbox-only");

    /// <summary>The provider runs only OpenPGP DANE, not a directory (deprecated keyword).</summary>
    public bool DaneOnly => Flags.ContainsKey("dane-only");

    /// <summary>Submissions arrive over an authenticated connection and are published without a confirmation request.</summary>
    public bool AuthSubmit => Flags.ContainsKey("auth-submit");

    /// <summary>The claimed Update Protocol draft revision, if the policy states one as an integer.</summary>
    public int? ProtocolVersion => Flags.TryGetValue("protocol-version", out string? v) && int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out int n) ? n : null;

    /// <summary>The submission address named by the <c>submission-address</c> keyword, if any.</summary>
    public string? SubmissionAddress => Flags.TryGetValue("submission-address", out string? v) ? v : null;

    /// <summary>Reads a policy file. Never throws: lines that are not keywords are counted and skipped, and an empty file is a valid policy.</summary>
    /// <param name="text">The file content.</param>
    /// <returns>The keywords.</returns>
    public static WkdPolicy Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var flags = new Dictionary<string, string?>(StringComparer.Ordinal);
        int ignored = 0;
        foreach (string raw in text.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Trim().Length == 0 || line[0] == '#')
            {
                continue;
            }

            int colon = line.IndexOf(':', StringComparison.Ordinal);
            string key = (colon < 0 ? line : line[..colon]).Trim().ToLowerInvariant();
            // §4.5: lower-case letters, digits, hyphens, dots and an underscore as name-space delimiter; the first character is a letter.
            if (key.Length == 0 || key.Length > 128 || !(key[0] is >= 'a' and <= 'z') || key.Any(c => !(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.' or '_')))
            {
                ignored++;
                continue;
            }

            flags[key] = colon < 0 ? null : line[(colon + 1)..].Trim();
        }

        return new WkdPolicy(flags, ignored);
    }
}

/// <summary>How reading a policy file ended.</summary>
public enum WkdPolicyOutcome
{
    /// <summary>The domain serves a policy file (possibly empty), so it runs a Web Key Directory.</summary>
    Present = 0,

    /// <summary>The domain answered but has no policy file (404): by the draft it does not support the directory.</summary>
    Missing = 1,

    /// <summary>The request failed; <see cref="WkdPolicyResult.Fetch"/> has the detail.</summary>
    FetchFailed = 2,

    /// <summary>The address is not valid.</summary>
    InvalidQuery = 3,
}

/// <summary>A domain's policy file.</summary>
public sealed class WkdPolicyResult
{
    internal WkdPolicyResult(WkdPolicyOutcome outcome, string reason, WkdMethod? method, WkdPolicy? policy, FetchResult? fetch)
    {
        Outcome = outcome;
        Reason = reason;
        Method = method;
        Policy = policy;
        Fetch = fetch;
    }

    /// <summary>How it ended.</summary>
    public WkdPolicyOutcome Outcome { get; }

    /// <summary>A sentence saying why, empty when present.</summary>
    public string Reason { get; }

    /// <summary>The method that reached the server (null when nothing was reached).</summary>
    public WkdMethod? Method { get; }

    /// <summary>The keywords when <see cref="Outcome"/> is <see cref="WkdPolicyOutcome.Present"/>.</summary>
    public WkdPolicy? Policy { get; }

    /// <summary>The HTTP exchange.</summary>
    public FetchResult? Fetch { get; }
}

/// <summary>What looking up a submission address ended with.</summary>
public sealed class WkdSubmissionAddressResult
{
    internal WkdSubmissionAddressResult(KeyFetchOutcome outcome, string reason, string? address, WkdMethod? method, FetchResult? fetch)
    {
        Outcome = outcome;
        Reason = reason;
        Address = address;
        Method = method;
        Fetch = fetch;
    }

    /// <summary>Found when the file was read and holds an address.</summary>
    public KeyFetchOutcome Outcome { get; }

    /// <summary>A sentence saying why, empty on success.</summary>
    public string Reason { get; }

    /// <summary>The mail address a key would be submitted to (the Update Protocol itself is not implemented).</summary>
    public string? Address { get; }

    /// <summary>The method that reached the server.</summary>
    public WkdMethod? Method { get; }

    /// <summary>The HTTP exchange.</summary>
    public FetchResult? Fetch { get; }
}

/// <summary>Choices for <see cref="WkdClient"/>.</summary>
public sealed class WkdOptions
{
    /// <summary>The largest key response accepted (default 2 MiB).</summary>
    public long MaxResponseBytes { get; init; } = 2L << 20;

    /// <summary>Fetch the policy file first and stop with <see cref="KeyFetchOutcome.PolicyMissing"/> when the domain serves none (default false: the key URL is asked directly).</summary>
    public bool RequirePolicy { get; init; }

    /// <summary>Also fall back to the direct method when the advanced method fails for a reason other than the sub-domain not existing (default false: the draft allows the fallback only when the <c>openpgpkey</c> name does not resolve, and a silent server or a 404 is an answer).</summary>
    public bool FallbackOnAnyAdvancedFailure { get; init; }

    /// <summary>Use and fill the fetcher's HTTP cache (default false: key lookups are not cached).</summary>
    public bool UseCache { get; init; }
}

/// <summary>A Web Key Directory key lookup: which method found it and what each attempt did.</summary>
public sealed class WkdLookupResult : KeyFetchResult
{
    internal WkdLookupResult(KeyFetchResult last, WkdMethod? method, IReadOnlyList<KeyValuePair<WkdMethod, KeyFetchResult>> attempts)
        : base(last.Outcome, last.Reason, last.Uri, last.Fetch, last.Body, last.RetryAfter)
    {
        Method = method;
        Attempts = attempts;
    }

    /// <summary>The method of the final attempt (null when no request was made).</summary>
    public WkdMethod? Method { get; }

    /// <summary>Every attempt in order: one for the advanced method, and a second for the direct method when the first sub-domain did not exist.</summary>
    public IReadOnlyList<KeyValuePair<WkdMethod, KeyFetchResult>> Attempts { get; }
}

/// <summary>
/// Looks up OpenPGP certificates by mail address in a Web Key Directory (draft-koch-openpgp-webkey-service §3.1, §4.1, §4.5). Nothing is fetched until a method
/// is called. The domain comes from the address of a message or a user, so every request is treated as attacker-influenced: the fetcher's address guard applies
/// to the first request as well as to redirects. Only <c>https</c> is used, and a redirect must stay on <c>https</c> (§5); a redirect to another host is followed
/// within the fetcher's limits because the draft requires it.
/// </summary>
public sealed class WkdClient
{
    private readonly Fetcher _fetcher;

    /// <summary>Creates a client.</summary>
    /// <param name="fetcher">The fetcher that carries the requests, with its limits and transport.</param>
    public WkdClient(Fetcher fetcher)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
    }

    /// <summary>Asks for the certificates published for a mail address.</summary>
    /// <param name="address">A bare address such as <c>Joe.Doe@Example.ORG</c>.</param>
    /// <param name="options">Choices; null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the requests.</param>
    /// <returns>The raw response. Pass it to <c>KeyDiscovery.ForAddress</c> to keep only the User ID that matches the address.</returns>
    public async ValueTask<WkdLookupResult> LookupAsync(string address, WkdOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new WkdOptions();
        if (!WkdAddress.TryParse(address, out WkdAddress? a))
        {
            return new WkdLookupResult(KeyFetchResult.Invalid("not a mail address a Web Key Directory can be asked about"), null, []);
        }

        WkdMethod? only = null;
        if (options.RequirePolicy)
        {
            WkdPolicyResult policy = await GetPolicyAsync(address, cancellationToken).ConfigureAwait(false);
            if (policy.Outcome == WkdPolicyOutcome.Missing)
            {
                return new WkdLookupResult(new KeyFetchResult(KeyFetchOutcome.PolicyMissing, "the domain serves no policy file, so it does not run a Web Key Directory", policy.Fetch?.FinalUri, policy.Fetch), policy.Method, []);
            }

            if (policy.Outcome != WkdPolicyOutcome.Present)
            {
                return new WkdLookupResult(new KeyFetchResult(KeyFetchOutcome.FetchFailed, policy.Reason, policy.Fetch?.FinalUri, policy.Fetch), policy.Method, []);
            }

            only = policy.Method;
        }

        var attempts = new List<KeyValuePair<WkdMethod, KeyFetchResult>>();
        KeyFetchResult last = default!;
        WkdMethod method = only ?? WkdMethod.Advanced;
        while (true)
        {
            FetchResult fetch = await _fetcher.FetchAsync(Request(a!.KeyUri(method), options.MaxResponseBytes, options.UseCache), cancellationToken).ConfigureAwait(false);
            last = KeyFetchResult.From(fetch, _fetcher.Options.Time);
            attempts.Add(new(method, last));
            if (only is null && method == WkdMethod.Advanced && ShouldFallBack(fetch, options))
            {
                method = WkdMethod.Direct;
                continue;
            }

            return new WkdLookupResult(last, method, attempts);
        }
    }

    /// <summary>Reads the policy file of the domain of an address, which tells whether the domain runs a directory and what its provider accepts.</summary>
    /// <param name="addressOrDomain">An address, or just a domain name.</param>
    /// <param name="cancellationToken">Cancels the requests.</param>
    public async ValueTask<WkdPolicyResult> GetPolicyAsync(string addressOrDomain, CancellationToken cancellationToken = default)
    {
        if (!TryAddress(addressOrDomain, out WkdAddress? a))
        {
            return new WkdPolicyResult(WkdPolicyOutcome.InvalidQuery, "not an address or a domain name", null, null, null);
        }

        (FetchResult fetch, WkdMethod method) = await FetchSmallAsync(a!, WkdMethod.Advanced, m => a!.PolicyUri(m), 16 * 1024, cancellationToken).ConfigureAwait(false);
        if (fetch.IsSuccess)
        {
            return new WkdPolicyResult(WkdPolicyOutcome.Present, string.Empty, method, WkdPolicy.Parse(Encoding.UTF8.GetString(fetch.Body.Span)), fetch);
        }

        // A zero-length policy is valid, and an empty 2xx body is a success above. 404 and 410 mean the file is not there.
        return fetch.Outcome == FetchOutcome.HttpStatus && fetch.StatusCode is 404 or 410
            ? new WkdPolicyResult(WkdPolicyOutcome.Missing, fetch.Reason, method, null, fetch)
            : new WkdPolicyResult(WkdPolicyOutcome.FetchFailed, fetch.Reason, method, null, fetch);
    }

    /// <summary>Reads the submission-address file of a domain (§4.1). Only the lookup is implemented; submitting a key by mail is the caller's business.</summary>
    /// <param name="addressOrDomain">An address, or just a domain name.</param>
    /// <param name="cancellationToken">Cancels the requests.</param>
    public async ValueTask<WkdSubmissionAddressResult> GetSubmissionAddressAsync(string addressOrDomain, CancellationToken cancellationToken = default)
    {
        if (!TryAddress(addressOrDomain, out WkdAddress? a))
        {
            return new WkdSubmissionAddressResult(KeyFetchOutcome.InvalidQuery, "not an address or a domain name", null, null, null);
        }

        (FetchResult fetch, WkdMethod method) = await FetchSmallAsync(a!, WkdMethod.Advanced, m => a!.SubmissionAddressUri(m), 1024, cancellationToken).ConfigureAwait(false);
        if (!fetch.IsSuccess)
        {
            KeyFetchResult r = KeyFetchResult.From(fetch, _fetcher.Options.Time);
            return new WkdSubmissionAddressResult(r.Outcome, r.Reason, null, method, fetch);
        }

        // §4.1: exactly one line, ended by LF or CR LF, holding a full mail address.
        string text = Encoding.UTF8.GetString(fetch.Body.Span);
        string[] lines = text.Split('\n');
        bool oneLine = lines.Length <= 2 && (lines.Length == 1 || lines[1].Length == 0);
        string line = lines[0].TrimEnd('\r');
        if (!oneLine || !WkdAddress.TryParse(line, out _))
        {
            return new WkdSubmissionAddressResult(KeyFetchOutcome.EmptyResponse, "the file is not one mail address on one line", null, method, fetch);
        }

        return new WkdSubmissionAddressResult(KeyFetchOutcome.Found, string.Empty, line, method, fetch);
    }

    private static bool TryAddress(string value, out WkdAddress? a) =>
        WkdAddress.TryParse(value, out a) || WkdAddress.TryParse("x@" + value, out a);

    private async ValueTask<(FetchResult, WkdMethod)> FetchSmallAsync(WkdAddress a, WkdMethod start, Func<WkdMethod, Uri> uriFor, long max, CancellationToken ct)
    {
        WkdMethod method = start;
        while (true)
        {
            FetchResult fetch = await _fetcher.FetchAsync(Request(uriFor(method), max, false), ct).ConfigureAwait(false);
            if (method == WkdMethod.Advanced && ShouldFallBack(fetch, null))
            {
                method = WkdMethod.Direct;
                continue;
            }

            return (fetch, method);
        }
    }

    // §3.1: the direct method is only for a domain without the openpgpkey sub-domain. A server that does not answer is not that.
    private static bool ShouldFallBack(FetchResult advanced, WkdOptions? options) =>
        !advanced.IsSuccess && (advanced.TransportFailure == TransportFailure.NameResolution || (options?.FallbackOnAnyAdvancedFailure ?? false));

    private static FetchRequest Request(Uri uri, long max, bool cache) => new()
    {
        Uri = uri,
        Origin = UrlOrigin.Certificate,
        Headers = [new("Accept", "application/octet-stream, */*;q=0.1")],
        Cache = cache ? FetchCacheMode.Http : FetchCacheMode.None,
        MaxResponseBytes = max,
    };
}
