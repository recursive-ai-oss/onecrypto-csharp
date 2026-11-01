using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>A stored response.</summary>
/// <param name="StatusCode">The status code (only 200 is stored).</param>
/// <param name="Headers">The response headers as received.</param>
/// <param name="Body">The body.</param>
/// <param name="StoredAt">When it was received, by the fetcher's clock.</param>
/// <param name="InitialAge">Its age when received: the larger of the <c>Age</c> header and the gap between its <c>Date</c> and the time it arrived (RFC 9111 §4.2.3).</param>
/// <param name="Lifetime">How long it stays fresh from <paramref name="StoredAt"/> minus <paramref name="InitialAge"/>, from the response's own caching directives (RFC 9111 §4.2.1).</param>
/// <param name="MustRevalidate">True when the response forbids serving it stale (<c>must-revalidate</c>, <c>proxy-revalidate</c> does not apply to a private cache).</param>
/// <param name="ETag">The entity tag, for a conditional request.</param>
/// <param name="LastModified">The <c>Last-Modified</c> text, for a conditional request.</param>
public sealed record CacheEntry(int StatusCode, IReadOnlyList<KeyValuePair<string, string>> Headers, byte[] Body, DateTimeOffset StoredAt, TimeSpan InitialAge, TimeSpan Lifetime, bool MustRevalidate, string? ETag, string? LastModified)
{
    /// <summary>Whether the response may be reused without asking the server at <paramref name="now"/> (RFC 9111 §4.2).</summary>
    /// <param name="now">The current time.</param>
    public bool IsFresh(DateTimeOffset now)
    {
        TimeSpan resident = now - StoredAt;
        if (resident < TimeSpan.Zero)
        {
            // The clock went back: nothing can be said about the age, so treat it as stale.
            return false;
        }

        return InitialAge + resident < Lifetime;
    }
}

/// <summary>A store for responses. Implementations must be safe for concurrent use.</summary>
public interface IFetchCache
{
    /// <summary>Finds an entry.</summary>
    /// <param name="key">The key built by the fetcher.</param>
    /// <param name="entry">The entry.</param>
    /// <returns>True when there is one.</returns>
    bool TryGet(string key, out CacheEntry? entry);

    /// <summary>Stores or replaces an entry.</summary>
    /// <param name="key">The key.</param>
    /// <param name="entry">The entry.</param>
    void Put(string key, CacheEntry entry);

    /// <summary>Removes an entry.</summary>
    /// <param name="key">The key.</param>
    void Remove(string key);
}

/// <summary>A bounded in-memory <see cref="IFetchCache"/>. When it is over a bound it drops the entries stored longest ago.</summary>
public sealed class MemoryFetchCache : IFetchCache
{
    private readonly object _gate = new();
    private readonly Dictionary<string, CacheEntry> _entries = [];
    private readonly long _maxBytes;
    private readonly int _maxEntries;
    private long _bytes;

    /// <summary>Creates a cache.</summary>
    /// <param name="maxBytes">The most body bytes to hold (default 64 MiB).</param>
    /// <param name="maxEntries">The most entries to hold (default 1024).</param>
    public MemoryFetchCache(long maxBytes = 64L << 20, int maxEntries = 1024)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEntries);
        _maxBytes = maxBytes;
        _maxEntries = maxEntries;
    }

    /// <summary>How many entries are held.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    /// <inheritdoc />
    public bool TryGet(string key, out CacheEntry? entry)
    {
        lock (_gate)
        {
            return _entries.TryGetValue(key, out entry);
        }
    }

    /// <inheritdoc />
    public void Put(string key, CacheEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        lock (_gate)
        {
            if (entry.Body.Length > _maxBytes)
            {
                RemoveLocked(key);
                return;
            }

            RemoveLocked(key);
            _entries[key] = entry;
            _bytes += entry.Body.Length;
            while ((_bytes > _maxBytes || _entries.Count > _maxEntries) && _entries.Count > 1)
            {
                string? oldest = null;
                DateTimeOffset oldestAt = DateTimeOffset.MaxValue;
                foreach (KeyValuePair<string, CacheEntry> kv in _entries)
                {
                    if (!kv.Key.Equals(key, StringComparison.Ordinal) && kv.Value.StoredAt <= oldestAt)
                    {
                        oldest = kv.Key;
                        oldestAt = kv.Value.StoredAt;
                    }
                }

                if (oldest is null)
                {
                    break;
                }

                RemoveLocked(oldest);
            }
        }
    }

    /// <inheritdoc />
    public void Remove(string key)
    {
        lock (_gate)
        {
            RemoveLocked(key);
        }
    }

    private void RemoveLocked(string key)
    {
        if (_entries.Remove(key, out CacheEntry? old))
        {
            _bytes -= old.Body.Length;
        }
    }
}

/// <summary>The directives of a <c>Cache-Control</c> field (RFC 9111 §5.2), parsed leniently: unknown directives are kept, malformed ones ignored.</summary>
public sealed class CacheControl
{
    private readonly Dictionary<string, string?> _directives;

    private CacheControl(Dictionary<string, string?> directives) => _directives = directives;

    /// <summary>True for <c>no-store</c>.</summary>
    public bool NoStore => _directives.ContainsKey("no-store");

    /// <summary>True for <c>no-cache</c> (with or without field names; with names it is treated as the whole response, the safe reading).</summary>
    public bool NoCache => _directives.ContainsKey("no-cache");

    /// <summary>True for <c>must-revalidate</c>.</summary>
    public bool MustRevalidate => _directives.ContainsKey("must-revalidate");

    /// <summary><c>max-age</c> in seconds, or null when absent or not a non-negative integer. Values beyond a year-scale cap are clamped to int range.</summary>
    public long? MaxAge => Seconds("max-age");

    /// <summary>Whether a directive is present.</summary>
    /// <param name="name">The directive name, lower case.</param>
    public bool Has(string name) => _directives.ContainsKey(name);

    private long? Seconds(string name)
    {
        if (!_directives.TryGetValue(name, out string? v) || v is null || v.Length == 0 || v.Length > 18)
        {
            return null;
        }

        foreach (char c in v)
        {
            if (c is < '0' or > '9')
            {
                return null;
            }
        }

        return long.Parse(v, CultureInfo.InvariantCulture);
    }

    /// <summary>Parses the joined text of every <c>Cache-Control</c> field line.</summary>
    /// <param name="value">The field value, or null.</param>
    public static CacheControl Parse(string? value)
    {
        var d = new Dictionary<string, string?>(StringComparer.Ordinal);
        if (value is null)
        {
            return new CacheControl(d);
        }

        int i = 0;
        while (i < value.Length && d.Count < 64)
        {
            while (i < value.Length && (value[i] is ',' or ' ' or '\t'))
            {
                i++;
            }

            int start = i;
            while (i < value.Length && value[i] is not ('=' or ',') && value[i] is not (' ' or '\t'))
            {
                i++;
            }

            string name = value[start..i].ToLowerInvariant();
            while (i < value.Length && value[i] is ' ' or '\t')
            {
                i++;
            }

            string? arg = null;
            if (i < value.Length && value[i] == '=')
            {
                i++;
                while (i < value.Length && value[i] is ' ' or '\t')
                {
                    i++;
                }

                if (i < value.Length && value[i] == '"')
                {
                    i++;
                    var sb = new StringBuilder();
                    while (i < value.Length && value[i] != '"')
                    {
                        if (value[i] == '\\' && i + 1 < value.Length)
                        {
                            i++;
                        }

                        sb.Append(value[i]);
                        i++;
                    }

                    i++;
                    arg = sb.ToString();
                }
                else
                {
                    int s2 = i;
                    while (i < value.Length && value[i] != ',')
                    {
                        i++;
                    }

                    arg = value[s2..i].Trim();
                }
            }

            if (name.Length > 0)
            {
                // The first occurrence wins; a conflicting repeat is an error in the response and the first is the stricter reading for max-age only by luck, so keep it simple.
                d.TryAdd(name, arg);
            }
            else
            {
                i++;
            }
        }

        return new CacheControl(d);
    }
}

/// <summary>Freshness and keys for the cache (RFC 9111).</summary>
internal static class HttpCaching
{
    internal static string Key(string method, Uri uri, ReadOnlySpan<byte> body)
    {
        string k = method + " " + uri.AbsoluteUri;
        return body.IsEmpty ? k : k + " #" + Convert.ToHexString(SHA256.HashData(body));
    }

    /// <summary>Parses an HTTP-date (RFC 9110 §5.6.7): IMF-fixdate first, then the two obsolete forms.</summary>
    internal static bool TryParseDate(string? s, out DateTimeOffset when)
    {
        when = default;
        if (string.IsNullOrWhiteSpace(s) || s.Length > 64)
        {
            return false;
        }

        string[] formats =
        [
            "ddd, dd MMM yyyy HH:mm:ss 'GMT'",
            "dddd, dd-MMM-yy HH:mm:ss 'GMT'",
            "ddd MMM d HH:mm:ss yyyy",
            "ddd MMM  d HH:mm:ss yyyy",
        ];
        return DateTimeOffset.TryParseExact(s.Trim(), formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out when);
    }

    /// <summary>Builds a cache entry from a 200 response, or null when the response may not be stored.</summary>
    internal static CacheEntry? Store(int status, IReadOnlyList<KeyValuePair<string, string>> headers, byte[] body, DateTimeOffset now, TimeSpan defaultFreshness, TimeSpan maxFreshness)
    {
        if (status != 200)
        {
            return null;
        }

        CacheControl cc = CacheControl.Parse(HeaderLookup.Joined(headers, "Cache-Control"));
        if (cc.NoStore)
        {
            return null;
        }

        bool haveDate = TryParseDate(HeaderLookup.First(headers, "Date"), out DateTimeOffset date);
        TimeSpan apparentAge = haveDate && now > date ? now - date : TimeSpan.Zero;
        TimeSpan ageHeader = TimeSpan.Zero;
        if (long.TryParse(HeaderLookup.First(headers, "Age"), NumberStyles.None, CultureInfo.InvariantCulture, out long ageSeconds))
        {
            ageHeader = TimeSpan.FromSeconds(Math.Min(ageSeconds, int.MaxValue));
        }

        TimeSpan initialAge = apparentAge > ageHeader ? apparentAge : ageHeader;

        // RFC 9111 §4.2.1: max-age beats Expires; a private cache ignores s-maxage. Without either, the heuristic of §4.2.2 (a tenth of the time since Last-Modified).
        TimeSpan lifetime;
        string? lastModified = HeaderLookup.First(headers, "Last-Modified");
        if (cc.MaxAge is { } maxAge)
        {
            lifetime = TimeSpan.FromSeconds(Math.Min(maxAge, (long)maxFreshness.TotalSeconds));
        }
        else if (TryParseDate(HeaderLookup.First(headers, "Expires"), out DateTimeOffset expires) && haveDate)
        {
            lifetime = expires > date ? expires - date : TimeSpan.Zero;
            if (lifetime > maxFreshness)
            {
                lifetime = maxFreshness;
            }
        }
        else if (HeaderLookup.First(headers, "Expires") is not null)
        {
            // An invalid Expires means "already expired" (RFC 9111 §5.3).
            lifetime = TimeSpan.Zero;
        }
        else if (TryParseDate(lastModified, out DateTimeOffset modified) && haveDate && date > modified)
        {
            lifetime = TimeSpan.FromTicks(Math.Min((date - modified).Ticks / 10, TimeSpan.FromHours(24).Ticks));
        }
        else
        {
            lifetime = defaultFreshness;
        }

        if (cc.NoCache || HeaderLookup.First(headers, "Pragma")?.Contains("no-cache", StringComparison.OrdinalIgnoreCase) == true && !cc.Has("max-age"))
        {
            lifetime = TimeSpan.Zero;
        }

        return new CacheEntry(status, headers, body, now, initialAge, lifetime, cc.MustRevalidate, HeaderLookup.First(headers, "ETag"), lastModified);
    }
}
