using System.Net;
using System.Net.Sockets;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>
/// Decides which network addresses a fetch may reach. A URL that arrives inside a certificate or a message (authorityInfoAccess, cRLDistributionPoints, an OCSP
/// location) is chosen by whoever made that object, so by default it may not point at the machine's own services or at the local network: loopback, private
/// (RFC 1918, RFC 4193), link-local, carrier-grade NAT (RFC 6598), multicast, unspecified, documentation, benchmarking and reserved ranges, and the IPv6 forms that
/// wrap an IPv4 address (IPv4-mapped, NAT64, 6to4, IPv4-compatible) when the wrapped address is blocked. Teredo and the local-use NAT64 prefix are blocked outright.
/// </summary>
/// <remarks>
/// The check is applied by <see cref="HttpTransport"/> to the address it is about to connect to, after name resolution, so a host name that resolves to a blocked
/// address (or that changes its answer between lookups, "DNS rebinding") cannot get past it. <see cref="Fetcher"/> additionally refuses literal blocked addresses
/// and <c>localhost</c> names before a transport is asked, which is all a replay transport can see.
/// </remarks>
public sealed class NetworkGuard
{
    private static readonly (IPNetwork Network, string Name)[] Blocked =
    [
        // IPv4 (RFC 6890 and its updates)
        (IPNetwork.Parse("0.0.0.0/8"), "unspecified or 'this network' (RFC 1122)"),
        (IPNetwork.Parse("10.0.0.0/8"), "private (RFC 1918)"),
        (IPNetwork.Parse("100.64.0.0/10"), "carrier-grade NAT (RFC 6598)"),
        (IPNetwork.Parse("127.0.0.0/8"), "loopback (RFC 1122)"),
        (IPNetwork.Parse("169.254.0.0/16"), "link-local (RFC 3927)"),
        (IPNetwork.Parse("172.16.0.0/12"), "private (RFC 1918)"),
        (IPNetwork.Parse("192.0.0.0/24"), "IETF protocol assignments (RFC 6890)"),
        (IPNetwork.Parse("192.0.2.0/24"), "documentation (RFC 5737)"),
        (IPNetwork.Parse("192.88.99.0/24"), "6to4 relay anycast (RFC 7526)"),
        (IPNetwork.Parse("192.168.0.0/16"), "private (RFC 1918)"),
        (IPNetwork.Parse("198.18.0.0/15"), "benchmarking (RFC 2544)"),
        (IPNetwork.Parse("198.51.100.0/24"), "documentation (RFC 5737)"),
        (IPNetwork.Parse("203.0.113.0/24"), "documentation (RFC 5737)"),
        (IPNetwork.Parse("224.0.0.0/4"), "multicast (RFC 5771)"),
        (IPNetwork.Parse("240.0.0.0/4"), "reserved or broadcast (RFC 1112)"),

        // IPv6 (RFC 6890 and its updates). The wrapped-IPv4 prefixes are handled before this table.
        (IPNetwork.Parse("::/128"), "unspecified (RFC 4291)"),
        (IPNetwork.Parse("::1/128"), "loopback (RFC 4291)"),
        (IPNetwork.Parse("64:ff9b:1::/48"), "local-use NAT64 (RFC 8215)"),
        (IPNetwork.Parse("100::/64"), "discard-only (RFC 6666)"),
        (IPNetwork.Parse("2001::/32"), "Teredo (RFC 4380)"),
        (IPNetwork.Parse("2001:2::/48"), "benchmarking (RFC 5180)"),
        (IPNetwork.Parse("2001:10::/28"), "ORCHID (RFC 4843)"),
        (IPNetwork.Parse("2001:db8::/32"), "documentation (RFC 3849)"),
        (IPNetwork.Parse("fc00::/7"), "unique local (RFC 4193)"),
        (IPNetwork.Parse("fe80::/10"), "link-local (RFC 4291)"),
        (IPNetwork.Parse("fec0::/10"), "site-local, deprecated (RFC 3879)"),
        (IPNetwork.Parse("ff00::/8"), "multicast (RFC 4291)"),
    ];

    /// <summary>The guard used when none is given: every blocked range stays blocked.</summary>
    public static NetworkGuard Default { get; } = new();

    /// <summary>Lets every address through. For tests and for a deployment that fetches only from its own network.</summary>
    public static NetworkGuard AllowAll { get; } = new() { AllowPrivateAddresses = true };

    /// <summary>When true no address is refused (default false).</summary>
    public bool AllowPrivateAddresses { get; init; }

    /// <summary>Networks that are permitted although they are in a blocked range, for example the address of an internal responder. An address is permitted when it, or the IPv4 address it wraps, is in one of them.</summary>
    public IReadOnlyList<IPNetwork> AllowedNetworks { get; init; } = [];

    /// <summary>Says why <paramref name="address"/> may not be connected to.</summary>
    /// <param name="address">The address about to be used.</param>
    /// <returns>The name of the blocked range (for example "private (RFC 1918)"), or null when the address is allowed.</returns>
    public string? Check(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (AllowPrivateAddresses)
        {
            return null;
        }

        string? why = Classify(address);
        if (why is null)
        {
            return null;
        }

        IPAddress inner = Unwrap(address) ?? address;
        foreach (IPNetwork net in AllowedNetworks)
        {
            if (net.Contains(address) || net.Contains(inner))
            {
                return null;
            }
        }

        return why;
    }

    /// <summary>Checks the host part of a URI that is not resolved yet: literal addresses in any notation the URI parser accepts, and the names <c>localhost</c> and <c>*.localhost</c> (RFC 6761 §6.3).</summary>
    /// <param name="uri">An absolute URI.</param>
    /// <returns>The reason, or null when nothing in the URI text is blocked.</returns>
    public string? CheckLiteral(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (AllowPrivateAddresses)
        {
            return null;
        }

        if (uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6)
        {
            // IdnHost keeps the brackets off an IPv6 literal and has already normalised 0x7f.1, 2130706433 and the like.
            return IPAddress.TryParse(uri.IdnHost, out IPAddress? ip) ? Check(ip) : "unparseable address literal";
        }

        string host = uri.IdnHost.TrimEnd('.');
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return "loopback name (RFC 6761)";
        }

        return null;
    }

    private static string? Classify(IPAddress address)
    {
        IPAddress? inner = Unwrap(address);
        if (inner is not null)
        {
            // The wrapped address decides: ::ffff:10.0.0.1 is private, ::ffff:93.184.216.34 is not.
            string? innerWhy = Classify(inner);
            return innerWhy is null ? null : innerWhy + ", wrapped in an IPv6 address";
        }

        foreach ((IPNetwork net, string name) in Blocked)
        {
            if (net.Contains(address))
            {
                return name;
            }
        }

        return null;
    }

    /// <summary>The IPv4 address an IPv6 address carries, or null when it carries none.</summary>
    private static IPAddress? Unwrap(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return null;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        byte[] b = address.GetAddressBytes();
        bool zeroTo10 = b.AsSpan(0, 10).IndexOfAnyExcept((byte)0) < 0;

        bool zeroTo12 = zeroTo10 && b[10] == 0 && b[11] == 0;

        // The deprecated IPv4-compatible form ::a.b.c.d (RFC 4291 §2.5.5.1); :: and ::1 stay IPv6 literals.
        if (zeroTo12 && (b[12] != 0 || b[13] != 0 || b[14] != 0 || b[15] > 1))
        {
            return new IPAddress(b.AsSpan(12, 4));
        }

        // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052).
        if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B && b.AsSpan(4, 8).IndexOfAnyExcept((byte)0) < 0)
        {
            return new IPAddress(b.AsSpan(12, 4));
        }

        // 6to4 2002::/16 carries the IPv4 address in bits 16 to 47 (RFC 3056).
        if (b[0] == 0x20 && b[1] == 0x02)
        {
            return new IPAddress(b.AsSpan(2, 4));
        }

        return null;
    }
}
