using System.Linq;
using System.Globalization;
using System.Text;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

/// <summary>
/// The name constraints accumulated down a path (RFC 5280 §4.2.1.10, §6.1.3 (b) and (c)). Every certificate's constraints are kept as its own set:
/// a name must satisfy each of them, which is the intersection of the permitted subtrees and the union of the excluded ones.
/// </summary>
internal sealed class NameConstraintState
{
    private readonly List<(NameConstraints Constraints, bool Critical)> _sets = [];
    private readonly long _budget;
    private long _spent;

    public NameConstraintState(long budget) => _budget = budget;

    public bool Exhausted => _spent > _budget;

    public bool IsEmpty => _sets.Count == 0;

    public void Add(NameConstraints nc, bool critical) => _sets.Add((nc, critical));

    /// <summary>Checks one certificate's subject and alternative names against everything accumulated so far.</summary>
    public string? Check(Certificate cert)
    {
        if (_sets.Count == 0)
        {
            return null;
        }

        SubjectAlternativeName? san;
        try
        {
            san = cert.Extensions.Get<SubjectAlternativeName>();
        }
        catch (X509ParseException)
        {
            return "subjectAltName is malformed";
        }

        if (!cert.Subject.IsEmpty)
        {
            string? r = CheckDirectoryName(cert.Subject, "subject");
            if (r is not null)
            {
                return r;
            }

            // RFC 5280 §4.2.1.6: an emailAddress in the subject is constrained like an rfc822Name.
            foreach (RelativeDistinguishedName rdn in cert.Subject.Rdns)
            {
                foreach (AttributeTypeAndValue atv in rdn.Attributes)
                {
                    if (atv.Type == KnownOids.EmailAddress && atv.Text is string mail)
                    {
                        r = CheckSimple(GeneralNameKind.Rfc822Name, mail, "subject emailAddress");
                        if (r is not null)
                        {
                            return r;
                        }
                    }
                }
            }
        }

        if (san is not null)
        {
            foreach (GeneralName n in san.Names)
            {
                string? r = CheckName(n);
                if (r is not null)
                {
                    return r;
                }
            }
        }

        return Exhausted ? "name-constraint work limit reached" : null;
    }

    private string? CheckName(GeneralName n)
    {
        switch (n.Kind)
        {
            case GeneralNameKind.DnsName:
            case GeneralNameKind.Rfc822Name:
            case GeneralNameKind.Uri:
                return CheckSimple(n.Kind, n.Value ?? string.Empty, "subjectAltName " + n.Kind);
            case GeneralNameKind.IPAddress:
                return CheckIp(n.IPAddressBytes.Span);
            case GeneralNameKind.DirectoryName:
                DistinguishedName? dn;
                try
                {
                    dn = n.DirectoryName;
                }
                catch (X509ParseException)
                {
                    return "directoryName in subjectAltName is malformed";
                }

                return dn is null ? null : CheckDirectoryName(dn, "subjectAltName directoryName");
            default:
                // A form we cannot compare. A critical constraint of that form makes the answer unknowable, so it fails (§4.2.1.10).
                foreach ((NameConstraints c, bool critical) in _sets)
                {
                    if (critical && (HasKind(c.PermittedSubtrees, n.Kind) || HasKind(c.ExcludedSubtrees, n.Kind)))
                    {
                        return $"a critical name constraint covers {n.Kind}, which cannot be evaluated";
                    }
                }

                return null;
        }
    }

    private static bool HasKind(IReadOnlyList<GeneralSubtree>? list, GeneralNameKind kind) => list is not null && list.Any(s => s.Base.Kind == kind);

    private string? CheckSimple(GeneralNameKind kind, string value, string what)
    {
        foreach ((NameConstraints c, _) in _sets)
        {
            if (c.ExcludedSubtrees is not null)
            {
                foreach (GeneralSubtree s in c.ExcludedSubtrees)
                {
                    _spent++;
                    if (s.Base.Kind == kind && (MatchSimple(kind, s.Base.Value ?? string.Empty, value) || WildcardOverlaps(kind, s.Base.Value ?? string.Empty, value)))
                    {
                        return $"{what} {value} is inside an excluded subtree";
                    }
                }
            }

            if (c.PermittedSubtrees is not null && HasKind(c.PermittedSubtrees, kind))
            {
                bool any = false;
                foreach (GeneralSubtree s in c.PermittedSubtrees)
                {
                    _spent++;
                    if (s.Base.Kind == kind && MatchSimple(kind, s.Base.Value ?? string.Empty, value))
                    {
                        any = true;
                        break;
                    }
                }

                if (!any)
                {
                    return $"{what} {value} is outside every permitted subtree";
                }
            }

            if (Exhausted)
            {
                return "name-constraint work limit reached";
            }
        }

        return null;
    }

    private string? CheckIp(ReadOnlySpan<byte> ip)
    {
        foreach ((NameConstraints c, _) in _sets)
        {
            if (c.ExcludedSubtrees is not null)
            {
                foreach (GeneralSubtree s in c.ExcludedSubtrees)
                {
                    _spent++;
                    if (s.Base.Kind == GeneralNameKind.IPAddress && IpInside(s.Base.IPAddressBytes.Span, ip))
                    {
                        return "an iPAddress is inside an excluded subtree";
                    }
                }
            }

            if (c.PermittedSubtrees is not null && HasKind(c.PermittedSubtrees, GeneralNameKind.IPAddress))
            {
                bool any = false;
                foreach (GeneralSubtree s in c.PermittedSubtrees)
                {
                    _spent++;
                    if (s.Base.Kind == GeneralNameKind.IPAddress && IpInside(s.Base.IPAddressBytes.Span, ip))
                    {
                        any = true;
                        break;
                    }
                }

                if (!any)
                {
                    return "an iPAddress is outside every permitted subtree";
                }
            }
        }

        return null;
    }

    private string? CheckDirectoryName(DistinguishedName name, string what)
    {
        foreach ((NameConstraints c, _) in _sets)
        {
            if (c.ExcludedSubtrees is not null)
            {
                foreach (GeneralSubtree s in c.ExcludedSubtrees)
                {
                    _spent++;
                    if (s.Base.Kind == GeneralNameKind.DirectoryName && DnInside(s.Base, name))
                    {
                        return $"{what} is inside an excluded directoryName subtree";
                    }
                }
            }

            if (c.PermittedSubtrees is not null && HasKind(c.PermittedSubtrees, GeneralNameKind.DirectoryName))
            {
                bool any = false;
                foreach (GeneralSubtree s in c.PermittedSubtrees)
                {
                    _spent++;
                    if (s.Base.Kind == GeneralNameKind.DirectoryName && DnInside(s.Base, name))
                    {
                        any = true;
                        break;
                    }
                }

                if (!any)
                {
                    return $"{what} is outside every permitted directoryName subtree";
                }
            }

            if (Exhausted)
            {
                return "name-constraint work limit reached";
            }
        }

        return null;
    }

    private static bool DnInside(GeneralName constraint, DistinguishedName name)
    {
        DistinguishedName? cdn;
        try
        {
            cdn = constraint.DirectoryName;
        }
        catch (X509ParseException)
        {
            return false;
        }

        if (cdn is null)
        {
            return false;
        }

        IReadOnlyList<RelativeDistinguishedName> c = cdn.Rdns;
        IReadOnlyList<RelativeDistinguishedName> n = name.Rdns;
        if (c.Count > n.Count)
        {
            return false;
        }

        // RFC 5280 §4.2.1.10: a DN is within a subtree when the constraint's RDN sequence is a prefix of it.
        for (int i = 0; i < c.Count; i++)
        {
            if (c[i].Encoded.Span.SequenceEqual(n[i].Encoded.Span))
            {
                continue;
            }

            if (!RdnMatches(c[i], n[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool RdnMatches(RelativeDistinguishedName a, RelativeDistinguishedName b)
    {
        DistinguishedName da = DistinguishedName.Parse(DerWriter.Sequence(a.Encoded.ToArray()));
        DistinguishedName db = DistinguishedName.Parse(DerWriter.Sequence(b.Encoded.ToArray()));
        return da.Matches(db);
    }

    internal static bool IpInside(ReadOnlySpan<byte> constraint, ReadOnlySpan<byte> ip)
    {
        // RFC 5280 §4.2.1.10: a constraint is an address and a mask of the same length (8 or 32 octets); the name is 4 or 16.
        if (constraint.Length != ip.Length * 2 || (ip.Length != 4 && ip.Length != 16))
        {
            return false;
        }

        int n = ip.Length;
        for (int i = 0; i < n; i++)
        {
            byte mask = constraint[n + i];
            if ((constraint[i] & mask) != (ip[i] & mask))
            {
                return false;
            }
        }

        return true;
    }

    internal static bool MatchSimple(GeneralNameKind kind, string constraint, string value) => kind switch
    {
        GeneralNameKind.DnsName => DnsInside(constraint, value),
        GeneralNameKind.Rfc822Name => EmailInside(constraint, value),
        GeneralNameKind.Uri => UriInside(constraint, value),
        _ => false,
    };

    internal static bool DnsInside(string constraint, string name)
    {
        // RFC 5280 §4.2.1.10: "host.example.com" is within "example.com"; a constraint with a leading dot matches subdomains only.
        string c = constraint.ToLowerInvariant();
        string n = name.ToLowerInvariant();
        if (c.Length == 0)
        {
            return true;
        }

        if (c[0] == '.')
        {
            return n.Length > c.Length && n.EndsWith(c, StringComparison.Ordinal);
        }

        return n == c || (n.Length > c.Length && n.EndsWith(c, StringComparison.Ordinal) && n[n.Length - c.Length - 1] == '.');
    }

    internal static bool EmailInside(string constraint, string mailbox)
    {
        int at = mailbox.LastIndexOf('@');
        if (at < 0)
        {
            return false;
        }

        string local = mailbox[..at];
        string domain = mailbox[(at + 1)..];
        int cat = constraint.IndexOf('@', StringComparison.Ordinal);
        if (cat >= 0)
        {
            // A full mailbox: the local part is case-sensitive, the domain is not (RFC 5321 §2.4).
            return string.Equals(constraint[..cat], local, StringComparison.Ordinal)
                && string.Equals(constraint[(cat + 1)..], domain, StringComparison.OrdinalIgnoreCase);
        }

        if (constraint.Length > 0 && constraint[0] == '.')
        {
            return domain.Length > constraint.Length && domain.EndsWith(constraint, StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(constraint, domain, StringComparison.OrdinalIgnoreCase);
    }

    // A wildcard such as *.example.com may stand for any name one label below example.com, so it overlaps every excluded subtree it could reach.
    internal static bool WildcardOverlaps(GeneralNameKind kind, string constraint, string value)
    {
        if (kind != GeneralNameKind.DnsName || !value.StartsWith("*.", StringComparison.Ordinal))
        {
            return false;
        }

        string tail = value[1..].ToLowerInvariant(); // ".example.com"
        string c = constraint.ToLowerInvariant();
        string cc = c.StartsWith('.') ? c : "." + c;
        return cc.EndsWith(tail, StringComparison.Ordinal) || tail.EndsWith(cc, StringComparison.Ordinal);
    }

    internal static bool UriInside(string constraint, string uri)
    {
        string? host = UriHost(uri);
        if (host is null || LooksLikeIp(host))
        {
            return false;
        }

        // RFC 5280 §4.2.1.10: for a URI, "example.com" names that one host and ".example.com" the hosts below it.
        return constraint.StartsWith('.')
            ? DnsInside(constraint, host)
            : string.Equals(constraint, host, StringComparison.OrdinalIgnoreCase);
    }

    internal static string? UriHost(string uri)
    {
        int s = uri.IndexOf("://", StringComparison.Ordinal);
        if (s <= 0)
        {
            return null;
        }

        string rest = uri[(s + 3)..];
        int end = rest.IndexOfAny(['/', '?', '#']);
        string auth = end < 0 ? rest : rest[..end];
        int at = auth.LastIndexOf('@');
        if (at >= 0)
        {
            auth = auth[(at + 1)..];
        }

        if (auth.StartsWith('['))
        {
            return auth; // an IPv6 literal: reported as an address by LooksLikeIp
        }

        int colon = auth.LastIndexOf(':');
        if (colon >= 0)
        {
            auth = auth[..colon];
        }

        return auth.Length == 0 ? null : auth;
    }

    private static bool LooksLikeIp(string host)
    {
        if (host.StartsWith('['))
        {
            return true;
        }

        string[] parts = host.Split('.');
        return parts.Length == 4 && parts.All(p => p.Length is > 0 and <= 3 && p.All(char.IsAsciiDigit));
    }

    /// <summary>Text for an IP address, for reports.</summary>
    internal static string IpText(ReadOnlySpan<byte> ip)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < ip.Length; i++)
        {
            if (i > 0)
            {
                sb.Append(ip.Length == 4 ? '.' : ':');
            }

            sb.Append(ip[i].ToString(ip.Length == 4 ? "D" : "x2", CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }
}
