using System.Linq;
using System.Globalization;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

internal sealed partial class Engine
{
    private static void WebPkiTarget(CertView v, CertResults r, WebPkiProfile wp)
    {
        const string Br = "CA/Browser Forum Baseline Requirements §7.1.2.7";
        if (wp.EnforceBaselineRequirements)
        {
            if (v.BasicConstraints is { IsCA: true })
            {
                r.Fail(ValidationRule.WebPkiProfile, "a server certificate must not be a CA", Br);
            }

            if (v.KeyUsage is { } ku && (ku.Usages & (KeyUsages.KeyCertSign | KeyUsages.CrlSign)) != 0)
            {
                r.Fail(ValidationRule.WebPkiProfile, "a server certificate's keyUsage must not include keyCertSign or cRLSign", Br);
            }

            PublicKeyInfo key = v.Cert.PublicKey;
            if (key.KeyAlgorithm is KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss && key.KeySizeBits is > 0 and < 2048)
            {
                r.Fail(ValidationRule.WebPkiProfile, $"RSA key of {key.KeySizeBits} bits is below 2048", "CA/Browser Forum Baseline Requirements §6.1.5");
            }
        }

        if (wp.RequireServerAuth)
        {
            // Baseline Requirements §7.1.2.7.6: a server certificate states serverAuth, not anyExtendedKeyUsage, and the extension is not critical.
            if (wp.EnforceBaselineRequirements)
            {
                if (v.ExtendedKeyUsage is not { } eku0 || !eku0.Purposes.Contains(KnownOids.ServerAuth))
                {
                    r.Fail(ValidationRule.WebPkiProfile, "a server certificate must have extKeyUsage containing serverAuth", Br);
                }
                else if (eku0.Purposes.Contains(KnownOids.AnyExtendedKeyUsage))
                {
                    r.Fail(ValidationRule.WebPkiProfile, "a server certificate must not use anyExtendedKeyUsage", Br);
                }
                else if (v.Ext.IsCritical(KnownOids.ExtendedKeyUsage) == true)
                {
                    r.Fail(ValidationRule.WebPkiProfile, "extKeyUsage of a server certificate is marked critical", Br);
                }
            }
            else if (v.ExtendedKeyUsage is { } eku && !eku.Allows(KnownOids.ServerAuth))
            {
                r.Fail(ValidationRule.WebPkiProfile, "extKeyUsage does not include serverAuth", Br);
            }

            if (v.SubjectAltName is null || !v.SubjectAltName.Names.Any(n => n.Kind is GeneralNameKind.DnsName or GeneralNameKind.IPAddress))
            {
                r.Fail(ValidationRule.WebPkiProfile, "a server certificate needs a dNSName or iPAddress in subjectAltName", "RFC 9525 §6.1; Baseline Requirements §7.1.2.7.12");
            }
        }

        if (wp.EnforceBaselineRequirements)
        {
            if (!v.Cert.Subject.IsEmpty && v.Ext.IsCritical(KnownOids.SubjectAltName) == true)
            {
                r.Fail(ValidationRule.WebPkiProfile, "subjectAltName is critical although the subject is not empty", "RFC 5280 §4.2.1.6; Baseline Requirements §7.1.2.7.12");
            }

            string? cn = wp.RequireCommonNameInSan ? CommonNameProblem(v) : null;
            if (cn is not null)
            {
                r.Fail(ValidationRule.WebPkiProfile, cn, "Baseline Requirements §7.1.4.3");
            }
        }

        if (wp.ServerName is { } name)
        {
            string? why = HostMismatch(v, name);
            if (why is null)
            {
                r.Pass(ValidationRule.HostName, $"{name} matches a subjectAltName entry", "RFC 9525 §6.3");
            }
            else
            {
                r.Fail(ValidationRule.HostName, why, "RFC 9525 §6.3");
            }
        }
    }

    /// <summary>Null when <paramref name="name"/> matches the certificate; otherwise the reason it does not. Only subjectAltName is used, never the common name (RFC 9525 §2).</summary>
    internal static string? HostMismatch(CertView v, string name)
    {
        if (v.SubjectAltName is null)
        {
            return "the certificate has no subjectAltName to match against";
        }

        if (TryParseIp(name, out byte[] ip))
        {
            foreach (GeneralName g in v.SubjectAltName.Names)
            {
                if (g.Kind == GeneralNameKind.IPAddress && g.IPAddressBytes.Span.SequenceEqual(ip))
                {
                    return null;
                }
            }

            return $"no iPAddress entry equals {name}";
        }

        string host = name.TrimEnd('.').ToLowerInvariant();
        foreach (GeneralName g in v.SubjectAltName.Names)
        {
            if (g.Kind == GeneralNameKind.DnsName && DnsMatches((g.Value ?? string.Empty).ToLowerInvariant(), host))
            {
                return null;
            }
        }

        return string.Create(CultureInfo.InvariantCulture, $"no dNSName entry matches {name}");
    }

    // RFC 9525 §6.3: a wildcard is only the whole left-most label and stands for exactly one label. That label may be an A-label host:
    // only a wildcard INSIDE an IDN label ("xn--*", "b*cher") is forbidden, and such patterns never reach here because only a leading "*." is a wildcard.
    internal static bool DnsMatches(string pattern, string host)
    {
        pattern = pattern.TrimEnd('.');
        if (pattern.Length == 0 || host.Length == 0)
        {
            return false;
        }

        if (!pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            return pattern == host;
        }

        string suffix = pattern[1..]; // ".example.com"
        if (suffix.Contains('*', StringComparison.Ordinal) || suffix.Count(c => c == '.') < 2)
        {
            return false; // "*.com" and "a.*.b" are not accepted
        }

        int dot = host.IndexOf('.', StringComparison.Ordinal);
        if (dot <= 0)
        {
            return false;
        }

        return host[dot..] == suffix;
    }
}
