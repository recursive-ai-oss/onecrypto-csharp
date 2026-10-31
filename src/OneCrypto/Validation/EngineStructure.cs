using System.Linq;
using System.Net;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

internal sealed partial class Engine
{
    /// <summary>
    /// Checks a certificate for what RFC 5280 requires of its form (§4.1, §4.2). Malformed values and duplicated extensions always fail;
    /// the rest ("MUST" rules for CAs, such as critical flags and key identifiers) fail only under <see cref="ValidationOptions.StrictStructure"/>.
    /// </summary>
    private void StructureChecks(CertView v, CertResults r, bool last, bool isAnchor)
    {
        Certificate c = v.Cert;
        if (v.Malformed.Count > 0)
        {
            r.Fail(ValidationRule.Structure, $"extension value is malformed: {string.Join(", ", v.Malformed)}", "RFC 5280 §4.2");
            return;
        }

        if (v.Ext.HasDuplicates)
        {
            r.Fail(ValidationRule.Structure, "an extension appears more than once", "RFC 5280 §4.2");
            return;
        }

        if (c.NotAfter < c.NotBefore)
        {
            r.Fail(ValidationRule.Structure, "notAfter is before notBefore", "RFC 5280 §4.1.2.5");
            return;
        }

        if (!_o.StrictStructure)
        {
            r.Pass(ValidationRule.Structure, "structure accepted", "RFC 5280 §4.1, §4.2");
            return;
        }

        string? bad = StrictProblem(v, last, isAnchor);
        if (bad is null)
        {
            r.Pass(ValidationRule.Structure, "structure accepted", "RFC 5280 §4.1, §4.2");
        }
        else
        {
            r.Fail(ValidationRule.Structure, bad, "RFC 5280 §4");
        }
    }

    private string? StrictProblem(CertView v, bool last, bool isAnchor)
    {
        Certificate c = v.Cert;
        bool webpki = _o.WebPki?.EnforceBaselineRequirements == true;
        if (c.Issuer.IsEmpty && !isAnchor)
        {
            return "the issuer name is empty (§4.1.2.4)";
        }

        // A trust anchor is a name and a key (RFC 5937 §2); nothing about its serial number matters.
        ReadOnlySpan<byte> serial = c.SerialNumber.Span;
        int sl = serial.Length;
        while (sl > 1 && serial[serial.Length - sl] == 0)
        {
            sl--;
        }

        if (!isAnchor && c.SerialNumberValue.Sign <= 0)
        {
            return "the serial number is not a positive integer (§4.1.2.2)";
        }

        if (!isAnchor && sl > 20)
        {
            return $"the serial number has {sl} octets, at most 20 are allowed (§4.1.2.2)";
        }

        if (c.Subject.IsEmpty && !(v.SubjectAltName is not null && v.Ext.IsCritical(KnownOids.SubjectAltName) == true))
        {
            return "the subject is empty and subjectAltName is missing or not critical (§4.1.2.6, §4.2.1.6)";
        }

        if (c.Version < 3 && c.Extensions.Count > 0)
        {
            return "extensions in a version 1 or 2 certificate (§4.1.2.1)";
        }

        // §4.2.1.1, §4.2.1.2, §4.2.2.1, §4.2.1.11: these extensions are never critical, except policyConstraints, which always is.
        if (v.Ext.IsCritical(KnownOids.SubjectKeyIdentifier) == true)
        {
            return "subjectKeyIdentifier is marked critical (§4.2.1.2)";
        }

        if (v.Ext.IsCritical(KnownOids.AuthorityKeyIdentifier) == true)
        {
            return "authorityKeyIdentifier is marked critical (§4.2.1.1)";
        }

        if (v.Ext.IsCritical(KnownOids.AuthorityInfoAccess) == true)
        {
            return "authorityInfoAccess is marked critical (§4.2.2.1)";
        }

        if (v.Ext.IsCritical(KnownOids.PolicyConstraints) == false)
        {
            return "policyConstraints is not marked critical (§4.2.1.11)";
        }

        bool ca = v.IsCa;
        if (c.Version >= 3 && isAnchor && v.BasicConstraints is null)
        {
            return "the trust anchor certificate has no basicConstraints (§4.2.1.9)";
        }

        if (ca)
        {
            if (v.SubjectKeyIdentifier is null)
            {
                return "a CA certificate lacks subjectKeyIdentifier (§4.2.1.2)";
            }

            if (v.Ext.IsCritical(KnownOids.BasicConstraints) != true)
            {
                return "basicConstraints of a CA certificate is not marked critical (§4.2.1.9)";
            }
        }

        // §4.2.1.9: keyCertSign only goes with cA.
        if (!ca && v.KeyUsage is { } kuc && (kuc.Usages & KeyUsages.KeyCertSign) != 0)
        {
            return "keyUsage asserts keyCertSign but basicConstraints does not assert cA (§4.2.1.9)";
        }

        // §4.2.1.1: every certificate not self-signed names its issuer's key. A trust anchor is exempt: it is trusted for its name and key.
        if (!isAnchor && !v.SelfIssued && (v.AuthorityKeyIdentifier is null || v.AuthorityKeyIdentifier.KeyIdentifier.IsEmpty))
        {
            return "authorityKeyIdentifier with a keyIdentifier is missing (§4.2.1.1)";
        }

        if (v.NameConstraints is { } nc)
        {
            if (!ca)
            {
                return "nameConstraints in a certificate that is not a CA (§4.2.1.10)";
            }

            if (!webpki && v.Ext.IsCritical(KnownOids.NameConstraints) != true)
            {
                return "nameConstraints is not marked critical (§4.2.1.10)";
            }

            if (nc.PermittedSubtrees is null && nc.ExcludedSubtrees is null)
            {
                return "nameConstraints has neither permittedSubtrees nor excludedSubtrees (§4.2.1.10)";
            }

            foreach (GeneralSubtree s in (nc.PermittedSubtrees ?? []).Concat(nc.ExcludedSubtrees ?? []))
            {
                if (s.Base.Kind == GeneralNameKind.DnsName && (s.Base.Value ?? string.Empty).StartsWith('.'))
                {
                    return "a dNSName constraint begins with a period (§4.2.1.10)";
                }

                if (s.Minimum != 0 || s.Maximum is not null)
                {
                    return "a name constraint uses minimum or maximum (§4.2.1.10)";
                }
            }
        }

        if (v.SubjectAltName is { } san)
        {
            foreach (GeneralName n in san.Names)
            {
                if (n.Kind == GeneralNameKind.DnsName && !ValidDnsName(n.Value ?? string.Empty, allowWildcard: true))
                {
                    return $"dNSName \"{n.Value}\" is not in the preferred name syntax (§4.2.1.6)";
                }

                if (n.Kind == GeneralNameKind.Rfc822Name && !ValidMailbox(n.Value ?? string.Empty))
                {
                    return $"rfc822Name \"{n.Value}\" is not a mailbox (§4.2.1.6)";
                }

                if (n.Kind == GeneralNameKind.IPAddress && n.IPAddressBytes.Length is not (4 or 16))
                {
                    return "an iPAddress is not 4 or 16 octets (§4.2.1.6)";
                }
            }
        }

        // RFC 9881 §4, RFC 8410 §3: a key that only signs must not be certified for key agreement or encipherment.
        if (c.PublicKey.KeyAlgorithm is KeyAlgorithm.MlDsa or KeyAlgorithm.SlhDsa or KeyAlgorithm.Ed25519 or KeyAlgorithm.Ed448 && v.KeyUsage is { } sku
            && (sku.Usages & (KeyUsages.KeyEncipherment | KeyUsages.DataEncipherment | KeyUsages.KeyAgreement | KeyUsages.EncipherOnly | KeyUsages.DecipherOnly)) != 0)
        {
            return $"keyUsage {sku.Usages} is not allowed for a signature-only {c.PublicKey.KeyAlgorithm} key (RFC 9881 §4, RFC 8410 §3)";
        }

        _ = last;
        return null;
    }

    internal static bool ValidDnsName(string s, bool allowWildcard)
    {
        if (s.Length is 0 or > 253)
        {
            return false;
        }

        string[] labels = s.Split('.');
        for (int i = 0; i < labels.Length; i++)
        {
            string l = labels[i];
            if (l.Length is 0 or > 63)
            {
                return false;
            }

            if (l == "*")
            {
                if (!allowWildcard || i != 0)
                {
                    return false;
                }

                continue;
            }

            if (l[0] == '-' || l[^1] == '-')
            {
                return false;
            }

            foreach (char ch in l)
            {
                if (!(char.IsAsciiLetterOrDigit(ch) || ch == '-'))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool ValidMailbox(string s)
    {
        int at = s.IndexOf('@', StringComparison.Ordinal);
        return at > 0 && at == s.LastIndexOf('@') && at < s.Length - 1;
    }

    // ------------------------------------------------------------ server-authentication profile, per certificate

    private void WebPkiCertificate(CertView v, CertResults r, bool isAnchor)
    {
        if (_o.WebPki is not { EnforceBaselineRequirements: true })
        {
            return;
        }

        // Baseline Requirements §6.1.5 and §7.1.3.1: the key types and sizes CAs may certify.
        PublicKeyInfo key = v.Cert.PublicKey;
        string? bad = key.KeyAlgorithm switch
        {
            KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss => key.KeySizeBits < 2048 ? $"RSA key of {key.KeySizeBits} bits is below 2048"
                : key.KeySizeBits % 8 != 0 ? $"RSA key of {key.KeySizeBits} bits is not a multiple of 8" : null,
            KeyAlgorithm.EllipticCurve => key.CurveOid is KnownOids.P256 or KnownOids.P384 or KnownOids.P521 ? null
                : key.CurveOid is null ? "EC key parameters are not a named curve" : "EC curve is not P-256, P-384 or P-521",
            KeyAlgorithm.Unknown => "public key algorithm is not permitted",
            _ => null,
        };
        if (bad is not null)
        {
            r.Fail(ValidationRule.WebPkiProfile, bad, "CA/Browser Forum Baseline Requirements §6.1.5, §7.1.3.1");
        }

        if (isAnchor)
        {
            // §7.1.2.1: a root has no extKeyUsage; its authorityKeyIdentifier, if any, repeats its own key identifier and nothing else.
            if (v.ExtendedKeyUsage is not null)
            {
                r.Fail(ValidationRule.WebPkiProfile, "a root certificate carries extKeyUsage", "CA/Browser Forum Baseline Requirements §7.1.2.1.2");
            }

            if (v.AuthorityKeyIdentifier is { } aki)
            {
                bool keyIdOk = !aki.KeyIdentifier.IsEmpty && v.SubjectKeyIdentifier is { } ski && ski.KeyIdentifier.Span.SequenceEqual(aki.KeyIdentifier.Span);
                if (!keyIdOk || aki.AuthorityCertIssuer is { Count: > 0 } || !aki.AuthorityCertSerialNumber.IsEmpty)
                {
                    r.Fail(ValidationRule.WebPkiProfile, "a root's authorityKeyIdentifier must hold only a keyIdentifier equal to its subjectKeyIdentifier", "CA/Browser Forum Baseline Requirements §7.1.2.1.3");
                }
            }
        }
    }

    private static string? CommonNameProblem(CertView v)
    {
        // Baseline Requirements §7.1.4.3: a commonName, if present, repeats one of the subjectAltName entries exactly as encoded there.
        foreach (RelativeDistinguishedName rdn in v.Cert.Subject.Rdns)
        {
            foreach (AttributeTypeAndValue atv in rdn.Attributes)
            {
                if (atv.Type != KnownOids.CommonName)
                {
                    continue;
                }

                string cn = atv.Text ?? string.Empty;
                if (v.SubjectAltName is null)
                {
                    return "the commonName has no subjectAltName entry to repeat";
                }

                foreach (GeneralName g in v.SubjectAltName.Names)
                {
                    if (g.Kind == GeneralNameKind.DnsName && string.Equals(g.Value, cn, StringComparison.Ordinal))
                    {
                        return null;
                    }

                    if (g.Kind == GeneralNameKind.IPAddress && new IPAddress(g.IPAddressBytes.Span).ToString() == cn)
                    {
                        return null;
                    }
                }

                return $"the commonName \"{cn}\" is not repeated exactly in subjectAltName";
            }
        }

        return null;
    }
}
