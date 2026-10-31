using System.Linq;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

/// <summary>A certificate with its extensions decoded once. A malformed extension value is remembered, never thrown.</summary>
internal sealed class CertView
{
    public CertView(Certificate cert)
    {
        Cert = cert;
        ExtensionCollection ext;
        try
        {
            ext = cert.Extensions;
        }
        catch (X509ParseException)
        {
            ext = ExtensionCollection.Empty;
            Malformed.Add("extensions");
        }

        Ext = ext;
        BasicConstraints = Read<BasicConstraints>("basicConstraints");
        KeyUsage = Read<KeyUsageExtension>("keyUsage");
        ExtendedKeyUsage = Read<ExtendedKeyUsage>("extKeyUsage");
        SubjectAltName = Read<SubjectAlternativeName>("subjectAltName");
        SubjectKeyIdentifier = Read<SubjectKeyIdentifier>("subjectKeyIdentifier");
        AuthorityKeyIdentifier = Read<AuthorityKeyIdentifier>("authorityKeyIdentifier");
        NameConstraints = Read<NameConstraints>("nameConstraints");
        Policies = Read<CertificatePolicies>("certificatePolicies");
        Mappings = Read<PolicyMappings>("policyMappings");
        PolicyConstraints = Read<PolicyConstraints>("policyConstraints");
        InhibitAnyPolicy = Read<InhibitAnyPolicy>("inhibitAnyPolicy");
        CrlDistributionPoints = Read<CrlDistributionPoints>("cRLDistributionPoints");
        AuthorityInfoAccess = Read<AuthorityInfoAccess>("authorityInfoAccess");
        SelfIssued = cert.Issuer.Matches(cert.Subject);
    }

    public Certificate Cert { get; }

    public ExtensionCollection Ext { get; }

    public List<string> Malformed { get; } = [];

    public BasicConstraints? BasicConstraints { get; }

    public KeyUsageExtension? KeyUsage { get; }

    public ExtendedKeyUsage? ExtendedKeyUsage { get; }

    public SubjectAlternativeName? SubjectAltName { get; }

    public SubjectAlternativeName? SubjectAlternativeName => SubjectAltName;

    public SubjectKeyIdentifier? SubjectKeyIdentifier { get; }

    public AuthorityKeyIdentifier? AuthorityKeyIdentifier { get; }

    public NameConstraints? NameConstraints { get; }

    public CertificatePolicies? Policies { get; }

    public PolicyMappings? Mappings { get; }

    public PolicyConstraints? PolicyConstraints { get; }

    public InhibitAnyPolicy? InhibitAnyPolicy { get; }

    public CrlDistributionPoints? CrlDistributionPoints { get; }

    public AuthorityInfoAccess? AuthorityInfoAccess { get; }

    public bool SelfIssued { get; }

    public bool IsCa => BasicConstraints?.IsCA == true;

    private T? Read<T>(string name)
        where T : class, IExtensionValue<T>
    {
        if (!Ext.TryGet(out T? value))
        {
            Malformed.Add(name);
            return null;
        }

        return value;
    }

    /// <summary>The extensions this validator processes (RFC 5280 §4.2); anything else that is critical fails the path (§6.1.4 (o)).</summary>
    public static readonly HashSet<string> Recognised = new(StringComparer.Ordinal)
    {
        KnownOids.BasicConstraints,
        KnownOids.KeyUsage,
        KnownOids.ExtendedKeyUsage,
        KnownOids.SubjectAltName,
        KnownOids.IssuerAltName,
        KnownOids.SubjectKeyIdentifier,
        KnownOids.AuthorityKeyIdentifier,
        KnownOids.NameConstraints,
        KnownOids.CertificatePolicies,
        KnownOids.PolicyMappings,
        KnownOids.PolicyConstraints,
        KnownOids.InhibitAnyPolicy,
        KnownOids.CrlDistributionPoints,
        KnownOids.FreshestCrl,
        KnownOids.AuthorityInfoAccess,
        KnownOids.SubjectInfoAccess,
    };

    /// <summary>The first critical extension that is not recognised, or null.</summary>
    public string? UnrecognisedCritical()
    {
        foreach (Extension e in Ext)
        {
            if (e.Critical && !Recognised.Contains(e.Oid))
            {
                return e.Oid;
            }
        }

        return null;
    }
}
