using System.Linq;
using System.Numerics;
using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto.X509;

/// <summary>The bits of the keyUsage extension (RFC 5280 §4.2.1.3).</summary>
[Flags]
public enum KeyUsages
{
    /// <summary>No bit set.</summary>
    None = 0,
    /// <summary>digitalSignature (bit 0).</summary>
    DigitalSignature = 1 << 0,
    /// <summary>nonRepudiation / contentCommitment (bit 1).</summary>
    NonRepudiation = 1 << 1,
    /// <summary>keyEncipherment (bit 2).</summary>
    KeyEncipherment = 1 << 2,
    /// <summary>dataEncipherment (bit 3).</summary>
    DataEncipherment = 1 << 3,
    /// <summary>keyAgreement (bit 4).</summary>
    KeyAgreement = 1 << 4,
    /// <summary>keyCertSign (bit 5).</summary>
    KeyCertSign = 1 << 5,
    /// <summary>cRLSign (bit 6).</summary>
    CrlSign = 1 << 6,
    /// <summary>encipherOnly (bit 7).</summary>
    EncipherOnly = 1 << 7,
    /// <summary>decipherOnly (bit 8).</summary>
    DecipherOnly = 1 << 8,
}

/// <summary>The bits of RevocationReasons (RFC 5280 §4.2.1.13). Bit 0 is unused in the standard and not offered here.</summary>
[Flags]
public enum RevocationReasons
{
    /// <summary>No bit set.</summary>
    None = 0,
    /// <summary>keyCompromise (bit 1).</summary>
    KeyCompromise = 1 << 1,
    /// <summary>cACompromise (bit 2).</summary>
    CACompromise = 1 << 2,
    /// <summary>affiliationChanged (bit 3).</summary>
    AffiliationChanged = 1 << 3,
    /// <summary>superseded (bit 4).</summary>
    Superseded = 1 << 4,
    /// <summary>cessationOfOperation (bit 5).</summary>
    CessationOfOperation = 1 << 5,
    /// <summary>certificateHold (bit 6).</summary>
    CertificateHold = 1 << 6,
    /// <summary>privilegeWithdrawn (bit 7).</summary>
    PrivilegeWithdrawn = 1 << 7,
    /// <summary>aACompromise (bit 8).</summary>
    AACompromise = 1 << 8,
}

/// <summary>The values of CRLReason (RFC 5280 §5.3.1).</summary>
public enum RevocationReason
{
    /// <summary>unspecified (0).</summary>
    Unspecified = 0,
    /// <summary>keyCompromise (1).</summary>
    KeyCompromise = 1,
    /// <summary>cACompromise (2).</summary>
    CACompromise = 2,
    /// <summary>affiliationChanged (3).</summary>
    AffiliationChanged = 3,
    /// <summary>superseded (4).</summary>
    Superseded = 4,
    /// <summary>cessationOfOperation (5).</summary>
    CessationOfOperation = 5,
    /// <summary>certificateHold (6).</summary>
    CertificateHold = 6,
    /// <summary>removeFromCRL (8), used in delta CRLs.</summary>
    RemoveFromCrl = 8,
    /// <summary>privilegeWithdrawn (9).</summary>
    PrivilegeWithdrawn = 9,
    /// <summary>aACompromise (10).</summary>
    AACompromise = 10,
}

/// <summary>basicConstraints (RFC 5280 §4.2.1.9).</summary>
/// <param name="IsCA">Whether the subject is a CA.</param>
/// <param name="PathLengthConstraint">The most non-self-issued intermediate CAs that may follow, or null for no limit.</param>
public sealed record BasicConstraints(bool IsCA, int? PathLengthConstraint = null) : IExtensionValue<BasicConstraints>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.BasicConstraints;

    /// <inheritdoc/>
    public static BasicConstraints Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("basicConstraints", value, static (v, lim) =>
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(v, lim);
        bool ca = false;
        if (s.TryPeekTag(out Asn1Tag t) && t == new Asn1Tag(Asn1Tags.Boolean))
        {
            ca = s.ReadBoolean();
        }

        int? len = null;
        if (s.HasData)
        {
            len = ExtensionHelpers.ReadNonNegative(ref s);
        }

        s.ThrowIfNotEmpty();
        return new BasicConstraints(ca, len);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.Sequence(
        IsCA ? DerWriter.Boolean(true) : [],
        PathLengthConstraint is int n ? DerWriter.SignedInteger(n) : []);
}

/// <summary>keyUsage (RFC 5280 §4.2.1.3).</summary>
/// <param name="Usages">The bits that are set.</param>
public sealed record KeyUsageExtension(KeyUsages Usages) : IExtensionValue<KeyUsageExtension>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.KeyUsage;

    /// <inheritdoc/>
    public static KeyUsageExtension Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("keyUsage", value, static (v, lim) =>
    {
        var r = new Asn1Reader(v.Span, Asn1Rules.Ber, lim.Asn1);
        int f = ExtensionHelpers.ReadFlags(ref r);
        r.ThrowIfNotEmpty();
        return new KeyUsageExtension((KeyUsages)(f & 0x1FF));
    });

    /// <inheritdoc/>
    public byte[] Encode() => ExtensionHelpers.WriteFlags((int)Usages);
}

/// <summary>extKeyUsage (RFC 5280 §4.2.1.12).</summary>
/// <param name="Purposes">The key purpose identifiers in encoded order.</param>
public sealed record ExtendedKeyUsage(IReadOnlyList<string> Purposes) : IExtensionValue<ExtendedKeyUsage>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.ExtendedKeyUsage;

    /// <summary>True when the list names <paramref name="purpose"/> or anyExtendedKeyUsage.</summary>
    public bool Allows(string purpose) => Purposes.Contains(purpose) || Purposes.Contains(KnownOids.AnyExtendedKeyUsage);

    /// <inheritdoc/>
    public static ExtendedKeyUsage Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("extKeyUsage", value, static (v, lim) =>
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(v, lim);
        var list = new List<string>();
        while (s.HasData)
        {
            if (list.Count >= lim.MaxListEntries)
            {
                throw X509Read.Limit("extKeyUsage", "too many purposes");
            }

            list.Add(s.ReadObjectIdentifier());
        }

        return new ExtendedKeyUsage(list);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.Sequence([.. Purposes.Select(DerWriter.Oid)]);
}

/// <summary>subjectKeyIdentifier (RFC 5280 §4.2.1.2).</summary>
/// <param name="KeyIdentifier">The identifier octets.</param>
public sealed record SubjectKeyIdentifier(ReadOnlyMemory<byte> KeyIdentifier) : IExtensionValue<SubjectKeyIdentifier>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.SubjectKeyIdentifier;

    /// <inheritdoc/>
    public static SubjectKeyIdentifier Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("subjectKeyIdentifier", value, static (v, lim) =>
    {
        var r = new Asn1Reader(v.Span, Asn1Rules.Ber, lim.Asn1);
        byte[] id = r.ReadOctetStringBytes();
        r.ThrowIfNotEmpty();
        return new SubjectKeyIdentifier(id);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.OctetString(KeyIdentifier.Span);
}

/// <summary>authorityKeyIdentifier (RFC 5280 §4.2.1.1).</summary>
/// <param name="KeyIdentifier">The issuer's key identifier, or empty when absent.</param>
/// <param name="AuthorityCertIssuer">The issuer names, or null when absent.</param>
/// <param name="AuthorityCertSerialNumber">The issuer certificate's serial number as INTEGER content octets, or empty when absent.</param>
public sealed record AuthorityKeyIdentifier(ReadOnlyMemory<byte> KeyIdentifier, IReadOnlyList<GeneralName>? AuthorityCertIssuer = null, ReadOnlyMemory<byte> AuthorityCertSerialNumber = default)
    : IExtensionValue<AuthorityKeyIdentifier>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.AuthorityKeyIdentifier;

    /// <inheritdoc/>
    public static AuthorityKeyIdentifier Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("authorityKeyIdentifier", value, static (v, lim) =>
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(v, lim);
        ReadOnlyMemory<byte> id = default, serial = default;
        IReadOnlyList<GeneralName>? issuer = null;
        if (s.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(0))
        {
            id = X509Read.Slice(v, s.ReadOctetString(Asn1Tag.Context(0)));
        }

        if (s.TryPeekTag(out t) && t == Asn1Tag.Context(1))
        {
            Asn1Reader names = s.ReadSequence(Asn1Tag.Context(1, true));
            issuer = GeneralName.ReadList(ref names, v, lim);
        }

        if (s.TryPeekTag(out t) && t == Asn1Tag.Context(2))
        {
            serial = X509Read.Slice(v, s.ReadIntegerBytes(Asn1Tag.Context(2)));
        }

        s.ThrowIfNotEmpty();
        return new AuthorityKeyIdentifier(id, issuer, serial);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.Sequence(
        KeyIdentifier.IsEmpty ? [] : DerWriter.ContextPrimitive(0, KeyIdentifier.Span),
        AuthorityCertIssuer is null ? [] : DerWriter.Context(1, ExtensionHelpers.NameEncodings(AuthorityCertIssuer)),
        AuthorityCertSerialNumber.IsEmpty ? [] : DerWriter.ContextPrimitive(2, AuthorityCertSerialNumber.Span));
}

/// <summary>subjectAltName (RFC 5280 §4.2.1.6).</summary>
/// <param name="Names">The names in encoded order.</param>
public sealed record SubjectAlternativeName(IReadOnlyList<GeneralName> Names) : IExtensionValue<SubjectAlternativeName>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.SubjectAltName;

    /// <inheritdoc/>
    public static SubjectAlternativeName Parse(ReadOnlyMemory<byte> value) => new(GeneralNames.Read("subjectAltName", value));

    /// <inheritdoc/>
    public byte[] Encode() => GeneralNames.Write(Names);
}

/// <summary>issuerAltName (RFC 5280 §4.2.1.7).</summary>
/// <param name="Names">The names in encoded order.</param>
public sealed record IssuerAlternativeName(IReadOnlyList<GeneralName> Names) : IExtensionValue<IssuerAlternativeName>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.IssuerAltName;

    /// <inheritdoc/>
    public static IssuerAlternativeName Parse(ReadOnlyMemory<byte> value) => new(GeneralNames.Read("issuerAltName", value));

    /// <inheritdoc/>
    public byte[] Encode() => GeneralNames.Write(Names);
}

/// <summary>certificateIssuer, an entry extension of an indirect CRL (RFC 5280 §5.3.3).</summary>
/// <param name="Names">The issuer names.</param>
public sealed record CertificateIssuerExtension(IReadOnlyList<GeneralName> Names) : IExtensionValue<CertificateIssuerExtension>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.CertificateIssuer;

    /// <inheritdoc/>
    public static CertificateIssuerExtension Parse(ReadOnlyMemory<byte> value) => new(GeneralNames.Read("certificateIssuer", value));

    /// <inheritdoc/>
    public byte[] Encode() => GeneralNames.Write(Names);
}

internal static class GeneralNames
{
    public static List<GeneralName> Read(string what, ReadOnlyMemory<byte> value) => ExtensionHelpers.Run(what, value, static (v, lim) =>
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(v, lim);
        return GeneralName.ReadList(ref s, v, lim);
    });

    public static byte[] Write(IReadOnlyList<GeneralName> names) => DerWriter.Sequence(ExtensionHelpers.NameEncodings(names));
}

/// <summary>One <c>GeneralSubtree</c> of a name constraint (RFC 5280 §4.2.1.10).</summary>
/// <param name="Base">The name the subtree is rooted at.</param>
/// <param name="Minimum">The minimum distance (must be 0 in the profile; kept as received).</param>
/// <param name="Maximum">The maximum distance, or null (must be absent in the profile).</param>
public sealed record GeneralSubtree(GeneralName Base, int Minimum = 0, int? Maximum = null);

/// <summary>nameConstraints (RFC 5280 §4.2.1.10).</summary>
/// <param name="PermittedSubtrees">The permitted subtrees, or null when the field is absent.</param>
/// <param name="ExcludedSubtrees">The excluded subtrees, or null when the field is absent.</param>
public sealed record NameConstraints(IReadOnlyList<GeneralSubtree>? PermittedSubtrees, IReadOnlyList<GeneralSubtree>? ExcludedSubtrees) : IExtensionValue<NameConstraints>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.NameConstraints;

    /// <inheritdoc/>
    public static NameConstraints Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("nameConstraints", value, static (v, lim) =>
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(v, lim);
        List<GeneralSubtree>? permitted = null, excluded = null;
        if (s.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(0))
        {
            Asn1Reader l = s.ReadSequence(Asn1Tag.Context(0, true));
            permitted = ReadSubtrees(ref l, v, lim);
        }

        if (s.TryPeekTag(out t) && t == Asn1Tag.Context(1))
        {
            Asn1Reader l = s.ReadSequence(Asn1Tag.Context(1, true));
            excluded = ReadSubtrees(ref l, v, lim);
        }

        s.ThrowIfNotEmpty();
        return new NameConstraints(permitted, excluded);
    });

    private static List<GeneralSubtree> ReadSubtrees(ref Asn1Reader l, ReadOnlyMemory<byte> root, X509Limits lim)
    {
        var list = new List<GeneralSubtree>();
        while (l.HasData)
        {
            if (list.Count >= lim.MaxListEntries)
            {
                throw X509Read.Limit("nameConstraints", "too many subtrees");
            }

            Asn1Reader st = l.ReadSequence();
            GeneralName b = GeneralName.Read(ref st, root);
            int min = 0;
            int? max = null;
            if (st.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(0))
            {
                min = ExtensionHelpers.ReadNonNegative(ref st, Asn1Tag.Context(0));
            }

            if (st.TryPeekTag(out t) && t == Asn1Tag.Context(1))
            {
                max = ExtensionHelpers.ReadNonNegative(ref st, Asn1Tag.Context(1));
            }

            st.ThrowIfNotEmpty();
            list.Add(new GeneralSubtree(b, min, max));
        }

        if (list.Count == 0)
        {
            throw X509Read.Bad("nameConstraints", "an empty subtree list");
        }

        return list;
    }

    private static byte[] WriteSubtrees(int n, IReadOnlyList<GeneralSubtree> trees) => DerWriter.Context(n, [.. trees.Select(t => DerWriter.Sequence(
        t.Base.Encoded.ToArray(),
        t.Minimum != 0 ? DerWriter.Tlv(0x80, new BigInteger(t.Minimum).ToByteArray(isUnsigned: true, isBigEndian: true)) : [],
        t.Maximum is int m ? DerWriter.Tlv(0x81, new BigInteger(m).ToByteArray(isUnsigned: true, isBigEndian: true)) : []))]);

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.Sequence(
        PermittedSubtrees is null ? [] : WriteSubtrees(0, PermittedSubtrees),
        ExcludedSubtrees is null ? [] : WriteSubtrees(1, ExcludedSubtrees));
}

/// <summary>One qualifier of a policy (RFC 5280 §4.2.1.4).</summary>
/// <param name="Id">The qualifier identifier (id-qt-cps and id-qt-unotice are the standard ones).</param>
/// <param name="Qualifier">The qualifier element, encoded.</param>
public sealed record PolicyQualifier(string Id, ReadOnlyMemory<byte> Qualifier);

/// <summary>One <c>PolicyInformation</c>.</summary>
/// <param name="PolicyId">The policy identifier.</param>
/// <param name="Qualifiers">The qualifiers, empty when absent.</param>
public sealed record PolicyInformation(string PolicyId, IReadOnlyList<PolicyQualifier> Qualifiers);

/// <summary>certificatePolicies (RFC 5280 §4.2.1.4).</summary>
/// <param name="Policies">The policies in encoded order.</param>
public sealed record CertificatePolicies(IReadOnlyList<PolicyInformation> Policies) : IExtensionValue<CertificatePolicies>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.CertificatePolicies;

    /// <inheritdoc/>
    public static CertificatePolicies Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("certificatePolicies", value, static (v, lim) =>
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(v, lim);
        var list = new List<PolicyInformation>();
        while (s.HasData)
        {
            if (list.Count >= lim.MaxListEntries)
            {
                throw X509Read.Limit("certificatePolicies", "too many policies");
            }

            Asn1Reader pi = s.ReadSequence();
            string id = pi.ReadObjectIdentifier();
            var quals = new List<PolicyQualifier>();
            if (pi.HasData)
            {
                Asn1Reader ql = pi.ReadSequence();
                while (ql.HasData)
                {
                    if (quals.Count >= lim.MaxListEntries)
                    {
                        throw X509Read.Limit("certificatePolicies", "too many qualifiers");
                    }

                    Asn1Reader q = ql.ReadSequence();
                    string qid = q.ReadObjectIdentifier();
                    quals.Add(new PolicyQualifier(qid, X509Read.Slice(v, q.ReadEncodedValue())));
                    q.ThrowIfNotEmpty();
                }
            }

            pi.ThrowIfNotEmpty();
            list.Add(new PolicyInformation(id, quals));
        }

        return new CertificatePolicies(list);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.Sequence([.. Policies.Select(p => DerWriter.Sequence(
        DerWriter.Oid(p.PolicyId),
        p.Qualifiers.Count == 0 ? [] : DerWriter.Sequence([.. p.Qualifiers.Select(q => DerWriter.Sequence(DerWriter.Oid(q.Id), q.Qualifier.ToArray()))])))]);
}

/// <summary>One mapping of policyMappings.</summary>
/// <param name="IssuerDomainPolicy">The policy in the issuer's domain.</param>
/// <param name="SubjectDomainPolicy">The equivalent policy in the subject's domain.</param>
public sealed record PolicyMapping(string IssuerDomainPolicy, string SubjectDomainPolicy);

/// <summary>policyMappings (RFC 5280 §4.2.1.5).</summary>
/// <param name="Mappings">The mappings in encoded order.</param>
public sealed record PolicyMappings(IReadOnlyList<PolicyMapping> Mappings) : IExtensionValue<PolicyMappings>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.PolicyMappings;

    /// <inheritdoc/>
    public static PolicyMappings Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("policyMappings", value, static (v, lim) =>
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(v, lim);
        var list = new List<PolicyMapping>();
        while (s.HasData)
        {
            if (list.Count >= lim.MaxListEntries)
            {
                throw X509Read.Limit("policyMappings", "too many mappings");
            }

            Asn1Reader m = s.ReadSequence();
            list.Add(new PolicyMapping(m.ReadObjectIdentifier(), m.ReadObjectIdentifier()));
            m.ThrowIfNotEmpty();
        }

        return new PolicyMappings(list);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.Sequence([.. Mappings.Select(m => DerWriter.Sequence(DerWriter.Oid(m.IssuerDomainPolicy), DerWriter.Oid(m.SubjectDomainPolicy)))]);
}

/// <summary>policyConstraints (RFC 5280 §4.2.1.11).</summary>
/// <param name="RequireExplicitPolicy">Certificates until a policy is required, or null.</param>
/// <param name="InhibitPolicyMapping">Certificates until mapping is forbidden, or null.</param>
public sealed record PolicyConstraints(int? RequireExplicitPolicy, int? InhibitPolicyMapping) : IExtensionValue<PolicyConstraints>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.PolicyConstraints;

    /// <inheritdoc/>
    public static PolicyConstraints Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("policyConstraints", value, static (v, lim) =>
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(v, lim);
        int? req = null, inh = null;
        if (s.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(0))
        {
            req = ExtensionHelpers.ReadNonNegative(ref s, Asn1Tag.Context(0));
        }

        if (s.TryPeekTag(out t) && t == Asn1Tag.Context(1))
        {
            inh = ExtensionHelpers.ReadNonNegative(ref s, Asn1Tag.Context(1));
        }

        s.ThrowIfNotEmpty();
        return new PolicyConstraints(req, inh);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.Sequence(
        RequireExplicitPolicy is int a ? DerWriter.Tlv(0x80, new BigInteger(a).ToByteArray(isUnsigned: true, isBigEndian: true)) : [],
        InhibitPolicyMapping is int b ? DerWriter.Tlv(0x81, new BigInteger(b).ToByteArray(isUnsigned: true, isBigEndian: true)) : []);
}

/// <summary>inhibitAnyPolicy (RFC 5280 §4.2.1.14).</summary>
/// <param name="SkipCerts">Certificates after which anyPolicy is no longer a match.</param>
public sealed record InhibitAnyPolicy(int SkipCerts) : IExtensionValue<InhibitAnyPolicy>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.InhibitAnyPolicy;

    /// <inheritdoc/>
    public static InhibitAnyPolicy Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("inhibitAnyPolicy", value, static (v, lim) =>
    {
        var r = new Asn1Reader(v.Span, Asn1Rules.Ber, lim.Asn1);
        int n = ExtensionHelpers.ReadNonNegative(ref r);
        r.ThrowIfNotEmpty();
        return new InhibitAnyPolicy(n);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.SignedInteger(SkipCerts);
}

/// <summary>The name in a distribution point: either full names or a name relative to the CRL issuer (RFC 5280 §4.2.1.13).</summary>
/// <param name="FullName">The URLs or names, or null when the relative form is used.</param>
/// <param name="RelativeName">The encoded AttributeTypeAndValue elements of nameRelativeToCRLIssuer, empty when FullName is used.</param>
public sealed record DistributionPointName(IReadOnlyList<GeneralName>? FullName, ReadOnlyMemory<byte> RelativeName = default)
{
    internal static DistributionPointName Read(ref Asn1Reader outer, ReadOnlyMemory<byte> root, X509Limits lim)
    {
        // The CHOICE sits inside an explicit [0] wrapper.
        Asn1Reader w = outer.ReadSequence(Asn1Tag.Context(0, true));
        Asn1Tag t = w.PeekTag();
        DistributionPointName result;
        if (t == Asn1Tag.Context(0))
        {
            Asn1Reader names = w.ReadSequence(Asn1Tag.Context(0, true));
            result = new DistributionPointName(GeneralName.ReadList(ref names, root, lim));
        }
        else if (t == Asn1Tag.Context(1))
        {
            Asn1Reader rdn = w.ReadSet(Asn1Tag.Context(1, true));
            result = new DistributionPointName(null, X509Read.Slice(root, rdn.Remaining));
        }
        else
        {
            throw X509Read.Bad("DistributionPointName", "neither fullName nor nameRelativeToCRLIssuer");
        }

        w.ThrowIfNotEmpty();
        return result;
    }

    internal byte[] Write() => DerWriter.Context(0, FullName is not null
        ? DerWriter.Context(0, ExtensionHelpers.NameEncodings(FullName))
        : DerWriter.Tlv(0xA1, RelativeName.ToArray()));
}

/// <summary>One <c>DistributionPoint</c>.</summary>
/// <param name="Name">Where the CRL is, or null.</param>
/// <param name="Reasons">The reasons the CRL covers, or null for all.</param>
/// <param name="CrlIssuer">The CRL issuer's names when it is not the certificate's issuer, or null.</param>
public sealed record DistributionPoint(DistributionPointName? Name, RevocationReasons? Reasons = null, IReadOnlyList<GeneralName>? CrlIssuer = null)
{
    internal static List<DistributionPoint> ReadAll(string what, ReadOnlyMemory<byte> value, X509Limits lim)
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(value, lim);
        var list = new List<DistributionPoint>();
        while (s.HasData)
        {
            if (list.Count >= lim.MaxListEntries)
            {
                throw X509Read.Limit(what, "too many distribution points");
            }

            Asn1Reader dp = s.ReadSequence();
            DistributionPointName? name = null;
            RevocationReasons? reasons = null;
            IReadOnlyList<GeneralName>? issuer = null;
            if (dp.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(0))
            {
                name = DistributionPointName.Read(ref dp, value, lim);
            }

            if (dp.TryPeekTag(out t) && t == Asn1Tag.Context(1))
            {
                reasons = (RevocationReasons)(ExtensionHelpers.ReadFlags(ref dp, Asn1Tag.Context(1)) & 0x1FE);
            }

            if (dp.TryPeekTag(out t) && t == Asn1Tag.Context(2))
            {
                Asn1Reader names = dp.ReadSequence(Asn1Tag.Context(2, true));
                issuer = GeneralName.ReadList(ref names, value, lim);
            }

            dp.ThrowIfNotEmpty();
            list.Add(new DistributionPoint(name, reasons, issuer));
        }

        return list;
    }

    internal static byte[] WriteAll(IReadOnlyList<DistributionPoint> points) => DerWriter.Sequence([.. points.Select(p => DerWriter.Sequence(
        p.Name is null ? [] : p.Name.Write(),
        p.Reasons is RevocationReasons r ? ExtensionHelpers.WriteFlags((int)r, 0x81) : [],
        p.CrlIssuer is null ? [] : DerWriter.Context(2, ExtensionHelpers.NameEncodings(p.CrlIssuer))))]);
}

/// <summary>cRLDistributionPoints (RFC 5280 §4.2.1.13).</summary>
/// <param name="Points">The distribution points in encoded order.</param>
public sealed record CrlDistributionPoints(IReadOnlyList<DistributionPoint> Points) : IExtensionValue<CrlDistributionPoints>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.CrlDistributionPoints;

    /// <inheritdoc/>
    public static CrlDistributionPoints Parse(ReadOnlyMemory<byte> value) =>
        ExtensionHelpers.Run("cRLDistributionPoints", value, static (v, lim) => new CrlDistributionPoints(DistributionPoint.ReadAll("cRLDistributionPoints", v, lim)));

    /// <inheritdoc/>
    public byte[] Encode() => DistributionPoint.WriteAll(Points);
}

/// <summary>freshestCRL (RFC 5280 §4.2.1.15): where delta CRLs are.</summary>
/// <param name="Points">The distribution points in encoded order.</param>
public sealed record FreshestCrl(IReadOnlyList<DistributionPoint> Points) : IExtensionValue<FreshestCrl>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.FreshestCrl;

    /// <inheritdoc/>
    public static FreshestCrl Parse(ReadOnlyMemory<byte> value) =>
        ExtensionHelpers.Run("freshestCRL", value, static (v, lim) => new FreshestCrl(DistributionPoint.ReadAll("freshestCRL", v, lim)));

    /// <inheritdoc/>
    public byte[] Encode() => DistributionPoint.WriteAll(Points);
}

/// <summary>One <c>AccessDescription</c> of authorityInfoAccess or subjectInfoAccess.</summary>
/// <param name="Method">The access method identifier (see <see cref="KnownOids.AdOcsp"/> and <see cref="KnownOids.AdCaIssuers"/>).</param>
/// <param name="Location">Where to find the information.</param>
public sealed record AccessDescription(string Method, GeneralName Location)
{
    internal static List<AccessDescription> ReadAll(string what, ReadOnlyMemory<byte> value, X509Limits lim)
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(value, lim);
        var list = new List<AccessDescription>();
        while (s.HasData)
        {
            if (list.Count >= lim.MaxListEntries)
            {
                throw X509Read.Limit(what, "too many access descriptions");
            }

            Asn1Reader ad = s.ReadSequence();
            string method = ad.ReadObjectIdentifier();
            GeneralName loc = GeneralName.Read(ref ad, value);
            ad.ThrowIfNotEmpty();
            list.Add(new AccessDescription(method, loc));
        }

        return list;
    }

    internal static byte[] WriteAll(IReadOnlyList<AccessDescription> items) =>
        DerWriter.Sequence([.. items.Select(a => DerWriter.Sequence(DerWriter.Oid(a.Method), a.Location.Encoded.ToArray()))]);
}

/// <summary>authorityInfoAccess (RFC 5280 §4.2.2.1).</summary>
/// <param name="Descriptions">The access descriptions in encoded order.</param>
public sealed record AuthorityInfoAccess(IReadOnlyList<AccessDescription> Descriptions) : IExtensionValue<AuthorityInfoAccess>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.AuthorityInfoAccess;

    /// <summary>The locations of the given method that are URIs.</summary>
    public IEnumerable<string> UrisFor(string method) =>
        Descriptions.Where(d => d.Method == method && d.Location.Kind == GeneralNameKind.Uri).Select(d => d.Location.Value!);

    /// <inheritdoc/>
    public static AuthorityInfoAccess Parse(ReadOnlyMemory<byte> value) =>
        ExtensionHelpers.Run("authorityInfoAccess", value, static (v, lim) => new AuthorityInfoAccess(AccessDescription.ReadAll("authorityInfoAccess", v, lim)));

    /// <inheritdoc/>
    public byte[] Encode() => AccessDescription.WriteAll(Descriptions);
}

/// <summary>subjectInfoAccess (RFC 5280 §4.2.2.2).</summary>
/// <param name="Descriptions">The access descriptions in encoded order.</param>
public sealed record SubjectInfoAccess(IReadOnlyList<AccessDescription> Descriptions) : IExtensionValue<SubjectInfoAccess>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.SubjectInfoAccess;

    /// <inheritdoc/>
    public static SubjectInfoAccess Parse(ReadOnlyMemory<byte> value) =>
        ExtensionHelpers.Run("subjectInfoAccess", value, static (v, lim) => new SubjectInfoAccess(AccessDescription.ReadAll("subjectInfoAccess", v, lim)));

    /// <inheritdoc/>
    public byte[] Encode() => AccessDescription.WriteAll(Descriptions);
}

/// <summary>cRLNumber (RFC 5280 §5.2.3).</summary>
/// <param name="Number">The sequence number.</param>
public sealed record CrlNumber(BigInteger Number) : IExtensionValue<CrlNumber>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.CrlNumber;

    /// <inheritdoc/>
    public static CrlNumber Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("cRLNumber", value, static (v, lim) =>
    {
        var r = new Asn1Reader(v.Span, Asn1Rules.Ber, lim.Asn1);
        BigInteger n = r.ReadInteger();
        r.ThrowIfNotEmpty();
        return new CrlNumber(n);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriterExtras.Integer(Number);
}

/// <summary>deltaCRLIndicator (RFC 5280 §5.2.4), always critical.</summary>
/// <param name="BaseCrlNumber">The number of the complete CRL this delta builds on.</param>
public sealed record DeltaCrlIndicator(BigInteger BaseCrlNumber) : IExtensionValue<DeltaCrlIndicator>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.DeltaCrlIndicator;

    /// <inheritdoc/>
    public static DeltaCrlIndicator Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("deltaCRLIndicator", value, static (v, lim) =>
    {
        var r = new Asn1Reader(v.Span, Asn1Rules.Ber, lim.Asn1);
        BigInteger n = r.ReadInteger();
        r.ThrowIfNotEmpty();
        return new DeltaCrlIndicator(n);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriterExtras.Integer(BaseCrlNumber);
}

/// <summary>issuingDistributionPoint (RFC 5280 §5.2.5).</summary>
/// <param name="DistributionPoint">The distribution point this CRL covers, or null.</param>
/// <param name="OnlyContainsUserCerts">Only end-entity certificates.</param>
/// <param name="OnlyContainsCACerts">Only CA certificates.</param>
/// <param name="OnlySomeReasons">Only these reasons, or null.</param>
/// <param name="IndirectCrl">The CRL may list certificates of other issuers.</param>
/// <param name="OnlyContainsAttributeCerts">Only attribute certificates.</param>
public sealed record IssuingDistributionPoint(
    DistributionPointName? DistributionPoint,
    bool OnlyContainsUserCerts = false,
    bool OnlyContainsCACerts = false,
    RevocationReasons? OnlySomeReasons = null,
    bool IndirectCrl = false,
    bool OnlyContainsAttributeCerts = false) : IExtensionValue<IssuingDistributionPoint>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.IssuingDistributionPoint;

    /// <inheritdoc/>
    public static IssuingDistributionPoint Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("issuingDistributionPoint", value, static (v, lim) =>
    {
        Asn1Reader s = ExtensionHelpers.OpenSequence(v, lim);
        DistributionPointName? name = null;
        RevocationReasons? reasons = null;
        bool user = false, ca = false, indirect = false, attr = false;
        if (s.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(0))
        {
            name = DistributionPointName.Read(ref s, v, lim);
        }

        if (s.TryPeekTag(out t) && t == Asn1Tag.Context(1))
        {
            user = s.ReadBoolean(Asn1Tag.Context(1));
        }

        if (s.TryPeekTag(out t) && t == Asn1Tag.Context(2))
        {
            ca = s.ReadBoolean(Asn1Tag.Context(2));
        }

        if (s.TryPeekTag(out t) && t == Asn1Tag.Context(3))
        {
            reasons = (RevocationReasons)(ExtensionHelpers.ReadFlags(ref s, Asn1Tag.Context(3)) & 0x1FE);
        }

        if (s.TryPeekTag(out t) && t == Asn1Tag.Context(4))
        {
            indirect = s.ReadBoolean(Asn1Tag.Context(4));
        }

        if (s.TryPeekTag(out t) && t == Asn1Tag.Context(5))
        {
            attr = s.ReadBoolean(Asn1Tag.Context(5));
        }

        s.ThrowIfNotEmpty();
        return new IssuingDistributionPoint(name, user, ca, reasons, indirect, attr);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.Sequence(
        DistributionPoint is null ? [] : DistributionPoint.Write(),
        OnlyContainsUserCerts ? [0x81, 1, 0xFF] : [],
        OnlyContainsCACerts ? [0x82, 1, 0xFF] : [],
        OnlySomeReasons is RevocationReasons r ? ExtensionHelpers.WriteFlags((int)r, 0x83) : [],
        IndirectCrl ? [0x84, 1, 0xFF] : [],
        OnlyContainsAttributeCerts ? [0x85, 1, 0xFF] : []);
}

/// <summary>cRLReason, an entry extension (RFC 5280 §5.3.1).</summary>
/// <param name="Reason">The reason code.</param>
public sealed record CrlReasonExtension(RevocationReason Reason) : IExtensionValue<CrlReasonExtension>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.CrlReason;

    /// <inheritdoc/>
    public static CrlReasonExtension Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("cRLReason", value, static (v, lim) =>
    {
        var r = new Asn1Reader(v.Span, Asn1Rules.Ber, lim.Asn1);
        int n = r.ReadEnumerated();
        r.ThrowIfNotEmpty();
        return Enum.IsDefined((RevocationReason)n) ? new CrlReasonExtension((RevocationReason)n) : throw X509Read.Invalid("cRLReason", "unknown reason code " + n);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.Tlv(0x0A, new[] { (byte)Reason });
}

/// <summary>invalidityDate, an entry extension (RFC 5280 §5.3.2).</summary>
/// <param name="Date">When the private key was believed compromised.</param>
public sealed record InvalidityDate(DateTimeOffset Date) : IExtensionValue<InvalidityDate>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.InvalidityDate;

    /// <inheritdoc/>
    public static InvalidityDate Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("invalidityDate", value, static (v, lim) =>
    {
        var r = new Asn1Reader(v.Span, Asn1Rules.Ber, lim.Asn1);
        DateTimeOffset d = r.ReadGeneralizedTime();
        r.ThrowIfNotEmpty();
        return new InvalidityDate(d);
    });

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.GeneralizedTime(Date);
}

/// <summary>The OCSP nonce extension (RFC 6960 §4.4.1, RFC 8954).</summary>
/// <param name="Nonce">The nonce octets, 1 to 32 under RFC 8954 (longer values are read, since older responders send them).</param>
public sealed record OcspNonce(ReadOnlyMemory<byte> Nonce) : IExtensionValue<OcspNonce>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.OcspNonce;

    /// <summary>
    /// Reads the value as an OCTET STRING wrapping the nonce, or, when it is not exactly one OCTET STRING, as the raw nonce octets some
    /// responders send.
    /// </summary>
    public static OcspNonce Parse(ReadOnlyMemory<byte> value)
    {
        var r = new Asn1Reader(value.Span, Asn1Rules.Ber);
        if (r.TryReadOctetString(out ReadOnlySpan<byte> inner) && !r.HasData)
        {
            return new OcspNonce(X509Read.Slice(value, inner));
        }

        return new OcspNonce(value);
    }

    /// <inheritdoc/>
    public byte[] Encode() => DerWriter.OctetString(Nonce.Span);
}

/// <summary>The OCSP no-check extension (RFC 6960 §4.2.2.2.1): a responder certificate that needs no revocation check. Its value is NULL.</summary>
public sealed record OcspNoCheck : IExtensionValue<OcspNoCheck>
{
    /// <inheritdoc/>
    public static string ExtensionOid => KnownOids.OcspNoCheck;

    /// <inheritdoc/>
    public static OcspNoCheck Parse(ReadOnlyMemory<byte> value) => ExtensionHelpers.Run("ocspNoCheck", value, static (v, lim) =>
    {
        var r = new Asn1Reader(v.Span, Asn1Rules.Ber, lim.Asn1);
        r.ReadNull();
        r.ThrowIfNotEmpty();
        return new OcspNoCheck();
    });

    /// <inheritdoc/>
    public byte[] Encode() => [5, 0];
}

internal static class DerWriterExtras
{
    public static byte[] Integer(BigInteger n) => DerWriter.Tlv(0x02, n.ToByteArray(isUnsigned: false, isBigEndian: true));
}
