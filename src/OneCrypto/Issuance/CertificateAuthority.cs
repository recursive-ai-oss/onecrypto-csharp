using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Issuance;

/// <summary>Raised when a certificate authority refuses to issue: the request or the options break a rule of the profile, the issuing certificate or RFC 5280.</summary>
public sealed class IssuanceException : InvalidOperationException
{
    /// <summary>Creates the exception for the named rule.</summary>
    public IssuanceException(string rule, string message, string reference)
        : base(message)
    {
        Rule = rule;
        Reference = reference;
    }

    /// <summary>Creates an empty exception.</summary>
    public IssuanceException()
        : this("issuance", "The certificate cannot be issued.", string.Empty)
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public IssuanceException(string message)
        : this("issuance", message, string.Empty)
    {
    }

    /// <summary>Creates the exception with a message and a cause.</summary>
    public IssuanceException(string message, Exception innerException)
        : base(message, innerException)
    {
        Rule = "issuance";
        Reference = string.Empty;
    }

    /// <summary>A short stable name of the rule that refused, such as <c>validity</c> or <c>csr-signature</c>.</summary>
    public string Rule { get; } = "issuance";

    /// <summary>The standard or profile section the rule comes from.</summary>
    public string Reference { get; } = string.Empty;
}

/// <summary>Configuration of a <see cref="CertificateAuthority"/>.</summary>
public sealed class CertificateAuthorityOptions
{
    /// <summary>The crypto policy applied to every key and signature the CA handles (default <see cref="CryptoPolicy.Standard"/>).</summary>
    public CryptoPolicy Policy { get; init; } = CryptoPolicy.Standard;

    /// <summary>OCSP responder URLs written into issued certificates' authorityInfoAccess (RFC 5280 §4.2.2.1).</summary>
    public IReadOnlyList<string> OcspUrls { get; init; } = [];

    /// <summary>URLs of the issuing CA's certificate, written as the caIssuers access method.</summary>
    public IReadOnlyList<string> CaIssuersUrls { get; init; } = [];

    /// <summary>CRL URLs written into issued certificates' cRLDistributionPoints (RFC 5280 §4.2.1.13).</summary>
    public IReadOnlyList<string> CrlUrls { get; init; } = [];

    /// <summary>Octets of random data in each serial number (default 16, at least 9). The top bit is cleared so the number is positive, leaving at least 70 random bits (RFC 5280 §4.1.2.2; CA/Browser Forum Baseline Requirements §7.1 asks for 64).</summary>
    public int SerialOctets { get; init; } = 16;
}

/// <summary>What to issue.</summary>
public sealed class CertificateIssueOptions
{
    /// <summary>The profile the certificate must follow.</summary>
    public required CertificateProfile Profile { get; init; }

    /// <summary>The start of validity. The CA never reads a clock: this is the issuance time unless the host deliberately back-dates.</summary>
    public required DateTimeOffset NotBefore { get; init; }

    /// <summary>The length of validity, or null for the profile's longest, cut back to the issuing certificate's end.</summary>
    public TimeSpan? Validity { get; init; }

    /// <summary>The subject names to certify. Null takes them from the request (a CSR's subject alternative name request); a profile that allows none ignores nothing: asking is refused.</summary>
    public IReadOnlyList<GeneralName>? SubjectAlternativeNames { get; init; }

    /// <summary>For a CA profile, the path length constraint to write (null: the profile's, then the issuer's limit).</summary>
    public int? PathLength { get; init; }

    /// <summary>More extensions to add, such as name constraints on an intermediate. They must not repeat an extension the profile writes.</summary>
    public IReadOnlyList<Extension> AdditionalExtensions { get; init; } = [];
}

/// <summary>What goes into a CRL or delta CRL.</summary>
public sealed class CrlIssueOptions
{
    /// <summary>When the list is issued (the host's clock, passed in).</summary>
    public required DateTimeOffset ThisUpdate { get; init; }

    /// <summary>When the next list is due. Required: a list without it can never be known to be current (RFC 5280 §5.1.2.5 makes it optional but conforming CAs include it).</summary>
    public required DateTimeOffset NextUpdate { get; init; }

    /// <summary>The cRLNumber: a monotonically increasing integer (RFC 5280 §5.2.3).</summary>
    public required BigInteger Number { get; init; }

    /// <summary>The revoked entries, with reason codes and invalidity dates.</summary>
    public IReadOnlyList<RevokedCertificateInfo> Revoked { get; init; } = [];

    /// <summary>For a delta CRL, the number of the complete list it builds on. Its entries are the changes since then, and <see cref="Number"/> must be greater.</summary>
    public BigInteger? DeltaBaseNumber { get; init; }

    /// <summary>The URL this list is published at, written as the issuingDistributionPoint (RFC 5280 §5.2.5) so a CRL cannot be passed off for another distribution point's.</summary>
    public string? DistributionPointUrl { get; init; }

    /// <summary>True to mark the list as covering end-entity certificates only (needs <see cref="DistributionPointUrl"/> or stands alone).</summary>
    public bool OnlyUserCertificates { get; init; }

    /// <summary>True to mark the list as covering CA certificates only.</summary>
    public bool OnlyCaCertificates { get; init; }

    /// <summary>For a complete list, the URL of its delta CRL, written as freshestCRL (RFC 5280 §5.2.6).</summary>
    public string? DeltaCrlUrl { get; init; }
}

/// <summary>
/// A certificate authority: a CA certificate with the key that signs for it. It issues from a certification request (whose signature it checks) or from a public key and
/// subject, under a <see cref="CertificateProfile"/>, and issues CRLs and delta CRLs. It is I/O-free and reads no clock; every time is an argument. Any
/// <see cref="X509Signer"/> works, so the key can be in memory, in the operating system, on a token or remote, and each step has a two-phase form that splits signing
/// from preparation.
/// </summary>
public sealed class CertificateAuthority
{
    private readonly X509Signer _signer;

    /// <summary>Creates a CA from its certificate and signer.</summary>
    /// <exception cref="ArgumentException">The certificate is not a CA certificate allowed to sign certificates, or the signer's key is not the certificate's.</exception>
    public CertificateAuthority(Certificate certificate, X509Signer signer, CertificateAuthorityOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(signer);
        Options = options ?? new CertificateAuthorityOptions();
        if (Options.SerialOctets < 9)
        {
            throw new ArgumentException("A serial number needs at least 9 octets of randomness.", nameof(options));
        }

        if (certificate.BasicConstraints is not { IsCA: true })
        {
            throw new ArgumentException("The certificate is not a CA certificate (basicConstraints cA, RFC 5280 §4.2.1.9).", nameof(certificate));
        }

        if (certificate.KeyUsage is { } ku && (ku.Usages & KeyUsages.KeyCertSign) == 0)
        {
            throw new ArgumentException("The certificate's key usage does not include keyCertSign (RFC 5280 §4.2.1.3).", nameof(certificate));
        }

        if (!certificate.PublicKey.Equals(signer.PublicKey))
        {
            throw new ArgumentException("The signer's key is not the certificate's key.", nameof(signer));
        }

        Certificate = certificate;
        _signer = signer;
    }

    /// <summary>The CA certificate.</summary>
    public Certificate Certificate { get; }

    /// <summary>The CA's options.</summary>
    public CertificateAuthorityOptions Options { get; }

    /// <summary>Creates a self-signed root CA.</summary>
    /// <param name="subject">The root's name.</param>
    /// <param name="signer">The root key.</param>
    /// <param name="notBefore">The start of validity.</param>
    /// <param name="validity">The length of validity.</param>
    /// <param name="options">The CA options, or null for the defaults.</param>
    /// <param name="profile">The profile (default <see cref="CertificateProfile.Root"/>).</param>
    /// <exception cref="IssuanceException">The validity or the key breaks the profile or the policy.</exception>
    public static CertificateAuthority CreateRoot(DistinguishedName subject, X509Signer signer, DateTimeOffset notBefore, TimeSpan validity, CertificateAuthorityOptions? options = null, CertificateProfile? profile = null)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(signer);
        options ??= new CertificateAuthorityOptions();
        profile ??= CertificateProfile.Root;
        if (!profile.IsCa)
        {
            throw new ArgumentException("A root needs a CA profile.", nameof(profile));
        }

        if (validity > profile.MaxValidity || validity <= TimeSpan.Zero)
        {
            throw new IssuanceException("validity", $"The validity of {validity.TotalDays:0} days is outside the {profile.Name} profile (longest {profile.MaxValidity.TotalDays:0}).", "profile");
        }

        PolicyReport report = options.Policy.CheckSignature(signer.SignatureAlgorithm, signer.PublicKey, CryptoUse.Sign, notBefore);
        if (!report.IsAllowed)
        {
            throw new PolicyViolationException(report);
        }

        Certificate cert = CertificateBuilder.CreateSelfSigned(new CertificateOptions
        {
            Subject = subject,
            NotBefore = notBefore,
            NotAfter = notBefore + validity,
            SerialNumber = NewSerial(options.SerialOctets),
            Extensions = ProfileExtensions(profile, signer.PublicKey, profile.MaxPathLength, [], null),
        }, signer);
        return new CertificateAuthority(cert, signer, options);
    }

    /// <summary>Issues a certificate for the key in a certification request, after checking the request's signature (proof of possession, RFC 2986 §3).</summary>
    /// <remarks>Only the subject, the key and a subject alternative name request are taken from the request. Every other requested extension is ignored: the profile decides what the certificate says.</remarks>
    /// <exception cref="IssuanceException">The request or options break a rule; <see cref="IssuanceException.Rule"/> names it.</exception>
    /// <exception cref="PolicyViolationException">The policy rejects the subject key or the CA's signature.</exception>
    public Certificate Issue(CertificateSigningRequest request, CertificateIssueOptions options)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);
        CertificateOptions o = FromRequest(request, options);
        return CertificateBuilder.Create(o, Certificate, _signer);
    }

    /// <summary>Issues a certificate for a public key and subject the caller vouches for.</summary>
    /// <exception cref="IssuanceException">The options break a rule.</exception>
    /// <exception cref="PolicyViolationException">The policy rejects the subject key or the CA's signature.</exception>
    public Certificate Issue(PublicKeyInfo subjectKey, DistinguishedName subject, CertificateIssueOptions options)
    {
        ArgumentNullException.ThrowIfNull(subjectKey);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(options);
        return CertificateBuilder.Create(Build(subjectKey, subject, options.SubjectAlternativeNames ?? [], options), Certificate, _signer);
    }

    /// <summary>Phase one of issuing from a request in two steps; sign <see cref="PreparedSignature.ToSign"/> with the CA key under <paramref name="spec"/> anywhere, then <see cref="CompleteIssue"/>.</summary>
    public PreparedSignature PrepareIssue(CertificateSigningRequest request, CertificateIssueOptions options, SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);
        return CertificateBuilder.Prepare(FromRequest(request, options), Certificate, spec, Options.Policy, options.NotBefore);
    }

    /// <summary>Phase one of issuing for a key and subject in two steps; see <see cref="PrepareIssue(CertificateSigningRequest, CertificateIssueOptions, SignatureSpec)"/>.</summary>
    public PreparedSignature PrepareIssue(PublicKeyInfo subjectKey, DistinguishedName subject, CertificateIssueOptions options, SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(subjectKey);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(options);
        return CertificateBuilder.Prepare(Build(subjectKey, subject, options.SubjectAlternativeNames ?? [], options), Certificate, spec, Options.Policy, options.NotBefore);
    }

    /// <summary>Phase two: checks the signature against the CA's key and returns the certificate.</summary>
    /// <exception cref="InvalidSignatureException">The signature does not verify.</exception>
    public static Certificate CompleteIssue(PreparedSignature prepared, ReadOnlySpan<byte> signature) => CertificateBuilder.Complete(prepared, signature);

    /// <summary>Issues a CRL or, when <see cref="CrlIssueOptions.DeltaBaseNumber"/> is set, a delta CRL (RFC 5280 §5).</summary>
    /// <exception cref="IssuanceException">The options break a rule: the CA may not sign CRLs, the times or numbers do not fit, or the entries do not suit the kind of list.</exception>
    public CertificateRevocationList IssueCrl(CrlIssueOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return RevocationListBuilder.Create(BuildCrl(options), _signer, Certificate);
    }

    /// <summary>Phase one of issuing a CRL in two steps; see <see cref="CompleteCrl"/>.</summary>
    public PreparedSignature PrepareCrl(CrlIssueOptions options, SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(options);
        return RevocationListBuilder.Prepare(BuildCrl(options), Certificate.PublicKey, spec, Options.Policy, options.ThisUpdate, Certificate);
    }

    /// <summary>Phase two of a CRL: checks the signature and returns the list.</summary>
    public static CertificateRevocationList CompleteCrl(PreparedSignature prepared, ReadOnlySpan<byte> signature) => RevocationListBuilder.Complete(prepared, signature);

    private CertificateOptions FromRequest(CertificateSigningRequest request, CertificateIssueOptions options)
    {
        SignatureVerification pop = request.VerifySignature();
        if (!pop.IsValid)
        {
            throw new IssuanceException("csr-signature", "The request's signature does not verify, so the requester has not shown it holds the key: " + pop.Reason, "RFC 2986 §3");
        }

        IReadOnlyList<GeneralName> names = options.SubjectAlternativeNames
            ?? request.RequestedExtensions.Get<SubjectAlternativeName>()?.Names
            ?? [];
        return Build(request.PublicKey, request.Subject, names, options);
    }

    private CertificateOptions Build(PublicKeyInfo subjectKey, DistinguishedName subject, IReadOnlyList<GeneralName> names, CertificateIssueOptions o)
    {
        CertificateProfile p = o.Profile;
        Certificate ca = Certificate;
        DateTimeOffset notBefore = o.NotBefore;

        // The issuing certificate must itself be valid when it signs (RFC 5280 §6.1.3(a)(2)).
        if (notBefore < ca.NotBefore || notBefore > ca.NotAfter)
        {
            throw new IssuanceException("issuer-validity", $"The issuing certificate is valid from {ca.NotBefore:u} to {ca.NotAfter:u}, which does not include {notBefore:u}.", "RFC 5280 §6.1.3");
        }

        TimeSpan validity;
        if (o.Validity is { } v)
        {
            TimeSpan longest = p.MaxValidityAt(notBefore);
            if (v <= TimeSpan.Zero || v > longest)
            {
                throw new IssuanceException("validity", $"The validity of {v.TotalDays:0.##} days is outside the {p.Name} profile (longest {longest.TotalDays:0} days for a certificate starting {notBefore:yyyy-MM-dd}).", "profile " + p.Name);
            }

            if (notBefore + v > ca.NotAfter)
            {
                throw new IssuanceException("issuer-validity", "The certificate would outlive the CA certificate that issues it.", "RFC 5280 §6.1.3");
            }

            validity = v;
        }
        else
        {
            validity = TimeSpan.FromTicks(Math.Min(p.MaxValidityAt(notBefore).Ticks, (ca.NotAfter - notBefore).Ticks));
        }

        // A CA may only issue CA certificates under its own path length constraint (RFC 5280 §4.2.1.9, §6.1.4(l)).
        int? pathLength = null;
        if (p.IsCa)
        {
            int? limit = ca.BasicConstraints!.PathLengthConstraint;
            if (limit == 0)
            {
                throw new IssuanceException("path-length", "The issuing CA's path length constraint is 0: it cannot issue another CA certificate.", "RFC 5280 §4.2.1.9");
            }

            int? allowed = limit is int l ? l - 1 : null;
            int? wanted = o.PathLength ?? p.MaxPathLength;
            if (wanted is int w && allowed is int a && w > a)
            {
                throw new IssuanceException("path-length", $"A path length of {w} exceeds what the issuing CA allows ({a}).", "RFC 5280 §4.2.1.9");
            }

            pathLength = wanted is int w2 ? (allowed is int a2 ? Math.Min(w2, a2) : w2) : allowed;
        }
        else if (o.PathLength is not null)
        {
            throw new IssuanceException("path-length", "A path length applies to CA certificates only.", "RFC 5280 §4.2.1.9");
        }

        // Subject alternative names: only what the profile allows, and always when it requires them.
        foreach (GeneralName n in names)
        {
            if (!p.AllowedSubjectAlternativeNames.Contains(n.Kind))
            {
                throw new IssuanceException("san", $"A {n.Kind} subject alternative name is not allowed in the {p.Name} profile.", "profile " + p.Name);
            }
        }

        if (p.SubjectAlternativeNameRequired && names.Count == 0)
        {
            throw new IssuanceException("san", $"The {p.Name} profile needs a subject alternative name.", "profile " + p.Name);
        }

        if (subject.Rdns.Count == 0 && names.Count == 0)
        {
            throw new IssuanceException("subject", "A certificate needs a subject name or a subject alternative name (RFC 5280 §4.1.2.6).", "RFC 5280 §4.1.2.6");
        }

        PolicyDecision keyDecision = Options.Policy.CheckKey(subjectKey, CryptoUse.Sign, notBefore);
        if (!keyDecision.IsAllowed)
        {
            throw new PolicyViolationException(new PolicyReport([keyDecision]));
        }

        PolicyReport sigReport = Options.Policy.CheckSignature(_signer.SignatureAlgorithm, Certificate.PublicKey, CryptoUse.Sign, notBefore);
        if (!sigReport.IsAllowed)
        {
            throw new PolicyViolationException(sigReport);
        }

        List<Extension> exts = ProfileExtensions(p, subjectKey, pathLength, names, subject.Rdns.Count == 0);
        exts.AddRange(AccessExtensions());
        foreach (Extension extra in o.AdditionalExtensions)
        {
            if (exts.Any(e => e.Oid == extra.Oid))
            {
                throw new IssuanceException("extensions", $"The extension {extra.Oid} is already written by the profile or the CA.", "RFC 5280 §4.2");
            }

            exts.Add(extra);
        }

        return new CertificateOptions
        {
            Subject = subject,
            PublicKey = subjectKey,
            NotBefore = notBefore,
            NotAfter = notBefore + validity,
            SerialNumber = NewSerial(Options.SerialOctets),
            Extensions = exts,
        };
    }

    private static List<Extension> ProfileExtensions(CertificateProfile p, PublicKeyInfo subjectKey, int? pathLength, IReadOnlyList<GeneralName> names, bool? sanCritical)
    {
        var exts = new List<Extension>
        {
            Extension.Create(new BasicConstraints(p.IsCa, p.IsCa ? pathLength : null), critical: true),
        };
        KeyUsages usage = p.KeyUsages;
        if (subjectKey.KeyAlgorithm is KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss)
        {
            usage |= p.RsaAdditionalKeyUsages;
        }

        if (usage != KeyUsages.None)
        {
            exts.Add(Extension.Create(new KeyUsageExtension(usage), critical: true));
        }

        if (p.ExtendedKeyUsages.Count > 0)
        {
            exts.Add(Extension.Create(new ExtendedKeyUsage([.. p.ExtendedKeyUsages]), p.ExtendedKeyUsageCritical));
        }

        if (names.Count > 0)
        {
            // RFC 5280 §4.2.1.6: the extension is critical when the subject name is empty.
            exts.Add(Extension.Create(new SubjectAlternativeName([.. names]), sanCritical == true));
        }

        if (p.OcspNoCheck)
        {
            exts.Add(Extension.Create(new OcspNoCheck(), critical: false));
        }

        return exts;
    }

    private List<Extension> AccessExtensions()
    {
        var exts = new List<Extension>();
        var access = new List<AccessDescription>();
        access.AddRange(Options.OcspUrls.Select(static u => new AccessDescription(KnownOids.AdOcsp, GeneralName.FromUri(u))));
        access.AddRange(Options.CaIssuersUrls.Select(static u => new AccessDescription(KnownOids.AdCaIssuers, GeneralName.FromUri(u))));
        if (access.Count > 0)
        {
            exts.Add(Extension.Create(new AuthorityInfoAccess(access), critical: false));
        }

        if (Options.CrlUrls.Count > 0)
        {
            exts.Add(Extension.Create(new CrlDistributionPoints([.. Options.CrlUrls.Select(static u => new DistributionPoint(new DistributionPointName([GeneralName.FromUri(u)])))]), critical: false));
        }

        return exts;
    }

    private RevocationListOptions BuildCrl(CrlIssueOptions o)
    {
        Certificate ca = Certificate;
        if (ca.KeyUsage is { } ku && (ku.Usages & KeyUsages.CrlSign) == 0)
        {
            throw new IssuanceException("crl-sign", "The CA certificate's key usage does not include cRLSign (RFC 5280 §4.2.1.3).", "RFC 5280 §4.2.1.3");
        }

        if (o.ThisUpdate < ca.NotBefore || o.ThisUpdate > ca.NotAfter)
        {
            throw new IssuanceException("issuer-validity", "The CA certificate is not valid at thisUpdate.", "RFC 5280 §5.1.2.4");
        }

        if (o.NextUpdate <= o.ThisUpdate)
        {
            throw new IssuanceException("next-update", "nextUpdate must be later than thisUpdate.", "RFC 5280 §5.1.2.5");
        }

        if (o.Number.Sign < 0 || o.Number.GetByteCount(isUnsigned: true) > 20)
        {
            throw new IssuanceException("crl-number", "The cRLNumber must be a non-negative integer of at most 20 octets.", "RFC 5280 §5.2.3");
        }

        bool delta = o.DeltaBaseNumber is not null;
        if (delta && o.DeltaBaseNumber >= o.Number)
        {
            throw new IssuanceException("delta-base", "A delta CRL's number must be greater than its base number.", "RFC 5280 §5.2.4");
        }

        if (delta && o.DeltaCrlUrl is not null)
        {
            throw new IssuanceException("delta-url", "freshestCRL belongs on a complete CRL, not on a delta CRL.", "RFC 5280 §5.2.6");
        }

        if (o.OnlyUserCertificates && o.OnlyCaCertificates)
        {
            throw new IssuanceException("scope", "A CRL cannot cover end-entity certificates only and CA certificates only at once.", "RFC 5280 §5.2.5");
        }

        foreach (RevokedCertificateInfo r in o.Revoked)
        {
            if (r.Reason == RevocationReason.RemoveFromCrl && !delta)
            {
                throw new IssuanceException("reason", "removeFromCRL belongs in delta CRLs only.", "RFC 5280 §5.3.1");
            }

        }

        var exts = new List<Extension>();
        if (o.DistributionPointUrl is not null || o.OnlyUserCertificates || o.OnlyCaCertificates)
        {
            DistributionPointName? name = o.DistributionPointUrl is { } url ? new DistributionPointName([GeneralName.FromUri(url)]) : null;
            exts.Add(Extension.Create(new IssuingDistributionPoint(name, o.OnlyUserCertificates, o.OnlyCaCertificates), critical: true));
        }

        if (o.DeltaCrlUrl is { } deltaUrl)
        {
            exts.Add(Extension.Create(new FreshestCrl([new DistributionPoint(new DistributionPointName([GeneralName.FromUri(deltaUrl)]))]), critical: false));
        }

        return new RevocationListOptions
        {
            Issuer = ca.Subject,
            ThisUpdate = o.ThisUpdate,
            NextUpdate = o.NextUpdate,
            Number = o.Number,
            DeltaBaseNumber = o.DeltaBaseNumber,
            Revoked = o.Revoked,
            Extensions = exts,
        };
    }

    /// <summary>A random positive serial number of <paramref name="octets"/> octets from the system generator, never zero.</summary>
    private static byte[] NewSerial(int octets)
    {
        byte[] b = RandomNumberGenerator.GetBytes(octets);
        b[0] &= 0x7F;
        b[0] |= 0x10; // a fixed high bit position keeps the length constant and leaves 8 * octets - 2 random bits
        return b;
    }
}
