using System.Linq;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Issuance;

/// <summary>A validity limit that applies to certificates starting on or after a date.</summary>
/// <param name="From">The first notBefore the limit applies to.</param>
/// <param name="Max">The longest validity from then on.</param>
public sealed record ValidityStep(DateTimeOffset From, TimeSpan Max);

/// <summary>
/// What a class of certificate must look like, as data: the key usage, extended key usage, basic constraints, subject alternative name rules and the longest
/// validity. A <see cref="CertificateAuthority"/> refuses to issue anything a profile does not allow and writes the extensions the profile fixes. Make your own with
/// object initializers; the presets are starting points that follow the CA/Browser Forum baseline where there is one.
/// </summary>
public sealed class CertificateProfile
{
    /// <summary>A name for messages and reports.</summary>
    public required string Name { get; init; }

    /// <summary>True for a certificate that may issue certificates (basicConstraints cA, critical).</summary>
    public bool IsCa { get; init; }

    /// <summary>For a CA profile, the path length constraint to write, or null for none. The issuing CA's own constraint still applies, whichever is stricter.</summary>
    public int? MaxPathLength { get; init; }

    /// <summary>The key usage bits written (critical, RFC 5280 §4.2.1.3).</summary>
    public KeyUsages KeyUsages { get; init; }

    /// <summary>Further key usage bits added when the subject key is RSA (key encipherment, for S/MIME encryption certificates).</summary>
    public KeyUsages RsaAdditionalKeyUsages { get; init; }

    /// <summary>The extended key usage purposes written, or empty for none.</summary>
    public IReadOnlyList<string> ExtendedKeyUsages { get; init; } = [];

    /// <summary>True to mark the extended key usage extension critical (RFC 3161 §2.3 requires it for a time-stamping certificate).</summary>
    public bool ExtendedKeyUsageCritical { get; init; }

    /// <summary>True to add id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1), for a delegated OCSP responder certificate.</summary>
    public bool OcspNoCheck { get; init; }

    /// <summary>True when the certificate must have a subject alternative name.</summary>
    public bool SubjectAlternativeNameRequired { get; init; }

    /// <summary>The name kinds a subject alternative name may hold. Empty means none, and a request for one is refused.</summary>
    public IReadOnlyList<GeneralNameKind> AllowedSubjectAlternativeNames { get; init; } = [];

    /// <summary>The longest validity the profile allows, unless <see cref="ValiditySchedule"/> says otherwise for the issuance date.</summary>
    public required TimeSpan MaxValidity { get; init; }

    /// <summary>Limits that start on a date, for rules that tighten over time. The step with the latest <see cref="ValidityStep.From"/> that is not after the certificate's notBefore applies; before the first step, <see cref="MaxValidity"/>.</summary>
    public IReadOnlyList<ValidityStep> ValiditySchedule { get; init; } = [];

    /// <summary>The longest validity for a certificate that starts at <paramref name="notBefore"/>.</summary>
    public TimeSpan MaxValidityAt(DateTimeOffset notBefore)
    {
        TimeSpan max = MaxValidity;
        DateTimeOffset latest = DateTimeOffset.MinValue;
        foreach (ValidityStep step in ValiditySchedule)
        {
            if (step.From <= notBefore && step.From >= latest)
            {
                latest = step.From;
                max = step.Max;
            }
        }

        return max;
    }

    /// <summary>A self-signed or cross-certified root: cA, keyCertSign and cRLSign, 25 years.</summary>
    public static CertificateProfile Root { get; } = new()
    {
        Name = "root",
        IsCa = true,
        KeyUsages = KeyUsages.KeyCertSign | KeyUsages.CrlSign,
        MaxValidity = TimeSpan.FromDays(25 * 365),
    };

    /// <summary>An intermediate CA: cA, keyCertSign and cRLSign, 10 years, no path length unless set by the issuer.</summary>
    public static CertificateProfile Intermediate { get; } = new()
    {
        Name = "intermediate",
        IsCa = true,
        KeyUsages = KeyUsages.KeyCertSign | KeyUsages.CrlSign,
        MaxValidity = TimeSpan.FromDays(10 * 365),
    };

    /// <summary>
    /// A TLS server certificate: digitalSignature, serverAuth, a DNS or IP subject alternative name required. The longest validity follows the schedule of the
    /// CA/Browser Forum TLS Baseline Requirements §6.3.2 (version 2.3.1): 398 days before 2026-03-15, then 200 days, 100 days from 2027-03-15 and 47 days from 2029-03-15.
    /// </summary>
    public static CertificateProfile TlsServer { get; } = new()
    {
        Name = "tls-server",
        KeyUsages = KeyUsages.DigitalSignature,
        ExtendedKeyUsages = [KnownOids.ServerAuth],
        SubjectAlternativeNameRequired = true,
        AllowedSubjectAlternativeNames = [GeneralNameKind.DnsName, GeneralNameKind.IPAddress],
        MaxValidity = TimeSpan.FromDays(398),
        ValiditySchedule =
        [
            new ValidityStep(new DateTimeOffset(2026, 3, 15, 0, 0, 0, TimeSpan.Zero), TimeSpan.FromDays(200)),
            new ValidityStep(new DateTimeOffset(2027, 3, 15, 0, 0, 0, TimeSpan.Zero), TimeSpan.FromDays(100)),
            new ValidityStep(new DateTimeOffset(2029, 3, 15, 0, 0, 0, TimeSpan.Zero), TimeSpan.FromDays(47)),
        ],
    };

    /// <summary>A TLS client certificate: digitalSignature, clientAuth, any identity-like subject alternative name, 398 days (our default; no baseline sets one for client certificates).</summary>
    public static CertificateProfile TlsClient { get; } = new()
    {
        Name = "tls-client",
        KeyUsages = KeyUsages.DigitalSignature,
        ExtendedKeyUsages = [KnownOids.ClientAuth],
        AllowedSubjectAlternativeNames = [GeneralNameKind.DnsName, GeneralNameKind.Rfc822Name, GeneralNameKind.Uri, GeneralNameKind.IPAddress],
        MaxValidity = TimeSpan.FromDays(398),
    };

    /// <summary>An S/MIME certificate: digitalSignature and nonRepudiation (plus keyEncipherment for RSA), emailProtection, an rfc822Name subject alternative name required, 825 days (our default).</summary>
    public static CertificateProfile SMime { get; } = new()
    {
        Name = "smime",
        KeyUsages = KeyUsages.DigitalSignature | KeyUsages.NonRepudiation,
        RsaAdditionalKeyUsages = KeyUsages.KeyEncipherment,
        ExtendedKeyUsages = [KnownOids.EmailProtection],
        SubjectAlternativeNameRequired = true,
        AllowedSubjectAlternativeNames = [GeneralNameKind.Rfc822Name],
        MaxValidity = TimeSpan.FromDays(825),
    };

    /// <summary>A code-signing certificate: digitalSignature, codeSigning, no subject alternative name, 1185 days (39 months; our default).</summary>
    public static CertificateProfile CodeSigning { get; } = new()
    {
        Name = "code-signing",
        KeyUsages = KeyUsages.DigitalSignature,
        ExtendedKeyUsages = [KnownOids.CodeSigning],
        MaxValidity = TimeSpan.FromDays(1185),
    };

    /// <summary>A delegated OCSP responder certificate: digitalSignature, id-kp-OCSPSigning, id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2), 90 days (our default; a short life limits what a stolen responder key can vouch for).</summary>
    public static CertificateProfile OcspSigning { get; } = new()
    {
        Name = "ocsp-signing",
        KeyUsages = KeyUsages.DigitalSignature,
        ExtendedKeyUsages = [KnownOids.OcspSigning],
        OcspNoCheck = true,
        MaxValidity = TimeSpan.FromDays(90),
    };

    /// <summary>A time-stamping authority certificate: digitalSignature, a critical extended key usage naming only id-kp-timeStamping (RFC 3161 §2.3), 15 years.</summary>
    public static CertificateProfile TimeStamping { get; } = new()
    {
        Name = "time-stamping",
        KeyUsages = KeyUsages.DigitalSignature,
        ExtendedKeyUsages = [KnownOids.TimeStamping],
        ExtendedKeyUsageCritical = true,
        MaxValidity = TimeSpan.FromDays(15 * 365),
    };
}
