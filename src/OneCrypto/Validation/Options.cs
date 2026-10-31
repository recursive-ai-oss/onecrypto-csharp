using System.Linq;
using System.Collections.Immutable;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

/// <summary>A trust anchor: a certificate, or just a name and a public key (RFC 5937 §2).</summary>
public sealed class TrustAnchor
{
    private TrustAnchor(Certificate? certificate, DistinguishedName name, PublicKeyInfo key)
    {
        Certificate = certificate;
        Name = name;
        PublicKey = key;
    }

    /// <summary>The anchor's certificate, or null for a bare name and key.</summary>
    public Certificate? Certificate { get; }

    /// <summary>The anchor's name: what the issuer field of the certificates it signed must match.</summary>
    public DistinguishedName Name { get; }

    /// <summary>The anchor's public key.</summary>
    public PublicKeyInfo PublicKey { get; }

    /// <summary>Trusts a certificate. Its key and name are used, and, per <see cref="ValidationOptions.ApplyAnchorNameConstraints"/>, its name constraints.</summary>
    public static TrustAnchor FromCertificate(Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new(certificate, certificate.Subject, certificate.PublicKey);
    }

    /// <summary>Trusts a name and key without a certificate.</summary>
    public static TrustAnchor FromNameAndKey(DistinguishedName name, PublicKeyInfo key)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(key);
        return new(null, name, key);
    }
}

/// <summary>Work limits, on by default. A limit that is reached is reported (<see cref="ValidationReport.LimitReached"/>), never thrown.</summary>
public sealed class ValidationLimits
{
    /// <summary>The defaults.</summary>
    public static ValidationLimits Default { get; } = new();

    /// <summary>The most certificates in a path including the target (default 16 below the anchor, RFC 4158 §4 leaves it to the application).</summary>
    public int MaxPathLength { get; init; } = 16;

    /// <summary>The most issuer candidates examined for one certificate (default 64).</summary>
    public int MaxCandidatesPerCertificate { get; init; } = 64;

    /// <summary>The most search steps over the whole validation (default 20,000).</summary>
    public int MaxSearchSteps { get; init; } = 20_000;

    /// <summary>The most signature verifications over the whole validation (default 256). Results are cached per certificate and key.</summary>
    public int MaxSignatureChecks { get; init; } = 256;

    /// <summary>The most paths that are fully validated (default 32).</summary>
    public int MaxPathsValidated { get; init; } = 32;

    /// <summary>The most paths kept in the report (default 16).</summary>
    public int MaxReportedPaths { get; init; } = 16;

    /// <summary>The most nodes the policy tree may hold at any time (default 4,000). The published policy-tree explosion constructions need exponentially many.</summary>
    public int MaxPolicyNodes { get; init; } = 4_000;

    /// <summary>The most name/constraint comparisons for one path (default 2,000,000).</summary>
    public int MaxNameConstraintComparisons { get; init; } = 2_000_000;

    /// <summary>The most CRLs and OCSP responses examined per certificate (default 64).</summary>
    public int MaxRevocationObjectsPerCertificate { get; init; } = 64;

    /// <summary>The most rounds of asking an <see cref="ICertificateSource"/> or <see cref="IRevocationSource"/> (default 8).</summary>
    public int MaxSourceRounds { get; init; } = 8;
}

/// <summary>Which certificates must have revocation data.</summary>
public enum RevocationScope
{
    /// <summary>Revocation is not required. Data that is supplied is still used.</summary>
    None,

    /// <summary>The target.</summary>
    EndEntity,

    /// <summary>Every certificate of the path except the trust anchor.</summary>
    AllCertificates,
}

/// <summary>How revocation after the reference time is treated.</summary>
public enum RevocationModel
{
    /// <summary>RFC 5280 §6.3: a certificate listed as revoked is revoked, whatever the date.</summary>
    Current,

    /// <summary>
    /// Validation at an earlier instant with revocation data collected later: a certificate revoked after the reference time with a
    /// reason other than keyCompromise, cACompromise, aACompromise or unspecified still counts as good at the reference time
    /// (the intent of ETSI EN 319 102-1 §5.6.2.1). A "good" answer needs data issued at or after the reference time.
    /// </summary>
    PastTime,
}

/// <summary>What an algorithm check is asked about.</summary>
/// <param name="SignatureAlgorithm">The signature algorithm of a certificate, CRL or OCSP response.</param>
/// <param name="IssuerKey">The public key that verifies it.</param>
/// <param name="ReferenceTime">The validation instant, so a check can have dated cutoffs.</param>
public sealed record AlgorithmQuery(AlgorithmIdentifier SignatureAlgorithm, PublicKeyInfo IssuerKey, DateTimeOffset ReferenceTime);

/// <summary>The answer of an algorithm check.</summary>
/// <param name="Outcome"><see cref="RuleOutcome.Pass"/>, <see cref="RuleOutcome.Warning"/> or <see cref="RuleOutcome.Fail"/>.</param>
/// <param name="Reason">The reason, in plain words.</param>
public sealed record AlgorithmDecision(RuleOutcome Outcome, string Reason)
{
    /// <summary>The algorithm is acceptable.</summary>
    public static AlgorithmDecision Accept { get; } = new(RuleOutcome.Pass, "algorithm accepted");
}

/// <summary>Ready-made algorithm checks.</summary>
public static class AlgorithmChecks
{
    /// <summary>Accepts everything the library can verify: the checks RFC 5280 itself makes.</summary>
    public static AlgorithmDecision Rfc5280Only(AlgorithmQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        return AlgorithmDecision.Accept;
    }

    /// <summary>
    /// The default. MD2/MD4/MD5 signatures fail; SHA-1 signatures are a warning before 2017-01-01 and fail from then on
    /// (the date public CAs stopped issuing and browsers stopped trusting them); RSA keys under 1024 bits fail,
    /// under 2048 bits warn before 2014-01-01 and fail from then on (the date the Baseline Requirements set 2048 as the minimum).
    /// </summary>
    public static AlgorithmDecision Standard(AlgorithmQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        string oid = query.SignatureAlgorithm.Oid;
        if (oid == KnownOids.Md5WithRsa)
        {
            return new(RuleOutcome.Fail, "MD5 signatures are not acceptable");
        }

        bool sha1 = oid == KnownOids.Sha1WithRsa || oid == KnownOids.EcdsaSha1;
        if (sha1)
        {
            return query.ReferenceTime >= new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero)
                ? new(RuleOutcome.Fail, "SHA-1 signatures are not acceptable at or after 2017-01-01")
                : new(RuleOutcome.Warning, "SHA-1 signature accepted for data before 2017-01-01");
        }

        if (query.IssuerKey.KeyAlgorithm is KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss)
        {
            int bits = query.IssuerKey.KeySizeBits;
            if (bits > 0 && bits < 1024)
            {
                return new(RuleOutcome.Fail, $"RSA key of {bits} bits is too small");
            }

            if (bits > 0 && bits < 2048)
            {
                return query.ReferenceTime >= new DateTimeOffset(2014, 1, 1, 0, 0, 0, TimeSpan.Zero)
                    ? new(RuleOutcome.Fail, $"RSA key of {bits} bits is below 2048 bits, not acceptable at or after 2014-01-01")
                    : new(RuleOutcome.Warning, $"RSA key of {bits} bits accepted for data before 2014-01-01");
            }
        }

        return AlgorithmDecision.Accept;
    }
}

/// <summary>The server-authentication profile (opt-in): the extra rules WebPKI clients apply on top of RFC 5280. It is a layer of rules over the same validation, not a separate validator.</summary>
public sealed class WebPkiProfile
{
    /// <summary>The DNS name or IP address the certificate must be valid for (RFC 9525 §6: subjectAltName only, never the common name). Null skips host matching.</summary>
    public string? ServerName { get; init; }

    /// <summary>Require the target to carry a subjectAltName and, if it has an extKeyUsage, serverAuth (default true).</summary>
    public bool RequireServerAuth { get; init; } = true;

    /// <summary>
    /// Apply the Baseline Requirements' structural rules: the target is not a CA, CA certificates carry basicConstraints marked critical
    /// and keyCertSign, subscriber keys are RSA 2048+ or P-256/384/521 or Ed25519, serial numbers are positive and at most 20 octets,
    /// and the target states serverAuth in a non-critical extKeyUsage that does not use anyExtendedKeyUsage (default true).
    /// </summary>
    public bool EnforceBaselineRequirements { get; init; } = true;

    /// <summary>
    /// Also require a commonName in the target's subject, if there is one, to repeat a subjectAltName entry exactly (Baseline Requirements §7.1.4.3, a rule on what CAs issue).
    /// Off by default: clients identify servers by subjectAltName and ignore the commonName, so a stray commonName does not make a certificate unusable (RFC 9525 §2).
    /// </summary>
    public bool RequireCommonNameInSan { get; init; }
}

/// <summary>Input of a validation.</summary>
public sealed class ValidationOptions
{
    /// <summary>The trust anchors. Required; an empty list gives an <see cref="ValidationVerdict.Invalid"/> report.</summary>
    public IReadOnlyList<TrustAnchor> TrustAnchors { get; init; } = [];

    /// <summary>Certificates that may serve as intermediates. Anything in this pool is untrusted; only the anchors confer trust.</summary>
    public IReadOnlyList<Certificate> Intermediates { get; init; } = [];

    /// <summary>The instant validity, algorithm cutoffs and revocation freshness are judged at. Required: the validator never reads a clock.</summary>
    public required DateTimeOffset ReferenceTime { get; init; }

    /// <summary>The instant revocation data is judged fresh at (CRL and OCSP thisUpdate/nextUpdate). Defaults to <see cref="ReferenceTime"/>; for the past-time model it is the time the data was collected.</summary>
    public DateTimeOffset? RevocationDataTime { get; init; }

    /// <summary>CRLs and OCSP responses to use. Nothing is fetched.</summary>
    public RevocationData? Revocation { get; init; }

    /// <summary>Which certificates need revocation data (default <see cref="RevocationScope.None"/>).</summary>
    public RevocationScope RevocationRequired { get; init; } = RevocationScope.None;

    /// <summary>Whether missing revocation data for a required certificate makes the verdict <see cref="ValidationVerdict.Indeterminate"/> (default false: it is reported, the verdict stays valid).</summary>
    public bool UnknownRevocationIsFatal { get; init; }

    /// <summary>How revocation after the reference time counts (default <see cref="RevocationModel.Current"/>).</summary>
    public RevocationModel RevocationModel { get; init; } = RevocationModel.Current;

    /// <summary>OCSP responses are fresh for this long after thisUpdate when they carry no nextUpdate (default 7 days).</summary>
    public TimeSpan OcspMaxAge { get; init; } = TimeSpan.FromDays(7);

    /// <summary>The check applied to every signature algorithm and key (default <see cref="AlgorithmChecks.Standard"/>).</summary>
    public Func<AlgorithmQuery, AlgorithmDecision> AlgorithmCheck { get; init; } = AlgorithmChecks.Standard;

    /// <summary>The purpose the target must be usable for, as an extended-key-usage OID (for example <see cref="KnownOids.ServerAuth"/>); null does not check. Intermediates that carry an extKeyUsage must allow it too.</summary>
    public string? RequiredExtendedKeyUsage { get; init; }

    /// <summary>Key usage bits the target's keyUsage extension, if present, must include.</summary>
    public KeyUsages RequiredKeyUsage { get; init; }

    /// <summary>Policies the caller accepts (user-initial-policy-set, RFC 5280 §6.1.1 (c)); empty means any policy.</summary>
    public IReadOnlyList<string> InitialPolicySet { get; init; } = [];

    /// <summary>initial-explicit-policy (§6.1.1 (f)).</summary>
    public bool InitialExplicitPolicy { get; init; }

    /// <summary>initial-policy-mapping-inhibit (§6.1.1 (g)).</summary>
    public bool InitialPolicyMappingInhibit { get; init; }

    /// <summary>initial-any-policy-inhibit (§6.1.1 (h)).</summary>
    public bool InitialAnyPolicyInhibit { get; init; }

    /// <summary>When a certificate is an anchor, apply the name constraints in it (default true; RFC 5937 §3.2 leaves it to the application).</summary>
    public bool ApplyAnchorNameConstraints { get; init; } = true;

    /// <summary>Also apply the policy-related extensions of an anchor certificate (policyConstraints, inhibitAnyPolicy); default false.</summary>
    public bool ApplyAnchorPolicyConstraints { get; init; }

    /// <summary>Require the anchor certificate to be valid at the reference time (default true).</summary>
    public bool CheckAnchorValidity { get; init; } = true;

    /// <summary>The longest chain of non-self-issued intermediates, as a hard cap (null: pathLenConstraints only). A third-party maximum depth such as 0 means the target must be signed directly by an anchor.</summary>
    public int? MaxIntermediates { get; init; }

    /// <summary>
    /// Apply the checks RFC 5280 states as MUST beyond path validation: unique extensions, positive serial numbers of at most 20 octets,
    /// subject key identifiers on CA certificates, authority key identifiers on non-self-signed certificates and so on. Default true.
    /// </summary>
    public bool StrictStructure { get; init; } = true;

    /// <summary>The server-authentication profile; null leaves it off.</summary>
    public WebPkiProfile? WebPki { get; init; }

    /// <summary>Work limits.</summary>
    public ValidationLimits Limits { get; init; } = ValidationLimits.Default;

    /// <summary>Asked for missing issuers by <see cref="PathValidator.ValidateAsync"/> only.</summary>
    public ICertificateSource? CertificateSource { get; init; }

    /// <summary>Asked for missing revocation data by <see cref="PathValidator.ValidateAsync"/> only.</summary>
    public IRevocationSource? RevocationSource { get; init; }

    /// <summary>Responders trusted directly for OCSP (RFC 6960 §4.2.2.2 (1) "trusted responder"); their certificates need no chain.</summary>
    public IReadOnlyList<Certificate> TrustedOcspResponders { get; init; } = [];
}

/// <summary>Revocation data supplied by the caller, as received.</summary>
public sealed class RevocationData
{
    /// <summary>CRLs, complete and delta.</summary>
    public IReadOnlyList<CertificateRevocationList> Crls { get; init; } = [];

    /// <summary>Basic OCSP responses (take them from <see cref="OcspResponse.BasicResponse"/>).</summary>
    public IReadOnlyList<OcspBasicResponse> OcspResponses { get; init; } = [];
}

/// <summary>Finds issuer certificates the caller's pool lacks. The validator calls it only from <see cref="PathValidator.ValidateAsync"/>, with the locations the certificate itself names; implementations decide whether to fetch.</summary>
public interface ICertificateSource
{
    /// <summary>Candidates that might have issued <paramref name="subject"/>.</summary>
    /// <param name="subject">The certificate that lacks an issuer.</param>
    /// <param name="caIssuersUris">Its authorityInfoAccess caIssuers locations.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    ValueTask<IReadOnlyList<Certificate>> FindIssuersAsync(Certificate subject, IReadOnlyList<string> caIssuersUris, CancellationToken cancellationToken);
}

/// <summary>Finds revocation data for a certificate. The validator calls it only from <see cref="PathValidator.ValidateAsync"/>.</summary>
public interface IRevocationSource
{
    /// <summary>Revocation data that might cover <paramref name="certificate"/>.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="issuer">Its issuer in the selected path.</param>
    /// <param name="crlUris">Its cRLDistributionPoints locations.</param>
    /// <param name="ocspUris">Its authorityInfoAccess OCSP locations.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    ValueTask<RevocationData> GetRevocationDataAsync(Certificate certificate, Certificate issuer, IReadOnlyList<string> crlUris, IReadOnlyList<string> ocspUris, CancellationToken cancellationToken);
}
