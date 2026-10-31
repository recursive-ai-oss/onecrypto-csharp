using System.Collections.Immutable;
using System.Linq;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

/// <summary>The overall answer of a validation.</summary>
public enum ValidationVerdict
{
    /// <summary>At least one path satisfies every rule. Revocation may still be reported as unknown; see <see cref="ValidationReport.RevocationSummary"/>.</summary>
    Valid,

    /// <summary>No path satisfies the rules; <see cref="ValidationReport.DecidingRule"/> names the rule that decided it.</summary>
    Invalid,

    /// <summary>A path satisfies every rule that could be decided, but a required answer is missing (revocation data the caller required, a work limit that was reached).</summary>
    Indeterminate,
}

/// <summary>The rules the validator reports on. Each result carries the clause it comes from.</summary>
public enum ValidationRule
{
    /// <summary>A path from the target to a trust anchor exists (RFC 4158 §2, RFC 5280 §6.1).</summary>
    PathBuilding,

    /// <summary>The path is no longer than the limit.</summary>
    PathLength,

    /// <summary>The signature verifies over the received bytes (§6.1.3 (a)(1)).</summary>
    Signature,

    /// <summary>The certificate is valid at the reference time (§6.1.3 (a)(2)).</summary>
    Validity,

    /// <summary>The issuer name equals the working issuer name (§6.1.3 (a)(4)).</summary>
    IssuerName,

    /// <summary>Name constraints (§6.1.3 (b), (c), §4.2.1.10).</summary>
    NameConstraints,

    /// <summary>Certificate policies, mappings and the constraints on them (§6.1.3 (d)–(f), §6.1.4, §6.1.5).</summary>
    Policy,

    /// <summary>basicConstraints: a CA certificate asserts cA (§6.1.4 (k), §4.2.1.9).</summary>
    BasicConstraints,

    /// <summary>The number of non-self-issued intermediates is within pathLenConstraint (§6.1.4 (l), (m)).</summary>
    PathLengthConstraint,

    /// <summary>keyUsage (§6.1.4 (n), §4.2.1.3).</summary>
    KeyUsage,

    /// <summary>Extended key usage, chained through the CAs (§4.2.1.12).</summary>
    ExtendedKeyUsage,

    /// <summary>Critical extensions are recognised (§6.1.4 (o), §6.1.5 (f)).</summary>
    CriticalExtension,

    /// <summary>The certificate is well formed in the ways RFC 5280 requires beyond ASN.1 (§4.1, §4.2).</summary>
    Structure,

    /// <summary>The algorithm is acceptable under the caller's algorithm check.</summary>
    Algorithm,

    /// <summary>The trust anchor itself (§6.1.1 (d), RFC 5937).</summary>
    TrustAnchor,

    /// <summary>The certificate is not revoked (§6.3, RFC 6960).</summary>
    Revocation,

    /// <summary>A name in the certificate matches the expected host name or address (RFC 9525 §6).</summary>
    HostName,

    /// <summary>The server-authentication profile's additional rules (CA/Browser Forum Baseline Requirements).</summary>
    WebPkiProfile,

    /// <summary>A work limit was reached.</summary>
    Limit,
}

/// <summary>How one rule came out for one certificate.</summary>
public enum RuleOutcome
{
    /// <summary>The rule holds.</summary>
    Pass,

    /// <summary>The rule holds but something deserves attention (for example an algorithm accepted for old data only).</summary>
    Warning,

    /// <summary>The rule does not hold.</summary>
    Fail,

    /// <summary>The rule could not be decided (for example missing revocation data when it was required).</summary>
    Indeterminate,

    /// <summary>The rule does not apply to this certificate.</summary>
    NotApplicable,
}

/// <summary>One rule applied to one certificate: what was decided, why in plain words, and the clause it comes from.</summary>
/// <param name="Rule">The rule.</param>
/// <param name="Outcome">The outcome.</param>
/// <param name="Reason">A short reason in plain words.</param>
/// <param name="Clause">The RFC clause, for example <c>RFC 5280 §6.1.3 (a)(2)</c>.</param>
public sealed record RuleResult(ValidationRule Rule, RuleOutcome Outcome, string Reason, string Clause)
{
    /// <inheritdoc/>
    public override string ToString() => $"{Rule}: {Outcome} ({Reason}; {Clause})";
}

/// <summary>What the validator learned about a certificate's revocation status.</summary>
public enum RevocationStatus
{
    /// <summary>Not looked at: revocation checking was not requested for this certificate.</summary>
    NotChecked,

    /// <summary>Fresh, authorised data says the certificate is not revoked.</summary>
    Good,

    /// <summary>Fresh, authorised data says the certificate is revoked (or on hold).</summary>
    Revoked,

    /// <summary>No usable data: none supplied, stale, not yet valid, out of scope or from an unauthorised signer. <see cref="RevocationReport.Reason"/> says which.</summary>
    Unknown,
}

/// <summary>The revocation finding for one certificate.</summary>
/// <param name="Status">The status.</param>
/// <param name="Reason">Why, in plain words.</param>
/// <param name="Clause">The clause the finding comes from.</param>
/// <param name="RevocationTime">When it was revoked, for <see cref="RevocationStatus.Revoked"/>.</param>
/// <param name="RevocationReason">The reason given, if any.</param>
/// <param name="Source">The data used: <c>CRL</c>, <c>OCSP</c> or null.</param>
public sealed record RevocationReport(
    RevocationStatus Status,
    string Reason,
    string Clause,
    DateTimeOffset? RevocationTime = null,
    RevocationReason? RevocationReason = null,
    string? Source = null)
{
    /// <summary>The finding for a certificate nobody asked about.</summary>
    public static RevocationReport NotCheckedReport { get; } = new(RevocationStatus.NotChecked, "revocation checking was not requested for this certificate", "RFC 5280 §6.3");
}

/// <summary>The results for one certificate of a path.</summary>
public sealed class CertificateReport
{
    internal CertificateReport(Certificate certificate, int index, bool isTrustAnchor, ImmutableArray<RuleResult> results, RevocationReport revocation)
    {
        Certificate = certificate;
        Index = index;
        IsTrustAnchor = isTrustAnchor;
        Results = results;
        Revocation = revocation;
    }

    /// <summary>The certificate (a trust anchor given as name and key has no certificate and is not listed).</summary>
    public Certificate Certificate { get; }

    /// <summary>Position in the path: 0 is the certificate under the trust anchor, the last is the target.</summary>
    public int Index { get; }

    /// <summary>True when this certificate is itself the trust anchor (the target was trusted directly).</summary>
    public bool IsTrustAnchor { get; }

    /// <summary>The rule results, in the order the rules were applied.</summary>
    public ImmutableArray<RuleResult> Results { get; }

    /// <summary>The revocation finding.</summary>
    public RevocationReport Revocation { get; }

    /// <summary>The first failing result, or null.</summary>
    public RuleResult? FirstFailure => Results.FirstOrDefault(r => r.Outcome is RuleOutcome.Fail or RuleOutcome.Indeterminate);
}

/// <summary>The result of the certificate-policy computation of RFC 5280 §6.1.</summary>
/// <param name="Computed">True when the policy tree was computed (false when the path failed earlier).</param>
/// <param name="ExplicitPolicyRequired">True when an explicit policy was required at the end of the path.</param>
/// <param name="AuthoritiesConstrainedPolicySet">The policies the whole path is valid under (the tree's valid policies); empty for a NULL tree.</param>
/// <param name="TreeIsNull">True when the valid_policy_tree ended NULL.</param>
public sealed record PolicyReport(bool Computed, bool ExplicitPolicyRequired, ImmutableArray<string> AuthoritiesConstrainedPolicySet, bool TreeIsNull);

/// <summary>Everything the validator decided about one candidate path.</summary>
public sealed class PathReport
{
    internal PathReport(
        ImmutableArray<CertificateReport> certificates,
        Certificate? anchorCertificate,
        string? anchorName,
        ValidationVerdict verdict,
        RuleResult? decidingResult,
        int decidingIndex,
        PolicyReport policy,
        ImmutableArray<RuleResult> pathResults)
    {
        Certificates = certificates;
        AnchorCertificate = anchorCertificate;
        AnchorName = anchorName;
        Verdict = verdict;
        DecidingResult = decidingResult;
        DecidingIndex = decidingIndex;
        Policy = policy;
        PathResults = pathResults;
    }

    /// <summary>The certificates below the anchor, from the one the anchor signed to the target. When the target is itself trusted, one entry.</summary>
    public ImmutableArray<CertificateReport> Certificates { get; }

    /// <summary>The trust anchor's certificate, or null when the path did not end at one or the anchor was a bare name and key.</summary>
    public Certificate? AnchorCertificate { get; }

    /// <summary>The anchor's name in RFC 4514 form, or null when the path did not end at an anchor.</summary>
    public string? AnchorName { get; }

    /// <summary>The path's verdict.</summary>
    public ValidationVerdict Verdict { get; }

    /// <summary>The result that decided an <see cref="ValidationVerdict.Invalid"/> or <see cref="ValidationVerdict.Indeterminate"/> verdict, or null.</summary>
    public RuleResult? DecidingResult { get; }

    /// <summary>The index in <see cref="Certificates"/> of the certificate the deciding result belongs to, or -1 for a path-level result.</summary>
    public int DecidingIndex { get; }

    /// <summary>The policy computation.</summary>
    public PolicyReport Policy { get; }

    /// <summary>Path-level results (path building, the path-wide policy outcome, limits).</summary>
    public ImmutableArray<RuleResult> PathResults { get; }

    /// <summary>The target certificate (the last in the path).</summary>
    public Certificate Target => Certificates[^1].Certificate;
}

/// <summary>A candidate issuer the builder looked at and refused, with the reason.</summary>
/// <param name="Subject">The certificate that needed an issuer.</param>
/// <param name="Candidate">The candidate.</param>
/// <param name="Reason">Why it was refused.</param>
public sealed record RejectedCandidate(Certificate Subject, Certificate Candidate, string Reason);

/// <summary>A CA-issuers location found in a certificate that the validator did not fetch.</summary>
/// <param name="Certificate">The certificate carrying the location.</param>
/// <param name="Uri">The location (RFC 5280 §4.2.2.1 id-ad-caIssuers).</param>
public sealed record IssuerLocation(Certificate Certificate, string Uri);

/// <summary>The full answer of <see cref="PathValidator"/>: the verdict, the path it chose and every path it tried.</summary>
public sealed class ValidationReport
{
    internal ValidationReport(
        ValidationVerdict verdict,
        PathReport? selectedPath,
        ImmutableArray<PathReport> paths,
        ImmutableArray<RejectedCandidate> rejected,
        ImmutableArray<IssuerLocation> issuerLocations,
        ImmutableArray<Certificate> unchained,
        ImmutableArray<RuleResult> targetResults,
        bool limitReached,
        DateTimeOffset referenceTime,
        RevocationStatus revocationSummary)
    {
        Verdict = verdict;
        SelectedPath = selectedPath;
        Paths = paths;
        Rejected = rejected;
        IssuerLocations = issuerLocations;
        Unchained = unchained;
        TargetResults = targetResults;
        LimitReached = limitReached;
        ReferenceTime = referenceTime;
        RevocationSummary = revocationSummary;
    }

    /// <summary>The verdict.</summary>
    public ValidationVerdict Verdict { get; }

    /// <summary>True when <see cref="Verdict"/> is <see cref="ValidationVerdict.Valid"/>.</summary>
    public bool IsValid => Verdict == ValidationVerdict.Valid;

    /// <summary>The path the verdict rests on: the valid path, or for a failure the path that got furthest; null when no certificate could be chained at all.</summary>
    public PathReport? SelectedPath { get; }

    /// <summary>The rule that decided a failed or indeterminate verdict, or null for a valid one.</summary>
    public RuleResult? DecidingRule => Verdict == ValidationVerdict.Valid ? null : SelectedPath?.DecidingResult ?? TargetResults.FirstOrDefault(r => r.Outcome is RuleOutcome.Fail or RuleOutcome.Indeterminate);

    /// <summary>Every path the builder completed or abandoned, in the order tried (at most <see cref="ValidationLimits.MaxReportedPaths"/>).</summary>
    public ImmutableArray<PathReport> Paths { get; }

    /// <summary>Candidate issuers that were refused during building (bounded).</summary>
    public ImmutableArray<RejectedCandidate> Rejected { get; }

    /// <summary>Locations from authorityInfoAccess caIssuers on certificates that lacked an issuer. Nothing was fetched from them.</summary>
    public ImmutableArray<IssuerLocation> IssuerLocations { get; }

    /// <summary>Certificates that had no issuer in the pool or among the anchors (path-building dead ends).</summary>
    public ImmutableArray<Certificate> Unchained { get; }

    /// <summary>Results about the target that do not depend on the path (host name, profile rules).</summary>
    public ImmutableArray<RuleResult> TargetResults { get; }

    /// <summary>True when a work limit stopped the search early, so a missing path is not proof that none exists.</summary>
    public bool LimitReached { get; }

    /// <summary>The instant the validation was done at.</summary>
    public DateTimeOffset ReferenceTime { get; }

    /// <summary>
    /// The weakest revocation status over the selected path's certificates that were checked:
    /// <see cref="RevocationStatus.Revoked"/>, else <see cref="RevocationStatus.Unknown"/>, else <see cref="RevocationStatus.Good"/>,
    /// or <see cref="RevocationStatus.NotChecked"/> when checking was off. A valid verdict with <see cref="RevocationStatus.Unknown"/> means
    /// the path is good but nothing has shown the certificates are not revoked.
    /// </summary>
    public RevocationStatus RevocationSummary { get; }

    /// <inheritdoc/>
    public override string ToString() => Verdict == ValidationVerdict.Valid
        ? $"Valid ({RevocationSummary})"
        : $"{Verdict}: {DecidingRule}";
}
