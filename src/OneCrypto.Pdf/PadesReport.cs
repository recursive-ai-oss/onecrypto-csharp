using OnePdf;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;

namespace RecursiveAI.OneCrypto.Pdf;

/// <summary>What a PDF signature dictionary is.</summary>
public enum PadesSignatureKind
{
    /// <summary>A CMS signature over the byte ranges (<c>adbe.pkcs7.detached</c> or <c>ETSI.CAdES.detached</c>).</summary>
    Signature,

    /// <summary>A document time-stamp (<c>ETSI.RFC3161</c>, ISO 32000-2 §12.8.5).</summary>
    DocumentTimestamp,

    /// <summary>A sub-filter the bridge does not evaluate (for example <c>adbe.pkcs7.sha1</c>). OnePDF's verdict stands, and the bridge adds nothing.</summary>
    Other,
}

/// <summary>A time-stamp found on a signature (RFC 3161 token in the signature, or a document time-stamp) and what was checked on it.</summary>
public sealed class PadesTimestamp
{
    internal PadesTimestamp(bool isDocument, string? fieldName, TimeStampReport? report, IReadOnlyList<CmsCheck> checks, long coveredEnd, long holeStart, bool trusted)
    {
        IsDocument = isDocument;
        FieldName = fieldName;
        Report = report;
        Checks = checks;
        CoveredEnd = coveredEnd;
        HoleStart = holeStart;
        IsTrusted = trusted;
    }

    /// <summary>True for a document time-stamp, false for the signature time-stamp inside a signature.</summary>
    public bool IsDocument { get; }

    /// <summary>The field of a document time-stamp.</summary>
    public string? FieldName { get; }

    /// <summary>The core report of the token: one check per rule with its RFC 3161 clause, and the authority's chain as of <c>genTime</c>. Null when the value did not parse as a time-stamp token (the reason is in <see cref="Checks"/>).</summary>
    public TimeStampReport? Report { get; }

    /// <summary>The core report, for code that wants a non-null value.</summary>
    /// <returns>The report.</returns>
    /// <exception cref="PadesException">The value did not parse as a time-stamp token (<see cref="PadesException.Reason"/> is <see cref="PadesError.NotPresent"/>); <see cref="Checks"/> says why.</exception>
    public TimeStampReport RequireReport() =>
        Report ?? throw new PadesException(PadesError.NotPresent, "The time-stamp has no report: " + (Checks.FirstOrDefault(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported)?.Reason ?? "the value did not parse as a time-stamp token."));

    /// <summary>The time-stamp token (a CMS SignedData), for code that wants a non-null value.</summary>
    /// <returns>The token.</returns>
    /// <exception cref="PadesException">There is no readable token (<see cref="PadesError.NotPresent"/>).</exception>
    public SignedData RequireToken() =>
        Report?.Token ?? throw new PadesException(PadesError.NotPresent, "The time-stamp has no readable token.");

    /// <summary>Gets the core report without a null check.</summary>
    /// <param name="report">The report.</param>
    /// <returns>False when the value did not parse as a time-stamp token.</returns>
    public bool TryGetReport([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out TimeStampReport? report)
    {
        report = Report;
        return report is not null;
    }

    /// <summary>One check per rule, with its reason and RFC 3161 clause (the core report's, or the single failure when there is no report).</summary>
    public IReadOnlyList<CmsCheck> Checks { get; }

    /// <summary>The time the authority put in the token, when the token parsed.</summary>
    public DateTimeOffset? GenTime => Report?.GenTime;

    /// <summary>The offset up to which the file is covered (a document time-stamp covers everything before its own contents).</summary>
    public long CoveredEnd { get; }

    internal long HoleStart { get; }

    /// <summary>True when every rule passed and the authority chains to a trust anchor the caller gave. Only such a time proves anything.</summary>
    public bool IsTrusted { get; }

    /// <summary>True when the token's own rules hold (imprint, signature, authority certificate); trust is <see cref="IsTrusted"/>.</summary>
    public bool IsValid => Report is not null && Report.IsValid;
}

/// <summary>The bridge's findings on one signature or document time-stamp, beside OnePDF's own verdict.</summary>
public sealed class PadesSignatureReport
{
    internal PadesSignatureReport(
        PdfSignatureVerification onePdf,
        PadesSignatureKind kind,
        IReadOnlyList<CmsCheck> checks,
        SignedDataReport? cms,
        ValidationReport? chain,
        IReadOnlyList<PadesTimestamp> timestamps,
        DateTimeOffset? proofOfExistence,
        DateTimeOffset validationTime,
        PadesLevel level,
        bool isValid)
    {
        OnePdf = onePdf;
        Kind = kind;
        Checks = checks;
        Cms = cms;
        Chain = chain;
        Timestamps = timestamps;
        ProofOfExistence = proofOfExistence;
        ValidationTime = validationTime;
        Level = level;
        IsValid = isValid;
    }

    /// <summary>OnePDF's verification of the same signature, untouched: byte range, digest, signature, chain, modification analysis, certification level.</summary>
    public PdfSignatureVerification OnePdf { get; }

    /// <summary>What the dictionary is.</summary>
    public PadesSignatureKind Kind { get; }

    /// <summary>The field name, if any.</summary>
    public string? FieldName => OnePdf.Signature.FieldName;

    /// <summary>One check per rule the bridge evaluated, each with its reason and the clause it comes from.</summary>
    public IReadOnlyList<CmsCheck> Checks { get; }

    /// <summary>The core CMS verification (signed attributes, digest, signature, ESS signing-certificate, countersignatures) of a signature; null for a document time-stamp or when the CMS did not parse.</summary>
    public SignedDataReport? Cms { get; }

    /// <summary>The path validator's report for the signer's certificate (paths tried, per-rule results, revocation findings), judged at <see cref="ValidationTime"/>.</summary>
    public ValidationReport? Chain { get; }

    /// <summary>The time-stamps relevant to this signature: its own signature time-stamp and every document time-stamp that covers it.</summary>
    public IReadOnlyList<PadesTimestamp> Timestamps { get; }

    /// <summary>
    /// The earliest instant a trusted time-stamp proves the signature existed (EN 319 102-1 §5.4), or null when none does. The signing
    /// time in the dictionary and in the CMS is the signer's own claim and is never used as this time.
    /// </summary>
    public DateTimeOffset? ProofOfExistence { get; }

    /// <summary>The instant the signer's chain was validated at: <see cref="ProofOfExistence"/> when there is one, otherwise the reference time.</summary>
    public DateTimeOffset ValidationTime { get; }

    /// <summary>The highest PAdES baseline level the signature reaches (EN 319 142-1 §6), or <see cref="PadesLevel.None"/>.</summary>
    public PadesLevel Level { get; }

    /// <summary>
    /// True when OnePDF's verdict is valid <em>and</em> every rule the bridge evaluated passed or only warned. The bridge adds rules to
    /// OnePDF's; it never turns one of OnePDF's failures into a pass.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>The check for <paramref name="rule"/>, if the bridge evaluated it.</summary>
    /// <param name="rule">A rule name such as <c>cms-signature</c> or <c>chain</c>.</param>
    public CmsCheck? Find(string rule) => Checks.FirstOrDefault(c => c.Rule == rule);

    /// <inheritdoc/>
    public override string ToString() =>
        $"{FieldName ?? "(unnamed)"}: {(IsValid ? "valid" : "not valid")}, {Kind}, level {Level}" + (ProofOfExistence is { } t ? $", proven at {t:u}" : string.Empty);
}

/// <summary>The verification of every signature and document time-stamp in a PDF.</summary>
public sealed class PadesReport
{
    internal PadesReport(IReadOnlyList<PadesSignatureReport> signatures, IReadOnlyList<string> warnings, DssSummary dss)
    {
        Signatures = signatures;
        Warnings = warnings;
        Dss = dss;
    }

    /// <summary>One report per signature or document time-stamp, in file order.</summary>
    public IReadOnlyList<PadesSignatureReport> Signatures { get; }

    /// <summary>Problems with the document security store and other notes about the file as a whole.</summary>
    public IReadOnlyList<string> Warnings { get; }

    /// <summary>What the document security store holds.</summary>
    public DssSummary Dss { get; }

    /// <summary>True when the file has at least one signature or time-stamp.</summary>
    public bool HasSignatures => Signatures.Count > 0;

    /// <summary>True when there is at least one and every one is valid.</summary>
    public bool AllValid => Signatures.Count > 0 && Signatures.All(static s => s.IsValid);

    /// <summary>A one-line summary.</summary>
    public string Summary
    {
        get
        {
            int valid = Signatures.Count(static s => s.IsValid);
            return Signatures.Count == 0 ? "No signatures." : $"{Signatures.Count} signature{(Signatures.Count == 1 ? string.Empty : "s")}: {valid} valid, {Signatures.Count - valid} not valid.";
        }
    }
}

/// <summary>Counts of what the /DSS dictionary holds.</summary>
/// <param name="Present">The document has a /DSS dictionary.</param>
/// <param name="Certificates">Certificates in the global arrays.</param>
/// <param name="Crls">CRLs in the global arrays.</param>
/// <param name="OcspResponses">OCSP responses in the global arrays.</param>
/// <param name="VriEntries">Entries of /VRI.</param>
public sealed record DssSummary(bool Present, int Certificates, int Crls, int OcspResponses, int VriEntries);

/// <summary>Choices for verification.</summary>
public sealed class PadesVerifyOptions
{
    /// <summary>Trust anchors. With none, every chain is reported untrusted (and no time-stamp is trusted).</summary>
    public IReadOnlyList<TrustAnchor> TrustAnchors { get; init; } = [];

    /// <summary>Untrusted intermediates besides those the PDF carries.</summary>
    public IReadOnlyList<Certificate> Intermediates { get; init; } = [];

    /// <summary>The instant of the verification: signatures without a trusted time-stamp are judged as of this instant. Required; the bridge reads no clock.</summary>
    public required DateTimeOffset ReferenceTime { get; init; }

    /// <summary>The algorithm policy, asked about every signature, time-stamp and certificate at the instant it is judged at (default <see cref="CryptoPolicy.Standard"/>).</summary>
    public CryptoPolicy Policy { get; init; } = CryptoPolicy.Standard;

    /// <summary>CRLs and OCSP responses to use besides those in the signature and in the document security store.</summary>
    public RevocationData? Revocation { get; init; }

    /// <summary>Which certificates need revocation data before the chain counts as valid (default none: the report still says <c>Unknown</c>, never "good").</summary>
    public RevocationScope RevocationRequired { get; init; } = RevocationScope.None;

    /// <summary>
    /// When revocation data is judged fresh. Default: the earliest trusted document time-stamp that covers all the stored data, else the
    /// newest issue time among the data (it is then judged as of its own issue, because when it was collected is not proven).
    /// </summary>
    public DateTimeOffset? RevocationDataTime { get; init; }

    /// <summary>Finds missing issuers (async verification only).</summary>
    public ICertificateSource? CertificateSource { get; init; }

    /// <summary>Finds revocation data (async verification only).</summary>
    public IRevocationSource? RevocationSource { get; init; }

    /// <summary>Require the signer certificate to permit signing documents, as OnePDF does (default true).</summary>
    public bool RequireSigningKeyUsage { get; init; } = true;

    /// <summary>Compare the signed revision with later ones (default true).</summary>
    public bool AnalyzeModifications { get; init; } = true;

    /// <summary>Validation limits for the path validator.</summary>
    public ValidationLimits Limits { get; init; } = ValidationLimits.Default;
}
