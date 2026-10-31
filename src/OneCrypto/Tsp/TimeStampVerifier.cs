using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Tsp;

/// <summary>Choices for checking a time-stamp response or token.</summary>
public sealed class TimeStampVerifyOptions
{
    /// <summary>Certificates to look for the authority's certificate in, besides those in the token (a token made without <c>certReq</c> carries none).</summary>
    public IReadOnlyList<Certificate> ExtraCertificates { get; init; } = [];

    /// <summary>The policy that judges the imprint hash and the token signature (default <see cref="CryptoPolicy.Standard"/>).</summary>
    public CryptoPolicy Policy { get; init; } = CryptoPolicy.Standard;

    /// <summary>
    /// The time the algorithms are judged at. Null (the default) means the token's own genTime, which is the right time for "was this algorithm acceptable when
    /// the stamp was made" but is the authority's claim; pass the moment of verification to ask whether it is acceptable now.
    /// </summary>
    public DateTimeOffset? ReferenceTime { get; init; }

    /// <summary>The limits for the CMS layer.</summary>
    public CmsLimits CmsLimits { get; init; } = CmsLimits.Default;

    /// <summary>
    /// Trust anchors for the authority's certificate. When empty (the default) the <c>trust</c> check is reported as not applicable; when set, the authority's
    /// certificate is validated by <see cref="PathValidator"/> as of the token's genTime, with the time-stamping extended key usage required, using the
    /// certificates of the token and <see cref="ExtraCertificates"/> as the untrusted pool.
    /// </summary>
    public IReadOnlyList<TrustAnchor> TrustAnchors { get; init; } = [];

    /// <summary>CRLs and OCSP responses the path validation may use; null means revocation is not checked and the report says so.</summary>
    public RevocationData? Revocation { get; init; }

    /// <summary>Whether a revocation answer is required for every certificate of the authority's path (default false: unknown revocation is reported, not fatal).</summary>
    public RevocationScope RevocationRequired { get; init; } = RevocationScope.None;
}

/// <summary>
/// What checking a time-stamp response against its request found: one <see cref="CmsCheck"/> per rule, with the RFC section it comes from, plus the parsed
/// pieces. The report speaks of the token's integrity and its binding to the request; whether the authority's certificate chains to a trust anchor and was not
/// revoked is answered by <see cref="PathValidator"/> when the options carry trust anchors, and reported as <c>trust</c>; without anchors it is not evaluated.
/// </summary>
public sealed class TimeStampReport
{
    internal TimeStampReport(TimeStampResponse? response, SignedData? token, TstInfo? info, Certificate? signer, SignedDataReport? signature, IReadOnlyList<CmsCheck> checks, IReadOnlyList<PolicyDecision> policy)
    {
        Response = response;
        Token = token;
        Info = info;
        SignerCertificate = signer;
        Signature = signature;
        Checks = checks;
        PolicyFindings = policy;
    }

    /// <summary>The response, or null when the input was a bare token or unreadable.</summary>
    public TimeStampResponse? Response { get; }

    /// <summary>The token, or null when there is none or it could not be read.</summary>
    public SignedData? Token { get; }

    /// <summary>The TSTInfo, or null when it could not be read.</summary>
    public TstInfo? Info { get; }

    /// <summary>The authority's certificate, or null when none matched the signer identifier.</summary>
    public Certificate? SignerCertificate { get; }

    /// <summary>The CMS layer's report for the token's signature.</summary>
    public SignedDataReport? Signature { get; }

    /// <summary>The time-stamp rules in the order they ran.</summary>
    public IReadOnlyList<CmsCheck> Checks { get; }

    /// <summary>What the crypto policy said about the hashes and keys involved that was not a plain accept.</summary>
    public IReadOnlyList<PolicyDecision> PolicyFindings { get; }

    /// <summary>The time the token states, valid only when <see cref="IsValid"/> and the authority is trusted.</summary>
    public DateTimeOffset? GenTime => Info?.GenTime;

    /// <summary>True when no rule failed or went undecided. It does not mean the authority is trusted; see the <c>trust</c> check.</summary>
    public bool IsValid => Checks.All(static c => c.Status is not (CmsCheckStatus.Failed or CmsCheckStatus.Unsupported));

    /// <summary>The result of the named rule, or null when it did not run.</summary>
    public CmsCheck? Find(string rule) => Checks.FirstOrDefault(c => c.Rule == rule);
}

/// <summary>Checks time-stamp responses and tokens against the request that asked for them (RFC 3161 §2.4.2, RFC 5816). It reads bytes and does no network I/O.</summary>
public static class TimeStampVerifier
{
    private const string Rfc3161 = "RFC 3161";

    /// <summary>Checks a response (or a bare token) against its request.</summary>
    /// <param name="request">The request that was sent.</param>
    /// <param name="response">The response octets: a <c>TimeStampResp</c>, or a bare token (a ContentInfo), as some servers return.</param>
    /// <param name="options">Choices, or null for the defaults.</param>
    /// <returns>A report; bad input is reported, never thrown.</returns>
    public static TimeStampReport Verify(TimeStampRequest request, ReadOnlyMemory<byte> response, TimeStampVerifyOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        options ??= new TimeStampVerifyOptions();
        var checks = new List<CmsCheck>();
        if (response.Length == 0 || response.Length > TimeStampLimits.Default.MaxResponseSize)
        {
            checks.Add(new CmsCheck("response", CmsCheckStatus.Failed, response.Length == 0 ? "The response is empty." : "The response is larger than the limit.", Rfc3161 + " §2.4.2"));
            return new TimeStampReport(null, null, null, null, null, checks, []);
        }

        TimeStampResponse? resp = null;
        SignedData? token;
        if (response.Span[0] == 0x30 && LooksLikeBareToken(response.Span))
        {
            // Some servers answer with the bare token.
            token = SignedData.TryParse(response, out SignedData? bare, options.CmsLimits) ? bare : null;
            checks.Add(new CmsCheck("response", CmsCheckStatus.Warning, "The answer is a bare token, not a TimeStampResp.", Rfc3161 + " §2.4.2"));
        }
        else
        {
            if (!TimeStampResponse.TryParse(response, out resp) || resp is null)
            {
                checks.Add(new CmsCheck("response", CmsCheckStatus.Failed, "The response is not a well-formed TimeStampResp.", Rfc3161 + " §2.4.2"));
                return new TimeStampReport(null, null, null, null, null, checks, []);
            }

            if (!resp.IsGranted)
            {
                string why = resp.FailureInfo == TimeStampFailure.None ? string.Empty : $" ({resp.FailureInfo})";
                checks.Add(new CmsCheck("status", CmsCheckStatus.Failed, $"The authority answered {resp.Status}{why}.", Rfc3161 + " §2.4.2"));
                return new TimeStampReport(resp, null, null, null, null, checks, []);
            }

            checks.Add(new CmsCheck("status", resp.Status == TimeStampStatus.Granted ? CmsCheckStatus.Passed : CmsCheckStatus.Warning,
                resp.Status == TimeStampStatus.Granted ? string.Empty : "grantedWithMods: the token may differ from the request; the rules below say how.", Rfc3161 + " §2.4.2"));
            if (resp.TokenEncoded.IsEmpty)
            {
                checks.Add(new CmsCheck("token", CmsCheckStatus.Failed, "The response is granted but holds no token.", Rfc3161 + " §2.4.2"));
                return new TimeStampReport(resp, null, null, null, null, checks, []);
            }

            token = SignedData.TryParse(resp.TokenEncoded, out SignedData? parsed, options.CmsLimits) ? parsed : null;
        }

        if (token is null || token.EncapsulatedContentType != CmsOids.TstInfo || !token.HasEncapsulatedContent)
        {
            checks.Add(new CmsCheck("token", CmsCheckStatus.Failed, "The token is not a CMS SignedData holding a TSTInfo.", Rfc3161 + " §2.4.2"));
            return new TimeStampReport(resp, token, null, null, null, checks, []);
        }

        TstInfo info;
        try
        {
            info = TstInfo.FromSignedData(token);
        }
        catch (TimeStampParseException e)
        {
            checks.Add(new CmsCheck("token", CmsCheckStatus.Failed, "The TSTInfo is malformed: " + e.Message, Rfc3161 + " §2.4.2"));
            return new TimeStampReport(resp, token, null, null, null, checks, []);
        }

        checks.Add(new CmsCheck("token", CmsCheckStatus.Passed, string.Empty, Rfc3161 + " §2.4.2"));
        CheckBinding(request, info, checks);

        // RFC 3161 §2.4.2: the token has exactly one signature, the authority's.
        checks.Add(token.Signers.Count == 1
            ? new CmsCheck("single-signer", CmsCheckStatus.Passed, string.Empty, Rfc3161 + " §2.4.2")
            : new CmsCheck("single-signer", CmsCheckStatus.Failed, $"The token has {token.Signers.Count} signers; it must have exactly one.", Rfc3161 + " §2.4.2"));

        SignedDataReport sig = token.Verify(new SignedDataVerifyOptions
        {
            ExtraCertificates = options.ExtraCertificates,
            AnyOfKeyUsages = KeyUsages.DigitalSignature | KeyUsages.NonRepudiation,
            RequiredExtendedKeyUsage = KnownOids.TimeStamping,
            Limits = options.CmsLimits,
        });
        Certificate? signer = sig.Signers.Count > 0 ? sig.Signers[0].Certificate : null;
        checks.Add(sig.IsValid
            ? new CmsCheck("signature", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §5.4")
            : new CmsCheck("signature", CmsCheckStatus.Failed, FirstProblem(sig), "RFC 5652 §5.4"));

        var findings = new List<PolicyDecision>();
        if (signer is not null)
        {
            CheckAuthorityCertificate(token, info, signer, sig, checks);
            DateTimeOffset at = options.ReferenceTime ?? info.GenTime;
            if (SignatureAlgorithms.TryHash(info.HashAlgorithm.Oid, out HashAlgorithmName h))
            {
                findings.Add(options.Policy.CheckHash(h, CryptoUse.SignatureHash, at));
            }

            findings.AddRange(options.Policy.CheckSignature(token.Signers[0].SignatureAlgorithm, signer.PublicKey, CryptoUse.Verify, at).Decisions);
            findings.RemoveAll(static d => d.Verdict == PolicyVerdict.Accepted);
            if (findings.Count == 0)
            {
                checks.Add(new CmsCheck("policy", CmsCheckStatus.Passed, string.Empty, "RFC 3161 §3"));
            }
            else
            {
                bool rejected = findings.Any(static d => !d.IsAllowed);
                checks.Add(new CmsCheck("policy", rejected ? CmsCheckStatus.Failed : CmsCheckStatus.Warning, string.Join(" ", findings.Select(static d => d.Reason)), findings[0].Reference));
            }
        }
        else
        {
            checks.Add(new CmsCheck("tsa-certificate", CmsCheckStatus.Unsupported, "The authority's certificate is not in the token; supply it in ExtraCertificates (the request asked for it with certReq).", Rfc3161 + " §2.4.2"));
        }

        // RFC 3161 §2.4.2 / RFC 5280 §6: the authority's certificate must chain to a caller-supplied anchor, as of the time the token states.
        checks.Add(CheckTrust(token, info, signer, options));
        return new TimeStampReport(resp, token, info, signer, sig, checks, findings);
    }

    private static CmsCheck CheckTrust(SignedData token, TstInfo info, Certificate? signer, TimeStampVerifyOptions options)
    {
        const string clause = "RFC 5280 §6";
        if (options.TrustAnchors.Count == 0)
        {
            return new CmsCheck("trust", CmsCheckStatus.NotApplicable, "No trust anchors were supplied, so whether the authority's certificate chains to one was not evaluated.", clause);
        }

        if (signer is null)
        {
            return new CmsCheck("trust", CmsCheckStatus.Unsupported, "There is no authority certificate to validate.", clause);
        }

        ValidationReport v = PathValidator.Validate(signer, new ValidationOptions
        {
            TrustAnchors = options.TrustAnchors,
            Intermediates = [.. token.Certificates, .. options.ExtraCertificates],
            ReferenceTime = info.GenTime,
            RequiredExtendedKeyUsage = KnownOids.TimeStamping,
            Revocation = options.Revocation,
            RevocationRequired = options.RevocationRequired,
        });
        if (v.IsValid)
        {
            return v.RevocationSummary is RevocationStatus.Good
                ? new CmsCheck("trust", CmsCheckStatus.Passed, string.Empty, clause)
                : new CmsCheck("trust", CmsCheckStatus.Warning, "The authority's certificate chains to a supplied anchor at genTime; revocation status: " + v.RevocationSummary + ".", clause);
        }

        return new CmsCheck("trust", CmsCheckStatus.Failed, v.DecidingRule?.ToString() ?? v.Verdict.ToString(), clause);
    }

    private static bool LooksLikeBareToken(ReadOnlySpan<byte> data)
    {
        // A TimeStampResp starts SEQUENCE { SEQUENCE ...; a ContentInfo starts SEQUENCE { OBJECT IDENTIFIER.
        try
        {
            var r = new Asn1.Asn1Reader(data, Asn1.Asn1Rules.Ber);
            Asn1.Asn1Reader s = r.ReadSequence();
            return s.PeekTag() == new Asn1.Asn1Tag(Asn1.Asn1Tags.ObjectIdentifier);
        }
        catch (Asn1.Asn1ParseException)
        {
            return false;
        }
    }

    private static string FirstProblem(SignedDataReport sig)
    {
        CmsCheck? message = sig.Checks.FirstOrDefault(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported);
        if (message is not null)
        {
            return message.Reason;
        }

        foreach (SignerReport s in sig.Signers)
        {
            CmsCheck? c = s.Checks.FirstOrDefault(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported);
            if (c is not null)
            {
                return $"{c.Rule}: {c.Reason}";
            }
        }

        return "The signature did not verify.";
    }

    /// <summary>RFC 3161 §2.4.2: the token must answer the request that was sent.</summary>
    private static void CheckBinding(TimeStampRequest request, TstInfo info, List<CmsCheck> checks)
    {
        bool imprintOk = info.HashAlgorithm.Oid == request.HashAlgorithm.Oid && info.MessageImprint.Span.SequenceEqual(request.MessageImprint.Span);
        checks.Add(imprintOk
            ? new CmsCheck("message-imprint", CmsCheckStatus.Passed, string.Empty, Rfc3161 + " §2.4.2")
            : new CmsCheck("message-imprint", CmsCheckStatus.Failed, "The token stamps a different imprint or hash algorithm than the request carried.", Rfc3161 + " §2.4.2"));

        if (request.HasNonce)
        {
            bool nonceOk = info.HasNonce && TspRead.NormalizeInteger(info.Nonce.Span).SequenceEqual(TspRead.NormalizeInteger(request.Nonce.Span));
            checks.Add(nonceOk
                ? new CmsCheck("nonce", CmsCheckStatus.Passed, string.Empty, Rfc3161 + " §2.4.2")
                : new CmsCheck("nonce", CmsCheckStatus.Failed, info.HasNonce ? "The token echoes a different nonce." : "The request carried a nonce and the token does not echo it.", Rfc3161 + " §2.4.2"));
        }
        else
        {
            checks.Add(info.HasNonce
                ? new CmsCheck("nonce", CmsCheckStatus.Warning, "The request had no nonce but the token carries one.", Rfc3161 + " §2.4.2")
                : new CmsCheck("nonce", CmsCheckStatus.NotApplicable, "The request carried no nonce, so a replayed token cannot be told from a fresh one.", Rfc3161 + " §2.4.2"));
        }

        if (request.Policy is { } wanted)
        {
            checks.Add(wanted == info.Policy
                ? new CmsCheck("policy-id", CmsCheckStatus.Passed, string.Empty, Rfc3161 + " §2.4.2")
                : new CmsCheck("policy-id", CmsCheckStatus.Failed, $"The request asked for policy {wanted}; the token is under {info.Policy}.", Rfc3161 + " §2.4.2"));
        }
    }

    /// <summary>The authority's certificate rules of RFC 3161 §2.3 and the binding of RFC 5035 and RFC 3161 §2.4.2.</summary>
    private static void CheckAuthorityCertificate(SignedData token, TstInfo info, Certificate signer, SignedDataReport sig, List<CmsCheck> checks)
    {
        // RFC 3161 §2.3: the certificate must carry one extended key usage extension, critical, that names only id-kp-timeStamping.
        try
        {
            Extension? eku = signer.Extensions.Find(KnownOids.ExtendedKeyUsage);
            if (eku is null)
            {
                checks.Add(new CmsCheck("tsa-eku", CmsCheckStatus.Failed, "The authority's certificate has no extended key usage extension.", Rfc3161 + " §2.3"));
            }
            else
            {
                ExtendedKeyUsage usage = ExtendedKeyUsage.Parse(eku.Value);
                bool only = usage.Purposes.Count == 1 && usage.Purposes[0] == KnownOids.TimeStamping;
                checks.Add(!only
                    ? new CmsCheck("tsa-eku", CmsCheckStatus.Failed, "The extended key usage must name id-kp-timeStamping and nothing else.", Rfc3161 + " §2.3")
                    : !eku.Critical
                        ? new CmsCheck("tsa-eku", CmsCheckStatus.Failed, "The extended key usage extension must be critical.", Rfc3161 + " §2.3")
                        : new CmsCheck("tsa-eku", CmsCheckStatus.Passed, string.Empty, Rfc3161 + " §2.3"));
            }
        }
        catch (X509ParseException e)
        {
            checks.Add(new CmsCheck("tsa-eku", CmsCheckStatus.Failed, "The extended key usage extension is malformed: " + e.Message, Rfc3161 + " §2.3"));
        }

        // RFC 3161 §2.4.2 and RFC 5035 §5: the signed attributes must name the signer's certificate (the CMS layer checks that the hash matches).
        CmsCheck? binding = sig.Signers[0].Find("signing-certificate");
        checks.Add(binding is null || binding.Status == CmsCheckStatus.NotApplicable
            ? new CmsCheck("ess-cert-id", CmsCheckStatus.Failed, "The token has no signing-certificate or signing-certificate-v2 attribute, so the signature is not bound to the certificate.", "RFC 5035 §5; " + Rfc3161 + " §2.4.2")
            : binding.Status == CmsCheckStatus.Passed
                ? new CmsCheck("ess-cert-id", CmsCheckStatus.Passed, string.Empty, binding.Reference)
                : new CmsCheck("ess-cert-id", binding.Status, binding.Reason, binding.Reference));

        // RFC 3161 §2.4.2: when the tsa field is present it must identify the signer's certificate.
        if (info.Tsa is { } tsa)
        {
            bool match = tsa.Kind == GeneralNameKind.DirectoryName
                ? tsa.DirectoryName is { } dn && (dn.Matches(signer.Subject) || (signer.SubjectAlternativeName?.Names.Any(n => n.Kind == GeneralNameKind.DirectoryName && n.Equals(tsa)) ?? false))
                : signer.SubjectAlternativeName?.Names.Any(n => n.Equals(tsa)) ?? false;
            checks.Add(match
                ? new CmsCheck("tsa-name", CmsCheckStatus.Passed, string.Empty, Rfc3161 + " §2.4.2")
                : new CmsCheck("tsa-name", CmsCheckStatus.Failed, "The tsa field does not name the signer's certificate.", Rfc3161 + " §2.4.2"));
        }

        // The stamp must fall inside the certificate's validity (the time is the authority's own claim; revocation is not looked at here).
        checks.Add(info.GenTime >= signer.NotBefore && info.GenTime <= signer.NotAfter
            ? new CmsCheck("tsa-validity", CmsCheckStatus.Passed, string.Empty, "RFC 5280 §4.1.2.5")
            : new CmsCheck("tsa-validity", CmsCheckStatus.Failed, $"genTime {info.GenTime:u} is outside the certificate's validity ({signer.NotBefore:u} to {signer.NotAfter:u}).", "RFC 5280 §4.1.2.5"));
    }
}
