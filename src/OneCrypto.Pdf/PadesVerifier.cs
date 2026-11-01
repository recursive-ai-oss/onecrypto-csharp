using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OnePdf;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Pdf;

/// <summary>
/// Verifies the signatures and document time-stamps of a PDF with OneCrypto's CMS verifier, RFC 3161 verifier and path validator,
/// on top of OnePDF's byte-range, digest, modification and attack checks. The verdict of each signature is OnePDF's verdict and the
/// bridge's together: the bridge adds rules and never removes one. Bad input is reported, never thrown; the one exception is a file that changed after it was opened (<see cref="PadesError.SourceChanged"/>).
/// </summary>
/// <remarks>
/// <para>Time follows EN 319 102-1 §5.4 and §5.6: the instant a signature is judged at is the earliest time a <em>trusted</em> time-stamp
/// proves (its own signature time-stamp, or a document time-stamp made after it); without one it is the reference time. The signing
/// time written in the file is a claim and is never used. Revocation data comes from the signature, the document security store
/// (/DSS and the signature's /VRI entry) and the options; nothing is fetched except through the async sources the caller passes to
/// <see cref="VerifyAsync"/>. A chain with no revocation data is reported with revocation <c>Unknown</c>, never as "good".</para>
/// </remarks>
public static class PadesVerifier
{
    private const string Pades = "ETSI EN 319 142-1";

    /// <summary>Opens <paramref name="pdf"/> and verifies it.</summary>
    /// <param name="pdf">The file.</param>
    /// <param name="options">Anchors, reference time and policy.</param>
    /// <param name="cancellationToken">Checked between signatures.</param>
    /// <returns>The report. A file that cannot be opened gives a report with no signatures and a warning.</returns>
    public static PadesReport Verify(ReadOnlyMemory<byte> pdf, PadesVerifyOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!PdfDocument.TryOpen(pdf, out PdfDocument? document, out PdfException? error))
        {
            return new PadesReport([], ["The file cannot be opened: " + error.Message], new DssSummary(false, 0, 0, 0, 0));
        }

        using (document)
        {
            return Run(document, pdf, options, useSources: false, cancellationToken).AsTask().GetAwaiter().GetResult();
        }
    }

    /// <summary>Verifies an opened document. Sources in the options are ignored: use <see cref="VerifyAsync"/> to let them look things up.</summary>
    /// <param name="document">The document. Its original bytes are read through <see cref="PdfDocument.OpenRead"/>, so in-memory edits are not part of what is verified.</param>
    /// <param name="options">Anchors, reference time and policy.</param>
    /// <param name="cancellationToken">Checked between signatures.</param>
    /// <returns>The report.</returns>
    /// <exception cref="PadesException">Reason <see cref="PadesError.SourceChanged"/>: the file changed after the document was opened.</exception>
    public static PadesReport Verify(PdfDocument document, PadesVerifyOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(options);
        return Run(document, ReadOriginal(document), options, useSources: false, cancellationToken).AsTask().GetAwaiter().GetResult();
    }

    /// <summary>Like <see cref="Verify(PdfDocument, PadesVerifyOptions, CancellationToken)"/>, asking the options' certificate and revocation sources for what is missing.</summary>
    /// <param name="document">The document, read as in <see cref="Verify(PdfDocument, PadesVerifyOptions, CancellationToken)"/>.</param>
    /// <param name="options">Anchors, reference time, policy and sources.</param>
    /// <param name="cancellationToken">Cancels the lookups.</param>
    /// <returns>The report.</returns>
    /// <exception cref="PadesException">Reason <see cref="PadesError.SourceChanged"/>: the file changed after the document was opened.</exception>
    public static ValueTask<PadesReport> VerifyAsync(PdfDocument document, PadesVerifyOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(options);
        return Run(document, ReadOriginal(document), options, useSources: true, cancellationToken);
    }

    // The verifier hashes ranges of the original file, so it works on the file as opened and never on a re-serialisation.
    private static byte[] ReadOriginal(PdfDocument document)
    {
        try
        {
            using Stream original = document.OpenRead();
            using MemoryStream copy = new();
            original.CopyTo(copy);
            return copy.ToArray();
        }
        catch (PdfSourceChangedException e)
        {
            throw new PadesException(PadesError.SourceChanged, "The file changed after the document was opened; open it again to verify it.", e);
        }
    }

    private sealed class Stamp
    {
        public required PdfSignature Source { get; init; }

        public required PadesTimestamp Result { get; init; }
    }

    private static async ValueTask<PadesReport> Run(PdfDocument document, ReadOnlyMemory<byte> pdf, PadesVerifyOptions options, bool useSources, CancellationToken ct)
    {
        IReadOnlyList<PdfSignature> signatures;
        try
        {
            signatures = document.GetSignatures();
        }
        catch (PdfException e)
        {
            // OnePDF opened the file but cannot walk its form (for example, the catalog is gone): nothing can be verified.
            return new PadesReport([], ["The signatures cannot be listed: " + e.Message], new DssSummary(false, 0, 0, 0, 0));
        }

        DssStore dss = DssStore.Read(document);
        var warnings = new List<string>(dss.Warnings);
        var onePdfAnchors = new List<X509Certificate2>();
        foreach (TrustAnchor a in options.TrustAnchors)
        {
            if (a.Certificate is { } ac && ac.TryToX509Certificate2(out X509Certificate2? x) && x is not null)
            {
                onePdfAnchors.Add(x);
            }
        }

        var pool = new List<Certificate>(options.Intermediates);
        pool.AddRange(dss.Certificates.Select(static c => c.Value));
        foreach (DssStore v in dss.Vri.Values)
        {
            pool.AddRange(v.Certificates.Select(static c => c.Value));
        }

        // Document time-stamps first: they bound the time of every signature that comes before them.
        var stamps = new List<Stamp>();
        foreach (PdfSignature s in signatures)
        {
            ct.ThrowIfCancellationRequested();
            if (IsDocumentTimestamp(s))
            {
                stamps.Add(new Stamp { Source = s, Result = VerifyDocumentTimestamp(s, pdf.Span, pdf, options, pool, dss) });
            }
        }

        var reports = new List<PadesSignatureReport>();
        foreach (PdfSignature s in signatures)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                reports.Add(IsDocumentTimestamp(s)
                    ? DocumentTimestampReport(s, stamps.First(t => ReferenceEquals(t.Source, s)).Result, pdf.Span, options, onePdfAnchors, pool, ct)
                    : await SignatureReport(s, pdf, options, useSources, onePdfAnchors, pool, dss, stamps, ct).ConfigureAwait(false));
            }
            catch (Exception e) when (e is FormatException or CryptographicException or PdfException or ArgumentException or InvalidOperationException or NotSupportedException or OverflowException or InvalidDataException)
            {
                // A bug in the bridge must not turn into a verdict of "valid": report the signature as failed and say why.
                PdfSignatureVerification one = s.Verify(new PdfSignatureVerifyOptions { AnalyzeModifications = false }, ct);
                reports.Add(new PadesSignatureReport(one, PadesSignatureKind.Other, [new CmsCheck("bridge-error", CmsCheckStatus.Failed, e.GetType().Name + ": " + e.Message, Pades)], null, null, [], null, options.ReferenceTime, PadesLevel.None, false));
            }
        }

        int vri = dss.Vri.Count;
        return new PadesReport(reports, warnings, new DssSummary(dss.Present, dss.Certificates.Count, dss.Crls.Count, dss.Ocsp.Count, vri));
    }

    private static bool IsDocumentTimestamp(PdfSignature s) => s.SubFilter == "ETSI.RFC3161";

    private static bool IsCmsSubFilter(PdfSignature s) => s.SubFilter is "adbe.pkcs7.detached" or "ETSI.CAdES.detached";

    // ---- time-stamps -----------------------------------------------------------------------------------------------------

    private static bool TryHash(string oid, out HashAlgorithmName name)
    {
        switch (oid)
        {
            case "1.3.14.3.2.26": name = HashAlgorithmName.SHA1; return true;
            case "2.16.840.1.101.3.4.2.1": name = HashAlgorithmName.SHA256; return true;
            case "2.16.840.1.101.3.4.2.2": name = HashAlgorithmName.SHA384; return true;
            case "2.16.840.1.101.3.4.2.3": name = HashAlgorithmName.SHA512; return true;
            case "2.16.840.1.101.3.4.2.8": name = HashAlgorithmName.SHA3_256; return true;
            case "2.16.840.1.101.3.4.2.9": name = HashAlgorithmName.SHA3_384; return true;
            case "2.16.840.1.101.3.4.2.10": name = HashAlgorithmName.SHA3_512; return true;
            default: name = default; return false;
        }
    }

    /// <summary>
    /// Checks a time-stamp token against the data it should stamp: reads the hash the token names, hashes the data with it, and runs
    /// the core RFC 3161 verifier on a request built from that digest. A token without a nonce cannot be told from a replay, which the
    /// verifier reports as not applicable; the imprint is what binds it to this data.
    /// </summary>
    private static (TimeStampReport? Report, IReadOnlyList<CmsCheck> Checks, bool Trusted) CheckToken(ReadOnlyMemory<byte> tokenBytes, Func<HashAlgorithmName, byte[]> digestOf, PadesVerifyOptions options, IReadOnlyList<Certificate> pool, RevocationData revocation)
    {
        var checks = new List<CmsCheck>();
        if (!SignedData.TryParse(tokenBytes, out SignedData? token, null, allowTrailingZeros: true) || token is null || !token.HasEncapsulatedContent || token.EncapsulatedContentType != CmsOids.TstInfo)
        {
            checks.Add(new CmsCheck("token", CmsCheckStatus.Failed, "The value is not a CMS SignedData holding a TSTInfo.", "RFC 3161 §2.4.2"));
            return (null, checks, false);
        }

        TstInfo info;
        try
        {
            info = TstInfo.FromSignedData(token);
        }
        catch (TimeStampParseException e)
        {
            checks.Add(new CmsCheck("token", CmsCheckStatus.Failed, "The TSTInfo is malformed: " + e.Message, "RFC 3161 §2.4.2"));
            return (null, checks, false);
        }

        if (!TryHash(info.HashAlgorithm.Oid, out HashAlgorithmName hash))
        {
            checks.Add(new CmsCheck("message-imprint", CmsCheckStatus.Failed, "The token's hash algorithm " + info.HashAlgorithm.Oid + " is not one the bridge can compute.", "RFC 3161 §2.4.2"));
            return (null, checks, false);
        }

        TimeStampRequest request;
        try
        {
            request = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = hash, MessageImprint = digestOf(hash), CertReq = false });
        }
        catch (ArgumentException e)
        {
            // SHA-1 imprints cannot be put in a request; they are reported as a failed imprint rule, not skipped.
            checks.Add(new CmsCheck("message-imprint", CmsCheckStatus.Failed, e.Message, "RFC 3161 §2.4.2"));
            return (null, checks, false);
        }

        TimeStampReport report = TimeStampVerifier.Verify(request, tokenBytes[..PdfLayout.DerLength(tokenBytes.Span)], new TimeStampVerifyOptions
        {
            ExtraCertificates = pool,
            Policy = options.Policy,
            TrustAnchors = options.TrustAnchors,
            Revocation = revocation,
        });
        CmsCheck? trust = report.Find("trust");
        bool trusted = options.TrustAnchors.Count > 0 && report.IsValid && trust is { Status: CmsCheckStatus.Passed or CmsCheckStatus.Warning };
        return (report, report.Checks, trusted);
    }

    private static RevocationData MergeRevocation(PadesVerifyOptions options, DssStore dss, DssStore? vri, SignedData? cms)
    {
        var crls = new List<CertificateRevocationList>();
        var ocsp = new List<OcspBasicResponse>();
        if (options.Revocation is { } r)
        {
            crls.AddRange(r.Crls);
            ocsp.AddRange(r.OcspResponses);
        }

        crls.AddRange(dss.Crls.Select(static c => c.Value));
        ocsp.AddRange(dss.Ocsp.Select(static c => c.Value));
        if (vri is not null)
        {
            crls.AddRange(vri.Crls.Select(static c => c.Value));
            ocsp.AddRange(vri.Ocsp.Select(static c => c.Value));
        }

        if (cms is not null)
        {
            crls.AddRange(cms.Crls);
        }

        return new RevocationData { Crls = crls, OcspResponses = ocsp };
    }

    private static PadesTimestamp VerifyDocumentTimestamp(PdfSignature s, ReadOnlySpan<byte> file, ReadOnlyMemory<byte> pdf, PadesVerifyOptions options, IReadOnlyList<Certificate> pool, DssStore dss)
    {
        if (!PdfLayout.TryRanges(s, file, out long a, out long b, out long c) || s.CoveredRevision < 0 || !PdfLayout.TryContentsBytes(file, a, b, out byte[] contents))
        {
            return new PadesTimestamp(true, s.FieldName, null, [new CmsCheck("byte-range", CmsCheckStatus.Failed, "The byte range or the /Contents string of the document time-stamp is not usable.", "ISO 32000-2 §12.8.1")], 0, long.MaxValue, false);
        }

        (TimeStampReport? report, IReadOnlyList<CmsCheck> tokenChecks, bool trusted) = CheckToken(contents, hash =>
        {
            // The signed bytes come from OnePDF's own accessor, so the digest covers exactly what its model says the ranges are.
            using IncrementalHash h = IncrementalHash.CreateHash(hash);
            using Stream signed = s.OpenSignedData() ?? PdfLayout.SignedContent(pdf, a, b, c);
            byte[] buffer = new byte[1 << 16];
            int n;
            while ((n = signed.Read(buffer, 0, buffer.Length)) > 0)
            {
                h.AppendData(buffer, 0, n);
            }

            return h.GetHashAndReset();
        }, options, pool, MergeRevocation(options, dss, null, null));
        return new PadesTimestamp(true, s.FieldName, report, tokenChecks, b + c, a, trusted);
    }

    private static PadesSignatureReport DocumentTimestampReport(PdfSignature s, PadesTimestamp stamp, ReadOnlySpan<byte> file, PadesVerifyOptions options, List<X509Certificate2> anchors, List<Certificate> pool, CancellationToken ct)
    {
        var checks = new List<CmsCheck>();
        bool rangeOk = PdfLayout.TryRanges(s, file, out _, out _, out _) && s.CoveredRevision >= 0;
        checks.Add(rangeOk
            ? new CmsCheck("byte-range", CmsCheckStatus.Passed, string.Empty, "ISO 32000-2 §12.8.1")
            : new CmsCheck("byte-range", CmsCheckStatus.Failed, "The byte range does not describe a hole that holds /Contents.", "ISO 32000-2 §12.8.1"));
        checks.Add(s.SubFilter == "ETSI.RFC3161" && s.Kind == PdfSignatureKind.DocumentTimestamp
            ? new CmsCheck("subfilter", CmsCheckStatus.Passed, string.Empty, "ISO 32000-2 §12.8.5")
            : new CmsCheck("subfilter", CmsCheckStatus.Failed, "A document time-stamp is /Type /DocTimeStamp with sub-filter ETSI.RFC3161; this dictionary is not both.", "ISO 32000-2 §12.8.5"));
        checks.Add(stamp.IsValid
            ? new CmsCheck("timestamp", CmsCheckStatus.Passed, string.Empty, "RFC 3161 §2.4.2")
            : new CmsCheck("timestamp", CmsCheckStatus.Failed, FirstProblem(stamp), "RFC 3161 §2.4.2"));
        checks.Add(stamp.IsTrusted
            ? new CmsCheck("timestamp-trust", CmsCheckStatus.Passed, string.Empty, "EN 319 102-1 §5.4")
            : new CmsCheck("timestamp-trust", CmsCheckStatus.Failed, options.TrustAnchors.Count == 0 ? "No trust anchors were given." : "The time-stamp authority does not chain to a trust anchor at the time of the token.", "EN 319 102-1 §5.4"));

        DateTimeOffset at = stamp.GenTime ?? options.ReferenceTime;
        PdfSignatureVerification one = s.Verify(OnePdfOptions(options, anchors, pool, at), ct);
        bool valid = one.IsValid && checks.All(static c => c.Status is not (CmsCheckStatus.Failed or CmsCheckStatus.Unsupported));
        return new PadesSignatureReport(one, PadesSignatureKind.DocumentTimestamp, checks, null, null, [stamp], stamp.IsTrusted ? stamp.GenTime : null, at, PadesLevel.None, valid);
    }

    private static PdfSignatureVerifyOptions OnePdfOptions(PadesVerifyOptions options, List<X509Certificate2> anchors, List<Certificate> pool, DateTimeOffset at)
    {
        var extra = new List<X509Certificate2>();
        foreach (Certificate c in pool)
        {
            if (c.TryToX509Certificate2(out X509Certificate2? x) && x is not null)
            {
                extra.Add(x);
            }
        }

        return new PdfSignatureVerifyOptions
        {
            TrustAnchors = anchors,
            ExtraCertificates = extra,
            ValidationTime = at,
            RequireSigningKeyUsage = options.RequireSigningKeyUsage,
            AnalyzeModifications = options.AnalyzeModifications,
        };
    }

    private static string FirstProblem(PadesTimestamp r) =>
        r.Checks.FirstOrDefault(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported) is { } f ? f.Rule + ": " + f.Reason : "The token is not valid.";

    // ---- signatures ------------------------------------------------------------------------------------------------------

    /// <summary>True when OnePDF left the signature or digest check open (an algorithm it does not support) and found nothing else wrong.</summary>
    private static bool OnePdfDefersToBridge(PdfSignatureVerification one, bool requireKeyUsage) =>
        (one.Integrity == PdfCheckStatus.NotChecked || one.SignatureCheck == PdfCheckStatus.NotChecked)
        && one.ByteRange == PdfByteRangeStatus.Valid
        && one.Integrity != PdfCheckStatus.Invalid
        && one.SignatureCheck != PdfCheckStatus.Invalid
        && one.Chain is PdfChainStatus.Trusted or PdfChainStatus.NotChecked
        && (one.KeyUsage != PdfCheckStatus.Invalid || !requireKeyUsage)
        && (one.Timestamp is null || one.Timestamp.IsValid)
        && one.Revocation != PdfRevocationStatus.Revoked
        && one.Coverage != PdfSignatureCoverage.EarlierRevisionDisallowedChanges;

    private static async ValueTask<PadesSignatureReport> SignatureReport(
        PdfSignature s,
        ReadOnlyMemory<byte> pdf,
        PadesVerifyOptions options,
        bool useSources,
        List<X509Certificate2> anchors,
        List<Certificate> pool,
        DssStore dss,
        List<Stamp> stamps,
        CancellationToken ct)
    {
        var checks = new List<CmsCheck>();
        ReadOnlySpan<byte> file = pdf.Span;
        if (!IsCmsSubFilter(s))
        {
            PdfSignatureVerification other = s.Verify(OnePdfOptions(options, anchors, pool, options.ReferenceTime), ct);
            checks.Add(new CmsCheck("subfilter", CmsCheckStatus.Warning, "The sub-filter " + (s.SubFilter ?? "(none)") + " is not evaluated by the bridge; OnePDF's verdict stands.", "ISO 32000-2 §12.8.3"));
            return new PadesSignatureReport(other, PadesSignatureKind.Other, checks, null, null, [], null, options.ReferenceTime, PadesLevel.None, other.IsValid);
        }

        bool rangeOk = PdfLayout.TryRanges(s, file, out long a, out long b, out long c) && s.CoveredRevision >= 0;
        byte[] contents = [];
        if (rangeOk && !PdfLayout.TryContentsBytes(file, a, b, out contents))
        {
            rangeOk = false;
        }

        if (rangeOk && !s.Contents.Span.SequenceEqual(contents))
        {
            // The caller's bytes are not the bytes the document was opened from, or the dictionary and the file disagree.
            rangeOk = false;
            checks.Add(new CmsCheck("contents", CmsCheckStatus.Failed, "The /Contents the document model read is not the hex string at the byte range's hole.", "ISO 32000-2 §12.8.1"));
        }

        checks.Add(rangeOk
            ? new CmsCheck("byte-range", CmsCheckStatus.Passed, string.Empty, "ISO 32000-2 §12.8.1")
            : new CmsCheck("byte-range", CmsCheckStatus.Failed, "The byte range does not describe a hole in the file that holds /Contents.", "ISO 32000-2 §12.8.1"));

        SignedData? cms = null;
        if (rangeOk)
        {
            if (SignedData.TryParse(contents, out cms, null, allowTrailingZeros: true) && cms is not null)
            {
                checks.Add(new CmsCheck("cms", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §5"));
            }
            else
            {
                cms = null;
                checks.Add(new CmsCheck("cms", CmsCheckStatus.Failed, "/Contents does not hold a CMS SignedData.", "RFC 5652 §5"));
            }
        }

        // The signature time-stamp, then the document time-stamps made after this signature.
        var timestamps = new List<PadesTimestamp>();
        SignerInfo? signer = null;
        if (cms is not null)
        {
            if (cms.Signers.Count == 1)
            {
                signer = cms.Signers[0];
                checks.Add(new CmsCheck("single-signer", CmsCheckStatus.Passed, string.Empty, Pades + " §6.3"));
            }
            else
            {
                checks.Add(new CmsCheck("single-signer", CmsCheckStatus.Failed, $"A PDF signature carries exactly one SignerInfo; this one has {cms.Signers.Count}.", Pades + " §6.3"));
            }

            if (cms.HasEncapsulatedContent)
            {
                checks.Add(new CmsCheck("detached", CmsCheckStatus.Failed, "A PDF signature is detached: the CMS must not carry the content.", "ISO 32000-2 §12.8.3.3"));
            }
        }

        // The spec words the hashed bytes loosely, so the entry is found under the hash of the DER structure or of the whole padded string.
        DssStore? vri = null;
        if (contents.Length > 0)
        {
            vri = dss.Vri.TryGetValue(PdfLayout.VriKey(contents), out DssStore? v) ? v : dss.Vri.TryGetValue(PdfLayout.VriKey(contents, trim: false), out v) ? v : null;
        }
        PadesTimestamp? sigStamp = null;
        if (signer?.FindUnsigned(CmsOids.SignatureTimeStampToken) is { Values.Count: > 0 } attr)
        {
            RevocationData rd = MergeRevocation(options, dss, vri, cms);
            ReadOnlyMemory<byte> signature = signer.Signature;
            (TimeStampReport? report, IReadOnlyList<CmsCheck> tokenChecks, bool trusted) = CheckToken(attr.Values[0], hash => CryptographicOperations.HashData(hash, signature.Span), options, pool, rd);
            sigStamp = new PadesTimestamp(false, null, report, tokenChecks, 0, 0, trusted);
            timestamps.Add(sigStamp);
        }

        foreach (Stamp st in stamps)
        {
            // RFC 3161 document time-stamps cover everything before their own /Contents (ISO 32000-2 §12.8.5), signature included.
            if (rangeOk && st.Result.HoleStart >= b)
            {
                timestamps.Add(st.Result);
            }
        }

        DateTimeOffset? proof = timestamps.Where(static t => t.IsTrusted && t.GenTime is not null).Select(static t => t.GenTime!.Value).Cast<DateTimeOffset?>().Min();
        DateTimeOffset at = proof is { } p && p <= options.ReferenceTime ? p : options.ReferenceTime;
        if (proof is { } pf && pf > options.ReferenceTime)
        {
            checks.Add(new CmsCheck("proof-of-existence", CmsCheckStatus.Failed, "A time-stamp is dated after the reference time.", "EN 319 102-1 §5.4"));
            proof = null;
        }

        checks.Add(proof is null
            ? new CmsCheck("proof-of-existence", CmsCheckStatus.Warning, "No trusted time-stamp proves when the signature existed, so it is judged at the reference time.", "EN 319 102-1 §5.4")
            : new CmsCheck("proof-of-existence", CmsCheckStatus.Passed, "A trusted time-stamp proves the signature existed at " + proof.Value.ToString("u", System.Globalization.CultureInfo.InvariantCulture) + ".", "EN 319 102-1 §5.4"));
        if (sigStamp is not null)
        {
            checks.Add(sigStamp.IsTrusted
                ? new CmsCheck("signature-timestamp", CmsCheckStatus.Passed, string.Empty, "EN 319 142-1 §6.3 (n)")
                : new CmsCheck("signature-timestamp", CmsCheckStatus.Failed, sigStamp.IsValid ? "The time-stamp authority is not trusted at the time of the token." : FirstProblem(sigStamp), "EN 319 142-1 §6.3 (n)"));
        }

        // The CMS signature itself, over the received bytes of both ranges.
        SignedDataReport? cmsReport = null;
        ValidationReport? chain = null;
        ValidationReport? embedded = null;
        if (cms is not null && signer is not null && rangeOk)
        {
            using Stream content = s.OpenSignedData() ?? PdfLayout.SignedContent(pdf, a, b, c);
            cmsReport = cms.Verify(content, new SignedDataVerifyOptions
            {
                ExtraCertificates = pool,
                Policy = options.Policy,
                ReferenceTime = at,
                AnyOfKeyUsages = options.RequireSigningKeyUsage ? KeyUsages.DigitalSignature | KeyUsages.NonRepudiation : KeyUsages.None,
            });
            foreach (CmsCheck ck in cmsReport.Signers[0].Checks.Where(static k => k.Status != CmsCheckStatus.Passed && k.Status != CmsCheckStatus.NotApplicable))
            {
                checks.Add(ck with { Rule = "cms-" + ck.Rule });
            }

            checks.Add(cmsReport.IsValid
                ? new CmsCheck("cms-signature", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §5.4")
                : new CmsCheck("cms-signature", CmsCheckStatus.Failed, cmsReport.Signers[0].Checks.FirstOrDefault(static k => k.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported)?.Reason ?? "The CMS does not verify.", "RFC 5652 §5.4"));

            if (cmsReport.Signers[0].Certificate is { } signerCertificate)
            {
                (chain, embedded) = await ValidateChain(signerCertificate, cms, vri, dss, pool, options, at, proof is not null, timestamps, useSources, ct).ConfigureAwait(false);
                checks.Add(ChainCheck(chain, options));
            }
        }

        PdfSignatureVerification one = s.Verify(OnePdfOptions(options, anchors, pool, at), ct);
        // OnePDF cannot check EdDSA or ML-DSA signatures (it reports the integrity or signature check as not checked, and the chain with it).
        // When everything else it can judge is fine and the bridge verified the CMS signature itself, the bridge's verdict stands in, and the
        // report says so: the verdict for those signatures comes from this package, not from OnePDF.
        bool bridgeCmsPassed = checks.Any(static k => k.Rule == "cms-signature" && k.Status == CmsCheckStatus.Passed);
        bool delegated = !one.IsValid && bridgeCmsPassed && OnePdfDefersToBridge(one, options.RequireSigningKeyUsage);
        checks.Add(one.IsValid
            ? new CmsCheck("onepdf", CmsCheckStatus.Passed, string.Empty, "ISO 32000-2 §12.8")
            : delegated
                ? new CmsCheck("onepdf", CmsCheckStatus.Warning, "OnePDF does not check this signature algorithm; the verdict is the bridge's.", "ISO 32000-2 §12.8")
                : new CmsCheck("onepdf", CmsCheckStatus.Failed, OnePdfReason(one), "ISO 32000-2 §12.8"));

        PadesLevel level = LevelOf(s, cms, cmsReport, chain, embedded, timestamps, dss, vri, checks);
        bool valid = (one.IsValid || delegated) && checks.All(static k => k.Status is not (CmsCheckStatus.Failed or CmsCheckStatus.Unsupported));
        return new PadesSignatureReport(one, PadesSignatureKind.Signature, checks, cmsReport, chain, timestamps, proof, at, valid ? level : PadesLevel.None, valid);
    }

    // Names the change that OnePDF refuses when that is the cause, because its first warning is often an unrelated note (for example that no revocation data was supplied).
    private static string OnePdfReason(PdfSignatureVerification one)
    {
        PdfSignatureChange? refused = one.Changes.FirstOrDefault(static c => !c.Allowed);
        if (refused is not null)
        {
            return "OnePDF reports a change after the signature that its permission level does not allow: " + refused.Description + ".";
        }

        return one.Warnings.Count > 0 ? one.Warnings[0] : "OnePDF does not accept the signature.";
    }

    private static CmsCheck ChainCheck(ValidationReport chain, PadesVerifyOptions options)
    {
        string note = options.TrustAnchors.Count == 0 ? " No trust anchors were given." : string.Empty;
        return chain.Verdict switch
        {
            ValidationVerdict.Valid when chain.RevocationSummary is RevocationStatus.Unknown or RevocationStatus.NotChecked =>
                new CmsCheck("chain", CmsCheckStatus.Warning, "The signer's certificate chains to a trust anchor; revocation is unknown.", "RFC 5280 §6"),
            ValidationVerdict.Valid => new CmsCheck("chain", CmsCheckStatus.Passed, string.Empty, "RFC 5280 §6"),
            ValidationVerdict.Indeterminate => new CmsCheck("chain", CmsCheckStatus.Unsupported, (chain.DecidingRule?.Reason ?? "The chain could not be decided.") + note, "RFC 5280 §6"),
            _ => new CmsCheck("chain", CmsCheckStatus.Failed, (chain.DecidingRule?.Reason ?? "No path to a trust anchor.") + note, "RFC 5280 §6"),
        };
    }

    private static async ValueTask<(ValidationReport Full, ValidationReport Embedded)> ValidateChain(
        Certificate signer,
        SignedData cms,
        DssStore? vri,
        DssStore dss,
        List<Certificate> pool,
        PadesVerifyOptions options,
        DateTimeOffset at,
        bool proven,
        List<PadesTimestamp> timestamps,
        bool useSources,
        CancellationToken ct)
    {
        var all = new List<Certificate>(pool);
        all.AddRange(cms.Certificates);
        if (vri is not null)
        {
            all.AddRange(vri.Certificates.Select(static x => x.Value));
        }

        RevocationData embeddedData = MergeRevocation(new PadesVerifyOptions { ReferenceTime = options.ReferenceTime }, dss, vri, cms);
        DateTimeOffset? dataTime = options.RevocationDataTime ?? (proven ? DataTime(embeddedData, dss, vri, timestamps, options.ReferenceTime) : null);
        ValidationOptions Make(RevocationData data, bool withSources) => new()
        {
            TrustAnchors = options.TrustAnchors,
            Intermediates = all,
            ReferenceTime = at,
            RevocationDataTime = dataTime,
            Revocation = data,
            RevocationRequired = options.RevocationRequired,
            RevocationModel = proven ? RevocationModel.PastTime : RevocationModel.Current,
            Policy = options.Policy,
            Limits = options.Limits,
            CertificateSource = withSources ? options.CertificateSource : null,
            RevocationSource = withSources ? options.RevocationSource : null,
        };

        ValidationReport embedded = PathValidator.Validate(signer, Make(embeddedData, false));
        bool extra = options.Revocation is not null || (useSources && (options.RevocationSource is not null || options.CertificateSource is not null));
        if (!extra)
        {
            return (embedded, embedded);
        }

        RevocationData merged = MergeRevocation(options, dss, vri, cms);
        ValidationOptions opts = Make(merged, useSources);
        ValidationReport full = useSources ? await PathValidator.ValidateAsync(signer, opts, ct).ConfigureAwait(false) : PathValidator.Validate(signer, opts);
        return (full, embedded);
    }

    /// <summary>
    /// The instant stored revocation data is judged fresh at. Data covered by a trusted document time-stamp existed when it was made, so
    /// the earliest such time-stamp that covers every stored object is used; otherwise the newest issue time among the data (the
    /// collection time is not proven, so each object is judged as of the latest one's issue).
    /// </summary>
    private static DateTimeOffset? DataTime(RevocationData data, DssStore dss, DssStore? vri, List<PadesTimestamp> timestamps, DateTimeOffset reference)
    {
        long newest = -1;
        foreach (StoredItem<Certificate> i in dss.Certificates.Concat(vri?.Certificates ?? []))
        {
            newest = Math.Max(newest, i.Offset);
        }

        foreach (long o in dss.Crls.Select(static x => x.Offset).Concat(dss.Ocsp.Select(static x => x.Offset)).Concat(vri?.Crls.Select(static x => x.Offset) ?? []).Concat(vri?.Ocsp.Select(static x => x.Offset) ?? []))
        {
            newest = Math.Max(newest, o);
        }

        if (newest >= 0)
        {
            DateTimeOffset? covering = timestamps.Where(t => t.IsDocument && t.IsTrusted && t.HoleStart > newest).Select(static t => t.GenTime).Min();
            if (covering is { } cov && cov <= reference)
            {
                return cov;
            }
        }

        DateTimeOffset? best = null;
        foreach (CertificateRevocationList crl in data.Crls)
        {
            best = best is null || crl.ThisUpdate > best ? crl.ThisUpdate : best;
        }

        foreach (OcspBasicResponse o in data.OcspResponses)
        {
            best = best is null || o.ProducedAt > best ? o.ProducedAt : best;
        }

        return best is { } bt && bt > reference ? reference : best;
    }

    private static PadesLevel LevelOf(
        PdfSignature s,
        SignedData? cms,
        SignedDataReport? cmsReport,
        ValidationReport? chain,
        ValidationReport? embedded,
        List<PadesTimestamp> timestamps,
        DssStore dss,
        DssStore? vri,
        List<CmsCheck> checks)
    {
        // B-B (EN 319 142-1 §6.2.1): a CAdES signature with signing-certificate-v2 (no signing-time attribute is required).
        if (cms is null || cmsReport is null || chain is null || s.SubFilter != "ETSI.CAdES.detached")
        {
            return PadesLevel.None;
        }

        CmsCheck? ess = cmsReport.Signers[0].Find("signing-certificate");
        if (ess is not { Status: CmsCheckStatus.Passed })
        {
            return PadesLevel.None;
        }

        PadesLevel level = PadesLevel.Basic;

        // B-T (§6.3 (n)): the trusted time comes from a signature time-stamp or from a document time-stamp made after the signature.
        PadesTimestamp? sigStamp = timestamps.Where(static t => t.IsTrusted && t.GenTime is not null).OrderBy(static t => t.GenTime).FirstOrDefault();
        if (sigStamp is null)
        {
            return level;
        }

        level = PadesLevel.Timestamped;

        // B-LT (§6.2.3): the chain's revocation status is established from data the file itself carries, for the signer and for the
        // time-stamp authority.
        bool signerGood = embedded?.SelectedPath is { } path && path.Certificates.Where(static x => !x.IsTrustAnchor).All(static x => x.Revocation.Status == RevocationStatus.Good);
        CmsCheck? tsTrust = sigStamp.Checks.FirstOrDefault(static k => k.Rule == "trust");
        bool tsaGood = tsTrust is { Status: CmsCheckStatus.Passed };
        if (!signerGood || !tsaGood || !(dss.Present || cms.Crls.Count > 0))
        {
            return level;
        }

        level = PadesLevel.LongTerm;

        // B-LTA (§6.2.4): a trusted document time-stamp made after the stored data covers it.
        long newest = dss.Certificates.Select(static x => x.Offset).Concat(dss.Crls.Select(static x => x.Offset)).Concat(dss.Ocsp.Select(static x => x.Offset))
            .Concat(vri?.Certificates.Select(static x => x.Offset) ?? []).Concat(vri?.Crls.Select(static x => x.Offset) ?? []).Concat(vri?.Ocsp.Select(static x => x.Offset) ?? []).DefaultIfEmpty(-1).Max();
        if (timestamps.Any(t => t.IsDocument && t.IsTrusted && t.HoleStart > newest))
        {
            level = PadesLevel.LongTermArchive;
        }

        checks.Add(new CmsCheck("level", CmsCheckStatus.Passed, "PAdES " + level + ".", Pades + " §6"));
        return level;
    }
}
