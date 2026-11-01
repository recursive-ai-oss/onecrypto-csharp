using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OnePdf;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>Signing at every level with every supported key kind, augmentation, renewal, and re-verification by the bridge and by OnePDF.</summary>
public class PadesRoundTripTests
{
    private static readonly PadesKit Kit = PadesKit.Shared;

    internal static byte[] Sign(TestSigner signer, PadesSignOptions options, byte[]? input = null)
    {
        using var doc = PdfDocument.Open(input ?? PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
        using var ms = new MemoryStream();
        doc.SignPades(ms, signer.Key, signer.Certificate, signer.Chain, options);
        return ms.ToArray();
    }

    internal static PadesReport Verify(byte[] pdf, PadesVerifyOptions options)
    {
        using PdfDocument doc = PdfDocument.Open(pdf);
        return doc.VerifyPades(pdf, options);
    }

    private static PdfSignatureVerifyOptions OnePdfTrusting(DateTimeOffset at) => new()
    {
        TrustAnchors = [Kit.Root.Certificate.ToX509Certificate2()],
        ExtraCertificates = [Kit.Intermediate.Certificate.ToX509Certificate2()],
        ValidationTime = at,
    };

    private static PadesSignOptions Options(PadesLevel level, DateTimeOffset at, RevocationData? revocation = null, bool pss = false) => new()
    {
        Level = level,
        RsaPss = pss,
        ReferenceTime = at,
        Timestamp = Kit.Tsa(at),
        ValidationData = level >= PadesLevel.LongTerm ? Kit.Validation(at, revocation) : null,
    };

    private static RevocationData FreshRevocation(DateTimeOffset at, TestSigner s) =>
        PadesKit.Merge(Kit.Crls(at), Kit.Ocsp(at, s.Certificate, Kit.TsaCertificate));

    [Theory]
    [InlineData(KeyKind.Rsa2048, false)]
    [InlineData(KeyKind.Rsa2048, true)]
    [InlineData(KeyKind.P256, false)]
    [InlineData(KeyKind.P384, false)]
    public void EveryLevelSignsAndVerifiesWithTheBridgeAndOnePdf(KeyKind kind, bool pss)
    {
        TestSigner signer = Kit.Signer(kind);
        DateTimeOffset at = Kit.Now;
        DateTimeOffset later = at.AddHours(1);
        foreach (PadesLevel level in new[] { PadesLevel.Basic, PadesLevel.Timestamped, PadesLevel.LongTerm, PadesLevel.LongTermArchive })
        {
            byte[] pdf = Sign(signer, Options(level, at, FreshRevocation(at, signer), pss));
            PadesReport report = Verify(pdf, Kit.Verify(later));
            PadesSignatureReport sig = report.Signatures.Single(static s => s.Kind == PadesSignatureKind.Signature);
            Assert.True(sig.IsValid, $"{kind} {level}: " + string.Join("; ", sig.Checks.Where(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported).Select(static c => c.Rule + ": " + c.Reason)));
            Assert.Equal(level, sig.Level);
            Assert.True(sig.OnePdf.IsValid);
            Assert.Equal(level >= PadesLevel.Timestamped, sig.ProofOfExistence is not null);
            Assert.Equal(level == PadesLevel.LongTermArchive ? 2 : 1, report.Signatures.Count);
            Assert.True(report.AllValid, report.Summary);

            // OnePDF's own verifier accepts what the bridge wrote.
            using PdfDocument doc = PdfDocument.Open(pdf);
            PdfSignatureReport onePdf = doc.VerifySignatures(OnePdfTrusting(later));
            Assert.True(onePdf.AllValid, string.Join("; ", onePdf.Signatures.SelectMany(static v => v.Warnings)));
            Assert.Equal(level >= PadesLevel.LongTerm, DssStoreOf(pdf).Present);
        }
    }

    private static DssStore DssStoreOf(byte[] pdf)
    {
        using PdfDocument doc = PdfDocument.Open(pdf);
        return DssStore.Read(doc);
    }

    [Fact]
    public void AnUntimestampedSignatureIsJudgedAtTheReferenceTimeAndSaysSo()
    {
        TestSigner signer = Kit.Signer(KeyKind.P256);
        byte[] pdf = Sign(signer, Options(PadesLevel.Basic, Kit.Now));
        PadesSignatureReport sig = Verify(pdf, Kit.Verify(Kit.Now.AddDays(1))).Signatures.Single();
        Assert.True(sig.IsValid);
        Assert.Null(sig.ProofOfExistence);
        Assert.Equal(CmsCheckStatus.Warning, sig.Find("proof-of-existence")!.Status);
        Assert.Equal(CmsCheckStatus.Warning, sig.Find("chain")!.Status);
        Assert.Equal(RevocationStatus.Unknown, sig.Chain!.RevocationSummary);

        // The signing time written in the file is a claim: moving the reference time past the certificate's life invalidates it.
        PadesSignatureReport expired = Verify(pdf, Kit.Verify(Kit.Now.AddDays(2000))).Signatures.Single();
        Assert.False(expired.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, expired.Find("chain")!.Status);

        // Required revocation with no data is undecided, never "valid" (offline).
        PadesSignatureReport required = Verify(pdf, Kit.Verify(Kit.Now.AddDays(1), null, static o => new PadesVerifyOptions { TrustAnchors = o.TrustAnchors, Intermediates = o.Intermediates, ReferenceTime = o.ReferenceTime, RevocationRequired = RevocationScope.EndEntity })).Signatures.Single();
        Assert.False(required.IsValid);
    }

    [Fact]
    public void AnExpiredCertificateIsValidAtTheProvenTimeAndNotWithoutOne()
    {
        // Signed 250 days ago with a certificate that has since expired; the time-stamp proves the signature predates the expiry.
        DateTimeOffset signedAt = Kit.Now.AddDays(-250);
        TestSigner shortLived = Kit.Signer(KeyKind.Rsa2048, "Short-lived signer", Kit.Now.AddDays(-300), TimeSpan.FromDays(100));
        byte[] stamped = Sign(shortLived, Options(PadesLevel.LongTermArchive, signedAt, FreshRevocation(signedAt, shortLived)));
        PadesSignatureReport good = Verify(stamped, Kit.Verify(Kit.Now)).Signatures.Single(static s => s.Kind == PadesSignatureKind.Signature);
        Assert.True(good.IsValid, string.Join("; ", good.Checks.Where(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported).Select(static c => c.Rule + ": " + c.Reason)));
        Assert.Equal(signedAt.ToUnixTimeSeconds(), good.ProofOfExistence!.Value.ToUnixTimeSeconds());
        Assert.Equal(PadesLevel.LongTermArchive, good.Level);
        Assert.Equal(RevocationStatus.Good, good.Chain!.SelectedPath!.Certificates[^1].Revocation.Status);

        byte[] bare = Sign(shortLived, Options(PadesLevel.Basic, signedAt));
        PadesSignatureReport bad = Verify(bare, Kit.Verify(Kit.Now)).Signatures.Single();
        Assert.False(bad.IsValid);
        Assert.Contains("expired", bad.Find("chain")!.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ARevokedSignerIsRefusedAndALateRevocationDoesNotUndoAProvenSignature()
    {
        TestSigner signer = Kit.Signer(KeyKind.P256, "Revoked signer");
        DateTimeOffset at = Kit.Now;
        // Revoked a day before the signature was made: the CRL says so, and the store carries it.
        RevocationData revokedBefore = PadesKit.Merge(Kit.Crls(at, signer.Certificate), Kit.Ocsp(at, Kit.TsaCertificate));
        byte[] pdf = Sign(signer, Options(PadesLevel.LongTerm, at, revokedBefore));
        PadesSignatureReport sig = Verify(pdf, Kit.Verify(at.AddHours(1))).Signatures.Single();
        Assert.False(sig.IsValid);
        Assert.Equal(RevocationStatus.Revoked, sig.Chain!.SelectedPath?.Certificates[^1].Revocation.Status ?? sig.Chain.RevocationSummary);

        // Revoked a day after the proven signing time for a reason other than compromise: still good at that time (past-time model).
        DateTimeOffset signedAt = Kit.Now.AddDays(-20);
        var crl = Kit.Intermediate.IssueCrl(new RecursiveAI.OneCrypto.Issuance.CrlIssueOptions
        {
            ThisUpdate = Kit.Now.AddDays(-5),
            NextUpdate = Kit.Now.AddDays(25),
            Number = 9,
            Revoked = [new RevokedCertificateInfo(signer.Certificate.SerialNumberValue, Kit.Now.AddDays(-10), RevocationReason.Superseded)],
        });
        RevocationData late = PadesKit.Merge(new RevocationData { Crls = [crl] }, Kit.Crls(Kit.Now.AddDays(-5)), Kit.Ocsp(Kit.Now.AddDays(-5), Kit.TsaCertificate));
        byte[] proven = Sign(signer, Options(PadesLevel.LongTerm, signedAt, late));
        PadesSignatureReport ok = Verify(proven, Kit.Verify(Kit.Now)).Signatures.Single();
        Assert.True(ok.IsValid, string.Join("; ", ok.Checks.Where(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported).Select(static c => c.Rule + ": " + c.Reason)));
    }

    [Fact]
    public async Task AugmentationRaisesBbToTToLtToLtaAndRenewsTheArchiveTimestamp()
    {
        TestSigner signer = Kit.Signer(KeyKind.Rsa2048);
        DateTimeOffset at = Kit.Now;
        byte[] bb = Sign(signer, Options(PadesLevel.Basic, at));
        Assert.Equal(PadesLevel.Basic, Verify(bb, Kit.Verify(at.AddHours(1))).Signatures[0].Level);

        PadesAugmentOptions Step(PadesLevel level) => new()
        {
            Level = level,
            Timestamp = Kit.Tsa(at),
            ValidationData = Kit.Validation(at, FreshRevocation(at, signer)),
        };

        byte[] bt = await PadesAugmenter.AugmentAsync(bb, Step(PadesLevel.Timestamped));
        PadesSignatureReport t = Verify(bt, Kit.Verify(at.AddHours(1))).Signatures.Single();
        Assert.True(t.IsValid);
        Assert.Equal(PadesLevel.Timestamped, t.Level);
        Assert.Equal(bb.Length, bt.Length);

        byte[] blt = await PadesAugmenter.AugmentAsync(bt, Step(PadesLevel.LongTerm));
        Assert.True(blt.AsSpan(0, bt.Length).SequenceEqual(bt), "the store is an incremental update");
        Assert.Equal(PadesLevel.LongTerm, Verify(blt, Kit.Verify(at.AddHours(1))).Signatures.Single().Level);

        byte[] blta = await PadesAugmenter.AugmentAsync(blt, Step(PadesLevel.LongTermArchive));
        Assert.True(blta.AsSpan(0, blt.Length).SequenceEqual(blt));
        PadesReport lta = Verify(blta, Kit.Verify(at.AddHours(1)));
        Assert.Equal(PadesLevel.LongTermArchive, lta.Signatures.First(static s => s.Kind == PadesSignatureKind.Signature).Level);

        // Renewal: a second archive time-stamp, later, covering the first and the data of its authority.
        DateTimeOffset renewedAt = at.AddDays(30);
        byte[] renewed = await PadesAugmenter.AugmentAsync(blta, new PadesAugmentOptions
        {
            Level = PadesLevel.LongTermArchive,
            Timestamp = Kit.Tsa(renewedAt),
            ValidationData = Kit.Validation(renewedAt, FreshRevocation(renewedAt, signer)),
        });
        PadesReport r = Verify(renewed, Kit.Verify(renewedAt.AddHours(1)));
        Assert.Equal(3, r.Signatures.Count);
        Assert.True(r.AllValid, r.Summary);
        Assert.Equal(2, r.Signatures.Count(static s => s.Kind == PadesSignatureKind.DocumentTimestamp));
        Assert.Equal(PadesLevel.LongTermArchive, r.Signatures[0].Level);
        Assert.Equal(at.ToUnixTimeSeconds(), r.Signatures[0].ProofOfExistence!.Value.ToUnixTimeSeconds());

        using PdfDocument doc = PdfDocument.Open(renewed);
        Assert.True(doc.VerifySignatures(OnePdfTrusting(renewedAt.AddHours(1))).AllValid);
    }

    [Fact]
    public void ASecondSignatureAndTheFirstBothVerify()
    {
        DateTimeOffset at = Kit.Now;
        byte[] first = Sign(Kit.Signer(KeyKind.P256), Options(PadesLevel.Timestamped, at));
        using var doc = PdfDocument.Open(first, new PdfOpenOptions { AllowEditing = true });
        using var ms = new MemoryStream();
        TestSigner other = Kit.Signer(KeyKind.P384);
        doc.SignPades(ms, other.Key, other.Certificate, other.Chain, Options(PadesLevel.Timestamped, at));
        PadesReport report = Verify(ms.ToArray(), Kit.Verify(at.AddHours(1)));
        Assert.Equal(2, report.Signatures.Count);
        Assert.True(report.AllValid, report.Summary);
    }

    [Fact]
    public void KeysThatSignTheAttributesThemselvesAreRefusedWithTheSeamNamed()
    {
        using Primitives.Ed25519PrivateKey key = Primitives.Ed25519PrivateKey.Generate();
        ISigningKey sk = PrivateKey.FromEd25519(key);
        TestSigner rsa = Kit.Signer(KeyKind.Rsa2048);
        using var doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
        var e = Assert.Throws<PadesException>(() => doc.SignPades(new MemoryStream(), sk, rsa.Certificate));
        Assert.Equal(PadesError.UnsupportedKey, e.Reason);
        Assert.Contains("external-signer", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingInputsAndWeakAlgorithmsAreRefusedBeforeAnythingIsWritten()
    {
        TestSigner s = Kit.Signer(KeyKind.P256);
        using var doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
        var output = new MemoryStream();
        Assert.Equal(PadesError.NoTimestampFunction, Assert.Throws<PadesException>(() => doc.SignPades(output, s.Key, s.Certificate, s.Chain, new PadesSignOptions { Level = PadesLevel.Timestamped })).Reason);
        Assert.Equal(PadesError.InvalidArgument, Assert.Throws<PadesException>(() => doc.SignPades(output, s.Key, s.Certificate, s.Chain, new PadesSignOptions { Level = PadesLevel.LongTerm, Timestamp = Kit.Tsa(Kit.Now) })).Reason);
        Assert.Throws<PolicyViolationException>(() => doc.SignPades(output, s.Key, s.Certificate, s.Chain, new PadesSignOptions { Hash = HashAlgorithmName.SHA1 }));
        Assert.Equal(0, output.Length);
    }

    [Fact]
    public async Task ATimestampAuthorityThatAnswersWithTheWrongDataIsRefused()
    {
        TestSigner s = Kit.Signer(KeyKind.P256);
        byte[] bb = Sign(s, Options(PadesLevel.Basic, Kit.Now));
        PadesTimestampFunction wrong = (request, ct) =>
        {
            var other = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData("something else"u8), Nonce = request.Nonce });
            return ValueTask.FromResult(Kit.Authority.Handle(other.Encoded, Kit.Now).Encoded.ToArray());
        };
        var e = await Assert.ThrowsAsync<PadesException>(async () => await PadesAugmenter.AugmentAsync(bb, new PadesAugmentOptions { Level = PadesLevel.Timestamped, Timestamp = wrong }));
        Assert.Equal(PadesError.TimestampRefused, e.Reason);
    }

    [Fact]
    public async Task CollectingValidationDataWithoutAChainIsAnErrorNotASilentGap()
    {
        TestSigner s = Kit.Signer(KeyKind.P256);
        byte[] bt = Sign(s, Options(PadesLevel.Timestamped, Kit.Now));
        var e = await Assert.ThrowsAsync<PadesException>(async () => await PadesAugmenter.AugmentAsync(bt, new PadesAugmentOptions
        {
            Level = PadesLevel.LongTerm,
            Timestamp = Kit.Tsa(Kit.Now),
            ValidationData = new PadesValidationData { ReferenceTime = Kit.Now },
        }));
        Assert.Equal(PadesError.NoChain, e.Reason);
    }

    [Fact]
    public void ChangesAfterTheSignatureAreReportedByOnePdfAndStayInTheVerdict()
    {
        TestSigner s = Kit.Signer(KeyKind.P256);
        byte[] pdf = Sign(s, Options(PadesLevel.Timestamped, Kit.Now));
        byte[] tampered = (byte[])pdf.Clone();
        int at = System.Text.Encoding.Latin1.GetString(tampered).IndexOf("Hello, signature", StringComparison.Ordinal);
        tampered[at] = (byte)'J';
        PadesSignatureReport r = Verify(tampered, Kit.Verify(Kit.Now.AddHours(1))).Signatures.Single();
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Find("cms-signature")!.Status);
        Assert.False(r.OnePdf.IsValid);
    }
}
