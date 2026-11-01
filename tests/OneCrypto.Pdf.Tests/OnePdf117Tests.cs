using System.Text;
using OnePdf;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>Typed signing errors, certified documents that forbid changes, and verification over the document's own original bytes.</summary>
public class OnePdf117Tests
{
    private static readonly PadesKit Kit = PadesKit.Shared;

    private static PadesSignOptions Basic(PdfSigningOptions? pdf = null) => new() { ReferenceTime = Kit.Now, Pdf = pdf };

    private static byte[] NoPages()
    {
        const string body = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n";
        int o1 = body.IndexOf("1 0 obj", StringComparison.Ordinal);
        int o2 = body.IndexOf("2 0 obj", StringComparison.Ordinal);
        var sb = new StringBuilder(body);
        int xref = sb.Length;
        sb.Append("xref\n0 3\n0000000000 65535 f \n").Append(o1.ToString("D10", System.Globalization.CultureInfo.InvariantCulture)).Append(" 00000 n \n")
          .Append(o2.ToString("D10", System.Globalization.CultureInfo.InvariantCulture)).Append(" 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n").Append(xref).Append("\n%%EOF\n");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    private static byte[] Certified(PdfCertificationLevel level) =>
        PadesRoundTripTests.Sign(Kit.Signer(KeyKind.P256), Basic(new PdfSigningOptions { Certify = level }));

    private static byte[] SignOver(byte[] input, PadesSignOptions options)
    {
        using var doc = PdfDocument.Open(input, new PdfOpenOptions { AllowEditing = true });
        using var ms = new MemoryStream();
        TestSigner signer = Kit.Signer(KeyKind.Rsa2048);
        doc.SignPades(ms, signer.Key, signer.Certificate, signer.Chain, options);
        return ms.ToArray();
    }

    [Fact]
    public void AnEmptyPageTreeIsRefusedWithTheTypedErrorAndNothingIsWritten()
    {
        using var doc = PdfDocument.Open(NoPages(), new PdfOpenOptions { AllowEditing = true });
        using var ms = new MemoryStream();
        TestSigner signer = Kit.Signer(KeyKind.P256);
        PdfSigningException e = Assert.Throws<PdfSigningException>(() => doc.SignPades(ms, signer.Key, signer.Certificate, signer.Chain, Basic()));
        Assert.Equal(PdfSigningError.NoPage, e.Reason);
        Assert.Equal(0, ms.Length);
    }

    [Fact]
    public void ABadPageIndexOnADocumentWithPagesIsAnArgumentError()
    {
        using var doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
        using var ms = new MemoryStream();
        TestSigner signer = Kit.Signer(KeyKind.P256);
        Assert.Throws<ArgumentOutOfRangeException>(() => doc.SignPades(ms, signer.Key, signer.Certificate, signer.Chain, Basic(new PdfSigningOptions { PageIndex = 7 })));
    }

    [Fact]
    public void ANoChangesCertificationRefusesASignatureUnlessBreakingIsAllowed()
    {
        byte[] certified = Certified(PdfCertificationLevel.NoChanges);

        using (var doc = PdfDocument.Open(certified, new PdfOpenOptions { AllowEditing = true }))
        using (var ms = new MemoryStream())
        {
            TestSigner signer = Kit.Signer(KeyKind.Rsa2048);
            PdfSigningException e = Assert.Throws<PdfSigningException>(() => doc.SignPades(ms, signer.Key, signer.Certificate, signer.Chain, Basic()));
            Assert.Equal(PdfSigningError.CertificationForbidsChanges, e.Reason);
            Assert.Equal(0, ms.Length);
        }

        byte[] second = SignOver(certified, Basic(new PdfSigningOptions { AllowBreakingCertification = true }));
        PadesReport report = PadesRoundTripTests.Verify(second, Kit.Verify(Kit.Now.AddHours(1)));
        Assert.Equal(2, report.Signatures.Count);
        Assert.False(report.AllValid, "a signature added with the override must not leave the certification intact");
    }

    [Theory]
    [InlineData(PdfCertificationLevel.FormFilling)]
    [InlineData(PdfCertificationLevel.FormFillingAndAnnotations)]
    public void TheOtherCertificationLevelsStillTakeASignature(PdfCertificationLevel level)
    {
        byte[] second = SignOver(Certified(level), Basic());
        PadesReport report = PadesRoundTripTests.Verify(second, Kit.Verify(Kit.Now.AddHours(1)));
        Assert.True(report.AllValid, report.Summary);
    }

    [Fact]
    public async Task ANoChangesCertifiedDocumentTakesADocumentTimestampAndEverythingStaysValid()
    {
        byte[] certified = Certified(PdfCertificationLevel.NoChanges);
        DateTimeOffset at = Kit.Now;

        // Augmentation only appends time-stamps and store data; a document time-stamp's own update is allowed at every permission level
        // (ISO 32000-2 Table 257), so the certification must not be reported broken by it.
        byte[] stamped = await PadesAugmenter.AugmentAsync(certified, new PadesAugmentOptions
        {
            Level = PadesLevel.LongTermArchive,
            Timestamp = Kit.Tsa(at),
            ValidationData = Kit.Validation(at, PadesKit.Merge(Kit.Crls(at), Kit.Ocsp(at, Kit.Signer(KeyKind.P256).Certificate, Kit.TsaCertificate))),
        });

        PadesReport report = PadesRoundTripTests.Verify(stamped, Kit.Verify(at.AddHours(1)));
        Assert.Equal(2, report.Signatures.Count);
        Assert.True(report.AllValid, report.Summary);
        Assert.Equal(PadesLevel.LongTermArchive, report.Signatures.First(static s => s.Kind == PadesSignatureKind.Signature).Level);
    }

    [Fact]
    public void VerifyReadsTheOriginalBytesNotTheEditsInMemory()
    {
        byte[] signed = PadesRoundTripTests.Sign(Kit.Signer(KeyKind.P256), Basic());
        using var doc = PdfDocument.Open(signed, new PdfOpenOptions { AllowEditing = true });
        PadesReport before = doc.VerifyPades(Kit.Verify(Kit.Now.AddHours(1)));
        Assert.True(before.AllValid, before.Summary);

        doc.SetInfo("Title", "changed in memory");
        PadesReport after = doc.VerifyPades(Kit.Verify(Kit.Now.AddHours(1)));
        Assert.True(after.AllValid, after.Summary);
    }

    [Fact]
    public async Task VerifyAsyncTakesNoBytesEither()
    {
        byte[] signed = PadesRoundTripTests.Sign(Kit.Signer(KeyKind.P256), Basic());
        using var doc = PdfDocument.Open(signed);
        PadesReport report = await doc.VerifyPadesAsync(Kit.Verify(Kit.Now.AddHours(1)));
        Assert.True(report.AllValid, report.Summary);
    }

    [Fact]
    public void AFileThatChangedUnderTheReaderGivesTheTypedBridgeError()
    {
        string path = Path.Combine(Path.GetTempPath(), "onecrypto-pdf-" + Guid.NewGuid().ToString("N") + ".pdf");
        try
        {
            File.WriteAllBytes(path, PadesRoundTripTests.Sign(Kit.Signer(KeyKind.P256), Basic()));
            using PdfDocument doc = PdfDocument.Open(path);
            Assert.True(doc.VerifyPades(Kit.Verify(Kit.Now.AddHours(1))).AllValid);

            File.AppendAllText(path, "\n% appended after the document was opened\n");
            PadesException e = Assert.Throws<PadesException>(() => doc.VerifyPades(Kit.Verify(Kit.Now.AddHours(1))));
            Assert.Equal(PadesError.SourceChanged, e.Reason);
            Assert.IsType<PdfSourceChangedException>(e.InnerException);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("", null)]
    [InlineData("/Annots []", null)]
    [InlineData("/Annots 6 0 R", "[]")]
    public void SecondAndThirdSignaturesKeepEarlierOnesValidWhateverTheAnnotsLookLike(string pageExtra, string? extraObject)
    {
        byte[] pdf = PadesKit.Pdf(pageExtra: pageExtra, extraObject: extraObject);
        foreach (KeyKind kind in new[] { KeyKind.P256, KeyKind.Rsa2048, KeyKind.P384 })
        {
            pdf = SignOverWith(pdf, kind);
        }

        PadesReport report = PadesRoundTripTests.Verify(pdf, Kit.Verify(Kit.Now.AddHours(1)));
        Assert.Equal(3, report.Signatures.Count);
        Assert.True(report.AllValid, report.Summary);

        using PdfDocument doc = PdfDocument.Open(pdf);
        Assert.True(doc.VerifySignatures(new PdfSignatureVerifyOptions
        {
            TrustAnchors = [Kit.Root.Certificate.ToX509Certificate2()],
            ExtraCertificates = [Kit.Intermediate.Certificate.ToX509Certificate2()],
            ValidationTime = Kit.Now.AddHours(1),
        }).AllValid);
    }

    private static byte[] SignOverWith(byte[] input, KeyKind kind)
    {
        using var doc = PdfDocument.Open(input, new PdfOpenOptions { AllowEditing = true });
        using var ms = new MemoryStream();
        TestSigner signer = Kit.Signer(kind);
        doc.SignPades(ms, signer.Key, signer.Certificate, signer.Chain, Basic());
        return ms.ToArray();
    }
}
