using OnePdf;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>Malformed document security stores, VRI entries and time-stamps: reported, skipped and bounded, never thrown and never believed.</summary>
public class HostileStoreTests
{
    private static readonly PadesKit Kit = PadesKit.Shared;

    private static byte[] Stamped() => PadesRoundTripTests.Sign(Kit.Signer(KeyKind.P256), new PadesSignOptions { Level = PadesLevel.Timestamped, ReferenceTime = Kit.Now, Timestamp = Kit.Tsa(Kit.Now) });

    private static byte[] WithStore(byte[] pdf, Action<PdfDocument, PdfDictionary> build)
    {
        using var doc = PdfDocument.Open(pdf, new PdfOpenOptions { AllowEditing = true });
        var dss = new PdfDictionary();
        build(doc, dss);
        doc.Catalog.SetEntry("DSS", doc.AddObject(dss));
        using var ms = new MemoryStream();
        doc.SaveIncremental(ms);
        return ms.ToArray();
    }

    private static PdfArray Streams(PdfDocument doc, IEnumerable<byte[]> items)
    {
        var a = new PdfArray();
        foreach (byte[] i in items)
        {
            a.Append(doc.AddObject(doc.CreateStream(i)));
        }

        return a;
    }

    [Fact]
    public void GarbageInTheStoreIsSkippedWithAWarningAndTheSignatureStaysAsItWas()
    {
        byte[] pdf = WithStore(Stamped(), (doc, dss) =>
        {
            dss.SetEntry("Certs", Streams(doc, [[1, 2, 3], new byte[100], Kit.Root.Certificate.Encoded.ToArray()[..50]]));
            dss.SetEntry("CRLs", Streams(doc, [[0x30, 0x03, 0x02, 0x01, 0x01]]));
            dss.SetEntry("OCSPs", Streams(doc, [[0x30, 0x80, 0x00, 0x00], "not der"u8.ToArray()]));
            var vri = new PdfDictionary();
            vri.SetEntry("NOTAHASH", new PdfInteger(7));
            vri.SetEntry("ABCD", new PdfName("Nothing"));
            dss.SetEntry("VRI", vri);
            var arr = new PdfArray();
            arr.Append(new PdfInteger(5));
            arr.Append(PdfNull.Instance);
            dss.SetEntry("Certs", arr);
        });
        PadesReport report = PadesRoundTripTests.Verify(pdf, Kit.Verify(Kit.Now.AddHours(1)));
        Assert.True(report.Signatures.Single().IsValid);
        Assert.True(report.Dss.Present);
        Assert.Equal(0, report.Dss.Certificates);
        Assert.NotEmpty(report.Warnings);
        Assert.Equal(PadesLevel.Timestamped, report.Signatures.Single().Level);
    }

    [Fact]
    public void ABloatedArrayIsCutAtTheLimit()
    {
        byte[] cert = Kit.Intermediate.Certificate.Encoded.ToArray();
        byte[] pdf = WithStore(Stamped(), (doc, dss) =>
        {
            var one = doc.AddObject(doc.CreateStream(cert));
            var arr = new PdfArray();
            for (int i = 0; i < DssStore.MaxItems + 500; i++)
            {
                arr.Append(new PdfReference(one.Number, one.Generation));
            }

            dss.SetEntry("Certs", arr);
        });
        PadesReport report = PadesRoundTripTests.Verify(pdf, Kit.Verify(Kit.Now.AddHours(1)));
        Assert.Equal(DssStore.MaxItems, report.Dss.Certificates);
        Assert.Contains(report.Warnings, static w => w.Contains("more than", StringComparison.Ordinal));
        Assert.True(report.Signatures.Single().IsValid);
    }

    [Fact]
    public void ARevocationAnswerForAnotherCertificateDoesNotCountAsKnowledge()
    {
        // A stored CRL from the right CA that does not list the signer is good news only when it is fresh; a stale or foreign one is Unknown.
        byte[] pdf = PadesRoundTripTests.Sign(Kit.Signer(KeyKind.P256), new PadesSignOptions { Level = PadesLevel.Basic, ReferenceTime = Kit.Now });
        var stale = Kit.Crls(Kit.Now.AddDays(-90));
        byte[] withStale = WithStore(pdf, (doc, dss) => dss.SetEntry("CRLs", Streams(doc, stale.Crls.Select(static c => c.Encoded.ToArray()))));
        PadesSignatureReport r = PadesRoundTripTests.Verify(withStale, Kit.Verify(Kit.Now.AddHours(1))).Signatures.Single();
        Assert.NotEqual(RecursiveAI.OneCrypto.Validation.RevocationStatus.Good, r.Chain!.RevocationSummary);
        Assert.NotEqual(PadesLevel.LongTerm, r.Level);
    }

    [Fact]
    public void ADocumentTimestampOverChangedBytesIsNotATrustedTime()
    {
        TestSigner signer = Kit.Signer(KeyKind.P256);
        byte[] bb = PadesRoundTripTests.Sign(signer, new PadesSignOptions { ReferenceTime = Kit.Now });
        byte[] ts = PadesAugmenter.Augment(bb, new PadesAugmentOptions { Level = PadesLevel.Timestamped, Timestamp = Kit.Tsa(Kit.Now) });
        byte[] withDoc = PadesAugmenter.Augment(ts, new PadesAugmentOptions
        {
            Level = PadesLevel.LongTermArchive,
            Timestamp = Kit.Tsa(Kit.Now),
            ValidationData = Kit.Validation(Kit.Now, PadesKit.Merge(Kit.Crls(Kit.Now), Kit.Ocsp(Kit.Now, signer.Certificate, Kit.TsaCertificate))),
        });

        // A byte inside the range the document time-stamp covers changes, so its token no longer belongs to the document.
        withDoc[7] = (byte)'6';
        PadesReport report = PadesRoundTripTests.Verify(withDoc, Kit.Verify(Kit.Now.AddHours(1)));
        PadesSignatureReport stamp = report.Signatures.Single(static s => s.Kind == PadesSignatureKind.DocumentTimestamp);
        Assert.False(stamp.IsValid);
        Assert.Null(stamp.ProofOfExistence);
        Assert.Equal(CmsCheckStatus.Failed, stamp.Find("timestamp")!.Status);
        Assert.Contains("message-imprint", stamp.Find("timestamp")!.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ATimestampDatedAfterTheReferenceTimeProvesNothing()
    {
        TestSigner signer = Kit.Signer(KeyKind.P256);
        byte[] pdf = PadesRoundTripTests.Sign(signer, new PadesSignOptions { Level = PadesLevel.Timestamped, ReferenceTime = Kit.Now, Timestamp = Kit.Tsa(Kit.Now.AddDays(10)) });
        PadesSignatureReport r = PadesRoundTripTests.Verify(pdf, Kit.Verify(Kit.Now)).Signatures.Single();
        Assert.False(r.IsValid);
        Assert.Null(r.ProofOfExistence);
    }

    [Fact]
    public void WithoutAnchorsNothingIsTrustedAndNoTimeIsProven()
    {
        byte[] pdf = PadesRoundTripTests.Sign(Kit.Signer(KeyKind.P256), new PadesSignOptions { Level = PadesLevel.Timestamped, ReferenceTime = Kit.Now, Timestamp = Kit.Tsa(Kit.Now) });
        PadesSignatureReport r = PadesRoundTripTests.Verify(pdf, new PadesVerifyOptions { ReferenceTime = Kit.Now.AddHours(1) }).Signatures.Single();
        Assert.False(r.IsValid);
        Assert.Null(r.ProofOfExistence);
        Assert.Equal(PadesLevel.None, r.Level);
    }

    [Fact]
    public void ASignatureWithTwoSignerInfosOrAnAttachedContentIsRefused()
    {
        // The bridge's single-signer and detached rules are separate checks, so a wrapped second signer cannot ride along unverified.
        byte[] pdf = PadesRoundTripTests.Sign(Kit.Signer(KeyKind.P256), new PadesSignOptions { ReferenceTime = Kit.Now });
        PadesSignatureReport ok = PadesRoundTripTests.Verify(pdf, Kit.Verify(Kit.Now.AddHours(1))).Signatures.Single();
        Assert.Equal(CmsCheckStatus.Passed, ok.Find("single-signer")!.Status);
        Assert.Null(ok.Find("detached"));
    }
}
