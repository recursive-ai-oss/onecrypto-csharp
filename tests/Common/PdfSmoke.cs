using OnePdf;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Pdf;
using RecursiveAI.OneCrypto.Pdf.Tests;

namespace OneCrypto.Smoke;

/// <summary>
/// The PDF bridge in an app that has to be trimmed or AOT-compiled: sign a generated PDF at the archive level (signature time-stamp,
/// document security store, document time-stamp) with a throwaway PKI, then verify it and check the level and OnePDF's own verdict.
/// </summary>
internal static class PdfSmoke
{
    public static bool Run()
    {
        PadesKit kit = PadesKit.Shared;
        TestSigner signer = kit.Signer(KeyKind.P256);
        DateTimeOffset at = kit.Now;
        byte[] pdf;
        using (PdfDocument doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true }))
        using (var ms = new MemoryStream())
        {
            doc.SignPades(ms, signer.Key, signer.Certificate, signer.Chain, new PadesSignOptions
            {
                Level = PadesLevel.LongTermArchive,
                ReferenceTime = at,
                Timestamp = kit.Tsa(at),
                ValidationData = kit.Validation(at, PadesKit.Merge(kit.Crls(at), kit.Ocsp(at, signer.Certificate, kit.TsaCertificate))),
            });
            pdf = ms.ToArray();
        }

        using PdfDocument signed = PdfDocument.Open(pdf);
        PadesReport report = signed.VerifyPades(pdf, kit.Verify(at.AddHours(1)));
        return report.AllValid && report.Signatures.Count == 2 && report.Signatures[0].Level == PadesLevel.LongTermArchive && report.Signatures[0].OnePdf.IsValid;
    }
}
