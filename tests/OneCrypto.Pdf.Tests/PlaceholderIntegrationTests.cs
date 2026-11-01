using OnePdf;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>The signature hole on input OnePDF has to treat with care: encrypted files, files that already carry signatures, certified files.</summary>
public class PlaceholderIntegrationTests
{
    private static readonly PadesKit Kit = PadesKit.Shared;

    private static PadesSignOptions Basic(PdfSigningOptions? pdf = null) => new() { ReferenceTime = Kit.Now, Pdf = pdf };

    private static byte[] SignAgain(byte[] input, TestSigner signer, PadesSignOptions options, string? password = null)
    {
        using var doc = PdfDocument.Open(input, new PdfOpenOptions { AllowEditing = true, Password = password });
        using var ms = new MemoryStream();
        doc.SignPades(ms, signer.Key, signer.Certificate, signer.Chain, options);
        return ms.ToArray();
    }

    private static PadesReport Report(byte[] pdf, string? password = null)
    {
        using PdfDocument doc = PdfDocument.Open(pdf, new PdfOpenOptions { Password = password });
        return doc.VerifyPades(Kit.Verify(Kit.Now.AddHours(1)));
    }

    private static string Why(PadesReport r) => r.Summary + " " + string.Join("; ", r.Signatures.SelectMany(static s => s.Checks).Where(static c => c.Status == CmsCheckStatus.Failed).Select(static c => c.Rule + ": " + c.Reason));

    [Theory]
    [InlineData(PdfCipher.Aes256)]
    [InlineData(PdfCipher.Aes128)]
    public void AnEncryptedFileTakesASignatureAndTheSignatureVerifies(PdfCipher cipher)
    {
        using var plain = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
        using var enc = new MemoryStream();
        plain.Save(enc, new PdfSaveOptions { Encryption = PdfEncryptionAction.Set, NewEncryption = new PdfEncryptionOptions { UserPassword = "open sesame", OwnerPassword = "owner", Cipher = cipher } });

        byte[] signed = SignAgain(enc.ToArray(), Kit.Signer(KeyKind.P256), Basic(), "open sesame");
        PadesReport report = Report(signed, "open sesame");
        Assert.True(report.AllValid, Why(report));
    }

    [Fact]
    public void SecondAndThirdSignaturesLeaveEarlierOnesValid()
    {
        byte[] pdf = SignAgain(PadesKit.Pdf(), Kit.Signer(KeyKind.P256), Basic());
        pdf = SignAgain(pdf, Kit.Signer(KeyKind.Rsa2048), Basic());
        pdf = SignAgain(pdf, Kit.Signer(KeyKind.Ed25519), Basic());
        PadesReport report = Report(pdf);
        Assert.Equal(3, report.Signatures.Count);
        Assert.True(report.AllValid, Why(report));
    }

    [Fact]
    public void ACertifiedFileThatAllowsSignaturesTakesAnother()
    {
        byte[] pdf = SignAgain(PadesKit.Pdf(), Kit.Signer(KeyKind.P256), Basic(new PdfSigningOptions { Certify = PdfCertificationLevel.FormFilling }));
        pdf = SignAgain(pdf, Kit.Signer(KeyKind.Rsa2048), Basic());
        PadesReport report = Report(pdf);
        Assert.True(report.AllValid, Why(report));
    }

    [Fact]
    public void ACertifiedFileThatForbidsChangesIsNotSilentlyBrokenByAnotherSignature()
    {
        byte[] pdf = SignAgain(PadesKit.Pdf(), Kit.Signer(KeyKind.P256), Basic(new PdfSigningOptions { Certify = PdfCertificationLevel.NoChanges }));

        // DocMDP level 1 allows no change at all: OnePDF either refuses to add the signature or the certification no longer holds.
        // Anything but a file whose reports all say valid is acceptable; a silent break of the first signature is not.
        try
        {
            byte[] second = SignAgain(pdf, Kit.Signer(KeyKind.Rsa2048), Basic());
            PadesReport report = Report(second);
            Assert.False(report.AllValid, "a signature added to a no-changes file left both reports valid");
        }
        catch (PdfException)
        {
            // refused up front
        }
    }
}
