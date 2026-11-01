using System.Text;
using OnePdf;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>
/// Writes the sample set for a check in a PDF reader that is not available to the test hosts: every level for RSA and ECDSA, one
/// RSASSA-PSS file and a tampered control, with the root certificate to trust and a manifest of the verdicts the bridge reports.
/// Runs only when ONECRYPTO_ACROBAT_OUT names a directory.
/// </summary>
public class ReaderSampleSetTests
{
    [Fact]
    public void WritesTheSampleSetAndItsManifest()
    {
        string? outDir = Environment.GetEnvironmentVariable("ONECRYPTO_ACROBAT_OUT");
        Assert.SkipWhen(string.IsNullOrEmpty(outDir), "ONECRYPTO_ACROBAT_OUT is not set");
        Directory.CreateDirectory(outDir!);
        PadesKit kit = PadesKit.Shared;
        DateTimeOffset at = kit.Now;
        File.WriteAllText(Path.Combine(outDir!, "test-root.pem"), kit.Root.Certificate.ToPem());
        File.WriteAllBytes(Path.Combine(outDir!, "test-root.cer"), kit.Root.Certificate.Encoded.ToArray());
        var manifest = new StringBuilder();
        manifest.AppendLine("# Sample set for a PDF reader check");
        manifest.AppendLine();
        manifest.AppendLine("Trust `test-root.cer` (a throwaway root generated with the set; it signs the signer and the time-stamp authority) as a trusted certificate for signatures and document time-stamps, then open each file. \"Bridge\" is the verdict of the OneCrypto verifier at the time of generation.");
        manifest.AppendLine();
        manifest.AppendLine("| File | Key | Level | Bridge verdict | Expected in the reader once the root is trusted |");
        manifest.AppendLine("|---|---|---|---|---|");

        void Add(string file, byte[] pdf, string key, string level, string expected)
        {
            File.WriteAllBytes(Path.Combine(outDir!, file), pdf);
            using PdfDocument doc = PdfDocument.Open(pdf);
            PadesReport report = doc.VerifyPades(kit.Verify(at.AddMinutes(5)));
            string verdict = report.Signatures.Count == 0 ? "no signatures" : $"{(report.AllValid ? "valid" : "not valid")}; level {report.Signatures[0].Level}";
            manifest.AppendLine($"| {file} | {key} | {level} | {verdict} | {expected} |");
        }

        foreach ((KeyKind kind, string name, bool pss) in new[] { (KeyKind.Rsa2048, "rsa", false), (KeyKind.P256, "ecdsa-p256", false), (KeyKind.Rsa2048, "rsa-pss", true), (KeyKind.Ed25519, "ed25519", false) })
        {
            TestSigner signer = kit.Signer(kind);
            foreach ((PadesLevel level, string lname) in new[] { (PadesLevel.Basic, "b-b"), (PadesLevel.Timestamped, "b-t"), (PadesLevel.LongTerm, "b-lt"), (PadesLevel.LongTermArchive, "b-lta") })
            {
                if (pss && level != PadesLevel.LongTermArchive)
                {
                    continue;
                }

                byte[] pdf = PadesRoundTripTests.Sign(signer, new PadesSignOptions
                {
                    Level = level,
                    RsaPss = pss,
                    ReferenceTime = at,
                    Timestamp = kit.Tsa(at),
                    ValidationData = level >= PadesLevel.LongTerm ? kit.Validation(at, PadesKit.Merge(kit.Crls(at), kit.Ocsp(at, signer.Certificate, kit.TsaCertificate))) : null,
                });
                string expected = level switch
                {
                    PadesLevel.Basic => "signature valid; no time-stamp; not long-term",
                    PadesLevel.Timestamped => "signature valid; signature time-stamp valid",
                    PadesLevel.LongTerm => "signature valid; time-stamp valid; \"signature is LTV enabled\" (validation data in the document)",
                    _ => "as B-LT, plus a valid document time-stamp over the whole file",
                };
                if (kind == KeyKind.Ed25519)
                {
                    expected = "Ed25519 is in PDF 2.0 (ISO/TS 32002): a reader that implements it shows: " + expected + ". An older reader may show an unknown or unsupported signature algorithm: note which";
                }

                Add($"{name}-{lname}.pdf", pdf, pss ? "RSA-2048 PSS" : name, level.ToString(), expected);
            }
        }

        TestSigner ec = kit.Signer(KeyKind.P256);
        byte[] good = PadesRoundTripTests.Sign(ec, new PadesSignOptions { Level = PadesLevel.Timestamped, ReferenceTime = at, Timestamp = kit.Tsa(at) });
        byte[] tampered = (byte[])good.Clone();
        int text = Encoding.Latin1.GetString(tampered).IndexOf("Hello, signature", StringComparison.Ordinal);
        tampered[text] = (byte)'J';
        Add("control-tampered.pdf", tampered, "ecdsa-p256", "tampered after B-T", "signature INVALID: the document was altered after signing");
        File.WriteAllText(Path.Combine(outDir!, "MANIFEST.md"), manifest.ToString());
    }
}
