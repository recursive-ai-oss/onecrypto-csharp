using OnePdf;
using Xunit;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>Real-world signed files (a directory named by ONECRYPTO_PDF_CORPUS, searched recursively) run through the bridge: nothing throws, nothing is reported as a bridge error, and the bridge never accepts what OnePDF rejects.</summary>
public class CorpusTests
{
    [Fact]
    public void SignedFilesOfTheCorpusProduceReportsThatNeverWeakenOnePdf()
    {
        string? root = Environment.GetEnvironmentVariable("ONECRYPTO_PDF_CORPUS");
        Assert.SkipWhen(string.IsNullOrEmpty(root) || !Directory.Exists(root), "ONECRYPTO_PDF_CORPUS is not set");
        int files = 0;
        foreach (string path in Directory.EnumerateFiles(root!, "*.pdf", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            byte[] data = File.ReadAllBytes(path);
            if (data.AsSpan().IndexOf("ByteRange"u8) < 0 || !PdfDocument.TryOpen(data, out PdfDocument? doc, out _))
            {
                continue;
            }

            using (doc)
            {
                files++;
                PadesReport report = PadesVerifier.Verify(doc, new PadesVerifyOptions { ReferenceTime = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero) });
                PdfSignatureReport one = doc.VerifySignatures(new PdfSignatureVerifyOptions { ValidationTime = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero) });
                Assert.Equal(one.Signatures.Count, report.Signatures.Count);
                for (int i = 0; i < report.Signatures.Count; i++)
                {
                    Assert.DoesNotContain(report.Signatures[i].Checks, static c => c.Rule == "bridge-error");
                    if (!one.Signatures[i].IsValid)
                    {
                        Assert.False(report.Signatures[i].IsValid, path);
                    }
                }
            }
        }

        Assert.True(files > 0);
    }
}
