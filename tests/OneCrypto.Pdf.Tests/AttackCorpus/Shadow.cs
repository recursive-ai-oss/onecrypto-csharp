using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using OnePdf;
using RecursiveAI.OneCrypto.Validation;
using Xunit;

namespace RecursiveAI.OneCrypto.Pdf.Tests.AttackCorpus;

/// <summary>
/// Runs the bridge beside OnePDF on every verification the lifted attack tests make. The tests keep their own assertions on OnePDF's
/// verdict; this adds the bridge's: a signature OnePDF rejects must be rejected by the bridge too (the bridge adds rules, never removes
/// one), and a signature OnePDF accepts must not be rejected without a reason the test file lists.
/// </summary>
internal static class Shadow
{
    private static readonly ConditionalWeakTable<PdfDocument, byte[]> Bytes = new();

    /// <summary>Signatures OnePDF accepted and the bridge did not, as "test: reason".</summary>
    public static readonly List<string> Stricter = [];

    /// <summary>Verifications compared.</summary>
    public static int Compared;

    public static PdfDocument Open(byte[] file, PdfOpenOptions? options = null)
    {
        PdfDocument doc = PdfDocument.Open(file, options);
        Bytes.AddOrUpdate(doc, file);
        return doc;
    }

    public static PdfSignatureVerification VerifyShadow(this PdfSignature signature, PdfSignatureVerifyOptions? options = null)
    {
        PdfSignatureVerification one = signature.Verify(options);
        IReadOnlyList<PdfSignature> all = signature.Document.GetSignatures();
        int index = -1;
        for (int i = 0; i < all.Count; i++)
        {
            if (ReferenceEquals(all[i].Dictionary, signature.Dictionary))
            {
                index = i;
            }
        }

        Compare(signature.Document, options, [(index, one)]);
        return one;
    }

    public static PdfSignatureReport VerifySignaturesShadow(this PdfDocument document, PdfSignatureVerifyOptions? options = null)
    {
        PdfSignatureReport report = document.VerifySignatures(options);
        Compare(document, options, report.Signatures.Select((v, i) => (i, v)).ToList());
        return report;
    }

    private static void Compare(PdfDocument document, PdfSignatureVerifyOptions? options, List<(int Index, PdfSignatureVerification One)> verdicts)
    {
        if (!Bytes.TryGetValue(document, out byte[]? file))
        {
            return;
        }

        PdfSignatureVerifyOptions o = options ?? new PdfSignatureVerifyOptions();
        var anchors = new List<TrustAnchor>();
        foreach (X509Certificate2 c in o.TrustAnchors)
        {
            anchors.Add(TrustAnchor.FromCertificate(Certificate.FromX509Certificate2(c)));
        }

        var pool = o.ExtraCertificates.Select(Certificate.FromX509Certificate2).ToList();
        PadesReport report = PadesVerifier.Verify(document, new PadesVerifyOptions
        {
            TrustAnchors = anchors,
            Intermediates = pool,
            ReferenceTime = o.ValidationTime ?? DateTimeOffset.UtcNow,
            RequireSigningKeyUsage = o.RequireSigningKeyUsage,
            AnalyzeModifications = o.AnalyzeModifications,
        });
        Assert.Equal(document.GetSignatures().Count, report.Signatures.Count);
        foreach ((int index, PdfSignatureVerification one) in verdicts)
        {
            if (index < 0)
            {
                continue;
            }

            PadesSignatureReport bridge = report.Signatures[index];
            Compared++;
            if (Environment.GetEnvironmentVariable("ONECRYPTO_SHADOW_LOG") is { Length: > 0 } log)
            {
                File.AppendAllText(log, TestName() + "\t" + one.IsValid + "\t" + bridge.IsValid + "\n");
            }

            Assert.DoesNotContain(bridge.Checks, static c => c.Rule == "bridge-error");
            if (!one.IsValid)
            {
                Assert.False(bridge.IsValid, "OnePDF rejects this signature (" + string.Join("; ", one.Warnings) + ") but the bridge accepts it.");
            }
            else if (!bridge.IsValid)
            {
                Lock.Enter();
                try
                {
                    string line = TestName() + ": " + string.Join("; ", bridge.Checks.Where(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported).Select(static c => c.Rule + " - " + c.Reason));
                    Stricter.Add(line);
                    File.AppendAllText(Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "pades-stricter.txt"), line + "\n");
                }
                finally
                {
                    Lock.Exit();
                }
            }
        }
    }

    private static readonly System.Threading.Lock Lock = new();

    private static string TestName()
    {
        foreach (System.Diagnostics.StackFrame f in new System.Diagnostics.StackTrace().GetFrames())
        {
            System.Reflection.MethodBase? m = f.GetMethod();
            if (m?.DeclaringType?.Namespace?.EndsWith("AttackCorpus", StringComparison.Ordinal) == true && m.DeclaringType != typeof(Shadow) && m.DeclaringType.Name is "AttackTests" or "SignatureModificationTests")
            {
                return m.DeclaringType.Name + "." + m.Name;
            }
        }

        return "?";
    }
}
