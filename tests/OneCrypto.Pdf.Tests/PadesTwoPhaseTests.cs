using System.Diagnostics;
using System.Security.Cryptography;
using OnePdf;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>Signing in two steps: the hole and the serialised state first, the key later, in another process.</summary>
public class PadesTwoPhaseTests
{
    private static readonly PadesKit Kit = PadesKit.Shared;
    private const string ChildDirVariable = "ONECRYPTO_PADES_TWOPHASE_DIR";

    private static Certificate IssueFor(ISigningKey key, string name) =>
        Kit.Intermediate.Issue(key.PublicKey, DistinguishedName.Create((KnownOids.CommonName, name)), new CertificateIssueOptions
        {
            Profile = CertificateProfile.SMime,
            NotBefore = Kit.Now.AddDays(-400),
            Validity = TimeSpan.FromDays(700),
            SubjectAlternativeNames = [GeneralName.Email("signer@example.test")],
        });

    private static PadesVerifyOptions VerifyOptions => Kit.Verify(Kit.Now.AddHours(1));

    [Theory]
    [InlineData(KeyKind.Rsa2048)]
    [InlineData(KeyKind.P256)]
    [InlineData(KeyKind.Ed25519)]
    [InlineData(KeyKind.Ed448)]
    [InlineData(KeyKind.MlDsa65)]
    public void TheStateSurvivesSerialisationAndTheFilledFileVerifiesAndAugments(KeyKind kind)
    {
        if (kind == KeyKind.MlDsa65 && !MLDsa.IsSupported)
        {
            return;
        }

        TestSigner signer = Kit.Signer(kind);
        using var doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
        using var file = new MemoryStream();
        PadesPendingSignature pending = PadesTwoPhase.Prepare(doc, file, signer.Certificate, signer.Chain, Kit.Now, new PadesSignOptions { ReferenceTime = Kit.Now });

        // A hole with nothing in it is not a signature yet.
        PadesReport before = PadesRoundTripTests.Verify(file.ToArray(), VerifyOptions);
        Assert.False(before.AllValid);

        PadesPendingSignature again = PadesPendingSignature.Decode(pending.Encode());
        Assert.Equal(pending.Encode(), again.Encode());
        PadesTwoPhase.Complete(file, again, signer.Key);

        PadesReport report = PadesRoundTripTests.Verify(file.ToArray(), VerifyOptions);
        Assert.True(report.AllValid, report.Summary);
        Assert.Equal(PadesLevel.Basic, report.Signatures[0].Level);

        byte[] lta = PadesAugmenter.Augment(file.ToArray(), new PadesAugmentOptions
        {
            Level = PadesLevel.LongTermArchive,
            Timestamp = Kit.Tsa(Kit.Now),
            ValidationData = Kit.Validation(Kit.Now, PadesKit.Merge(Kit.Crls(Kit.Now), Kit.Ocsp(Kit.Now, signer.Certificate, Kit.TsaCertificate))),
        });
        PadesReport upgraded = PadesRoundTripTests.Verify(lta, VerifyOptions);
        Assert.True(upgraded.AllValid, upgraded.Summary);
        Assert.Equal(PadesLevel.LongTermArchive, upgraded.Signatures.Single(static s => s.Kind == PadesSignatureKind.Signature).Level);
    }

    [Fact]
    public void ACompletionIsRefusedForAnotherFileAForeignKeyAndABadState()
    {
        TestSigner signer = Kit.Signer(KeyKind.P256);
        using var doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
        using var file = new MemoryStream();
        PadesPendingSignature pending = PadesTwoPhase.Prepare(doc, file, signer.Certificate, signer.Chain, Kit.Now);

        TestSigner other = Kit.Signer(KeyKind.P256, "Another Signer");
        Assert.ThrowsAny<Exception>(() => PadesTwoPhase.Complete(new MemoryStream(file.ToArray()), pending, other.Key));

        // One changed byte outside the hole: the signature would cover other bytes than it was made over.
        byte[] bytes = file.ToArray();
        bytes[20] ^= 1;
        var e = Assert.Throws<PadesException>(() => PadesTwoPhase.Complete(new MemoryStream(bytes), pending, signer.Key));
        Assert.Equal(PadesError.UnsupportedFile, e.Reason);

        byte[] encoded = pending.Encode();
        Assert.False(PadesPendingSignature.TryDecode(encoded.AsSpan(0, encoded.Length - 3), out _, out _));
        Assert.False(PadesPendingSignature.TryDecode([], out _, out _));
    }

    [Fact]
    public void AHoleTooSmallForTheSignatureIsReportedWithTheSizeNeeded()
    {
        TestSigner signer = Kit.Signer(KeyKind.Rsa2048);
        using var doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
        using var file = new MemoryStream();
        PadesPendingSignature pending = PadesTwoPhase.Prepare(doc, file, signer.Certificate, signer.Chain, Kit.Now, new PadesSignOptions { Pdf = new PdfSigningOptions { ContentsReserve = 128 } });
        var e = Assert.Throws<PdfSigningException>(() => PadesTwoPhase.Complete(file, pending, signer.Key));
        Assert.Equal(PdfSigningError.ContentsTooSmall, e.Reason);
        Assert.True(e.RequiredBytes > 128);
    }

    /// <summary>Phase one here, phase two in a child process that has only the file, the serialised state and a seed.</summary>
    [Fact]
    public void PhaseTwoInAnotherProcessFillsTheHole()
    {
        string dir = Path.Combine(Path.GetTempPath(), "pades-2p-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            byte[] seed = RandomNumberGenerator.GetBytes(32);
            using var edKey = Primitives.Ed25519PrivateKey.FromSeed(seed);
            ISigningKey key = PrivateKey.FromEd25519(edKey);
            Certificate cert = IssueFor(key, "Two Process Signer");

            using var doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
            string pdfPath = Path.Combine(dir, "doc.pdf");
            PadesPendingSignature pending;
            using (var fs = File.Create(pdfPath))
            {
                pending = PadesTwoPhase.Prepare(doc, fs, cert, Kit.Chain, Kit.Now);
            }

            File.WriteAllBytes(Path.Combine(dir, "pending.der"), pending.Encode());
            File.WriteAllBytes(Path.Combine(dir, "seed.bin"), seed);

            string host = Environment.ProcessPath!;
            var psi = new ProcessStartInfo(host) { RedirectStandardOutput = true, RedirectStandardError = true };
            if (Path.GetFileNameWithoutExtension(host) == "dotnet")
            {
                psi.ArgumentList.Add(typeof(PadesTwoPhaseTests).Assembly.Location);
            }

            psi.ArgumentList.Add("-method");
            psi.ArgumentList.Add("RecursiveAI.OneCrypto.Pdf.Tests.PadesTwoPhaseTests.PhaseTwoChild");
            psi.Environment[ChildDirVariable] = dir;
            using Process child = Process.Start(psi)!;
            string output = child.StandardOutput.ReadToEnd() + child.StandardError.ReadToEnd();
            Assert.True(child.WaitForExit(120_000), "the child did not finish");
            Assert.True(child.ExitCode == 0, "child: " + output);
            Assert.True(File.Exists(Path.Combine(dir, "done.txt")), "the child test did not run: " + output);

            byte[] filled = File.ReadAllBytes(pdfPath);
            PadesReport report = PadesRoundTripTests.Verify(filled, VerifyOptions);
            Assert.True(report.AllValid, report.Summary);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>The child half of <see cref="PhaseTwoInAnotherProcessFillsTheHole"/>; does nothing unless the parent set the directory.</summary>
    [Fact]
    public void PhaseTwoChild()
    {
        string? dir = Environment.GetEnvironmentVariable(ChildDirVariable);
        if (dir is null)
        {
            return;
        }

        byte[] seed = File.ReadAllBytes(Path.Combine(dir, "seed.bin"));
        PadesPendingSignature pending = PadesPendingSignature.Decode(File.ReadAllBytes(Path.Combine(dir, "pending.der")));
        using var edKey = Primitives.Ed25519PrivateKey.FromSeed(seed);
        PadesTwoPhase.Complete(Path.Combine(dir, "doc.pdf"), pending, PrivateKey.FromEd25519(edKey));
        File.WriteAllText(Path.Combine(dir, "done.txt"), "ok");
    }
}
