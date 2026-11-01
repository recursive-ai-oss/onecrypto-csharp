using System.Text;
using OnePdf;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>
/// Writes the sample set for a check in a PDF reader that is not available to the test hosts: every level for RSA and ECDSA, one
/// RSASSA-PSS file and a tampered control, plus variants that each change one thing a reader might key on (the length of the time-stamp
/// authority's ECDSA signature, an RSA-only chain, the ESS attribute, key usage bits, the RSA padding), with the root certificates to trust and
/// a manifest of the verdicts the bridge reports. Runs only when ONECRYPTO_ACROBAT_OUT names a directory.
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
        File.WriteAllText(Path.Combine(outDir!, "test-root-rsa.pem"), RsaKit.Value.Root.Certificate.ToPem());
        File.WriteAllBytes(Path.Combine(outDir!, "test-root-rsa.cer"), RsaKit.Value.Root.Certificate.Encoded.ToArray());
        var manifest = new StringBuilder();
        manifest.AppendLine("# Sample set for a PDF reader check");
        manifest.AppendLine();
        manifest.AppendLine("Trust `test-root.cer` (a throwaway root generated with the set; it signs the signer and the time-stamp authority) as a trusted certificate for signatures and document time-stamps, then open each file. \"Bridge\" is the verdict of the OneCrypto verifier at the time of generation.");
        manifest.AppendLine();
        manifest.AppendLine("| File | Key | Level | Bridge verdict | Expected in the reader once the root is trusted |");
        manifest.AppendLine("|---|---|---|---|---|");
        PadesKit current = kit;

        void Add(string file, byte[] pdf, string key, string level, string expected)
        {
            File.WriteAllBytes(Path.Combine(outDir!, file), pdf);
            using PdfDocument doc = PdfDocument.Open(pdf);
            PadesReport report = doc.VerifyPades(current.Verify(at.AddMinutes(5)));
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

        // ---- variants: one change each, to find what a reader keys on --------------------------------------------------
        manifest.AppendLine();
        manifest.AppendLine("## Variants");
        manifest.AppendLine();
        manifest.AppendLine("Each row changes one thing against its base file; the last column says which hypothesis it separates. Open each file in a fresh reader session (quit the reader between files, so nothing cached from one file reaches the next), and for the Basic files also try the other order: open an ECDSA Basic file first, then an RSA one, and the reverse, in two separate sessions.");
        manifest.AppendLine();
        manifest.AppendLine("Expected for every row, as for its base file: signature valid, and a signature time-stamp where the level has one. The last column says what any other result separates (the first set gave \"invalid, formatting errors\" for `rsa-b-t` and \"validity unknown\" for `rsa-b-b`, which is what these files try to explain).");
        manifest.AppendLine();
        manifest.AppendLine("Trust `test-root.cer` for every file except the `rsa-only-*` ones, which need `test-root-rsa.cer`. Every file here comes from one PKI generated in the same run, so the base files below carry new keys and values: `rsa-b-t.pdf` is a fresh draw of the file that failed in the first set (same level, same certificate profile, same first time-stamp serial, 1000).");
        string? control = Environment.GetEnvironmentVariable("ONECRYPTO_ACROBAT_CONTROL");
        if (!string.IsNullOrEmpty(control) && File.Exists(Path.Combine(control, "rsa-b-t.pdf")))
        {
            File.Copy(Path.Combine(control, "rsa-b-t.pdf"), Path.Combine(outDir!, "first-set-rsa-b-t.pdf"), overwrite: true);
            File.Copy(Path.Combine(control, "test-root.cer"), Path.Combine(outDir!, "first-set-test-root.cer"), overwrite: true);
            manifest.AppendLine();
            manifest.AppendLine("`first-set-rsa-b-t.pdf` is the file from the first set byte for byte, with its own root `first-set-test-root.cer` (trust it as well). It is the reproducibility control: invalid again means the verdict follows these bytes; valid means the first result depended on the session.");
        }

        manifest.AppendLine();
        manifest.AppendLine("| File | Key | Level | Bridge verdict | Changed against the base, and what a different verdict means |");
        manifest.AppendLine("|---|---|---|---|---|");

        TestSigner rsa = kit.Signer(KeyKind.Rsa2048);
        foreach ((int len, int copy) in new[] { (70, 1), (70, 2), (71, 1), (71, 2), (72, 1), (72, 2) })
        {
            byte[] pdf = PadesRoundTripTests.Sign(rsa, new PadesSignOptions { Level = PadesLevel.Timestamped, ReferenceTime = at, Timestamp = TsaWithSignatureLength(kit, at, len) });
            Add($"rsa-b-t-tsa{len}-{copy}.pdf", pdf, "rsa", "Timestamped", $"base rsa-b-t, the time-stamp authority's ECDSA signature chosen to be {len} octets (DER, r and s of 32 octets: 70; one needs a leading zero: 71; both: 72), fresh RSA signature and token. All six valid: the set 1 failure was not the signature length; only the 70s invalid: Reader mishandles a short authority signature inside a signature time-stamp");
        }

        byte[] ecTsa70 = PadesRoundTripTests.Sign(ec, new PadesSignOptions { Level = PadesLevel.Timestamped, ReferenceTime = at, Timestamp = TsaWithSignatureLength(kit, at, 70) });
        Add("ecdsa-p256-b-t-tsa70.pdf", ecTsa70, "ecdsa-p256", "Timestamped", "base ecdsa-p256-b-t with a 70-octet authority signature: invalid here too means the short authority signature matters whatever signs the document; valid means it is something in the RSA signature");

        foreach ((PadesLevel level, string lname) in new[] { (PadesLevel.Basic, "b-b"), (PadesLevel.Timestamped, "b-t"), (PadesLevel.LongTerm, "b-lt"), (PadesLevel.LongTermArchive, "b-lta") })
        {
            PadesKit rk = RsaKit.Value;
            current = rk;
            TestSigner rs = rk.Signer(KeyKind.Rsa2048);
            byte[] pdf = PadesRoundTripTests.Sign(rs, new PadesSignOptions
            {
                Level = level,
                ReferenceTime = at,
                Timestamp = rk.Tsa(at),
                ValidationData = level >= PadesLevel.LongTerm ? rk.Validation(at, PadesKit.Merge(rk.Crls(at), rk.Ocsp(at, rs.Certificate, rk.TsaCertificate))) : null,
            });
            Add($"rsa-only-{lname}.pdf", pdf, "rsa (RSA-only chain)", level.ToString(), "signer, intermediate, authority and root all RSA, no ECDSA signature anywhere; trust test-root-rsa.cer too. Same verdict as rsa-" + lname + " means the signer's key type is what Reader keys on; the b-t file valid and rsa-b-t invalid points at the ECDSA parts of the chain or token");
        }

        current = kit;
        byte[] noEss = PadesRoundTripTests.Sign(rsa, new PadesSignOptions { Level = PadesLevel.Basic, ReferenceTime = at, SigningCertificate = EssSigningCertificate.None });
        Add("rsa-b-b-no-ess.pdf", noEss, "rsa", "Basic", "base rsa-b-b without the ESS signing-certificate attribute (not baseline-conformant; a test only): plain valid means Reader wanted the attribute's absence or presence of the certificate hash handled differently for RSA");
        byte[] noEssEc = PadesRoundTripTests.Sign(ec, new PadesSignOptions { Level = PadesLevel.Basic, ReferenceTime = at, SigningCertificate = EssSigningCertificate.None });
        Add("ecdsa-p256-b-b-no-ess.pdf", noEssEc, "ecdsa-p256", "Basic", "base ecdsa-p256-b-b without ESS: a change from valid to unknown means the attribute is what lets Reader finish the check");

        CertificateProfile noEnc = new()
        {
            Name = "smime-signing-only",
            KeyUsages = KeyUsages.DigitalSignature | KeyUsages.NonRepudiation,
            ExtendedKeyUsages = [KnownOids.EmailProtection],
            SubjectAlternativeNameRequired = true,
            AllowedSubjectAlternativeNames = [GeneralNameKind.Rfc822Name],
            MaxValidity = TimeSpan.FromDays(825),
        };
        TestSigner rsaNoEnc = kit.Signer(KeyKind.Rsa2048, "Test Signer Rsa2048 SigningOnly", profile: noEnc);
        Add("rsa-b-b-signing-only.pdf", PadesRoundTripTests.Sign(rsaNoEnc, new PadesSignOptions { Level = PadesLevel.Basic, ReferenceTime = at }), "rsa", "Basic", "signer certificate without the keyEncipherment bit (the RSA signer of rsa-b-b has it, the ECDSA one has not): valid means Reader dislikes the extra key usage");
        CertificateProfile withEnc = new()
        {
            Name = "smime-with-encipherment",
            KeyUsages = KeyUsages.DigitalSignature | KeyUsages.NonRepudiation | KeyUsages.KeyEncipherment,
            ExtendedKeyUsages = [KnownOids.EmailProtection],
            SubjectAlternativeNameRequired = true,
            AllowedSubjectAlternativeNames = [GeneralNameKind.Rfc822Name],
            MaxValidity = TimeSpan.FromDays(825),
        };
        TestSigner ecEnc = kit.Signer(KeyKind.P256, "Test Signer P256 Encipherment", profile: withEnc);
        Add("ecdsa-p256-b-b-key-encipherment.pdf", PadesRoundTripTests.Sign(ecEnc, new PadesSignOptions { Level = PadesLevel.Basic, ReferenceTime = at }), "ecdsa-p256", "Basic", "ECDSA signer certificate that also carries keyEncipherment: unknown here means that bit is what Reader keys on");

        TestSigner rsa2 = kit.Signer(KeyKind.Rsa2048, "Test Signer Rsa2048 Second");
        Add("rsa-b-b-second-key.pdf", PadesRoundTripTests.Sign(rsa2, new PadesSignOptions { Level = PadesLevel.Basic, ReferenceTime = at }), "rsa", "Basic", "a second RSA signer under the same intermediate, the same profile as rsa-b-b: a different verdict from rsa-b-b means the result depends on the particular certificate or session state, not on RSA");
        Add("rsa-pss-b-b.pdf", PadesRoundTripTests.Sign(rsa, new PadesSignOptions { Level = PadesLevel.Basic, ReferenceTime = at, RsaPss = true }), "RSA-2048 PSS", "Basic", "rsa-b-b with RSASSA-PSS: valid means the padding or its algorithm identifier separates the verdicts");
        File.WriteAllText(Path.Combine(outDir!, "MANIFEST.md"), manifest.ToString());
    }

    private static readonly Lazy<PadesKit> RsaKit = new(PadesKit.CreateRsaOnly);

    /// <summary>A time-stamp function whose answers carry an authority signature of exactly <paramref name="length"/> octets (ECDSA is randomised, so it asks again until one fits).</summary>
    private static PadesTimestampFunction TsaWithSignatureLength(PadesKit kit, DateTimeOffset at, int length) => (request, ct) =>
    {
        for (int attempt = 0; attempt < 400; attempt++)
        {
            byte[] answer = kit.Authority.Handle(request.Encoded, at).Encoded.ToArray();
            if (TokenSignatureLength(answer) == length)
            {
                return ValueTask.FromResult(answer);
            }
        }

        throw new InvalidOperationException("No authority signature of the wanted length came up.");
    };

    /// <summary>The length of the last signature in a time-stamp response: the SignerInfo signature is the final element, a DER ECDSA-Sig-Value in an OCTET STRING.</summary>
    internal static int TokenSignatureLength(byte[] response)
    {
        for (int length = 68; length <= 72; length++)
        {
            int at = response.Length - length;
            if (at >= 2 && response[at - 2] == 0x04 && response[at - 1] == length && response[at] == 0x30 && response[at + 1] == length - 2)
            {
                return length;
            }
        }

        return 0;
    }
}
