using System.Linq;
using System.Buffers.Binary;
using OnePdf;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Pdf;
using RecursiveAI.OneCrypto.Pdf.Tests;
using RecursiveAI.OneCrypto.Validation;

namespace OneCrypto.Fuzz;

/// <summary>
/// The PDF signature verify path: a (mutated) signed PDF with its document security store, VRI entries and document time-stamps.
/// The input is <c>reference time (8 octets, Unix seconds) | anchor length (2) | anchor certificate | PDF</c>, so a run does not depend on
/// a key generated in another process. Only a typed result may come out: nothing thrown, no <c>bridge-error</c> check, and a signature
/// the bridge accepts must be one OnePDF accepts.
/// </summary>
internal static class PadesTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 10)
        {
            return;
        }

        long seconds = BinaryPrimitives.ReadInt64BigEndian(data);
        int anchorLength = Math.Min((data[8] << 8) | data[9], data.Length - 10);
        ReadOnlySpan<byte> anchor = data.Slice(10, anchorLength);
        byte[] pdf = data[(10 + anchorLength)..].ToArray();
        DateTimeOffset reference = seconds is > 0 and < 253402300799 ? DateTimeOffset.FromUnixTimeSeconds(seconds) : new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var anchors = new List<TrustAnchor>();
        if (Certificate.TryParse(anchor.ToArray(), out Certificate? root) && root is not null)
        {
            anchors.Add(TrustAnchor.FromCertificate(root));
        }

        if (!PdfDocument.TryOpen(pdf, out PdfDocument? doc, out _))
        {
            return;
        }

        using (doc)
        {
            PadesReport report = PadesVerifier.Verify(doc, pdf, new PadesVerifyOptions
            {
                TrustAnchors = anchors,
                ReferenceTime = reference,
                Limits = new ValidationLimits { MaxSearchSteps = 500, MaxSignatureChecks = 64, MaxPathsValidated = 8, MaxPolicyNodes = 500 },
            });
            if (report.Signatures.Count != 0 && report.Signatures.Count != doc.GetSignatures().Count)
            {
                throw new InvalidOperationException("the report does not cover every signature");
            }

            foreach (PadesSignatureReport s in report.Signatures)
            {
                if (s.Checks.Any(static c => c.Rule == "bridge-error"))
                {
                    throw new InvalidOperationException("bridge-error: " + string.Join("; ", s.Checks.Where(static c => c.Rule == "bridge-error").Select(static c => c.Reason)));
                }

                if (s.IsValid && !s.OnePdf.IsValid)
                {
                    throw new InvalidOperationException("the bridge accepts a signature OnePDF rejects");
                }
            }
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        PadesKit kit = PadesKit.Shared;
        DateTimeOffset at = kit.Now;
        byte[] root = kit.Root.Certificate.Encoded.ToArray();
        byte[] Wrap(byte[] pdf)
        {
            byte[] head = new byte[10];
            BinaryPrimitives.WriteInt64BigEndian(head, at.AddHours(1).ToUnixTimeSeconds());
            head[8] = (byte)(root.Length >> 8);
            head[9] = (byte)root.Length;
            return [.. head, .. root, .. pdf];
        }

        foreach (KeyKind kind in new[] { KeyKind.P256, KeyKind.Rsa2048 })
        {
            TestSigner signer = kit.Signer(kind);
            RevocationData revocation = PadesKit.Merge(kit.Crls(at), kit.Ocsp(at, signer.Certificate, kit.TsaCertificate));
            foreach (PadesLevel level in new[] { PadesLevel.Basic, PadesLevel.Timestamped, PadesLevel.LongTerm, PadesLevel.LongTermArchive })
            {
                using var doc = PdfDocument.Open(PadesKit.Pdf(), new PdfOpenOptions { AllowEditing = true });
                using var ms = new MemoryStream();
                doc.SignPades(ms, signer.Key, signer.Certificate, signer.Chain, new PadesSignOptions
                {
                    Level = level,
                    ReferenceTime = at,
                    Timestamp = kit.Tsa(at),
                    ValidationData = level >= PadesLevel.LongTerm ? new PadesValidationData
                    {
                        TrustAnchors = [kit.Anchor],
                        Intermediates = kit.Chain,
                        ReferenceTime = at,
                        Revocation = revocation,
                        WriteVri = true,
                    } : null,
                });
                yield return Wrap(ms.ToArray());
            }
        }
    }
}
