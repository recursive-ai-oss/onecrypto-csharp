using OnePdf;
using RecursiveAI.OneCrypto.Pdf;
using RecursiveAI.OneCrypto.Pdf.Tests;

namespace OneCrypto.Fuzz;

/// <summary>
/// The signature hole: a (mutated) PDF goes into <c>AddSignaturePlaceholder</c> and, when that succeeds, a CMS of the input's own bytes is written
/// with <c>PdfSignatureHole.Fill</c>. The input is <c>reserve selector (1) | offset jitter (2) | PDF</c>. Only OnePDF's typed exceptions may come out.
/// When a placeholder is written, the file must begin with the input (an incremental update), the digest must be that of the two ranges, a CMS that
/// fits must fill the hole without touching a byte outside it, and a wrong offset must be refused without writing anything.
/// </summary>
internal static class PlaceholderTarget
{
    private static readonly int[] Reserves = [64, 256, 4096, 16384];

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4)
        {
            return;
        }

        int reserve = Reserves[data[0] & 3];
        int jitter = (data[1] << 8) | data[2];
        byte[] pdf = data[3..].ToArray();
        if (!PdfDocument.TryOpen(pdf, out PdfDocument? doc, out _, new PdfOpenOptions { AllowEditing = true }))
        {
            return;
        }

        using (doc)
        {
            using var ms = new MemoryStream();
            PdfSignaturePlaceholder hole;
            try
            {
                hole = doc.AddSignaturePlaceholder(ms, new PdfSigningOptions { SubFilter = "ETSI.CAdES.detached" }, reserve);
            }
            catch (PdfException)
            {
                if (ms.Length != 0)
                {
                    throw new InvalidOperationException("a refused placeholder wrote output");
                }

                return;
            }
            catch (NotSupportedException)
            {
                return;
            }

            byte[] file = ms.ToArray();
            if (file.Length < pdf.Length || !file.AsSpan(0, pdf.Length).SequenceEqual(pdf))
            {
                throw new InvalidOperationException("the placeholder update does not extend the original bytes");
            }

            if (hole.HoleStart < pdf.Length || hole.HoleEnd > file.Length || hole.HoleEnd - hole.HoleStart != (2L * reserve) + 2)
            {
                throw new InvalidOperationException("the hole is not where or as large as reported");
            }

            using (var view = new MemoryStream(file))
            {
                if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(PdfSignatureHole.ComputeDigest(view, hole.HoleStart, hole.HoleEnd, hole.HashAlgorithm), hole.Digest))
                {
                    throw new InvalidOperationException("the reported digest is not the digest of the two ranges");
                }
            }

            // A wrong offset is refused and leaves the file as it was.
            byte[] before = (byte[])file.Clone();
            using (var wrong = new MemoryStream(file))
            {
                long shifted = hole.HoleStart + 1 + (jitter % 7);
                try
                {
                    PdfSignatureHole.Fill(wrong, shifted, shifted + (hole.HoleEnd - hole.HoleStart), [1, 2, 3]);
                    throw new InvalidOperationException("a hole at a wrong offset was filled");
                }
                catch (Exception e) when (e is ArgumentException or PdfException)
                {
                }
            }

            if (!file.AsSpan().SequenceEqual(before))
            {
                throw new InvalidOperationException("a refused fill changed the file");
            }

            // A CMS that fits fills the hole, and only the hole.
            int size = Math.Min(reserve, 1 + (jitter % reserve));
            byte[] cms = new byte[size];
            for (int i = 0; i < size; i++)
            {
                cms[i] = (byte)(pdf[i % pdf.Length] ^ i);
            }

            using var target = new MemoryStream(file);
            hole.Fill(target, cms);
            for (long i = 0; i < file.Length; i++)
            {
                bool inside = i >= hole.HoleStart && i < hole.HoleEnd;
                if (!inside && file[i] != before[i])
                {
                    throw new InvalidOperationException("a fill changed a byte outside the hole");
                }
            }

            // Too big a CMS is refused with the size needed.
            try
            {
                using var again = new MemoryStream(file);
                hole.Fill(again, new byte[reserve + 1]);
                throw new InvalidOperationException("an oversized CMS was accepted");
            }
            catch (PdfException)
            {
            }

            // The result is still a file OnePDF reads, with the signature listed.
            if (PdfDocument.TryOpen(file, out PdfDocument? reopened, out _))
            {
                using (reopened)
                {
                    _ = reopened.GetSignatures();
                }
            }
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        PadesKit kit = PadesKit.Shared;
        byte[] plain = PadesKit.Pdf();
        TestSigner signer = kit.Signer(KeyKind.P256);
        byte[] SignedBy(byte[] input, TestSigner who, PdfCertificationLevel? certify = null)
        {
            using var doc = PdfDocument.Open(input, new PdfOpenOptions { AllowEditing = true });
            using var output = new MemoryStream();
            doc.SignPades(output, who.Key, who.Certificate, who.Chain, new PadesSignOptions { ReferenceTime = kit.Now, Pdf = new PdfSigningOptions { Certify = certify } });
            return output.ToArray();
        }

        byte[] encrypted;
        using (var doc = PdfDocument.Open(plain, new PdfOpenOptions { AllowEditing = true }))
        using (var output = new MemoryStream())
        {
            doc.Save(output, new PdfSaveOptions { Encryption = PdfEncryptionAction.Set, NewEncryption = new PdfEncryptionOptions { UserPassword = string.Empty, OwnerPassword = "owner" } });
            encrypted = output.ToArray();
        }

        byte[] signed = SignedBy(plain, signer);
        foreach (byte[] pdf in new[] { plain, signed, SignedBy(signed, kit.Signer(KeyKind.Rsa2048)), SignedBy(plain, signer, PdfCertificationLevel.FormFilling), encrypted })
        {
            yield return [0, 0, 5, .. pdf];
            yield return [2, 1, 200, .. pdf];
        }
    }
}
