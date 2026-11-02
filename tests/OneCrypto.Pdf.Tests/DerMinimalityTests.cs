using System.Formats.Asn1;
using System.Security.Cryptography;
using OnePdf;
using RecursiveAI.OneCrypto.Tsp;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>
/// Every signature, time-stamp token and certificate the bridge writes must be strict DER: shortest lengths, minimal integers, sorted SET OF,
/// canonical times. Readers that parse the signature with a hand-written DER reader reject what the BCL-style lenient readers accept, and the
/// failure shows up as "errors in the formatting" with no signer. The check walks the whole tree, and the octet strings and bit strings that
/// themselves hold DER (time-stamp token content, certificate extensions, keys, signatures), with a reader in DER mode that throws on any
/// deviation.
/// </summary>
public class DerMinimalityTests
{
    private static readonly PadesKit Kit = PadesKit.Shared;

    [Theory]
    [InlineData(KeyKind.Rsa2048, false)]
    [InlineData(KeyKind.Rsa2048, true)]
    [InlineData(KeyKind.P256, false)]
    [InlineData(KeyKind.P384, false)]
    [InlineData(KeyKind.Ed25519, false)]
    public void EverythingWrittenIsStrictDerAtEveryLevel(KeyKind kind, bool pss)
    {
        TestSigner signer = Kit.Signer(kind);
        foreach (PadesLevel level in new[] { PadesLevel.Basic, PadesLevel.Timestamped, PadesLevel.LongTerm, PadesLevel.LongTermArchive })
        {
            // Repeat: ECDSA signature lengths and RSA/ECDSA values change from run to run, so a value-dependent encoding slip shows up in a few.
            for (int i = 0; i < 6; i++)
            {
                byte[] pdf = PadesRoundTripTests.Sign(signer, new PadesSignOptions
                {
                    Level = level,
                    RsaPss = pss,
                    ReferenceTime = Kit.Now,
                    Timestamp = Kit.Tsa(Kit.Now),
                    ValidationData = level >= PadesLevel.LongTerm ? Kit.Validation(Kit.Now, PadesKit.Merge(Kit.Crls(Kit.Now), Kit.Ocsp(Kit.Now, signer.Certificate, Kit.TsaCertificate))) : null,
                });
                AssertSignaturesAreStrictDer(pdf, $"{kind} pss={pss} {level} #{i}");
            }
        }
    }

    [Fact]
    public void TimeStampAnswersOfEveryAuthoritySignatureLengthAreStrictDer()
    {
        // The authority's ECDSA signature is 70, 71 or 72 octets depending on whether r and s need a leading zero.
        var seen = new HashSet<int>();
        for (int i = 0; i < 600 && !(seen.Contains(70) && seen.Contains(71) && seen.Contains(72)); i++)
        {
            byte[] request = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = new byte[32], Nonce = TimeStampRequest.NewNonce(), CertReq = true }).Encoded.ToArray();
            byte[] answer = Kit.Authority.Handle(request, Kit.Now).Encoded.ToArray();
            AssertStrictDer(answer, "time-stamp response");
            seen.Add(ReaderSampleSetTests.TokenSignatureLength(answer));
        }

        // Shorter ones (69, 68) occur too, when r or s has a leading zero byte of its own.
        Assert.Contains(70, seen);
        Assert.Contains(71, seen);
        Assert.Contains(72, seen);
    }

    [Fact]
    public void RandomOctetsThatLookLikeATagAreNotJudgedAsDer()
    {
        // A digest whose first two octets read as a context tag and a length that fits (this exact value failed the repeated-signing test once in
        // about 25 runs). It is a message digest, not nested DER.
        byte[] digest = Convert.FromHexString("A21ED3CCEF9439AA17F35A23ACA8A026CD4F6EFD588A910B7DCC6FDC781CEC3D");
        AssertStrictDer(RecursiveAI.OneCrypto.Asn1.DerWriter.Sequence(RecursiveAI.OneCrypto.Asn1.DerWriter.OctetString(digest)), "digest");
    }

    [Fact]
    public void NestedDerWithANonMinimalLengthIsStillReported()
    {
        // SEQUENCE { OCTET STRING { SEQUENCE with the length 5 written as 81 05 } }
        byte[] inner = [0x30, 0x81, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01];
        byte[] outer = RecursiveAI.OneCrypto.Asn1.DerWriter.Sequence(RecursiveAI.OneCrypto.Asn1.DerWriter.OctetString(inner));
        Assert.Throws<Xunit.Sdk.XunitException>(() => AssertStrictDer(outer, "nested"));
    }

    [Fact]
    public void LengthsAroundEveryOctetCountBoundaryAreMinimal()
    {
        foreach (int size in new[] { 0, 1, 126, 127, 128, 129, 254, 255, 256, 257, 65534, 65535, 65536, 65537 })
        {
            byte[] content = new byte[size];
            byte[] viaTlv = RecursiveAI.OneCrypto.Asn1.DerWriter.OctetString(content);
            AssertStrictDer(viaTlv, $"DerWriter {size}");
            var w = new RecursiveAI.OneCrypto.Asn1.Asn1Writer(RecursiveAI.OneCrypto.Asn1.Asn1Rules.Der);
            w.PushSequence();
            w.WriteOctetString(content);
            w.Pop();
            AssertStrictDer(w.Encode(), $"Asn1Writer {size}");
        }
    }

    [Fact]
    public void ChecksTheFilesOfADirectory()
    {
        string? dir = Environment.GetEnvironmentVariable("ONECRYPTO_DER_CHECK_DIR");
        Assert.SkipWhen(string.IsNullOrEmpty(dir), "ONECRYPTO_DER_CHECK_DIR is not set");
        foreach (string file in Directory.EnumerateFiles(dir!, "*.pdf"))
        {
            AssertSignaturesAreStrictDer(File.ReadAllBytes(file), Path.GetFileName(file));
        }
    }

    private static void AssertSignaturesAreStrictDer(byte[] pdf, string label)
    {
        using PdfDocument doc = PdfDocument.Open(pdf);
        int found = 0;
        foreach (PdfSignature sig in doc.GetSignatures())
        {
            Assert.True(PdfLayout.TryRanges(sig, pdf, out long a, out long b, out _), label);
            Assert.True(PdfLayout.TryContentsBytes(pdf, a, b, out byte[] contents), label);
            // The hole is zero-filled after the signature; strip that padding, which is not part of the CMS.
            int length = 4 + System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(contents.AsSpan(2));
            Assert.True(contents[0] == 0x30 && contents[1] == 0x82, label + ": CMS header");
            AssertStrictDer(contents.AsSpan(0, length).ToArray(), $"{label} {sig.FieldName}");
            found++;
        }

        Assert.True(found > 0, label + ": no signature");
    }

    internal static void AssertStrictDer(byte[] der, string label)
    {
        try
        {
            Walk(der, 0);
        }
        catch (Exception e) when (e is AsnContentException or FormatException)
        {
            throw new Xunit.Sdk.XunitException($"{label}: not strict DER: {e.Message}");
        }
    }

    // A manual walk over tag, length and value, so each rule is checked on the bytes as written: the BCL reader in DER mode judges the leaf values.
    private static void Walk(ReadOnlyMemory<byte> data, int depth)
    {
        if (depth > 40)
        {
            return;
        }

        ReadOnlySpan<byte> span = data.Span;
        int at = 0;
        while (at < span.Length)
        {
            int start = at;
            byte tag = span[at++];
            if ((tag & 0x1F) == 0x1F)
            {
                throw new FormatException("high tag numbers are not used");
            }

            if (at >= span.Length)
            {
                throw new FormatException("truncated length");
            }

            int length = span[at++];
            if (length == 0x80)
            {
                throw new FormatException("indefinite length");
            }

            if (length > 0x80)
            {
                int n = length & 0x7F;
                if (n > 3 || at + n > span.Length || span[at] == 0)
                {
                    throw new FormatException("non-minimal or oversized length");
                }

                length = 0;
                for (int i = 0; i < n; i++)
                {
                    length = (length << 8) | span[at++];
                }

                if (length < 0x80)
                {
                    throw new FormatException("long form for a short length");
                }
            }

            if (at + length > span.Length)
            {
                throw new FormatException("length beyond the enclosing value");
            }

            ReadOnlyMemory<byte> whole = data.Slice(start, at + length - start);
            ReadOnlyMemory<byte> content = data.Slice(at, length);
            at += length;
            if ((tag & 0x20) != 0)
            {
                if (tag == 0x31)
                {
                    // A SET OF is sorted by encoding in DER; the BCL reader checks it.
                    var reader = new AsnReader(whole, AsnEncodingRules.DER);
                    _ = reader.ReadSetOf(skipSortOrderValidation: false);
                }

                Walk(content, depth + 1);
                continue;
            }

            if ((tag & 0xC0) != 0)
            {
                continue;
            }

            var leaf = new AsnReader(whole, AsnEncodingRules.DER);
            switch (tag)
            {
                case 0x02:
                    _ = leaf.ReadIntegerBytes();
                    break;
                case 0x01:
                    _ = leaf.ReadBoolean();
                    break;
                case 0x05:
                    leaf.ReadNull();
                    break;
                case 0x06:
                    _ = leaf.ReadObjectIdentifier();
                    break;
                case 0x17:
                    _ = leaf.ReadUtcTime();
                    break;
                case 0x18:
                    _ = leaf.ReadGeneralizedTime();
                    break;
                case 0x04:
                    TryNested(leaf.ReadOctetString(), depth);
                    break;
                case 0x03:
                    {
                        byte[] bits = leaf.ReadBitString(out int unused);
                        if (unused == 0)
                        {
                            TryNested(bits, depth);
                        }

                        break;
                    }

                default:
                    break;
            }
        }
    }

    // An octet string or bit string often holds DER of its own (TSTInfo, extension values, subject public keys, ECDSA signatures), but digests,
    // nonces, key identifiers and RSA signatures are random bytes that start with a tag-like octet now and then. Descend only when the bytes are,
    // as a whole, a well-formed tree of definite-length values, accepting any length form (so a genuinely non-minimal nested length is still
    // reached and reported). Random bytes pass that test with negligible probability; judging them as DER instead made this test fail about one
    // run in 25.
    private static void TryNested(byte[] bytes, int depth)
    {
        if (bytes.Length < 2 || bytes[0] is not (0x30 or 0x31 or 0x02 or 0xA0 or 0xA1 or 0xA2 or 0xA3) || !IsWellFormedValue(bytes))
        {
            return;
        }

        Walk(bytes, depth + 1);
    }

    /// <summary>True when <paramref name="bytes"/> is exactly one value, and every constructed value in it holds only complete values, in any definite length form.</summary>
    internal static bool IsWellFormedValue(ReadOnlySpan<byte> bytes) => TryReadValue(bytes, out int used, 0) && used == bytes.Length;

    private static bool TryReadValue(ReadOnlySpan<byte> s, out int used, int depth)
    {
        used = 0;
        if (s.Length < 2 || depth > 40 || (s[0] & 0x1F) == 0x1F)
        {
            return false;
        }

        int at = 1;
        long length = s[at++];
        if (length == 0x80)
        {
            return false;
        }

        if (length > 0x80)
        {
            int n = (int)(length & 0x7F);
            if (n > 4 || at + n > s.Length)
            {
                return false;
            }

            length = 0;
            for (int i = 0; i < n; i++)
            {
                length = (length << 8) | s[at++];
            }
        }

        if (at + length > s.Length)
        {
            return false;
        }

        if ((s[0] & 0x20) != 0)
        {
            ReadOnlySpan<byte> inner = s.Slice(at, (int)length);
            while (!inner.IsEmpty)
            {
                if (!TryReadValue(inner, out int m, depth + 1))
                {
                    return false;
                }

                inner = inner[m..];
            }
        }

        used = at + (int)length;
        return true;
    }
}
