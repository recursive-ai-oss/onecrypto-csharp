using System.Text;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Pem;

namespace OneCrypto.Fuzz;

/// <summary>
/// ASN.1 reading surface. The first byte picks the rules (BER, CER, DER) and the way in: the span reader walking every type, the
/// element model, the stream reader (with and without the constructed OCTET STRING stream), or BER-to-DER conversion. Only
/// <see cref="Asn1ParseException"/> may come out of the throwing calls; the Try calls must not throw at all.
/// </summary>
internal static class Asn1Target
{
    private static readonly Asn1Limits Small = new() { MaxDepth = 24, MaxScanElements = 4096, MaxCopiedLength = 1 << 20 };

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        var rules = (Asn1Rules)(data[0] % 3);
        byte[] rest = data[1..].ToArray();
        switch ((data[0] >> 2) % 4)
        {
            case 0:
                Walk(rest, rules);
                break;
            case 1:
                if (Asn1Element.TryRead(rest, rules, Small, out Asn1Element e, out _, out _))
                {
                    var kids = new List<Asn1Element>();
                    _ = Asn1Element.TryChildren(e, 64, kids, out _);
                    _ = Asn1Values.TryOid(e);
                    _ = Asn1Values.TryTime(e, out _);
                    _ = Asn1Values.TrySmallInt(e);
                    _ = Asn1Values.TryOctetString(e, 1 << 16, out _);
                }

                break;
            case 2:
                Stream(rest, rules);
                break;
            default:
                _ = BerToDer.TryConvert(rest, out _);
                break;
        }
    }

    private static void Walk(byte[] data, Asn1Rules rules)
    {
        var r = new Asn1Reader(data, rules, Small);
        try
        {
            WalkReader(ref r);
        }
        catch (Asn1ParseException)
        {
        }
    }

    private static void WalkReader(ref Asn1Reader r)
    {
        while (r.HasData)
        {
            Asn1Tag tag = r.PeekTag();
            if (tag.TagClass == Asn1TagClass.Universal)
            {
                switch (tag.TagNumber)
                {
                    case 1: _ = r.ReadBoolean(); continue;
                    case 2: _ = r.ReadInteger(); continue;
                    case 3: _ = r.ReadBitStringBytes(out _); continue;
                    case 4: _ = r.ReadOctetStringBytes(); continue;
                    case 5: r.ReadNull(); continue;
                    case 6: _ = r.ReadObjectIdentifier(); continue;
                    case 10: _ = r.ReadEnumerated(); continue;
                    case 23: _ = r.ReadUtcTime(); continue;
                    case 24: _ = r.ReadGeneralizedTime(); continue;
                    case 16:
                        {
                            Asn1Reader c = r.ReadSequence();
                            WalkReader(ref c);
                            continue;
                        }

                    case 17:
                        {
                            Asn1Reader c = r.ReadSetOf();
                            WalkReader(ref c);
                            continue;
                        }

                    case 12 or 18 or 19 or 20 or 22 or 26 or 27 or 28 or 30:
                        _ = r.ReadCharacterString(tag.TagNumber);
                        continue;
                }

                _ = r.ReadEncodedValue();
                continue;
            }

            if (tag.IsConstructed)
            {
                Asn1Reader c = r.ReadSequence(tag);
                WalkReader(ref c);
            }
            else
            {
                _ = r.ReadEncodedValue();
            }
        }
    }

    private static void Stream(byte[] data, Asn1Rules rules)
    {
        var reader = new Asn1StreamReader(new MemoryStream(data), rules, Small);
        try
        {
            int guard = 0;
            while (guard++ < 10000 && reader.TryReadToken(out Asn1Token t))
            {
                if (t.Kind == Asn1TokenKind.Primitive && t.Length <= 4096)
                {
                    _ = reader.TryReadContent(out _);
                }
                else if (t.Kind == Asn1TokenKind.StartConstructed && t.Tag == new Asn1Tag(Asn1Tags.OctetString))
                {
                    using Stream s = reader.OpenOctetString(t);
                    var buf = new byte[512];
                    while (s.Read(buf, 0, buf.Length) > 0)
                    {
                    }
                }
            }
        }
        catch (Asn1ParseException)
        {
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        foreach (byte mode in new byte[] { 2, 6, 10, 14, 0, 4 })
        {
            yield return [mode, .. DerWriter.Sequence(DerWriter.SignedInteger(5), DerWriter.Oid("1.2.840.113549.1.7.2"), DerWriter.Boolean(true), DerWriter.Null(), DerWriter.OctetString([1, 2, 3]), DerWriter.UtcTime(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero)), DerWriter.Utf8String("x"), DerWriter.SetOf([DerWriter.OctetString([2]), DerWriter.OctetString([1])]))];
            yield return [mode, 0x30, 0x80, 0x24, 0x80, 0x04, 0x02, 0xAA, 0xBB, 0x04, 0x01, 0xCC, 0, 0, 0x02, 0x01, 0x07, 0, 0];
            yield return [mode, 0x23, 0x08, 0x03, 0x02, 0x00, 0xFF, 0x03, 0x02, 0x04, 0xF0];
            yield return [mode, 0x1F, 0x81, 0x00, 0x01, 0x05, 0x18, 0x0F, .. Encoding.ASCII.GetBytes("20260102030405Z")];
        }
    }
}

/// <summary>PEM surface: strict and lax parsing of arbitrary bytes; whatever parses must write and parse back to the same data.</summary>
internal static class PemTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return;
        }

        PemMode mode = (data[0] & 1) == 0 ? PemMode.Strict : PemMode.Lax;
        ReadOnlySpan<byte> text = data[1..];
        if (PemCodec.TryParseAll(text, mode, out IReadOnlyList<PemBlock> blocks, out _))
        {
            foreach (PemBlock b in blocks)
            {
                string again = PemCodec.Write(b.Label, b.Data, b.Headers);
                PemBlock back = PemCodec.Parse(again, PemMode.Lax);
                if (!back.Data.AsSpan().SequenceEqual(b.Data) || back.Label != b.Label)
                {
                    throw new InvalidOperationException("PEM did not round-trip");
                }
            }
        }

        _ = PemCodec.TryParse(text, mode, out _, out _);
    }

    public static IEnumerable<byte[]> Seeds()
    {
        yield return [0, .. Encoding.ASCII.GetBytes(PemCodec.Write("CERTIFICATE", new byte[100]))];
        yield return [1, .. Encoding.ASCII.GetBytes("text\r\n-----BEGIN RSA PRIVATE KEY-----\r\nProc-Type: 4,ENCRYPTED\r\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\r\n\r\nAQID BAUG\r\n-----END RSA PRIVATE KEY-----")];
        yield return [1, .. Encoding.ASCII.GetBytes("-----BEGIN A-----\n-----END A-----\n-----BEGIN B-----\nAA==\n-----END B-----")];
    }
}
