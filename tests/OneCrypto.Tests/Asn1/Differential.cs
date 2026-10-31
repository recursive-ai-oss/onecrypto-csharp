using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Text;
using RecursiveAI.OneCrypto.Asn1;
using OurTag = RecursiveAI.OneCrypto.Asn1.Asn1Tag;
using TheirTag = System.Formats.Asn1.Asn1Tag;

namespace OneCrypto.Tests.Asn1;

/// <summary>
/// Walks an encoding with this library's reader and with System.Formats.Asn1's AsnReader (the oracle) and records what each decodes,
/// element by element, as lines of text. The two transcripts must agree on accept/reject and, when both accept, on every value.
/// </summary>
internal static class Differential
{
    internal const string Reject = "REJECT";

    // Universal types decoded by both sides. T61String, GeneralString and UniversalString are left as raw elements: the oracle cannot decode them.
    private static readonly int[] StringTags = [12, 18, 19, 22, 26, 30];

    internal static List<string> Ours(byte[] data, Asn1Rules rules)
    {
        var t = new List<string>();
        var r = new Asn1Reader(data, rules);
        try
        {
            OursWalk(ref r, t, 0);
        }
        catch (Asn1ParseException)
        {
            t.Add(Reject);
        }

        return t;
    }

    private static void OursWalk(ref Asn1Reader r, List<string> t, int depth)
    {
        while (r.HasData)
        {
            OurTag tag = r.PeekTag();
            if (tag.TagClass == Asn1TagClass.Universal)
            {
                switch (tag.TagNumber)
                {
                    case 1: t.Add("BOOL " + r.ReadBoolean()); continue;
                    case 2: t.Add("INT " + r.ReadInteger()); continue;
                    case 3:
                        {
                            byte[] b = r.ReadBitStringBytes(out int u);
                            // The oracle clears the unused bits; this library returns the octets as received.
                            if (b.Length > 0 && u > 0)
                            {
                                b[^1] &= (byte)(0xFF << u);
                            }

                            t.Add($"BITS {u} {Convert.ToHexString(b)}");
                            continue;
                        }
                    case 4: t.Add("OCT " + Convert.ToHexString(r.ReadOctetStringBytes())); continue;
                    case 5: r.ReadNull(); t.Add("NULL"); continue;
                    case 6:
                        {
                            string oid = r.ReadObjectIdentifier();
                            // Documented difference: the oracle refuses object identifiers whose dotted form is longer than 127 characters.
                            if (oid.Length > 127)
                            {
                                throw new Asn1ParseException(Asn1Error.ValueOutOfRange, 0);
                            }

                            t.Add("OID " + oid);
                            continue;
                        }
                    case 10: t.Add("ENUM " + Convert.ToHexString(r.ReadIntegerBytes(new OurTag(10)))); continue;
                    case 23: t.Add("UTC " + r.ReadUtcTime().UtcTicks); continue;
                    case 24: t.Add("GEN " + r.ReadGeneralizedTime().UtcTicks); continue;
                    case 16:
                        {
                            Asn1Reader c = r.ReadSequence();
                            t.Add("SEQ(");
                            OursWalk(ref c, t, depth + 1);
                            t.Add(")");
                            continue;
                        }

                    case 17:
                        {
                            Asn1Reader c = r.ReadSetOf();
                            t.Add("SET(");
                            OursWalk(ref c, t, depth + 1);
                            t.Add(")");
                            continue;
                        }
                }

                if (Array.IndexOf(StringTags, tag.TagNumber) >= 0)
                {
                    t.Add($"STR{tag.TagNumber} " + r.ReadCharacterString(tag.TagNumber));
                    continue;
                }

                t.Add("RAW " + Convert.ToHexString(r.ReadEncodedValue()));
                continue;
            }

            if (tag.IsConstructed)
            {
                Asn1Reader c = r.ReadSequence(tag);
                t.Add($"CTX{(int)tag.TagClass}.{tag.TagNumber}(");
                OursWalk(ref c, t, depth + 1);
                t.Add(")");
            }
            else
            {
                t.Add("RAW " + Convert.ToHexString(r.ReadEncodedValue()));
            }
        }
    }

    internal static List<string> Oracle(byte[] data, AsnEncodingRules rules)
    {
        var t = new List<string>();
        try
        {
            OracleWalk(new AsnReader(data, rules), t);
        }
        catch (Exception e) when (e is AsnContentException or ArgumentException or InvalidOperationException or OverflowException)
        {
            t.Add(Reject);
        }

        return t;
    }

    private static void OracleWalk(AsnReader r, List<string> t)
    {
        while (r.HasData)
        {
            TheirTag tag = r.PeekTag();
            if (tag.TagClass == TagClass.Universal && tag.TagValue == 0)
            {
                // Documented difference: the oracle reads a universal tag 0 element; X.690 8.1.5 reserves it for end-of-contents.
                throw new ArgumentException("universal tag 0");
            }

            if (tag.TagClass == TagClass.Universal)
            {
                switch ((UniversalTagNumber)tag.TagValue)
                {
                    case UniversalTagNumber.Boolean: t.Add("BOOL " + r.ReadBoolean()); continue;
                    case UniversalTagNumber.Integer: t.Add("INT " + r.ReadInteger()); continue;
                    case UniversalTagNumber.BitString: { byte[] b = r.ReadBitString(out int u); t.Add($"BITS {u} {Convert.ToHexString(b)}"); continue; }
                    case UniversalTagNumber.OctetString: t.Add("OCT " + Convert.ToHexString(r.ReadOctetString())); continue;
                    case UniversalTagNumber.Null: r.ReadNull(); t.Add("NULL"); continue;
                    case UniversalTagNumber.ObjectIdentifier: t.Add("OID " + r.ReadObjectIdentifier()); continue;
                    case UniversalTagNumber.Enumerated: t.Add("ENUM " + Convert.ToHexString(r.ReadEnumeratedBytes().Span)); continue;
                    case UniversalTagNumber.UtcTime: t.Add("UTC " + r.ReadUtcTime().UtcTicks); continue;
                    case UniversalTagNumber.GeneralizedTime: t.Add("GEN " + r.ReadGeneralizedTime().UtcTicks); continue;
                    case UniversalTagNumber.Sequence:
                        {
                            AsnReader c = r.ReadSequence();
                            t.Add("SEQ(");
                            OracleWalk(c, t);
                            t.Add(")");
                            continue;
                        }

                    case UniversalTagNumber.Set:
                        {
                            AsnReader c = r.ReadSetOf();
                            t.Add("SET(");
                            OracleWalk(c, t);
                            t.Add(")");
                            continue;
                        }
                }

                if (Array.IndexOf(StringTags, tag.TagValue) >= 0)
                {
                    t.Add($"STR{tag.TagValue} " + r.ReadCharacterString((UniversalTagNumber)tag.TagValue));
                    continue;
                }

                t.Add("RAW " + Convert.ToHexString(r.ReadEncodedValue().Span));
                continue;
            }

            if (tag.IsConstructed)
            {
                AsnReader c = r.ReadSequence(tag);
                t.Add($"CTX{(int)tag.TagClass >> 6}.{tag.TagValue}(");
                OracleWalk(c, t);
                t.Add(")");
            }
            else
            {
                t.Add("RAW " + Convert.ToHexString(r.ReadEncodedValue().Span));
            }
        }
    }

    /// <summary>One comparison: same decision, and the same values when both accept.</summary>
    internal static (bool Same, bool OursAccepts, bool OracleAccepts) Compare(byte[] data, bool der)
    {
        List<string> a = Ours(data, der ? Asn1Rules.Der : Asn1Rules.Ber);
        List<string> b = Oracle(data, der ? AsnEncodingRules.DER : AsnEncodingRules.BER);
        bool ra = a.Count > 0 && a[^1] == Reject;
        bool rb = b.Count > 0 && b[^1] == Reject;
        bool same = ra == rb && (ra || LinesEqual(a, b));
        return (same, !ra, !rb);
    }

    // The oracle computes a GeneralizedTime fraction in floating point and can be one tick (100 ns) off the exact decimal value.
    private static bool LinesEqual(List<string> a, List<string> b)
    {
        if (a.Count != b.Count)
        {
            return false;
        }

        for (int i = 0; i < a.Count; i++)
        {
            if (a[i] == b[i])
            {
                continue;
            }

            if (a[i].StartsWith("GEN ", StringComparison.Ordinal) && b[i].StartsWith("GEN ", StringComparison.Ordinal)
                && Math.Abs(long.Parse(a[i].AsSpan(4), CultureInfo.InvariantCulture) - long.Parse(b[i].AsSpan(4), CultureInfo.InvariantCulture)) <= 1)
            {
                continue;
            }

            return false;
        }

        return true;
    }
}

/// <summary>A random tree of valid ASN.1 values, serialised as DER or as a deliberately varied BER.</summary>
internal sealed class Node
{
    public int Class;
    public int Number;
    public bool Constructed;
    public byte[] Content = [];
    public List<Node> Kids = [];
    public bool SetOf;
    public bool IsString;

    public static Node Random(Random rng, int depth)
    {
        int k = rng.Next(depth >= 4 ? 18 : 22);
        var n = new Node();
        switch (k)
        {
            case 0: n.Number = 1; n.Content = [rng.Next(2) == 0 ? (byte)0 : (byte)0xFF]; break;
            case 1:
            case 2:
                {
                    n.Number = 2;
                    var b = new byte[rng.Next(1, 12)];
                    rng.NextBytes(b);
                    n.Content = Minimal(b);
                    break;
                }

            case 3:
                {
                    n.Number = 3;
                    var b = new byte[rng.Next(0, 20)];
                    rng.NextBytes(b);
                    int unused = b.Length == 0 ? 0 : rng.Next(8);
                    if (b.Length > 0)
                    {
                        b[^1] &= (byte)(0xFF << unused);
                    }

                    n.Content = [(byte)unused, .. b];
                    break;
                }

            case 4: { n.Number = 4; n.Content = new byte[rng.Next(0, rng.Next(8) == 0 ? 300 : 30)]; rng.NextBytes(n.Content); n.IsString = true; break; }
            case 5: n.Number = 5; break;
            case 6:
                {
                    n.Number = 6;
                    var w = new AsnWriter(AsnEncodingRules.DER);
                    var arcs = new List<string> { rng.Next(3).ToString(CultureInfo.InvariantCulture), rng.Next(40).ToString(CultureInfo.InvariantCulture) };
                    for (int i = rng.Next(0, 5); i > 0; i--)
                    {
                        arcs.Add(rng.NextInt64(0, rng.Next(2) == 0 ? 200 : long.MaxValue).ToString(CultureInfo.InvariantCulture));
                    }

                    w.WriteObjectIdentifier(string.Join('.', arcs));
                    n.Content = w.Encode().AsSpan(2).ToArray();
                    if (w.Encode()[1] >= 0x80)
                    {
                        n.Content = w.Encode().AsSpan(2 + (w.Encode()[1] & 0x7F)).ToArray();
                    }

                    break;
                }

            case 7: { n.Number = 10; n.Content = Minimal([(byte)rng.Next(256), (byte)rng.Next(256)]); break; }
            case 8: { n.Number = 12; n.Content = Encoding.UTF8.GetBytes(Text(rng, "aé€z0 ")); n.IsString = true; break; }
            case 9: { n.Number = 19; n.Content = Encoding.ASCII.GetBytes(Text(rng, "AZaz09 '()+,-./:=?")); n.IsString = true; break; }
            case 10: { n.Number = 22; n.Content = Encoding.ASCII.GetBytes(Text(rng, "AZaz09@~!")); n.IsString = true; break; }
            case 11: { n.Number = 30; n.Content = Encoding.BigEndianUnicode.GetBytes(Text(rng, "aé€z")); n.IsString = true; break; }
            case 12:
                {
                    n.Number = 23;
                    var t = new DateTime(rng.Next(1950, 2050), rng.Next(1, 13), rng.Next(1, 28), rng.Next(24), rng.Next(60), rng.Next(60), DateTimeKind.Utc);
                    n.Content = Encoding.ASCII.GetBytes(t.ToString("yyMMddHHmmss'Z'", CultureInfo.InvariantCulture));
                    break;
                }

            case 13:
                {
                    n.Number = 24;
                    var t = new DateTime(rng.Next(1, 9999), rng.Next(1, 13), rng.Next(1, 28), rng.Next(24), rng.Next(60), rng.Next(60), DateTimeKind.Utc);
                    string frac = rng.Next(3) == 0 ? "." + rng.Next(1, 1000).ToString("D3", CultureInfo.InvariantCulture).TrimEnd('0') : string.Empty;
                    n.Content = Encoding.ASCII.GetBytes(t.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + frac + "Z");
                    break;
                }

            case 14: { n.Class = 2; n.Number = rng.Next(0, 40); n.Content = new byte[rng.Next(0, 10)]; rng.NextBytes(n.Content); break; }
            case 15: { n.Class = rng.Next(1, 4); n.Number = rng.Next(0, 3000); n.Content = new byte[rng.Next(0, 10)]; rng.NextBytes(n.Content); break; }
            case 16: { n.Number = 28; n.Content = [0, 0, 0, 65, 0, 1, 0x20, 0xAC]; n.IsString = true; break; }
            case 17: { n.Number = 18; n.Content = Encoding.ASCII.GetBytes(Text(rng, "0123 456789")); n.IsString = true; break; }
            default:
                {
                    n.Constructed = true;
                    int kind = rng.Next(4);
                    n.Number = kind == 1 ? 17 : 16;
                    n.SetOf = kind == 1;
                    if (kind == 2) { n.Class = 2; n.Number = rng.Next(0, 40); }
                    if (kind == 3) { n.Class = rng.Next(1, 4); n.Number = rng.Next(0, 300); }
                    for (int i = rng.Next(0, 5); i > 0; i--)
                    {
                        n.Kids.Add(Random(rng, depth + 1));
                    }

                    break;
                }
        }

        return n;
    }

    private static string Text(Random rng, string alphabet)
    {
        var sb = new StringBuilder();
        for (int i = rng.Next(0, 12); i > 0; i--)
        {
            sb.Append(alphabet[rng.Next(alphabet.Length)]);
        }

        return sb.ToString();
    }

    private static byte[] Minimal(byte[] b)
    {
        int i = 0;
        while (i < b.Length - 1 && ((b[i] == 0 && (b[i + 1] & 0x80) == 0) || (b[i] == 0xFF && (b[i + 1] & 0x80) != 0)))
        {
            i++;
        }

        return b[i..];
    }

    private static void Id(List<byte> o, Node n, bool constructed)
    {
        int first = (n.Class << 6) | (constructed ? 0x20 : 0);
        if (n.Number < 31)
        {
            o.Add((byte)(first | n.Number));
            return;
        }

        o.Add((byte)(first | 0x1F));
        var g = new Stack<byte>();
        for (int v = n.Number; v != 0; v >>= 7)
        {
            g.Push((byte)(v & 0x7F));
        }

        byte[] arr = g.ToArray();
        for (int i = 0; i < arr.Length; i++)
        {
            o.Add((byte)(arr[i] | (i < arr.Length - 1 ? 0x80 : 0)));
        }
    }

    private static void Len(List<byte> o, int len, Random? rng, int variety)
    {
        if (rng is not null && rng.Next(100) < variety)
        {
            int count = rng.Next(1, 4);
            while (count < 4 && len >> (8 * count) != 0)
            {
                count++;
            }

            o.Add((byte)(0x80 | count));
            for (int i = count - 1; i >= 0; i--)
            {
                o.Add((byte)(len >> (8 * i)));
            }

            return;
        }

        if (len < 0x80)
        {
            o.Add((byte)len);
        }
        else
        {
            int c = len <= 0xFF ? 1 : len <= 0xFFFF ? 2 : len <= 0xFFFFFF ? 3 : 4;
            o.Add((byte)(0x80 | c));
            for (int i = c - 1; i >= 0; i--)
            {
                o.Add((byte)(len >> (8 * i)));
            }
        }
    }

    /// <summary>DER when <paramref name="rng"/> is null; otherwise BER with the given percentage of non-minimal lengths, indefinite constructed elements and split strings.</summary>
    public byte[] Serialize(Random? rng = null, int variety = 0)
    {
        var o = new List<byte>();
        Write(o, rng, variety);
        return o.ToArray();
    }

    private void Write(List<byte> o, Random? rng, int variety)
    {
        if (Constructed)
        {
            var body = new List<byte>();
            List<Node> kids = Kids;
            var parts = new List<byte[]>();
            foreach (Node k in kids)
            {
                parts.Add(k.Serialize(rng, variety));
            }

            if (SetOf && rng is null)
            {
                parts.Sort(static (a, b) => Pad(a, b));
            }

            foreach (byte[] p in parts)
            {
                body.AddRange(p);
            }

            Id(o, this, true);
            if (rng is not null && rng.Next(100) < variety)
            {
                o.Add(0x80);
                o.AddRange(body);
                o.AddRange([0, 0]);
            }
            else
            {
                Len(o, body.Count, rng, variety);
                o.AddRange(body);
            }

            return;
        }

        if (rng is not null && IsString && Class == 0 && Number is 4 && Content.Length > 1 && rng.Next(100) < variety)
        {
            // Constructed OCTET STRING in two segments.
            int cut = rng.Next(0, Content.Length + 1);
            var seg = new List<byte>();
            foreach (byte[] part in new[] { Content[..cut], Content[cut..] })
            {
                seg.Add(0x04);
                Len(seg, part.Length, null, 0);
                seg.AddRange(part);
            }

            o.Add(0x24);
            if (rng.Next(2) == 0)
            {
                o.Add(0x80);
                o.AddRange(seg);
                o.AddRange([0, 0]);
            }
            else
            {
                Len(o, seg.Count, rng, variety);
                o.AddRange(seg);
            }

            return;
        }

        Id(o, this, false);
        Len(o, Content.Length, rng, variety);
        o.AddRange(Content);
    }

    private static int Pad(byte[] a, byte[] b)
    {
        int n = Math.Min(a.Length, b.Length);
        int c = a.AsSpan(0, n).SequenceCompareTo(b.AsSpan(0, n));
        if (c != 0)
        {
            return c;
        }

        for (int i = n; i < Math.Max(a.Length, b.Length); i++)
        {
            byte x = i < a.Length ? a[i] : (byte)0, y = i < b.Length ? b[i] : (byte)0;
            if (x != y)
            {
                return x.CompareTo(y);
            }
        }

        return 0;
    }

    public static byte[] Mutate(byte[] src, Random rng)
    {
        var l = new List<byte>(src);
        int ops = rng.Next(1, 4);
        for (int i = 0; i < ops && l.Count > 0; i++)
        {
            int at = rng.Next(l.Count);
            switch (rng.Next(8))
            {
                case 0: l[at] ^= (byte)(1 << rng.Next(8)); break;
                case 1: l[at] = (byte)rng.Next(256); break;
                case 2: l.RemoveRange(at, Math.Min(l.Count - at, rng.Next(1, 4))); break;
                case 3: l.Insert(at, (byte)rng.Next(256)); break;
                case 4: l.RemoveRange(at, l.Count - at); break;
                case 5: l[at] = new byte[] { 0, 0x80, 0x81, 0x7F, 0xFF, 0x1F, 0x30, 0x04 }[rng.Next(8)]; break;
                case 6: l.InsertRange(at, [0x80, 0x00, 0x00]); break;
                default: l.AddRange(l.GetRange(at, Math.Min(l.Count - at, 6))); break;
            }
        }

        return l.ToArray();
    }
}
