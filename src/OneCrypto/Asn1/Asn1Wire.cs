using System.Buffers.Binary;

namespace RecursiveAI.OneCrypto.Asn1;

/// <summary>
/// The identifier and length octets of one element (ITU-T X.690 clauses 8.1.2 and 8.1.3), parsed once for every reader in this
/// namespace so that the span, memory and stream readers apply the same rules.
/// </summary>
internal static class Asn1Wire
{
    /// <summary>Most identifier octets accepted: a tag number is at most 31 bits, which takes five 7-bit groups.</summary>
    private const int MaxTagOctets = 6;

    /// <summary>The longest header this parser consumes: six identifier octets and the long-form length octets.</summary>
    internal const int MaxHeaderLength = MaxTagOctets + 9;

    /// <summary>
    /// Parses the header at the start of <paramref name="s"/>. <paramref name="length"/> is -1 for the indefinite form. On
    /// <see cref="Asn1Error.Truncated"/> more input might complete the header.
    /// </summary>
    internal static Asn1Error ParseHeader(ReadOnlySpan<byte> s, Asn1Rules rules, out Asn1Tag tag, out int headerLength, out long length)
    {
        tag = default;
        headerLength = 0;
        length = 0;
        if (s.IsEmpty)
        {
            return Asn1Error.Truncated;
        }

        byte b0 = s[0];
        if ((b0 & 0x1F) != 0x1F && s.Length >= 2 && s[1] < 0x80)
        {
            // Fast path for what nearly every element looks like: a one-octet identifier and a one-octet length.
            if (rules == Asn1Rules.Cer && (b0 & 0x20) != 0)
            {
                return Asn1Error.LengthFormNotAllowed;
            }

            tag = new Asn1Tag((Asn1TagClass)(b0 >> 6), b0 & 0x1F, (b0 & 0x20) != 0, true);
            headerLength = 2;
            length = s[1];
            return Asn1Error.None;
        }

        var cls = (Asn1TagClass)(b0 >> 6);
        bool constructed = (b0 & 0x20) != 0;
        int number = b0 & 0x1F;
        int pos = 1;
        if (number == 0x1F)
        {
            // X.690 8.1.2.4: the number follows in base-128 groups, high bit set on all but the last.
            long acc = 0;
            int groups = 0;
            while (true)
            {
                if (pos >= s.Length)
                {
                    return Asn1Error.Truncated;
                }

                byte t = s[pos++];
                if (groups == 0 && t == 0x80)
                {
                    // 8.1.2.4.2(c): the first group shall not be all zero bits.
                    return Asn1Error.NonMinimalTag;
                }

                acc = (acc << 7) | (uint)(t & 0x7F);
                groups++;
                if (acc > int.MaxValue || groups > MaxTagOctets - 1)
                {
                    return Asn1Error.InvalidTag;
                }

                if ((t & 0x80) == 0)
                {
                    break;
                }
            }

            if (acc < 31)
            {
                // 8.1.2.2: numbers below 31 use the single-octet form.
                return Asn1Error.NonMinimalTag;
            }

            number = (int)acc;
        }

        tag = new Asn1Tag(cls, number, constructed, true);
        if (pos >= s.Length)
        {
            return Asn1Error.Truncated;
        }

        byte l0 = s[pos++];
        if (l0 < 0x80)
        {
            length = l0;
        }
        else if (l0 == 0x80)
        {
            // 8.1.3.6: indefinite, constructed only. DER forbids it (10.1); CER requires it for constructed (9.1).
            if (!constructed)
            {
                return Asn1Error.InvalidLength;
            }

            if (rules == Asn1Rules.Der)
            {
                return Asn1Error.LengthFormNotAllowed;
            }

            length = -1;
        }
        else if (l0 == 0xFF)
        {
            // 8.1.3.5(c): reserved for future extension.
            return Asn1Error.InvalidLength;
        }
        else
        {
            int count = l0 & 0x7F;
            if (count > 8)
            {
                return Asn1Error.LengthExceedsData;
            }

            if (pos + count > s.Length)
            {
                return Asn1Error.Truncated;
            }

            ulong v = 0;
            for (int i = 0; i < count; i++)
            {
                v = (v << 8) | s[pos + i];
            }

            if (rules != Asn1Rules.Ber && (count > 1 ? s[pos] == 0 : v < 0x80))
            {
                // 10.1: the length is encoded in the fewest octets possible.
                return Asn1Error.NonMinimalLength;
            }

            pos += count;
            if (v > long.MaxValue)
            {
                return Asn1Error.LengthExceedsData;
            }

            length = (long)v;
        }

        if (rules == Asn1Rules.Cer && constructed && length >= 0)
        {
            return Asn1Error.LengthFormNotAllowed;
        }

        headerLength = pos;
        return Asn1Error.None;
    }

    /// <summary>
    /// Finds the end of an indefinite-length element whose content starts at <paramref name="start"/>. A counter of open indefinite
    /// elements stands in for recursion and definite-length children are skipped whole, so the work is linear in the input.
    /// </summary>
    internal static Asn1Failure FindEndOfContents(ReadOnlySpan<byte> s, int start, int baseOffset, int depth, Asn1Rules rules, Asn1Limits limits, out int contentLength)
    {
        contentLength = 0;
        int open = 1;
        int pos = start;
        int elements = 0;
        while (open > 0)
        {
            if (++elements > limits.MaxScanElements)
            {
                return new Asn1Failure(Asn1Error.TooManyElements, baseOffset + pos);
            }

            if (pos + 2 <= s.Length && s[pos] == 0 && s[pos + 1] == 0)
            {
                open--;
                pos += 2;
                if (open == 0)
                {
                    contentLength = pos - 2 - start;
                }

                continue;
            }

            Asn1Error e = ParseHeader(s[pos..], rules, out Asn1Tag tag, out int hl, out long len);
            if (e != Asn1Error.None)
            {
                return new Asn1Failure(e, baseOffset + pos);
            }

            if (tag.TagClass == Asn1TagClass.Universal && tag.TagNumber == 0)
            {
                return new Asn1Failure(Asn1Error.InvalidTag, baseOffset + pos);
            }

            if (len < 0)
            {
                if (depth + open + 1 > limits.MaxDepth)
                {
                    return new Asn1Failure(Asn1Error.DepthExceeded, baseOffset + pos);
                }

                open++;
                pos += hl;
            }
            else
            {
                if (len > s.Length - pos - hl)
                {
                    return new Asn1Failure(Asn1Error.LengthExceedsData, baseOffset + pos);
                }

                pos += hl + (int)len;
            }
        }

        return default;
    }

    /// <summary>Compares two encodings the way DER orders SET OF members: as octet strings, the shorter padded with zeros (X.690 11.6).</summary>
    internal static int CompareSetOfMembers(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        int n = Math.Min(a.Length, b.Length);
        int c = a[..n].SequenceCompareTo(b[..n]);
        if (c != 0)
        {
            return c;
        }

        ReadOnlySpan<byte> longer = a.Length > b.Length ? a[n..] : b[n..];
        foreach (byte x in longer)
        {
            if (x != 0)
            {
                return a.Length > b.Length ? 1 : -1;
            }
        }

        return 0;
    }

    /// <summary>Writes a definite length in the shortest form and returns the octets used (1 to 5).</summary>
    internal static int EncodeLength(int length, Span<byte> destination)
    {
        if (length < 0x80)
        {
            destination[0] = (byte)length;
            return 1;
        }

        int count = length <= 0xFF ? 1 : length <= 0xFFFF ? 2 : length <= 0xFFFFFF ? 3 : 4;
        destination[0] = (byte)(0x80 | count);
        for (int i = 0; i < count; i++)
        {
            destination[1 + i] = (byte)(length >> (8 * (count - 1 - i)));
        }

        return 1 + count;
    }

    internal static int LengthOfLength(int length) => length < 0x80 ? 1 : length <= 0xFF ? 2 : length <= 0xFFFF ? 3 : length <= 0xFFFFFF ? 4 : 5;

    /// <summary>Reads a big-endian value of up to 8 octets.</summary>
    internal static ulong ReadUInt64BigEndian(ReadOnlySpan<byte> s)
    {
        Span<byte> tmp = stackalloc byte[8]; // fixed 8-byte buffer
        tmp.Clear();
        s.CopyTo(tmp[(8 - s.Length)..]);
        return BinaryPrimitives.ReadUInt64BigEndian(tmp);
    }
}
