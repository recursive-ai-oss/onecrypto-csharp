using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Unicode;

namespace RecursiveAI.OneCrypto.Asn1;

/// <summary>Validation and decoding of the content octets of the universal types (ITU-T X.690 clause 8 and 11).</summary>
internal static class Asn1Content
{
    /// <summary>X.690 8.3.2: the first nine bits of a multi-octet INTEGER must not all be equal.</summary>
    internal static bool IsMinimalInteger(ReadOnlySpan<byte> c) =>
        c.Length != 0 && (c.Length == 1 || !((c[0] == 0 && (c[1] & 0x80) == 0) || (c[0] == 0xFF && (c[1] & 0x80) != 0)));

    internal static bool TryInt64(ReadOnlySpan<byte> c, out long value)
    {
        value = 0;
        if (c.Length is 0 or > 8)
        {
            return false;
        }

        long v = (c[0] & 0x80) != 0 ? -1 : 0;
        foreach (byte b in c)
        {
            v = (v << 8) | b;
        }

        value = v;
        return true;
    }

    internal static bool TryUInt64(ReadOnlySpan<byte> c, out ulong value)
    {
        value = 0;
        if ((c[0] & 0x80) != 0)
        {
            return false;
        }

        if (c[0] == 0)
        {
            c = c[1..];
        }

        if (c.Length > 8)
        {
            return false;
        }

        value = Asn1Wire.ReadUInt64BigEndian(c);
        return true;
    }

    /// <summary>Public values only (lengths, versions, moduli): never secrets.</summary>
    internal static BigInteger ToBigInteger(ReadOnlySpan<byte> c) => new(c, isUnsigned: false, isBigEndian: true);

    /// <summary>X.690 8.19.2: groups of 7 bits, the last octet of each group has the high bit clear, and no group starts 0x80.</summary>
    internal static bool IsValidOid(ReadOnlySpan<byte> c)
    {
        if (c.IsEmpty || (c[^1] & 0x80) != 0)
        {
            return false;
        }

        bool start = true;
        foreach (byte b in c)
        {
            if (start && b == 0x80)
            {
                return false;
            }

            start = (b & 0x80) == 0;
        }

        return true;
    }

    /// <summary>Validates and decodes an object identifier, consulting the cache before doing either.</summary>
    internal static Asn1Error TryOidString(ReadOnlySpan<byte> c, out string? value)
    {
        if (c.Length is > 0 and <= 32)
        {
            OidEntry? e = s_oidCache[SlotOf(c)];
            if (e is not null && c.SequenceEqual(e.Key))
            {
                value = e.Value;
                return Asn1Error.None;
            }
        }

        value = null;
        if (!IsValidOid(c))
        {
            return Asn1Error.InvalidContent;
        }

        value = OidToString(c);
        return value is null ? Asn1Error.ValueOutOfRange : Asn1Error.None;
    }

    private static int SlotOf(ReadOnlySpan<byte> c) => (c.Length + (c[^1] * 7) + (c[c.Length > 1 ? ^2 : ^1] * 31) + (c[c.Length > 2 ? ^3 : ^1] * 131)) & 255;

    // Documents repeat the same few identifiers (algorithms, attribute types, extensions), so a small direct-mapped cache of the
    // dotted strings spares an allocation per read. Entries are immutable and replaced whole, which is safe across threads; the table
    // never grows, so hostile input cannot make it. Only identifiers of up to 32 content octets are cached.
    private sealed class OidEntry(byte[] key, string value)
    {
        public readonly byte[] Key = key;
        public readonly string Value = value;
    }

    private static readonly OidEntry?[] s_oidCache = new OidEntry?[256];

    /// <summary>The dotted form, or null when an arc exceeds 128 bits (enough for 2.25.&lt;UUID&gt;) or, with <paramref name="allow128Bits"/> false, 64 bits.</summary>
    internal static string? OidToString(ReadOnlySpan<byte> c, bool allow128Bits = true)
    {
        if (c.Length is 0 or > 32 || !allow128Bits)
        {
            return OidToStringUncached(c, allow128Bits);
        }

        ref OidEntry? slot = ref s_oidCache[SlotOf(c)];
        OidEntry? e = slot;
        if (e is not null && c.SequenceEqual(e.Key))
        {
            return e.Value;
        }

        string? s = OidToStringUncached(c, allow128Bits);
        if (s is not null)
        {
            slot = new OidEntry(c.ToArray(), s);
        }

        return s;
    }

    private static string? OidToStringUncached(ReadOnlySpan<byte> c, bool allow128Bits)
    {
        // Common case: short identifiers whose arcs fit 64 bits are formatted straight into a stack buffer (at most 4 characters
        // per content octet: a 7-bit group is at most three digits and a dot) so that one string is the only allocation.
        if (c.Length <= 128)
        {
            Span<char> buf = stackalloc char[(4 * c.Length) + 24]; // bound: 4 * 128 + 24 characters
            int n = 0;
            ulong a = 0;
            bool first = true;
            bool fits = true;
            foreach (byte b in c)
            {
                if ((a >> 57) != 0)
                {
                    fits = false;
                    break;
                }

                a = (a << 7) | (uint)(b & 0x7F);
                if ((b & 0x80) != 0)
                {
                    continue;
                }

                if (first)
                {
                    // X.690 8.19.4: the first two arcs share the first subidentifier, 40*X+Y with X in 0..2.
                    ulong x = a < 80 ? a / 40 : 2;
                    buf[n++] = (char)('0' + (int)x);
                    buf[n++] = '.';
                    (a - (x * 40)).TryFormat(buf[n..], out int w0, default, CultureInfo.InvariantCulture);
                    n += w0;
                    first = false;
                }
                else
                {
                    buf[n++] = '.';
                    a.TryFormat(buf[n..], out int w, default, CultureInfo.InvariantCulture);
                    n += w;
                }

                a = 0;
            }

            if (fits)
            {
                return new string(buf[..n]);
            }
        }

        return OidToStringWide(c, allow128Bits);
    }

    private static string? OidToStringWide(ReadOnlySpan<byte> c, bool allow128Bits)
    {
        var sb = new StringBuilder(c.Length * 3);
        UInt128 acc = 0;
        bool first = true;
        foreach (byte b in c)
        {
            if (acc >> 121 != 0)
            {
                return null;
            }

            acc = (acc << 7) | (uint)(b & 0x7F);
            if ((b & 0x80) != 0)
            {
                continue;
            }

            if (!allow128Bits && acc > ulong.MaxValue)
            {
                return null;
            }

            if (first)
            {
                // X.690 8.19.4: the first two arcs share the first subidentifier, 40*X+Y with X in 0..2.
                UInt128 x = acc < 80 ? acc / 40 : 2;
                sb.Append(((int)x).ToString(CultureInfo.InvariantCulture)).Append('.').Append((acc - (x * 40)).ToString(CultureInfo.InvariantCulture));
                first = false;
            }
            else
            {
                sb.Append('.').Append(acc.ToString(CultureInfo.InvariantCulture));
            }

            acc = 0;
        }

        return sb.ToString();
    }

    /// <summary>
    /// UTCTime (X.680 clause 47) and GeneralizedTime (clause 46) as X.690 clause 11.7 and 11.8 and RFC 5280 clause 4.1.2.5 use them. DER and
    /// CER need the "Z" form with seconds; BER also takes an hour/minute offset, a missing seconds field and a fraction.
    /// </summary>
    internal static Asn1Error TryParseTime(ReadOnlySpan<byte> s, bool utc, Asn1Rules rules, out DateTimeOffset value)
    {
        value = default;
        int pos = 0;
        int year;
        bool strict = rules != Asn1Rules.Ber;
        if (utc)
        {
            if (!Num(s, ref pos, 2, out year))
            {
                return Asn1Error.InvalidContent;
            }

            // RFC 5280 4.1.2.5.1: 50 and above are 19YY, below are 20YY.
            year += year >= 50 ? 1900 : 2000;
        }
        else if (!Num(s, ref pos, 4, out year))
        {
            return Asn1Error.InvalidContent;
        }

        if (!Num(s, ref pos, 2, out int month) || !Num(s, ref pos, 2, out int day) || !Num(s, ref pos, 2, out int hour) || !Num(s, ref pos, 2, out int minute))
        {
            return Asn1Error.InvalidContent;
        }

        int second = 0;
        bool hasSeconds = pos + 2 <= s.Length && (uint)(s[pos] - '0') <= 9;
        if (hasSeconds && !Num(s, ref pos, 2, out second))
        {
            return Asn1Error.InvalidContent;
        }

        long ticks = 0;
        if (!utc && hasSeconds && pos < s.Length && s[pos] is (byte)'.' or (byte)',')
        {
            pos++;
            long scale = 1_000_000;
            int digits = 0;
            bool lastZero = false;
            while (pos < s.Length && (uint)(s[pos] - '0') <= 9)
            {
                if (scale > 0)
                {
                    ticks += (s[pos] - '0') * scale;
                    scale /= 10;
                }

                lastZero = s[pos] == '0';
                digits++;
                pos++;
            }

            if (digits == 0)
            {
                return Asn1Error.InvalidContent;
            }

            if (strict && (lastZero || s[pos - digits - 1] == ','))
            {
                // X.690 11.7.3: no trailing zeros, and the decimal point is a full stop.
                return Asn1Error.NotCanonical;
            }
        }

        TimeSpan offset = TimeSpan.Zero;
        if (pos == s.Length - 1 && s[pos] == (byte)'Z')
        {
            pos++;
        }
        else if (!strict && pos + 5 == s.Length && s[pos] is (byte)'+' or (byte)'-')
        {
            bool neg = s[pos] == (byte)'-';
            pos++;
            if (!Num(s, ref pos, 2, out int oh) || !Num(s, ref pos, 2, out int om) || oh > 23 || om > 59)
            {
                return Asn1Error.InvalidContent;
            }

            offset = new TimeSpan(oh, om, 0);
            if (neg)
            {
                offset = -offset;
            }
        }
        else
        {
            return Asn1Error.InvalidContent;
        }

        if (pos != s.Length)
        {
            return Asn1Error.InvalidContent;
        }

        if (strict && !hasSeconds)
        {
            // X.690 11.7.2 / 11.8.2: the seconds are always present.
            return Asn1Error.NotCanonical;
        }

        if (year < 1 || month is < 1 or > 12 || day < 1 || day > DateTime.DaysInMonth(year, month) || hour > 23 || minute > 59 || second > 59)
        {
            return Asn1Error.InvalidContent;
        }

        DateTimeOffset local = new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero).AddTicks(ticks);
        if ((offset > TimeSpan.Zero && local - DateTimeOffset.MinValue < offset) || (offset < TimeSpan.Zero && DateTimeOffset.MaxValue - local < -offset))
        {
            return Asn1Error.InvalidContent;
        }

        value = local - offset;
        return Asn1Error.None;
    }

    private static bool Num(ReadOnlySpan<byte> s, ref int pos, int digits, out int value)
    {
        value = 0;
        if (pos + digits > s.Length)
        {
            return false;
        }

        for (int i = 0; i < digits; i++)
        {
            int d = s[pos + i] - '0';
            if ((uint)d > 9)
            {
                return false;
            }

            value = (value * 10) + d;
        }

        pos += digits;
        return true;
    }

    /// <summary>Decodes a restricted character string (X.680 clause 41), rejecting octets outside its repertoire.</summary>
    internal static bool TryDecodeString(int universalTag, ReadOnlySpan<byte> c, out string value)
    {
        value = string.Empty;
        switch (universalTag)
        {
            case Asn1Tags.Utf8String:
                if (!Utf8.IsValid(c))
                {
                    return false;
                }

                value = Encoding.UTF8.GetString(c);
                return true;
            case Asn1Tags.Ia5String:
                foreach (byte b in c)
                {
                    if (b >= 0x80)
                    {
                        return false;
                    }
                }

                value = Encoding.ASCII.GetString(c);
                return true;
            case Asn1Tags.VisibleString:
                foreach (byte b in c)
                {
                    if (b is < 0x20 or > 0x7E)
                    {
                        return false;
                    }
                }

                value = Encoding.ASCII.GetString(c);
                return true;
            case Asn1Tags.PrintableString:
                foreach (byte b in c)
                {
                    bool ok = b is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9'
                        or (byte)' ' or (byte)'\'' or (byte)'(' or (byte)')' or (byte)'+' or (byte)',' or (byte)'-' or (byte)'.' or (byte)'/' or (byte)':' or (byte)'=' or (byte)'?';
                    if (!ok)
                    {
                        return false;
                    }
                }

                value = Encoding.ASCII.GetString(c);
                return true;
            case Asn1Tags.NumericString:
                foreach (byte b in c)
                {
                    if (b is not (>= (byte)'0' and <= (byte)'9') and not (byte)' ')
                    {
                        return false;
                    }
                }

                value = Encoding.ASCII.GetString(c);
                return true;
            case Asn1Tags.T61String:
            case Asn1Tags.GeneralString:
                value = Encoding.Latin1.GetString(c);
                return true;
            case Asn1Tags.BmpString:
                {
                    if ((c.Length & 1) != 0)
                    {
                        return false;
                    }

                    for (int i = 0; i < c.Length; i += 2)
                    {
                        int u = (c[i] << 8) | c[i + 1];
                        if (u is >= 0xD800 and <= 0xDBFF)
                        {
                            if (i + 3 >= c.Length || (c[i + 2] & 0xFC) != 0xDC)
                            {
                                return false;
                            }

                            i += 2;
                        }
                        else if (u is >= 0xDC00 and <= 0xDFFF)
                        {
                            return false;
                        }
                    }

                    value = Encoding.BigEndianUnicode.GetString(c);
                    return true;
                }

            case Asn1Tags.UniversalString:
                {
                    if ((c.Length & 3) != 0)
                    {
                        return false;
                    }

                    var sb = new StringBuilder(c.Length / 4);
                    for (int i = 0; i < c.Length; i += 4)
                    {
                        uint cp = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(c[i..]);
                        if (cp > int.MaxValue || !Rune.TryCreate((int)cp, out Rune r))
                        {
                            return false;
                        }

                        sb.Append(r.ToString());
                    }

                    value = sb.ToString();
                    return true;
                }

            default:
                return false;
        }
    }
}
