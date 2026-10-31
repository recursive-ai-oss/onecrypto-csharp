using System.Linq;
using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto.X509;

/// <summary>Shared reading and writing steps for the typed extension values.</summary>
internal static class ExtensionHelpers
{
    internal delegate T ReadValue<T>(ReadOnlyMemory<byte> value, X509Limits limits);

    /// <summary>Runs <paramref name="read"/> and reports ASN.1 failures as a typed parse error for <paramref name="what"/>.</summary>
    public static T Run<T>(string what, ReadOnlyMemory<byte> value, ReadValue<T> read)
    {
        try
        {
            return read(value, X509Limits.Default);
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException(what, e);
        }
    }

    /// <summary>Opens <c>SEQUENCE { ... }</c> that must fill <paramref name="value"/>, returning a reader over the body.</summary>
    public static Asn1Reader OpenSequence(ReadOnlyMemory<byte> value, X509Limits limits, Asn1Tag? tag = null)
    {
        var outer = new Asn1Reader(value.Span, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader seq = outer.ReadSequence(tag);
        outer.ThrowIfNotEmpty();
        return seq;
    }

    /// <summary>Reads named bits (a BIT STRING that lists the set bits): bit 0 is the most significant bit of the first octet. Bits past 15 are ignored.</summary>
    public static int ReadFlags(ref Asn1Reader r, Asn1Tag? tag = null)
    {
        ReadOnlySpan<byte> bits = r.ReadBitString(out _, tag);
        int flags = 0;
        for (int i = 0; i < 16 && i / 8 < bits.Length; i++)
        {
            if ((bits[i / 8] & (0x80 >> (i % 8))) != 0)
            {
                flags |= 1 << i;
            }
        }

        return flags;
    }

    /// <summary>Encodes named bits in DER form (trailing zero bits removed, RFC 5280 §4.2.1.3 and X.690 11.2.2).</summary>
    public static byte[] WriteFlags(int flags, byte tag = 0x03)
    {
        int top = -1;
        for (int i = 0; i < 16; i++)
        {
            if ((flags & (1 << i)) != 0)
            {
                top = i;
            }
        }

        if (top < 0)
        {
            return [tag, 1, 0];
        }

        int n = (top / 8) + 1;
        var b = new byte[n + 1];
        b[0] = (byte)((n * 8) - top - 1);
        for (int i = 0; i <= top; i++)
        {
            if ((flags & (1 << i)) != 0)
            {
                b[1 + (i / 8)] |= (byte)(0x80 >> (i % 8));
            }
        }

        return DerWriter.Tlv(tag, b);
    }

    /// <summary>Encodes GeneralNames members back to back.</summary>
    public static byte[][] NameEncodings(IEnumerable<GeneralName> names) => [.. names.Select(n => n.Encoded.ToArray())];

    /// <summary>A non-negative INTEGER in the range of <see cref="int"/>.</summary>
    public static int ReadNonNegative(ref Asn1Reader r, Asn1Tag? tag = null)
    {
        int v = r.ReadInt32(tag);
        return v < 0 ? throw X509Read.Invalid("extension", "negative number") : v;
    }
}
