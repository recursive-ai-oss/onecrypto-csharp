using System.Globalization;
using System.Numerics;
using System.Text;

namespace RecursiveAI.OneCrypto.Asn1;

/// <summary>
/// Builds BER or DER in one growing buffer. Constructed elements are opened with a <c>Push…</c> and closed with the matching
/// <see cref="Pop"/>, which writes the definite length in front of the content in its shortest form. Under
/// <see cref="Asn1Rules.Der"/> (the default) a SET OF is sorted when it is closed (ITU-T X.690 clause 11.6), booleans are 0xFF and
/// times use the canonical forms (11.7, 11.8). Misuse (a <c>Pop</c> with nothing open, <see cref="Encode"/> with an element still
/// open) throws <see cref="InvalidOperationException"/>: the writer takes no untrusted input.
/// </summary>
public sealed class Asn1Writer
{
    private byte[] _buf = new byte[256];
    private int _len;
    private readonly Stack<(Asn1Tag Tag, int Start, bool SetOf)> _open = new();

    /// <summary>Creates a writer. <paramref name="rules"/> must be <see cref="Asn1Rules.Der"/> or <see cref="Asn1Rules.Ber"/> (definite lengths either way).</summary>
    public Asn1Writer(Asn1Rules rules = Asn1Rules.Der)
    {
        if (rules == Asn1Rules.Cer)
        {
            throw new ArgumentOutOfRangeException(nameof(rules), "CER output needs indefinite lengths; use BerStreamWriter.");
        }

        Rules = rules;
    }

    /// <summary>The rules applied to what is written.</summary>
    public Asn1Rules Rules { get; }

    /// <summary>Octets written so far, including the content of elements still open.</summary>
    public int Length => _len;

    /// <summary>Starts again with an empty buffer.</summary>
    public void Reset()
    {
        _len = 0;
        _open.Clear();
    }

    // ---- constructed -----------------------------------------------------------------------------------------------------

    /// <summary>Opens a constructed element with the given tag; the constructed bit is set whatever the tag says.</summary>
    public void PushConstructed(Asn1Tag tag)
    {
        _open.Push((tag.WithConstructed(true), _len, false));
    }

    /// <summary>Opens a SEQUENCE, or a constructed element with the given tag.</summary>
    public void PushSequence(Asn1Tag? tag = null) => PushConstructed(tag ?? Asn1Tag.Sequence);

    /// <summary>Opens a SET, written in the order given.</summary>
    public void PushSet(Asn1Tag? tag = null) => PushConstructed(tag ?? Asn1Tag.Set);

    /// <summary>Opens a SET OF; under DER its members are sorted when it closes.</summary>
    public void PushSetOf(Asn1Tag? tag = null)
    {
        _open.Push(((tag ?? Asn1Tag.Set).WithConstructed(true), _len, true));
    }

    /// <summary>Closes the innermost open element and writes its length.</summary>
    public void Pop()
    {
        if (_open.Count == 0)
        {
            throw new InvalidOperationException("No constructed element is open.");
        }

        (Asn1Tag tag, int start, bool setOf) = _open.Pop();
        int contentLength = _len - start;
        if (setOf && Rules == Asn1Rules.Der)
        {
            SortMembers(start, contentLength);
        }

        Span<byte> header = stackalloc byte[Asn1Wire.MaxHeaderLength]; // fixed: tag (<= 6) + length (<= 5) octets
        int n = tag.Encode(header);
        n += Asn1Wire.EncodeLength(contentLength, header[n..]);
        Reserve(n);
        _len += n;
        Span<byte> all = _buf.AsSpan(0, _len);
        all.Slice(start, contentLength).CopyTo(all.Slice(start + n, contentLength));
        header[..n].CopyTo(all[start..]);
    }

    private void Reserve(int extra)
    {
        if (_buf.Length - _len < extra)
        {
            Array.Resize(ref _buf, checked(Math.Max(_buf.Length * 2, _len + extra)));
        }
    }

    private void Append(ReadOnlySpan<byte> data)
    {
        Reserve(data.Length);
        data.CopyTo(_buf.AsSpan(_len));
        _len += data.Length;
    }

    private void SortMembers(int start, int length)
    {
        Span<byte> content = _buf.AsSpan(start, length);
        var members = new List<byte[]>();
        var r = new Asn1Reader(content);
        while (r.HasData)
        {
            members.Add(r.ReadEncodedValue().ToArray());
        }

        members.Sort(static (a, b) => Asn1Wire.CompareSetOfMembers(a, b));
        int at = 0;
        foreach (byte[] m in members)
        {
            m.CopyTo(content[at..]);
            at += m.Length;
        }
    }

    // ---- primitives ------------------------------------------------------------------------------------------------------

    private void Primitive(Asn1Tag tag, ReadOnlySpan<byte> content)
    {
        Span<byte> header = stackalloc byte[Asn1Wire.MaxHeaderLength]; // fixed: tag (<= 6) + length (<= 5) octets
        int n = tag.WithConstructed(false).Encode(header);
        n += Asn1Wire.EncodeLength(content.Length, header[n..]);
        Append(header[..n]);
        Append(content);
    }

    /// <summary>Appends an encoded element unchanged, for embedding bytes that must stay as received.</summary>
    public void WriteEncodedValue(ReadOnlySpan<byte> encoded) => Append(encoded);

    /// <summary>Writes a primitive element with the given tag and content octets (an implicitly tagged value the caller encoded).</summary>
    public void WriteContent(Asn1Tag tag, ReadOnlySpan<byte> content) => Primitive(tag, content);

    /// <summary>Writes a BOOLEAN: 0xFF for true.</summary>
    public void WriteBoolean(bool value, Asn1Tag? tag = null) => Primitive(tag ?? new Asn1Tag(Asn1Tags.Boolean), [value ? (byte)0xFF : (byte)0]);

    /// <summary>Writes an INTEGER in the fewest two's-complement octets.</summary>
    public void WriteInteger(long value, Asn1Tag? tag = null) => WriteInteger(new BigInteger(value), tag);

    /// <summary>Writes an INTEGER of any size (public values only).</summary>
    public void WriteInteger(BigInteger value, Asn1Tag? tag = null)
    {
        Primitive(tag ?? new Asn1Tag(Asn1Tags.IntegerType), value.ToByteArray(isUnsigned: false, isBigEndian: true));
    }

    /// <summary>Writes a non-negative INTEGER from its big-endian magnitude, adding the sign octet when the top bit is set and dropping redundant leading zeros.</summary>
    public void WriteUnsignedInteger(ReadOnlySpan<byte> magnitude, Asn1Tag? tag = null)
    {
        while (magnitude.Length > 1 && magnitude[0] == 0)
        {
            magnitude = magnitude[1..];
        }

        Asn1Tag t = tag ?? new Asn1Tag(Asn1Tags.IntegerType);
        if (magnitude.IsEmpty)
        {
            Primitive(t, [0]);
        }
        else if ((magnitude[0] & 0x80) != 0)
        {
            byte[] padded = new byte[magnitude.Length + 1];
            magnitude.CopyTo(padded.AsSpan(1));
            Primitive(t, padded);
        }
        else
        {
            Primitive(t, magnitude);
        }
    }

    /// <summary>Writes an ENUMERATED.</summary>
    public void WriteEnumerated(int value, Asn1Tag? tag = null) => WriteInteger(value, tag ?? new Asn1Tag(Asn1Tags.Enumerated));

    /// <summary>Writes NULL.</summary>
    public void WriteNull(Asn1Tag? tag = null) => Primitive(tag ?? new Asn1Tag(Asn1Tags.Null), []);

    /// <summary>Writes an OCTET STRING.</summary>
    public void WriteOctetString(ReadOnlySpan<byte> value, Asn1Tag? tag = null) => Primitive(tag ?? new Asn1Tag(Asn1Tags.OctetString), value);

    /// <summary>Writes a BIT STRING of <paramref name="value"/> whose last octet has <paramref name="unusedBits"/> (0 to 7) unused low bits, which under DER must already be zero.</summary>
    public void WriteBitString(ReadOnlySpan<byte> value, int unusedBits = 0, Asn1Tag? tag = null)
    {
        if (unusedBits is < 0 or > 7 || (value.IsEmpty && unusedBits != 0) || (unusedBits != 0 && (value[^1] & ((1 << unusedBits) - 1)) != 0 && Rules == Asn1Rules.Der))
        {
            throw new ArgumentOutOfRangeException(nameof(unusedBits));
        }

        byte[] content = new byte[value.Length + 1];
        content[0] = (byte)unusedBits;
        value.CopyTo(content.AsSpan(1));
        Primitive(tag ?? new Asn1Tag(Asn1Tags.BitString), content);
    }

    /// <summary>Writes an OBJECT IDENTIFIER from its dotted form. Throws <see cref="ArgumentException"/> when it is not one.</summary>
    public void WriteObjectIdentifier(string dotted, Asn1Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(dotted);
        string[] parts = dotted.Split('.');
        if (parts.Length < 2)
        {
            throw new ArgumentException("An object identifier needs at least two arcs.", nameof(dotted));
        }

        var arcs = new BigInteger[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length == 0 || !BigInteger.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out arcs[i]))
            {
                throw new ArgumentException("An arc is not a non-negative number.", nameof(dotted));
            }
        }

        if (arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39))
        {
            throw new ArgumentException("The first arcs of the object identifier are out of range.", nameof(dotted));
        }

        var bytes = new List<byte>();
        Arc(bytes, (arcs[0] * 40) + arcs[1]);
        for (int i = 2; i < arcs.Length; i++)
        {
            Arc(bytes, arcs[i]);
        }

        Primitive(tag ?? new Asn1Tag(Asn1Tags.ObjectIdentifier), bytes.ToArray());
    }

    // Object identifiers are public values, so BigInteger is fine here (2.25.<UUID> arcs take 128 bits).
    private static void Arc(List<byte> into, BigInteger value)
    {
        int start = into.Count;
        into.Add((byte)(value & 0x7F));
        value >>= 7;
        while (!value.IsZero)
        {
            into.Insert(start, (byte)(0x80 | (int)(value & 0x7F)));
            value >>= 7;
        }
    }

    /// <summary>Writes a UTCTime in the canonical form YYMMDDHHMMSSZ (years 1950 to 2049 only).</summary>
    public void WriteUtcTime(DateTimeOffset value, Asn1Tag? tag = null)
    {
        DateTime t = value.UtcDateTime;
        if (t.Year is < 1950 or > 2049)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "UTCTime covers 1950 to 2049.");
        }

        Primitive(tag ?? new Asn1Tag(Asn1Tags.UtcTime), Encoding.ASCII.GetBytes(t.ToString("yyMMddHHmmss'Z'", CultureInfo.InvariantCulture)));
    }

    /// <summary>Writes a GeneralizedTime as YYYYMMDDHHMMSS[.fff]Z, with any fraction written without trailing zeros (X.690 clause 11.7).</summary>
    public void WriteGeneralizedTime(DateTimeOffset value, Asn1Tag? tag = null)
    {
        DateTime t = value.UtcDateTime;
        string text = t.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        long ticks = t.Ticks % TimeSpan.TicksPerSecond;
        if (ticks != 0)
        {
            text += "." + ticks.ToString("D7", CultureInfo.InvariantCulture).TrimEnd('0');
        }

        Primitive(tag ?? new Asn1Tag(Asn1Tags.GeneralizedTime), Encoding.ASCII.GetBytes(text + "Z"));
    }

    /// <summary>Writes a UTF8String, PrintableString, IA5String, VisibleString or NumericString from text, rejecting characters outside the repertoire.</summary>
    public void WriteCharacterString(int universalTagNumber, string value, Asn1Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(value);
        byte[] bytes;
        switch (universalTagNumber)
        {
            case Asn1Tags.Utf8String:
                bytes = new UTF8Encoding(false, true).GetBytes(value);
                break;
            case Asn1Tags.Ia5String or Asn1Tags.VisibleString or Asn1Tags.PrintableString or Asn1Tags.NumericString:
                bytes = new byte[value.Length];
                for (int i = 0; i < value.Length; i++)
                {
                    bytes[i] = value[i] < 0x80 ? (byte)value[i] : throw new ArgumentException("A character is outside the repertoire.", nameof(value));
                }

                if (!Asn1Content.TryDecodeString(universalTagNumber, bytes, out _))
                {
                    throw new ArgumentException("A character is outside the repertoire.", nameof(value));
                }

                break;
            case Asn1Tags.BmpString:
                bytes = Encoding.BigEndianUnicode.GetBytes(value);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(universalTagNumber));
        }

        Primitive(tag ?? new Asn1Tag(universalTagNumber), bytes);
    }

    // ---- result ----------------------------------------------------------------------------------------------------------

    /// <summary>The finished encoding. Every element opened must have been closed.</summary>
    public byte[] Encode()
    {
        if (_open.Count != 0)
        {
            throw new InvalidOperationException("A constructed element is still open.");
        }

        return _buf.AsSpan(0, _len).ToArray();
    }

    /// <summary>Copies the finished encoding to <paramref name="destination"/> when it fits.</summary>
    public bool TryEncode(Span<byte> destination, out int bytesWritten)
    {
        if (_open.Count != 0)
        {
            throw new InvalidOperationException("A constructed element is still open.");
        }

        bytesWritten = 0;
        if (destination.Length < _len)
        {
            return false;
        }

        _buf.AsSpan(0, _len).CopyTo(destination);
        bytesWritten = _len;
        return true;
    }
}

/// <summary>
/// Writes BER with indefinite lengths straight to a <see cref="Stream"/>, so content of any size — a CMS signed-data payload, for
/// one — goes out in chunks without being held in memory (ITU-T X.690 clause 8.1.3.6 and 8.7.3). Close every
/// <see cref="BeginIndefinite"/> with <see cref="End"/>.
/// </summary>
public sealed class BerStreamWriter
{
    private readonly Stream _stream;
    private int _open;

    /// <summary>Creates a writer over <paramref name="stream"/>, which stays open and is never flushed.</summary>
    public BerStreamWriter(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        _stream = stream;
    }

    /// <summary>Constructed elements opened and not yet closed.</summary>
    public int OpenCount => _open;

    /// <summary>Writes the identifier (constructed bit forced on) and the indefinite length octet 0x80.</summary>
    public void BeginIndefinite(Asn1Tag tag)
    {
        Span<byte> header = stackalloc byte[8]; // fixed: tag (<= 6) + 0x80
        int n = tag.WithConstructed(true).Encode(header);
        header[n++] = 0x80;
        _stream.Write(header[..n]);
        _open++;
    }

    /// <summary>Writes the end-of-contents octets that close the innermost indefinite element.</summary>
    public void End()
    {
        if (_open == 0)
        {
            throw new InvalidOperationException("No indefinite-length element is open.");
        }

        _stream.Write([0, 0]);
        _open--;
    }

    /// <summary>Writes a complete element with a definite length.</summary>
    public void WriteDefinite(Asn1Tag tag, ReadOnlySpan<byte> content)
    {
        Span<byte> header = stackalloc byte[Asn1Wire.MaxHeaderLength]; // fixed: tag (<= 6) + length (<= 5) octets
        int n = tag.Encode(header);
        n += Asn1Wire.EncodeLength(content.Length, header[n..]);
        _stream.Write(header[..n]);
        _stream.Write(content);
    }

    /// <summary>Writes already-encoded bytes unchanged.</summary>
    public void WriteEncodedValue(ReadOnlySpan<byte> encoded) => _stream.Write(encoded);

    /// <summary>
    /// Writes a constructed OCTET STRING of indefinite length whose segments are the chunks of <paramref name="source"/> (at most
    /// <paramref name="segmentSize"/> octets each), reading it to the end. Memory use is one segment.
    /// </summary>
    public void WriteOctetStringFrom(Stream source, int segmentSize = 1 << 16, Asn1Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentOutOfRangeException.ThrowIfLessThan(segmentSize, 1);
        BeginIndefinite(tag ?? new Asn1Tag(Asn1Tags.OctetString));
        byte[] buffer = new byte[segmentSize];
        int n;
        while ((n = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            WriteDefinite(new Asn1Tag(Asn1Tags.OctetString), buffer.AsSpan(0, n));
        }

        End();
    }
}
