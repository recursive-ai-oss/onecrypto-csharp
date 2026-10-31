namespace RecursiveAI.OneCrypto.Asn1;

/// <summary>
/// One element of BER or DER with its tag, content and complete encoding, held as slices of the buffer it was read from: nothing is
/// copied, and <see cref="Encoded"/> is always the original bytes. The model layers keep elements like this and decode them lazily.
/// </summary>
public readonly struct Asn1Element
{
    /// <summary>Creates an element from parts already known to be consistent with each other.</summary>
    public Asn1Element(Asn1Tag tag, ReadOnlyMemory<byte> content, ReadOnlyMemory<byte> encoded, bool indefinite)
    {
        Tag = tag;
        Content = content;
        Encoded = encoded;
        Indefinite = indefinite;
    }

    /// <summary>The tag, with the constructed bit as encoded.</summary>
    public Asn1Tag Tag { get; }

    /// <summary>The content octets; for an indefinite length, without the end-of-contents marker.</summary>
    public ReadOnlyMemory<byte> Content { get; }

    /// <summary>Identifier, length and content (and the end-of-contents marker for an indefinite length), as received.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>True when the length was encoded in the indefinite form.</summary>
    public bool Indefinite { get; }

    /// <summary>The tag class as a number: 0 universal, 1 application, 2 context-specific, 3 private.</summary>
    public int TagClass => (int)Tag.TagClass;

    /// <summary>The tag number.</summary>
    public int TagNumber => Tag.TagNumber;

    /// <summary>Whether the element is constructed.</summary>
    public bool Constructed => Tag.IsConstructed;

    /// <summary>True for the universal tag with this number.</summary>
    public bool IsUniversal(int tagNumber) => Tag.TagClass == Asn1TagClass.Universal && Tag.TagNumber == tagNumber;

    /// <summary>True for the context-specific tag with this number.</summary>
    public bool IsContext(int tagNumber) => Tag.TagClass == Asn1TagClass.ContextSpecific && Tag.TagNumber == tagNumber;

    /// <summary>True for a constructed universal SEQUENCE.</summary>
    public bool IsSequence => Constructed && IsUniversal(Asn1Tags.Sequence);

    /// <summary>True for a constructed universal SET.</summary>
    public bool IsSet => Constructed && IsUniversal(Asn1Tags.Set);

    /// <summary>A reader over the content octets, for decoding the children with the typed reads.</summary>
    public Asn1Reader ContentReader(Asn1Rules rules = Asn1Rules.Ber, Asn1Limits? limits = null) => new(Content.Span, rules, limits);

    /// <summary>
    /// Reads one element at the start of <paramref name="data"/> as BER with the default limits; <paramref name="consumed"/> is its
    /// total encoded length. <paramref name="error"/> says why on failure.
    /// </summary>
    public static bool TryRead(ReadOnlyMemory<byte> data, out Asn1Element element, out int consumed, out string? error)
    {
        bool ok = TryRead(data, Asn1Rules.Ber, null, out element, out consumed, out Asn1Failure f);
        error = ok ? null : f.Message;
        return ok;
    }

    /// <summary>Reads one element at the start of <paramref name="data"/> under the given rules and limits.</summary>
    public static bool TryRead(ReadOnlyMemory<byte> data, Asn1Rules rules, Asn1Limits? limits, out Asn1Element element, out int consumed, out Asn1Failure failure)
    {
        element = default;
        consumed = 0;
        var r = new Asn1Reader(data.Span, rules, limits);
        if (!r.TryNextExtent(out Asn1Tag tag, out int hl, out int cl, out int total, out bool indefinite))
        {
            failure = r.LastFailure;
            return false;
        }

        element = new Asn1Element(tag, data.Slice(hl, cl), data[..total], indefinite);
        consumed = total;
        failure = default;
        return true;
    }

    /// <summary>Reads one element at the start of <paramref name="data"/>. Throws <see cref="Asn1ParseException"/>.</summary>
    public static Asn1Element Read(ReadOnlyMemory<byte> data, Asn1Rules rules = Asn1Rules.Ber, Asn1Limits? limits = null) =>
        TryRead(data, rules, limits, out Asn1Element e, out _, out Asn1Failure f) ? e : throw f.ToException();

    /// <summary>Reads exactly one element that fills <paramref name="data"/> apart from trailing zero padding.</summary>
    public static bool TryReadPadded(ReadOnlyMemory<byte> data, out Asn1Element element, out string? error)
    {
        if (!TryRead(data, out element, out int used, out error))
        {
            return false;
        }

        foreach (byte b in data.Span[used..])
        {
            if (b != 0)
            {
                error = new Asn1Failure(Asn1Error.TrailingData, used).Message;
                return false;
            }
        }

        return true;
    }

    /// <summary>Splits a constructed element's content into its children, at most <paramref name="max"/> of them, appending to <paramref name="into"/>.</summary>
    public static bool TryChildren(in Asn1Element parent, int max, List<Asn1Element> into, out string? error)
    {
        error = null;
        ReadOnlyMemory<byte> rest = parent.Content;
        while (!rest.IsEmpty)
        {
            if (into.Count >= max)
            {
                error = "Too many elements.";
                return false;
            }

            if (!TryRead(rest, out Asn1Element child, out int used, out error))
            {
                return false;
            }

            into.Add(child);
            rest = rest[used..];
        }

        return true;
    }
}

/// <summary>Lenient helpers that decode the value of an <see cref="Asn1Element"/> and return a null/false/-1 answer instead of failing.</summary>
public static class Asn1Values
{
    /// <summary>
    /// The octets of an OCTET STRING, joining the pieces of a constructed (BER) one. Fails above <paramref name="maxBytes"/>.
    /// </summary>
    public static bool TryOctetString(in Asn1Element e, int maxBytes, out byte[] bytes)
    {
        bytes = [];
        if (!e.IsUniversal(Asn1Tags.OctetString))
        {
            return false;
        }

        var limits = new Asn1Limits { MaxCopiedLength = maxBytes, MaxStringNesting = 4 };
        var r = new Asn1Reader(e.Encoded.Span, Asn1Rules.Ber, limits);
        if (!r.TryReadOctetStringBytes(out bytes) || bytes.Length > maxBytes)
        {
            bytes = [];
            return false;
        }

        return true;
    }

    /// <summary>The dotted form of an OBJECT IDENTIFIER, or null when it is malformed or an arc overflows 64 bits.</summary>
    public static string? TryOid(in Asn1Element e)
    {
        if (!e.IsUniversal(Asn1Tags.ObjectIdentifier) || e.Constructed)
        {
            return null;
        }

        ReadOnlySpan<byte> s = e.Content.Span;
        return s.Length > 128 || !Asn1Content.IsValidOid(s) ? null : Asn1Content.OidToString(s, allow128Bits: false);
    }

    /// <summary>A small non-negative INTEGER or ENUMERATED (up to four content octets), or -1.</summary>
    public static int TrySmallInt(in Asn1Element e)
    {
        if (e.TagClass != 0 || e.Constructed || (e.TagNumber != Asn1Tags.IntegerType && e.TagNumber != Asn1Tags.Enumerated))
        {
            return -1;
        }

        ReadOnlySpan<byte> s = e.Content.Span;
        if (s.Length is 0 or > 4 || (s[0] & 0x80) != 0)
        {
            return -1;
        }

        int v = 0;
        foreach (byte b in s)
        {
            v = (v << 8) | b;
        }

        return v < 0 ? -1 : v;
    }

    /// <summary>The magnitude bytes of an INTEGER with leading zero octets removed.</summary>
    public static ReadOnlySpan<byte> IntegerMagnitude(in Asn1Element e)
    {
        ReadOnlySpan<byte> s = e.Content.Span;
        while (s.Length > 1 && s[0] == 0)
        {
            s = s[1..];
        }

        return s;
    }

    /// <summary>Parses a UTCTime (years 50-99 are 19xx) or GeneralizedTime element, with the BER forms (offsets, fractions).</summary>
    public static bool TryTime(in Asn1Element e, out DateTimeOffset value)
    {
        value = default;
        if (e.TagClass != 0 || e.Constructed || (e.TagNumber != Asn1Tags.UtcTime && e.TagNumber != Asn1Tags.GeneralizedTime))
        {
            return false;
        }

        return Asn1Content.TryParseTime(e.Content.Span, e.TagNumber == Asn1Tags.UtcTime, Asn1Rules.Ber, out value) == Asn1Error.None;
    }
}
