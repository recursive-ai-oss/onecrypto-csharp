using System.Numerics;

namespace RecursiveAI.OneCrypto.Asn1;

/// <summary>
/// A forward-only reader over one buffer of BER, CER or DER (ITU-T X.690). Reads never copy: spans point into the buffer, so the
/// original encoded bytes of any element are always available (<see cref="TryReadEncodedValue"/>) for hashing or embedding.
/// </summary>
/// <remarks>
/// <para>Every <c>TryRead…</c> returns false on malformed input or a different tag and leaves the position unchanged;
/// <see cref="LastFailure"/> then says why. The throwing twin raises <see cref="Asn1ParseException"/> with the same reason and
/// offset, and nothing else: hostile input never produces another exception type. A <c>Read…</c> that is passed an
/// <c>expectedTag</c> reads an implicitly or explicitly tagged value; without one it expects the universal tag of the type.</para>
/// <para>In <see cref="Asn1Rules.Der"/> and <see cref="Asn1Rules.Cer"/> the reader rejects every encoding X.690 clause 9, 10 and 11
/// forbids. In <see cref="Asn1Rules.Ber"/> it accepts every valid encoding, including indefinite lengths and non-minimal definite
/// lengths. A reader over a child element (<see cref="TryReadSequence(out Asn1Reader, Asn1Tag?)"/>) continues from its parent's depth, so
/// <see cref="Asn1Limits.MaxDepth"/> bounds nesting however the document is walked.</para>
/// </remarks>
public ref struct Asn1Reader
{
    private readonly ReadOnlySpan<byte> _data;
    private readonly int _base;
    private readonly int _depth;
    private readonly Asn1Rules _rules;
    private readonly Asn1Limits _limits;
    private readonly bool _tooBig;
    private int _pos;
    private Asn1Failure _failure;


    /// <summary>Reads <paramref name="data"/> as a sequence of elements under <paramref name="rules"/> and <paramref name="limits"/>.</summary>
    /// <param name="data">The encoded bytes. The reader keeps a view of them; they must not change while it is in use.</param>
    /// <param name="rules">The rules to enforce. Default <see cref="Asn1Rules.Ber"/>.</param>
    /// <param name="limits">Resource limits; <see cref="Asn1Limits.Default"/> when null.</param>
    public Asn1Reader(ReadOnlySpan<byte> data, Asn1Rules rules = Asn1Rules.Ber, Asn1Limits? limits = null)
        : this(data, rules, limits ?? Asn1Limits.Default, 0, 0)
    {
    }

    private Asn1Reader(ReadOnlySpan<byte> data, Asn1Rules rules, Asn1Limits limits, int baseOffset, int depth)
    {
        _data = data;
        _rules = rules;
        _limits = limits;
        _base = baseOffset;
        _depth = depth;
        _pos = 0;
        _failure = default;
        _tooBig = data.Length > limits.MaxTotalSize;
    }

    /// <summary>The rules this reader enforces.</summary>
    public readonly Asn1Rules Rules => _rules;

    /// <summary>The limits in force.</summary>
    public readonly Asn1Limits Limits => _limits;

    /// <summary>Nesting depth of this reader: 0 for the root.</summary>
    public readonly int Depth => _depth;

    /// <summary>Offset of the next element from the start of the outermost buffer.</summary>
    public readonly int Offset => _base + _pos;

    /// <summary>True while at least one octet remains.</summary>
    public readonly bool HasData => _pos < _data.Length;

    /// <summary>The octets not yet read.</summary>
    public readonly ReadOnlySpan<byte> Remaining => _data[_pos..];

    /// <summary>Why the last failed <c>TryRead…</c> or <c>TryPeek…</c> failed.</summary>
    public readonly Asn1Failure LastFailure => _failure;

    /// <summary>Raises <see cref="Asn1ParseException"/> with <see cref="Asn1Error.TrailingData"/> unless the input is used up.</summary>
    public readonly void ThrowIfNotEmpty()
    {
        if (HasData)
        {
            throw new Asn1ParseException(Asn1Error.TrailingData, _base + _pos);
        }
    }

    // ---- extents ----------------------------------------------------------------------------------------------------------

    private readonly struct Extent
    {
        public Extent(Asn1Tag tag, int headerLength, int contentLength, int total, bool indefinite)
        {
            Tag = tag;
            HeaderLength = headerLength;
            ContentLength = contentLength;
            Total = total;
            Indefinite = indefinite;
        }

        public Asn1Tag Tag { get; }

        public int HeaderLength { get; }

        public int ContentLength { get; }

        /// <summary>Header, content and (for the indefinite form) the end-of-contents octets.</summary>
        public int Total { get; }

        public bool Indefinite { get; }
    }

    private bool Fail(Asn1Error error, int at)
    {
        _failure = new Asn1Failure(error, _base + at);
        return false;
    }

    private bool TryExtent(out Extent x)
    {
        x = default;
        if (_tooBig)
        {
            return Fail(Asn1Error.TotalSizeExceeded, _pos);
        }

        ReadOnlySpan<byte> rest = _data[_pos..];
        Asn1Error e = Asn1Wire.ParseHeader(rest, _rules, out Asn1Tag tag, out int hl, out long length);
        if (e != Asn1Error.None)
        {
            return Fail(e, _pos);
        }

        // X.690 8.1.5 / X.680 8.6: universal tag 0 is reserved for the end-of-contents octets, which are not an element.
        if (tag.TagClass == Asn1TagClass.Universal && tag.TagNumber == 0)
        {
            return Fail(Asn1Error.InvalidTag, _pos);
        }

        if (length >= 0)
        {
            if (length > rest.Length - hl)
            {
                return Fail(Asn1Error.LengthExceedsData, _pos);
            }

            x = new Extent(tag, hl, (int)length, hl + (int)length, false);
            return true;
        }

        Asn1Failure f = Asn1Wire.FindEndOfContents(rest, hl, _base + _pos, _depth, _rules, _limits, out int contentLength);
        if (f.Error != Asn1Error.None)
        {
            _failure = f;
            return false;
        }

        x = new Extent(tag, hl, contentLength, hl + contentLength + 2, true);
        return true;
    }

    /// <summary>Extent for the element-model layer: tag, header length, content length, total length, indefinite.</summary>
    internal bool TryNextExtent(out Asn1Tag tag, out int headerLength, out int contentLength, out int total, out bool indefinite)
    {
        bool ok = TryExtent(out Extent x);
        tag = x.Tag;
        headerLength = x.HeaderLength;
        contentLength = x.ContentLength;
        total = x.Total;
        indefinite = x.Indefinite;
        return ok;
    }

    private bool TryPrimitive(Asn1Tag? expected, int universal, out Extent x, out ReadOnlySpan<byte> content)
    {
        content = default;
        if (!TryExtent(out x))
        {
            return false;
        }

        Asn1Tag want = expected ?? new Asn1Tag(Asn1TagClass.Universal, universal, false, true);
        if (x.Tag != want)
        {
            return Fail(Asn1Error.UnexpectedTag, _pos);
        }

        if (x.Tag.IsConstructed)
        {
            return Fail(Asn1Error.ConstructedNotAllowed, _pos);
        }

        content = _data.Slice(_pos + x.HeaderLength, x.ContentLength);
        return true;
    }

    private bool Done(in Extent x)
    {
        _pos += x.Total;
        return true;
    }

    // ---- structure --------------------------------------------------------------------------------------------------------

    /// <summary>The tag of the next element without consuming it.</summary>
    public bool TryPeekTag(out Asn1Tag tag)
    {
        bool ok = TryExtent(out Extent x);
        tag = x.Tag;
        return ok;
    }

    /// <summary>The tag of the next element without consuming it. Throws <see cref="Asn1ParseException"/> when there is none or it is malformed.</summary>
    public Asn1Tag PeekTag() => TryPeekTag(out Asn1Tag t) ? t : throw _failure.ToException();

    /// <summary>
    /// Reads the next element whole — identifier, length, content and any end-of-contents octets — exactly as it appears in the input.
    /// Hash these bytes, never a re-encoding.
    /// </summary>
    public bool TryReadEncodedValue(out ReadOnlySpan<byte> encoded)
    {
        encoded = default;
        if (!TryExtent(out Extent x))
        {
            return false;
        }

        encoded = _data.Slice(_pos, x.Total);
        return Done(x);
    }

    /// <summary>Reads the next element whole, as it appears in the input. Throws <see cref="Asn1ParseException"/>.</summary>
    public ReadOnlySpan<byte> ReadEncodedValue() => TryReadEncodedValue(out ReadOnlySpan<byte> v) ? v : throw _failure.ToException();

    /// <summary>The next element whole, without consuming it.</summary>
    public bool TryPeekEncodedValue(out ReadOnlySpan<byte> encoded)
    {
        encoded = default;
        if (!TryExtent(out Extent x))
        {
            return false;
        }

        encoded = _data.Slice(_pos, x.Total);
        return true;
    }

    /// <summary>Skips the next element, whatever it is, after checking that its header and extent are valid.</summary>
    public bool TrySkipValue() => TryExtent(out Extent x) && Done(x);

    /// <summary>Skips the next element. Throws <see cref="Asn1ParseException"/>.</summary>
    public void SkipValue()
    {
        if (!TrySkipValue())
        {
            throw _failure.ToException();
        }
    }

    /// <summary>
    /// Reads the content of the next element, which may be primitive or constructed, with its tag. For implicitly tagged values of a
    /// type the caller decodes itself. For an indefinite length the content excludes the end-of-contents octets.
    /// </summary>
    public bool TryReadAnyContent(out Asn1Tag tag, out ReadOnlySpan<byte> content)
    {
        content = default;
        if (!TryExtent(out Extent x))
        {
            tag = default;
            return false;
        }

        tag = x.Tag;
        content = _data.Slice(_pos + x.HeaderLength, x.ContentLength);
        return Done(x);
    }

    private bool TryConstructed(Asn1Tag? expected, int universal, out Asn1Reader child)
    {
        child = default;
        if (!TryExtent(out Extent x))
        {
            return false;
        }

        Asn1Tag want = expected ?? new Asn1Tag(universal, true);
        if (x.Tag != want)
        {
            return Fail(Asn1Error.UnexpectedTag, _pos);
        }

        if (!x.Tag.IsConstructed)
        {
            return Fail(Asn1Error.ConstructedNotAllowed, _pos);
        }

        if (_depth + 1 > _limits.MaxDepth)
        {
            return Fail(Asn1Error.DepthExceeded, _pos);
        }

        child = new Asn1Reader(_data.Slice(_pos + x.HeaderLength, x.ContentLength), _rules, _limits, _base + _pos + x.HeaderLength, _depth + 1);
        return Done(x);
    }

    /// <summary>
    /// Enters a SEQUENCE (or, with <paramref name="expectedTag"/>, an explicitly tagged or implicitly tagged constructed value) and
    /// returns a reader over its content. The constructed bit must be set.
    /// </summary>
    public bool TryReadSequence(out Asn1Reader content, Asn1Tag? expectedTag = null) => TryConstructed(expectedTag, Asn1Tags.Sequence, out content);

    /// <summary>Enters a SEQUENCE or tagged constructed value. Throws <see cref="Asn1ParseException"/>.</summary>
    public Asn1Reader ReadSequence(Asn1Tag? expectedTag = null) => TryReadSequence(out Asn1Reader r, expectedTag) ? r : throw _failure.ToException();

    /// <summary>Enters a SET; no ordering is checked (X.690 clause 10.3 orders SET members by tag; DER readers of SET do not need it).</summary>
    public bool TryReadSet(out Asn1Reader content, Asn1Tag? expectedTag = null) => TryConstructed(expectedTag, Asn1Tags.Set, out content);

    /// <summary>Enters a SET. Throws <see cref="Asn1ParseException"/>.</summary>
    public Asn1Reader ReadSet(Asn1Tag? expectedTag = null) => TryReadSet(out Asn1Reader r, expectedTag) ? r : throw _failure.ToException();

    /// <summary>
    /// Enters a SET OF. Under DER and CER the members must be in ascending order of their encodings, shorter ones padded with zero
    /// octets (X.690 clause 11.6); a different order is <see cref="Asn1Error.NotCanonical"/>.
    /// </summary>
    public bool TryReadSetOf(out Asn1Reader content, Asn1Tag? expectedTag = null)
    {
        Asn1Reader copy = this;
        if (!TryConstructed(expectedTag, Asn1Tags.Set, out content))
        {
            return false;
        }

        if (_rules != Asn1Rules.Ber)
        {
            Asn1Reader members = content;
            int prevStart = -1;
            int prevLength = 0;
            while (members.HasData)
            {
                int at = members._pos;
                if (!members.TryReadEncodedValue(out _))
                {
                    this = copy;
                    _failure = members._failure;
                    return false;
                }

                int length = members._pos - at;
                if (prevStart >= 0 && Asn1Wire.CompareSetOfMembers(content._data.Slice(prevStart, prevLength), content._data.Slice(at, length)) > 0)
                {
                    this = copy;
                    return Fail(Asn1Error.NotCanonical, content._base - _base + at);
                }

                prevStart = at;
                prevLength = length;
            }
        }

        return true;
    }

    /// <summary>Enters a SET OF, checking member order under DER and CER. Throws <see cref="Asn1ParseException"/>.</summary>
    public Asn1Reader ReadSetOf(Asn1Tag? expectedTag = null) => TryReadSetOf(out Asn1Reader r, expectedTag) ? r : throw _failure.ToException();

    // ---- scalar types -------------------------------------------------------------------------------------------------------

    /// <summary>Reads a BOOLEAN. BER accepts any non-zero octet as TRUE; DER and CER need 0xFF (X.690 clause 11.1).</summary>
    public bool TryReadBoolean(out bool value, Asn1Tag? expectedTag = null)
    {
        value = false;
        if (!TryPrimitive(expectedTag, Asn1Tags.Boolean, out Extent x, out ReadOnlySpan<byte> c))
        {
            return false;
        }

        if (c.Length != 1)
        {
            return Fail(Asn1Error.InvalidContent, _pos);
        }

        if (_rules != Asn1Rules.Ber && c[0] is not (0 or 0xFF))
        {
            return Fail(Asn1Error.NotCanonical, _pos);
        }

        value = c[0] != 0;
        return Done(x);
    }

    /// <summary>Reads a BOOLEAN. Throws <see cref="Asn1ParseException"/>.</summary>
    public bool ReadBoolean(Asn1Tag? expectedTag = null) => TryReadBoolean(out bool v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads the two's-complement content octets of an INTEGER, checked to be minimal (X.690 clause 8.3.2).</summary>
    public bool TryReadIntegerBytes(out ReadOnlySpan<byte> twosComplement, Asn1Tag? expectedTag = null)
    {
        twosComplement = default;
        if (!TryPrimitive(expectedTag, Asn1Tags.IntegerType, out Extent x, out ReadOnlySpan<byte> c))
        {
            return false;
        }

        if (!Asn1Content.IsMinimalInteger(c))
        {
            return Fail(Asn1Error.InvalidContent, _pos);
        }

        twosComplement = c;
        return Done(x);
    }

    /// <summary>Reads the content octets of an INTEGER. Throws <see cref="Asn1ParseException"/>.</summary>
    public ReadOnlySpan<byte> ReadIntegerBytes(Asn1Tag? expectedTag = null) => TryReadIntegerBytes(out ReadOnlySpan<byte> v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads a non-negative INTEGER as its big-endian magnitude without the sign octet, as an RSA modulus or an ECDSA r and s are used.</summary>
    public bool TryReadUnsignedIntegerBytes(out ReadOnlySpan<byte> magnitude, Asn1Tag? expectedTag = null)
    {
        magnitude = default;
        Asn1Reader copy = this;
        if (!TryReadIntegerBytes(out ReadOnlySpan<byte> c, expectedTag))
        {
            return false;
        }

        if ((c[0] & 0x80) != 0)
        {
            this = copy;
            return Fail(Asn1Error.ValueOutOfRange, _pos);
        }

        magnitude = c.Length > 1 && c[0] == 0 ? c[1..] : c;
        return true;
    }

    /// <summary>Reads a non-negative INTEGER as its magnitude. Throws <see cref="Asn1ParseException"/>.</summary>
    public ReadOnlySpan<byte> ReadUnsignedIntegerBytes(Asn1Tag? expectedTag = null) => TryReadUnsignedIntegerBytes(out ReadOnlySpan<byte> v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads an INTEGER of any size. For public values only (versions, serial numbers, moduli): <see cref="BigInteger"/> is not constant-time.</summary>
    public bool TryReadInteger(out BigInteger value, Asn1Tag? expectedTag = null)
    {
        value = default;
        if (!TryReadIntegerBytes(out ReadOnlySpan<byte> c, expectedTag))
        {
            return false;
        }

        value = Asn1Content.ToBigInteger(c);
        return true;
    }

    /// <summary>Reads an INTEGER of any size. Throws <see cref="Asn1ParseException"/>.</summary>
    public BigInteger ReadInteger(Asn1Tag? expectedTag = null) => TryReadInteger(out BigInteger v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads an INTEGER that fits 64 bits; otherwise <see cref="Asn1Error.ValueOutOfRange"/>.</summary>
    public bool TryReadInt64(out long value, Asn1Tag? expectedTag = null)
    {
        value = 0;
        Asn1Reader copy = this;
        if (!TryReadIntegerBytes(out ReadOnlySpan<byte> c, expectedTag))
        {
            return false;
        }

        if (!Asn1Content.TryInt64(c, out value))
        {
            this = copy;
            return Fail(Asn1Error.ValueOutOfRange, _pos);
        }

        return true;
    }

    /// <summary>Reads an INTEGER that fits 64 bits. Throws <see cref="Asn1ParseException"/>.</summary>
    public long ReadInt64(Asn1Tag? expectedTag = null) => TryReadInt64(out long v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads an INTEGER that fits 32 bits.</summary>
    public bool TryReadInt32(out int value, Asn1Tag? expectedTag = null)
    {
        value = 0;
        Asn1Reader copy = this;
        if (!TryReadInt64(out long v, expectedTag))
        {
            return false;
        }

        if (v is < int.MinValue or > int.MaxValue)
        {
            this = copy;
            return Fail(Asn1Error.ValueOutOfRange, _pos);
        }

        value = (int)v;
        return true;
    }

    /// <summary>Reads an INTEGER that fits 32 bits. Throws <see cref="Asn1ParseException"/>.</summary>
    public int ReadInt32(Asn1Tag? expectedTag = null) => TryReadInt32(out int v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads a non-negative INTEGER that fits 64 bits unsigned.</summary>
    public bool TryReadUInt64(out ulong value, Asn1Tag? expectedTag = null)
    {
        value = 0;
        Asn1Reader copy = this;
        if (!TryReadIntegerBytes(out ReadOnlySpan<byte> c, expectedTag))
        {
            return false;
        }

        if (!Asn1Content.TryUInt64(c, out value))
        {
            this = copy;
            return Fail(Asn1Error.ValueOutOfRange, _pos);
        }

        return true;
    }

    /// <summary>Reads a non-negative INTEGER that fits 64 bits unsigned. Throws <see cref="Asn1ParseException"/>.</summary>
    public ulong ReadUInt64(Asn1Tag? expectedTag = null) => TryReadUInt64(out ulong v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads an ENUMERATED that fits 32 bits (same content rules as INTEGER, X.690 clause 8.4).</summary>
    public bool TryReadEnumerated(out int value, Asn1Tag? expectedTag = null)
    {
        value = 0;
        Asn1Reader copy = this;
        if (!TryReadInt64(out long v, expectedTag ?? new Asn1Tag(Asn1Tags.Enumerated)))
        {
            return false;
        }

        if (v is < int.MinValue or > int.MaxValue)
        {
            this = copy;
            return Fail(Asn1Error.ValueOutOfRange, _pos);
        }

        value = (int)v;
        return true;
    }

    /// <summary>Reads an ENUMERATED. Throws <see cref="Asn1ParseException"/>.</summary>
    public int ReadEnumerated(Asn1Tag? expectedTag = null) => TryReadEnumerated(out int v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads a NULL.</summary>
    public bool TryReadNull(Asn1Tag? expectedTag = null)
    {
        if (!TryPrimitive(expectedTag, Asn1Tags.Null, out Extent x, out ReadOnlySpan<byte> c))
        {
            return false;
        }

        return c.IsEmpty ? Done(x) : Fail(Asn1Error.InvalidContent, _pos);
    }

    /// <summary>Reads a NULL. Throws <see cref="Asn1ParseException"/>.</summary>
    public void ReadNull(Asn1Tag? expectedTag = null)
    {
        if (!TryReadNull(expectedTag))
        {
            throw _failure.ToException();
        }
    }

    /// <summary>Reads the validated content octets of an OBJECT IDENTIFIER (X.690 clause 8.19), without decoding them.</summary>
    public bool TryReadObjectIdentifierBytes(out ReadOnlySpan<byte> content, Asn1Tag? expectedTag = null)
    {
        content = default;
        if (!TryPrimitive(expectedTag, Asn1Tags.ObjectIdentifier, out Extent x, out ReadOnlySpan<byte> c))
        {
            return false;
        }

        if (!Asn1Content.IsValidOid(c))
        {
            return Fail(Asn1Error.InvalidContent, _pos);
        }

        content = c;
        return Done(x);
    }

    /// <summary>Reads the content octets of an OBJECT IDENTIFIER. Throws <see cref="Asn1ParseException"/>.</summary>
    public ReadOnlySpan<byte> ReadObjectIdentifierBytes(Asn1Tag? expectedTag = null) => TryReadObjectIdentifierBytes(out ReadOnlySpan<byte> v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads an OBJECT IDENTIFIER as its dotted form. An arc beyond 128 bits is <see cref="Asn1Error.ValueOutOfRange"/>.</summary>
    public bool TryReadObjectIdentifier(out string value, Asn1Tag? expectedTag = null)
    {
        value = string.Empty;
        if (!TryPrimitive(expectedTag, Asn1Tags.ObjectIdentifier, out Extent x, out ReadOnlySpan<byte> c))
        {
            return false;
        }

        Asn1Error e = Asn1Content.TryOidString(c, out string? s);
        if (e != Asn1Error.None)
        {
            return Fail(e, _pos);
        }

        value = s!;
        return Done(x);
    }

    /// <summary>Reads an OBJECT IDENTIFIER as its dotted form. Throws <see cref="Asn1ParseException"/>.</summary>
    public string ReadObjectIdentifier(Asn1Tag? expectedTag = null) => TryReadObjectIdentifier(out string v, expectedTag) ? v : throw _failure.ToException();

    // ---- time -------------------------------------------------------------------------------------------------------------

    private bool TryTime(Asn1Tag? expectedTag, bool utc, out DateTimeOffset value)
    {
        value = default;
        if (!TryPrimitive(expectedTag, utc ? Asn1Tags.UtcTime : Asn1Tags.GeneralizedTime, out Extent x, out ReadOnlySpan<byte> c))
        {
            return false;
        }

        Asn1Error e = Asn1Content.TryParseTime(c, utc, _rules, out value);
        return e == Asn1Error.None ? Done(x) : Fail(e, _pos);
    }

    /// <summary>Reads a UTCTime (two-digit years: 50 and over are 19xx, below 50 are 20xx).</summary>
    public bool TryReadUtcTime(out DateTimeOffset value, Asn1Tag? expectedTag = null) => TryTime(expectedTag, true, out value);

    /// <summary>Reads a UTCTime. Throws <see cref="Asn1ParseException"/>.</summary>
    public DateTimeOffset ReadUtcTime(Asn1Tag? expectedTag = null) => TryReadUtcTime(out DateTimeOffset v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads a GeneralizedTime. Fractions of a second are kept to 100 ns; further digits are dropped.</summary>
    public bool TryReadGeneralizedTime(out DateTimeOffset value, Asn1Tag? expectedTag = null) => TryTime(expectedTag, false, out value);

    /// <summary>Reads a GeneralizedTime. Throws <see cref="Asn1ParseException"/>.</summary>
    public DateTimeOffset ReadGeneralizedTime(Asn1Tag? expectedTag = null) => TryReadGeneralizedTime(out DateTimeOffset v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads whichever of UTCTime and GeneralizedTime comes next, as X.509 Time does (RFC 5280 clause 4.1.2.5).</summary>
    public bool TryReadTime(out DateTimeOffset value)
    {
        value = default;
        if (!TryPeekTag(out Asn1Tag t))
        {
            return false;
        }

        if (t == new Asn1Tag(Asn1Tags.UtcTime))
        {
            return TryTime(null, true, out value);
        }

        if (t == new Asn1Tag(Asn1Tags.GeneralizedTime))
        {
            return TryTime(null, false, out value);
        }

        return Fail(Asn1Error.UnexpectedTag, _pos);
    }

    /// <summary>Reads a UTCTime or GeneralizedTime. Throws <see cref="Asn1ParseException"/>.</summary>
    public DateTimeOffset ReadTime() => TryReadTime(out DateTimeOffset v) ? v : throw _failure.ToException();

    // ---- strings ----------------------------------------------------------------------------------------------------------

    /// <summary>
    /// Reads a primitive OCTET STRING (or an implicitly tagged one) and points into the input. A constructed string, which only BER
    /// and CER allow (X.690 clause 8.7.3), is <see cref="Asn1Error.ConstructedNotAllowed"/> here; use <see cref="TryReadOctetStringBytes"/>.
    /// </summary>
    public bool TryReadOctetString(out ReadOnlySpan<byte> value, Asn1Tag? expectedTag = null)
    {
        value = default;
        if (!TryPrimitive(expectedTag, Asn1Tags.OctetString, out Extent x, out ReadOnlySpan<byte> c))
        {
            return false;
        }

        if (_rules == Asn1Rules.Cer && c.Length > 1000)
        {
            // X.690 9.2: CER splits strings longer than 1000 octets into constructed segments.
            return Fail(Asn1Error.NotCanonical, _pos);
        }

        value = c;
        return Done(x);
    }

    /// <summary>Reads a primitive OCTET STRING. Throws <see cref="Asn1ParseException"/>.</summary>
    public ReadOnlySpan<byte> ReadOctetString(Asn1Tag? expectedTag = null) => TryReadOctetString(out ReadOnlySpan<byte> v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads an OCTET STRING in either form and returns its octets, joining the segments of a constructed one (BER and CER).</summary>
    public bool TryReadOctetStringBytes(out byte[] value, Asn1Tag? expectedTag = null) => TryStringBytes(expectedTag, Asn1Tags.OctetString, false, out value, out _);

    /// <summary>Reads an OCTET STRING in either form. Throws <see cref="Asn1ParseException"/>.</summary>
    public byte[] ReadOctetStringBytes(Asn1Tag? expectedTag = null) => TryReadOctetStringBytes(out byte[] v, expectedTag) ? v : throw _failure.ToException();

    /// <summary>
    /// Reads a primitive BIT STRING: its octets and the number of unused bits in the last one (X.690 clause 8.6). Under DER and CER the
    /// unused bits must be zero (clause 11.2).
    /// </summary>
    public bool TryReadBitString(out ReadOnlySpan<byte> value, out int unusedBits, Asn1Tag? expectedTag = null)
    {
        value = default;
        unusedBits = 0;
        if (!TryPrimitive(expectedTag, Asn1Tags.BitString, out Extent x, out ReadOnlySpan<byte> c))
        {
            return false;
        }

        if (!BitStringContentOk(c, _rules))
        {
            return Fail(_rules != Asn1Rules.Ber && c.Length > 1 && c[0] <= 7 ? Asn1Error.NotCanonical : Asn1Error.InvalidContent, _pos);
        }

        unusedBits = c[0];
        value = c[1..];
        return Done(x);
    }

    /// <summary>Reads a primitive BIT STRING. Throws <see cref="Asn1ParseException"/>.</summary>
    public ReadOnlySpan<byte> ReadBitString(out int unusedBits, Asn1Tag? expectedTag = null) =>
        TryReadBitString(out ReadOnlySpan<byte> v, out unusedBits, expectedTag) ? v : throw _failure.ToException();

    /// <summary>Reads a BIT STRING in either form, joining the segments of a constructed one.</summary>
    public bool TryReadBitStringBytes(out byte[] value, out int unusedBits, Asn1Tag? expectedTag = null) => TryStringBytes(expectedTag, Asn1Tags.BitString, true, out value, out unusedBits);

    /// <summary>Reads a BIT STRING in either form. Throws <see cref="Asn1ParseException"/>.</summary>
    public byte[] ReadBitStringBytes(out int unusedBits, Asn1Tag? expectedTag = null) =>
        TryReadBitStringBytes(out byte[] v, out unusedBits, expectedTag) ? v : throw _failure.ToException();

    private static bool BitStringContentOk(ReadOnlySpan<byte> c, Asn1Rules rules)
    {
        if (c.IsEmpty || c[0] > 7 || (c.Length == 1 && c[0] != 0))
        {
            return false;
        }

        // X.690 11.2.1: under DER and CER the unused bits are zero.
        return rules == Asn1Rules.Ber || c[0] == 0 || (c[^1] & ((1 << c[0]) - 1)) == 0;
    }

    /// <summary>Reads a restricted character string with the given universal tag number (see <see cref="Asn1Tags"/>) and decodes it, rejecting octets outside the repertoire.</summary>
    public bool TryReadCharacterString(int universalTagNumber, out string value, Asn1Tag? expectedTag = null)
    {
        value = string.Empty;
        if (universalTagNumber is not (Asn1Tags.Utf8String or Asn1Tags.NumericString or Asn1Tags.PrintableString or Asn1Tags.T61String
            or Asn1Tags.Ia5String or Asn1Tags.VisibleString or Asn1Tags.GeneralString or Asn1Tags.UniversalString or Asn1Tags.BmpString))
        {
            throw new ArgumentOutOfRangeException(nameof(universalTagNumber), "Not a character string type.");
        }

        Asn1Reader copy = this;
        if (!TryStringBytes(expectedTag, universalTagNumber, false, out byte[] bytes, out _, true))
        {
            return false;
        }

        if (!Asn1Content.TryDecodeString(universalTagNumber, bytes, out value))
        {
            this = copy;
            return Fail(Asn1Error.InvalidContent, _pos);
        }

        return true;
    }

    /// <summary>Reads a restricted character string. Throws <see cref="Asn1ParseException"/>.</summary>
    public string ReadCharacterString(int universalTagNumber, Asn1Tag? expectedTag = null) =>
        TryReadCharacterString(universalTagNumber, out string v, expectedTag) ? v : throw _failure.ToException();

    private bool TryStringBytes(Asn1Tag? expected, int universal, bool bits, out byte[] value, out int unusedBits, bool characterString = false)
    {
        value = [];
        unusedBits = 0;
        if (!TryExtent(out Extent x))
        {
            return false;
        }

        Asn1Tag want = expected ?? new Asn1Tag(Asn1TagClass.Universal, universal, false, true);
        if (x.Tag != want)
        {
            return Fail(Asn1Error.UnexpectedTag, _pos);
        }

        ReadOnlySpan<byte> content = _data.Slice(_pos + x.HeaderLength, x.ContentLength);
        if (!x.Tag.IsConstructed)
        {
            if (bits)
            {
                if (!BitStringContentOk(content, _rules))
                {
                    return Fail(Asn1Error.InvalidContent, _pos);
                }

                unusedBits = content[0];
                value = content[1..].ToArray();
            }
            else
            {
                if (_rules == Asn1Rules.Cer && content.Length > 1000)
                {
                    return Fail(Asn1Error.NotCanonical, _pos);
                }

                value = content.ToArray();
            }

            return Done(x);
        }

        // X.690 8.7.3 / 8.6.4 / 8.23.6: a constructed string is a sequence of segments. DER forbids it (10.2).
        if (_rules == Asn1Rules.Der)
        {
            return Fail(Asn1Error.ConstructedNotAllowed, _pos);
        }

        // Segments of a restricted character string are OCTET STRINGs; those of a BIT STRING or OCTET STRING have the string's own tag.
        int segmentTag = characterString ? Asn1Tags.OctetString : universal;
        var sink = new MemoryStream();
        int lastUnused = 0;
        int count = 0;
        Asn1Failure f = JoinSegments(content, _base + _pos + x.HeaderLength, _depth + 1, 1, segmentTag, bits, sink, ref lastUnused, ref count);
        if (f.Error != Asn1Error.None)
        {
            _failure = f;
            return false;
        }

        value = sink.ToArray();
        unusedBits = lastUnused;
        return Done(x);
    }

    private Asn1Failure JoinSegments(ReadOnlySpan<byte> content, int baseOffset, int depth, int nesting, int segmentTag, bool bits, MemoryStream sink, ref int lastUnused, ref int count)
    {
        if (nesting > _limits.MaxStringNesting || depth > _limits.MaxDepth)
        {
            return new Asn1Failure(Asn1Error.DepthExceeded, baseOffset);
        }

        var r = new Asn1Reader(content, _rules, _limits, baseOffset, depth);
        while (r.HasData)
        {
            if (!r.TryExtent(out Extent x))
            {
                return r._failure;
            }

            int at = r._base + r._pos;
            if (x.Tag != new Asn1Tag(segmentTag))
            {
                return new Asn1Failure(Asn1Error.UnexpectedTag, at);
            }

            if (++count > _limits.MaxScanElements)
            {
                return new Asn1Failure(Asn1Error.TooManyElements, at);
            }

            ReadOnlySpan<byte> inner = r._data.Slice(r._pos + x.HeaderLength, x.ContentLength);
            if (x.Tag.IsConstructed)
            {
                Asn1Failure f = JoinSegments(inner, at + x.HeaderLength, depth + 1, nesting + 1, segmentTag, bits, sink, ref lastUnused, ref count);
                if (f.Error != Asn1Error.None)
                {
                    return f;
                }
            }
            else
            {
                if (bits)
                {
                    // X.690 8.6.4.1: every segment but the last has no unused bits.
                    if (lastUnused != 0 || inner.IsEmpty || inner[0] > 7 || (inner.Length == 1 && inner[0] != 0))
                    {
                        return new Asn1Failure(Asn1Error.InvalidContent, at);
                    }

                    lastUnused = inner[0];
                    inner = inner[1..];
                }
                else if (_rules == Asn1Rules.Cer && inner.Length > 1000)
                {
                    return new Asn1Failure(Asn1Error.NotCanonical, at);
                }

                if (sink.Length + inner.Length > _limits.MaxCopiedLength)
                {
                    return new Asn1Failure(Asn1Error.LengthExceedsData, at);
                }

                sink.Write(inner);
            }

            r._pos += x.Total;
        }

        return default;
    }
}
