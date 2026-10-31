namespace RecursiveAI.OneCrypto.Asn1;

/// <summary>What an <see cref="Asn1Token"/> marks.</summary>
public enum Asn1TokenKind
{
    /// <summary>A primitive element; its content is still unread in the stream.</summary>
    Primitive,

    /// <summary>The start of a constructed element; its children follow as tokens.</summary>
    StartConstructed,

    /// <summary>The end of the innermost constructed element: the end-of-contents octets, or the last octet of a definite one.</summary>
    EndConstructed,
}

/// <summary>One step of an <see cref="Asn1StreamReader"/>.</summary>
public readonly struct Asn1Token
{
    internal Asn1Token(Asn1TokenKind kind, Asn1Tag tag, int headerLength, long length, long offset, int depth)
    {
        Kind = kind;
        Tag = tag;
        HeaderLength = headerLength;
        Length = length;
        Offset = offset;
        Depth = depth;
    }

    /// <summary>What this token is.</summary>
    public Asn1TokenKind Kind { get; }

    /// <summary>The element's tag (for an end token, the tag of the element that ends).</summary>
    public Asn1Tag Tag { get; }

    /// <summary>Header octets of the element (0 for a definite end token).</summary>
    public int HeaderLength { get; }

    /// <summary>The content length, or -1 when the element has an indefinite length.</summary>
    public long Length { get; }

    /// <summary>Offset of the token's first octet from the start of the stream.</summary>
    public long Offset { get; }

    /// <summary>Number of constructed elements open around this token (a start token is counted at its own level).</summary>
    public int Depth { get; }

    /// <summary>True for an element with the indefinite length form.</summary>
    public bool IsIndefinite => Length < 0;
}

/// <summary>
/// Reads BER, CER or DER from a <see cref="Stream"/> as a sequence of tokens, in constant memory whatever the size of the
/// document. Primitive content is not buffered: read it in pieces with <see cref="Read(Span{byte})"/>, copy it out with
/// <see cref="ReadContent"/> within <see cref="Asn1Limits.MaxCopiedLength"/>, or let the next token skip it. A multi-gigabyte
/// constructed OCTET STRING (a CMS signed-data payload) is consumed as a <see cref="Stream"/> from <see cref="OpenOctetString"/>.
/// </summary>
/// <remarks>
/// The same header rules apply as for <see cref="Asn1Reader"/>; the stream is checked as it goes, so a child that overruns its
/// parent, a missing end-of-contents or a truncated stream fails at the point it is found. The reader owns a read buffer of 16 KiB
/// and never reads past what the document needs by more than that.
/// </remarks>
public sealed class Asn1StreamReader
{
    private const int BufferSize = 16 * 1024;

    private readonly Stream _stream;
    private readonly Asn1Rules _rules;
    private readonly Asn1Limits _limits;
    private readonly byte[] _buf = new byte[BufferSize];
    private readonly List<Frame> _frames = [];
    private int _bufPos;
    private int _bufLen;
    private long _consumed;
    private long _pending;
    private bool _eof;

    private readonly record struct Frame(long End, Asn1Tag Tag, int HeaderLength, long Offset);

    /// <summary>Reads from <paramref name="stream"/>, which stays open.</summary>
    public Asn1StreamReader(Stream stream, Asn1Rules rules = Asn1Rules.Ber, Asn1Limits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        _stream = stream;
        _rules = rules;
        _limits = limits ?? Asn1Limits.Default;
    }

    /// <summary>Octets consumed from the stream so far.</summary>
    public long Position => _consumed;

    /// <summary>Constructed elements currently open.</summary>
    public int Depth => _frames.Count;

    /// <summary>Why the last failed call failed.</summary>
    public Asn1Failure LastFailure { get; private set; }

    private bool Fail(Asn1Error e, long at)
    {
        LastFailure = new Asn1Failure(e, (int)Math.Min(at, int.MaxValue));
        return false;
    }

    private int Available(int want)
    {
        if (_bufLen - _bufPos < want && !_eof)
        {
            if (_bufPos > 0)
            {
                Buffer.BlockCopy(_buf, _bufPos, _buf, 0, _bufLen - _bufPos);
                _bufLen -= _bufPos;
                _bufPos = 0;
            }

            while (_bufLen < want && !_eof)
            {
                int n = _stream.Read(_buf, _bufLen, _buf.Length - _bufLen);
                if (n == 0)
                {
                    _eof = true;
                }

                _bufLen += n;
            }
        }

        return Math.Min(want, _bufLen - _bufPos);
    }

    private void Consume(int n)
    {
        _bufPos += n;
        _consumed += n;
    }

    private bool SkipPending()
    {
        while (_pending > 0)
        {
            int n = Available((int)Math.Min(_pending, BufferSize));
            if (n == 0)
            {
                return Fail(Asn1Error.Truncated, _consumed);
            }

            Consume(n);
            _pending -= n;
        }

        return true;
    }

    /// <summary>
    /// Reads the next token. Returns false with <see cref="LastFailure"/> of <see cref="Asn1Error.None"/> at a clean end of the
    /// stream (no element open), and false with the reason on malformed or truncated input. Unread content of the previous
    /// primitive is skipped.
    /// </summary>
    public bool TryReadToken(out Asn1Token token)
    {
        token = default;
        LastFailure = default;
        if (!SkipPending())
        {
            return false;
        }

        // A definite-length element ends when its last content octet has been consumed.
        if (_frames.Count > 0 && _frames[^1].End >= 0)
        {
            Frame top = _frames[^1];
            if (_consumed == top.End)
            {
                _frames.RemoveAt(_frames.Count - 1);
                token = new Asn1Token(Asn1TokenKind.EndConstructed, top.Tag, 0, top.End - top.Offset - top.HeaderLength, _consumed, _frames.Count);
                return true;
            }
        }

        if (_consumed > _limits.MaxTotalSize)
        {
            return Fail(Asn1Error.TotalSizeExceeded, _consumed);
        }

        if (Available(1) == 0)
        {
            return _frames.Count == 0 ? false : Fail(Asn1Error.Truncated, _consumed);
        }

        int have = Available(Asn1Wire.MaxHeaderLength);
        Asn1Error e = Asn1Wire.ParseHeader(_buf.AsSpan(_bufPos, have), _rules, out Asn1Tag tag, out int hl, out long length);
        if (e != Asn1Error.None)
        {
            return Fail(e, _consumed);
        }

        long offset = _consumed;
        bool endOfContents = tag.TagClass == Asn1TagClass.Universal && tag.TagNumber == 0 && !tag.IsConstructed && length == 0;
        if (endOfContents && _frames.Count > 0 && _frames[^1].End < 0)
        {
            Consume(hl);
            Frame f = _frames[^1];
            _frames.RemoveAt(_frames.Count - 1);
            token = new Asn1Token(Asn1TokenKind.EndConstructed, f.Tag, hl, -1, offset, _frames.Count);
            return true;
        }

        if (tag.TagClass == Asn1TagClass.Universal && tag.TagNumber == 0)
        {
            return Fail(Asn1Error.InvalidTag, offset);
        }

        if (length >= 0 && _frames.Count > 0 && _frames[^1].End >= 0 && offset + hl + length > _frames[^1].End)
        {
            return Fail(Asn1Error.LengthExceedsData, offset);
        }

        if (_frames.Count > 0 && _frames[^1].End >= 0 && offset + hl > _frames[^1].End)
        {
            return Fail(Asn1Error.LengthExceedsData, offset);
        }

        if (tag.IsConstructed)
        {
            if (_frames.Count + 1 > _limits.MaxDepth)
            {
                return Fail(Asn1Error.DepthExceeded, offset);
            }

            Consume(hl);
            _frames.Add(new Frame(length < 0 ? -1 : offset + hl + length, tag, hl, offset));
            token = new Asn1Token(Asn1TokenKind.StartConstructed, tag, hl, length, offset, _frames.Count - 1);
            return true;
        }

        Consume(hl);
        _pending = length;
        token = new Asn1Token(Asn1TokenKind.Primitive, tag, hl, length, offset, _frames.Count);
        return true;
    }

    /// <summary>Reads the next token. Throws <see cref="Asn1ParseException"/> on malformed input and at the end of the stream.</summary>
    public Asn1Token ReadToken() =>
        TryReadToken(out Asn1Token t) ? t : throw new Asn1ParseException(LastFailure.Error == Asn1Error.None ? Asn1Error.Truncated : LastFailure.Error, (int)Math.Min(_consumed, int.MaxValue));

    /// <summary>True when the stream has ended and no element is open. Reads ahead one octet.</summary>
    public bool AtEnd => _pending == 0 && _frames.Count == 0 && Available(1) == 0;

    /// <summary>
    /// Reads some of the unread content of the current primitive element into <paramref name="destination"/>; returns 0 when it is
    /// used up. Throws <see cref="Asn1ParseException"/> if the stream ends inside it.
    /// </summary>
    public int Read(Span<byte> destination)
    {
        if (_pending == 0 || destination.IsEmpty)
        {
            return 0;
        }

        int want = (int)Math.Min(Math.Min(_pending, destination.Length), BufferSize);
        int n = Available(want);
        if (n == 0)
        {
            throw new Asn1ParseException(Asn1Error.Truncated, (int)Math.Min(_consumed, int.MaxValue));
        }

        _buf.AsSpan(_bufPos, n).CopyTo(destination);
        Consume(n);
        _pending -= n;
        return n;
    }

    /// <summary>Copies out the whole unread content of the current primitive element, if it is within <see cref="Asn1Limits.MaxCopiedLength"/>.</summary>
    public bool TryReadContent(out byte[] content)
    {
        content = [];
        if (_pending > _limits.MaxCopiedLength)
        {
            return Fail(Asn1Error.LengthExceedsData, _consumed);
        }

        byte[] result = new byte[(int)_pending];
        int at = 0;
        while (at < result.Length)
        {
            int n = Available(Math.Min(result.Length - at, BufferSize));
            if (n == 0)
            {
                return Fail(Asn1Error.Truncated, _consumed);
            }

            _buf.AsSpan(_bufPos, n).CopyTo(result.AsSpan(at));
            Consume(n);
            _pending -= n;
            at += n;
        }

        content = result;
        return true;
    }

    /// <summary>Copies out the content of the current primitive element. Throws <see cref="Asn1ParseException"/>.</summary>
    public byte[] ReadContent() => TryReadContent(out byte[] c) ? c : throw LastFailure.ToException();

    /// <summary>
    /// After the start token of a constructed OCTET STRING, returns a stream of its octets: the segments joined, read as they arrive,
    /// ending where the string ends (X.690 clause 8.7.3). Segments must be OCTET STRINGs, nested no deeper than
    /// <see cref="Asn1Limits.MaxStringNesting"/>. Malformed input surfaces as <see cref="Asn1ParseException"/> from
    /// <see cref="Stream.Read(byte[], int, int)"/>. Do not use the reader until the returned stream has reported its end.
    /// </summary>
    public Stream OpenOctetString(Asn1Token start)
    {
        if (start.Kind != Asn1TokenKind.StartConstructed || start.Tag != new Asn1Tag(Asn1Tags.OctetString))
        {
            throw new ArgumentException("The token is not the start of a constructed OCTET STRING.", nameof(start));
        }

        return new SegmentStream(this, _frames.Count);
    }

    private sealed class SegmentStream : Stream
    {
        private readonly Asn1StreamReader _r;
        private readonly int _baseDepth;
        private bool _done;

        public SegmentStream(Asn1StreamReader reader, int baseDepth)
        {
            _r = reader;
            _baseDepth = baseDepth;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (_done || buffer.IsEmpty)
            {
                return 0;
            }

            while (true)
            {
                int n = _r.Read(buffer);
                if (n > 0)
                {
                    return n;
                }

                if (!_r.TryReadToken(out Asn1Token t))
                {
                    throw (_r.LastFailure.Error == Asn1Error.None ? new Asn1Failure(Asn1Error.Truncated, (int)Math.Min(_r._consumed, int.MaxValue)) : _r.LastFailure).ToException();
                }

                switch (t.Kind)
                {
                    case Asn1TokenKind.EndConstructed:
                        if (_r._frames.Count < _baseDepth)
                        {
                            _done = true;
                            return 0;
                        }

                        break;
                    case Asn1TokenKind.StartConstructed:
                        if (t.Tag != new Asn1Tag(Asn1Tags.OctetString) || _r._frames.Count - _baseDepth >= _r._limits.MaxStringNesting)
                        {
                            throw new Asn1ParseException(t.Tag != new Asn1Tag(Asn1Tags.OctetString) ? Asn1Error.UnexpectedTag : Asn1Error.DepthExceeded, (int)Math.Min(t.Offset, int.MaxValue));
                        }

                        break;
                    default:
                        if (t.Tag != new Asn1Tag(Asn1Tags.OctetString))
                        {
                            throw new Asn1ParseException(Asn1Error.UnexpectedTag, (int)Math.Min(t.Offset, int.MaxValue));
                        }

                        break;
                }
            }
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
