using System.Buffers.Binary;

namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>
/// Reads OpenPGP packets from a stream or from memory, one at a time, forward only. <see cref="ReadFrame"/> hands out a packet's header
/// and its body as a stream, so a gigabyte of literal data passes through in constant memory; <see cref="ReadPacket"/> buffers one
/// packet (up to <see cref="OpenPgpLimits.MaxPacketBodyLength"/>) and returns it typed. Both old and new header formats, partial body
/// lengths and indeterminate lengths are read (RFC 9580 §4.2); nothing is normalised, so the packets can be written back byte for byte.
/// </summary>
public sealed class PacketReader : IDisposable
{
    private readonly ByteSource _source;
    private PacketFrame? _current;
    private readonly byte[] _scratch = new byte[4];

    /// <summary>Reads packets from a stream.</summary>
    /// <param name="input">The binary (not armored) packet stream.</param>
    /// <param name="limits">Resource limits; <see cref="OpenPgpLimits.Default"/> when null.</param>
    /// <param name="leaveOpen">True to leave <paramref name="input"/> open when the reader is disposed.</param>
    public PacketReader(Stream input, OpenPgpLimits? limits = null, bool leaveOpen = true)
    {
        ArgumentNullException.ThrowIfNull(input);
        _source = new ByteSource(input, leaveOpen);
        Limits = limits ?? OpenPgpLimits.Default;
    }

    /// <summary>Reads packets from memory. Packets with definite lengths share the memory instead of copying it.</summary>
    /// <param name="input">The binary packet stream.</param>
    /// <param name="limits">Resource limits; <see cref="OpenPgpLimits.Default"/> when null.</param>
    public PacketReader(ReadOnlyMemory<byte> input, OpenPgpLimits? limits = null)
    {
        _source = new ByteSource(input);
        Limits = limits ?? OpenPgpLimits.Default;
    }

    /// <summary>The limits in force.</summary>
    public OpenPgpLimits Limits { get; }

    /// <summary>Octets consumed from the input so far.</summary>
    public long Position => _source.Position;

    internal ByteSource Source => _source;

    internal byte[] Scratch => _scratch;

    /// <summary>
    /// Reads the next packet header. The previous frame, if its body was not read to the end, is skipped first. Returns null at a clean end
    /// of input (no octets left before a header).
    /// </summary>
    /// <exception cref="OpenPgpParseException">The header is malformed or the input ends inside it.</exception>
    public PacketFrame? ReadFrame()
    {
        _current?.Finish();
        _current = null;

        long offset = _source.Position;
        int first = _source.ReadByte();
        if (first < 0)
        {
            return null;
        }

        if ((first & 0x80) == 0)
        {
            throw new OpenPgpParseException(OpenPgpError.InvalidPacketHeader, offset, "bit 7 of the first octet is clear");
        }

        PacketHeader header;
        byte[] headerBytes;
        if ((first & 0x40) == 0)
        {
            // RFC 9580 §4.2.2: old format. Bits 5-2 are the tag, bits 1-0 the length type.
            byte tag = (byte)((first >> 2) & 0x0F);
            int lengthType = first & 3;
            switch (lengthType)
            {
                case 0:
                    {
                        int b = NeedByte(offset);
                        header = new PacketHeader(PacketHeaderFormat.Old, tag, PacketLengthKind.OldOneOctet, b, 2);
                        headerBytes = [(byte)first, (byte)b];
                        break;
                    }

                case 1:
                    {
                        Span<byte> two = _scratch.AsSpan(0, 2);
                        NeedBytes(two, offset);
                        header = new PacketHeader(PacketHeaderFormat.Old, tag, PacketLengthKind.OldTwoOctet, BinaryPrimitives.ReadUInt16BigEndian(two), 3);
                        headerBytes = [(byte)first, two[0], two[1]];
                        break;
                    }

                case 2:
                    {
                        Span<byte> four = _scratch.AsSpan(0, 4);
                        NeedBytes(four, offset);
                        header = new PacketHeader(PacketHeaderFormat.Old, tag, PacketLengthKind.OldFourOctet, BinaryPrimitives.ReadUInt32BigEndian(four), 5);
                        headerBytes = [(byte)first, four[0], four[1], four[2], four[3]];
                        break;
                    }

                default:
                    header = new PacketHeader(PacketHeaderFormat.Old, tag, PacketLengthKind.OldIndeterminate, -1, 1);
                    headerBytes = [(byte)first];
                    break;
            }
        }
        else
        {
            // RFC 9580 §4.2.1: new format. Bits 5-0 are the tag; the length is one, two or five octets, or a partial length.
            byte tag = (byte)(first & 0x3F);
            int l0 = NeedByte(offset);
            if (l0 < 192)
            {
                header = new PacketHeader(PacketHeaderFormat.New, tag, PacketLengthKind.NewOneOctet, l0, 2);
                headerBytes = [(byte)first, (byte)l0];
            }
            else if (l0 < 224)
            {
                int l1 = NeedByte(offset);
                header = new PacketHeader(PacketHeaderFormat.New, tag, PacketLengthKind.NewTwoOctet, ((l0 - 192) << 8) + l1 + 192, 3);
                headerBytes = [(byte)first, (byte)l0, (byte)l1];
            }
            else if (l0 == 255)
            {
                Span<byte> four = _scratch.AsSpan(0, 4);
                NeedBytes(four, offset);
                header = new PacketHeader(PacketHeaderFormat.New, tag, PacketLengthKind.NewFiveOctet, BinaryPrimitives.ReadUInt32BigEndian(four), 6);
                headerBytes = [(byte)first, 0xFF, four[0], four[1], four[2], four[3]];
            }
            else
            {
                // §4.2.1.4: 224 to 254 give a partial chunk of 2^(l0 & 0x1F) octets; more length fields follow it.
                header = new PacketHeader(PacketHeaderFormat.New, tag, PacketLengthKind.NewPartial, 1L << (l0 & 0x1F), 2);
                headerBytes = [(byte)first, (byte)l0];
            }
        }

        _current = new PacketFrame(this, header, headerBytes, offset);
        return _current;
    }

    /// <summary>
    /// Reads the next packet whole and returns it typed, or null at a clean end of input.
    /// </summary>
    /// <exception cref="OpenPgpParseException">The header or body is malformed, or the body exceeds <see cref="OpenPgpLimits.MaxPacketBodyLength"/>.</exception>
    public Packet? ReadPacket() => ReadFrame()?.ReadPacket();

    /// <summary>Like <see cref="ReadPacket"/> without throwing for bad input.</summary>
    /// <param name="packet">The packet, or null at the end of input or on failure.</param>
    /// <param name="failure">The reason when the result is false.</param>
    /// <returns>False if the input is malformed; true otherwise (including at a clean end, with a null packet).</returns>
    public bool TryReadPacket(out Packet? packet, out OpenPgpFailure failure)
    {
        try
        {
            packet = ReadPacket();
            failure = default;
            return true;
        }
        catch (OpenPgpParseException e)
        {
            packet = null;
            failure = e.Failure;
            return false;
        }
    }

    /// <inheritdoc />
    public void Dispose() => _source.Dispose();

    private int NeedByte(long headerOffset)
    {
        int b = _source.ReadByte();
        if (b < 0)
        {
            throw new OpenPgpParseException(OpenPgpError.Truncated, headerOffset, "packet header");
        }

        return b;
    }

    private void NeedBytes(Span<byte> destination, long headerOffset)
    {
        int got = 0;
        while (got < destination.Length)
        {
            int n = _source.Read(destination[got..]);
            if (n == 0)
            {
                throw new OpenPgpParseException(OpenPgpError.Truncated, headerOffset, "packet header");
            }

            got += n;
        }
    }
}

/// <summary>The header of a packet that is being read, and its body as a one-shot stream. See <see cref="PacketReader.ReadFrame"/>.</summary>
public sealed class PacketFrame
{
    private readonly PacketReader _reader;
    private readonly byte[] _headerBytes;
    private PacketBodyStream? _body;
    private bool _consumed;
    private bool _done;

    internal PacketFrame(PacketReader reader, PacketHeader header, byte[] headerBytes, long offset)
    {
        _reader = reader;
        Header = header;
        _headerBytes = headerBytes;
        Offset = offset;
    }

    /// <summary>The header.</summary>
    public PacketHeader Header { get; }

    /// <summary>The packet tag.</summary>
    public PacketTag Tag => Header.Tag;

    /// <summary>The position of the header in the input.</summary>
    public long Offset { get; }

    /// <summary>The header octets as read (the tag octet and the first length field).</summary>
    public ReadOnlyMemory<byte> HeaderBytes => _headerBytes;

    /// <summary>
    /// The packet body as a forward-only stream: partial chunk lengths are folded away, and it ends at the end of the packet. Valid until the reader moves to
    /// the next frame. A body that ends early raises <see cref="OpenPgpParseException"/>.
    /// </summary>
    public Stream Body => _body ??= NewBody();

    /// <summary>Reads the body whole and returns the typed packet. A frame can be read, copied or skipped once.</summary>
    /// <exception cref="OpenPgpParseException">The body is malformed, truncated or over the size limit.</exception>
    public Packet ReadPacket()
    {
        EnsureUnused();
        _consumed = true;
        _done = true;
        ByteSource src = _reader.Source;
        long max = _reader.Limits.MaxPacketBodyLength;
        PacketHeader h = Header;
        if (h.LengthKind != PacketLengthKind.NewPartial && h.LengthKind != PacketLengthKind.OldIndeterminate)
        {
            if (h.BodyLength > max)
            {
                throw new OpenPgpParseException(OpenPgpError.PacketTooLarge, Offset);
            }

            int len = (int)h.BodyLength;
            if (src.IsMemory)
            {
                if (!src.TrySlice(len, out ReadOnlyMemory<byte> body))
                {
                    throw new OpenPgpParseException(OpenPgpError.LengthExceedsData, Offset, "packet body");
                }

                ReadOnlyMemory<byte> whole = src.MemoryRange(src.MemoryPosition - len - _headerBytes.Length);
                return PacketFactory.Create(h.TagId, body, h, whole, _reader.Limits);
            }

            byte[] encoded = new byte[_headerBytes.Length + len];
            _headerBytes.CopyTo(encoded, 0);
            ReadExactly(src, encoded.AsSpan(_headerBytes.Length));
            return PacketFactory.Create(h.TagId, encoded.AsMemory(_headerBytes.Length), h, encoded, _reader.Limits);
        }

        // Partial or indeterminate: gather the chunks, and keep the raw bytes (with the chunk length octets) for a lossless write.
        using var raw = new MemoryStream();
        raw.Write(_headerBytes);
        var bodyStream = new PacketBodyStream(_reader, this) { Tee = raw };
        using var joined = new MemoryStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = bodyStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (joined.Length + n > max)
            {
                throw new OpenPgpParseException(OpenPgpError.PacketTooLarge, Offset);
            }

            joined.Write(buffer, 0, n);
        }

        return PacketFactory.Create(h.TagId, joined.ToArray(), h, raw.ToArray(), _reader.Limits);
    }

    /// <summary>Copies the packet exactly as it is in the input (header, chunk lengths and body) to <paramref name="destination"/>, in constant memory.</summary>
    /// <param name="destination">Where to write.</param>
    /// <exception cref="OpenPgpParseException">The packet is truncated.</exception>
    public void CopyRawTo(Stream destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        EnsureUnused();
        _consumed = true;
        _done = true;
        destination.Write(_headerBytes);
        var bodyStream = new PacketBodyStream(_reader, this) { Tee = destination };
        _body = bodyStream;
        byte[] buffer = Scratch.Rent();
        while (bodyStream.Read(buffer, 0, buffer.Length) > 0)
        {
        }

        Scratch.Return(buffer);
    }

    internal void Finish()
    {
        if (_done)
        {
            return;
        }

        _consumed = true;
        _done = true;
        Stream body = _body ??= new PacketBodyStream(_reader, this);
        byte[] buffer = Scratch.Rent();
        while (body.Read(buffer, 0, buffer.Length) > 0)
        {
        }

        Scratch.Return(buffer);
    }

    private PacketBodyStream NewBody()
    {
        EnsureUnused();
        _consumed = true;
        return new PacketBodyStream(_reader, this);
    }

    private void EnsureUnused()
    {
        if (_consumed)
        {
            throw new InvalidOperationException("The packet body has already been read, copied or skipped.");
        }
    }

    internal static void ReadExactly(ByteSource src, Span<byte> destination)
    {
        int got = 0;
        while (got < destination.Length)
        {
            int n = src.Read(destination[got..]);
            if (n == 0)
            {
                throw new OpenPgpParseException(OpenPgpError.LengthExceedsData, src.Position, "packet body");
            }

            got += n;
        }
    }
}

/// <summary>The body of a packet as a stream, folding partial body lengths (RFC 9580 §4.2.1.4) away.</summary>
internal sealed class PacketBodyStream : Stream
{
    private readonly ByteSource _source;
    private readonly PacketFrame _frame;
    private readonly PacketReader _reader;
    private readonly bool _partial;
    private readonly bool _indeterminate;
    private long _chunkRemaining;
    private bool _finalChunk;
    private long _delivered;

    internal PacketBodyStream(PacketReader reader, PacketFrame frame)
    {
        _source = reader.Source;
        _reader = reader;
        _frame = frame;
        PacketHeader h = frame.Header;
        _partial = h.IsPartial;
        _indeterminate = h.IsIndeterminate;
        _chunkRemaining = _indeterminate ? long.MaxValue : h.BodyLength;
        _finalChunk = !_partial;
    }

    /// <summary>When set, every octet consumed after the header (chunk length octets included) is also written here.</summary>
    internal Stream? Tee { get; set; }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => _delivered;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty)
        {
            return 0;
        }

        while (_chunkRemaining == 0)
        {
            if (_finalChunk)
            {
                return 0;
            }

            NextChunk();
        }

        int want = (int)Math.Min(buffer.Length, _chunkRemaining);
        int n = _source.Read(buffer[..want]);
        if (n == 0)
        {
            if (_indeterminate)
            {
                _chunkRemaining = 0;
                _finalChunk = true;
                return 0;
            }

            throw new OpenPgpParseException(OpenPgpError.LengthExceedsData, _source.Position, "packet body ends early");
        }

        if (!_indeterminate)
        {
            _chunkRemaining -= n;
        }

        _delivered += n;
        Tee?.Write(buffer[..n]);
        return n;
    }

    private void NextChunk()
    {
        // RFC 9580 §4.2.1.4: after a partial chunk comes another length field; a non-partial one is the last chunk.
        int l0 = RawByte();
        if (l0 < 192)
        {
            _chunkRemaining = l0;
            _finalChunk = true;
        }
        else if (l0 < 224)
        {
            int l1 = RawByte();
            _chunkRemaining = ((l0 - 192) << 8) + l1 + 192;
            _finalChunk = true;
        }
        else if (l0 == 255)
        {
            Span<byte> four = _reader.Scratch.AsSpan(0, 4);
            for (int i = 0; i < 4; i++)
            {
                four[i] = (byte)RawByte();
            }

            _chunkRemaining = BinaryPrimitives.ReadUInt32BigEndian(four);
            _finalChunk = true;
        }
        else
        {
            _chunkRemaining = 1L << (l0 & 0x1F);
        }
    }

    private int RawByte()
    {
        int b = _source.ReadByte();
        if (b < 0)
        {
            throw new OpenPgpParseException(OpenPgpError.Truncated, _frame.Offset, "partial body length");
        }

        Tee?.WriteByte((byte)b);
        return b;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>Reads whole packet streams from memory.</summary>
public static class PacketParser
{
    /// <summary>Reads every packet in <paramref name="data"/>. Definite-length bodies share the memory instead of copying it.</summary>
    /// <param name="data">A binary packet stream.</param>
    /// <param name="limits">Resource limits; <see cref="OpenPgpLimits.Default"/> when null.</param>
    /// <returns>The packets in order; an empty list for empty input.</returns>
    /// <exception cref="OpenPgpParseException">Any packet is malformed, or there are more than <see cref="OpenPgpLimits.MaxPackets"/>.</exception>
    public static IReadOnlyList<Packet> ParseAll(ReadOnlyMemory<byte> data, OpenPgpLimits? limits = null)
    {
        limits ??= OpenPgpLimits.Default;
        using var reader = new PacketReader(data, limits);
        return ReadAll(reader, limits);
    }

    /// <summary>Reads every packet from <paramref name="stream"/> into memory.</summary>
    /// <param name="stream">A binary packet stream.</param>
    /// <param name="limits">Resource limits; <see cref="OpenPgpLimits.Default"/> when null.</param>
    /// <returns>The packets in order.</returns>
    /// <exception cref="OpenPgpParseException">Any packet is malformed, or there are more than <see cref="OpenPgpLimits.MaxPackets"/>.</exception>
    public static IReadOnlyList<Packet> ParseAll(Stream stream, OpenPgpLimits? limits = null)
    {
        limits ??= OpenPgpLimits.Default;
        using var reader = new PacketReader(stream, limits);
        return ReadAll(reader, limits);
    }

    /// <summary>Like <see cref="ParseAll(ReadOnlyMemory{byte}, OpenPgpLimits?)"/> without throwing for bad input.</summary>
    /// <param name="data">A binary packet stream.</param>
    /// <param name="packets">The packets, or an empty list on failure.</param>
    /// <param name="failure">The reason when the result is false.</param>
    /// <param name="limits">Resource limits; <see cref="OpenPgpLimits.Default"/> when null.</param>
    public static bool TryParseAll(ReadOnlyMemory<byte> data, out IReadOnlyList<Packet> packets, out OpenPgpFailure failure, OpenPgpLimits? limits = null)
    {
        try
        {
            packets = ParseAll(data, limits);
            failure = default;
            return true;
        }
        catch (OpenPgpParseException e)
        {
            packets = [];
            failure = e.Failure;
            return false;
        }
    }

    /// <summary>Writes packets back; packets read from input are written exactly as read unless <paramref name="canonical"/> is set.</summary>
    /// <param name="packets">The packets.</param>
    /// <param name="destination">Where to write.</param>
    /// <param name="canonical">True to re-encode every header canonically.</param>
    public static void Write(IEnumerable<Packet> packets, Stream destination, bool canonical = false)
    {
        ArgumentNullException.ThrowIfNull(packets);
        foreach (Packet p in packets)
        {
            p.WriteTo(destination, canonical);
        }
    }

    private static List<Packet> ReadAll(PacketReader reader, OpenPgpLimits limits)
    {
        var list = new List<Packet>();
        while (reader.ReadPacket() is { } p)
        {
            if (list.Count >= limits.MaxPackets)
            {
                throw new OpenPgpParseException(OpenPgpError.TooManyPackets, reader.Position);
            }

            list.Add(p);
        }

        return list;
    }
}
