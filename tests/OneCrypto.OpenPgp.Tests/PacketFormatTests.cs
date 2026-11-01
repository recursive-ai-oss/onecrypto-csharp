using System.Buffers.Binary;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

[Collection("ProcessMemory")]
public class PacketFormatTests
{
    private static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    private static byte[] Marker => "PGP"u8.ToArray();

    private static byte[] U32(uint v)
    {
        byte[] b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        return b;
    }

    public static TheoryData<string, byte[]> Encodings() => new()
    {
        { "old one-octet", Cat([0x80 | (10 << 2) | 0, 3], Marker) },
        { "old two-octet", Cat([0x80 | (10 << 2) | 1, 0, 3], Marker) },
        { "old four-octet", Cat([0x80 | (10 << 2) | 2, 0, 0, 0, 3], Marker) },
        { "old indeterminate", Cat([0x80 | (10 << 2) | 3], Marker) },
        { "new one-octet", Cat([0xC0 | 10, 3], Marker) },
        { "new two-octet, non-minimal", Cat([0xC0 | 10, 192, 0], new byte[192]) },
        { "new five-octet for a short body", Cat([0xC0 | 10, 0xFF], U32(3), Marker) },
        { "new five-octet zero length", Cat([0xC0 | 13, 0xFF], U32(0)) },
        { "new partial", Cat([0xC0 | 9, 0xE0 | 9], new byte[512], [3], new byte[3]) },
        { "new partial, then a zero final chunk", Cat([0xC0 | 9, 0xE0 | 9], new byte[512], [0]) },
        { "new tag above 15", Cat([0xC0 | 21, 4], new byte[4]) },
        { "reserved tag zero", Cat([0xC0, 2, 9, 9]) },
        { "unknown tag 40", Cat([0xC0 | 40, 2, 9, 9]) },
    };

    [Theory]
    [MemberData(nameof(Encodings))]
    public void ReadThenWriteIsByteIdentical(string name, byte[] input)
    {
        _ = name;
        IReadOnlyList<Packet> packets = PacketParser.ParseAll(input);
        Assert.Single(packets);
        Assert.Equal(input, packets[0].ToArray());

        // The same through a stream, which cannot slice the input.
        using var ms = new MemoryStream(input);
        IReadOnlyList<Packet> streamed = PacketParser.ParseAll(ms);
        Assert.Equal(input, streamed[0].ToArray());

        // Raw copy of the frame, in constant memory, is also exact.
        using var reader = new PacketReader(new MemoryStream(input));
        using var copy = new MemoryStream();
        reader.ReadFrame()!.CopyRawTo(copy);
        Assert.Equal(input, copy.ToArray());
    }

    [Fact]
    public void ConcatenatedPacketsAreKeptSeparatelyAndInOrder()
    {
        byte[] input = Cat([0xC0 | 10, 3], Marker, [0xC0 | 12, 2, 1, 2], [0xC0 | 13, 1, (byte)'x']);
        IReadOnlyList<Packet> packets = PacketParser.ParseAll(input);
        Assert.Equal([PacketTag.Marker, PacketTag.Trust, PacketTag.UserId], packets.Select(p => p.Tag));
        using var ms = new MemoryStream();
        PacketParser.Write(packets, ms);
        Assert.Equal(input, ms.ToArray());
    }

    [Fact]
    public void CanonicalWriteUsesTheNewFormatAndTheShortestLength()
    {
        byte[] old = Cat([0x80 | (10 << 2) | 2, 0, 0, 0, 3], Marker);
        Packet p = PacketParser.ParseAll(old)[0];
        Assert.Equal(Cat([0xC0 | 10, 3], Marker), p.ToArray(canonical: true));
        Assert.Equal([0xC0 | 13, 191], PacketHeader.EncodeCanonical(13, 191));
        Assert.Equal([0xC0 | 13, 192, 0], PacketHeader.EncodeCanonical(13, 192));
        Assert.Equal([0xC0 | 13, 223, 255], PacketHeader.EncodeCanonical(13, 8383));
        Assert.Equal([0xC0 | 13, 0xFF, 0, 0, 0x20, 0xC0], PacketHeader.EncodeCanonical(13, 8384));
    }

    [Fact]
    public void APartialBodyIsJoinedAndKeepsItsFraming()
    {
        byte[] first = Cat([(byte)'b', 0, 0, 0, 0, 1], new byte[504], [7, 7]);
        byte[] input = Cat([0xC0 | 11, 0xE0 | 9], first, [2], [1, 2]);
        Packet p = PacketParser.ParseAll(input)[0];
        Assert.True(p.OriginalHeader!.Value.IsPartial);
        Assert.Equal([.. first, 1, 2], p.Body.ToArray());
        var lit = Assert.IsType<LiteralDataPacket>(p);
        Assert.Equal((byte)'b', lit.Literal.Format);
        Assert.Equal(1u, lit.Literal.Date);
        Assert.Equal(512 - 6 + 2, lit.Data.Length);
    }

    [Fact]
    public void AFirstPartialChunkUnder512OctetsIsRefused()
    {
        // RFC 9580 §4.2.1.4: the first partial chunk holds at least 512 octets.
        byte[] input = Cat([0xC0 | 11, 0xE0 | 8], new byte[256], [0]);
        var e = Assert.Throws<OpenPgpParseException>(() => PacketParser.ParseAll(input));
        Assert.Equal(OpenPgpError.InvalidField, e.Error);
    }

    [Theory]
    [InlineData(new byte[] { 0x00 })]
    [InlineData(new byte[] { 0x7F, 0x01 })]
    public void AFirstOctetWithoutBit7IsRejected(byte[] input)
    {
        var e = Assert.Throws<OpenPgpParseException>(() => PacketParser.ParseAll(input));
        Assert.Equal(OpenPgpError.InvalidPacketHeader, e.Error);
    }

    [Theory]
    [InlineData(new byte[] { 0xCA })]
    [InlineData(new byte[] { 0xCA, 0xFF, 0, 0 })]
    [InlineData(new byte[] { 0x88 })]
    [InlineData(new byte[] { 0x89, 0 })]
    [InlineData(new byte[] { 0xCB, 5, 1, 2 })]
    [InlineData(new byte[] { 0xCB, 0xE0, 1 })]
    [InlineData(new byte[] { 0xCB, 0xE0, 1, 5 })]
    public void TruncatedInputRaisesATypedError(byte[] input)
    {
        Assert.Throws<OpenPgpParseException>(() => PacketParser.ParseAll(input));
        Assert.False(PacketParser.TryParseAll(input, out IReadOnlyList<Packet> packets, out OpenPgpFailure failure));
        Assert.Empty(packets);
        Assert.NotEqual(default, failure);
    }

    [Fact]
    public void ABodyOverTheLimitIsRefusedBeforeItIsRead()
    {
        byte[] input = Cat([0xC0 | 11, 0xFF], U32(1_000_000));
        var limits = new OpenPgpLimits { MaxPacketBodyLength = 1000 };
        var e = Assert.Throws<OpenPgpParseException>(() => PacketParser.ParseAll(new MemoryStream(input), limits));
        Assert.Equal(OpenPgpError.PacketTooLarge, e.Error);
    }

    [Fact]
    public void APartialBodyOverTheLimitIsRefused()
    {
        byte[] chunk = Cat([0xC0 | 9, 0xE0 | 10], new byte[1024], [0xE0 | 10], new byte[1024], [0]);
        var limits = new OpenPgpLimits { MaxPacketBodyLength = 1500 };
        var e = Assert.Throws<OpenPgpParseException>(() => PacketParser.ParseAll(new MemoryStream(chunk), limits));
        Assert.Equal(OpenPgpError.PacketTooLarge, e.Error);
    }

    [Fact]
    public void TooManyPacketsIsRefused()
    {
        byte[] one = Cat([0xC0 | 12, 0]);
        byte[] input = Enumerable.Repeat(one, 10).SelectMany(x => x).ToArray();
        var e = Assert.Throws<OpenPgpParseException>(() => PacketParser.ParseAll(input, new OpenPgpLimits { MaxPackets = 5 }));
        Assert.Equal(OpenPgpError.TooManyPackets, e.Error);
    }

    [Fact]
    public void UnknownVersionsArePreservedAsUnrecognizedPackets()
    {
        // A public key packet claiming version 9 cannot be decoded, but it must survive a round trip.
        byte[] input = Cat([0xC0 | 6, 6, 9, 1, 2, 3, 4, 5]);
        Packet p = PacketParser.ParseAll(input)[0];
        var u = Assert.IsType<UnrecognizedPacket>(p);
        Assert.Equal(9, u.FirstOctet);
        Assert.Equal(input, p.ToArray());
    }

    [Fact]
    public void TheLiteralHeaderCanBeReadFromAStreamedBody()
    {
        byte[] name = "a.txt"u8.ToArray();
        byte[] body = Cat([(byte)'u', (byte)name.Length], name, U32(1700000000), "hello"u8.ToArray());
        byte[] input = Cat([0xC0 | 11, (byte)body.Length], body);
        using var reader = new PacketReader(new MemoryStream(input));
        PacketFrame frame = reader.ReadFrame()!;
        LiteralDataHeader h = LiteralDataHeader.Read(frame.Body);
        Assert.Equal((byte)'u', h.Format);
        Assert.Equal(name, h.FileName.ToArray());
        Assert.Equal(1700000000u, h.Date);
        var rest = new MemoryStream();
        frame.Body.CopyTo(rest);
        Assert.Equal("hello"u8.ToArray(), rest.ToArray());
        Assert.Null(reader.ReadFrame());
    }

    [Fact]
    public void AnUnreadFrameIsSkippedByTheNextRead()
    {
        byte[] input = Cat([0xC0 | 9, 0xE0 | 9], new byte[512], [3], new byte[3], [0xC0 | 12, 1, 7]);
        using var reader = new PacketReader(new MemoryStream(input));
        PacketFrame first = reader.ReadFrame()!;
        Assert.Equal(PacketTag.SymmetricallyEncryptedData, first.Tag);
        PacketFrame second = reader.ReadFrame()!;
        Assert.Equal(PacketTag.Trust, second.Tag);
        Assert.Equal([7], ((TrustPacket)second.ReadPacket()).Body.ToArray());
        Assert.Null(reader.ReadFrame());
    }

    [Fact]
    public void ALargeStreamedLiteralPassesInConstantMemory()
    {
        // 256 MiB by default; set ONECRYPTO_STREAM_CHUNKS=16384 for the 1 GiB run (64 KiB chunks).
        // The bound is on bytes allocated while reading, which stays far below the stream size only if nothing is buffered.
        long chunks = long.TryParse(Environment.GetEnvironmentVariable("ONECRYPTO_STREAM_CHUNKS"), out long c) ? c : 4096;
        using var input = new SyntheticLiteralStream(chunks);
        long total = input.BodyLength;
        using var reader = new PacketReader(input);
        PacketFrame frame = reader.ReadFrame()!;
        // Allocations on this thread, not the process working set: other test classes run in parallel in the same process
        // and would make a working-set reading meaningless. The read below is synchronous, so every byte it allocates counts here.
        long baseline = GC.GetAllocatedBytesForCurrentThread();
        long seen = 0;
        byte[] buffer = new byte[64 * 1024];
        int n;
        while ((n = frame.Body.Read(buffer, 0, buffer.Length)) > 0)
        {
            seen += n;
        }

        Assert.Equal(total, seen);
        long growth = GC.GetAllocatedBytesForCurrentThread() - baseline;
        string? artifacts = Environment.GetEnvironmentVariable("ONECRYPTO_ARTIFACTS");
        if (artifacts is not null)
        {
            Directory.CreateDirectory(artifacts);
            File.WriteAllText(Path.Combine(artifacts, "stream-allocations.txt"), $"streamed {total >> 20} MiB; allocated {growth >> 10} KiB while reading\n");
        }

        Assert.True(growth < 100L << 20, $"reading allocated {growth >> 20} MiB over {total >> 20} MiB");
        Assert.Null(reader.ReadFrame());
    }
}

/// <summary>A stream that presents one literal data packet as 64 KiB partial chunks and a short final chunk, without holding it.</summary>
internal sealed class SyntheticLiteralStream : Stream
{
    private const int ChunkExp = 16;
    private const long ChunkBytes = 1L << ChunkExp;
    private const int FinalBytes = 100;
    private readonly long _chunks;
    private long _pos;

    public SyntheticLiteralStream(long chunks)
    {
        _chunks = chunks;
    }

    /// <summary>The packet body length: the chunks plus the final chunk.</summary>
    public long BodyLength => (_chunks * ChunkBytes) + FinalBytes;

    private long Total => 1 + (_chunks * (1 + ChunkBytes)) + 1 + FinalBytes;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => Total;

    public override long Position
    {
        get => _pos;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int written = 0;
        while (written < count && _pos < Total)
        {
            buffer[offset + written++] = At(_pos++);
        }

        return written;
    }

    private byte At(long pos)
    {
        if (pos == 0)
        {
            return 0xC0 | 11;
        }

        long p = pos - 1;
        long perChunk = 1 + ChunkBytes;
        if (p < _chunks * perChunk)
        {
            long inChunk = p % perChunk;
            if (inChunk == 0)
            {
                return 0xE0 | ChunkExp;
            }

            long bodyPos = ((p / perChunk) << ChunkExp) + inChunk - 1;
            return bodyPos == 0 ? (byte)'b' : bodyPos < 6 ? (byte)0 : (byte)(bodyPos & 0xFF);
        }

        long tail = p - (_chunks * perChunk);
        return tail == 0 ? (byte)FinalBytes : (byte)(tail & 0xFF);
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
