using System.Diagnostics;
using System.Text;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>BZip2 (RFC 9580 §9.4, algorithm 3): the decompressor on its own and inside a message, with hostile streams.</summary>
public class Bzip2Tests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static byte[] Inflate(byte[] bz)
    {
        using var s = new Bzip2DecompressStream(new MemoryStream(bz));
        using var o = new MemoryStream();
        s.CopyTo(o);
        return o.ToArray();
    }

    // The bzip2 program is the oracle where it is installed; the committed sample covers machines without it.
    private static byte[]? Bzip2(byte[] data, int level = 9)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("bzip2", $"-{level} -c") { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false })!;
            var task = Task.Run(() =>
            {
                using var o = new MemoryStream();
                p.StandardOutput.BaseStream.CopyTo(o);
                return o.ToArray();
            });
            p.StandardInput.BaseStream.Write(data);
            p.StandardInput.Close();
            byte[] r = task.Result;
            p.WaitForExit();
            return p.ExitCode == 0 ? r : null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    private static byte[] Packet(int tag, byte[] body) => [(byte)(0xC0 | tag), 0xFF, .. new[] { (byte)(body.Length >> 24), (byte)(body.Length >> 16), (byte)(body.Length >> 8), (byte)body.Length }, .. body];

    private static byte[] Literal(byte[] data) => Packet(11, [(byte)'b', 0, 0, 0, 0, 0, .. data]);

    private static byte[] CompressedMessage(byte[] bz) => Packet(8, [3, .. bz]);

    [Fact]
    public void TheCommittedSampleDecompresses()
    {
        byte[] bz = File.ReadAllBytes(TestFiles.OpenPgp("librepgp", "bzip2-sample.bz2"));
        Assert.Equal(File.ReadAllBytes(TestFiles.OpenPgp("librepgp", "bzip2-sample.txt")), Inflate(bz));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(1000, 9)]
    [InlineData(100_000, 1)]
    [InlineData(250_000, 1)]
    [InlineData(3_000_000, 9)]
    public void MatchesTheBzip2Program(int size, int level)
    {
        var rng = new Random(size);
        byte[] data = new byte[size];
        // Text-like with long runs, so every code path (runs, move-to-front, the RLE layer) is exercised.
        for (int i = 0; i < size; i++)
        {
            data[i] = rng.Next(10) < 3 ? (byte)'a' : (byte)rng.Next(32, 127);
            if (i % 997 < 40)
            {
                data[i] = (byte)'z';
            }
        }

        byte[]? bz = Bzip2(data, level);
        if (bz is null)
        {
            return;
        }

        Assert.Equal(data, Inflate(bz));
    }

    [Fact]
    public void HandlesRunsOfEveryLengthAroundTheRepeatThreshold()
    {
        var all = new List<byte>();
        for (int run = 1; run <= 300; run++)
        {
            all.AddRange(Enumerable.Repeat((byte)(run % 3), run));
        }

        byte[]? bz = Bzip2([.. all]);
        if (bz is not null)
        {
            Assert.Equal(all.ToArray(), Inflate(bz));
        }
    }

    [Fact]
    public void ABitFlipIsAnErrorNotWrongOutput()
    {
        byte[] bz = File.ReadAllBytes(TestFiles.OpenPgp("librepgp", "bzip2-sample.bz2"));
        byte[] expected = File.ReadAllBytes(TestFiles.OpenPgp("librepgp", "bzip2-sample.txt"));
        for (int i = 4; i < bz.Length - 1; i++)
        {
            byte[] bad = (byte[])bz.Clone();
            bad[i] ^= 0x10;
            try
            {
                // A flip in the code length of a symbol that never occurs changes nothing; anything else must be caught by a check or the CRC.
                Assert.True(expected.AsSpan().SequenceEqual(Inflate(bad)), "a damaged stream decoded to different data without an error at offset " + i);
            }
            catch (InvalidDataException)
            {
            }
        }
    }

    [Fact]
    public void ATruncatedStreamIsAnError()
    {
        byte[] bz = File.ReadAllBytes(TestFiles.OpenPgp("librepgp", "bzip2-sample.bz2"));
        for (int n = 0; n < bz.Length; n++)
        {
            Assert.Throws<InvalidDataException>(() => Inflate(bz[..n]));
        }
    }

    [Fact]
    public void ABzip2MessageReadsThroughTheMessageReader()
    {
        byte[] text = Encoding.ASCII.GetBytes("bzip2 inside a message\n");
        byte[]? bz = Bzip2(Literal(text));
        if (bz is null)
        {
            return;
        }

        using var output = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(CompressedMessage(bz)), output, new PgpReadOptions { Now = Now });
        Assert.Equal(text, output.ToArray());
    }

    [Fact]
    public void ABombStopsAtTheLimitBeforeItsOutputIsAllocated()
    {
        // 200 MiB of zeros compresses to a few hundred octets. The message reader refuses beyond its ceiling and never holds the output: it streams.
        byte[] zeros = new byte[200 << 20];
        byte[] lit = Literal(zeros);
        byte[]? bz = Bzip2(lit);
        if (bz is null)
        {
            return;
        }

        Assert.True(bz.Length < 4096);
        var sink = new CountingSink();
        var e = Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(CompressedMessage(bz)), sink, new PgpReadOptions { Now = Now }));
        Assert.Equal(PgpFailure.LimitExceeded, e.Failure);
        Assert.True(sink.Count <= (130L << 20), "released " + sink.Count);
    }

    [Fact]
    public void ARandomisedBlockIsRefused()
    {
        byte[] bz = (byte[])File.ReadAllBytes(TestFiles.OpenPgp("librepgp", "bzip2-sample.bz2")).Clone();

        // The randomised bit is the first bit after the 48-bit block magic and the 32-bit CRC: header(4) + 6 + 4 octets.
        bz[14] |= 0x80;
        Assert.Throws<InvalidDataException>(() => Inflate(bz));
    }

    private sealed class CountingSink : Stream
    {
        public long Count { get; private set; }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count) => Count += count;

        public override void Write(ReadOnlySpan<byte> buffer) => Count += buffer.Length;

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
