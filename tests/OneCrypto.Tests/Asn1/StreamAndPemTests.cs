using System.Diagnostics;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Pem;

namespace OneCrypto.Tests.Asn1;

public class StreamReaderTests
{
    [Fact]
    public void TokensWalkNestedDefiniteAndIndefiniteElements()
    {
        byte[] data = Convert.FromHexString("30 80 02 01 05 30 03 04 01 41 00 00".Replace(" ", string.Empty));
        var r = new Asn1StreamReader(new MemoryStream(data));
        var seen = new List<string>();
        while (r.TryReadToken(out Asn1Token t))
        {
            seen.Add($"{t.Kind}:{t.Tag.TagNumber}:{t.Depth}");
            if (t.Kind == Asn1TokenKind.Primitive)
            {
                seen.Add(Convert.ToHexString(r.ReadContent()));
            }
        }

        Assert.Equal(Asn1Error.None, r.LastFailure.Error);
        Assert.Equal(
            ["StartConstructed:16:0", "Primitive:2:1", "05", "StartConstructed:16:1", "Primitive:4:2", "41", "EndConstructed:16:1", "EndConstructed:16:0"],
            seen);
        Assert.True(r.AtEnd);
    }

    [Theory]
    [InlineData("3003 0201")]
    [InlineData("30 80 02 01 05")]
    [InlineData("3002 0401 41")]
    [InlineData("3084FFFFFFFF")]
    [InlineData("0000")]
    public void MalformedStreamsFailWithTypedErrors(string hex)
    {
        var r = new Asn1StreamReader(new MemoryStream(Convert.FromHexString(hex.Replace(" ", string.Empty))));
        int guard = 0;
        bool failed = false;
        while (guard++ < 20)
        {
            if (!r.TryReadToken(out Asn1Token t))
            {
                failed = r.LastFailure.Error != Asn1Error.None;
                break;
            }

            if (t.Kind == Asn1TokenKind.Primitive && t.Length <= 100)
            {
                if (!r.TryReadContent(out _))
                {
                    failed = true;
                    break;
                }
            }
        }

        Assert.True(failed, "expected a typed failure");
    }

    [Fact]
    public void ConstructedOctetStringStreamsSegmentsAndNestedSegments()
    {
        byte[] data = Convert.FromHexString("24 80 04 02 AA BB 24 06 04 01 CC 04 01 DD 04 00 00 00 05 00".Replace(" ", string.Empty));
        var r = new Asn1StreamReader(new MemoryStream(data));
        Asn1Token start = r.ReadToken();
        using Stream s = r.OpenOctetString(start);
        var all = new MemoryStream();
        s.CopyTo(all);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }, all.ToArray());
        Assert.Equal(Asn1TokenKind.Primitive, r.ReadToken().Kind);
    }

    /// <summary>
    /// The 1 GiB streaming run: ONECRYPTO_STREAM_BYTES selects the size (default off). Reports the peak working set, which must stay
    /// near the size of the runtime itself, whatever the content length.
    /// </summary>
    [Fact]
    public void LargeIndefiniteLengthOctetStringIsReadInConstantMemory()
    {
        if (!long.TryParse(Environment.GetEnvironmentVariable("ONECRYPTO_STREAM_BYTES"), out long total))
        {
            total = 64L << 20;
        }

        using var source = new SyntheticOctetString(total, 1 << 16);
        var r = new Asn1StreamReader(source);
        Asn1Token start = r.ReadToken();
        Assert.True(start.IsIndefinite);
        GC.Collect();
        long before = Process.GetCurrentProcess().WorkingSet64;
        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        long peak = before;
        long read = 0;
        long sum = 0;
        byte[] buf = new byte[1 << 16];
        using (Stream s = r.OpenOctetString(start))
        {
            int n;
            while ((n = s.Read(buf, 0, buf.Length)) > 0)
            {
                read += n;
                sum += buf[0] + buf[n - 1];
                if ((read & ((1 << 26) - 1)) == 0)
                {
                    peak = Math.Max(peak, Process.GetCurrentProcess().WorkingSet64);
                }
            }
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
        Assert.Equal(total, read);
        Assert.True(sum > 0);
        Assert.False(r.TryReadToken(out _));
        Assert.Equal(Asn1Error.None, r.LastFailure.Error);
        string? report = Environment.GetEnvironmentVariable("ONECRYPTO_STREAM_REPORT");
        if (report is not null)
        {
            File.AppendAllText(report, $"bytes={total} workingSetBefore={before >> 20}MB peakWorkingSet={peak >> 20}MB allocatedDuringRead={allocated}B gcHeap={GC.GetTotalMemory(false) >> 20}MB\n");
        }

        Assert.True(allocated < (1 << 20), $"{allocated} bytes allocated while streaming");
        // Other tests run in this process at the same time, so the working set is only meaningful for a run of this test alone.
        if (Environment.GetEnvironmentVariable("ONECRYPTO_STREAM_ISOLATED") == "1")
        {
            Assert.True(peak - before < (32L << 20), $"working set grew by {(peak - before) >> 20} MB");
        }
    }

    /// <summary>A read-only stream that produces <c>24 80 (04 len data)* 00 00</c> without holding it.</summary>
    private sealed class SyntheticOctetString : Stream
    {
        private readonly long _total;
        private readonly int _segment;
        private long _emitted;
        private long _pos;
        private readonly byte[] _pending = new byte[16];
        private int _pendingLength;
        private int _pendingAt;
        private long _segmentLeft;
        private int _state;

        public SyntheticOctetString(long total, int segment)
        {
            _total = total;
            _segment = segment;
            _pending[0] = 0x24;
            _pending[1] = 0x80;
            _pendingLength = 2;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => _pos;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int done = 0;
            while (done < count)
            {
                if (_pendingAt < _pendingLength)
                {
                    buffer[offset + done++] = _pending[_pendingAt++];
                    continue;
                }

                if (_segmentLeft > 0)
                {
                    int n = (int)Math.Min(_segmentLeft, count - done);
                    for (int i = 0; i < n; i++)
                    {
                        buffer[offset + done + i] = (byte)(_emitted + i);
                    }

                    _emitted += n;
                    _segmentLeft -= n;
                    done += n;
                    continue;
                }

                if (_state == 2)
                {
                    break;
                }

                if (_emitted >= _total)
                {
                    _pending[0] = 0;
                    _pending[1] = 0;
                    _pendingLength = 2;
                    _pendingAt = 0;
                    _state = 2;
                    continue;
                }

                long len = Math.Min(_segment, _total - _emitted);
                _pending[0] = 0x04;
                _pending[1] = 0x84;
                _pending[2] = (byte)(len >> 24);
                _pending[3] = (byte)(len >> 16);
                _pending[4] = (byte)(len >> 8);
                _pending[5] = (byte)len;
                _pendingLength = 6;
                _pendingAt = 0;
                _segmentLeft = len;
            }

            _pos += done;
            return done;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

public class PemTests
{
    private static readonly string Cert = PemEncoding.Write("CERTIFICATE", Enumerable.Range(1, 99).Select(i => (byte)i).ToArray());

    [Fact]
    public void WritesSixtyFourColumnLinesAndReadsThemBack()
    {
        byte[] data = Enumerable.Range(1, 99).Select(i => (byte)i).ToArray();
        string pem = PemEncoding.Write("CERTIFICATE", data);
        string[] lines = pem.TrimEnd('\n').Split('\n');
        Assert.Equal("-----BEGIN CERTIFICATE-----", lines[0]);
        Assert.Equal(64, lines[1].Length);
        Assert.True(lines[2].Length <= 64);
        Assert.Equal("-----END CERTIFICATE-----", lines[^1]);
        Assert.Equal(data, PemEncoding.Parse(pem, PemMode.Strict).Data);
        Assert.Equal(pem, PemEncoding.Write("CERTIFICATE", data));
    }

    [Fact]
    public void StrictRejectsWhatLaxAccepts()
    {
        string lax = "junk before\r\n-----BEGIN PRIVATE KEY-----\r\n  AQID BAUG\r\n\r\nBwgJ  \r\n-----END PRIVATE KEY-----";
        Assert.False(PemEncoding.TryParse(lax, PemMode.Strict, out _, out PemError e));
        Assert.Equal(PemError.InvalidLayout, e);
        PemBlock b = PemEncoding.Parse(lax, PemMode.Lax);
        Assert.Equal("PRIVATE KEY", b.Label);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 }, b.Data);
    }

    [Fact]
    public void MultipleBlocksAndExplanatoryTextAreRead()
    {
        string text = "Subject: x\n" + Cert + "\nnote\n" + PemEncoding.Write("PUBLIC KEY", [1, 2, 3]) + PemEncoding.Write("EMPTY", []);
        IReadOnlyList<PemBlock> blocks = PemEncoding.ParseAll(text, PemMode.Strict);
        Assert.Equal(["CERTIFICATE", "PUBLIC KEY", "EMPTY"], blocks.Select(b => b.Label).ToArray());
        Assert.Empty(blocks[2].Data);
        Assert.Equal(99, blocks[0].Data.Length);
    }

    [Theory]
    [InlineData("-----BEGIN A-----\nAQID\n-----END B-----\n", PemError.LabelMismatch)]
    [InlineData("-----BEGIN A-----\nAQID\n", PemError.MissingEnd)]
    [InlineData("-----BEGIN A-----\nAQI*\n-----END A-----\n", PemError.InvalidLayout)]
    [InlineData("-----BEGIN A-----\nAQI\n-----END A-----\n", PemError.InvalidBase64)]
    [InlineData("-----BEGIN A--B-----\nAQID\n-----END A--B-----\n", PemError.InvalidLabel)]
    [InlineData("-----BEGIN A-----\nProc-Type: 4,ENCRYPTED\n\nAQID\n-----END A-----\n", PemError.HeadersNotAllowed)]
    public void MalformedBlocksAreTypedErrors(string text, PemError expected)
    {
        Assert.False(PemEncoding.TryParse(text, PemMode.Strict, out _, out PemError e));
        Assert.Equal(expected, e);
        Assert.Throws<PemFormatException>(() => PemEncoding.Parse(text, PemMode.Strict));
    }

    [Fact]
    public void LegacyEncryptedHeadersAreParsed()
    {
        string text = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\nAQIDBAUGBwgJ\n-----END RSA PRIVATE KEY-----\n";
        PemBlock b = PemEncoding.Parse(text, PemMode.Lax);
        Assert.True(b.IsLegacyEncrypted);
        Assert.Equal("AES-128-CBC,0123456789ABCDEF0123456789ABCDEF", b.DekInfo);
        Assert.Equal(9, b.Data.Length);
        Assert.Equal(b.Data, PemEncoding.Parse(PemEncoding.Write(b.Label, b.Data, b.Headers), PemMode.Lax).Data);
    }

    [Fact]
    public void Utf8InputIsCheckedAndNoInputGivesNoBlock()
    {
        Assert.False(PemEncoding.TryParse(new byte[] { 0xFF, 0xFE }, PemMode.Lax, out _, out PemError e));
        Assert.Equal(PemError.InvalidText, e);
        Assert.False(PemEncoding.TryParse("nothing here", PemMode.Lax, out _, out e));
        Assert.Equal(PemError.NoBlock, e);
        Assert.True(PemEncoding.TryParse(System.Text.Encoding.ASCII.GetBytes(Cert), PemMode.Strict, out PemBlock? b, out _));
        Assert.Equal(99, b!.Data.Length);
    }
}
