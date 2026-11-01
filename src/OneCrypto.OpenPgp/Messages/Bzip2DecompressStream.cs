namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// Reads a bzip2 stream (RFC 9580 §9.4, algorithm 3). Written from the published description of the format: a stream is the header "BZh" and a
/// level digit, blocks of Burrows-Wheeler-transformed, move-to-front and run-length coded, Huffman-compressed data, and an end marker with a
/// combined CRC. A block is decoded into one array of at most level × 100,000 entries and its output is produced on demand, so memory is
/// bounded by the block size however much a hostile stream expands to; the caller's limit stream bounds the volume.
/// </summary>
/// <remarks>
/// Corrupt data raises <see cref="InvalidDataException"/>. The obsolete "randomised" block form is refused: no current encoder writes it.
/// Decompression only: the writer side of the format is not implemented.
/// </remarks>
internal sealed class Bzip2DecompressStream : Stream
{
    private const ulong BlockMagic = 0x314159265359;
    private const ulong EndMagic = 0x177245385090;
    private const int MaxCodeLength = 20;
    private const int GroupSize = 50;

    private static readonly uint[] CrcTable = BuildCrcTable();

    private readonly Stream _in;
    private readonly byte[] _inBuf = new byte[16 * 1024];
    private int _inPos;
    private int _inLen;
    private ulong _bits;
    private int _bitCount;

    private bool _started;
    private bool _finished;
    private int _maxBlock;
    private uint[] _tt = [];

    // The block being produced.
    private int _remaining;
    private uint _tPos;
    private uint _blockCrc;
    private uint _storedBlockCrc;
    private uint _combinedCrc;

    // The run-length layer (4 equal bytes are followed by a repeat count, 0 to 255).
    private int _prev = -1;
    private int _runLength;
    private int _repeatLeft;
    private byte _repeatByte;

    internal Bzip2DecompressStream(Stream input) => _in = input;

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

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> destination)
    {
        if (!_started)
        {
            ReadStreamHeader();
        }

        int written = 0;
        while (written < destination.Length)
        {
            if (_repeatLeft > 0)
            {
                int n = Math.Min(_repeatLeft, destination.Length - written);
                destination.Slice(written, n).Fill(_repeatByte);
                for (int i = 0; i < n; i++)
                {
                    _blockCrc = (_blockCrc << 8) ^ CrcTable[(_blockCrc >> 24) ^ _repeatByte];
                }

                written += n;
                _repeatLeft -= n;
                continue;
            }

            if (_remaining > 0)
            {
                _tPos = _tt[_tPos];
                byte ch = (byte)_tPos;
                _tPos >>= 8;
                _remaining--;
                if (_runLength == 4)
                {
                    // Four equal bytes were just written, so this octet is the number of further copies.
                    _repeatLeft = ch;
                    _repeatByte = (byte)_prev;
                    _runLength = 0;
                    _prev = -1;
                    continue;
                }

                if (ch == _prev)
                {
                    _runLength++;
                }
                else
                {
                    _prev = ch;
                    _runLength = 1;
                }

                destination[written++] = ch;
                _blockCrc = (_blockCrc << 8) ^ CrcTable[(_blockCrc >> 24) ^ ch];
                continue;
            }

            if (_finished)
            {
                break;
            }

            if (_blockActive)
            {
                FinishBlock();
            }

            ReadNextBlockOrEnd();
        }

        return written;
    }

    private bool _blockActive;

    private void FinishBlock()
    {
        // The block CRC covers the decoded output, bit-wise complemented at the end.
        if (~_blockCrc != _storedBlockCrc)
        {
            throw new InvalidDataException("A bzip2 block fails its CRC.");
        }

        _combinedCrc = ((_combinedCrc << 1) | (_combinedCrc >> 31)) ^ _storedBlockCrc;
        _blockActive = false;
    }

    private void ReadStreamHeader()
    {
        _started = true;
        if (ReadBits(8) != 'B' || ReadBits(8) != 'Z' || ReadBits(8) != 'h')
        {
            throw new InvalidDataException("Not a bzip2 stream.");
        }

        int level = (int)ReadBits(8) - '0';
        if (level is < 1 or > 9)
        {
            throw new InvalidDataException("The bzip2 block size is invalid.");
        }

        _maxBlock = level * 100_000;
        _tt = new uint[_maxBlock];
        _blockCrc = 0xFFFFFFFF;
        ReadNextBlockOrEnd();
    }

    private void ReadNextBlockOrEnd()
    {
        ulong magic = ((ulong)ReadBits(24) << 24) | ReadBits(24);
        if (magic == EndMagic)
        {
            uint stored = ReadBits(32);
            if (stored != _combinedCrc)
            {
                throw new InvalidDataException("The bzip2 stream fails its combined CRC.");
            }

            _finished = true;
            return;
        }

        if (magic != BlockMagic)
        {
            throw new InvalidDataException("A bzip2 block header is missing.");
        }

        _storedBlockCrc = ReadBits(32);
        DecodeBlock();
        _blockCrc = 0xFFFFFFFF;
        _blockActive = true;
        _prev = -1;
        _runLength = 0;
        _repeatLeft = 0;
    }

    private void DecodeBlock()
    {
        if (ReadBits(1) != 0)
        {
            throw new InvalidDataException("Randomised bzip2 blocks are not supported.");
        }

        int origPtr = (int)ReadBits(24);

        // Which byte values occur: a 16-bit map of 16-value ranges, then 16 bits for each range present.
        byte[] seqToUnseq = new byte[256];
        int used = 0;
        uint ranges = ReadBits(16);
        for (int i = 0; i < 16; i++)
        {
            if ((ranges & (0x8000u >> i)) == 0)
            {
                continue;
            }

            uint map = ReadBits(16);
            for (int j = 0; j < 16; j++)
            {
                if ((map & (0x8000u >> j)) != 0)
                {
                    seqToUnseq[used++] = (byte)((i * 16) + j);
                }
            }
        }

        if (used == 0)
        {
            throw new InvalidDataException("A bzip2 block uses no symbols.");
        }

        int alphaSize = used + 2;
        int groups = (int)ReadBits(3);
        if (groups is < 2 or > 6)
        {
            throw new InvalidDataException("The bzip2 block has an invalid number of Huffman tables.");
        }

        int selectorCount = (int)ReadBits(15);
        if (selectorCount < 1)
        {
            throw new InvalidDataException("The bzip2 block has no selectors.");
        }

        // Selectors are move-to-front coded in unary.
        byte[] selectors = new byte[selectorCount];
        byte[] order = new byte[6];
        for (int i = 0; i < groups; i++)
        {
            order[i] = (byte)i;
        }

        for (int i = 0; i < selectorCount; i++)
        {
            int j = 0;
            while (ReadBits(1) == 1)
            {
                if (++j >= groups)
                {
                    throw new InvalidDataException("A bzip2 selector is out of range.");
                }
            }

            byte v = order[j];
            for (; j > 0; j--)
            {
                order[j] = order[j - 1];
            }

            order[0] = v;
            selectors[i] = v;
        }

        // Code lengths, delta coded.
        var tables = new HuffmanTable[groups];
        for (int t = 0; t < groups; t++)
        {
            byte[] lengths = new byte[alphaSize];
            int len = (int)ReadBits(5);
            for (int s = 0; s < alphaSize; s++)
            {
                while (true)
                {
                    if (len is < 1 or > MaxCodeLength)
                    {
                        throw new InvalidDataException("A bzip2 code length is out of range.");
                    }

                    if (ReadBits(1) == 0)
                    {
                        break;
                    }

                    len += ReadBits(1) == 0 ? 1 : -1;
                }

                lengths[s] = (byte)len;
            }

            tables[t] = new HuffmanTable(lengths);
        }

        // Symbols: 0 and 1 (RUNA, RUNB) are digits of a bijective base-2 run length of the front symbol; 2..used are move-to-front
        // positions (symbol - 1); the last symbol ends the block.
        int endOfBlock = used + 1;
        byte[] mtf = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            mtf[i] = (byte)i;
        }

        int[] counts = new int[256];
        int n = 0;
        int run = 0;
        int runWeight = 1;
        int groupPos = 0;
        int groupNo = -1;
        HuffmanTable table = tables[0];
        while (true)
        {
            if (groupPos == 0)
            {
                if (++groupNo >= selectorCount)
                {
                    throw new InvalidDataException("A bzip2 block runs out of selectors.");
                }

                table = tables[selectors[groupNo]];
                groupPos = GroupSize;
            }

            groupPos--;
            int sym = table.Decode(this);
            if (sym <= 1)
            {
                run += runWeight << sym;
                runWeight <<= 1;
                if (run > _maxBlock)
                {
                    throw new InvalidDataException("A bzip2 run is longer than a block.");
                }

                continue;
            }

            if (run > 0)
            {
                byte uc = seqToUnseq[mtf[0]];
                if (n + run > _maxBlock)
                {
                    throw new InvalidDataException("A bzip2 block is larger than its declared size.");
                }

                counts[uc] += run;
                Array.Fill(_tt, uc, n, run);
                n += run;
                run = 0;
                runWeight = 1;
            }

            if (sym == endOfBlock)
            {
                break;
            }

            if (n >= _maxBlock)
            {
                throw new InvalidDataException("A bzip2 block is larger than its declared size.");
            }

            int pos = sym - 1;
            byte front = mtf[pos];
            Array.Copy(mtf, 0, mtf, 1, pos);
            mtf[0] = front;
            byte b = seqToUnseq[front];
            counts[b]++;
            _tt[n++] = b;
        }

        if (n == 0 || origPtr >= n)
        {
            throw new InvalidDataException("The bzip2 block's origin pointer is out of range.");
        }

        // Inverse Burrows-Wheeler transform: link each position to the next in the original order through the high 24 bits.
        int[] start = new int[256];
        int sum = 0;
        for (int i = 0; i < 256; i++)
        {
            start[i] = sum;
            sum += counts[i];
        }

        for (int i = 0; i < n; i++)
        {
            byte uc = (byte)_tt[i];
            _tt[start[uc]++] |= (uint)i << 8;
        }

        _tPos = _tt[origPtr] >> 8;
        _remaining = n;
    }

    // The bit reader is most-significant-bit first.
    internal uint ReadBits(int count)
    {
        while (_bitCount < count)
        {
            if (_inPos == _inLen)
            {
                _inLen = _in.Read(_inBuf, 0, _inBuf.Length);
                _inPos = 0;
                if (_inLen == 0)
                {
                    throw new InvalidDataException("The bzip2 stream is truncated.");
                }
            }

            _bits = (_bits << 8) | _inBuf[_inPos++];
            _bitCount += 8;
        }

        _bitCount -= count;
        return (uint)((_bits >> _bitCount) & ((1UL << count) - 1));
    }

    private static uint[] BuildCrcTable()
    {
        // bzip2 uses the CRC-32 polynomial 0x04C11DB7 most-significant-bit first.
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i << 24;
            for (int k = 0; k < 8; k++)
            {
                c = (c & 0x80000000) != 0 ? (c << 1) ^ 0x04C11DB7 : c << 1;
            }

            t[i] = c;
        }

        return t;
    }

    /// <summary>A canonical Huffman code: the codes of one length are consecutive, and shorter codes sort first.</summary>
    private sealed class HuffmanTable
    {
        private readonly int[] _first = new int[MaxCodeLength + 2];
        private readonly int[] _count = new int[MaxCodeLength + 2];
        private readonly int[] _offset = new int[MaxCodeLength + 2];
        private readonly int[] _symbols;
        private readonly int _minLength;
        private readonly int _maxLength;

        internal HuffmanTable(byte[] lengths)
        {
            _symbols = new int[lengths.Length];
            _minLength = MaxCodeLength;
            foreach (byte l in lengths)
            {
                _count[l]++;
                _minLength = Math.Min(_minLength, l);
                _maxLength = Math.Max(_maxLength, l);
            }

            int idx = 0;
            int code = 0;
            for (int l = 1; l <= MaxCodeLength; l++)
            {
                _first[l] = code;
                _offset[l] = idx;
                for (int s = 0; s < lengths.Length; s++)
                {
                    if (lengths[s] == l)
                    {
                        _symbols[idx++] = s;
                    }
                }

                code = (code + _count[l]) << 1;
            }
        }

        internal int Decode(Bzip2DecompressStream r)
        {
            int code = 0;
            for (int len = 1; len <= _maxLength; len++)
            {
                code = (code << 1) | (int)r.ReadBits(1);
                if (len >= _minLength && (uint)(code - _first[len]) < (uint)_count[len])
                {
                    return _symbols[_offset[len] + code - _first[len]];
                }
            }

            throw new InvalidDataException("A bzip2 Huffman code is invalid.");
        }
    }
}
