namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>A forward-only octet source over a stream or a block of memory, with a small read-ahead buffer for the stream case.</summary>
internal sealed class ByteSource : IDisposable
{
    private readonly Stream? _stream;
    private readonly bool _leaveOpen;
    private readonly byte[]? _buffer;
    private int _bufferPos;
    private int _bufferLen;
    private readonly ReadOnlyMemory<byte> _memory;
    private int _memoryPos;
    private long _consumedFromStream;

    internal ByteSource(Stream stream, bool leaveOpen)
    {
        _stream = stream;
        _leaveOpen = leaveOpen;
        _buffer = new byte[16 * 1024];
    }

    internal ByteSource(ReadOnlyMemory<byte> memory)
    {
        _memory = memory;
    }

    internal bool IsMemory => _stream is null;

    /// <summary>Octets consumed so far, counted from the start of the source.</summary>
    internal long Position => _stream is null ? _memoryPos : _consumedFromStream;

    /// <summary>The next octet, or -1 at the end of the source.</summary>
    internal int ReadByte()
    {
        if (_stream is null)
        {
            return _memoryPos < _memory.Length ? _memory.Span[_memoryPos++] : -1;
        }

        if (_bufferPos >= _bufferLen && !Fill())
        {
            return -1;
        }

        _consumedFromStream++;
        return _buffer![_bufferPos++];
    }

    /// <summary>Reads up to <paramref name="destination"/>.Length octets; returns 0 only at the end of the source.</summary>
    internal int Read(Span<byte> destination)
    {
        if (destination.IsEmpty)
        {
            return 0;
        }

        if (_stream is null)
        {
            int n = Math.Min(destination.Length, _memory.Length - _memoryPos);
            _memory.Span.Slice(_memoryPos, n).CopyTo(destination);
            _memoryPos += n;
            return n;
        }

        if (_bufferPos >= _bufferLen)
        {
            // Large reads skip the buffer; the rest go through it so that tiny length fields cost one system read per 16 KiB.
            if (destination.Length >= _buffer!.Length)
            {
                int direct = _stream.Read(destination);
                _consumedFromStream += direct;
                return direct;
            }

            if (!Fill())
            {
                return 0;
            }
        }

        int take = Math.Min(destination.Length, _bufferLen - _bufferPos);
        _buffer.AsSpan(_bufferPos, take).CopyTo(destination);
        _bufferPos += take;
        _consumedFromStream += take;
        return take;
    }

    /// <summary>Takes <paramref name="count"/> octets as a slice of the source memory without copying; false for a stream source or when too few remain.</summary>
    internal bool TrySlice(int count, out ReadOnlyMemory<byte> slice)
    {
        if (_stream is not null || count > _memory.Length - _memoryPos)
        {
            slice = default;
            return false;
        }

        slice = _memory.Slice(_memoryPos, count);
        _memoryPos += count;
        return true;
    }

    /// <summary>The octets from <paramref name="start"/> to the current position, for a memory source.</summary>
    internal ReadOnlyMemory<byte> MemoryRange(int start) => _memory.Slice(start, _memoryPos - start);

    internal int MemoryPosition => _memoryPos;

    private bool Fill()
    {
        _bufferPos = 0;
        _bufferLen = _stream!.Read(_buffer!, 0, _buffer!.Length);
        return _bufferLen > 0;
    }

    public void Dispose()
    {
        if (_stream is not null && !_leaveOpen)
        {
            _stream.Dispose();
        }
    }
}
