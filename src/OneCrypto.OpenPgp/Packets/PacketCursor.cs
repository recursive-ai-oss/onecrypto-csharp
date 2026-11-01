using System.Buffers.Binary;

namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>A forward-only reader over a packet body that hands out slices of the same memory, never copies, and raises typed errors.</summary>
internal struct PacketCursor
{
    private readonly ReadOnlyMemory<byte> _data;
    private readonly long _baseOffset;
    private int _pos;

    internal PacketCursor(ReadOnlyMemory<byte> data, long baseOffset = 0)
    {
        _data = data;
        _baseOffset = baseOffset;
        _pos = 0;
    }

    internal readonly int Position => _pos;

    internal readonly int Remaining => _data.Length - _pos;

    internal readonly bool AtEnd => _pos >= _data.Length;

    internal readonly long Offset => _baseOffset + _pos;

    internal readonly OpenPgpParseException Fail(OpenPgpError error, string? detail = null) => new(error, Offset, detail);

    internal byte Byte(string what)
    {
        if (_pos >= _data.Length)
        {
            throw Fail(OpenPgpError.Truncated, what);
        }

        return _data.Span[_pos++];
    }

    internal readonly int PeekByte() => _pos < _data.Length ? _data.Span[_pos] : -1;

    internal ushort U16(string what)
    {
        if (Remaining < 2)
        {
            throw Fail(OpenPgpError.Truncated, what);
        }

        ushort v = BinaryPrimitives.ReadUInt16BigEndian(_data.Span.Slice(_pos, 2));
        _pos += 2;
        return v;
    }

    internal uint U32(string what)
    {
        if (Remaining < 4)
        {
            throw Fail(OpenPgpError.Truncated, what);
        }

        uint v = BinaryPrimitives.ReadUInt32BigEndian(_data.Span.Slice(_pos, 4));
        _pos += 4;
        return v;
    }

    internal ReadOnlyMemory<byte> Take(int count, string what)
    {
        if (count < 0 || count > Remaining)
        {
            throw Fail(count < 0 ? OpenPgpError.InvalidField : OpenPgpError.Truncated, what);
        }

        ReadOnlyMemory<byte> slice = _data.Slice(_pos, count);
        _pos += count;
        return slice;
    }

    /// <summary>Takes a four-octet count and then that many octets, refusing counts beyond what is left.</summary>
    internal ReadOnlyMemory<byte> TakeCounted32(string what)
    {
        uint n = U32(what);
        if (n > (uint)Remaining)
        {
            throw Fail(OpenPgpError.LengthExceedsData, what);
        }

        return Take((int)n, what);
    }

    internal ReadOnlyMemory<byte> Rest()
    {
        ReadOnlyMemory<byte> slice = _data.Slice(_pos);
        _pos = _data.Length;
        return slice;
    }

    /// <summary>Reads a multiprecision integer (RFC 9580 §3.2) and returns its octets after the bit count.</summary>
    internal ReadOnlyMemory<byte> Mpi(string what, int maxBits)
    {
        int start = _pos;
        ushort bits = U16(what);
        if (bits > maxBits)
        {
            _pos = start;
            throw Fail(OpenPgpError.InvalidMpi, what);
        }

        int len = (bits + 7) / 8;
        if (len > Remaining)
        {
            _pos = start;
            throw Fail(OpenPgpError.Truncated, what);
        }

        return Take(len, what);
    }

    /// <summary>The octets consumed since <paramref name="start"/>, including length prefixes.</summary>
    internal readonly ReadOnlyMemory<byte> Since(int start) => _data.Slice(start, _pos - start);
}
