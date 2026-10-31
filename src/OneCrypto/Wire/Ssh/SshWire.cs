using System.Buffers.Binary;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Wire.Ssh;

/// <summary>Why OpenSSH key data was rejected.</summary>
public enum SshError
{
    /// <summary>The data ends inside a field.</summary>
    Truncated,

    /// <summary>A field holds a value the format does not allow, or the structure is wrong.</summary>
    InvalidValue,

    /// <summary>The key type, curve, cipher or key-derivation function is not one this library reads.</summary>
    Unsupported,

    /// <summary>A size or cost limit was exceeded.</summary>
    LimitExceeded,
}

/// <summary>Raised when OpenSSH key data cannot be parsed. <c>TryParse</c> methods return false instead.</summary>
public sealed class SshParseException : FormatException
{
    /// <summary>Creates the exception.</summary>
    public SshParseException(string structure, SshError error, string message)
        : base($"{structure}: {message}")
    {
        Structure = structure;
        Error = error;
    }

    /// <summary>Creates an empty exception.</summary>
    public SshParseException()
        : this("SSH", SshError.InvalidValue, "invalid key data")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public SshParseException(string message)
        : this("SSH", SshError.InvalidValue, message)
    {
    }

    /// <summary>Creates the exception with a message and an inner exception.</summary>
    public SshParseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>The structure being read.</summary>
    public string Structure { get; } = "SSH";

    /// <summary>The category of the failure.</summary>
    public SshError Error { get; }
}

/// <summary>A forward-only reader of the SSH wire types of RFC 4251 §5: <c>uint32</c>, <c>uint64</c>, <c>string</c> and <c>mpint</c>.</summary>
public ref struct SshReader
{
    private readonly string _what;
    private ReadOnlySpan<byte> _data;

    /// <summary>Starts reading <paramref name="data"/>; <paramref name="structure"/> names it in errors.</summary>
    public SshReader(ReadOnlySpan<byte> data, string structure = "SSH")
    {
        _data = data;
        _what = structure;
    }

    /// <summary>True while bytes remain.</summary>
    public readonly bool HasData => !_data.IsEmpty;

    /// <summary>The unread bytes.</summary>
    public readonly ReadOnlySpan<byte> Remaining => _data;

    /// <summary>Reads one byte.</summary>
    public byte ReadByte()
    {
        if (_data.IsEmpty)
        {
            throw new SshParseException(_what, SshError.Truncated, "unexpected end of data");
        }

        byte b = _data[0];
        _data = _data[1..];
        return b;
    }

    /// <summary>Reads a big-endian <c>uint32</c>.</summary>
    public uint ReadUInt32()
    {
        if (_data.Length < 4)
        {
            throw new SshParseException(_what, SshError.Truncated, "unexpected end of data");
        }

        uint v = BinaryPrimitives.ReadUInt32BigEndian(_data);
        _data = _data[4..];
        return v;
    }

    /// <summary>Reads a big-endian <c>uint64</c>.</summary>
    public ulong ReadUInt64()
    {
        if (_data.Length < 8)
        {
            throw new SshParseException(_what, SshError.Truncated, "unexpected end of data");
        }

        ulong v = BinaryPrimitives.ReadUInt64BigEndian(_data);
        _data = _data[8..];
        return v;
    }

    /// <summary>Reads a length-prefixed <c>string</c> and returns its content.</summary>
    public ReadOnlySpan<byte> ReadString()
    {
        uint n = ReadUInt32();
        if (n > _data.Length)
        {
            throw new SshParseException(_what, SshError.Truncated, "a string is longer than the data that remains");
        }

        ReadOnlySpan<byte> s = _data[..(int)n];
        _data = _data[(int)n..];
        return s;
    }

    /// <summary>Reads a <c>string</c> that must be ASCII (algorithm and curve names).</summary>
    public string ReadAscii()
    {
        ReadOnlySpan<byte> s = ReadString();
        foreach (byte b in s)
        {
            if (b is < 0x20 or > 0x7E)
            {
                throw new SshParseException(_what, SshError.InvalidValue, "a name contains a character outside printable ASCII");
            }
        }

        return System.Text.Encoding.ASCII.GetString(s);
    }

    /// <summary>
    /// Reads a non-negative <c>mpint</c> and returns its magnitude without the leading zero octet. A negative number, or one with a
    /// redundant leading zero, is refused (RFC 4251 §5).
    /// </summary>
    public ReadOnlySpan<byte> ReadMpint()
    {
        ReadOnlySpan<byte> s = ReadString();
        if (s.IsEmpty)
        {
            return s;
        }

        if ((s[0] & 0x80) != 0)
        {
            throw new SshParseException(_what, SshError.InvalidValue, "a negative mpint");
        }

        if (s[0] == 0)
        {
            if (s.Length == 1 || (s[1] & 0x80) == 0)
            {
                throw new SshParseException(_what, SshError.InvalidValue, "an mpint with a redundant leading zero");
            }

            return s[1..];
        }

        return s;
    }

    /// <summary>Throws unless all data was read.</summary>
    public readonly void ThrowIfNotEmpty()
    {
        if (!_data.IsEmpty)
        {
            throw new SshParseException(_what, SshError.InvalidValue, "unexpected data after the structure");
        }
    }
}

/// <summary>Builds SSH wire encodings (RFC 4251 §5). The buffer is pinned and zeroed on <see cref="Dispose"/> because it may hold private-key fields.</summary>
public sealed class SshWriter : IDisposable
{
    private byte[] _buffer = GC.AllocateUninitializedArray<byte>(256, pinned: true);
    private int _length;

    /// <summary>The bytes written so far. Valid until the next write or <see cref="Dispose"/>.</summary>
    public ReadOnlySpan<byte> Written => _buffer.AsSpan(0, _length);

    /// <summary>Appends a byte.</summary>
    public void WriteByte(byte value)
    {
        Reserve(1);
        _buffer[_length++] = value;
    }

    /// <summary>Appends a <c>uint32</c>.</summary>
    public void WriteUInt32(uint value)
    {
        Reserve(4);
        BinaryPrimitives.WriteUInt32BigEndian(_buffer.AsSpan(_length), value);
        _length += 4;
    }

    /// <summary>Appends a <c>uint64</c>.</summary>
    public void WriteUInt64(ulong value)
    {
        Reserve(8);
        BinaryPrimitives.WriteUInt64BigEndian(_buffer.AsSpan(_length), value);
        _length += 8;
    }

    /// <summary>Appends raw bytes with no length.</summary>
    public void WriteRaw(ReadOnlySpan<byte> value)
    {
        Reserve(value.Length);
        value.CopyTo(_buffer.AsSpan(_length));
        _length += value.Length;
    }

    /// <summary>Appends a <c>string</c>.</summary>
    public void WriteString(ReadOnlySpan<byte> value)
    {
        WriteUInt32((uint)value.Length);
        WriteRaw(value);
    }

    /// <summary>Appends an ASCII <c>string</c>.</summary>
    public void WriteString(string value) => WriteString(System.Text.Encoding.ASCII.GetBytes(value));

    /// <summary>Appends a non-negative <c>mpint</c> from its big-endian magnitude (leading zeros are dropped).</summary>
    public void WriteMpint(ReadOnlySpan<byte> magnitude)
    {
        while (!magnitude.IsEmpty && magnitude[0] == 0)
        {
            magnitude = magnitude[1..];
        }

        bool pad = !magnitude.IsEmpty && (magnitude[0] & 0x80) != 0;
        WriteUInt32((uint)(magnitude.Length + (pad ? 1 : 0)));
        if (pad)
        {
            WriteByte(0);
        }

        WriteRaw(magnitude);
    }

    /// <summary>A copy of the bytes written. The caller owns it and should zero it if it holds a secret.</summary>
    public byte[] ToArray() => _buffer.AsSpan(0, _length).ToArray();

    /// <summary>Zeroes the buffer.</summary>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_buffer);
        _length = 0;
    }

    private void Reserve(int extra)
    {
        if (_length + extra <= _buffer.Length)
        {
            return;
        }

        byte[] bigger = GC.AllocateUninitializedArray<byte>(Math.Max(_buffer.Length * 2, _length + extra), pinned: true);
        _buffer.AsSpan(0, _length).CopyTo(bigger);
        CryptographicOperations.ZeroMemory(_buffer);
        _buffer = bigger;
    }
}
