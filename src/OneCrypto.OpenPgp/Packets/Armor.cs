using System.Text;

namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>The kind of data an armor header line announces (RFC 9580 §6.2.1).</summary>
public enum ArmorKind
{
    /// <summary>A header line this layer does not know.</summary>
    Unknown = 0,

    /// <summary>BEGIN PGP MESSAGE: signed, encrypted or compressed data.</summary>
    Message,

    /// <summary>BEGIN PGP PUBLIC KEY BLOCK.</summary>
    PublicKey,

    /// <summary>BEGIN PGP PRIVATE KEY BLOCK.</summary>
    PrivateKey,

    /// <summary>BEGIN PGP SIGNATURE: a detached signature, or the signature of a cleartext signed message.</summary>
    Signature,

    /// <summary>BEGIN PGP MESSAGE, PART X or PART X/Y: a legacy split message.</summary>
    MessagePart,

    /// <summary>BEGIN PGP SIGNED MESSAGE: the start of a cleartext signed message, whose body is text, not Radix-64. Not decoded by <see cref="ArmorReadStream"/>.</summary>
    CleartextSigned,
}

/// <summary>Options for reading ASCII armor.</summary>
public sealed class ArmorReadOptions
{
    /// <summary>Lenient reading: text before the header line is skipped, trailing data is ignored, and Radix-64 lines of any length up to the limit are accepted.</summary>
    public static ArmorReadOptions Lenient { get; } = new();

    /// <summary>
    /// Strict reading: nothing before the header line, nothing but white space after the tail line, Radix-64 lines of at most 76 characters
    /// (RFC 9580 §6), and only the header lines the RFC defines.
    /// </summary>
    public static ArmorReadOptions Strict { get; } = new() { AllowLeadingText = false, AllowTrailingData = false, MaxDataLineLength = 76, AllowUnknownKinds = false };

    /// <summary>True to skip lines before the header line. Default true.</summary>
    public bool AllowLeadingText { get; init; } = true;

    /// <summary>True to ignore what follows the tail line. Default true.</summary>
    public bool AllowTrailingData { get; init; } = true;

    /// <summary>The longest Radix-64 line accepted, in characters. Default 8,192 (the limit in <see cref="OpenPgpLimits"/> also applies).</summary>
    public int MaxDataLineLength { get; init; } = 8192;

    /// <summary>True to accept header lines other than the five RFC 9580 defines. Default true.</summary>
    public bool AllowUnknownKinds { get; init; } = true;
}

/// <summary>Options for writing ASCII armor.</summary>
public sealed class ArmorWriteOptions
{
    /// <summary>Radix-64 line length of 64 characters, no checksum, no headers: the form most implementations write.</summary>
    public static ArmorWriteOptions Default { get; } = new();

    /// <summary>Characters per Radix-64 line, 4 to 76 and a multiple of 4. Default 64.</summary>
    public int LineLength { get; init; } = 64;

    /// <summary>True to write the optional CRC-24 line (RFC 9580 §6.1 discourages it). Default false.</summary>
    public bool Checksum { get; init; }

    /// <summary>Armor header key/value pairs to write after the header line, in order. Default none.</summary>
    public IReadOnlyList<KeyValuePair<string, string>>? Headers { get; init; }
}

/// <summary>ASCII armor (RFC 9580 §6) helpers: labels, the CRC-24, and one-shot encode and decode.</summary>
public static class Armor
{
    private static readonly uint[] CrcTable = BuildCrcTable();

    /// <summary>The label text for a kind, for example "PGP PUBLIC KEY BLOCK"; null for kinds without a fixed label.</summary>
    /// <param name="kind">The kind.</param>
    public static string? LabelOf(ArmorKind kind) => kind switch
    {
        ArmorKind.Message => "PGP MESSAGE",
        ArmorKind.PublicKey => "PGP PUBLIC KEY BLOCK",
        ArmorKind.PrivateKey => "PGP PRIVATE KEY BLOCK",
        ArmorKind.Signature => "PGP SIGNATURE",
        ArmorKind.CleartextSigned => "PGP SIGNED MESSAGE",
        _ => null,
    };

    /// <summary>Classifies a header line label (the text between "BEGIN " and the closing dashes).</summary>
    /// <param name="label">The label, for example "PGP MESSAGE".</param>
    public static ArmorKind KindOf(string label)
    {
        ArgumentNullException.ThrowIfNull(label);
        return label switch
        {
            "PGP MESSAGE" => ArmorKind.Message,
            "PGP PUBLIC KEY BLOCK" => ArmorKind.PublicKey,
            "PGP PRIVATE KEY BLOCK" => ArmorKind.PrivateKey,
            "PGP SIGNATURE" => ArmorKind.Signature,
            "PGP SIGNED MESSAGE" => ArmorKind.CleartextSigned,
            _ when label.StartsWith("PGP MESSAGE, PART ", StringComparison.Ordinal) => ArmorKind.MessagePart,
            _ => ArmorKind.Unknown,
        };
    }

    /// <summary>True if the first octet of binary input suggests armor rather than a packet: bit 7 of a packet's first octet is always set (RFC 9580 §4.2).</summary>
    /// <param name="firstOctet">The first octet of the input.</param>
    public static bool LooksArmored(byte firstOctet) => (firstOctet & 0x80) == 0;

    /// <summary>The CRC-24 of RFC 9580 §6.1.1 (initial value 0xB704CE, polynomial 0x864CFB), continuing from <paramref name="crc"/>.</summary>
    /// <param name="crc">The running value; start from 0xB704CE.</param>
    /// <param name="data">The octets to add.</param>
    public static uint Crc24(uint crc, ReadOnlySpan<byte> data)
    {
        foreach (byte b in data)
        {
            crc = (crc << 8) ^ CrcTable[((crc >> 16) ^ b) & 0xFF];
            crc &= 0xFFFFFF;
        }

        return crc;
    }

    /// <summary>The CRC-24 initial value, 0xB704CE.</summary>
    public const uint Crc24Init = 0xB704CE;

    /// <summary>Armors <paramref name="data"/> into text.</summary>
    /// <param name="label">The text between BEGIN and the dashes, for example "PGP PUBLIC KEY BLOCK".</param>
    /// <param name="data">The binary data.</param>
    /// <param name="options">Line length, checksum and headers; <see cref="ArmorWriteOptions.Default"/> when null.</param>
    /// <returns>The armor, ending in a line feed.</returns>
    public static string Encode(string label, ReadOnlySpan<byte> data, ArmorWriteOptions? options = null)
    {
        using var ms = new MemoryStream();
        using (var w = new ArmorWriteStream(ms, label, options, leaveOpen: true))
        {
            w.Write(data);
        }

        return Encoding.ASCII.GetString(ms.GetBuffer(), 0, (int)ms.Length);
    }

    /// <summary>Armors <paramref name="data"/> into text using the label for <paramref name="kind"/>.</summary>
    /// <param name="kind">One of the kinds with a fixed label.</param>
    /// <param name="data">The binary data.</param>
    /// <param name="options">Line length, checksum and headers.</param>
    public static string Encode(ArmorKind kind, ReadOnlySpan<byte> data, ArmorWriteOptions? options = null) =>
        Encode(LabelOf(kind) ?? throw new ArgumentOutOfRangeException(nameof(kind), "This kind has no fixed label."), data, options);

    /// <summary>Decodes one armor block from memory.</summary>
    /// <param name="armored">The ASCII text.</param>
    /// <param name="options">Reading options; <see cref="ArmorReadOptions.Lenient"/> when null.</param>
    /// <param name="limits">Resource limits; <see cref="OpenPgpLimits.Default"/> when null.</param>
    /// <returns>The decoded block.</returns>
    /// <exception cref="OpenPgpParseException">The text is not well-formed armor.</exception>
    public static ArmorBlock Decode(ReadOnlySpan<byte> armored, ArmorReadOptions? options = null, OpenPgpLimits? limits = null)
    {
        using var ms = new MemoryStream(armored.ToArray(), false);
        using var r = new ArmorReadStream(ms, options, limits, leaveOpen: true);
        using var data = new MemoryStream();
        r.CopyTo(data);
        return new ArmorBlock(r.Label, r.Headers, data.ToArray(), r.HasChecksum);
    }

    /// <summary>Like <see cref="Decode"/> without throwing for bad input.</summary>
    /// <param name="armored">The ASCII text.</param>
    /// <param name="block">The decoded block, or null.</param>
    /// <param name="failure">The reason when the result is false.</param>
    /// <param name="options">Reading options.</param>
    /// <param name="limits">Resource limits.</param>
    public static bool TryDecode(ReadOnlySpan<byte> armored, out ArmorBlock? block, out OpenPgpFailure failure, ArmorReadOptions? options = null, OpenPgpLimits? limits = null)
    {
        try
        {
            block = Decode(armored, options, limits);
            failure = default;
            return true;
        }
        catch (OpenPgpParseException e)
        {
            block = null;
            failure = e.Failure;
            return false;
        }
    }

    private static uint[] BuildCrcTable()
    {
        const uint poly = 0x864CFB;
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i << 16;
            for (int k = 0; k < 8; k++)
            {
                c <<= 1;
                if ((c & 0x1000000) != 0)
                {
                    c ^= poly;
                }
            }

            table[i] = c & 0xFFFFFF;
        }

        return table;
    }
}

/// <summary>A decoded armor block: the label, the headers in order, and the binary data.</summary>
public sealed class ArmorBlock
{
    internal ArmorBlock(string label, IReadOnlyList<KeyValuePair<string, string>> headers, byte[] data, bool hasChecksum)
    {
        Label = label;
        Headers = headers;
        Data = data;
        HasChecksum = hasChecksum;
    }

    /// <summary>The header line label, for example "PGP MESSAGE".</summary>
    public string Label { get; }

    /// <summary>The kind the label announces.</summary>
    public ArmorKind Kind => Armor.KindOf(Label);

    /// <summary>The armor headers (key and value) in the order they appeared.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; }

    /// <summary>The decoded octets.</summary>
    public byte[] Data { get; }

    /// <summary>True when the block carried a checksum line (it matched; a mismatch raises <see cref="OpenPgpError.BadArmorChecksum"/>).</summary>
    public bool HasChecksum { get; }
}

/// <summary>
/// Decodes ASCII armor (RFC 9580 §6) from a stream as it is read, in constant memory. The header line and headers are read on first use;
/// the checksum, when present, is verified when the data ends, so a mismatch is raised by the last read (data before it has been
/// delivered already). One block per stream; with <see cref="ArmorReadOptions.AllowTrailingData"/> false nothing but white space may follow.
/// </summary>
public sealed class ArmorReadStream : Stream
{
    private readonly ByteSource _source;
    private readonly ArmorReadOptions _options;
    private readonly OpenPgpLimits _limits;
    private readonly List<KeyValuePair<string, string>> _headers = [];
    private readonly byte[] _out = new byte[4096];
    private readonly byte[] _quad = new byte[4];
    private int _quadCount;
    private bool _padded;
    private int _outPos;
    private int _outLen;
    private bool _started;
    private bool _finished;
    private string _label = string.Empty;
    private uint _crc = Armor.Crc24Init;
    private long _decoded;
    private uint? _expectedCrc;
    private long _lineStart;

    /// <summary>Reads armor from a stream.</summary>
    /// <param name="input">ASCII text.</param>
    /// <param name="options">Reading options; <see cref="ArmorReadOptions.Lenient"/> when null.</param>
    /// <param name="limits">Resource limits; <see cref="OpenPgpLimits.Default"/> when null.</param>
    /// <param name="leaveOpen">True to leave <paramref name="input"/> open on dispose.</param>
    public ArmorReadStream(Stream input, ArmorReadOptions? options = null, OpenPgpLimits? limits = null, bool leaveOpen = true)
    {
        ArgumentNullException.ThrowIfNull(input);
        _source = new ByteSource(input, leaveOpen);
        _options = options ?? ArmorReadOptions.Lenient;
        _limits = limits ?? OpenPgpLimits.Default;
    }

    /// <summary>The header line label. Reads the header on first use.</summary>
    /// <exception cref="OpenPgpParseException">The header line or headers are malformed.</exception>
    public string Label
    {
        get
        {
            Start();
            return _label;
        }
    }

    /// <summary>The kind the label announces.</summary>
    public ArmorKind Kind => Armor.KindOf(Label);

    /// <summary>The armor headers in order. Reads the header on first use.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers
    {
        get
        {
            Start();
            return _headers;
        }
    }

    /// <summary>True once the data has ended and a checksum line was seen (and matched).</summary>
    public bool HasChecksum => _expectedCrc is not null;

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => false;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => _decoded;
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    /// <inheritdoc />
    public override int Read(Span<byte> buffer)
    {
        Start();
        if (buffer.IsEmpty)
        {
            return 0;
        }

        while (_outPos >= _outLen)
        {
            if (_finished)
            {
                return 0;
            }

            Refill();
        }

        int n = Math.Min(buffer.Length, _outLen - _outPos);
        _out.AsSpan(_outPos, n).CopyTo(buffer);
        _outPos += n;
        return n;
    }

    private void Start()
    {
        if (_started)
        {
            return;
        }

        _started = true;
        // RFC 9580 §6.2: header line, headers, a blank line. Text before the header line is not armor.
        string? line;
        while (true)
        {
            line = ReadLine();
            if (line is null)
            {
                throw Fail(OpenPgpError.InvalidArmorHeader, "no armor header line");
            }

            string t = line.TrimEnd(' ', '\t');
            if (t.StartsWith("-----BEGIN ", StringComparison.Ordinal) && t.EndsWith("-----", StringComparison.Ordinal) && t.Length > 16)
            {
                _label = t[11..^5];
                break;
            }

            if (!_options.AllowLeadingText && t.Length > 0)
            {
                throw Fail(OpenPgpError.InvalidArmorHeader, "text before the armor header line");
            }
        }

        ArmorKind kind = Armor.KindOf(_label);
        if (kind == ArmorKind.CleartextSigned)
        {
            throw Fail(OpenPgpError.InvalidArmorHeader, "a cleartext signed message is not Radix-64 data");
        }

        if (kind == ArmorKind.Unknown && (!_options.AllowUnknownKinds || !_label.StartsWith("PGP ", StringComparison.Ordinal)))
        {
            throw Fail(OpenPgpError.InvalidArmorHeader, "unknown armor header line");
        }

        while (true)
        {
            line = ReadLine() ?? throw Fail(OpenPgpError.MissingArmorTail, "end of input in the armor headers");
            if (line.Trim(' ', '\t').Length == 0)
            {
                break;
            }

            if (_headers.Count >= _limits.MaxArmorHeaders)
            {
                throw Fail(OpenPgpError.InvalidArmorHeaders, "too many armor headers");
            }

            int colon = line.IndexOf(": ", StringComparison.Ordinal);
            if (colon <= 0)
            {
                // RFC 9580 §6.2.2: the key is followed by a colon and a space. A header with an empty value may omit the space.
                if (line.EndsWith(':') && line.Length > 1)
                {
                    _headers.Add(new KeyValuePair<string, string>(line[..^1], string.Empty));
                    continue;
                }

                throw Fail(OpenPgpError.InvalidArmorHeaders, "armor header is not a key and value");
            }

            _headers.Add(new KeyValuePair<string, string>(line[..colon], line[(colon + 2)..].TrimEnd(' ', '\t')));
        }
    }

    private void Refill()
    {
        _outPos = 0;
        _outLen = 0;
        while (_outLen == 0 && !_finished)
        {
            string? line = ReadLine() ?? throw Fail(OpenPgpError.MissingArmorTail, "end of input before the armor tail line");
            string t = line.Trim(' ', '\t');
            if (t.StartsWith("-----END ", StringComparison.Ordinal))
            {
                FinishBlock(t);
                return;
            }

            if (t.Length == 0)
            {
                continue;
            }

            if (t[0] == '=' && t.Length == 5)
            {
                // RFC 9580 §6.1: an optional "=" followed by four Radix-64 characters, the CRC-24.
                uint v = 0;
                for (int i = 1; i < 5; i++)
                {
                    v = (v << 6) | (uint)Sextet(t[i]);
                }

                _expectedCrc = v;
                // The decoded form is 24 bits in 4 characters: v is already 24 bits.
                continue;
            }

            if (_expectedCrc is not null)
            {
                throw Fail(OpenPgpError.InvalidBase64, "data after the armor checksum");
            }

            if (t.Length > _options.MaxDataLineLength || t.Length > _limits.MaxArmorLineLength)
            {
                throw Fail(OpenPgpError.InvalidBase64, "Radix-64 line too long");
            }

            DecodeLine(t);
        }
    }

    private void DecodeLine(string line)
    {
        int produced = 0;
        Span<byte> outSpan = _out;
        foreach (char ch in line)
        {
            if (ch is ' ' or '\t')
            {
                continue;
            }

            if (ch == '=')
            {
                if (_quadCount < 2)
                {
                    throw Fail(OpenPgpError.InvalidBase64, "misplaced padding");
                }

                _padded = true;
                continue;
            }

            if (_padded)
            {
                throw Fail(OpenPgpError.InvalidBase64, "data after padding");
            }

            _quad[_quadCount++] = (byte)Sextet(ch);
            if (_quadCount == 4)
            {
                outSpan[produced++] = (byte)((_quad[0] << 2) | (_quad[1] >> 4));
                outSpan[produced++] = (byte)((_quad[1] << 4) | (_quad[2] >> 2));
                outSpan[produced++] = (byte)((_quad[2] << 6) | _quad[3]);
                _quadCount = 0;
            }
        }

        if (_padded && _quadCount > 0)
        {
            produced += FlushPartial(outSpan[produced..]);
        }

        _outLen = produced;
        Account(produced);
    }

    private int FlushPartial(Span<byte> destination)
    {
        // A group of two or three characters carries one or two octets; the rest of the quad was padding (RFC 4648 §4).
        int n = 0;
        if (_quadCount >= 2)
        {
            destination[n++] = (byte)((_quad[0] << 2) | (_quad[1] >> 4));
        }

        if (_quadCount == 3)
        {
            destination[n++] = (byte)((_quad[1] << 4) | (_quad[2] >> 2));
        }

        _quadCount = 0;
        return n;
    }

    private void Account(int produced)
    {
        _decoded += produced;
        if (_decoded > _limits.MaxArmoredBytes)
        {
            throw Fail(OpenPgpError.ArmorTooLarge);
        }

        _crc = Armor.Crc24(_crc, _out.AsSpan(0, produced));
    }

    private void FinishBlock(string tail)
    {
        // An unpadded final group of two or three characters is accepted; a single leftover character is not a valid group.
        if (_quadCount == 1)
        {
            throw Fail(OpenPgpError.InvalidBase64, "truncated Radix-64 group");
        }

        if (_quadCount > 0)
        {
            int n = FlushPartial(_out);
            _outLen = n;
            Account(n);
        }

        if (!tail.EndsWith("-----", StringComparison.Ordinal) || tail[9..^5] != _label)
        {
            throw Fail(OpenPgpError.InvalidArmorHeader, "armor tail line does not match the header line");
        }

        if (_expectedCrc is uint expected && expected != _crc)
        {
            // Data already returned cannot be taken back; the exception is raised now, from the read that reaches the end.
            _finished = true;
            throw Fail(OpenPgpError.BadArmorChecksum);
        }

        _finished = true;
        if (!_options.AllowTrailingData)
        {
            int b;
            while ((b = _source.ReadByte()) >= 0)
            {
                if (b is not (' ' or '\t' or '\r' or '\n'))
                {
                    throw Fail(OpenPgpError.TrailingData, "data after the armor tail line");
                }
            }
        }
    }

    private static int Sextet(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= 'a' and <= 'z' => c - 'a' + 26,
        >= '0' and <= '9' => c - '0' + 52,
        '+' => 62,
        '/' => 63,
        _ => throw new OpenPgpParseException(OpenPgpError.InvalidBase64, 0, "invalid character"),
    };

    private string? ReadLine()
    {
        _lineStart = _source.Position;
        var sb = new StringBuilder();
        int b;
        while ((b = _source.ReadByte()) >= 0)
        {
            if (b == '\n')
            {
                if (sb.Length > 0 && sb[^1] == '\r')
                {
                    sb.Length--;
                }

                return sb.ToString();
            }

            if (b >= 0x80)
            {
                // Armor is 7-bit text; a high bit in a data line is invalid, and header values are limited to ASCII here as well.
                throw Fail(OpenPgpError.InvalidBase64, "non-ASCII octet");
            }

            sb.Append((char)b);
            if (sb.Length > _limits.MaxArmorLineLength + 2)
            {
                throw Fail(OpenPgpError.InvalidArmorHeader, "armor line too long");
            }
        }

        return sb.Length > 0 ? sb.ToString() : null;
    }

    private OpenPgpParseException Fail(OpenPgpError error, string? detail = null) => new(error, _lineStart, detail);

    /// <inheritdoc />
    public override void Flush()
    {
    }

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _source.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// Writes ASCII armor (RFC 9580 §6) around the octets written to it, in constant memory. The header line is written when the stream is
/// created; the final partial group, the optional checksum and the tail line when it is completed or disposed.
/// </summary>
public sealed class ArmorWriteStream : Stream
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private readonly Stream _output;
    private readonly bool _leaveOpen;
    private readonly string _label;
    private readonly int _lineLength;
    private readonly bool _checksum;
    private readonly byte[] _line;
    private int _lineFill;
    private readonly byte[] _group = new byte[3];
    private int _groupFill;
    private uint _crc = Armor.Crc24Init;
    private bool _completed;

    /// <summary>Starts an armor block.</summary>
    /// <param name="output">Where the text goes.</param>
    /// <param name="label">The text between BEGIN and the dashes, for example "PGP MESSAGE".</param>
    /// <param name="options">Line length, checksum and headers; <see cref="ArmorWriteOptions.Default"/> when null.</param>
    /// <param name="leaveOpen">True to leave <paramref name="output"/> open on dispose.</param>
    /// <exception cref="ArgumentException">The label or a header contains a line break, or the line length is not a multiple of 4 from 4 to 76.</exception>
    public ArmorWriteStream(Stream output, string label, ArmorWriteOptions? options = null, bool leaveOpen = true)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(label);
        options ??= ArmorWriteOptions.Default;
        if (label.AsSpan().IndexOfAny('\r', '\n') >= 0 || label.Length == 0)
        {
            throw new ArgumentException("The label must be one line.", nameof(label));
        }

        if (options.LineLength is < 4 or > 76 || options.LineLength % 4 != 0)
        {
            throw new ArgumentException("The line length must be a multiple of 4 from 4 to 76.", nameof(options));
        }

        _output = output;
        _leaveOpen = leaveOpen;
        _label = label;
        _lineLength = options.LineLength;
        _checksum = options.Checksum;
        _line = new byte[_lineLength + 1];
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).Append("-----\n");
        if (options.Headers is { } headers)
        {
            foreach (KeyValuePair<string, string> h in headers)
            {
                if (h.Key.AsSpan().IndexOfAny('\r', '\n', ':') >= 0 || h.Value.AsSpan().IndexOfAny('\r', '\n') >= 0)
                {
                    throw new ArgumentException("An armor header is one line, and its key has no colon.", nameof(options));
                }

                sb.Append(h.Key).Append(": ").Append(h.Value).Append('\n');
            }
        }

        sb.Append('\n');
        output.Write(Encoding.ASCII.GetBytes(sb.ToString()));
    }

    /// <inheritdoc />
    public override bool CanRead => false;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => true;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    /// <inheritdoc />
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_completed, this);
        _crc = Armor.Crc24(_crc, buffer);
        foreach (byte b in buffer)
        {
            _group[_groupFill++] = b;
            if (_groupFill == 3)
            {
                Emit(Alphabet[_group[0] >> 2], Alphabet[((_group[0] & 3) << 4) | (_group[1] >> 4)],
                    Alphabet[((_group[1] & 15) << 2) | (_group[2] >> 6)], Alphabet[_group[2] & 63]);
                _groupFill = 0;
            }
        }
    }

    /// <summary>Writes the final group, the checksum and the tail line. Further writes are refused. Called by dispose.</summary>
    public void Complete()
    {
        if (_completed)
        {
            return;
        }

        if (_groupFill == 1)
        {
            Emit(Alphabet[_group[0] >> 2], Alphabet[(_group[0] & 3) << 4], '=', '=');
        }
        else if (_groupFill == 2)
        {
            Emit(Alphabet[_group[0] >> 2], Alphabet[((_group[0] & 3) << 4) | (_group[1] >> 4)], Alphabet[(_group[1] & 15) << 2], '=');
        }

        _groupFill = 0;
        FlushLine();
        if (_checksum)
        {
            _output.WriteByte((byte)'=');
            _output.Write(Encoding.ASCII.GetBytes(
                [Alphabet[(int)(_crc >> 18) & 63], Alphabet[(int)(_crc >> 12) & 63], Alphabet[(int)(_crc >> 6) & 63], Alphabet[(int)_crc & 63]]));
            _output.WriteByte((byte)'\n');
        }

        _output.Write(Encoding.ASCII.GetBytes("-----END " + _label + "-----\n"));
        _completed = true;
    }

    private void Emit(char a, char b, char c, char d)
    {
        _line[_lineFill++] = (byte)a;
        _line[_lineFill++] = (byte)b;
        _line[_lineFill++] = (byte)c;
        _line[_lineFill++] = (byte)d;
        if (_lineFill >= _lineLength)
        {
            FlushLine();
        }
    }

    private void FlushLine()
    {
        if (_lineFill == 0)
        {
            return;
        }

        _line[_lineFill] = (byte)'\n';
        _output.Write(_line, 0, _lineFill + 1);
        _lineFill = 0;
    }

    /// <inheritdoc />
    public override void Flush() => _output.Flush();

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Complete();
            if (!_leaveOpen)
            {
                _output.Dispose();
            }
        }

        base.Dispose(disposing);
    }
}
