namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>Why OpenPGP data was rejected.</summary>
public enum OpenPgpError
{
    /// <summary>The input is malformed in a way no other reason describes.</summary>
    Invalid = 0,

    /// <summary>The input ends before the structure it started is complete.</summary>
    Truncated,

    /// <summary>A packet header is invalid (RFC 9580 §4.2): the first octet has bit 7 clear, or a length form is not allowed.</summary>
    InvalidPacketHeader,

    /// <summary>A packet body is longer than <see cref="OpenPgpLimits.MaxPacketBodyLength"/>.</summary>
    PacketTooLarge,

    /// <summary>A length field claims more data than the packet (or the input) holds.</summary>
    LengthExceedsData,

    /// <summary>More packets than <see cref="OpenPgpLimits.MaxPackets"/>.</summary>
    TooManyPackets,

    /// <summary>More subpackets than <see cref="OpenPgpLimits.MaxSubpackets"/> in one area.</summary>
    TooManySubpackets,

    /// <summary>A multiprecision integer is malformed or longer than <see cref="OpenPgpLimits.MaxMpiBits"/>.</summary>
    InvalidMpi,

    /// <summary>A field holds a value the format does not allow (a reserved algorithm, a bad count, a wrong fixed size).</summary>
    InvalidField,

    /// <summary>Data follows a structure that must be last.</summary>
    TrailingData,

    /// <summary>The armor header line is missing, unknown or does not match the tail line.</summary>
    InvalidArmorHeader,

    /// <summary>An armor header line (RFC 9580 §6.2.2) is not a key and value, or there are too many of them.</summary>
    InvalidArmorHeaders,

    /// <summary>The Radix-64 data contains a character it must not, or has an invalid length.</summary>
    InvalidBase64,

    /// <summary>The armor checksum (RFC 9580 §6.1) is present and wrong.</summary>
    BadArmorChecksum,

    /// <summary>The armor block has no tail line.</summary>
    MissingArmorTail,

    /// <summary>The armored data is larger than <see cref="OpenPgpLimits.MaxArmoredBytes"/>.</summary>
    ArmorTooLarge,

    /// <summary>A packet sequence does not form the structure asked for (for example a transferable key, RFC 9580 §10.1).</summary>
    InvalidStructure,
}

/// <summary>The reason and the position of a rejection.</summary>
/// <param name="Error">The reason.</param>
/// <param name="Offset">Offset in octets from the start of the input being read (the packet stream, packet body or armor text, as the message says).</param>
/// <param name="Detail">A short phrase naming the field or rule, or null.</param>
public readonly record struct OpenPgpFailure(OpenPgpError Error, long Offset, string? Detail = null)
{
    /// <summary>A sentence describing the reason, with the offset.</summary>
    public string Message => (Detail is null ? Describe(Error) : $"{Describe(Error)}: {Detail}") + $" (offset {Offset}).";

    /// <summary>Creates the exception for this failure.</summary>
    public OpenPgpParseException ToException() => new(this);

    internal static string Describe(OpenPgpError e) => e switch
    {
        OpenPgpError.Truncated => "The input is truncated",
        OpenPgpError.InvalidPacketHeader => "The packet header is invalid",
        OpenPgpError.PacketTooLarge => "The packet is larger than the configured limit",
        OpenPgpError.LengthExceedsData => "A length is larger than the data that holds it",
        OpenPgpError.TooManyPackets => "Too many packets",
        OpenPgpError.TooManySubpackets => "Too many subpackets",
        OpenPgpError.InvalidMpi => "A multiprecision integer is invalid",
        OpenPgpError.InvalidField => "A field has an invalid value",
        OpenPgpError.TrailingData => "Unexpected data follows the structure",
        OpenPgpError.InvalidArmorHeader => "The armor header or tail line is invalid",
        OpenPgpError.InvalidArmorHeaders => "The armor headers are invalid",
        OpenPgpError.InvalidBase64 => "The Radix-64 data is invalid",
        OpenPgpError.BadArmorChecksum => "The armor checksum does not match",
        OpenPgpError.MissingArmorTail => "The armor tail line is missing",
        OpenPgpError.ArmorTooLarge => "The armored data is larger than the configured limit",
        OpenPgpError.InvalidStructure => "The packets do not form the expected structure",
        _ => "The input is invalid",
    };
}

/// <summary>OpenPGP data is malformed under the rules in force. Carries the reason and the offset; nothing else is thrown for bad input.</summary>
public sealed class OpenPgpParseException : FormatException
{
    /// <summary>Creates the exception for a failure.</summary>
    public OpenPgpParseException(OpenPgpFailure failure)
        : base(failure.Message)
    {
        Failure = failure;
    }

    /// <summary>Creates the exception with a reason, an offset and an optional detail.</summary>
    public OpenPgpParseException(OpenPgpError error, long offset, string? detail = null)
        : this(new OpenPgpFailure(error, offset, detail))
    {
    }

    /// <summary>Creates an exception with a message and the reason <see cref="OpenPgpError.Invalid"/>.</summary>
    public OpenPgpParseException(string message)
        : base(message)
    {
        Failure = new OpenPgpFailure(OpenPgpError.Invalid, 0);
    }

    /// <summary>Creates an exception with a message and an inner exception.</summary>
    public OpenPgpParseException(string message, Exception innerException)
        : base(message, innerException)
    {
        Failure = new OpenPgpFailure(OpenPgpError.Invalid, 0);
    }

    /// <summary>Creates an exception with no details.</summary>
    public OpenPgpParseException()
        : this(new OpenPgpFailure(OpenPgpError.Invalid, 0))
    {
    }

    /// <summary>The reason and offset.</summary>
    public OpenPgpFailure Failure { get; }

    /// <summary>The reason.</summary>
    public OpenPgpError Error => Failure.Error;

    /// <summary>Offset in octets from the start of the input being read.</summary>
    public long Offset => Failure.Offset;
}

/// <summary>
/// Resource limits for reading untrusted OpenPGP data. Each is checked before the memory it bounds is committed. The defaults suit keys,
/// signatures and ordinary messages; streamed data packets (literal, compressed, encrypted) are never buffered, so they are bounded by
/// time only.
/// </summary>
public sealed class OpenPgpLimits
{
    /// <summary>The defaults: 16 MiB per buffered packet body, 1 Mi packets, 4,096 subpackets per area, 64 KiB per MPI, 64 session-key packets per encrypted layer, 64 GiB of armored data.</summary>
    public static OpenPgpLimits Default { get; } = new();

    /// <summary>Largest body, in octets, that is read into memory as one packet. A streamed body is not limited. Default 16 MiB.</summary>
    public long MaxPacketBodyLength { get; init; } = 16L << 20;

    /// <summary>Most packets <see cref="PacketParser"/> returns from one input. Default 1,048,576.</summary>
    public int MaxPackets { get; init; } = 1 << 20;

    /// <summary>Most subpackets in one hashed or unhashed area. Default 4,096.</summary>
    public int MaxSubpackets { get; init; } = 4096;

    /// <summary>Largest multiprecision integer, in bits (RFC 9580 §3.2 allows 65,535). Default 65,535.</summary>
    public int MaxMpiBits { get; init; } = 65535;

    /// <summary>
    /// Most public-key and password session-key packets (tags 1 and 3) in front of one encrypted layer. Each can cost a private-key operation or a
    /// key derivation, so a message with more is refused with <see cref="PgpFailure.LimitExceeded"/> before any is tried. Default 64.
    /// </summary>
    public int MaxSessionKeyPackets { get; init; } = 64;

    /// <summary>
    /// Total string-to-key work a single read may spend on password session-key packets, in units of one KiB hashed (iterated-and-salted) or one
    /// KiB of memory per pass (Argon2). A packet that would exceed the rest of the budget is skipped, so a hostile packet cannot cost more than the
    /// budget however many are sent. Default 8,388,608: four Argon2 runs at 2 GiB with one pass, or a hundred maximal iterated-and-salted runs.
    /// </summary>
    public long MaxS2kWork { get; init; } = 1L << 23;

    /// <summary>Longest armor line (header, header key or Radix-64 line) accepted, in characters. Default 8,192.</summary>
    public int MaxArmorLineLength { get; init; } = 8192;

    /// <summary>Most armor header lines (RFC 9580 §6.2.2). Default 256.</summary>
    public int MaxArmorHeaders { get; init; } = 256;

    /// <summary>Most decoded octets one armor block may hold. Default 64 GiB.</summary>
    public long MaxArmoredBytes { get; init; } = 1L << 36;
}
