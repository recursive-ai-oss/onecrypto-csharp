namespace RecursiveAI.OneCrypto.Asn1;

/// <summary>Why ASN.1 input was rejected.</summary>
public enum Asn1Error
{
    /// <summary>No error.</summary>
    None = 0,

    /// <summary>The input ends inside an element, or where one was required.</summary>
    Truncated,

    /// <summary>The identifier octets are malformed or the tag number does not fit (X.690 clause 8.1.2).</summary>
    InvalidTag,

    /// <summary>The length octets are malformed (X.690 clause 8.1.3), for example the reserved 0xFF or an indefinite primitive.</summary>
    InvalidLength,

    /// <summary>The declared length is larger than the data that remains, or larger than the configured limit.</summary>
    LengthExceedsData,

    /// <summary>The tag number is not in its shortest form (X.690 clause 8.1.2.2 and 8.1.2.4.2).</summary>
    NonMinimalTag,

    /// <summary>A definite length is not in its shortest form; DER and CER forbid that (X.690 clause 10.1).</summary>
    NonMinimalLength,

    /// <summary>The rules in force forbid this length form: indefinite in DER, definite constructed in CER (X.690 clause 9.1, 10.1).</summary>
    LengthFormNotAllowed,

    /// <summary>Elements are nested deeper than <see cref="Asn1Limits.MaxDepth"/>.</summary>
    DepthExceeded,

    /// <summary>More elements than <see cref="Asn1Limits.MaxScanElements"/> were examined to find the end of one element.</summary>
    TooManyElements,

    /// <summary>The input is larger than <see cref="Asn1Limits.MaxTotalSize"/>.</summary>
    TotalSizeExceeded,

    /// <summary>The next element does not have the tag the caller asked for.</summary>
    UnexpectedTag,

    /// <summary>The element has the right tag but its content is not a valid value of the type.</summary>
    InvalidContent,

    /// <summary>The content is valid BER but not the one encoding DER or CER allows (X.690 clause 10, 11).</summary>
    NotCanonical,

    /// <summary>The type must be primitive here, or the constructed form is not accepted by this call.</summary>
    ConstructedNotAllowed,

    /// <summary>The value does not fit the .NET type requested.</summary>
    ValueOutOfRange,

    /// <summary>Bytes remain after the last element where none are allowed.</summary>
    TrailingData,

    /// <summary>The destination buffer is too small.</summary>
    DestinationTooSmall,
}

/// <summary>The reason and the position of a rejection.</summary>
/// <param name="Error">The reason.</param>
/// <param name="Offset">Offset from the start of the outermost input to the element (or octet) that was rejected.</param>
public readonly record struct Asn1Failure(Asn1Error Error, int Offset)
{
    /// <summary>A sentence describing the reason, with the offset.</summary>
    public string Message => $"{Describe(Error)} (offset {Offset}).";

    /// <summary>Creates the exception for this failure.</summary>
    public Asn1ParseException ToException() => new(this);

    internal static string Describe(Asn1Error e) => e switch
    {
        Asn1Error.Truncated => "The input is truncated",
        Asn1Error.InvalidTag => "The identifier octets are invalid",
        Asn1Error.InvalidLength => "The length octets are invalid",
        Asn1Error.LengthExceedsData => "The element is longer than the data that holds it",
        Asn1Error.NonMinimalTag => "The tag number is not in its shortest form",
        Asn1Error.NonMinimalLength => "The length is not in its shortest form",
        Asn1Error.LengthFormNotAllowed => "The length form is not allowed by the encoding rules",
        Asn1Error.DepthExceeded => "The elements are nested too deeply",
        Asn1Error.TooManyElements => "Too many elements",
        Asn1Error.TotalSizeExceeded => "The input is larger than the configured limit",
        Asn1Error.UnexpectedTag => "The element does not have the expected tag",
        Asn1Error.InvalidContent => "The content is not a valid value of its type",
        Asn1Error.NotCanonical => "The encoding is not canonical",
        Asn1Error.ConstructedNotAllowed => "The constructed form is not allowed here",
        Asn1Error.ValueOutOfRange => "The value does not fit the requested type",
        Asn1Error.TrailingData => "Unexpected data follows the element",
        Asn1Error.DestinationTooSmall => "The destination is too small",
        _ => "The input is invalid",
    };
}

/// <summary>The input is not valid ASN.1 under the rules in force. Carries the reason and the offset.</summary>
public sealed class Asn1ParseException : FormatException
{
    /// <summary>Creates the exception for a failure.</summary>
    public Asn1ParseException(Asn1Failure failure)
        : base(failure.Message)
    {
        Failure = failure;
    }

    /// <summary>Creates the exception with a reason and an offset.</summary>
    public Asn1ParseException(Asn1Error error, int offset)
        : this(new Asn1Failure(error, offset))
    {
    }

    /// <summary>Creates an exception with a message and the reason <see cref="Asn1Error.InvalidContent"/>.</summary>
    public Asn1ParseException(string message)
        : base(message)
    {
        Failure = new Asn1Failure(Asn1Error.InvalidContent, 0);
    }

    /// <summary>Creates an exception with a message and an inner exception.</summary>
    public Asn1ParseException(string message, Exception innerException)
        : base(message, innerException)
    {
        Failure = new Asn1Failure(Asn1Error.InvalidContent, 0);
    }

    /// <summary>Creates an exception with no details.</summary>
    public Asn1ParseException()
        : this(new Asn1Failure(Asn1Error.InvalidContent, 0))
    {
    }

    /// <summary>The reason and offset.</summary>
    public Asn1Failure Failure { get; }

    /// <summary>The reason.</summary>
    public Asn1Error Error => Failure.Error;

    /// <summary>Offset from the start of the outermost input.</summary>
    public int Offset => Failure.Offset;
}

/// <summary>
/// Resource limits for reading untrusted ASN.1. The defaults suit certificates, CMS and similar documents; every limit is checked
/// before memory is committed for the thing it limits.
/// </summary>
public sealed class Asn1Limits
{
    /// <summary>The defaults: depth 64, 1 Mi elements per scan, 64 GiB total, 256 MiB for any one element copied out of the input.</summary>
    public static Asn1Limits Default { get; } = new();

    /// <summary>Deepest nesting of constructed elements. A reader started on a child continues from its parent's depth. Default 64.</summary>
    public int MaxDepth { get; init; } = 64;

    /// <summary>
    /// Most elements examined while looking for the end of one indefinite-length element, which bounds the work hostile input can cost
    /// a parser that revisits it. Default 1,048,576.
    /// </summary>
    public int MaxScanElements { get; init; } = 1 << 20;

    /// <summary>Largest input a reader accepts, in octets: a span longer than this is refused outright, and the stream reader stops at this many octets. Default 64 GiB.</summary>
    public long MaxTotalSize { get; init; } = 1L << 36;

    /// <summary>Largest value copied into a new array when joining constructed strings or reading from a stream. Default 256 MiB.</summary>
    public int MaxCopiedLength { get; init; } = 1 << 28;

    /// <summary>Most nested levels of constructed string segments accepted (X.690 clause 8.7.3 allows any). Default 4.</summary>
    public int MaxStringNesting { get; init; } = 4;
}
