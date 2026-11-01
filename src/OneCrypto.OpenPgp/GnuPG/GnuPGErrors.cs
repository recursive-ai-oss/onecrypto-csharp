namespace RecursiveAI.OneCrypto.OpenPgp.GnuPG;

/// <summary>Why a GnuPG file (keybox, key file, trust database, owner-trust export) or a cert-d entry was rejected.</summary>
public enum GnuPGError
{
    /// <summary>The input is malformed in a way no other reason describes.</summary>
    Invalid = 0,

    /// <summary>The input ends before the structure it started is complete.</summary>
    Truncated,

    /// <summary>A magic number, record type or version is not one this reader knows.</summary>
    BadHeader,

    /// <summary>A length, offset or count points outside the blob or file that holds it.</summary>
    OutOfBounds,

    /// <summary>A size, count or nesting depth exceeds <see cref="GnuPGLimits"/>.</summary>
    LimitExceeded,

    /// <summary>The checksum or integrity value stored with the data does not match.</summary>
    BadChecksum,

    /// <summary>A text field (a header line, an S-expression, a fingerprint line) is not well formed.</summary>
    BadSyntax,

    /// <summary>The OpenPGP data inside the container is not a well-formed transferable key.</summary>
    BadOpenPgp,

    /// <summary>The key uses an algorithm, curve or protection mode this reader does not handle.</summary>
    Unsupported,
}

/// <summary>The reason and the position of a rejection.</summary>
/// <param name="Error">The reason.</param>
/// <param name="Offset">Offset in octets (or the line number for text formats) from the start of the input being read.</param>
/// <param name="Detail">What was being read, or null.</param>
public readonly record struct GnuPGFailure(GnuPGError Error, long Offset, string? Detail = null)
{
    /// <summary>A sentence describing the failure and where it was found.</summary>
    public string Message => (Detail is null ? Error.ToString() : $"{Error}: {Detail}") + $" (at {Offset}).";

    /// <summary>The exception for this failure.</summary>
    public GnuPGFormatException ToException() => new(this);
}

/// <summary>Raised when a GnuPG file or cert-d entry is malformed. The <c>Try</c> forms of the readers return the same information as a <see cref="GnuPGFailure"/>.</summary>
public sealed class GnuPGFormatException : FormatException
{
    /// <summary>Creates the exception for a failure.</summary>
    /// <param name="failure">What went wrong and where.</param>
    public GnuPGFormatException(GnuPGFailure failure)
        : base(failure.Message)
    {
        Failure = failure;
    }

    /// <summary>Creates the exception from a reason and position.</summary>
    /// <param name="error">The reason.</param>
    /// <param name="offset">Where it was found.</param>
    /// <param name="detail">What was being read.</param>
    public GnuPGFormatException(GnuPGError error, long offset, string? detail = null)
        : this(new GnuPGFailure(error, offset, detail))
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public GnuPGFormatException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and a cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The cause.</param>
    public GnuPGFormatException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates an empty exception.</summary>
    public GnuPGFormatException()
    {
    }

    /// <summary>What went wrong and where.</summary>
    public GnuPGFailure Failure { get; }

    /// <summary>The reason.</summary>
    public GnuPGError Error => Failure.Error;
}

/// <summary>Resource limits for the GnuPG readers. They are on by default; a violation raises <see cref="GnuPGFormatException"/> with <see cref="GnuPGError.LimitExceeded"/>.</summary>
public sealed class GnuPGLimits
{
    /// <summary>The defaults.</summary>
    public static GnuPGLimits Default { get; } = new();

    /// <summary>Largest keybox blob accepted, in octets. Default 16 MiB.</summary>
    public int MaxBlobLength { get; init; } = 16 << 20;

    /// <summary>Most blobs read from one keybox. Default 1,048,576.</summary>
    public int MaxBlobs { get; init; } = 1 << 20;

    /// <summary>Largest key file accepted, in octets. Default 1 MiB.</summary>
    public int MaxKeyFileLength { get; init; } = 1 << 20;

    /// <summary>Deepest S-expression nesting. Default 32.</summary>
    public int MaxSexpDepth { get; init; } = 32;

    /// <summary>Most S-expression atoms and lists in one key file. Default 65,536.</summary>
    public int MaxSexpNodes { get; init; } = 1 << 16;

    /// <summary>
    /// Most octets the iterated and salted S2K may hash while stretching a passphrase. A count from an untrusted key file is checked against
    /// this before any work is done. Default 2^32 - 1 (the largest count the file field can name, a few seconds of SHA-1).
    /// </summary>
    public long MaxS2kCount { get; init; } = uint.MaxValue;

    /// <summary>Most records read from one trust database. Default 4,194,304.</summary>
    public int MaxTrustRecords { get; init; } = 1 << 22;

    /// <summary>Most lines read from one owner-trust export. Default 4,194,304.</summary>
    public int MaxTextLines { get; init; } = 1 << 22;

    /// <summary>Limits for the OpenPGP packets inside the containers.</summary>
    public Packets.OpenPgpLimits OpenPgp { get; init; } = Packets.OpenPgpLimits.Default;
}
