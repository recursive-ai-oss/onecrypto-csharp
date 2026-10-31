using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.Pkcs;

/// <summary>Why a PKCS#8, PKCS#12 or legacy key container was rejected.</summary>
public enum PkcsError
{
    /// <summary>The bytes are not valid ASN.1 or PEM.</summary>
    Malformed,

    /// <summary>Valid ASN.1 that is not the structure the standard defines.</summary>
    UnexpectedStructure,

    /// <summary>A field holds a value the standard does not allow.</summary>
    InvalidValue,

    /// <summary>A size, count, nesting or cost limit was exceeded (see <see cref="PkcsLimits"/>).</summary>
    LimitExceeded,

    /// <summary>The container is well formed but uses an algorithm or version this library does not read.</summary>
    Unsupported,
}

/// <summary>The outcome of a decryption or integrity check that depends on a password.</summary>
public enum PkcsStatus
{
    /// <summary>The password was accepted and the content is available.</summary>
    Ok = 0,

    /// <summary>
    /// The integrity check or padding failed. A wrong password and damaged data cannot be told apart, and no partial plaintext is
    /// released in either case.
    /// </summary>
    WrongPasswordOrCorrupt,

    /// <summary>The container has no MAC, and the caller required one.</summary>
    IntegrityMissing,

    /// <summary>The container is encrypted and no password was given.</summary>
    PasswordRequired,

    /// <summary>An algorithm in the container is not supported (the container itself may be valid).</summary>
    UnsupportedAlgorithm,

    /// <summary>A cost parameter from the file (iterations, scrypt work) is above the configured limit.</summary>
    LimitExceeded,

    /// <summary>The container is malformed.</summary>
    Malformed,
}

/// <summary>Raised when a PKCS#8, PKCS#12 or legacy key container cannot be parsed. <c>TryParse</c> methods return false instead.</summary>
public sealed class PkcsParseException : FormatException
{
    /// <summary>Creates the exception.</summary>
    public PkcsParseException(string structure, PkcsError error, string message)
        : base($"{structure}: {message}")
    {
        Structure = structure;
        Error = error;
    }

    /// <summary>Creates the exception from an ASN.1 failure.</summary>
    public PkcsParseException(string structure, Asn1ParseException inner)
        : base($"{structure}: {inner?.Message}", inner)
    {
        Structure = structure;
        Error = PkcsError.Malformed;
    }

    /// <summary>Creates an empty exception.</summary>
    public PkcsParseException()
        : this("PKCS", PkcsError.Malformed, "invalid container")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public PkcsParseException(string message)
        : this("PKCS", PkcsError.Malformed, message)
    {
    }

    /// <summary>Creates the exception with a message and an inner exception.</summary>
    public PkcsParseException(string message, Exception innerException)
        : base(message, innerException)
    {
        Structure = "PKCS";
    }

    /// <summary>The structure being read, for example <c>PrivateKeyInfo</c> or <c>PFX</c>.</summary>
    public string Structure { get; } = "PKCS";

    /// <summary>The category of the failure.</summary>
    public PkcsError Error { get; }
}

/// <summary>Raised by the throwing decryption methods when <see cref="PkcsStatus"/> is not <see cref="PkcsStatus.Ok"/>.</summary>
public sealed class PkcsPasswordException : System.Security.Cryptography.CryptographicException
{
    /// <summary>Creates the exception.</summary>
    public PkcsPasswordException(PkcsStatus status)
        : base($"The container could not be opened: {status}.")
    {
        Status = status;
    }

    /// <summary>Creates an empty exception.</summary>
    public PkcsPasswordException()
        : this(PkcsStatus.WrongPasswordOrCorrupt)
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public PkcsPasswordException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner exception.</summary>
    public PkcsPasswordException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Why opening failed.</summary>
    public PkcsStatus Status { get; } = PkcsStatus.WrongPasswordOrCorrupt;
}

/// <summary>Limits applied to every container read from untrusted input. All are on by default.</summary>
public sealed class PkcsLimits
{
    /// <summary>The defaults.</summary>
    public static PkcsLimits Default { get; } = new();

    /// <summary>The largest container accepted, in bytes. Default 64 MiB.</summary>
    public int MaxEncodedSize { get; init; } = 64 << 20;

    /// <summary>
    /// The largest PBKDF2 or PKCS#12 key-derivation iteration count accepted from a file. A hostile file can ask for billions;
    /// default 5,000,000 (current guidance is 600,000 for PBKDF2-HMAC-SHA-256, and the common legacy values are 1 to 100,000).
    /// </summary>
    public long MaxIterations { get; init; } = 5_000_000;

    /// <summary>The largest number of bags in one PKCS#12 file, nested ones included. Default 4096.</summary>
    public int MaxBags { get; init; } = 4096;

    /// <summary>The largest number of ContentInfo elements in one AuthenticatedSafe. Default 256.</summary>
    public int MaxSafes { get; init; } = 256;

    /// <summary>The deepest nesting of SafeContents bags. Default 4.</summary>
    public int MaxSafeNesting { get; init; } = 4;

    /// <summary>The longest salt accepted, in bytes. Default 1024.</summary>
    public int MaxSaltLength { get; init; } = 1024;

    /// <summary>Limits for the scrypt parameters of a PBES2 file.</summary>
    public KdfLimits Kdf { get; init; } = KdfLimits.Default;

    /// <summary>ASN.1 limits for the outer structure.</summary>
    public Asn1Limits Asn1 { get; init; } = new Asn1Limits { MaxDepth = 24 };
}

internal static class PkcsFail
{
    public static PkcsParseException Bad(string what, string message) => new(what, PkcsError.UnexpectedStructure, message);

    public static PkcsParseException Invalid(string what, string message) => new(what, PkcsError.InvalidValue, message);

    public static PkcsParseException Limit(string what, string message) => new(what, PkcsError.LimitExceeded, message);

    public static PkcsParseException Unsupported(string what, string message) => new(what, PkcsError.Unsupported, message);

    /// <summary>Runs <paramref name="parse"/>, turning ASN.1 failures into <see cref="PkcsParseException"/>.</summary>
    public static T Run<T>(string what, Func<T> parse)
    {
        try
        {
            return parse();
        }
        catch (Asn1ParseException ex)
        {
            throw new PkcsParseException(what, ex);
        }
        catch (X509ParseException ex)
        {
            throw new PkcsParseException(what, PkcsError.Malformed, ex.Message);
        }
    }

    public static bool Try<T>(Func<T> parse, out T? value)
        where T : class
    {
        try
        {
            value = parse();
            return true;
        }
        catch (PkcsParseException)
        {
            value = null;
            return false;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            value = null;
            return false;
        }
    }
}
