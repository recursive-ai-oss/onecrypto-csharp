namespace RecursiveAI.OneCrypto;

/// <summary>Why <see cref="Crypto.Load(ReadOnlySpan{byte}, Func{string, string?}?)"/> could not load its input.</summary>
public enum CryptoLoadError
{
    /// <summary>The input is empty or only white space.</summary>
    Empty = 0,

    /// <summary>The input matches none of the formats the loader reads.</summary>
    Unrecognized,

    /// <summary>The format was recognised but the data is malformed or damaged.</summary>
    Malformed,

    /// <summary>The format was recognised and is well formed, but uses an algorithm, version or content type this library does not load.</summary>
    Unsupported,

    /// <summary>The content is encrypted and no password was supplied (no callback, or the callback returned null).</summary>
    PasswordRequired,

    /// <summary>
    /// The password was wrong or the data is damaged; the two cannot be told apart. Nothing from the input is returned, not even the
    /// parts that are not encrypted.
    /// </summary>
    WrongPasswordOrCorrupt,

    /// <summary>A size or cost limit was exceeded (input size, KDF cost, nesting, element count).</summary>
    LimitExceeded,
}

/// <summary>One format the loader considered and why it was not (or could not be) loaded as that format.</summary>
/// <param name="Format">The format, for example <c>PEM</c>, <c>DER</c>, <c>PKCS#12</c>, <c>OpenSSH public key</c>.</param>
/// <param name="Reason">Why this format does not apply or what was wrong with it.</param>
public sealed record CryptoLoadAttempt(string Format, string Reason);

/// <summary>
/// Raised by <see cref="Crypto.Load(ReadOnlySpan{byte}, Func{string, string?}?)"/> when the input is unrecognised, malformed, needs a
/// password it did not get, or exceeds a limit. It is the only exception the loader raises for bad input; <see cref="Crypto.TryLoad(ReadOnlySpan{byte}, out LoadedItems?, out CryptoLoadException?, Func{string, string?}?)"/> returns it instead of throwing.
/// </summary>
public sealed class CryptoLoadException : FormatException
{
    /// <summary>Creates the exception.</summary>
    public CryptoLoadException(CryptoLoadError error, string message, IReadOnlyList<CryptoLoadAttempt>? considered = null, Exception? inner = null)
        : base(message, inner)
    {
        Error = error;
        Considered = considered ?? [];
    }

    /// <summary>Creates an empty-input exception.</summary>
    public CryptoLoadException()
        : this(CryptoLoadError.Malformed, "The input could not be loaded.")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public CryptoLoadException(string message)
        : this(CryptoLoadError.Malformed, message)
    {
    }

    /// <summary>Creates the exception with a message and the exception that caused it.</summary>
    public CryptoLoadException(string message, Exception innerException)
        : this(CryptoLoadError.Malformed, message, null, innerException)
    {
    }

    /// <summary>The category of failure.</summary>
    public CryptoLoadError Error { get; }

    /// <summary>
    /// The formats the loader considered, in the order of its decision table, with the reason each did not apply or failed. For input
    /// that was recognised, the last entry is the format that failed and why.
    /// </summary>
    public IReadOnlyList<CryptoLoadAttempt> Considered { get; }
}
