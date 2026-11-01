namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>What went wrong while processing an OpenPGP message or key.</summary>
public enum PgpFailure
{
    /// <summary>The data is not a well-formed message (RFC 9580 §10.3 grammar) or a packet is malformed.</summary>
    MalformedMessage,

    /// <summary>
    /// Decryption failed. One failure for every reason a session key cannot be recovered or a body does not authenticate (no matching key, wrong
    /// padding, bad checksum, bad MDC, bad AEAD tag), so the error does not tell an attacker which step failed (RFC 9580 §13).
    /// </summary>
    CannotDecrypt,

    /// <summary>The message is encrypted and no key or password was supplied that applies.</summary>
    NoDecryptionKey,

    /// <summary>The message was encrypted without integrity protection (SED) and the caller did not opt in.</summary>
    UnauthenticatedEncryption,

    /// <summary>A secret key is protected and no password given unlocks it.</summary>
    KeyIsProtected,

    /// <summary>The key cannot be used for the requested operation (no signing capability, expired, revoked).</summary>
    KeyCannotPerform,

    /// <summary>An algorithm is not supported on this platform or in this build.</summary>
    Unsupported,

    /// <summary>A limit (output size, nesting depth, KDF cost) was exceeded.</summary>
    LimitExceeded,

    /// <summary>The supplied text is not valid for a text operation (cleartext signing).</summary>
    ExpectedText,

    /// <summary>The operation was refused by the crypto policy.</summary>
    PolicyViolation,
}

/// <summary>
/// Raised when an OpenPGP message operation fails. The <see cref="Failure"/> value says which class of failure it was; decryption failures are
/// deliberately uniform (see <see cref="PgpFailure.CannotDecrypt"/>).
/// </summary>
public sealed class PgpException : Exception
{
    /// <summary>Creates the exception for a failure class and a message.</summary>
    public PgpException(PgpFailure failure, string message)
        : base(message)
    {
        Failure = failure;
    }

    /// <summary>Creates the exception with an inner exception.</summary>
    public PgpException(PgpFailure failure, string message, Exception innerException)
        : base(message, innerException)
    {
        Failure = failure;
    }

    /// <summary>Creates a generic message-processing exception.</summary>
    public PgpException()
        : this(PgpFailure.MalformedMessage, "OpenPGP operation failed.")
    {
    }

    /// <summary>Creates a generic exception with a message.</summary>
    public PgpException(string message)
        : this(PgpFailure.MalformedMessage, message)
    {
    }

    /// <summary>Creates a generic exception with a message and an inner exception.</summary>
    public PgpException(string message, Exception innerException)
        : this(PgpFailure.MalformedMessage, message, innerException)
    {
    }

    /// <summary>The class of failure.</summary>
    public PgpFailure Failure { get; }
}
