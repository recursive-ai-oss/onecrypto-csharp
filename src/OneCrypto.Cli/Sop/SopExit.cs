namespace RecursiveAI.OneCrypto.Cli.Sop;

/// <summary>The exit codes of the Stateless OpenPGP interface (draft-dkg-openpgp-stateless-cli, Failure Modes).</summary>
internal static class SopExit
{
    public const int Ok = 0;
    public const int UnspecifiedFailure = 1;
    public const int NoSignature = 3;
    public const int UnsupportedAsymmetricAlgo = 13;
    public const int CertCannotEncrypt = 17;
    public const int MissingArg = 19;
    public const int IncompleteVerification = 23;
    public const int CannotDecrypt = 29;
    public const int PasswordNotHumanReadable = 31;
    public const int UnsupportedOption = 37;
    public const int BadData = 41;
    public const int ExpectedText = 53;
    public const int OutputExists = 59;
    public const int MissingInput = 61;
    public const int KeyIsProtected = 67;
    public const int UnsupportedSubcommand = 69;
    public const int UnsupportedSpecialPrefix = 71;
    public const int AmbiguousInput = 73;
    public const int KeyCannotSign = 79;
    public const int IncompatibleOptions = 83;
    public const int UnsupportedProfile = 89;
    public const int PrimaryKeyBad = 103;
    public const int CertUseridNoMatch = 107;
    public const int KeyCannotCertify = 109;
}

/// <summary>A failure that ends the command with a given exit code and a message for standard error.</summary>
internal sealed class SopException : Exception
{
    public SopException(int exitCode, string message)
        : base(message)
    {
        ExitCode = exitCode;
    }

    public SopException(int exitCode, string message, Exception inner)
        : base(message, inner)
    {
        ExitCode = exitCode;
    }

    public SopException()
        : this(SopExit.UnspecifiedFailure, "failure")
    {
    }

    public SopException(string message)
        : this(SopExit.UnspecifiedFailure, message)
    {
    }

    public SopException(string message, Exception inner)
        : this(SopExit.UnspecifiedFailure, message, inner)
    {
    }

    public int ExitCode { get; }
}
