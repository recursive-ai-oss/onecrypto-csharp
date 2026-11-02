namespace RecursiveAI.OneCrypto.OpenPgp.Trust;

/// <summary>Which limit of <see cref="TrustLimits"/> was exceeded.</summary>
public enum TrustLimit
{
    /// <summary>More certificates than <see cref="TrustLimits.MaxCertificates"/>.</summary>
    Certificates,

    /// <summary>More certifications (signatures examined, or edges kept) than <see cref="TrustLimits.MaxCertifications"/>.</summary>
    Certifications,

    /// <summary>More trust roots than <see cref="TrustLimits.MaxRoots"/>.</summary>
    Roots,

    /// <summary>The path search or the validity computation took more steps than <see cref="TrustLimits.MaxWork"/>.</summary>
    Work,

    /// <summary>A regular expression is longer than <see cref="TrustLimits.MaxRegexLength"/> or expands to more states than <see cref="TrustLimits.MaxRegexStates"/>.</summary>
    Regex,
}

/// <summary>
/// Bounds on the work a trust computation does, so that a hostile bundle of certificates cannot make it run for long or use much memory.
/// A computation that reaches one stops with <see cref="TrustLimitExceededException"/>; it never returns a partial answer that could be mistaken for a complete one.
/// </summary>
public sealed class TrustLimits
{
    /// <summary>The limits used when none are given.</summary>
    public static TrustLimits Default { get; } = new();

    /// <summary>The most certificates (distinct primary keys) taken into one network. Default 50,000.</summary>
    public int MaxCertificates { get; init; } = 50_000;

    /// <summary>
    /// The most certification signatures examined while building a network, and the most edges a network may hold. Default 2,000,000.
    /// Every examined signature costs one public-key verification, so this also bounds the time to build.
    /// </summary>
    public int MaxCertifications { get; init; } = 2_000_000;

    /// <summary>The most trust roots. Default 10,000.</summary>
    public int MaxRoots { get; init; } = 10_000;

    /// <summary>
    /// The most basic steps (edges looked at) a path search or a validity computation may take across the whole call. Default 200,000,000,
    /// which a dense network of ten thousand certificates stays well under for the default target amount.
    /// </summary>
    public long MaxWork { get; init; } = 200_000_000;

    /// <summary>The longest regular expression, in characters, that is compiled. Default 1,024.</summary>
    public int MaxRegexLength { get; init; } = 1_024;

    /// <summary>The most states a compiled regular expression may have once repetition counts are expanded. Default 4,096.</summary>
    public int MaxRegexStates { get; init; } = 4_096;
}

/// <summary>Raised when a trust computation reaches one of its <see cref="TrustLimits"/>.</summary>
public sealed class TrustLimitExceededException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <param name="limit">The limit reached.</param>
    /// <param name="message">What was being done.</param>
    public TrustLimitExceededException(TrustLimit limit, string message)
        : base(message)
    {
        Limit = limit;
    }

    /// <summary>Creates the exception with a generic message.</summary>
    public TrustLimitExceededException()
        : this(TrustLimit.Work, "A trust limit was exceeded.")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">What was being done.</param>
    public TrustLimitExceededException(string message)
        : this(TrustLimit.Work, message)
    {
    }

    /// <summary>Creates the exception with a message and an inner exception.</summary>
    /// <param name="message">What was being done.</param>
    /// <param name="innerException">The cause.</param>
    public TrustLimitExceededException(string message, Exception innerException)
        : base(message, innerException)
    {
        Limit = TrustLimit.Work;
    }

    /// <summary>Which limit was reached.</summary>
    public TrustLimit Limit { get; }
}
