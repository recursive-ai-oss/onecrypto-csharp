namespace RecursiveAI.OneCrypto;

/// <summary>
/// The algorithm is not available on this platform and the library has no fallback for it. It is thrown only when the platform's
/// cryptography lacks the primitive and no narrow managed fallback applies; where a fallback exists, the call succeeds instead.
/// </summary>
/// <remarks>
/// The message names the algorithm and the platform, including the fact that decided it (for example, that the loaded OpenSSL is
/// version 3.0, which has no ML-DSA). Catch it to offer another algorithm; do not catch it to retry the same call. The
/// generated per-platform availability table in the documentation lists what each platform supports.
/// </remarks>
public sealed class AlgorithmNotSupportedException : NotSupportedException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="algorithm">The algorithm, as the documentation names it (for example <c>ML-DSA</c> or <c>Brainpool P-256</c>).</param>
    /// <param name="platform">The platform description: operating system, architecture, runtime and the provider fact.</param>
    /// <param name="reason">Why the platform cannot do it, in one short sentence.</param>
    public AlgorithmNotSupportedException(string algorithm, string platform, string reason)
        : base($"{algorithm} is not supported on {platform}: {reason}")
    {
        Algorithm = algorithm;
        Platform = platform;
        Reason = reason;
    }

    /// <summary>Creates the exception with an inner exception from the platform.</summary>
    /// <param name="algorithm">The algorithm, as the documentation names it.</param>
    /// <param name="platform">The platform description.</param>
    /// <param name="reason">Why the platform cannot do it.</param>
    /// <param name="innerException">What the platform threw.</param>
    public AlgorithmNotSupportedException(string algorithm, string platform, string reason, Exception innerException)
        : base($"{algorithm} is not supported on {platform}: {reason}", innerException)
    {
        Algorithm = algorithm;
        Platform = platform;
        Reason = reason;
    }

    /// <summary>The algorithm that is not available.</summary>
    public string Algorithm { get; }

    /// <summary>The platform: operating system, architecture, runtime and the provider fact that decided it.</summary>
    public string Platform { get; }

    /// <summary>Why the platform cannot do it.</summary>
    public string Reason { get; }
}
