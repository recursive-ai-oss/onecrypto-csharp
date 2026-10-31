using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// Upper bounds on the cost of password-based key derivation, so that parameters read from an untrusted file or message
/// cannot make a caller allocate gigabytes or burn minutes of CPU. A derivation whose parameters exceed a bound throws
/// <see cref="KdfLimitExceededException"/> before it allocates anything. The default instance is what every derivation uses
/// when the caller passes none; build a larger one to accept stronger parameters deliberately.
/// </summary>
public sealed class KdfLimits
{
    /// <summary>
    /// The limits used when none are given: 2 GiB of memory, at most 64 Argon2 passes, 64 Argon2 lanes, scrypt work
    /// N × r × p of at most 2^26, and 4096 bcrypt-pbkdf rounds.
    /// </summary>
    public static KdfLimits Default { get; } = new();

    /// <summary>The most working memory, in bytes, one derivation may allocate. Default 2 GiB (2^31), enough for the first parameter set RFC 9106 recommends.</summary>
    public long MaxMemoryBytes { get; init; } = 1L << 31;

    /// <summary>The most Argon2 passes (the time cost t). Default 64.</summary>
    public int MaxArgon2Passes { get; init; } = 64;

    /// <summary>The most Argon2 lanes (the parallelism p). Default 64.</summary>
    public int MaxArgon2Parallelism { get; init; } = 64;

    /// <summary>The most scrypt work, measured as N × r × p (block-mix operations). Default 2^26.</summary>
    public long MaxScryptWork { get; init; } = 1L << 26;

    /// <summary>The most bcrypt-pbkdf rounds. Default 4096.</summary>
    public int MaxBcryptRounds { get; init; } = 4096;

    // Checks the byte budget, and that the working array can exist at all (arrays hold at most Array.MaxLength elements).
    internal void RequireMemory(string algorithm, long requestedBytes, int elementSize)
    {
        long arrayLimit = (long)Array.MaxLength * elementSize;
        if (requestedBytes > MaxMemoryBytes || requestedBytes > arrayLimit)
        {
            throw new KdfLimitExceededException(algorithm, "memory (bytes)", requestedBytes, Math.Min(MaxMemoryBytes, arrayLimit));
        }
    }

    internal static void Require(string algorithm, string parameter, long requested, long limit)
    {
        if (requested > limit)
        {
            throw new KdfLimitExceededException(algorithm, parameter, requested, limit);
        }
    }
}

/// <summary>
/// Thrown when key-derivation parameters exceed the <see cref="KdfLimits"/> in force. Nothing was allocated or computed.
/// </summary>
public sealed class KdfLimitExceededException : CryptographicException
{
    /// <summary>Creates the exception.</summary>
    public KdfLimitExceededException(string algorithm, string parameter, long requested, long limit)
        : base($"{algorithm} {parameter} of {requested} exceeds the limit of {limit}.")
    {
        Algorithm = algorithm;
        Parameter = parameter;
        Requested = requested;
        Limit = limit;
    }

    /// <summary>The algorithm, for example <c>Argon2id</c>.</summary>
    public string Algorithm { get; }

    /// <summary>The parameter that is over the limit, for example <c>memory (bytes)</c>.</summary>
    public string Parameter { get; }

    /// <summary>The value the parameters asked for.</summary>
    public long Requested { get; }

    /// <summary>The limit in force.</summary>
    public long Limit { get; }
}
