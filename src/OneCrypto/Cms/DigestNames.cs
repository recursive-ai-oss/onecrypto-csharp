using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// The mapping between digest algorithm object identifiers, which the CMS and X.509 layers speak, and <see cref="HashAlgorithmName"/>, which the
/// platform and most callers speak. The table covers the digests core can compute: SHA-1, SHA-256, SHA-384, SHA-512, the SHA-3 family
/// (SHA3-256, SHA3-384, SHA3-512) and SHAKE256 with a 512-bit output, which Ed448 signatures use as their message digest (RFC 8419 §3.1).
/// </summary>
/// <remarks>Listing a digest here does not mean the platform has it: SHA-3 needs a platform with SHA-3 (see the availability table). Policy is separate: SHA-1 maps, and <see cref="Policy.CryptoPolicy"/> decides whether it may be used.</remarks>
public static class DigestNames
{
    /// <summary>The name that stands for SHAKE256 with a 512-bit output, which the BCL has no <see cref="HashAlgorithmName"/> constant for.</summary>
    public static HashAlgorithmName Shake256 { get; } = new("SHAKE256");

    /// <summary>Finds the digest algorithm OID for a hash name.</summary>
    /// <param name="hash">The hash name, such as <see cref="HashAlgorithmName.SHA256"/>.</param>
    /// <param name="oid">The dotted OID, or null when the name is not a digest core knows.</param>
    /// <returns>True when the name maps.</returns>
    public static bool TryGetOid(HashAlgorithmName hash, out string? oid)
    {
        oid = hash.Name switch
        {
            "SHA1" => KnownOids.Sha1,
            "SHA256" => KnownOids.Sha256,
            "SHA384" => KnownOids.Sha384,
            "SHA512" => KnownOids.Sha512,
            "SHA3-256" => KnownOids.Sha3256,
            "SHA3-384" => KnownOids.Sha3384,
            "SHA3-512" => KnownOids.Sha3512,
            "SHAKE256" => CmsOids.Shake256,
            _ => null,
        };
        return oid is not null;
    }

    /// <summary>The digest algorithm OID for a hash name.</summary>
    /// <param name="hash">The hash name.</param>
    /// <returns>The dotted OID.</returns>
    /// <exception cref="NotSupportedException">The name is not a digest core supports (MD5 and SHA-224 are not; the message lists the ones that are).</exception>
    public static string GetOid(HashAlgorithmName hash) =>
        TryGetOid(hash, out string? oid)
            ? oid!
            : throw new NotSupportedException($"The hash '{hash.Name}' has no digest algorithm OID in OneCrypto. Supported: SHA1, SHA256, SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512, SHAKE256.");

    /// <summary>Finds the hash name for a digest algorithm OID.</summary>
    /// <param name="oid">The dotted OID.</param>
    /// <param name="hash">The hash name, or default when the OID is not a digest core knows.</param>
    /// <returns>True when the OID maps.</returns>
    public static bool TryGetHashAlgorithmName(string oid, out HashAlgorithmName hash)
    {
        ArgumentNullException.ThrowIfNull(oid);
        if (oid == CmsOids.Shake256)
        {
            hash = Shake256;
            return true;
        }

        return SignatureAlgorithms.TryHash(oid, out hash);
    }

    /// <summary>The hash name for a digest algorithm OID.</summary>
    /// <param name="oid">The dotted OID.</param>
    /// <returns>The hash name.</returns>
    /// <exception cref="NotSupportedException">The OID is not a digest core supports.</exception>
    public static HashAlgorithmName GetHashAlgorithmName(string oid) =>
        TryGetHashAlgorithmName(oid, out HashAlgorithmName hash)
            ? hash
            : throw new NotSupportedException($"The OID {oid} is not a digest algorithm OneCrypto knows.");

    /// <summary>The digest length in bytes for a digest algorithm OID (64 for SHAKE256 as CMS uses it).</summary>
    /// <param name="oid">The dotted OID.</param>
    /// <param name="length">The length, or 0 when unknown or the platform lacks the digest.</param>
    /// <returns>True when the platform can compute it.</returns>
    public static bool TryGetDigestLength(string oid, out int length)
    {
        ArgumentNullException.ThrowIfNull(oid);
        if (CmsDigest.TryHash(oid, [], out byte[] empty))
        {
            length = empty.Length;
            return true;
        }

        length = 0;
        return false;
    }
}

/// <summary>
/// A digest was handed to a call that expected another digest algorithm or another length: the algorithm the signer uses is not the one the digest was
/// made with. The message names both. Derives from <see cref="ArgumentException"/>, so existing handlers keep working.
/// </summary>
public sealed class DigestMismatchException : ArgumentException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="message">What was expected and what was given, in words.</param>
    /// <param name="expected">The algorithm (or length) the call needed.</param>
    /// <param name="actual">The algorithm (or length) it was given.</param>
    /// <param name="paramName">The argument.</param>
    public DigestMismatchException(string message, string expected, string actual, string? paramName = null)
        : base(message, paramName)
    {
        Expected = expected;
        Actual = actual;
    }

    /// <summary>Creates the exception.</summary>
    public DigestMismatchException()
        : this("The digest does not match the digest algorithm.", string.Empty, string.Empty)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    public DigestMismatchException(string message)
        : this(message, string.Empty, string.Empty)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What happened.</param>
    /// <param name="innerException">The cause.</param>
    public DigestMismatchException(string message, Exception innerException)
        : base(message, innerException)
    {
        Expected = string.Empty;
        Actual = string.Empty;
    }

    /// <summary>What the call needed, for example "SHA-256 (32 bytes)".</summary>
    public string Expected { get; }

    /// <summary>What it was given, for example "SHA-512" or "48 bytes".</summary>
    public string Actual { get; }
}
