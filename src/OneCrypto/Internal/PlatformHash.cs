using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives.Fallback;

namespace RecursiveAI.OneCrypto.Internal;

/// <summary>
/// SHA-3 and SHAKE through the platform dispatch: the platform's hash where it has one, the managed Keccak where it does not.
/// Both give identical output (FIPS 202).
/// </summary>
internal static class PlatformHash
{
    // Inputs up to SmallLimit are joined in a small stack buffer, up to LargeLimit in a bigger one (a separate method, so the
    // frame only grows when it is needed); longer ones go through an incremental hash.
    private const int SmallLimit = 256;
    private const int LargeLimit = 4096;

    /// <summary>The name this library uses for SHA3-224, which the platform's <see cref="HashAlgorithmName"/> list does not have.</summary>
    public static readonly HashAlgorithmName Sha3_224Name = new("SHA3-224");

    /// <summary>The digest size in bytes of SHA-1, SHA-256/384/512 and SHA3-224/256/384/512, or 0 for any other hash.</summary>
    public static int DigestSize(HashAlgorithmName hash) =>
        hash == HashAlgorithmName.SHA1 ? 20
        : hash == HashAlgorithmName.SHA256 || hash == HashAlgorithmName.SHA3_256 ? 32
        : hash == HashAlgorithmName.SHA384 || hash == HashAlgorithmName.SHA3_384 ? 48
        : hash == HashAlgorithmName.SHA512 || hash == HashAlgorithmName.SHA3_512 ? 64
        : hash == Sha3_224Name ? 28
        : 0;

    /// <summary>The digest of <paramref name="data"/> under a hash <see cref="DigestSize"/> knows, or null for any other.</summary>
    public static byte[]? Digest(HashAlgorithmName hash, ReadOnlySpan<byte> data)
    {
        int size = DigestSize(hash);
        if (size == 0)
        {
            return null;
        }

        byte[] result = new byte[size];
        if (hash == HashAlgorithmName.SHA1 || hash == HashAlgorithmName.SHA256 || hash == HashAlgorithmName.SHA384 || hash == HashAlgorithmName.SHA512)
        {
            CryptographicOperations.HashData(hash, data, result);
        }
        else
        {
            Sha3(size * 8, data, result);
        }

        return result;
    }

    /// <summary>SHA3-224, -256, -384 or -512 of <paramref name="data"/> into <paramref name="destination"/> (bits / 8 bytes).</summary>
    /// <param name="bits">The digest size: 224, 256, 384 or 512.</param>
    /// <param name="data">The message.</param>
    /// <param name="destination">Receives the digest; must be exactly bits / 8 bytes.</param>
    public static void Sha3(int bits, ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if (bits is not (224 or 256 or 384 or 512))
        {
            throw new ArgumentOutOfRangeException(nameof(bits), "SHA-3 digests are 224, 256, 384 or 512 bits.");
        }

        if (destination.Length != bits / 8)
        {
            throw new ArgumentException("The destination must be exactly the digest size.", nameof(destination));
        }

        if (Platform.Sha3(bits) == Provider.Bcl)
        {
            switch (bits)
            {
                case 256:
                    SHA3_256.HashData(data, destination);
                    return;
                case 384:
                    SHA3_384.HashData(data, destination);
                    return;
                default:
                    SHA3_512.HashData(data, destination);
                    return;
            }
        }

        int rate = bits switch
        {
            224 => Keccak.RateSha3_224,
            256 => Keccak.RateSha3_256,
            384 => Keccak.RateSha3_384,
            _ => Keccak.RateSha3_512,
        };
        Keccak.Hash(rate, Keccak.SuffixSha3, destination, data);
    }

    /// <summary>SHAKE128 or SHAKE256 of <paramref name="data"/>, filling <paramref name="destination"/> (any length).</summary>
    /// <param name="bits">128 or 256.</param>
    /// <param name="data">The message.</param>
    /// <param name="destination">Receives the output.</param>
    public static void Shake(int bits, ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if (bits is not (128 or 256))
        {
            throw new ArgumentOutOfRangeException(nameof(bits), "SHAKE is SHAKE128 or SHAKE256.");
        }

        if (Platform.Shake(bits) == Provider.Bcl)
        {
            if (bits == 128)
            {
                System.Security.Cryptography.Shake128.HashData(data, destination);
            }
            else
            {
                System.Security.Cryptography.Shake256.HashData(data, destination);
            }

            return;
        }

        Keccak.Hash(bits == 128 ? Keccak.RateShake128 : Keccak.RateShake256, Keccak.SuffixShake, destination, data);
    }

    /// <summary>SHAKE256 of the concatenation of up to four pieces, so callers never concatenate a large message.</summary>
    public static void Shake256(Span<byte> destination, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b = default, ReadOnlySpan<byte> c = default, ReadOnlySpan<byte> d = default)
    {
        if (Platform.Shake(256) != Provider.Bcl)
        {
            Keccak.Hash(Keccak.RateShake256, Keccak.SuffixShake, destination, a, b, c, d);
            return;
        }

        int total = a.Length + b.Length + c.Length + d.Length;
        if (total <= SmallLimit)
        {
            Span<byte> joined = stackalloc byte[SmallLimit]; // fixed small buffer
            Join(joined, a, b, c, d);
            System.Security.Cryptography.Shake256.HashData(joined[..total], destination);
            joined[..total].Clear();
        }
        else if (total <= LargeLimit)
        {
            Shake256Large(destination, total, a, b, c, d);
        }
        else
        {
            using var h = new System.Security.Cryptography.Shake256();
            h.AppendData(a);
            h.AppendData(b);
            h.AppendData(c);
            h.AppendData(d);
            h.GetHashAndReset(destination);
        }
    }

    private static void Shake256Large(Span<byte> destination, int total, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        Span<byte> joined = stackalloc byte[LargeLimit]; // fixed buffer, bounded by LargeLimit
        Join(joined, a, b, c, d);
        System.Security.Cryptography.Shake256.HashData(joined[..total], destination);
        joined[..total].Clear();
    }

    internal static void Join(Span<byte> to, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        a.CopyTo(to);
        b.CopyTo(to[a.Length..]);
        c.CopyTo(to[(a.Length + b.Length)..]);
        d.CopyTo(to[(a.Length + b.Length + c.Length)..]);
    }
}
