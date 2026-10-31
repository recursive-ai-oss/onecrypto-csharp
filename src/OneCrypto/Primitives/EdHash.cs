using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// The hashes EdDSA needs, over several input pieces at once so callers never concatenate a large message. Inputs up to 4 KiB
/// are joined on the stack and hashed in one call (no allocation); longer ones go through an incremental hash.
/// </summary>
internal static class EdHash
{
    // Inputs up to SmallLimit are joined in a small stack buffer, up to LargeLimit in a bigger one (a separate method, so the
    // frame only grows when it is needed); longer ones go through an incremental hash. Joining is much cheaper than creating a
    // platform hash context, which matters for the usual message sizes.
    private const int SmallLimit = 256;
    private const int LargeLimit = 4096;

    /// <summary>SHA-512 of the concatenation of the pieces, into <paramref name="destination"/> (64 bytes).</summary>
    public static void Sha512(Span<byte> destination, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b = default, ReadOnlySpan<byte> c = default, ReadOnlySpan<byte> d = default)
    {
        int total = a.Length + b.Length + c.Length + d.Length;
        if (total <= SmallLimit)
        {
            Span<byte> joined = stackalloc byte[SmallLimit]; // fixed small buffer
            Join(joined, a, b, c, d);
            SHA512.HashData(joined[..total], destination);
            joined[..total].Clear();
        }
        else if (total <= LargeLimit)
        {
            Sha512Large(destination, total, a, b, c, d);
        }
        else
        {
            using IncrementalHash h = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
            h.AppendData(a);
            h.AppendData(b);
            h.AppendData(c);
            h.AppendData(d);
            h.GetHashAndReset(destination);
        }
    }

    private static void Sha512Large(Span<byte> destination, int total, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        Span<byte> joined = stackalloc byte[LargeLimit]; // fixed buffer, bounded by LargeLimit
        Join(joined, a, b, c, d);
        SHA512.HashData(joined[..total], destination);
        joined[..total].Clear();
    }

    /// <summary>SHAKE256 of the concatenation of the pieces, filling <paramref name="destination"/>. The platform's SHAKE256 where it
    /// exists, the library's managed Keccak elsewhere.</summary>
    public static void Shake256(Span<byte> destination, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b = default, ReadOnlySpan<byte> c = default, ReadOnlySpan<byte> d = default) =>
        PlatformHash.Shake256(destination, a, b, c, d);

    private static void Join(Span<byte> to, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        a.CopyTo(to);
        b.CopyTo(to[a.Length..]);
        c.CopyTo(to[(a.Length + b.Length)..]);
        d.CopyTo(to[(a.Length + b.Length + c.Length)..]);
    }
}
