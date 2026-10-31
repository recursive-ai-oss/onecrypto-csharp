using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// The hashes EdDSA needs, over several input pieces at once so callers never concatenate a large message. Inputs up to a few
/// hundred bytes are joined on the stack and hashed in one call (no allocation); longer ones go through an incremental hash.
/// </summary>
internal static class EdHash
{
    private const int StackLimit = 1024;

    /// <summary>SHA-512 of the concatenation of the pieces, into <paramref name="destination"/> (64 bytes).</summary>
    public static void Sha512(Span<byte> destination, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b = default, ReadOnlySpan<byte> c = default, ReadOnlySpan<byte> d = default)
    {
        int total = a.Length + b.Length + c.Length + d.Length;
        if (total <= StackLimit)
        {
            Span<byte> joined = stackalloc byte[StackLimit]; // fixed small buffer
            Join(joined, a, b, c, d);
            SHA512.HashData(joined[..total], destination);
            joined[..total].Clear();
            return;
        }
        using IncrementalHash h = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        h.AppendData(a);
        h.AppendData(b);
        h.AppendData(c);
        h.AppendData(d);
        h.GetHashAndReset(destination);
    }

    /// <summary>SHAKE256 of the concatenation of the pieces, filling <paramref name="destination"/>.</summary>
    public static void Shake256(Span<byte> destination, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b = default, ReadOnlySpan<byte> c = default, ReadOnlySpan<byte> d = default)
    {
        // The platform's SHAKE256 is used where it exists. A platform without it needs the managed SHA-3 fallback, which is
        // plugged in here once it exists; until then Ed448 reports the platform gap instead of computing a wrong answer.
        if (!System.Security.Cryptography.Shake256.IsSupported)
        {
            throw new PlatformNotSupportedException("SHAKE256 is not available on this platform, which Ed448 needs.");
        }
        int total = a.Length + b.Length + c.Length + d.Length;
        if (total <= StackLimit)
        {
            Span<byte> joined = stackalloc byte[StackLimit]; // fixed small buffer
            Join(joined, a, b, c, d);
            System.Security.Cryptography.Shake256.HashData(joined[..total], destination);
            joined[..total].Clear();
            return;
        }
        using var h = new System.Security.Cryptography.Shake256();
        h.AppendData(a);
        h.AppendData(b);
        h.AppendData(c);
        h.AppendData(d);
        h.GetHashAndReset(destination);
    }

    private static void Join(Span<byte> to, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        a.CopyTo(to);
        b.CopyTo(to[a.Length..]);
        c.CopyTo(to[(a.Length + b.Length)..]);
        d.CopyTo(to[(a.Length + b.Length + c.Length)..]);
    }
}
