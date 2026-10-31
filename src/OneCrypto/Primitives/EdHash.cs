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
        // The platform's SHAKE256 is used where it exists (it is native and fast); elsewhere the managed Keccak below, which
        // is constant time by construction (only xor, and, not and rotate on 64-bit lanes). Both give identical output.
        if (!System.Security.Cryptography.Shake256.IsSupported)
        {
            KeccakShake256.Hash(destination, a, b, c, d);
            return;
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

    /// <summary>Forces the managed path, for tests that compare it with the platform's.</summary>
    internal static void Shake256Managed(Span<byte> destination, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b = default, ReadOnlySpan<byte> c = default, ReadOnlySpan<byte> d = default) =>
        KeccakShake256.Hash(destination, a, b, c, d);

    private static void Join(Span<byte> to, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        a.CopyTo(to);
        b.CopyTo(to[a.Length..]);
        c.CopyTo(to[(a.Length + b.Length)..]);
        d.CopyTo(to[(a.Length + b.Length + c.Length)..]);
    }
}

/// <summary>
/// SHAKE256 (FIPS 202) over the Keccak-f[1600] permutation, used only where the platform has no SHAKE256. The permutation is
/// built from xor, and, not and fixed rotations on 64-bit lanes: no table lookup, branch or loop bound depends on the data.
/// </summary>
internal static class KeccakShake256
{
    private const int Rate = 136; // 1088 bits: 1600 minus twice the 256-bit security level

    private static ReadOnlySpan<ulong> RoundConstants =>
    [
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
    ];

    // FIPS 202 section 3.2.2 (rho): the rotation of lane (x, y) walks t = 0..23 along (x, y) -> (y, 2x + 3y) from (1, 0)
    // with offset (t + 1)(t + 2) / 2 mod 64. Lanes are indexed x + 5y; the first entry (0, 0) does not rotate.
    private static readonly int[] Rotations = BuildRotations();

    private static int[] BuildRotations()
    {
        var r = new int[25];
        int x = 1, y = 0;
        for (int t = 0; t < 24; t++)
        {
            r[x + (5 * y)] = ((t + 1) * (t + 2) / 2) % 64;
            (x, y) = (y, ((2 * x) + (3 * y)) % 5);
        }
        return r;
    }

    public static void Hash(Span<byte> output, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        Span<ulong> state = stackalloc ulong[25]; // fixed small buffer
        state.Clear();
        int pos = 0;
        Absorb(state, ref pos, a);
        Absorb(state, ref pos, b);
        Absorb(state, ref pos, c);
        Absorb(state, ref pos, d);
        // SHAKE domain bits 1111 then the pad10*1 rule (FIPS 202 section 6.2 and appendix B.2).
        state[pos >> 3] ^= 0x1FUL << (8 * (pos & 7));
        state[(Rate - 1) >> 3] ^= 0x80UL << (8 * ((Rate - 1) & 7));
        int done = 0;
        while (true)
        {
            Permute(state);
            int n = Math.Min(Rate, output.Length - done);
            for (int i = 0; i < n; i++)
            {
                output[done + i] = (byte)(state[i >> 3] >> (8 * (i & 7)));
            }
            done += n;
            if (done == output.Length)
            {
                break;
            }
        }
        state.Clear();
    }

    private static void Absorb(Span<ulong> state, ref int pos, ReadOnlySpan<byte> data)
    {
        foreach (byte v in data)
        {
            state[pos >> 3] ^= (ulong)v << (8 * (pos & 7));
            if (++pos == Rate)
            {
                Permute(state);
                pos = 0;
            }
        }
    }

    private static void Permute(Span<ulong> a)
    {
        Span<ulong> bState = stackalloc ulong[25]; // fixed small buffers
        Span<ulong> c = stackalloc ulong[5];
        ReadOnlySpan<ulong> rc = RoundConstants;
        int[] rot = Rotations;
        for (int round = 0; round < 24; round++)
        {
            // theta
            for (int x = 0; x < 5; x++)
            {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }
            for (int x = 0; x < 5; x++)
            {
                ulong dx = c[(x + 4) % 5] ^ ulong.RotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5)
                {
                    a[x + y] ^= dx;
                }
            }
            // rho and pi: lane (x, y) moves to (y, 2x + 3y)
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    bState[y + (5 * (((2 * x) + (3 * y)) % 5))] = ulong.RotateLeft(a[x + (5 * y)], rot[x + (5 * y)]);
                }
            }
            // chi
            for (int y = 0; y < 25; y += 5)
            {
                for (int x = 0; x < 5; x++)
                {
                    a[x + y] = bState[x + y] ^ (~bState[((x + 1) % 5) + y] & bState[((x + 2) % 5) + y]);
                }
            }
            // iota
            a[0] ^= rc[round];
        }
        bState.Clear();
    }
}
