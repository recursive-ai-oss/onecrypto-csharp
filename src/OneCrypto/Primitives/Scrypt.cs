using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.Intrinsics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// scrypt (RFC 7914): PBKDF2-HMAC-SHA256 from the platform around our Salsa20/8, BlockMix and ROMix.
/// </summary>
/// <remarks>
/// <para>Side channels: ROMix reads <c>V[j]</c> with <c>j</c> taken from the data being mixed, so the memory access pattern
/// depends on the password. That is how scrypt is defined (RFC 7914 §5); it is documented, not worked around. Nothing else
/// branches or indexes on secret data.</para>
/// <para>The cost is checked against <see cref="KdfLimits"/> before any memory is allocated. Lanes (the parameter p) run one after
/// another and share one working buffer, so memory does not grow with p.</para>
/// </remarks>
public static class Scrypt
{
    /// <summary>Derives <paramref name="destination"/>.Length bytes.</summary>
    /// <param name="password">The password. May be empty.</param>
    /// <param name="salt">The salt. May be empty.</param>
    /// <param name="cost">N: the CPU/memory cost, a power of two greater than 1.</param>
    /// <param name="blockSize">r: the block size parameter, at least 1.</param>
    /// <param name="parallelism">p: at least 1, with r × p below 2^30.</param>
    /// <param name="destination">Receives the key; at most (2^32 − 1) × 32 bytes.</param>
    /// <param name="limits">Cost bounds; <see cref="KdfLimits.Default"/> when <see langword="null"/>.</param>
    /// <exception cref="ArgumentException">A parameter is outside the range RFC 7914 §2 allows.</exception>
    /// <exception cref="KdfLimitExceededException">The parameters exceed <paramref name="limits"/>.</exception>
    public static void DeriveKey(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        int cost,
        int blockSize,
        int parallelism,
        Span<byte> destination,
        KdfLimits? limits = null)
    {
        limits ??= KdfLimits.Default;

        // RFC 7914 §2: N is a power of two larger than 1 and below 2^(128 * r / 8); r * p < 2^30.
        if (cost < 2 || !BitOperations.IsPow2(cost))
        {
            throw new ArgumentOutOfRangeException(nameof(cost), "scrypt N must be a power of two greater than 1.");
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(blockSize, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(parallelism, 1);
        if ((long)blockSize * parallelism >= 1L << 30)
        {
            throw new ArgumentOutOfRangeException(nameof(parallelism), "scrypt r * p must be below 2^30.");
        }

        if (blockSize < 2 && cost >= 1 << (16 * blockSize))
        {
            throw new ArgumentOutOfRangeException(nameof(cost), "scrypt N must be below 2^(16 * r).");
        }

        KdfLimits.Require("scrypt", "work (N * r * p)", (long)cost * blockSize * parallelism, limits.MaxScryptWork);
        long wordsPerBlock = 32L * blockSize;
        limits.RequireMemory("scrypt", (4L * wordsPerBlock * (cost + 3)) + (128L * blockSize * parallelism), sizeof(uint));

        limits.RequireMemory("scrypt", 128L * blockSize * parallelism, sizeof(byte));
        int blockBytes = 128 * blockSize;
        byte[] b = GC.AllocateUninitializedArray<byte>(parallelism * blockBytes, pinned: true);
        uint[] v = GC.AllocateUninitializedArray<uint>((int)(wordsPerBlock * cost), pinned: true);
        uint[] x = GC.AllocateUninitializedArray<uint>((int)wordsPerBlock, pinned: true);
        uint[] t = GC.AllocateUninitializedArray<uint>((int)wordsPerBlock, pinned: true);
        uint[] scratch = GC.AllocateUninitializedArray<uint>(16, pinned: true);
        try
        {
            // RFC 7914 §6 steps 1-2: B = PBKDF2-HMAC-SHA256(P, S, 1, p * 128 * r).
            Rfc2898DeriveBytes.Pbkdf2(password, salt, b, 1, HashAlgorithmName.SHA256);
            for (int i = 0; i < parallelism; i++)
            {
                Span<byte> lane = b.AsSpan(i * blockBytes, blockBytes);
                for (int w = 0; w < x.Length; w++)
                {
                    x[w] = BinaryPrimitives.ReadUInt32LittleEndian(lane[(4 * w)..]);
                }

                RoMix(x, t, v, cost, blockSize, scratch);
                for (int w = 0; w < x.Length; w++)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(lane[(4 * w)..], x[w]);
                }
            }

            // Step 3: DK = PBKDF2-HMAC-SHA256(P, B, 1, dkLen).
            Rfc2898DeriveBytes.Pbkdf2(password, b, destination, 1, HashAlgorithmName.SHA256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(b);
            Wipe.Array(v);
            Wipe.Array(x);
            Wipe.Array(t);
            Wipe.Array(scratch);
        }
    }

    /// <summary>Derives a key of <paramref name="length"/> bytes; see the span overload for the parameters.</summary>
    public static byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int cost, int blockSize, int parallelism, int length, KdfLimits? limits = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        byte[] key = new byte[length];
        DeriveKey(password, salt, cost, blockSize, parallelism, key, limits);
        return key;
    }

    // RFC 7914 §5: ROMix. x holds B on entry and the result on exit; t is a second block-sized buffer.
    private static void RoMix(uint[] x, uint[] t, uint[] v, int n, int r, uint[] scratch)
    {
        int words = 32 * r;

        // V[0] = B, V[i + 1] = BlockMix(V[i]); the final BlockMix result is X.
        x.AsSpan().CopyTo(v);
        for (int i = 0; i < n - 1; i++)
        {
            BlockMix(v.AsSpan(i * words, words), v.AsSpan((i + 1) * words, words), r, scratch);
        }

        BlockMix(v.AsSpan((n - 1) * words, words), x, r, scratch);

        uint[] cur = x;
        uint[] other = t;
        for (int i = 0; i < n; i++)
        {
            // Integerify: the first word of the last 64-byte block, reduced mod N (a power of two no larger than 2^30, so
            // the low 32 bits are enough). The address depends on the data by design.
            int j = (int)(cur[words - 16] & (uint)(n - 1));
            XorInto(cur, v.AsSpan(j * words, words));

            BlockMix(cur, other, r, scratch);
            (cur, other) = (other, cur);
        }

        if (!ReferenceEquals(cur, x))
        {
            cur.AsSpan().CopyTo(x);
        }
    }

    // destination ^= source over a whole number of 4-word groups (every scrypt block is a multiple of 16 words).
    private static void XorInto(Span<uint> destination, ReadOnlySpan<uint> source)
    {
        if (Vector128.IsHardwareAccelerated)
        {
            for (int w = 0; w < source.Length; w += 4)
            {
                (Vector128.Create<uint>(destination.Slice(w, 4)) ^ Vector128.Create(source.Slice(w, 4))).CopyTo(destination.Slice(w, 4));
            }
        }
        else
        {
            for (int w = 0; w < source.Length; w++)
            {
                destination[w] ^= source[w];
            }
        }
    }

    // RFC 7914 §4: BlockMix with Salsa20/8; the even outputs come first, then the odd ones.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void BlockMix(ReadOnlySpan<uint> input, Span<uint> output, int r, Span<uint> x)
    {
        input.Slice(((2 * r) - 1) * 16, 16).CopyTo(x);
        for (int i = 0; i < 2 * r; i++)
        {
            XorInto(x, input.Slice(i * 16, 16));

            if (Vector128.IsHardwareAccelerated)
            {
                Salsa208Vector(x);
            }
            else
            {
                Salsa208(x);
            }

            int target = (i & 1) == 0 ? i / 2 : r + (i / 2);
            x.CopyTo(output.Slice(target * 16, 16));
        }
    }

    // RFC 7914 §3: the Salsa20/8 core, in place, with one 4-word vector per diagonal so a quarter-round runs on four columns at
    // once. Between the column round and the row round the vectors are rotated by lane, as in the usual SIMD formulation of
    // Salsa20; the scalar Salsa208 below is the reference and the fallback when 128-bit vectors are not accelerated.
    internal static void Salsa208Vector(Span<uint> b)
    {
        Vector128<uint> a = Vector128.Create(b[0], b[5], b[10], b[15]);
        Vector128<uint> v1 = Vector128.Create(b[4], b[9], b[14], b[3]);
        Vector128<uint> v2 = Vector128.Create(b[8], b[13], b[2], b[7]);
        Vector128<uint> v3 = Vector128.Create(b[12], b[1], b[6], b[11]);
        Vector128<uint> a0 = a, b0 = v1, c0 = v2, d0 = v3;
        Vector128<uint> s1 = Vector128.Create(1u, 2, 3, 0);
        Vector128<uint> s2 = Vector128.Create(2u, 3, 0, 1);
        Vector128<uint> s3 = Vector128.Create(3u, 0, 1, 2);
        for (int i = 0; i < 8; i += 2)
        {
            // Column round: lane j is the quarter-round of column j.
            v1 ^= RotateLeft(a + v3, 7);
            v2 ^= RotateLeft(v1 + a, 9);
            v3 ^= RotateLeft(v2 + v1, 13);
            a ^= RotateLeft(v3 + v2, 18);

            // Row round on the transposed diagonals.
            Vector128<uint> rb = Vector128.Shuffle(v3, s1);
            Vector128<uint> rc = Vector128.Shuffle(v2, s2);
            Vector128<uint> rd = Vector128.Shuffle(v1, s3);
            rb ^= RotateLeft(a + rd, 7);
            rc ^= RotateLeft(rb + a, 9);
            rd ^= RotateLeft(rc + rb, 13);
            a ^= RotateLeft(rd + rc, 18);
            v1 = Vector128.Shuffle(rd, s1);
            v2 = Vector128.Shuffle(rc, s2);
            v3 = Vector128.Shuffle(rb, s3);
        }

        a += a0;
        v1 += b0;
        v2 += c0;
        v3 += d0;
        b[0] = a[0];
        b[5] = a[1];
        b[10] = a[2];
        b[15] = a[3];
        b[4] = v1[0];
        b[9] = v1[1];
        b[14] = v1[2];
        b[3] = v1[3];
        b[8] = v2[0];
        b[13] = v2[1];
        b[2] = v2[2];
        b[7] = v2[3];
        b[12] = v3[0];
        b[1] = v3[1];
        b[6] = v3[2];
        b[11] = v3[3];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> RotateLeft(Vector128<uint> v, int n) =>
        Vector128.ShiftLeft(v, n) | Vector128.ShiftRightLogical(v, 32 - n);

    // RFC 7914 §3: the Salsa20/8 core, in place (scalar reference).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void Salsa208(Span<uint> b)
    {
        uint x0 = b[0], x1 = b[1], x2 = b[2], x3 = b[3], x4 = b[4], x5 = b[5], x6 = b[6], x7 = b[7];
        uint x8 = b[8], x9 = b[9], x10 = b[10], x11 = b[11], x12 = b[12], x13 = b[13], x14 = b[14], x15 = b[15];
        for (int i = 0; i < 8; i += 2)
        {
            x4 ^= BitOperations.RotateLeft(x0 + x12, 7);
            x8 ^= BitOperations.RotateLeft(x4 + x0, 9);
            x12 ^= BitOperations.RotateLeft(x8 + x4, 13);
            x0 ^= BitOperations.RotateLeft(x12 + x8, 18);
            x9 ^= BitOperations.RotateLeft(x5 + x1, 7);
            x13 ^= BitOperations.RotateLeft(x9 + x5, 9);
            x1 ^= BitOperations.RotateLeft(x13 + x9, 13);
            x5 ^= BitOperations.RotateLeft(x1 + x13, 18);
            x14 ^= BitOperations.RotateLeft(x10 + x6, 7);
            x2 ^= BitOperations.RotateLeft(x14 + x10, 9);
            x6 ^= BitOperations.RotateLeft(x2 + x14, 13);
            x10 ^= BitOperations.RotateLeft(x6 + x2, 18);
            x3 ^= BitOperations.RotateLeft(x15 + x11, 7);
            x7 ^= BitOperations.RotateLeft(x3 + x15, 9);
            x11 ^= BitOperations.RotateLeft(x7 + x3, 13);
            x15 ^= BitOperations.RotateLeft(x11 + x7, 18);

            x1 ^= BitOperations.RotateLeft(x0 + x3, 7);
            x2 ^= BitOperations.RotateLeft(x1 + x0, 9);
            x3 ^= BitOperations.RotateLeft(x2 + x1, 13);
            x0 ^= BitOperations.RotateLeft(x3 + x2, 18);
            x6 ^= BitOperations.RotateLeft(x5 + x4, 7);
            x7 ^= BitOperations.RotateLeft(x6 + x5, 9);
            x4 ^= BitOperations.RotateLeft(x7 + x6, 13);
            x5 ^= BitOperations.RotateLeft(x4 + x7, 18);
            x11 ^= BitOperations.RotateLeft(x10 + x9, 7);
            x8 ^= BitOperations.RotateLeft(x11 + x10, 9);
            x9 ^= BitOperations.RotateLeft(x8 + x11, 13);
            x10 ^= BitOperations.RotateLeft(x9 + x8, 18);
            x12 ^= BitOperations.RotateLeft(x15 + x14, 7);
            x13 ^= BitOperations.RotateLeft(x12 + x15, 9);
            x14 ^= BitOperations.RotateLeft(x13 + x12, 13);
            x15 ^= BitOperations.RotateLeft(x14 + x13, 18);
        }

        b[0] += x0;
        b[1] += x1;
        b[2] += x2;
        b[3] += x3;
        b[4] += x4;
        b[5] += x5;
        b[6] += x6;
        b[7] += x7;
        b[8] += x8;
        b[9] += x9;
        b[10] += x10;
        b[11] += x11;
        b[12] += x12;
        b[13] += x13;
        b[14] += x14;
        b[15] += x15;
    }
}
