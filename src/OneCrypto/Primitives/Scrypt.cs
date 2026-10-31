using System.Buffers.Binary;
using System.Numerics;
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

                RoMix(x, t, v, cost, blockSize);
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
    private static void RoMix(uint[] x, uint[] t, uint[] v, int n, int r)
    {
        int words = 32 * r;

        // V[0] = B, V[i + 1] = BlockMix(V[i]); the final BlockMix result is X.
        x.AsSpan().CopyTo(v);
        for (int i = 0; i < n - 1; i++)
        {
            BlockMix(v.AsSpan(i * words, words), v.AsSpan((i + 1) * words, words), r);
        }

        BlockMix(v.AsSpan((n - 1) * words, words), x, r);

        uint[] cur = x;
        uint[] other = t;
        for (int i = 0; i < n; i++)
        {
            // Integerify: the first word of the last 64-byte block, reduced mod N (a power of two no larger than 2^30, so
            // the low 32 bits are enough). The address depends on the data by design.
            int j = (int)(cur[words - 16] & (uint)(n - 1));
            XorInto(cur, v.AsSpan(j * words, words));

            BlockMix(cur, other, r);
            (cur, other) = (other, cur);
        }

        if (!ReferenceEquals(cur, x))
        {
            cur.AsSpan().CopyTo(x);
        }
    }

    // destination ^= source, for equal-length spans (a multiple of 16 words).
    private static void XorInto(Span<uint> destination, ReadOnlySpan<uint> source)
    {
        for (int w = 0; w < source.Length; w++)
        {
            destination[w] ^= source[w];
        }
    }

    // RFC 7914 §4: BlockMix with Salsa20/8; the even outputs come first, then the odd ones. X starts as the last block of the
    // input and each Salsa20/8 reads the previous result straight from where it was written, so nothing is copied between steps.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void BlockMix(ReadOnlySpan<uint> input, Span<uint> output, int r)
    {
        ReadOnlySpan<uint> previous = input.Slice(((2 * r) - 1) * 16, 16);
        for (int i = 0; i < 2 * r; i++)
        {
            int target = (i & 1) == 0 ? i / 2 : r + (i / 2);
            Span<uint> destination = output.Slice(target * 16, 16);
            Salsa208Xor(previous, input.Slice(i * 16, 16), destination);
            previous = destination;
        }
    }

    // RFC 7914 §3: destination = Salsa20/8(previous xor block), the 8-round core with the feed-forward addition.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Salsa208Xor(ReadOnlySpan<uint> previous, ReadOnlySpan<uint> block, Span<uint> destination)
    {
        uint j0 = previous[0] ^ block[0], j1 = previous[1] ^ block[1], j2 = previous[2] ^ block[2], j3 = previous[3] ^ block[3];
        uint j4 = previous[4] ^ block[4], j5 = previous[5] ^ block[5], j6 = previous[6] ^ block[6], j7 = previous[7] ^ block[7];
        uint j8 = previous[8] ^ block[8], j9 = previous[9] ^ block[9], j10 = previous[10] ^ block[10], j11 = previous[11] ^ block[11];
        uint j12 = previous[12] ^ block[12], j13 = previous[13] ^ block[13], j14 = previous[14] ^ block[14], j15 = previous[15] ^ block[15];
        uint x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7;
        uint x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15;
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

        destination[0] = j0 + x0;
        destination[1] = j1 + x1;
        destination[2] = j2 + x2;
        destination[3] = j3 + x3;
        destination[4] = j4 + x4;
        destination[5] = j5 + x5;
        destination[6] = j6 + x6;
        destination[7] = j7 + x7;
        destination[8] = j8 + x8;
        destination[9] = j9 + x9;
        destination[10] = j10 + x10;
        destination[11] = j11 + x11;
        destination[12] = j12 + x12;
        destination[13] = j13 + x13;
        destination[14] = j14 + x14;
        destination[15] = j15 + x15;
    }
}
