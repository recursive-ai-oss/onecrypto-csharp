using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>The three Argon2 variants of RFC 9106 §3.1; the numbers are the type code y that the algorithm hashes in.</summary>
public enum Argon2Type
{
    /// <summary>Data-dependent addressing: fastest against GPUs and ASICs, but the memory access pattern depends on the password.</summary>
    Argon2d = 0,

    /// <summary>Data-independent addressing: the memory access pattern depends only on the public parameters.</summary>
    Argon2i = 1,

    /// <summary>
    /// Data-independent addressing for the first half of the first pass, data-dependent afterwards. The recommended choice
    /// (RFC 9106 §4).
    /// </summary>
    Argon2id = 2,
}

/// <summary>
/// Argon2 (RFC 9106), version 0x13: the memory-hard password hash and key-derivation function.
/// </summary>
/// <remarks>
/// <para>Parameters follow the RFC: <c>memoryKiB</c> is m (in 1 KiB blocks, at least 8 × lanes, rounded down to a multiple of
/// 4 × lanes), <c>passes</c> is t, <c>parallelism</c> is p. The salt is at least 8 bytes (16 recommended); the tag is at least
/// 4 bytes. The optional secret value K and associated data X are the RFC's. Several lanes run on several threads when the
/// memory is large enough for that to pay.</para>
/// <para>Side channels: for <see cref="Argon2Type.Argon2i"/> every memory index depends only on the public parameters, so the
/// password influences no address. <see cref="Argon2Type.Argon2d"/> chooses reference blocks from block contents by design,
/// and <see cref="Argon2Type.Argon2id"/> does so from the second half of the first pass on; neither is claimed to resist an
/// attacker who can observe the memory access pattern. No branch or loop bound depends on the password in any variant.</para>
/// <para>The cost is checked against <see cref="KdfLimits"/> before any memory is allocated.</para>
/// </remarks>
public static class Argon2
{
    private const int BlockWords = 128; // a block is 1024 bytes = 128 little-endian 64-bit words
    private const int SyncPoints = 4; // RFC 9106 §3.4: SL = 4 slices
    private const int ParallelMinSegmentBlocks = 256;

    /// <summary>Derives <paramref name="destination"/>.Length bytes (the tag, at least 4) and writes them to <paramref name="destination"/>.</summary>
    /// <param name="type">The variant.</param>
    /// <param name="password">The password P. May be empty.</param>
    /// <param name="salt">The salt S, 8 bytes or more.</param>
    /// <param name="memoryKiB">m: memory in KiB, at least 8 × <paramref name="parallelism"/>.</param>
    /// <param name="passes">t: the number of passes, at least 1.</param>
    /// <param name="parallelism">p: the number of lanes, 1 to 2^24 − 1.</param>
    /// <param name="destination">Receives the tag; its length is the tag length T.</param>
    /// <param name="secret">The optional secret value K (a pepper).</param>
    /// <param name="associatedData">The optional associated data X.</param>
    /// <param name="limits">Cost bounds; <see cref="KdfLimits.Default"/> when <see langword="null"/>.</param>
    /// <exception cref="ArgumentException">A parameter is outside the range the RFC allows.</exception>
    /// <exception cref="KdfLimitExceededException">The parameters exceed <paramref name="limits"/>.</exception>
    public static void DeriveKey(
        Argon2Type type,
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        int memoryKiB,
        int passes,
        int parallelism,
        Span<byte> destination,
        ReadOnlySpan<byte> secret = default,
        ReadOnlySpan<byte> associatedData = default,
        KdfLimits? limits = null)
    {
        limits ??= KdfLimits.Default;
        string name = type.ToString();
        if (type is not (Argon2Type.Argon2d or Argon2Type.Argon2i or Argon2Type.Argon2id))
        {
            throw new ArgumentOutOfRangeException(nameof(type));
        }

        // RFC 9106 §3.1: input ranges.
        ArgumentOutOfRangeException.ThrowIfLessThan(parallelism, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(parallelism, (1 << 24) - 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(passes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 4);
        if (salt.Length < 8)
        {
            throw new ArgumentException("The Argon2 salt must be at least 8 bytes.", nameof(salt));
        }

        if (memoryKiB < 8L * parallelism)
        {
            throw new ArgumentOutOfRangeException(nameof(memoryKiB), "Argon2 memory must be at least 8 KiB per lane.");
        }

        KdfLimits.Require(name, "passes", passes, limits.MaxArgon2Passes);
        KdfLimits.Require(name, "parallelism", parallelism, limits.MaxArgon2Parallelism);

        // RFC 9106 §3.2 step 2: m' = 4p * floor(m / 4p).
        int mPrime = 4 * parallelism * (memoryKiB / (4 * parallelism));
        limits.RequireMemory(name, mPrime * 1024L, sizeof(ulong));

        Span<byte> h0 = stackalloc byte[64]; // fixed 64-byte buffer
        PreHash(type, password, salt, memoryKiB, passes, parallelism, destination.Length, secret, associatedData, h0);

        ulong[] memory = GC.AllocateUninitializedArray<ulong>(mPrime * BlockWords, pinned: true);
        try
        {
            Fill(type, memory, mPrime, passes, parallelism, h0);
            Finish(memory, mPrime / parallelism, parallelism, destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryAsBytes(memory));
            CryptographicOperations.ZeroMemory(h0);
        }
    }

    /// <summary>Derives a tag of <paramref name="tagLength"/> bytes; see the span overload for the parameters.</summary>
    public static byte[] DeriveKey(
        Argon2Type type,
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        int memoryKiB,
        int passes,
        int parallelism,
        int tagLength,
        ReadOnlySpan<byte> secret = default,
        ReadOnlySpan<byte> associatedData = default,
        KdfLimits? limits = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(tagLength, 4);
        byte[] tag = new byte[tagLength];
        DeriveKey(type, password, salt, memoryKiB, passes, parallelism, tag, secret, associatedData, limits);
        return tag;
    }

    /// <summary>
    /// Recomputes the tag and compares it with <paramref name="expectedTag"/> in constant time. Returns <see langword="true"/>
    /// when they are equal; the comparison does not stop at the first differing byte.
    /// </summary>
    public static bool Verify(
        Argon2Type type,
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        int memoryKiB,
        int passes,
        int parallelism,
        ReadOnlySpan<byte> expectedTag,
        ReadOnlySpan<byte> secret = default,
        ReadOnlySpan<byte> associatedData = default,
        KdfLimits? limits = null)
    {
        byte[] tag = new byte[expectedTag.Length];
        try
        {
            DeriveKey(type, password, salt, memoryKiB, passes, parallelism, tag, secret, associatedData, limits);
            return CryptographicOperations.FixedTimeEquals(tag, expectedTag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    // RFC 9106 §3.2 step 1: H_0.
    private static void PreHash(
        Argon2Type type, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int m, int t, int p, int tagLength,
        ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, Span<byte> h0)
    {
        var h = new Blake2b(64);
        h.UpdateLe32((uint)p);
        h.UpdateLe32((uint)tagLength);
        h.UpdateLe32((uint)m);
        h.UpdateLe32((uint)t);
        h.UpdateLe32(0x13);
        h.UpdateLe32((uint)type);
        h.UpdateLe32((uint)password.Length);
        h.Update(password);
        h.UpdateLe32((uint)salt.Length);
        h.Update(salt);
        h.UpdateLe32((uint)secret.Length);
        h.Update(secret);
        h.UpdateLe32((uint)associatedData.Length);
        h.Update(associatedData);
        h.Finish(h0);
    }

    // RFC 9106 §3.3: H'^T(A) where A is given as a prefix span.
    private static void HPrime(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int length = output.Length;
        if (length <= 64)
        {
            var h = new Blake2b(length);
            h.UpdateLe32((uint)length);
            h.Update(input);
            h.Finish(output);
            return;
        }

        int r = ((length + 31) / 32) - 2;
        Span<byte> v = stackalloc byte[64]; // fixed 64-byte buffer
        var first = new Blake2b(64);
        first.UpdateLe32((uint)length);
        first.Update(input);
        first.Finish(v);
        v[..32].CopyTo(output);
        int written = 32;
        for (int i = 2; i <= r; i++)
        {
            Blake2b.Hash(v, v);
            v[..32].CopyTo(output[written..]);
            written += 32;
        }

        Span<byte> last = output[written..];
        var tail = new Blake2b(last.Length);
        tail.Update(v);
        tail.Finish(last);
        CryptographicOperations.ZeroMemory(v);
    }

    private static void Fill(Argon2Type type, ulong[] memory, int mPrime, int passes, int lanes, ReadOnlySpan<byte> h0)
    {
        int laneLength = mPrime / lanes;
        int segmentLength = laneLength / SyncPoints;

        // RFC 9106 §3.2 steps 3 and 4: the first two blocks of every lane.
        Span<byte> seed = stackalloc byte[72]; // fixed 72-byte buffer: H_0 || LE32(column) || LE32(lane)
        Span<byte> bytes = stackalloc byte[1024]; // fixed 1 KiB buffer
        h0.CopyTo(seed);
        for (int lane = 0; lane < lanes; lane++)
        {
            for (int column = 0; column < 2; column++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(seed[64..], (uint)column);
                BinaryPrimitives.WriteUInt32LittleEndian(seed[68..], (uint)lane);
                HPrime(seed, bytes);
                Span<ulong> block = memory.AsSpan(((lane * laneLength) + column) * BlockWords, BlockWords);
                for (int w = 0; w < BlockWords; w++)
                {
                    block[w] = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(8 * w)..]);
                }
            }
        }

        CryptographicOperations.ZeroMemory(seed);
        CryptographicOperations.ZeroMemory(bytes);

        var workers = new Worker[lanes];
        for (int i = 0; i < lanes; i++)
        {
            workers[i] = new Worker();
        }

        bool parallel = lanes > 1 && segmentLength >= ParallelMinSegmentBlocks;
        for (int pass = 0; pass < passes; pass++)
        {
            for (int slice = 0; slice < SyncPoints; slice++)
            {
                // RFC 9106 §3.2 step 5: slices are computed one after another; the segments of one slice are independent.
                int passNow = pass;
                int sliceNow = slice;
                if (parallel)
                {
                    Parallel.For(0, lanes, lane => FillSegment(type, memory, mPrime, passes, lanes, laneLength, segmentLength, passNow, lane, sliceNow, workers[lane]));
                }
                else
                {
                    for (int lane = 0; lane < lanes; lane++)
                    {
                        FillSegment(type, memory, mPrime, passes, lanes, laneLength, segmentLength, pass, lane, slice, workers[lane]);
                    }
                }
            }
        }

        foreach (Worker w in workers)
        {
            w.Clear();
        }
    }

    private static void FillSegment(
        Argon2Type type, ulong[] memory, int mPrime, int passes, int lanes, int laneLength, int segmentLength,
        int pass, int lane, int slice, Worker w)
    {
        // RFC 9106 §3.4.1.3: Argon2id addresses data-independently in the first two slices of the first pass.
        bool independent = type == Argon2Type.Argon2i || (type == Argon2Type.Argon2id && pass == 0 && slice < 2);
        int start = (pass == 0 && slice == 0) ? 2 : 0; // the first two blocks of a lane are already set

        if (independent)
        {
            Array.Clear(w.Input);
            w.Input[0] = (ulong)pass;
            w.Input[1] = (ulong)lane;
            w.Input[2] = (ulong)slice;
            w.Input[3] = (ulong)mPrime;
            w.Input[4] = (ulong)passes;
            w.Input[5] = (ulong)type;
        }

        int laneBase = lane * laneLength;
        int index = laneBase + (slice * segmentLength) + start; // block being computed
        for (int i = start; i < segmentLength; i++, index++)
        {
            // The previous block: the last block of the lane when computing column 0.
            int previous = (index % laneLength == 0) ? index + laneLength - 1 : index - 1;

            ulong random;
            if (independent)
            {
                // RFC 9106 §3.4.1.2: one address block yields 128 pairs (J1, J2).
                if (i == start || (i % BlockWords) == 0)
                {
                    w.Input[6]++;
                    CompressBlock(Zero, w.Input, w.Temp, w.R, w.Z, false);
                    CompressBlock(Zero, w.Temp, w.Address, w.R, w.Z, false);
                }

                random = w.Address[i % BlockWords];
            }
            else
            {
                random = memory[previous * BlockWords];
            }

            uint j1 = (uint)random;
            uint j2 = (uint)(random >> 32);

            // RFC 9106 §3.4.2: the lane, then the position, of the reference block.
            int refLane = (pass == 0 && slice == 0) ? lane : (int)(j2 % (uint)lanes);
            bool sameLane = refLane == lane;
            long areaSize;
            if (pass == 0)
            {
                if (slice == 0)
                {
                    areaSize = i - 1;
                }
                else if (sameLane)
                {
                    areaSize = (slice * (long)segmentLength) + i - 1;
                }
                else
                {
                    areaSize = (slice * (long)segmentLength) - (i == 0 ? 1 : 0);
                }
            }
            else if (sameLane)
            {
                areaSize = laneLength - segmentLength + i - 1;
            }
            else
            {
                areaSize = laneLength - segmentLength - (i == 0 ? 1 : 0);
            }

            // Figure 13: x = J1^2 / 2^32, y = |W| * x / 2^32, zz = |W| - 1 - y.
            ulong x = ((ulong)j1 * j1) >> 32;
            ulong y = ((ulong)areaSize * x) >> 32;
            long relative = areaSize - 1 - (long)y;

            // W starts at the oldest block still referenceable: after the current slice on later passes.
            long startPosition = (pass != 0 && slice != SyncPoints - 1) ? (slice + 1L) * segmentLength : 0;
            int z = (int)((startPosition + relative) % laneLength);
            int reference = (refLane * laneLength) + z;

            CompressBlock(
                memory.AsSpan(previous * BlockWords, BlockWords),
                memory.AsSpan(reference * BlockWords, BlockWords),
                memory.AsSpan(index * BlockWords, BlockWords),
                w.R,
                w.Z,
                pass > 0); // RFC 9106 §3.2 step 6: later passes XOR into the old block
        }
    }

    private static readonly ulong[] Zero = new ulong[BlockWords];

    // RFC 9106 §3.2 step 7 and 8: XOR the last column, then H'^T.
    private static void Finish(ulong[] memory, int laneLength, int lanes, Span<byte> tag)
    {
        Span<ulong> c = new ulong[BlockWords];
        for (int lane = 0; lane < lanes; lane++)
        {
            ReadOnlySpan<ulong> last = memory.AsSpan((((lane * laneLength) + laneLength) - 1) * BlockWords, BlockWords);
            for (int w = 0; w < BlockWords; w++)
            {
                c[w] ^= last[w];
            }
        }

        Span<byte> bytes = stackalloc byte[1024]; // fixed 1 KiB buffer
        for (int w = 0; w < BlockWords; w++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(bytes[(8 * w)..], c[w]);
        }

        HPrime(bytes, tag);
        CryptographicOperations.ZeroMemory(bytes);
        c.Clear();
    }

    // RFC 9106 §3.5: G(X, Y) = P-columns(P-rows(X xor Y)) xor (X xor Y), and XORed into the old value on later passes.
    private static void CompressBlock(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> destination, Span<ulong> r, Span<ulong> scratch, bool xorDestination)
    {
        for (int i = 0; i < BlockWords; i++)
        {
            r[i] = x[i] ^ y[i];
        }

        // Z is built in place in a copy of R held in the destination, then R is XORed back in.
        Span<ulong> z = xorDestination ? scratch : destination;
        r.CopyTo(z);
        for (int row = 0; row < 8; row++)
        {
            Permute(z, 16 * row, 2);
        }

        for (int column = 0; column < 8; column++)
        {
            Permute(z, 2 * column, 16);
        }

        if (xorDestination)
        {
            for (int i = 0; i < BlockWords; i++)
            {
                destination[i] ^= z[i] ^ r[i];
            }
        }
        else
        {
            for (int i = 0; i < BlockWords; i++)
            {
                destination[i] = z[i] ^ r[i];
            }
        }
    }

    // RFC 9106 §3.6: the permutation P on eight 16-byte registers; register i is the word pair at o + i * s.
    private static void Permute(Span<ulong> t, int o, int s)
    {
        ulong v0 = t[o], v1 = t[o + 1];
        ulong v2 = t[o + s], v3 = t[o + s + 1];
        ulong v4 = t[o + (2 * s)], v5 = t[o + (2 * s) + 1];
        ulong v6 = t[o + (3 * s)], v7 = t[o + (3 * s) + 1];
        ulong v8 = t[o + (4 * s)], v9 = t[o + (4 * s) + 1];
        ulong v10 = t[o + (5 * s)], v11 = t[o + (5 * s) + 1];
        ulong v12 = t[o + (6 * s)], v13 = t[o + (6 * s) + 1];
        ulong v14 = t[o + (7 * s)], v15 = t[o + (7 * s) + 1];

        Gb(ref v0, ref v4, ref v8, ref v12);
        Gb(ref v1, ref v5, ref v9, ref v13);
        Gb(ref v2, ref v6, ref v10, ref v14);
        Gb(ref v3, ref v7, ref v11, ref v15);
        Gb(ref v0, ref v5, ref v10, ref v15);
        Gb(ref v1, ref v6, ref v11, ref v12);
        Gb(ref v2, ref v7, ref v8, ref v13);
        Gb(ref v3, ref v4, ref v9, ref v14);

        t[o] = v0;
        t[o + 1] = v1;
        t[o + s] = v2;
        t[o + s + 1] = v3;
        t[o + (2 * s)] = v4;
        t[o + (2 * s) + 1] = v5;
        t[o + (3 * s)] = v6;
        t[o + (3 * s) + 1] = v7;
        t[o + (4 * s)] = v8;
        t[o + (4 * s) + 1] = v9;
        t[o + (5 * s)] = v10;
        t[o + (5 * s) + 1] = v11;
        t[o + (6 * s)] = v12;
        t[o + (6 * s) + 1] = v13;
        t[o + (7 * s)] = v14;
        t[o + (7 * s) + 1] = v15;
    }

    // RFC 9106 §3.6 Figure 19: BLAKE2b's G with the additions replaced by a + b + 2 * lo32(a) * lo32(b).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Gb(ref ulong a, ref ulong b, ref ulong c, ref ulong d)
    {
        a = a + b + (2UL * (uint)a * (uint)b);
        d = BitOperations.RotateRight(d ^ a, 32);
        c = c + d + (2UL * (uint)c * (uint)d);
        b = BitOperations.RotateRight(b ^ c, 24);
        a = a + b + (2UL * (uint)a * (uint)b);
        d = BitOperations.RotateRight(d ^ a, 16);
        c = c + d + (2UL * (uint)c * (uint)d);
        b = BitOperations.RotateRight(b ^ c, 63);
    }

    private static Span<byte> MemoryAsBytes(ulong[] memory) =>
        System.Runtime.InteropServices.MemoryMarshal.AsBytes(memory.AsSpan());

    // Per-lane scratch so lanes can run on different threads.
    private sealed class Worker
    {
        public ulong[] Input { get; } = new ulong[BlockWords];

        public ulong[] Temp { get; } = new ulong[BlockWords];

        public ulong[] Address { get; } = new ulong[BlockWords];

        public ulong[] R { get; } = new ulong[BlockWords];

        public ulong[] Z { get; } = new ulong[BlockWords];

        public void Clear()
        {
            Array.Clear(Input);
            Array.Clear(Temp);
            Array.Clear(Address);
            Array.Clear(R);
            Array.Clear(Z);
        }
    }
}
