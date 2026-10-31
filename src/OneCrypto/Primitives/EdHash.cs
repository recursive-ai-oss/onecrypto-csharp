using System.Buffers.Binary;
using System.Security.Cryptography;

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

    public static void Hash(Span<byte> output, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d)
    {
        Span<ulong> state = stackalloc ulong[25]; // fixed small buffers
        Span<byte> block = stackalloc byte[Rate];
        state.Clear();
        int pos = 0;
        Absorb(state, block, ref pos, a);
        Absorb(state, block, ref pos, b);
        Absorb(state, block, ref pos, c);
        Absorb(state, block, ref pos, d);
        // SHAKE domain bits 1111 then the pad10*1 rule (FIPS 202 section 6.2 and appendix B.2).
        block[pos..].Clear();
        block[pos] ^= 0x1F;
        block[Rate - 1] ^= 0x80;
        XorBlock(state, block);
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
        block.Clear();
    }

    private static void XorBlock(Span<ulong> state, ReadOnlySpan<byte> block)
    {
        for (int i = 0; i < Rate / 8; i++)
        {
            state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(block[(8 * i)..]);
        }
    }

    private static void Absorb(Span<ulong> state, Span<byte> block, ref int pos, ReadOnlySpan<byte> data)
    {
        while (data.Length > 0)
        {
            int n = Math.Min(Rate - pos, data.Length);
            data[..n].CopyTo(block[pos..]);
            pos += n;
            data = data[n..];
            if (pos == Rate)
            {
                XorBlock(state, block);
                Permute(state);
                pos = 0;
            }
        }
    }

    /// <summary>Keccak-f[1600] (FIPS 202 section 3), the 24 rounds written out on 25 local lanes. Generated from the round
    /// definition: theta, then rho and pi folded into one rotate-and-place step, chi, iota.</summary>
    private static void Permute(Span<ulong> state)
    {
        ReadOnlySpan<ulong> rc = RoundConstants;
        ulong a00 = state[0];
        ulong a10 = state[1];
        ulong a20 = state[2];
        ulong a30 = state[3];
        ulong a40 = state[4];
        ulong a01 = state[5];
        ulong a11 = state[6];
        ulong a21 = state[7];
        ulong a31 = state[8];
        ulong a41 = state[9];
        ulong a02 = state[10];
        ulong a12 = state[11];
        ulong a22 = state[12];
        ulong a32 = state[13];
        ulong a42 = state[14];
        ulong a03 = state[15];
        ulong a13 = state[16];
        ulong a23 = state[17];
        ulong a33 = state[18];
        ulong a43 = state[19];
        ulong a04 = state[20];
        ulong a14 = state[21];
        ulong a24 = state[22];
        ulong a34 = state[23];
        ulong a44 = state[24];
        for (int round = 0; round < 24; round++)
        {
            ulong c0 = a00 ^ a01 ^ a02 ^ a03 ^ a04;
            ulong c1 = a10 ^ a11 ^ a12 ^ a13 ^ a14;
            ulong c2 = a20 ^ a21 ^ a22 ^ a23 ^ a24;
            ulong c3 = a30 ^ a31 ^ a32 ^ a33 ^ a34;
            ulong c4 = a40 ^ a41 ^ a42 ^ a43 ^ a44;
            ulong d0 = c4 ^ ulong.RotateLeft(c1, 1);
            ulong d1 = c0 ^ ulong.RotateLeft(c2, 1);
            ulong d2 = c1 ^ ulong.RotateLeft(c3, 1);
            ulong d3 = c2 ^ ulong.RotateLeft(c4, 1);
            ulong d4 = c3 ^ ulong.RotateLeft(c0, 1);
            ulong b00 = a00 ^ d0;
            ulong b13 = ulong.RotateLeft(a01 ^ d0, 36);
            ulong b21 = ulong.RotateLeft(a02 ^ d0, 3);
            ulong b34 = ulong.RotateLeft(a03 ^ d0, 41);
            ulong b42 = ulong.RotateLeft(a04 ^ d0, 18);
            ulong b02 = ulong.RotateLeft(a10 ^ d1, 1);
            ulong b10 = ulong.RotateLeft(a11 ^ d1, 44);
            ulong b23 = ulong.RotateLeft(a12 ^ d1, 10);
            ulong b31 = ulong.RotateLeft(a13 ^ d1, 45);
            ulong b44 = ulong.RotateLeft(a14 ^ d1, 2);
            ulong b04 = ulong.RotateLeft(a20 ^ d2, 62);
            ulong b12 = ulong.RotateLeft(a21 ^ d2, 6);
            ulong b20 = ulong.RotateLeft(a22 ^ d2, 43);
            ulong b33 = ulong.RotateLeft(a23 ^ d2, 15);
            ulong b41 = ulong.RotateLeft(a24 ^ d2, 61);
            ulong b01 = ulong.RotateLeft(a30 ^ d3, 28);
            ulong b14 = ulong.RotateLeft(a31 ^ d3, 55);
            ulong b22 = ulong.RotateLeft(a32 ^ d3, 25);
            ulong b30 = ulong.RotateLeft(a33 ^ d3, 21);
            ulong b43 = ulong.RotateLeft(a34 ^ d3, 56);
            ulong b03 = ulong.RotateLeft(a40 ^ d4, 27);
            ulong b11 = ulong.RotateLeft(a41 ^ d4, 20);
            ulong b24 = ulong.RotateLeft(a42 ^ d4, 39);
            ulong b32 = ulong.RotateLeft(a43 ^ d4, 8);
            ulong b40 = ulong.RotateLeft(a44 ^ d4, 14);
            a00 = b00 ^ (~b10 & b20);
            a10 = b10 ^ (~b20 & b30);
            a20 = b20 ^ (~b30 & b40);
            a30 = b30 ^ (~b40 & b00);
            a40 = b40 ^ (~b00 & b10);
            a01 = b01 ^ (~b11 & b21);
            a11 = b11 ^ (~b21 & b31);
            a21 = b21 ^ (~b31 & b41);
            a31 = b31 ^ (~b41 & b01);
            a41 = b41 ^ (~b01 & b11);
            a02 = b02 ^ (~b12 & b22);
            a12 = b12 ^ (~b22 & b32);
            a22 = b22 ^ (~b32 & b42);
            a32 = b32 ^ (~b42 & b02);
            a42 = b42 ^ (~b02 & b12);
            a03 = b03 ^ (~b13 & b23);
            a13 = b13 ^ (~b23 & b33);
            a23 = b23 ^ (~b33 & b43);
            a33 = b33 ^ (~b43 & b03);
            a43 = b43 ^ (~b03 & b13);
            a04 = b04 ^ (~b14 & b24);
            a14 = b14 ^ (~b24 & b34);
            a24 = b24 ^ (~b34 & b44);
            a34 = b34 ^ (~b44 & b04);
            a44 = b44 ^ (~b04 & b14);
            a00 ^= rc[round];
        }
        state[0] = a00;
        state[1] = a10;
        state[2] = a20;
        state[3] = a30;
        state[4] = a40;
        state[5] = a01;
        state[6] = a11;
        state[7] = a21;
        state[8] = a31;
        state[9] = a41;
        state[10] = a02;
        state[11] = a12;
        state[12] = a22;
        state[13] = a32;
        state[14] = a42;
        state[15] = a03;
        state[16] = a13;
        state[17] = a23;
        state[18] = a33;
        state[19] = a43;
        state[20] = a04;
        state[21] = a14;
        state[22] = a24;
        state[23] = a34;
        state[24] = a44;
    }
}
