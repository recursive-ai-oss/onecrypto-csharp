using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace RecursiveAI.OneCrypto.Primitives.Fallback;

/// <summary>
/// SHA-3 and SHAKE (FIPS 202) over the Keccak-f[1600] permutation. This is the library's only Keccak; it runs where the platform has
/// no SHA-3 or SHAKE (macOS, older OpenSSL, the browser) and for SHA3-224, which the platform never offers. The permutation is built
/// from xor, and, not and fixed rotations on 64-bit lanes: no table lookup, branch or loop bound depends on the data, so it is
/// constant time by construction. Everything absorbed may be secret (a key or seed), so the state and block are cleared on exit.
/// </summary>
internal static class Keccak
{
    /// <summary>Rate in bytes of SHA3-224 (FIPS 202 table 3: 1600 - 2 * 224 bits).</summary>
    internal const int RateSha3_224 = 144;
    internal const int RateSha3_256 = 136;
    internal const int RateSha3_384 = 104;
    internal const int RateSha3_512 = 72;
    internal const int RateShake128 = 168;
    internal const int RateShake256 = 136;

    /// <summary>Domain-separation bits and first padding bit of SHA-3: 01 then 1 (FIPS 202 section 6.1).</summary>
    internal const byte SuffixSha3 = 0x06;

    /// <summary>Domain-separation bits and first padding bit of SHAKE: 1111 then 1 (FIPS 202 section 6.2).</summary>
    internal const byte SuffixShake = 0x1F;

    private const int MaxRate = 168;

    private static ReadOnlySpan<ulong> RoundConstants =>
    [
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
    ];


    /// <summary>
    /// Hashes the concatenation of up to four pieces and fills <paramref name="output"/> (any length for SHAKE; the digest size for
    /// SHA-3).
    /// </summary>
    /// <param name="rate">The sponge rate in bytes, one of the <c>Rate*</c> constants.</param>
    /// <param name="suffix"><see cref="SuffixSha3"/> or <see cref="SuffixShake"/>.</param>
    /// <param name="output">Receives the digest.</param>
    /// <param name="a">The first piece of input.</param>
    /// <param name="b">The second piece, if any.</param>
    /// <param name="c">The third piece, if any.</param>
    /// <param name="d">The fourth piece, if any.</param>
    public static void Hash(int rate, byte suffix, Span<byte> output, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b = default, ReadOnlySpan<byte> c = default, ReadOnlySpan<byte> d = default)
    {
        Span<ulong> state = stackalloc ulong[25]; // fixed small buffers
        Span<byte> block = stackalloc byte[MaxRate];
        state.Clear();
        block = block[..rate];
        int pos = 0;
        Absorb(state, block, ref pos, a);
        Absorb(state, block, ref pos, b);
        Absorb(state, block, ref pos, c);
        Absorb(state, block, ref pos, d);
        // FIPS 202 section B.2: pad10*1 after the domain bits.
        block[pos..].Clear();
        block[pos] ^= suffix;
        block[rate - 1] ^= 0x80;
        XorBlock(state, block);
        int done = 0;
        while (true)
        {
            Permute(state);
            int n = Math.Min(rate, output.Length - done);
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
        for (int i = 0; i < block.Length / 8; i++)
        {
            state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(block[(8 * i)..]);
        }
    }

    private static void Absorb(Span<ulong> state, Span<byte> block, ref int pos, ReadOnlySpan<byte> data)
    {
        int rate = block.Length;
        while (data.Length > 0)
        {
            if (pos == 0 && data.Length >= rate)
            {
                // Whole blocks straight from the input, no copy.
                XorBlock(state, data[..rate]);
                Permute(state);
                data = data[rate..];
                continue;
            }

            int n = Math.Min(rate - pos, data.Length);
            data[..n].CopyTo(block[pos..]);
            pos += n;
            data = data[n..];
            if (pos == rate)
            {
                XorBlock(state, block);
                Permute(state);
                pos = 0;
            }
        }
    }

    /// <summary>Keccak-f[1600] (FIPS 202 section 3), the 24 rounds written out on 25 local lanes. Generated from the round
    /// definition: theta, then rho and pi folded into one rotate-and-place step, chi, iota.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)] // kept separate so its compiled form can be inspected
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
