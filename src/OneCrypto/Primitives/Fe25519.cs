using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// An element of GF(2^255 - 19) in five 51-bit limbs (radix 2^51). Every operation is straight-line code over fixed-width
/// limbs: no branch, index or loop bound depends on the value, so it is safe for secret data. Operation results are "reduced":
/// every limb is below 2^51 plus a few thousand, which is what <see cref="Mul"/> and <see cref="Square"/> need to keep their
/// 128-bit column sums and the 19-fold carry inside 64 bits.
/// </summary>
internal struct Fe25519
{
    private const ulong Mask = (1UL << 51) - 1;

    public ulong V0, V1, V2, V3, V4;

    public static Fe25519 Zero => default;

    public static Fe25519 One => new() { V0 = 1 };

    /// <summary>Loads 32 little-endian bytes. The top bit (bit 255) is ignored; values in [p, 2^255) are accepted and read modulo p.</summary>
    public static Fe25519 FromBytes(ReadOnlySpan<byte> s)
    {
        ulong w0 = BinaryPrimitives.ReadUInt64LittleEndian(s);
        ulong w1 = BinaryPrimitives.ReadUInt64LittleEndian(s[8..]);
        ulong w2 = BinaryPrimitives.ReadUInt64LittleEndian(s[16..]);
        ulong w3 = BinaryPrimitives.ReadUInt64LittleEndian(s[24..]);
        Fe25519 r;
        r.V0 = w0 & Mask;
        r.V1 = ((w0 >> 51) | (w1 << 13)) & Mask;
        r.V2 = ((w1 >> 38) | (w2 << 26)) & Mask;
        r.V3 = ((w2 >> 25) | (w3 << 39)) & Mask;
        r.V4 = (w3 >> 12) & Mask;
        return r;
    }

    /// <summary>Writes the unique representative in [0, p) as 32 little-endian bytes.</summary>
    public readonly void ToBytes(Span<byte> s)
    {
        Fe25519 t = Carry(this);
        t = Carry(t);
        // Freeze: q = 1 exactly when t >= p, found by propagating the carry of t + 19 through all limbs.
        ulong q = (t.V0 + 19) >> 51;
        q = (t.V1 + q) >> 51;
        q = (t.V2 + q) >> 51;
        q = (t.V3 + q) >> 51;
        q = (t.V4 + q) >> 51;
        t.V0 += 19 * q;
        ulong c = t.V0 >> 51; t.V0 &= Mask;
        t.V1 += c; c = t.V1 >> 51; t.V1 &= Mask;
        t.V2 += c; c = t.V2 >> 51; t.V2 &= Mask;
        t.V3 += c; c = t.V3 >> 51; t.V3 &= Mask;
        t.V4 += c; t.V4 &= Mask; // dropping bit 255 subtracts the 2^255 that the +19q added
        BinaryPrimitives.WriteUInt64LittleEndian(s, t.V0 | (t.V1 << 51));
        BinaryPrimitives.WriteUInt64LittleEndian(s[8..], (t.V1 >> 13) | (t.V2 << 38));
        BinaryPrimitives.WriteUInt64LittleEndian(s[16..], (t.V2 >> 26) | (t.V3 << 25));
        BinaryPrimitives.WriteUInt64LittleEndian(s[24..], (t.V3 >> 39) | (t.V4 << 12));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Fe25519 Carry(in Fe25519 a)
    {
        Fe25519 r;
        ulong c = a.V0 >> 51;
        r.V0 = a.V0 & Mask;
        ulong t = a.V1 + c; c = t >> 51; r.V1 = t & Mask;
        t = a.V2 + c; c = t >> 51; r.V2 = t & Mask;
        t = a.V3 + c; c = t >> 51; r.V3 = t & Mask;
        t = a.V4 + c; c = t >> 51; r.V4 = t & Mask;
        r.V0 += 19 * c; // 2^255 = 19 (mod p)
        return r;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fe25519 Add(in Fe25519 a, in Fe25519 b)
    {
        Fe25519 r;
        r.V0 = a.V0 + b.V0;
        r.V1 = a.V1 + b.V1;
        r.V2 = a.V2 + b.V2;
        r.V3 = a.V3 + b.V3;
        r.V4 = a.V4 + b.V4;
        return Carry(r);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fe25519 Sub(in Fe25519 a, in Fe25519 b)
    {
        // Add 4p first so no limb goes negative: 4p has limbs 2^53 - 76 and 2^53 - 4, above any reduced limb.
        Fe25519 r;
        r.V0 = a.V0 + ((1UL << 53) - 76) - b.V0;
        r.V1 = a.V1 + ((1UL << 53) - 4) - b.V1;
        r.V2 = a.V2 + ((1UL << 53) - 4) - b.V2;
        r.V3 = a.V3 + ((1UL << 53) - 4) - b.V3;
        r.V4 = a.V4 + ((1UL << 53) - 4) - b.V4;
        return Carry(r);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fe25519 Neg(in Fe25519 a) => Sub(Zero, a);

    /// <summary>
    /// Adds the product a·b to a column kept as lo + hi·2^52, where <paramref name="bShifted"/> is b·2^12. The multiplier's
    /// 128-bit result is then (a·b)·2^12, so its high word is exactly a·b >> 52 and its low word, shifted back down, is
    /// a·b mod 2^52: both go straight into plain sums, with no masking, splitting or carry. Requires b below 2^52.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void MulAcc(ref ulong lo, ref ulong hi, ulong a, ulong bShifted)
    {
        lo += (a * bShifted) >> 12;
        hi += WideMul.High(a, bShifted);
    }

    /// <summary>
    /// Carries the five columns (each lo + hi·2^52 = lo + 2·hi·2^51) into limbs. The non-wrapping and wrapping (times 19,
    /// because 2^255 = 19) partial sums of a column are kept apart and combined here, which keeps every term of the multiplier
    /// inputs below 2^52 so the shifted operands fit in 64 bits. With reduced inputs a column's hi stays below 2^57.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Fe25519 Finish(ulong ln0, ulong hn0, ulong lw0, ulong hw0, ulong ln1, ulong hn1, ulong lw1, ulong hw1, ulong ln2, ulong hn2, ulong lw2, ulong hw2, ulong ln3, ulong hn3, ulong lw3, ulong hw3, ulong ln4, ulong hn4, ulong lw4, ulong hw4)
    {
        Fe25519 r;
        ulong t = ln0 + (19 * lw0);
        ulong c = (t >> 51) + ((hn0 + (19 * hw0)) << 1);
        r.V0 = t & Mask;
        t = ln1 + (19 * lw1) + c; c = (t >> 51) + ((hn1 + (19 * hw1)) << 1); r.V1 = t & Mask;
        t = ln2 + (19 * lw2) + c; c = (t >> 51) + ((hn2 + (19 * hw2)) << 1); r.V2 = t & Mask;
        t = ln3 + (19 * lw3) + c; c = (t >> 51) + ((hn3 + (19 * hw3)) << 1); r.V3 = t & Mask;
        t = ln4 + (19 * lw4) + c; c = (t >> 51) + ((hn4 + (19 * hw4)) << 1); r.V4 = t & Mask;
        r.V0 += c * 19; // 2^255 = 19 (mod p)
        c = r.V0 >> 51;
        r.V0 &= Mask;
        r.V1 += c;
        return r;
    }

    /// <summary>Field multiplication. Inputs must be reduced (limbs below 2^51 + a few thousand).</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Fe25519 Mul(in Fe25519 a, in Fe25519 b)
    {
        ulong a0 = a.V0, a1 = a.V1, a2 = a.V2, a3 = a.V3, a4 = a.V4;
        ulong c0 = b.V0 << 12, c1 = b.V1 << 12, c2 = b.V2 << 12, c3 = b.V3 << 12, c4 = b.V4 << 12;
        ulong ln0 = 0, hn0 = 0, lw0 = 0, hw0 = 0, ln1 = 0, hn1 = 0, lw1 = 0, hw1 = 0, ln2 = 0, hn2 = 0, lw2 = 0, hw2 = 0, ln3 = 0, hn3 = 0, lw3 = 0, hw3 = 0, ln4 = 0, hn4 = 0, lw4 = 0, hw4 = 0;
        MulAcc(ref ln0, ref hn0, a0, c0);
        MulAcc(ref lw0, ref hw0, a1, c4);
        MulAcc(ref lw0, ref hw0, a2, c3);
        MulAcc(ref lw0, ref hw0, a3, c2);
        MulAcc(ref lw0, ref hw0, a4, c1);
        MulAcc(ref ln1, ref hn1, a0, c1);
        MulAcc(ref ln1, ref hn1, a1, c0);
        MulAcc(ref lw1, ref hw1, a2, c4);
        MulAcc(ref lw1, ref hw1, a3, c3);
        MulAcc(ref lw1, ref hw1, a4, c2);
        MulAcc(ref ln2, ref hn2, a0, c2);
        MulAcc(ref ln2, ref hn2, a1, c1);
        MulAcc(ref ln2, ref hn2, a2, c0);
        MulAcc(ref lw2, ref hw2, a3, c4);
        MulAcc(ref lw2, ref hw2, a4, c3);
        MulAcc(ref ln3, ref hn3, a0, c3);
        MulAcc(ref ln3, ref hn3, a1, c2);
        MulAcc(ref ln3, ref hn3, a2, c1);
        MulAcc(ref ln3, ref hn3, a3, c0);
        MulAcc(ref lw3, ref hw3, a4, c4);
        MulAcc(ref ln4, ref hn4, a0, c4);
        MulAcc(ref ln4, ref hn4, a1, c3);
        MulAcc(ref ln4, ref hn4, a2, c2);
        MulAcc(ref ln4, ref hn4, a3, c1);
        MulAcc(ref ln4, ref hn4, a4, c0);
        return Finish(ln0, hn0, lw0, hw0, ln1, hn1, lw1, hw1, ln2, hn2, lw2, hw2, ln3, hn3, lw3, hw3, ln4, hn4, lw4, hw4);
    }

    /// <summary>Field squaring; cheaper than <see cref="Mul"/> because each cross product is computed once.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Fe25519 Square(in Fe25519 a)
    {
        ulong a0 = a.V0, a1 = a.V1, a2 = a.V2, a3 = a.V3, a4 = a.V4;
        ulong c0 = a0 << 12, c1 = a1 << 12, c2 = a2 << 12, c3 = a3 << 12, c4 = a4 << 12;
        ulong ln0 = 0, hn0 = 0, lw0 = 0, hw0 = 0, ln1 = 0, hn1 = 0, lw1 = 0, hw1 = 0, ln2 = 0, hn2 = 0, lw2 = 0, hw2 = 0, ln3 = 0, hn3 = 0, lw3 = 0, hw3 = 0, ln4 = 0, hn4 = 0, lw4 = 0, hw4 = 0;
        MulAcc(ref lw0, ref hw0, a1, c4);
        MulAcc(ref lw0, ref hw0, a2, c3);
        ln0 <<= 1;
        hn0 <<= 1;
        lw0 <<= 1;
        hw0 <<= 1;
        MulAcc(ref ln0, ref hn0, a0, c0);
        MulAcc(ref ln1, ref hn1, a0, c1);
        MulAcc(ref lw1, ref hw1, a2, c4);
        ln1 <<= 1;
        hn1 <<= 1;
        lw1 <<= 1;
        hw1 <<= 1;
        MulAcc(ref lw1, ref hw1, a3, c3);
        MulAcc(ref ln2, ref hn2, a0, c2);
        MulAcc(ref lw2, ref hw2, a3, c4);
        ln2 <<= 1;
        hn2 <<= 1;
        lw2 <<= 1;
        hw2 <<= 1;
        MulAcc(ref ln2, ref hn2, a1, c1);
        MulAcc(ref ln3, ref hn3, a0, c3);
        MulAcc(ref ln3, ref hn3, a1, c2);
        ln3 <<= 1;
        hn3 <<= 1;
        lw3 <<= 1;
        hw3 <<= 1;
        MulAcc(ref lw3, ref hw3, a4, c4);
        MulAcc(ref ln4, ref hn4, a0, c4);
        MulAcc(ref ln4, ref hn4, a1, c3);
        ln4 <<= 1;
        hn4 <<= 1;
        lw4 <<= 1;
        hw4 <<= 1;
        MulAcc(ref ln4, ref hn4, a2, c2);
        return Finish(ln0, hn0, lw0, hw0, ln1, hn1, lw1, hw1, ln2, hn2, lw2, hw2, ln3, hn3, lw3, hw3, ln4, hn4, lw4, hw4);
    }

    /// <summary>Squares <paramref name="a"/> <paramref name="n"/> times (n is a public constant).</summary>
    public static Fe25519 SquareN(in Fe25519 a, int n)
    {
        Fe25519 r = Square(a);
        for (int i = 1; i < n; i++)
        {
            r = Square(r);
        }
        return r;
    }

    /// <summary>a^(2^250 - 1) and a^11, shared by <see cref="Invert"/> and <see cref="Pow22523"/>.</summary>
    private static Fe25519 Pow2_250m1(in Fe25519 z, out Fe25519 z11)
    {
        Fe25519 z2 = Square(z);
        Fe25519 z9 = Mul(SquareN(z2, 2), z);
        z11 = Mul(z9, z2);
        Fe25519 e5 = Mul(Square(z11), z9);               // 2^5 - 1
        Fe25519 e10 = Mul(SquareN(e5, 5), e5);           // 2^10 - 1
        Fe25519 e20 = Mul(SquareN(e10, 10), e10);
        Fe25519 e40 = Mul(SquareN(e20, 20), e20);
        Fe25519 e50 = Mul(SquareN(e40, 10), e10);
        Fe25519 e100 = Mul(SquareN(e50, 50), e50);
        Fe25519 e200 = Mul(SquareN(e100, 100), e100);
        return Mul(SquareN(e200, 50), e50);              // 2^250 - 1
    }

    /// <summary>a^(p - 2) = a^-1 by Fermat's little theorem (0 maps to 0). p - 2 = (2^250 - 1)·2^5 + 11.</summary>
    public static Fe25519 Invert(in Fe25519 a)
    {
        Fe25519 e250 = Pow2_250m1(a, out Fe25519 z11);
        return Mul(SquareN(e250, 5), z11);
    }

    /// <summary>a^((p - 5) / 8) = a^(2^252 - 3), the exponent of RFC 8032 section 5.1.3. (2^252 - 3) = (2^250 - 1)·4 + 1.</summary>
    public static Fe25519 Pow22523(in Fe25519 a)
    {
        Fe25519 e250 = Pow2_250m1(a, out _);
        return Mul(SquareN(e250, 2), a);
    }

    /// <summary>The low bit of the canonical representative (the "sign" of RFC 8032 and RFC 7748).</summary>
    public readonly int Parity()
    {
        Span<byte> b = stackalloc byte[32]; // fixed small buffer
        ToBytes(b);
        return b[0] & 1;
    }

    /// <summary>True if the value is 0 mod p. Variable-time on the answer only; use for public data or fail-closed checks.</summary>
    public readonly bool IsZero()
    {
        Span<byte> b = stackalloc byte[32]; // fixed small buffer
        ToBytes(b);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(b, stackalloc byte[32]);
    }

    /// <summary>True if both values are equal mod p.</summary>
    public static bool Equal(in Fe25519 a, in Fe25519 b)
    {
        Span<byte> x = stackalloc byte[32]; // fixed small buffers
        Span<byte> y = stackalloc byte[32];
        a.ToBytes(x);
        b.ToBytes(y);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(x, y);
    }

    /// <summary>Swaps a and b when <paramref name="mask"/> is all ones; leaves them when it is zero.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CSwap(ref Fe25519 a, ref Fe25519 b, ulong mask)
    {
        ulong t = mask & (a.V0 ^ b.V0); a.V0 ^= t; b.V0 ^= t;
        t = mask & (a.V1 ^ b.V1); a.V1 ^= t; b.V1 ^= t;
        t = mask & (a.V2 ^ b.V2); a.V2 ^= t; b.V2 ^= t;
        t = mask & (a.V3 ^ b.V3); a.V3 ^= t; b.V3 ^= t;
        t = mask & (a.V4 ^ b.V4); a.V4 ^= t; b.V4 ^= t;
    }

    /// <summary>Sets <paramref name="a"/> to <paramref name="b"/> when <paramref name="mask"/> is all ones.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CMove(ref Fe25519 a, in Fe25519 b, ulong mask)
    {
        a.V0 ^= mask & (a.V0 ^ b.V0);
        a.V1 ^= mask & (a.V1 ^ b.V1);
        a.V2 ^= mask & (a.V2 ^ b.V2);
        a.V3 ^= mask & (a.V3 ^ b.V3);
        a.V4 ^= mask & (a.V4 ^ b.V4);
    }
}
