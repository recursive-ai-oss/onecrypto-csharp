using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// An element of GF(p), p = 2^448 - 2^224 - 1, in eight 56-bit limbs. Straight-line code over fixed-width limbs: nothing
/// branches or indexes on the value, so it is safe for secret data. The reduction uses 2^448 = 2^224 + 1 (mod p), which moves
/// limb i + 8 onto limbs i and i + 4. Results are "reduced": limbs are below 2^56 plus a few units.
/// </summary>
internal struct Fe448
{
    private const ulong Mask = (1UL << 56) - 1;

    public ulong V0, V1, V2, V3, V4, V5, V6, V7;

    public static Fe448 Zero => default;

    public static Fe448 One => new() { V0 = 1 };

    /// <summary>Loads 56 little-endian bytes (any value below 2^448; values at or above p are read modulo p).</summary>
    public static Fe448 FromBytes(ReadOnlySpan<byte> s)
    {
        Fe448 r;
        r.V0 = Load7(s, 0);
        r.V1 = Load7(s, 7);
        r.V2 = Load7(s, 14);
        r.V3 = Load7(s, 21);
        r.V4 = Load7(s, 28);
        r.V5 = Load7(s, 35);
        r.V6 = Load7(s, 42);
        r.V7 = Load7(s, 49);
        return r;
    }

    private static ulong Load7(ReadOnlySpan<byte> s, int o)
    {
        ReadOnlySpan<byte> b = s.Slice(o, 7);
        return b[0] | ((ulong)b[1] << 8) | ((ulong)b[2] << 16) | ((ulong)b[3] << 24) | ((ulong)b[4] << 32) | ((ulong)b[5] << 40) | ((ulong)b[6] << 48);
    }

    private static void Store7(Span<byte> s, int o, ulong v)
    {
        for (int i = 0; i < 7; i++)
        {
            s[o + i] = (byte)(v >> (8 * i));
        }
    }

    /// <summary>Writes the unique representative in [0, p) as 56 little-endian bytes.</summary>
    public readonly void ToBytes(Span<byte> s)
    {
        Fe448 t = Carry(this);
        t = Carry(t);
        t = Carry(t);
        // Freeze: t + 2^224 + 1 reaches 2^448 exactly when t >= p; in that case the low 448 bits of the sum are t - p.
        Fe448 u = t;
        u.V0 += 1;
        u.V4 += 1;
        ulong c = u.V0 >> 56; u.V0 &= Mask;
        u.V1 += c; c = u.V1 >> 56; u.V1 &= Mask;
        u.V2 += c; c = u.V2 >> 56; u.V2 &= Mask;
        u.V3 += c; c = u.V3 >> 56; u.V3 &= Mask;
        u.V4 += c; c = u.V4 >> 56; u.V4 &= Mask;
        u.V5 += c; c = u.V5 >> 56; u.V5 &= Mask;
        u.V6 += c; c = u.V6 >> 56; u.V6 &= Mask;
        u.V7 += c; c = u.V7 >> 56; u.V7 &= Mask;
        ulong m = 0 - c; // all ones when t >= p
        CMove(ref t, u, m);
        Store7(s, 0, t.V0);
        Store7(s, 7, t.V1);
        Store7(s, 14, t.V2);
        Store7(s, 21, t.V3);
        Store7(s, 28, t.V4);
        Store7(s, 35, t.V5);
        Store7(s, 42, t.V6);
        Store7(s, 49, t.V7);
    }

    /// <summary>One carry pass; the carry out of limb 7 folds onto limbs 0 and 4 (2^448 = 2^224 + 1).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Fe448 Carry(in Fe448 a)
    {
        Fe448 r;
        ulong t = a.V0; ulong c = t >> 56; r.V0 = t & Mask;
        t = a.V1 + c; c = t >> 56; r.V1 = t & Mask;
        t = a.V2 + c; c = t >> 56; r.V2 = t & Mask;
        t = a.V3 + c; c = t >> 56; r.V3 = t & Mask;
        t = a.V4 + c; c = t >> 56; r.V4 = t & Mask;
        t = a.V5 + c; c = t >> 56; r.V5 = t & Mask;
        t = a.V6 + c; c = t >> 56; r.V6 = t & Mask;
        t = a.V7 + c; c = t >> 56; r.V7 = t & Mask;
        r.V0 += c;
        r.V4 += c;
        return r;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fe448 Add(in Fe448 a, in Fe448 b)
    {
        Fe448 r;
        r.V0 = a.V0 + b.V0;
        r.V1 = a.V1 + b.V1;
        r.V2 = a.V2 + b.V2;
        r.V3 = a.V3 + b.V3;
        r.V4 = a.V4 + b.V4;
        r.V5 = a.V5 + b.V5;
        r.V6 = a.V6 + b.V6;
        r.V7 = a.V7 + b.V7;
        return Carry(r);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fe448 Sub(in Fe448 a, in Fe448 b)
    {
        // Add 4p so no limb goes negative. p has limbs 2^56 - 1 except limb 4 (2^56 - 2), so 4p has 2^58 - 4 and 2^58 - 8.
        const ulong B = (1UL << 58) - 4;
        const ulong B4 = (1UL << 58) - 8;
        Fe448 r;
        r.V0 = a.V0 + B - b.V0;
        r.V1 = a.V1 + B - b.V1;
        r.V2 = a.V2 + B - b.V2;
        r.V3 = a.V3 + B - b.V3;
        r.V4 = a.V4 + B4 - b.V4;
        r.V5 = a.V5 + B - b.V5;
        r.V6 = a.V6 + B - b.V6;
        r.V7 = a.V7 + B - b.V7;
        return Carry(r);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fe448 Neg(in Fe448 a) => Sub(Zero, a);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static UInt128 M(ulong a, ulong b)
        => Math.BigMul(a, b);

    /// <summary>Folds the 15 columns of a product back to eight limbs and carries.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Fe448 Reduce(
        UInt128 c0, UInt128 c1, UInt128 c2, UInt128 c3, UInt128 c4, UInt128 c5, UInt128 c6, UInt128 c7,
        UInt128 c8, UInt128 c9, UInt128 c10, UInt128 c11, UInt128 c12, UInt128 c13, UInt128 c14)
    {
        // 2^(56 i) for i >= 8 equals 2^(56 (i-8)) (2^224 + 1): column i lands on columns i - 8 and i - 4. Going from the
        // top down, a column is complete before it is folded (only higher columns add to it).
        c10 += c14; c6 += c14;
        c9 += c13; c5 += c13;
        c8 += c12; c4 += c12;
        c7 += c11; c3 += c11;
        c6 += c10; c2 += c10;
        c5 += c9; c1 += c9;
        c4 += c8; c0 += c8;
        Fe448 r;
        UInt128 t = c0; ulong c = (ulong)(t >> 56); r.V0 = (ulong)t & Mask;
        t = c1 + c; c = (ulong)(t >> 56); r.V1 = (ulong)t & Mask;
        t = c2 + c; c = (ulong)(t >> 56); r.V2 = (ulong)t & Mask;
        t = c3 + c; c = (ulong)(t >> 56); r.V3 = (ulong)t & Mask;
        t = c4 + c; c = (ulong)(t >> 56); r.V4 = (ulong)t & Mask;
        t = c5 + c; c = (ulong)(t >> 56); r.V5 = (ulong)t & Mask;
        t = c6 + c; c = (ulong)(t >> 56); r.V6 = (ulong)t & Mask;
        t = c7 + c; c = (ulong)(t >> 56); r.V7 = (ulong)t & Mask;
        r.V0 += c;
        r.V4 += c;
        return Carry(r);
    }

    /// <summary>Field multiplication. Inputs must be reduced (limbs below 2^56 + a few units; sums of two reduced values are fine).</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Fe448 Mul(in Fe448 a, in Fe448 b)
    {
        ulong a0 = a.V0, a1 = a.V1, a2 = a.V2, a3 = a.V3, a4 = a.V4, a5 = a.V5, a6 = a.V6, a7 = a.V7;
        ulong b0 = b.V0, b1 = b.V1, b2 = b.V2, b3 = b.V3, b4 = b.V4, b5 = b.V5, b6 = b.V6, b7 = b.V7;
        UInt128 c0 = M(a0, b0);
        UInt128 c1 = M(a0, b1) + M(a1, b0);
        UInt128 c2 = M(a0, b2) + M(a1, b1) + M(a2, b0);
        UInt128 c3 = M(a0, b3) + M(a1, b2) + M(a2, b1) + M(a3, b0);
        UInt128 c4 = M(a0, b4) + M(a1, b3) + M(a2, b2) + M(a3, b1) + M(a4, b0);
        UInt128 c5 = M(a0, b5) + M(a1, b4) + M(a2, b3) + M(a3, b2) + M(a4, b1) + M(a5, b0);
        UInt128 c6 = M(a0, b6) + M(a1, b5) + M(a2, b4) + M(a3, b3) + M(a4, b2) + M(a5, b1) + M(a6, b0);
        UInt128 c7 = M(a0, b7) + M(a1, b6) + M(a2, b5) + M(a3, b4) + M(a4, b3) + M(a5, b2) + M(a6, b1) + M(a7, b0);
        UInt128 c8 = M(a1, b7) + M(a2, b6) + M(a3, b5) + M(a4, b4) + M(a5, b3) + M(a6, b2) + M(a7, b1);
        UInt128 c9 = M(a2, b7) + M(a3, b6) + M(a4, b5) + M(a5, b4) + M(a6, b3) + M(a7, b2);
        UInt128 c10 = M(a3, b7) + M(a4, b6) + M(a5, b5) + M(a6, b4) + M(a7, b3);
        UInt128 c11 = M(a4, b7) + M(a5, b6) + M(a6, b5) + M(a7, b4);
        UInt128 c12 = M(a5, b7) + M(a6, b6) + M(a7, b5);
        UInt128 c13 = M(a6, b7) + M(a7, b6);
        UInt128 c14 = M(a7, b7);
        return Reduce(c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14);
    }

    /// <summary>Field squaring (each cross product computed once and doubled).</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Fe448 Square(in Fe448 a)
    {
        ulong a0 = a.V0, a1 = a.V1, a2 = a.V2, a3 = a.V3, a4 = a.V4, a5 = a.V5, a6 = a.V6, a7 = a.V7;
        ulong d0 = a0 << 1, d1 = a1 << 1, d2 = a2 << 1, d3 = a3 << 1, d4 = a4 << 1, d5 = a5 << 1, d6 = a6 << 1;
        UInt128 c0 = M(a0, a0);
        UInt128 c1 = M(d0, a1);
        UInt128 c2 = M(d0, a2) + M(a1, a1);
        UInt128 c3 = M(d0, a3) + M(d1, a2);
        UInt128 c4 = M(d0, a4) + M(d1, a3) + M(a2, a2);
        UInt128 c5 = M(d0, a5) + M(d1, a4) + M(d2, a3);
        UInt128 c6 = M(d0, a6) + M(d1, a5) + M(d2, a4) + M(a3, a3);
        UInt128 c7 = M(d0, a7) + M(d1, a6) + M(d2, a5) + M(d3, a4);
        UInt128 c8 = M(d1, a7) + M(d2, a6) + M(d3, a5) + M(a4, a4);
        UInt128 c9 = M(d2, a7) + M(d3, a6) + M(d4, a5);
        UInt128 c10 = M(d3, a7) + M(d4, a6) + M(a5, a5);
        UInt128 c11 = M(d4, a7) + M(d5, a6);
        UInt128 c12 = M(d5, a7) + M(a6, a6);
        UInt128 c13 = M(d6, a7);
        UInt128 c14 = M(a7, a7);
        return Reduce(c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14);
    }

    /// <summary>Squares <paramref name="a"/> <paramref name="n"/> times (n is a public constant).</summary>
    public static Fe448 SquareN(in Fe448 a, int n)
    {
        Fe448 r = Square(a);
        for (int i = 1; i < n; i++)
        {
            r = Square(r);
        }
        return r;
    }

    /// <summary>
    /// Computes a^(2^222 - 1) and a^(2^223 - 1) with a fixed addition chain. The prefix exponents e_k = 2^k - 1 combine as
    /// e_(m+n) = e_m·2^n + e_n.
    /// </summary>
    private static void Pow2_222m1(in Fe448 x, out Fe448 e222, out Fe448 e223)
    {
        Fe448 e2 = Mul(Square(x), x);
        Fe448 e3 = Mul(Square(e2), x);
        Fe448 e6 = Mul(SquareN(e3, 3), e3);
        Fe448 e9 = Mul(SquareN(e6, 3), e3);
        Fe448 e11 = Mul(SquareN(e9, 2), e2);
        Fe448 e22 = Mul(SquareN(e11, 11), e11);
        Fe448 e44 = Mul(SquareN(e22, 22), e22);
        Fe448 e88 = Mul(SquareN(e44, 44), e44);
        Fe448 e176 = Mul(SquareN(e88, 88), e88);
        Fe448 e220 = Mul(SquareN(e176, 44), e44);
        e222 = Mul(SquareN(e220, 2), e2);
        e223 = Mul(Square(e222), x);
    }

    /// <summary>a^-1 = a^(p - 2) (0 maps to 0). p - 2 = (2^223 - 1)·2^225 + (2^222 - 1)·4 + 1.</summary>
    public static Fe448 Invert(in Fe448 a)
    {
        Pow2_222m1(a, out Fe448 e222, out Fe448 e223);
        return Mul(SquareN(e223, 225), Mul(SquareN(e222, 2), a));
    }

    /// <summary>a^((p - 3) / 4) = a^(2^446 - 2^222 - 1), the exponent of RFC 8032 section 5.2.3. It equals (2^223 - 1)·2^223 + (2^222 - 1).</summary>
    public static Fe448 Pow446m3Over4(in Fe448 a)
    {
        Pow2_222m1(a, out Fe448 e222, out Fe448 e223);
        return Mul(SquareN(e223, 223), e222);
    }

    /// <summary>The low bit of the canonical representative.</summary>
    public readonly int Parity()
    {
        Span<byte> b = stackalloc byte[56]; // fixed small buffer
        ToBytes(b);
        return b[0] & 1;
    }

    /// <summary>True if both values are equal mod p.</summary>
    public static bool Equal(in Fe448 a, in Fe448 b)
    {
        Span<byte> x = stackalloc byte[56]; // fixed small buffers
        Span<byte> y = stackalloc byte[56];
        a.ToBytes(x);
        b.ToBytes(y);
        return CryptographicOperations.FixedTimeEquals(x, y);
    }

    /// <summary>Swaps a and b when <paramref name="mask"/> is all ones; leaves them when it is zero.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CSwap(ref Fe448 a, ref Fe448 b, ulong mask)
    {
        ulong t = mask & (a.V0 ^ b.V0); a.V0 ^= t; b.V0 ^= t;
        t = mask & (a.V1 ^ b.V1); a.V1 ^= t; b.V1 ^= t;
        t = mask & (a.V2 ^ b.V2); a.V2 ^= t; b.V2 ^= t;
        t = mask & (a.V3 ^ b.V3); a.V3 ^= t; b.V3 ^= t;
        t = mask & (a.V4 ^ b.V4); a.V4 ^= t; b.V4 ^= t;
        t = mask & (a.V5 ^ b.V5); a.V5 ^= t; b.V5 ^= t;
        t = mask & (a.V6 ^ b.V6); a.V6 ^= t; b.V6 ^= t;
        t = mask & (a.V7 ^ b.V7); a.V7 ^= t; b.V7 ^= t;
    }

    /// <summary>Sets <paramref name="a"/> to <paramref name="b"/> when <paramref name="mask"/> is all ones.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CMove(ref Fe448 a, in Fe448 b, ulong mask)
    {
        a.V0 ^= mask & (a.V0 ^ b.V0);
        a.V1 ^= mask & (a.V1 ^ b.V1);
        a.V2 ^= mask & (a.V2 ^ b.V2);
        a.V3 ^= mask & (a.V3 ^ b.V3);
        a.V4 ^= mask & (a.V4 ^ b.V4);
        a.V5 ^= mask & (a.V5 ^ b.V5);
        a.V6 ^= mask & (a.V6 ^ b.V6);
        a.V7 ^= mask & (a.V7 ^ b.V7);
    }
}
