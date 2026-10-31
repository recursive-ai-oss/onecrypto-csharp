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

    /// <summary>
    /// Adds the product a·b to a column kept as lo + hi·2^57, where <paramref name="bShifted"/> is b·2^7. The multiplier's
    /// 128-bit result is then (a·b)·2^7, so its high word is exactly a·b >> 57 and its low word, shifted back down, is
    /// a·b mod 2^57: both go straight into plain sums, with no masking, splitting or carry. Requires b below 2^57.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void MulAcc(ref ulong lo, ref ulong hi, ulong a, ulong bShifted)
    {
        lo += (a * bShifted) >> 7;
        hi += WideMul.High(a, bShifted);
    }

    /// <summary>Folds the 15 columns (each lo + hi·2^57 = lo + 2·hi·2^56) of a product back to eight limbs and carries.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Fe448 Reduce(ulong l0, ulong h0, ulong l1, ulong h1, ulong l2, ulong h2, ulong l3, ulong h3, ulong l4, ulong h4, ulong l5, ulong h5, ulong l6, ulong h6, ulong l7, ulong h7, ulong l8, ulong h8, ulong l9, ulong h9, ulong l10, ulong h10, ulong l11, ulong h11, ulong l12, ulong h12, ulong l13, ulong h13, ulong l14, ulong h14)
    {
        // 2^(56 i) for i >= 8 equals 2^(56 (i-8)) (2^224 + 1): column i lands on columns i - 8 and i - 4. Going from the
        // top down, a column is complete before it is folded (only higher columns add to it). Each column stays below
        // about 2^61 (lo) and 2^63 (hi), so nothing overflows 64 bits.
        l6 += l14; h6 += h14;
        l10 += l14; h10 += h14;
        l5 += l13; h5 += h13;
        l9 += l13; h9 += h13;
        l4 += l12; h4 += h12;
        l8 += l12; h8 += h12;
        l3 += l11; h3 += h11;
        l7 += l11; h7 += h11;
        l2 += l10; h2 += h10;
        l6 += l10; h6 += h10;
        l1 += l9; h1 += h9;
        l5 += l9; h5 += h9;
        l0 += l8; h0 += h8;
        l4 += l8; h4 += h8;
        Fe448 r;
        ulong t = l0;
        ulong c = (t >> 56) + (h0 << 1);
        r.V0 = t & Mask;
        t = l1 + c;
        c = (t >> 56) + (h1 << 1);
        r.V1 = t & Mask;
        t = l2 + c;
        c = (t >> 56) + (h2 << 1);
        r.V2 = t & Mask;
        t = l3 + c;
        c = (t >> 56) + (h3 << 1);
        r.V3 = t & Mask;
        t = l4 + c;
        c = (t >> 56) + (h4 << 1);
        r.V4 = t & Mask;
        t = l5 + c;
        c = (t >> 56) + (h5 << 1);
        r.V5 = t & Mask;
        t = l6 + c;
        c = (t >> 56) + (h6 << 1);
        r.V6 = t & Mask;
        t = l7 + c;
        c = (t >> 56) + (h7 << 1);
        r.V7 = t & Mask;
        r.V0 += c;
        r.V4 += c;
        return Carry(r);
    }

    /// <summary>Field multiplication. Inputs must be reduced (limbs below 2^57).</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Fe448 Mul(in Fe448 a, in Fe448 b)
    {
        ulong a0 = a.V0, a1 = a.V1, a2 = a.V2, a3 = a.V3, a4 = a.V4, a5 = a.V5, a6 = a.V6, a7 = a.V7;
        ulong c0 = b.V0 << 7, c1 = b.V1 << 7, c2 = b.V2 << 7, c3 = b.V3 << 7, c4 = b.V4 << 7, c5 = b.V5 << 7, c6 = b.V6 << 7, c7 = b.V7 << 7;
        ulong l0 = 0, h0 = 0, l1 = 0, h1 = 0, l2 = 0, h2 = 0, l3 = 0, h3 = 0, l4 = 0, h4 = 0, l5 = 0, h5 = 0, l6 = 0, h6 = 0, l7 = 0, h7 = 0, l8 = 0, h8 = 0, l9 = 0, h9 = 0, l10 = 0, h10 = 0, l11 = 0, h11 = 0, l12 = 0, h12 = 0, l13 = 0, h13 = 0, l14 = 0, h14 = 0;
        MulAcc(ref l0, ref h0, a0, c0);
        MulAcc(ref l1, ref h1, a0, c1);
        MulAcc(ref l1, ref h1, a1, c0);
        MulAcc(ref l2, ref h2, a0, c2);
        MulAcc(ref l2, ref h2, a1, c1);
        MulAcc(ref l2, ref h2, a2, c0);
        MulAcc(ref l3, ref h3, a0, c3);
        MulAcc(ref l3, ref h3, a1, c2);
        MulAcc(ref l3, ref h3, a2, c1);
        MulAcc(ref l3, ref h3, a3, c0);
        MulAcc(ref l4, ref h4, a0, c4);
        MulAcc(ref l4, ref h4, a1, c3);
        MulAcc(ref l4, ref h4, a2, c2);
        MulAcc(ref l4, ref h4, a3, c1);
        MulAcc(ref l4, ref h4, a4, c0);
        MulAcc(ref l5, ref h5, a0, c5);
        MulAcc(ref l5, ref h5, a1, c4);
        MulAcc(ref l5, ref h5, a2, c3);
        MulAcc(ref l5, ref h5, a3, c2);
        MulAcc(ref l5, ref h5, a4, c1);
        MulAcc(ref l5, ref h5, a5, c0);
        MulAcc(ref l6, ref h6, a0, c6);
        MulAcc(ref l6, ref h6, a1, c5);
        MulAcc(ref l6, ref h6, a2, c4);
        MulAcc(ref l6, ref h6, a3, c3);
        MulAcc(ref l6, ref h6, a4, c2);
        MulAcc(ref l6, ref h6, a5, c1);
        MulAcc(ref l6, ref h6, a6, c0);
        MulAcc(ref l7, ref h7, a0, c7);
        MulAcc(ref l7, ref h7, a1, c6);
        MulAcc(ref l7, ref h7, a2, c5);
        MulAcc(ref l7, ref h7, a3, c4);
        MulAcc(ref l7, ref h7, a4, c3);
        MulAcc(ref l7, ref h7, a5, c2);
        MulAcc(ref l7, ref h7, a6, c1);
        MulAcc(ref l7, ref h7, a7, c0);
        MulAcc(ref l8, ref h8, a1, c7);
        MulAcc(ref l8, ref h8, a2, c6);
        MulAcc(ref l8, ref h8, a3, c5);
        MulAcc(ref l8, ref h8, a4, c4);
        MulAcc(ref l8, ref h8, a5, c3);
        MulAcc(ref l8, ref h8, a6, c2);
        MulAcc(ref l8, ref h8, a7, c1);
        MulAcc(ref l9, ref h9, a2, c7);
        MulAcc(ref l9, ref h9, a3, c6);
        MulAcc(ref l9, ref h9, a4, c5);
        MulAcc(ref l9, ref h9, a5, c4);
        MulAcc(ref l9, ref h9, a6, c3);
        MulAcc(ref l9, ref h9, a7, c2);
        MulAcc(ref l10, ref h10, a3, c7);
        MulAcc(ref l10, ref h10, a4, c6);
        MulAcc(ref l10, ref h10, a5, c5);
        MulAcc(ref l10, ref h10, a6, c4);
        MulAcc(ref l10, ref h10, a7, c3);
        MulAcc(ref l11, ref h11, a4, c7);
        MulAcc(ref l11, ref h11, a5, c6);
        MulAcc(ref l11, ref h11, a6, c5);
        MulAcc(ref l11, ref h11, a7, c4);
        MulAcc(ref l12, ref h12, a5, c7);
        MulAcc(ref l12, ref h12, a6, c6);
        MulAcc(ref l12, ref h12, a7, c5);
        MulAcc(ref l13, ref h13, a6, c7);
        MulAcc(ref l13, ref h13, a7, c6);
        MulAcc(ref l14, ref h14, a7, c7);
        return Reduce(l0, h0, l1, h1, l2, h2, l3, h3, l4, h4, l5, h5, l6, h6, l7, h7, l8, h8, l9, h9, l10, h10, l11, h11, l12, h12, l13, h13, l14, h14);
    }

    /// <summary>Field squaring: each cross product is computed once and its column doubled.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Fe448 Square(in Fe448 a)
    {
        ulong a0 = a.V0, a1 = a.V1, a2 = a.V2, a3 = a.V3, a4 = a.V4, a5 = a.V5, a6 = a.V6, a7 = a.V7;
        ulong c0 = a0 << 7, c1 = a1 << 7, c2 = a2 << 7, c3 = a3 << 7, c4 = a4 << 7, c5 = a5 << 7, c6 = a6 << 7, c7 = a7 << 7;
        ulong l0 = 0, h0 = 0, l1 = 0, h1 = 0, l2 = 0, h2 = 0, l3 = 0, h3 = 0, l4 = 0, h4 = 0, l5 = 0, h5 = 0, l6 = 0, h6 = 0, l7 = 0, h7 = 0, l8 = 0, h8 = 0, l9 = 0, h9 = 0, l10 = 0, h10 = 0, l11 = 0, h11 = 0, l12 = 0, h12 = 0, l13 = 0, h13 = 0, l14 = 0, h14 = 0;
        MulAcc(ref l0, ref h0, a0, c0);
        MulAcc(ref l1, ref h1, a0, c1);
        l1 <<= 1;
        h1 <<= 1;
        MulAcc(ref l2, ref h2, a0, c2);
        l2 <<= 1;
        h2 <<= 1;
        MulAcc(ref l2, ref h2, a1, c1);
        MulAcc(ref l3, ref h3, a0, c3);
        MulAcc(ref l3, ref h3, a1, c2);
        l3 <<= 1;
        h3 <<= 1;
        MulAcc(ref l4, ref h4, a0, c4);
        MulAcc(ref l4, ref h4, a1, c3);
        l4 <<= 1;
        h4 <<= 1;
        MulAcc(ref l4, ref h4, a2, c2);
        MulAcc(ref l5, ref h5, a0, c5);
        MulAcc(ref l5, ref h5, a1, c4);
        MulAcc(ref l5, ref h5, a2, c3);
        l5 <<= 1;
        h5 <<= 1;
        MulAcc(ref l6, ref h6, a0, c6);
        MulAcc(ref l6, ref h6, a1, c5);
        MulAcc(ref l6, ref h6, a2, c4);
        l6 <<= 1;
        h6 <<= 1;
        MulAcc(ref l6, ref h6, a3, c3);
        MulAcc(ref l7, ref h7, a0, c7);
        MulAcc(ref l7, ref h7, a1, c6);
        MulAcc(ref l7, ref h7, a2, c5);
        MulAcc(ref l7, ref h7, a3, c4);
        l7 <<= 1;
        h7 <<= 1;
        MulAcc(ref l8, ref h8, a1, c7);
        MulAcc(ref l8, ref h8, a2, c6);
        MulAcc(ref l8, ref h8, a3, c5);
        l8 <<= 1;
        h8 <<= 1;
        MulAcc(ref l8, ref h8, a4, c4);
        MulAcc(ref l9, ref h9, a2, c7);
        MulAcc(ref l9, ref h9, a3, c6);
        MulAcc(ref l9, ref h9, a4, c5);
        l9 <<= 1;
        h9 <<= 1;
        MulAcc(ref l10, ref h10, a3, c7);
        MulAcc(ref l10, ref h10, a4, c6);
        l10 <<= 1;
        h10 <<= 1;
        MulAcc(ref l10, ref h10, a5, c5);
        MulAcc(ref l11, ref h11, a4, c7);
        MulAcc(ref l11, ref h11, a5, c6);
        l11 <<= 1;
        h11 <<= 1;
        MulAcc(ref l12, ref h12, a5, c7);
        l12 <<= 1;
        h12 <<= 1;
        MulAcc(ref l12, ref h12, a6, c6);
        MulAcc(ref l13, ref h13, a6, c7);
        l13 <<= 1;
        h13 <<= 1;
        MulAcc(ref l14, ref h14, a7, c7);
        return Reduce(l0, h0, l1, h1, l2, h2, l3, h3, l4, h4, l5, h5, l6, h6, l7, h7, l8, h8, l9, h9, l10, h10, l11, h11, l12, h12, l13, h13, l14, h14);
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
