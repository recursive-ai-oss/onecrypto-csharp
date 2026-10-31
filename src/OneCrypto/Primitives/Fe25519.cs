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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static UInt128 M(ulong a, ulong b)
        => Math.BigMul(a, b);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Fe25519 Finish(UInt128 r0, UInt128 r1, UInt128 r2, UInt128 r3, UInt128 r4)
    {
        Fe25519 r;
        ulong c = (ulong)(r0 >> 51);
        r.V0 = (ulong)r0 & Mask;
        r1 += c; c = (ulong)(r1 >> 51); r.V1 = (ulong)r1 & Mask;
        r2 += c; c = (ulong)(r2 >> 51); r.V2 = (ulong)r2 & Mask;
        r3 += c; c = (ulong)(r3 >> 51); r.V3 = (ulong)r3 & Mask;
        r4 += c; c = (ulong)(r4 >> 51); r.V4 = (ulong)r4 & Mask;
        r.V0 += c * 19;
        c = r.V0 >> 51; r.V0 &= Mask;
        r.V1 += c;
        return r;
    }

    /// <summary>Field multiplication. Inputs must be reduced (limbs below 2^51 + a few thousand).</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Fe25519 Mul(in Fe25519 a, in Fe25519 b)
    {
        ulong a0 = a.V0, a1 = a.V1, a2 = a.V2, a3 = a.V3, a4 = a.V4;
        ulong b0 = b.V0, b1 = b.V1, b2 = b.V2, b3 = b.V3, b4 = b.V4;
        ulong b1_19 = b1 * 19, b2_19 = b2 * 19, b3_19 = b3 * 19, b4_19 = b4 * 19;
        UInt128 r0 = M(a0, b0) + M(a1, b4_19) + M(a2, b3_19) + M(a3, b2_19) + M(a4, b1_19);
        UInt128 r1 = M(a0, b1) + M(a1, b0) + M(a2, b4_19) + M(a3, b3_19) + M(a4, b2_19);
        UInt128 r2 = M(a0, b2) + M(a1, b1) + M(a2, b0) + M(a3, b4_19) + M(a4, b3_19);
        UInt128 r3 = M(a0, b3) + M(a1, b2) + M(a2, b1) + M(a3, b0) + M(a4, b4_19);
        UInt128 r4 = M(a0, b4) + M(a1, b3) + M(a2, b2) + M(a3, b1) + M(a4, b0);
        return Finish(r0, r1, r2, r3, r4);
    }

    /// <summary>Field squaring; cheaper than <see cref="Mul"/> because each cross product is computed once.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static Fe25519 Square(in Fe25519 a)
    {
        ulong a0 = a.V0, a1 = a.V1, a2 = a.V2, a3 = a.V3, a4 = a.V4;
        ulong d0 = a0 * 2, d1 = a1 * 2, d2 = a2 * 2;
        ulong a3_19 = a3 * 19, a4_19 = a4 * 19;
        UInt128 r0 = M(a0, a0) + M(d1, a4_19) + M(d2, a3_19);
        UInt128 r1 = M(d0, a1) + M(d2, a4_19) + M(a3, a3_19);
        UInt128 r2 = M(d0, a2) + M(a1, a1) + M(a3 * 2, a4_19);
        UInt128 r3 = M(d0, a3) + M(d1, a2) + M(a4, a4_19);
        UInt128 r4 = M(d0, a4) + M(d1, a3) + M(a2, a2);
        return Finish(r0, r1, r2, r3, r4);
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
