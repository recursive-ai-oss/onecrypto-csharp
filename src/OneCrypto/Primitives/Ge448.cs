using System.Runtime.CompilerServices;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>A point on edwards448 in projective coordinates (X:Y:Z), x = X/Z, y = Y/Z.</summary>
internal struct Ge448
{
    public Fe448 X, Y, Z;

    public static Ge448 Identity => new() { X = Fe448.Zero, Y = Fe448.One, Z = Fe448.One };
}

/// <summary>An affine point (x, y) with Z = 1, for the cheaper mixed addition.</summary>
internal struct Ge448Affine
{
    public Fe448 X, Y;

    public static Ge448Affine Identity => new() { X = Fe448.Zero, Y = Fe448.One };
}

/// <summary>
/// The group of edwards448, x^2 + y^2 = 1 + d x^2 y^2 with d = -39081 (RFC 8032 section 5.2). Here a = 1 is a square and d is
/// not, so the addition law is complete: correct for every pair of points, with no branch on the operands.
/// </summary>
internal static class Ge448Ops
{
    // d = -39081 mod p, little-endian.
    private static ReadOnlySpan<byte> DBytes => [0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    // The base point B of RFC 8032 section 5.2.
    private static ReadOnlySpan<byte> BaseX => [0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26, 0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80, 0x3b, 0x43, 0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12, 0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea, 0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e, 0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22, 0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f];
    private static ReadOnlySpan<byte> BaseY => [0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98, 0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd, 0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a, 0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87, 0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b, 0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88, 0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69];

    private static readonly Fe448 D = Fe448.FromBytes(DBytes);

    public static Ge448 Base() => new() { X = Fe448.FromBytes(BaseX), Y = Fe448.FromBytes(BaseY), Z = Fe448.One };

    /// <summary>p + q (add-2007-bl for a = 1; complete for edwards448).</summary>
    public static Ge448 Add(in Ge448 p, in Ge448 q)
    {
        Fe448 a = Fe448.Mul(p.Z, q.Z);
        Fe448 b = Fe448.Square(a);
        Fe448 c = Fe448.Mul(p.X, q.X);
        Fe448 d = Fe448.Mul(p.Y, q.Y);
        Fe448 e = Fe448.Mul(Fe448.Mul(D, c), d);
        Fe448 f = Fe448.Sub(b, e);
        Fe448 g = Fe448.Add(b, e);
        Fe448 h = Fe448.Mul(Fe448.Add(p.X, p.Y), Fe448.Add(q.X, q.Y));
        h = Fe448.Sub(Fe448.Sub(h, c), d);
        return new Ge448
        {
            X = Fe448.Mul(Fe448.Mul(a, f), h),
            Y = Fe448.Mul(Fe448.Mul(a, g), Fe448.Sub(d, c)),
            Z = Fe448.Mul(f, g),
        };
    }

    /// <summary>p + q for an affine q (Z = 1).</summary>
    public static Ge448 AddAffine(in Ge448 p, in Ge448Affine q)
    {
        Fe448 b = Fe448.Square(p.Z);
        Fe448 c = Fe448.Mul(p.X, q.X);
        Fe448 d = Fe448.Mul(p.Y, q.Y);
        Fe448 e = Fe448.Mul(Fe448.Mul(D, c), d);
        Fe448 f = Fe448.Sub(b, e);
        Fe448 g = Fe448.Add(b, e);
        Fe448 h = Fe448.Mul(Fe448.Add(p.X, p.Y), Fe448.Add(q.X, q.Y));
        h = Fe448.Sub(Fe448.Sub(h, c), d);
        return new Ge448
        {
            X = Fe448.Mul(Fe448.Mul(p.Z, f), h),
            Y = Fe448.Mul(Fe448.Mul(p.Z, g), Fe448.Sub(d, c)),
            Z = Fe448.Mul(f, g),
        };
    }

    /// <summary>2p (dbl-2007-bl).</summary>
    public static Ge448 Double(in Ge448 p)
    {
        Fe448 xy = Fe448.Add(p.X, p.Y);
        Fe448 b = Fe448.Square(xy);
        Fe448 c = Fe448.Square(p.X);
        Fe448 d = Fe448.Square(p.Y);
        Fe448 e = Fe448.Add(c, d);
        Fe448 h = Fe448.Square(p.Z);
        Fe448 j = Fe448.Sub(Fe448.Sub(e, h), h);
        return new Ge448
        {
            X = Fe448.Mul(Fe448.Sub(b, e), j),
            Y = Fe448.Mul(e, Fe448.Sub(c, d)),
            Z = Fe448.Mul(e, j),
        };
    }

    public static Ge448 Negate(in Ge448 p) => new() { X = Fe448.Neg(p.X), Y = p.Y, Z = p.Z };

    /// <summary>Writes the 57-byte RFC 8032 encoding: y little-endian in 56 bytes, then a byte holding the low bit of x in its top bit.</summary>
    public static void Encode(in Ge448 p, Span<byte> s)
    {
        Fe448 zinv = Fe448.Invert(p.Z);
        Fe448 x = Fe448.Mul(p.X, zinv);
        Fe448 y = Fe448.Mul(p.Y, zinv);
        y.ToBytes(s);
        s[56] = (byte)(x.Parity() << 7);
    }

    /// <summary>
    /// Decodes a 57-byte point (RFC 8032 section 5.2.3). Fails if the last byte has any bit but the top one set, if y is not
    /// below p, if y gives no square x, or if x = 0 with the sign bit set. Public data only; may branch on the encoding.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> s, out Ge448 p)
    {
        p = default;
        if ((s[56] & 0x7f) != 0)
        {
            return false;
        }
        int sign = s[56] >> 7;
        Fe448 y = Fe448.FromBytes(s[..56]);
        Span<byte> canon = stackalloc byte[56]; // fixed small buffer
        y.ToBytes(canon);
        if (!canon.SequenceEqual(s[..56]))
        {
            return false; // y >= p
        }
        Fe448 y2 = Fe448.Square(y);
        Fe448 u = Fe448.Sub(y2, Fe448.One);
        Fe448 v = Fe448.Sub(Fe448.Mul(D, y2), Fe448.One);
        // x = u^3 v (u^5 v^3)^((p-3)/4) is a candidate root of u/v (RFC 8032 section 5.2.3).
        Fe448 u2 = Fe448.Square(u);
        Fe448 u3 = Fe448.Mul(u2, u);
        Fe448 u5 = Fe448.Mul(u3, u2);
        Fe448 v3 = Fe448.Mul(Fe448.Square(v), v);
        Fe448 x = Fe448.Mul(Fe448.Mul(u3, v), Fe448.Pow446m3Over4(Fe448.Mul(u5, v3)));
        if (!Fe448.Equal(Fe448.Mul(v, Fe448.Square(x)), u))
        {
            return false;
        }
        if (Fe448.Equal(x, Fe448.Zero) && sign == 1)
        {
            return false;
        }
        if (x.Parity() != sign)
        {
            x = Fe448.Neg(x);
        }
        p = new Ge448 { X = x, Y = y, Z = Fe448.One };
        return true;
    }

    private static Ge448Affine ToAffine(in Ge448 p)
    {
        Fe448 zinv = Fe448.Invert(p.Z);
        return new Ge448Affine { X = Fe448.Mul(p.X, zinv), Y = Fe448.Mul(p.Y, zinv) };
    }

    /// <summary>Table[i * 8 + (j - 1)] = j · 256^i · B for i in 0..55 and j in 1..8, built once on first use.</summary>
    private static readonly Ge448Affine[] BaseTable = BuildBaseTable();

    private static Ge448Affine[] BuildBaseTable()
    {
        var table = new Ge448Affine[56 * 8];
        Ge448 row = Base();
        for (int i = 0; i < 56; i++)
        {
            Ge448 acc = row;
            for (int j = 0; j < 8; j++)
            {
                table[(i * 8) + j] = ToAffine(acc);
                acc = Add(acc, row);
            }
            for (int k = 0; k < 8; k++)
            {
                row = Double(row);
            }
        }
        return table;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong EqMask(int a, int b)
    {
        uint x = (uint)(a ^ b);
        return 0 - (((x - 1) >> 31) & 1UL);
    }

    private static Ge448Affine Select(int row, int b)
    {
        int negative = (b >> 31) & 1;
        int babs = b - (((-negative) & b) << 1);
        Ge448Affine t = Ge448Affine.Identity;
        int offset = row * 8;
        for (int j = 1; j <= 8; j++)
        {
            ulong m = EqMask(babs, j);
            ref readonly Ge448Affine e = ref BaseTable[offset + j - 1];
            Fe448.CMove(ref t.X, e.X, m);
            Fe448.CMove(ref t.Y, e.Y, m);
        }
        // Negative digit: -(x, y) = (-x, y).
        Fe448 nx = Fe448.Neg(t.X);
        Fe448.CMove(ref t.X, nx, 0 - (ulong)negative);
        return t;
    }

    /// <summary>
    /// [scalar]B for a 56-byte little-endian scalar below the group order, constant time: 112 signed 4-bit digits, each
    /// selecting its table entry by scanning every entry with masks; the sequence of group operations is the same for every scalar.
    /// </summary>
    public static Ge448 ScalarMultBase(ReadOnlySpan<byte> scalar)
    {
        Span<int> e = stackalloc int[112]; // fixed small buffer
        for (int i = 0; i < 56; i++)
        {
            e[2 * i] = scalar[i] & 15;
            e[(2 * i) + 1] = (scalar[i] >> 4) & 15;
        }
        int carry = 0;
        for (int i = 0; i < 111; i++)
        {
            e[i] += carry;
            carry = (e[i] + 8) >> 4;
            e[i] -= carry << 4;
        }
        e[111] += carry; // the scalar is below 2^446, so this digit stays in [-8, 8]

        Ge448 h = Ge448.Identity;
        for (int i = 1; i < 112; i += 2)
        {
            h = AddAffine(h, Select(i / 2, e[i]));
        }
        h = Double(Double(Double(Double(h))));
        for (int i = 0; i < 112; i += 2)
        {
            h = AddAffine(h, Select(i / 2, e[i]));
        }
        e.Clear();
        return h;
    }

    /// <summary>[scalar]q for a public point and a 56-byte scalar, 4-bit windows, variable time. Used by verification only.</summary>
    public static Ge448 ScalarMultVartime(ReadOnlySpan<byte> scalar, in Ge448 q)
    {
        Span<Ge448> table = stackalloc Ge448[16]; // fixed small buffer
        table[0] = Ge448.Identity;
        table[1] = q;
        for (int i = 2; i < 16; i++)
        {
            table[i] = (i & 1) == 0 ? Double(table[i / 2]) : Add(table[i - 1], q);
        }
        Ge448 r = Ge448.Identity;
        bool started = false;
        for (int i = 111; i >= 0; i--)
        {
            if (started)
            {
                r = Double(Double(Double(Double(r))));
            }
            int w = (scalar[i >> 1] >> ((i & 1) * 4)) & 15;
            if (w != 0)
            {
                r = started ? Add(r, table[w]) : table[w];
                started = true;
            }
        }
        return r;
    }
}
