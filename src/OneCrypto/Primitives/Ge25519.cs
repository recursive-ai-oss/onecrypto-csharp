using System.Runtime.CompilerServices;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>A point on edwards25519 in extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z.</summary>
internal struct Ge25519
{
    public Fe25519 X, Y, Z, T;

    public static Ge25519 Identity => new() { X = Fe25519.Zero, Y = Fe25519.One, Z = Fe25519.One, T = Fe25519.Zero };
}

/// <summary>A precomputed affine point (y + x, y - x, 2dxy) for the cheap mixed addition.</summary>
internal struct Ge25519Niels
{
    public Fe25519 YpX, YmX, XY2D;

    public static Ge25519Niels Identity => new() { YpX = Fe25519.One, YmX = Fe25519.One, XY2D = Fe25519.Zero };
}

/// <summary>
/// The group of edwards25519, -x^2 + y^2 = 1 + d x^2 y^2 (RFC 8032 section 5.1). The addition law used is complete, so it is
/// correct for every pair of points (doubling, the identity, inverses) without special cases, and has no value-dependent branch.
/// </summary>
internal static class Ge25519Ops
{
    // d = -121665/121666 and 2d, little-endian.
    private static ReadOnlySpan<byte> DBytes => [0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52];
    private static ReadOnlySpan<byte> D2Bytes => [0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb, 0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00, 0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19, 0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24];
    // sqrt(-1) = 2^((p-1)/4).
    private static ReadOnlySpan<byte> SqrtM1Bytes => [0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b];
    // The base point B: y = 4/5 and the even x (RFC 8032 section 5.1).
    private static ReadOnlySpan<byte> BaseX => [0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21];
    private static ReadOnlySpan<byte> BaseY => [0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66];

    private static readonly Fe25519 D = Fe25519.FromBytes(DBytes);
    private static readonly Fe25519 D2 = Fe25519.FromBytes(D2Bytes);
    private static readonly Fe25519 SqrtM1 = Fe25519.FromBytes(SqrtM1Bytes);

    public static Ge25519 Base()
    {
        Fe25519 x = Fe25519.FromBytes(BaseX);
        Fe25519 y = Fe25519.FromBytes(BaseY);
        return new Ge25519 { X = x, Y = y, Z = Fe25519.One, T = Fe25519.Mul(x, y) };
    }

    /// <summary>p + q (add-2008-hwcd-3 with k = 2d; complete for this curve).</summary>
    public static Ge25519 Add(in Ge25519 p, in Ge25519 q)
    {
        Fe25519 a = Fe25519.Mul(Fe25519.Sub(p.Y, p.X), Fe25519.Sub(q.Y, q.X));
        Fe25519 b = Fe25519.Mul(Fe25519.Add(p.Y, p.X), Fe25519.Add(q.Y, q.X));
        Fe25519 c = Fe25519.Mul(Fe25519.Mul(p.T, q.T), D2);
        Fe25519 d = Fe25519.Mul(p.Z, q.Z);
        d = Fe25519.Add(d, d);
        Fe25519 e = Fe25519.Sub(b, a);
        Fe25519 f = Fe25519.Sub(d, c);
        Fe25519 g = Fe25519.Add(d, c);
        Fe25519 h = Fe25519.Add(b, a);
        return new Ge25519 { X = Fe25519.Mul(e, f), Y = Fe25519.Mul(g, h), T = Fe25519.Mul(e, h), Z = Fe25519.Mul(f, g) };
    }

    /// <summary>p + q for a precomputed affine q (Z = 1), one multiplication cheaper than <see cref="Add"/>.</summary>
    public static Ge25519 AddNiels(in Ge25519 p, in Ge25519Niels q)
    {
        Fe25519 a = Fe25519.Mul(Fe25519.Sub(p.Y, p.X), q.YmX);
        Fe25519 b = Fe25519.Mul(Fe25519.Add(p.Y, p.X), q.YpX);
        Fe25519 c = Fe25519.Mul(p.T, q.XY2D);
        Fe25519 d = Fe25519.Add(p.Z, p.Z);
        Fe25519 e = Fe25519.Sub(b, a);
        Fe25519 f = Fe25519.Sub(d, c);
        Fe25519 g = Fe25519.Add(d, c);
        Fe25519 h = Fe25519.Add(b, a);
        return new Ge25519 { X = Fe25519.Mul(e, f), Y = Fe25519.Mul(g, h), T = Fe25519.Mul(e, h), Z = Fe25519.Mul(f, g) };
    }

    /// <summary>2p (dbl-2008-hwcd for a = -1).</summary>
    public static Ge25519 Double(in Ge25519 p)
    {
        Fe25519 a = Fe25519.Square(p.X);
        Fe25519 b = Fe25519.Square(p.Y);
        Fe25519 c = Fe25519.Square(p.Z);
        c = Fe25519.Add(c, c);
        Fe25519 xy = Fe25519.Add(p.X, p.Y);
        Fe25519 e = Fe25519.Sub(Fe25519.Sub(Fe25519.Square(xy), a), b);
        Fe25519 g = Fe25519.Sub(b, a);      // D + B with D = -A
        Fe25519 f = Fe25519.Sub(g, c);
        Fe25519 h = Fe25519.Neg(Fe25519.Add(a, b)); // D - B = -A - B
        return new Ge25519 { X = Fe25519.Mul(e, f), Y = Fe25519.Mul(g, h), T = Fe25519.Mul(e, h), Z = Fe25519.Mul(f, g) };
    }

    /// <summary>2p without the T coordinate (one multiplication fewer); only valid when the result is doubled again.</summary>
    private static Ge25519 DoubleNoT(in Ge25519 p)
    {
        Fe25519 a = Fe25519.Square(p.X);
        Fe25519 b = Fe25519.Square(p.Y);
        Fe25519 c = Fe25519.Square(p.Z);
        c = Fe25519.Add(c, c);
        Fe25519 e = Fe25519.Sub(Fe25519.Sub(Fe25519.Square(Fe25519.Add(p.X, p.Y)), a), b);
        Fe25519 g = Fe25519.Sub(b, a);
        Fe25519 f = Fe25519.Sub(g, c);
        Fe25519 h = Fe25519.Neg(Fe25519.Add(a, b));
        return new Ge25519 { X = Fe25519.Mul(e, f), Y = Fe25519.Mul(g, h), Z = Fe25519.Mul(f, g) };
    }

    public static Ge25519 Negate(in Ge25519 p) =>
        new() { X = Fe25519.Neg(p.X), Y = p.Y, Z = p.Z, T = Fe25519.Neg(p.T) };

    /// <summary>Writes the RFC 8032 encoding: y little-endian, with the low bit of x in bit 255.</summary>
    public static void Encode(in Ge25519 p, Span<byte> s)
    {
        Fe25519 zinv = Fe25519.Invert(p.Z);
        Fe25519 x = Fe25519.Mul(p.X, zinv);
        Fe25519 y = Fe25519.Mul(p.Y, zinv);
        y.ToBytes(s);
        s[31] ^= (byte)(x.Parity() << 7);
    }

    /// <summary>
    /// Decodes a point (RFC 8032 section 5.1.3). Fails if y is not below p, if y does not give a square x, or if x = 0 with
    /// the sign bit set. This runs on public data (keys and signatures being verified), so it may branch on the encoding.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> s, out Ge25519 p)
    {
        p = default;
        int sign = s[31] >> 7;
        Span<byte> yb = stackalloc byte[32]; // fixed small buffers
        s[..32].CopyTo(yb);
        yb[31] &= 0x7f;
        Fe25519 y = Fe25519.FromBytes(yb);
        Span<byte> canon = stackalloc byte[32];
        y.ToBytes(canon);
        if (!canon.SequenceEqual(yb))
        {
            return false; // y >= p: not canonical
        }

        Fe25519 y2 = Fe25519.Square(y);
        Fe25519 u = Fe25519.Sub(y2, Fe25519.One);
        Fe25519 v = Fe25519.Add(Fe25519.Mul(D, y2), Fe25519.One);
        // x = u v^3 (u v^7)^((p-5)/8) is a candidate root of u/v (RFC 8032 section 5.1.3).
        Fe25519 v3 = Fe25519.Mul(Fe25519.Square(v), v);
        Fe25519 v7 = Fe25519.Mul(Fe25519.Square(v3), v);
        Fe25519 x = Fe25519.Mul(Fe25519.Mul(u, v3), Fe25519.Pow22523(Fe25519.Mul(u, v7)));
        Fe25519 vxx = Fe25519.Mul(v, Fe25519.Square(x));
        if (!Fe25519.Equal(vxx, u))
        {
            if (!Fe25519.Equal(vxx, Fe25519.Neg(u)))
            {
                return false; // no square root: not on the curve
            }
            x = Fe25519.Mul(x, SqrtM1);
        }
        bool xZero = Fe25519.Equal(x, Fe25519.Zero);
        if (xZero && sign == 1)
        {
            return false;
        }
        if (x.Parity() != sign)
        {
            x = Fe25519.Neg(x);
        }
        p = new Ge25519 { X = x, Y = y, Z = Fe25519.One, T = Fe25519.Mul(x, y) };
        return true;
    }

    private static Ge25519Niels ToNiels(in Ge25519 p)
    {
        Fe25519 zinv = Fe25519.Invert(p.Z);
        Fe25519 x = Fe25519.Mul(p.X, zinv);
        Fe25519 y = Fe25519.Mul(p.Y, zinv);
        return new Ge25519Niels { YpX = Fe25519.Add(y, x), YmX = Fe25519.Sub(y, x), XY2D = Fe25519.Mul(Fe25519.Mul(x, y), D2) };
    }

    /// <summary>
    /// Table[i * 8 + (j - 1)] = j · 256^i · B for i in 0..31 and j in 1..8, built once on first use. A signed 4-bit window of the
    /// scalar at an even position 2i selects from row i; odd positions use the same rows after a multiplication by 16.
    /// </summary>
    private static readonly Ge25519Niels[] BaseTable = BuildBaseTable();

    private static Ge25519Niels[] BuildBaseTable()
    {
        var table = new Ge25519Niels[32 * 8];
        Ge25519 row = Base();
        for (int i = 0; i < 32; i++)
        {
            Ge25519 acc = row;
            for (int j = 0; j < 8; j++)
            {
                table[(i * 8) + j] = ToNiels(acc);
                acc = Add(acc, row);
            }
            for (int k = 0; k < 8; k++)
            {
                row = Double(row);
            }
        }
        return table;
    }

    /// <summary>All-ones if a == b, else zero, for small non-negative ints, without branching.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong EqMask(int a, int b)
    {
        uint x = (uint)(a ^ b);
        return 0 - (((x - 1) >> 31) & 1UL);
    }

    /// <summary>Picks signed digit <paramref name="b"/> in [-8, 8] times row <paramref name="row"/>'s base, scanning the whole row.</summary>
    private static Ge25519Niels Select(int row, int b)
    {
        int negative = (b >> 31) & 1;
        int babs = b - (((-negative) & b) << 1);
        Ge25519Niels t = Ge25519Niels.Identity;
        int offset = row * 8;
        for (int j = 1; j <= 8; j++)
        {
            ulong m = EqMask(babs, j);
            ref readonly Ge25519Niels e = ref BaseTable[offset + j - 1];
            Fe25519.CMove(ref t.YpX, e.YpX, m);
            Fe25519.CMove(ref t.YmX, e.YmX, m);
            Fe25519.CMove(ref t.XY2D, e.XY2D, m);
        }
        // Negative digit: -(y+x, y-x, 2dxy) = (y-x, y+x, -2dxy).
        Ge25519Niels neg = new() { YpX = t.YmX, YmX = t.YpX, XY2D = Fe25519.Neg(t.XY2D) };
        ulong nm = 0 - (ulong)negative;
        Fe25519.CMove(ref t.YpX, neg.YpX, nm);
        Fe25519.CMove(ref t.YmX, neg.YmX, nm);
        Fe25519.CMove(ref t.XY2D, neg.XY2D, nm);
        return t;
    }

    /// <summary>
    /// [scalar]B for a 32-byte little-endian scalar below 2^255, constant time: the scalar is recoded into 64 signed 4-bit
    /// digits, each digit selects its table entry by scanning every entry with masks, and the sequence of group operations
    /// is the same for every scalar.
    /// </summary>
    public static Ge25519 ScalarMultBase(ReadOnlySpan<byte> scalar)
    {
        Span<int> e = stackalloc int[64]; // fixed small buffer
        for (int i = 0; i < 32; i++)
        {
            e[2 * i] = scalar[i] & 15;
            e[(2 * i) + 1] = (scalar[i] >> 4) & 15;
        }
        int carry = 0;
        for (int i = 0; i < 63; i++)
        {
            e[i] += carry;
            carry = (e[i] + 8) >> 4;
            e[i] -= carry << 4;
        }
        e[63] += carry;

        Ge25519 h = Ge25519.Identity;
        for (int i = 1; i < 64; i += 2)
        {
            h = AddNiels(h, Select(i / 2, e[i]));
        }
        h = Double(Double(Double(Double(h))));
        for (int i = 0; i < 64; i += 2)
        {
            h = AddNiels(h, Select(i / 2, e[i]));
        }
        e.Clear();
        return h;
    }

    /// <summary>[scalar]q for a public point and scalar, 4-bit windows, variable time. Used by verification only.</summary>
    public static Ge25519 ScalarMultVartime(ReadOnlySpan<byte> scalar, in Ge25519 q)
    {
        Span<Ge25519> table = stackalloc Ge25519[16]; // fixed small buffer
        table[0] = Ge25519.Identity;
        table[1] = q;
        for (int i = 2; i < 16; i++)
        {
            table[i] = (i & 1) == 0 ? Double(table[i / 2]) : Add(table[i - 1], q);
        }
        Ge25519 r = Ge25519.Identity;
        bool started = false;
        for (int i = 63; i >= 0; i--)
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

    /// <summary>(2j + 1)·B in precomputed affine form for j in 0..31, for the width-7 digits of verification.</summary>
    private static readonly Ge25519Niels[] BaseOdd = BuildBaseOdd();

    private static Ge25519Niels[] BuildBaseOdd()
    {
        var table = new Ge25519Niels[32];
        Ge25519 b = Base();
        Ge25519 b2 = Double(b);
        Ge25519 acc = b;
        for (int j = 0; j < 32; j++)
        {
            table[j] = ToNiels(acc);
            acc = Add(acc, b2);
        }
        return table;
    }

    /// <summary>
    /// [s]B + [k]q for public scalars below 2^256, variable time (verification only): one shared chain of doublings with
    /// width-7 digits for the fixed base point and width-5 digits for q.
    /// </summary>
    public static Ge25519 DoubleScalarMulBaseVartime(ReadOnlySpan<byte> s, ReadOnlySpan<byte> k, in Ge25519 q)
    {
        Span<sbyte> ds = stackalloc sbyte[257]; // fixed small buffers
        Span<sbyte> dk = stackalloc sbyte[257];
        Wnaf.Compute(s, ds, 7);
        Wnaf.Compute(k, dk, 5);
        Span<Ge25519> tq = stackalloc Ge25519[8]; // q, 3q, 5q, ... 15q
        tq[0] = q;
        Ge25519 q2 = Double(q);
        for (int j = 1; j < 8; j++)
        {
            tq[j] = Add(tq[j - 1], q2);
        }
        int top = 256;
        while (top >= 0 && ds[top] == 0 && dk[top] == 0)
        {
            top--;
        }
        Ge25519 r = Ge25519.Identity;
        for (int i = top; i >= 0; i--)
        {
            bool adds = ds[i] != 0 || dk[i] != 0;
            r = adds ? Double(r) : DoubleNoT(r);
            int dq = dk[i];
            if (dq > 0)
            {
                r = Add(r, tq[dq >> 1]);
            }
            else if (dq < 0)
            {
                r = Add(r, Negate(tq[(-dq) >> 1]));
            }
            int db = ds[i];
            if (db > 0)
            {
                r = AddNiels(r, BaseOdd[db >> 1]);
            }
            else if (db < 0)
            {
                Ge25519Niels n = BaseOdd[(-db) >> 1];
                r = AddNiels(r, new Ge25519Niels { YpX = n.YmX, YmX = n.YpX, XY2D = Fe25519.Neg(n.XY2D) });
            }
        }
        return r;
    }
}
