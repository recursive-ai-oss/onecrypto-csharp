using System.Runtime.CompilerServices;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// Arithmetic modulo a group order N for the EdDSA scalars, in Montgomery form with R = 2^(64 n) and little-endian 64-bit limbs.
/// Everything is fixed-width limb arithmetic with masks: no branch, loop bound or index depends on a value, because the
/// nonce and the clamped secret scalar both pass through here during signing.
/// </summary>
internal sealed class ScalarField
{
    private readonly int _n;
    private readonly ulong[] _modulus;
    private readonly ulong _n0; // -N^-1 mod 2^64
    private readonly ulong[][] _rPowers; // R^2, R^3, ... mod N, one per limb group of a wide input

    public ScalarField(ulong[] modulus, ulong n0, params ulong[][] rPowers)
    {
        _n = modulus.Length;
        _modulus = modulus;
        _n0 = n0;
        _rPowers = rPowers;
    }

    /// <summary>The number of 64-bit limbs of a scalar.</summary>
    public int Limbs => _n;

    /// <summary>The carry out (0 or 1) of x + y = sum, computed with bit operations only, never a comparison.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong AddCarry(ulong x, ulong y, ulong sum) => ((x & y) | ((x | y) & ~sum)) >> 63;

    /// <summary>a·b + c + d as a 128-bit value: returns the high word and writes the low word. It cannot overflow 128 bits.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong MulAdd2(ulong a, ulong b, ulong c, ulong d, out ulong low)
    {
        ulong lo = a * b;
        ulong high = WideMul.High(a, b);
        ulong s1 = lo + c;
        high += AddCarry(lo, c, s1);
        ulong s2 = s1 + d;
        high += AddCarry(s1, d, s2);
        low = s2;
        return high;
    }

    /// <summary>r = a·b·R^-1 mod N. Requires a·b &lt; N·R; the result is fully reduced. r may alias a or b.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public void MontMul(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> r)
    {
        int n = _n;
        Span<ulong> t = stackalloc ulong[n + 2]; // fixed small buffer (at most 9 limbs)
        for (int i = 0; i < n; i++)
        {
            ulong bi = b[i];
            ulong carry = 0;
            for (int j = 0; j < n; j++)
            {
                carry = MulAdd2(a[j], bi, t[j], carry, out t[j]);
            }
            ulong sumTop = t[n] + carry;
            t[n + 1] = AddCarry(t[n], carry, sumTop);
            t[n] = sumTop;

            ulong m = t[0] * _n0;
            carry = MulAdd2(m, _modulus[0], t[0], 0, out _);
            for (int j = 1; j < n; j++)
            {
                carry = MulAdd2(m, _modulus[j], t[j], carry, out t[j - 1]);
            }
            ulong sumHigh = t[n] + carry;
            ulong carryOut = AddCarry(t[n], carry, sumHigh);
            t[n - 1] = sumHigh;
            t[n] = t[n + 1] + carryOut;
        }
        CondSubtract(t, t[n], r);
        t.Clear();
    }

    /// <summary>r = (a + b) mod N for a, b &lt; N. r may alias a or b.</summary>
    public void AddMod(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> r)
    {
        int n = _n;
        Span<ulong> t = stackalloc ulong[n]; // fixed small buffer
        ulong carry = 0;
        for (int i = 0; i < n; i++)
        {
            ulong partial = a[i] + b[i];
            ulong c1 = AddCarry(a[i], b[i], partial);
            ulong total = partial + carry;
            carry = c1 + AddCarry(partial, carry, total);
            t[i] = total;
        }
        CondSubtract(t, carry, r);
    }

    /// <summary>r = t - N when the (n+1)-limb value (top:t) is at least N, else t. Constant time.</summary>
    private void CondSubtract(ReadOnlySpan<ulong> t, ulong top, Span<ulong> r)
    {
        int n = _n;
        Span<ulong> d = stackalloc ulong[n]; // fixed small buffer
        ulong borrow = 0;
        for (int j = 0; j < n; j++)
        {
            ulong x = t[j], y = _modulus[j];
            ulong diff = x - y - borrow;
            borrow = ((~x & y) | (~(x ^ y) & diff)) >> 63;
            d[j] = diff;
        }
        // The value is below N exactly when the subtraction borrows out of the top limb, that is when top < borrow.
        ulong topDiff = top - borrow;
        ulong lessThan = (~top & topDiff) >> 63;
        ulong keepT = 0 - lessThan;
        for (int j = 0; j < n; j++)
        {
            r[j] = (t[j] & keepT) | (d[j] & ~keepT);
        }
        d.Clear();
    }

    /// <summary>
    /// Reduces a little-endian integer of up to three limb groups (for example a 64-byte or 114-byte hash) modulo N:
    /// x = x0 + x1·R + x2·R^2 becomes mont(x0,R^2) + mont(x1,R^3) + mont(x2,R^4) = x·R, and one more mont(·,1) removes R.
    /// </summary>
    public void ReduceWide(ReadOnlySpan<byte> wide, Span<ulong> r)
    {
        int n = _n;
        int groups = (wide.Length + (8 * n) - 1) / (8 * n);
        Span<ulong> chunk = stackalloc ulong[n]; // fixed small buffers
        Span<ulong> sum = stackalloc ulong[n];
        Span<ulong> term = stackalloc ulong[n];
        Span<ulong> one = stackalloc ulong[n];
        one.Clear();
        one[0] = 1;
        sum.Clear();
        for (int g = 0; g < groups; g++)
        {
            ReadOnlySpan<byte> part = wide.Slice(g * 8 * n, Math.Min(8 * n, wide.Length - (g * 8 * n)));
            Load(part, chunk);
            MontMul(chunk, _rPowers[g], term);
            AddMod(sum, term, sum);
        }
        MontMul(sum, one, r);
        chunk.Clear();
        sum.Clear();
        term.Clear();
    }

    /// <summary>r = (a·b + c) mod N, where a may be any n-limb value (such as a clamped secret scalar) and b, c &lt; N.</summary>
    public void MulAdd(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, ReadOnlySpan<ulong> c, Span<ulong> r)
    {
        Span<ulong> t = stackalloc ulong[_n]; // fixed small buffer
        MontMul(b, a, t); // a·b·R^-1
        MontMul(t, _rPowers[0], t); // times R^2 and R^-1 again: a·b
        AddMod(t, c, r);
        t.Clear();
    }

    /// <summary>Loads little-endian bytes (up to 8·n of them) into limbs, zero-padded.</summary>
    public static void Load(ReadOnlySpan<byte> bytes, Span<ulong> limbs)
    {
        limbs.Clear();
        for (int i = 0; i < bytes.Length; i++)
        {
            limbs[i >> 3] |= (ulong)bytes[i] << (8 * (i & 7));
        }
    }

    /// <summary>Writes limbs as little-endian bytes into <paramref name="bytes"/> (which may be shorter than 8·n; the dropped bytes must be zero).</summary>
    public static void Store(ReadOnlySpan<ulong> limbs, Span<byte> bytes)
    {
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(limbs[i >> 3] >> (8 * (i & 7)));
        }
    }

    /// <summary>True if the little-endian integer is below N. Used on public signature data only.</summary>
    public bool IsBelowModulus(ReadOnlySpan<byte> bytes)
    {
        int max = 8 * _n;
        for (int i = max; i < bytes.Length; i++)
        {
            if (bytes[i] != 0)
            {
                return false;
            }
        }
        Span<ulong> x = stackalloc ulong[_n]; // fixed small buffer
        Load(bytes[..Math.Min(max, bytes.Length)], x);
        ulong borrow = 0;
        for (int j = 0; j < _n; j++)
        {
            ulong a = x[j], b = _modulus[j];
            ulong diff = a - b - borrow;
            borrow = ((~a & b) | (~(a ^ b) & diff)) >> 63;
        }
        return borrow == 1;
    }
}

internal static class Ed25519Scalar
{
    // N = 2^252 + 27742317777372353535851937790883648493 (RFC 8032 section 5.1). The Montgomery constants are for R = 2^256.
    public static readonly ScalarField Field = new(
        [0x5812631a5cf5d3edUL, 0x14def9dea2f79cd6UL, 0x0000000000000000UL, 0x1000000000000000UL],
        0xd2b51da312547e1bUL,
        [0xa40611e3449c0f01UL, 0xd00e1ba768859347UL, 0xceec73d217f5be65UL, 0x0399411b7c309a3dUL],
        [0x2a9e49687b83a2dbUL, 0x278324e6aef7f3ecUL, 0x8065dc6c04ec5b65UL, 0x0e530b773599cec7UL]);
}

internal static class Ed448Scalar
{
    // N = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885 (RFC 8032 section 5.2). R = 2^448.
    public static readonly ScalarField Field = new(
        [0x2378c292ab5844f3UL, 0x216cc2728dc58f55UL, 0xc44edb49aed63690UL, 0xffffffff7cca23e9UL, 0xffffffffffffffffUL, 0xffffffffffffffffUL, 0x3fffffffffffffffUL],
        0x03bd440fae918bc5UL,
        [0xe3539257049b9b60UL, 0x7af32c4bc1b195d9UL, 0x0d66de2388ea1859UL, 0xae17cf725ee4d838UL, 0x1a9cc14ba3c47c44UL, 0x2052bcb7e4d070afUL, 0x3402a939f823b729UL],
        [0x62db79e25f9b74edUL, 0x32d533584f61d636UL, 0x3e0d0c8b5fa74964UL, 0x178769ed878dfcdaUL, 0xe4c71af86754b842UL, 0xed66e7f42bab736dUL, 0x0d30a4f69d3af5f1UL],
        [0xf23989320785209eUL, 0xbbddbe45ec1d63acUL, 0xdd3886273db9f5b5UL, 0x5ebb7c56b3aff7f5UL, 0xee0d93089a06c3fbUL, 0xe5c5b8eb1af94cb2UL, 0x184d17470727eb5cUL]);
}
