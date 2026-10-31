namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>Width-w non-adjacent form, for the variable-time double-scalar multiplication used by signature verification only.</summary>
internal static class Wnaf
{
    /// <summary>
    /// Recodes a little-endian scalar (up to 56 bytes) into signed odd digits in (-2^(w-1), 2^(w-1)) with at least w - 1 zeros
    /// after every non-zero digit, so that scalar = sum of digits[i]·2^i. <paramref name="digits"/> must have room for one more
    /// entry than the scalar has bits. The scalars are public (a signature's S and a hash), so this branches freely.
    /// </summary>
    public static void Compute(ReadOnlySpan<byte> scalar, Span<sbyte> digits, int w)
    {
        Span<ulong> k = stackalloc ulong[8]; // fixed small buffer: up to 512 bits
        k.Clear();
        for (int i = 0; i < scalar.Length; i++)
        {
            k[i >> 3] |= (ulong)scalar[i] << (8 * (i & 7));
        }
        digits.Clear();
        int mask = (1 << w) - 1;
        int half = 1 << (w - 1);
        for (int pos = 0; pos < digits.Length; pos++)
        {
            if ((k[0] & 1) != 0)
            {
                int u = (int)(k[0] & (ulong)mask);
                if (u >= half)
                {
                    u -= 1 << w;
                }
                digits[pos] = (sbyte)u;
                // k -= u (a negative u adds)
                if (u > 0)
                {
                    ulong borrow = (ulong)u;
                    for (int j = 0; j < 8 && borrow != 0; j++)
                    {
                        ulong before = k[j];
                        k[j] = before - borrow;
                        borrow = before < borrow ? 1UL : 0UL;
                    }
                }
                else
                {
                    ulong carry = (ulong)(-u);
                    for (int j = 0; j < 8 && carry != 0; j++)
                    {
                        ulong sum = k[j] + carry;
                        carry = sum < carry ? 1UL : 0UL;
                        k[j] = sum;
                    }
                }
            }
            for (int j = 0; j < 7; j++)
            {
                k[j] = (k[j] >> 1) | (k[j + 1] << 63);
            }
            k[7] >>= 1;
        }
    }
}
