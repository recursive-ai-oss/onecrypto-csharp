using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Internal;

/// <summary>
/// Arithmetic on secret big numbers that must not branch or index on their value. Used to rebuild the CRT exponents of an RSA key
/// (d mod p-1, d mod q-1) that formats such as OpenSSH's omit. <see cref="System.Numerics.BigInteger"/> is not constant time, so it is not used.
/// </summary>
internal static class SecretMod
{
    /// <summary>
    /// Computes <paramref name="value"/> mod <paramref name="modulus"/> (both big-endian, modulus non-zero) into
    /// <paramref name="result"/>, which must be <paramref name="modulus"/>.Length bytes. The loop count depends only on the lengths,
    /// which are public; each step is a shift, one subtraction and a mask select.
    /// </summary>
    public static void Reduce(ReadOnlySpan<byte> value, ReadOnlySpan<byte> modulus, Span<byte> result)
    {
        int limbs = ((modulus.Length + 7) / 8) + 1; // one spare limb so 2r+1 never overflows
        ulong[] m = new ulong[limbs];
        ulong[] r = new ulong[limbs];
        ulong[] t = new ulong[limbs];
        try
        {
            for (int i = 0; i < modulus.Length; i++)
            {
                int bytePos = modulus.Length - 1 - i;
                m[i / 8] |= (ulong)modulus[bytePos] << (8 * (i % 8));
            }

            foreach (byte vb in value)
            {
                for (int bit = 7; bit >= 0; bit--)
                {
                    ulong carry = (ulong)((vb >> bit) & 1);
                    for (int i = 0; i < limbs; i++)
                    {
                        ulong next = r[i] >> 63;
                        r[i] = (r[i] << 1) | carry;
                        carry = next;
                    }

                    // t = r - m; if no borrow came out (r >= m) keep t, otherwise keep r.
                    ulong borrow = 0;
                    for (int i = 0; i < limbs; i++)
                    {
                        ulong a = r[i];
                        ulong b = m[i];
                        ulong d = a - b - borrow;
                        borrow = ((~a & b) | (~(a ^ b) & d)) >> 63;
                        t[i] = d;
                    }

                    ulong mask = borrow - 1; // borrow 0 -> all ones, 1 -> zero
                    for (int i = 0; i < limbs; i++)
                    {
                        r[i] = (t[i] & mask) | (r[i] & ~mask);
                    }
                }
            }

            for (int i = 0; i < result.Length; i++)
            {
                result[result.Length - 1 - i] = (byte)(r[i / 8] >> (8 * (i % 8)));
            }
        }
        finally
        {
            Array.Clear(m);
            Array.Clear(r);
            Array.Clear(t);
        }
    }

    /// <summary>Left-pads a big-endian magnitude with zeros (or drops leading zeros) to exactly <paramref name="length"/> bytes.</summary>
    public static byte[] Fixed(ReadOnlySpan<byte> magnitude, int length)
    {
        while (magnitude.Length > length && magnitude[0] == 0)
        {
            magnitude = magnitude[1..];
        }

        if (magnitude.Length > length)
        {
            throw new CryptographicException("A number is longer than its field.");
        }

        byte[] r = new byte[length];
        magnitude.CopyTo(r.AsSpan(length - magnitude.Length));
        return r;
    }
}
