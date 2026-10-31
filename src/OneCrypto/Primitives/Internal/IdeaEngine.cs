using System.Runtime.CompilerServices;
using System.Buffers.Binary;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// IDEA (Lai and Massey, "A Proposal for a New Block Encryption Standard", EUROCRYPT 1990), 128-bit key, 8.5 rounds.
/// </summary>
/// <remarks>
/// Side channels: IDEA has no tables. Its multiplication modulo 2^16 + 1 is computed with masks instead of the usual zero test and
/// division, and the multiplicative inverses of the decryption key schedule are computed as x^(2^16 - 1) with a fixed sequence of
/// multiplications, so neither the data nor the key reaches a branch.
/// </remarks>
internal sealed class IdeaEngine : BlockEngine
{
    private readonly ushort[] _encrypt = GC.AllocateUninitializedArray<ushort>(52, pinned: true);
    private readonly ushort[] _decrypt = GC.AllocateUninitializedArray<ushort>(52, pinned: true);

    internal IdeaEngine(ReadOnlySpan<byte> key)
    {
        if (key.Length != 16)
        {
            throw new ArgumentException("An IDEA key is 16 bytes.", nameof(key));
        }

        // The 128-bit key is eight 16-bit subkeys; each further group of eight comes from rotating the key left by 25 bits.
        ulong hi = BinaryPrimitives.ReadUInt64BigEndian(key);
        ulong lo = BinaryPrimitives.ReadUInt64BigEndian(key[8..]);
        for (int i = 0; i < 52; i += 8)
        {
            for (int j = 0; j < 8 && i + j < 52; j++)
            {
                ulong half = j < 4 ? hi : lo;
                _encrypt[i + j] = (ushort)(half >> (48 - (16 * (j % 4))));
            }

            (hi, lo) = ((hi << 25) | (lo >> 39), (lo << 25) | (hi >> 39));
        }

        // Decryption subkeys: the keys of the last round are inverted and applied first (Lai and Massey; the two additive keys swap
        // places in the middle rounds because the halves are not exchanged after the last round).
        for (int r = 0; r < 8; r++)
        {
            int b = 48 - (6 * r);
            _decrypt[6 * r] = Inverse(_encrypt[b]);
            _decrypt[(6 * r) + 3] = Inverse(_encrypt[b + 3]);
            _decrypt[(6 * r) + 4] = _encrypt[b - 2];
            _decrypt[(6 * r) + 5] = _encrypt[b - 1];
            if (r == 0)
            {
                _decrypt[1] = (ushort)(0 - _encrypt[b + 1]);
                _decrypt[2] = (ushort)(0 - _encrypt[b + 2]);
            }
            else
            {
                _decrypt[(6 * r) + 1] = (ushort)(0 - _encrypt[b + 2]);
                _decrypt[(6 * r) + 2] = (ushort)(0 - _encrypt[b + 1]);
            }
        }

        _decrypt[48] = Inverse(_encrypt[0]);
        _decrypt[49] = (ushort)(0 - _encrypt[1]);
        _decrypt[50] = (ushort)(0 - _encrypt[2]);
        _decrypt[51] = Inverse(_encrypt[3]);
    }

    internal override int BlockSize => 8;

    /// <summary>Multiplication modulo 65537 in which the 16-bit value 0 stands for 2^16.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ushort Mul(uint a, uint b)
    {
        // Map 0 to 65536 by adding 2^16 when a - 1 wraps below zero.
        ulong x = a + (((a - 1) >> 31) << 16);
        ulong y = b + (((b - 1) >> 31) << 16);
        ulong p = x * y;
        // 2^16 = -1 (mod 65537), so p = high * 2^16 + low is low - high.
        long r = (long)(p & 0xFFFF) - (long)(p >> 16);
        r += 65537 & (r >> 63);
        return (ushort)r; // 65536 (the value 2^16) truncates to 0, the encoding of 2^16
    }

    private static ushort Inverse(ushort x)
    {
        // x^(65535) is the inverse modulo the prime 65537, 2^16 included (it is its own inverse).
        ushort t = x;
        for (int i = 0; i < 15; i++)
        {
            t = Mul(Mul(t, t), x);
        }

        return t;
    }

    private static void Crypt(ushort[] k, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        uint x1 = BinaryPrimitives.ReadUInt16BigEndian(source);
        uint x2 = BinaryPrimitives.ReadUInt16BigEndian(source[2..]);
        uint x3 = BinaryPrimitives.ReadUInt16BigEndian(source[4..]);
        uint x4 = BinaryPrimitives.ReadUInt16BigEndian(source[6..]);
        for (int r = 0; r < 8; r++)
        {
            int p = 6 * r;
            x1 = Mul(x1, k[p]);
            x2 = (ushort)(x2 + k[p + 1]);
            x3 = (ushort)(x3 + k[p + 2]);
            x4 = Mul(x4, k[p + 3]);
            uint t0 = x1 ^ x3;
            uint t1 = x2 ^ x4;
            t0 = Mul(t0, k[p + 4]);
            t1 = (ushort)(t1 + t0);
            t1 = Mul(t1, k[p + 5]);
            t0 = (ushort)(t0 + t1);
            x1 ^= t1;
            x4 ^= t0;
            uint swap = x2 ^ t0;
            x2 = x3 ^ t1;
            x3 = swap;
        }

        // Output transformation; the middle words are taken back un-swapped.
        BinaryPrimitives.WriteUInt16BigEndian(destination, Mul(x1, k[48]));
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], (ushort)(x3 + k[49]));
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..], (ushort)(x2 + k[50]));
        BinaryPrimitives.WriteUInt16BigEndian(destination[6..], Mul(x4, k[51]));
    }

    internal override void EncryptBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Crypt(_encrypt, source, destination);

    internal override void DecryptBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Crypt(_decrypt, source, destination);

    public override void Dispose()
    {
        Array.Clear(_encrypt);
        Array.Clear(_decrypt);
    }
}
