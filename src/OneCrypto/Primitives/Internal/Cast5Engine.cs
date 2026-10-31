using System.Runtime.CompilerServices;
using System.Buffers.Binary;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// CAST5 / CAST-128 (RFC 2144) with 40- to 128-bit keys.
/// </summary>
/// <remarks>
/// Side channels: every S-box lookup, in the rounds and in the key schedule, reads the whole 256-entry box and selects by mask
/// (<see cref="CtLookup.Word"/>), so no address depends on the key or the data. The rotation amount of a round is a key-derived
/// value; it is applied with a rotate instruction, which takes the same time for every amount.
/// </remarks>
internal sealed class Cast5Engine : BlockEngine
{
    private const int BoxWords = 256;

    // Km1..Km16 then Kr1..Kr16 (RFC 2144 section 2.4.1).
    private readonly uint[] _keys = GC.AllocateUninitializedArray<uint>(32, pinned: true);
    private readonly int _rounds;

    internal Cast5Engine(ReadOnlySpan<byte> key)
    {
        if (key.Length is < 5 or > 16)
        {
            throw new ArgumentException("A CAST5 key is 5 to 16 bytes (40 to 128 bits).", nameof(key));
        }

        // RFC 2144 section 2.5: keys of up to 80 bits use 12 rounds, longer keys 16.
        _rounds = key.Length <= 10 ? 12 : 16;
        Span<byte> x = stackalloc byte[16]; // fixed size: the key padded with zero bytes
        key.CopyTo(x);
        Schedule(x);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(x);
    }

    internal override int BlockSize => 8;

    // S-box number 1 to 8.
    private static uint S(int box, uint index) => CtLookup.Word(Cast5Tables.SBoxes.Slice((box - 1) * BoxWords, BoxWords), index);

    private static uint Word(ReadOnlySpan<byte> b, int i) => BinaryPrimitives.ReadUInt32BigEndian(b[i..]);

    // One of the 32 subkeys: the first four S-boxes indexed by the listed bytes and one more lookup (RFC 2144 section 2.4).
    private static uint Subkey(ReadOnlySpan<byte> state, int a, int b, int c, int d, int e, int boxE) =>
        S(5, state[a]) ^ S(6, state[b]) ^ S(7, state[c]) ^ S(8, state[d]) ^ S(boxE, state[e]);

    private static void Z(Span<byte> x, Span<byte> z)
    {
        BinaryPrimitives.WriteUInt32BigEndian(z, Word(x, 0) ^ S(5, x[0xD]) ^ S(6, x[0xF]) ^ S(7, x[0xC]) ^ S(8, x[0xE]) ^ S(7, x[0x8]));
        BinaryPrimitives.WriteUInt32BigEndian(z[4..], Word(x, 8) ^ S(5, z[0]) ^ S(6, z[2]) ^ S(7, z[1]) ^ S(8, z[3]) ^ S(8, x[0xA]));
        BinaryPrimitives.WriteUInt32BigEndian(z[8..], Word(x, 0xC) ^ S(5, z[7]) ^ S(6, z[6]) ^ S(7, z[5]) ^ S(8, z[4]) ^ S(5, x[0x9]));
        BinaryPrimitives.WriteUInt32BigEndian(z[0xC..], Word(x, 4) ^ S(5, z[0xA]) ^ S(6, z[9]) ^ S(7, z[0xB]) ^ S(8, z[8]) ^ S(6, x[0xB]));
    }

    private static void X(Span<byte> x, Span<byte> z)
    {
        BinaryPrimitives.WriteUInt32BigEndian(x, Word(z, 8) ^ S(5, z[5]) ^ S(6, z[7]) ^ S(7, z[4]) ^ S(8, z[6]) ^ S(7, z[0]));
        BinaryPrimitives.WriteUInt32BigEndian(x[4..], Word(z, 0) ^ S(5, x[0]) ^ S(6, x[2]) ^ S(7, x[1]) ^ S(8, x[3]) ^ S(8, z[2]));
        BinaryPrimitives.WriteUInt32BigEndian(x[8..], Word(z, 4) ^ S(5, x[7]) ^ S(6, x[6]) ^ S(7, x[5]) ^ S(8, x[4]) ^ S(5, z[1]));
        BinaryPrimitives.WriteUInt32BigEndian(x[0xC..], Word(z, 0xC) ^ S(5, x[0xA]) ^ S(6, x[9]) ^ S(7, x[0xB]) ^ S(8, x[8]) ^ S(6, z[3]));
    }

    private void Schedule(Span<byte> x)
    {
        Span<byte> z = stackalloc byte[16]; // fixed size
        for (int half = 0; half < 2; half++)
        {
            // RFC 2144 section 2.4 lists K1..K16; "the remaining half is identical", continuing from the last x, gives K17..K32.
            Span<uint> k = _keys.AsSpan(half * 16, 16);
            Z(x, z);
            k[0] = Subkey(z, 0x8, 0x9, 0x7, 0x6, 0x2, 5);
            k[1] = Subkey(z, 0xA, 0xB, 0x5, 0x4, 0x6, 6);
            k[2] = Subkey(z, 0xC, 0xD, 0x3, 0x2, 0x9, 7);
            k[3] = Subkey(z, 0xE, 0xF, 0x1, 0x0, 0xC, 8);
            X(x, z);
            k[4] = Subkey(x, 0x3, 0x2, 0xC, 0xD, 0x8, 5);
            k[5] = Subkey(x, 0x1, 0x0, 0xE, 0xF, 0xD, 6);
            k[6] = Subkey(x, 0x7, 0x6, 0x8, 0x9, 0x3, 7);
            k[7] = Subkey(x, 0x5, 0x4, 0xA, 0xB, 0x7, 8);
            Z(x, z);
            k[8] = Subkey(z, 0x3, 0x2, 0xC, 0xD, 0x9, 5);
            k[9] = Subkey(z, 0x1, 0x0, 0xE, 0xF, 0xC, 6);
            k[10] = Subkey(z, 0x7, 0x6, 0x8, 0x9, 0x2, 7);
            k[11] = Subkey(z, 0x5, 0x4, 0xA, 0xB, 0x6, 8);
            X(x, z);
            k[12] = Subkey(x, 0x8, 0x9, 0x7, 0x6, 0x3, 5);
            k[13] = Subkey(x, 0xA, 0xB, 0x5, 0x4, 0x7, 6);
            k[14] = Subkey(x, 0xC, 0xD, 0x3, 0x2, 0x8, 7);
            k[15] = Subkey(x, 0xE, 0xF, 0x1, 0x0, 0xD, 8);
        }

        System.Security.Cryptography.CryptographicOperations.ZeroMemory(z);
    }

    // The round function f of RFC 2144 section 2.2; type 1, 2 or 3 depends on the round number only.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private uint F(uint d, int round)
    {
        uint km = _keys[round];
        int kr = (int)(_keys[16 + round] & 31);
        int type = round % 3; // round index 0, 3, 6, ... is round 1, 4, 7, ...: type 1
        uint i = type switch
        {
            0 => uint.RotateLeft(km + d, kr),
            1 => uint.RotateLeft(km ^ d, kr),
            _ => uint.RotateLeft(km - d, kr),
        };
        uint s1 = S(1, i >> 24);
        uint s2 = S(2, (i >> 16) & 0xFF);
        uint s3 = S(3, (i >> 8) & 0xFF);
        uint s4 = S(4, i & 0xFF);
        return type switch
        {
            0 => ((s1 ^ s2) - s3) + s4,
            1 => ((s1 - s2) + s3) ^ s4,
            _ => ((s1 + s2) ^ s3) - s4,
        };
    }

    internal override void EncryptBlock(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        uint l = Word(source, 0);
        uint r = Word(source, 4);
        for (int i = 0; i < _rounds; i++)
        {
            (l, r) = (r, l ^ F(r, i));
        }

        BinaryPrimitives.WriteUInt32BigEndian(destination, r);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], l);
    }

    internal override void DecryptBlock(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        // The ciphertext is (R16, L16): run the rounds backwards.
        uint r = Word(source, 0);
        uint l = Word(source, 4);
        for (int i = _rounds - 1; i >= 0; i--)
        {
            (l, r) = (r ^ F(l, i), l);
        }

        BinaryPrimitives.WriteUInt32BigEndian(destination, l);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], r);
    }

    public override void Dispose() => WordWipe.Clear(_keys);
}
