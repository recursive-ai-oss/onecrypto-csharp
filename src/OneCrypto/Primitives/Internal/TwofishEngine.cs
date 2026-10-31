using System.Runtime.CompilerServices;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// Twofish (Schneier, Kelsey, Whiting, Wagner, Hall and Ferguson, "Twofish: A 128-Bit Block Cipher", 1998) with 128-, 192- and
/// 256-bit keys.
/// </summary>
/// <remarks>
/// <para>Side channels: the key-dependent S-boxes are not tabulated. Each S-box byte is computed on the fly as the paper defines
/// it, from the two fixed byte permutations of the paper, and those are built from four 4-bit permutations, which a byte shuffle evaluates
/// without any memory access that depends on the data. The eight S-box bytes of a round's two g functions go through the chain
/// together as one vector. The 4 x 4 matrix multiplications over GF(2^8) use shifts and masks. Nothing indexes memory by a secret.</para>
/// <para>Words are little-endian, as in the paper.</para>
/// </remarks>
internal sealed class TwofishEngine : BlockEngine
{
    // Reduction constants: v(x) = x^8 + x^6 + x^5 + x^3 + 1 for the MDS matrix, w(x) = x^8 + x^6 + x^3 + x^2 + 1 for the RS matrix.
    private const uint MdsPolynomial = 0x169;
    private const uint RsPolynomial = 0x14D;

    // The 4-bit permutations behind the two fixed byte permutations (paper section 4.3.5), t0..t3 each, as 16-entry rows for a byte shuffle.
    private static readonly Vector128<byte>[] PermA =
    [
        Row(0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4),
        Row(0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD),
        Row(0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1),
        Row(0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA),
    ];

    private static readonly Vector128<byte>[] PermB =
    [
        Row(0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5),
        Row(0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8),
        Row(0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF),
        Row(0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA),
    ];

    // Which of the two byte permutations (A is the first, B the second of the paper) each of the four bytes passes through at each stage of h (paper section 4.3.2): the first stage
    // applied for a key of k words is Patterns[k], the last Patterns[0]. Byte j is lane j of each half of the vector.
    private static readonly Vector128<byte>[] Patterns =
    [
        Pattern(1, 0, 1, 0),
        Pattern(0, 0, 1, 1),
        Pattern(0, 1, 0, 1),
        Pattern(1, 1, 0, 0),
        Pattern(1, 0, 0, 1),
    ];

    private static readonly Vector128<byte> Nibble = Vector128.Create((byte)0x0F);
    private static readonly Vector128<byte> ReductionMds = Vector128.Create((byte)(MdsPolynomial & 0xFF));

    // The MDS matrix (paper section 4.2) as, for each input byte j, a shuffle that copies lane j of each half into all four lanes
    // of that half, and for each of the constants 01, EF and 5B a mask of the output lanes that multiply by it.
    private static readonly Vector128<byte>[] Broadcast = BuildBroadcast();
    private static readonly Vector128<byte>[,] MdsSelect = BuildMdsSelect();

    private readonly uint[] _k = GC.AllocateUninitializedArray<uint>(40, pinned: true);

    // The key-dependent words of the S-boxes in the order of the paper's list L (the vector S, last word first), each repeated in
    // both halves of a 64-bit value so one vector carries the two g functions of a round.
    private readonly ulong[] _s;

    internal TwofishEngine(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new ArgumentException("A Twofish key is 16, 24 or 32 bytes.", nameof(key));
        }

        int k = key.Length / 8;
        _s = GC.AllocateUninitializedArray<ulong>(k, pinned: true);
        Span<ulong> schedule = stackalloc ulong[4]; // fixed size: M_even and M_odd words side by side, per stage
        schedule = schedule[..k];
        for (int i = 0; i < k; i++)
        {
            uint even = BinaryPrimitives.ReadUInt32LittleEndian(key[(8 * i)..]);
            uint odd = BinaryPrimitives.ReadUInt32LittleEndian(key[((8 * i) + 4)..]);
            schedule[i] = even | ((ulong)odd << 32); // low half: Me_i, high half: Mo_i
            uint s = ReedSolomon(key.Slice(8 * i, 8));
            _s[k - 1 - i] = s | ((ulong)s << 32); // L_0 is S_(k-1)
        }

        for (int i = 0; i < 20; i++)
        {
            // Paper section 4.3.5: A_i = h(2i rho, Me), B_i = ROL(h((2i+1) rho, Mo), 8).
            uint evenByte = (uint)(2 * i) * 0x01010101u;
            uint oddByte = (uint)((2 * i) + 1) * 0x01010101u;
            Vector128<byte> x = Vector128.CreateScalar(evenByte | ((ulong)oddByte << 32)).AsByte();
            (uint a, uint b) = H(x, schedule);
            b = uint.RotateLeft(b, 8);
            _k[2 * i] = a + b;
            _k[(2 * i) + 1] = uint.RotateLeft(a + (2 * b), 9);
        }

        schedule.Clear();
    }

    internal override int BlockSize => 16;

    private static Vector128<byte> Row(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) =>
        Vector128.Create((byte)a, (byte)b, (byte)c, (byte)d, (byte)e, (byte)f, (byte)g, (byte)h, (byte)i, (byte)j, (byte)k, (byte)l, (byte)m, (byte)n, (byte)o, (byte)p);

    private static Vector128<byte> Pattern(int a, int b, int c, int d)
    {
        byte ma = (byte)(0 - a);
        byte mb = (byte)(0 - b);
        byte mc = (byte)(0 - c);
        byte md = (byte)(0 - d);
        return Vector128.Create(ma, mb, mc, md, ma, mb, mc, md, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    private static Vector128<byte>[] BuildBroadcast()
    {
        var result = new Vector128<byte>[4];
        for (int j = 0; j < 4; j++)
        {
            result[j] = Vector128.Create((byte)j, (byte)j, (byte)j, (byte)j, (byte)(4 + j), (byte)(4 + j), (byte)(4 + j), (byte)(4 + j), 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80);
        }

        return result;
    }

    private static Vector128<byte>[,] BuildMdsSelect()
    {
        byte[][] mds = [[0x01, 0xEF, 0x5B, 0x5B], [0x5B, 0xEF, 0xEF, 0x01], [0xEF, 0x5B, 0x01, 0xEF], [0xEF, 0x01, 0xEF, 0x5B]];
        byte[] constants = [0x01, 0xEF, 0x5B];
        var result = new Vector128<byte>[4, 3];
        Span<byte> mask = stackalloc byte[16]; // fixed size
        for (int j = 0; j < 4; j++)
        {
            for (int c = 0; c < 3; c++)
            {
                mask.Clear();
                for (int i = 0; i < 4; i++)
                {
                    if (mds[i][j] == constants[c])
                    {
                        mask[i] = 0xFF;
                        mask[4 + i] = 0xFF;
                    }
                }

                result[j, c] = Vector128.Create<byte>(mask);
            }
        }

        return result;
    }

    /// <summary>Multiplication in GF(2^8) modulo the given polynomial, by shifts and masks.</summary>
    private static uint GfMul(uint a, uint b, uint polynomial)
    {
        uint result = 0;
        for (int i = 0; i < 8; i++)
        {
            result ^= a & (0u - ((b >> i) & 1));
            a = (a << 1) ^ (polynomial & (0u - (a >> 7)));
        }

        return result;
    }

    /// <summary>The S word of eight key bytes: the RS matrix times the bytes (paper section 4.3).</summary>
    private static uint ReedSolomon(ReadOnlySpan<byte> m)
    {
        ReadOnlySpan<byte> rs =
        [
            0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E,
            0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5,
            0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19,
            0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03,
        ];
        uint word = 0;
        for (int row = 0; row < 4; row++)
        {
            uint sum = 0;
            for (int col = 0; col < 8; col++)
            {
                sum ^= GfMul(m[col], rs[(8 * row) + col], RsPolynomial);
            }

            word |= sum << (8 * row);
        }

        return word;
    }

    // The first or second byte permutation on every byte of the vector, as the lanes of 'useSecond' say (paper section 4.3.5).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> Q(Vector128<byte> x, Vector128<byte> useSecond)
    {
        Vector128<byte> a = Vector128.ShiftRightLogical(x, 4);
        Vector128<byte> b = x & Nibble;
        Vector128<byte> a1 = a ^ b;
        Vector128<byte> b1 = a ^ RotateRight4(b) ^ ((a << 3) & Vector128.Create((byte)8));
        a = Table(0, a1, useSecond);
        b = Table(1, b1, useSecond);
        a1 = a ^ b;
        b1 = a ^ RotateRight4(b) ^ ((a << 3) & Vector128.Create((byte)8));
        a = Table(2, a1, useSecond);
        b = Table(3, b1, useSecond);
        return Vector128.ShiftLeft(b, 4) | a;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> RotateRight4(Vector128<byte> v) => (Vector128.ShiftRightLogical(v, 1) | (v << 3)) & Nibble;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> Table(int t, Vector128<byte> index, Vector128<byte> useSecond) =>
        Vector128.ConditionalSelect(useSecond, ByteShuffle.Lookup(PermB[t], index), ByteShuffle.Lookup(PermA[t], index));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> XTime(Vector128<byte> v) =>
        Vector128.ShiftLeft(v, 1) ^ (ReductionMds & Vector128.LessThan(v.AsSByte(), Vector128<sbyte>.Zero).AsByte());

    /// <summary>
    /// The h function of the paper (section 4.3.2) on the two halves of the vector, which hold a 32-bit word each as four bytes:
    /// the chain of byte permutations and key XORs, then the MDS matrix. <paramref name="keys"/> holds the list L, one 64-bit value
    /// per word, the low half's key word in the low 32 bits and the high half's in the high 32.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (uint Low, uint High) H(Vector128<byte> x, ReadOnlySpan<ulong> keys)
    {
        int k = keys.Length;
        for (int stage = k; stage >= 1; stage--)
        {
            x = Q(x, Patterns[stage]);
            x ^= Vector128.CreateScalar(keys[stage - 1]).AsByte();
        }

        x = Q(x, Patterns[0]);

        // Multiply by the MDS matrix over GF(2^8): per lane the products with 01, EF = 11101111b and 5B = 01011011b.
        Vector128<byte> x1 = XTime(x);
        Vector128<byte> x2 = XTime(x1);
        Vector128<byte> x3 = XTime(x2);
        Vector128<byte> x4 = XTime(x3);
        Vector128<byte> x5 = XTime(x4);
        Vector128<byte> x6 = XTime(x5);
        Vector128<byte> x7 = XTime(x6);
        Vector128<byte> ef = x ^ x1 ^ x2 ^ x3 ^ x5 ^ x6 ^ x7;
        Vector128<byte> b5 = x ^ x1 ^ x3 ^ x4 ^ x6;
        Vector128<byte> z = Vector128<byte>.Zero;
        for (int j = 0; j < 4; j++)
        {
            Vector128<byte> index = Broadcast[j];
            z ^= (Vector128.Shuffle(x, index) & MdsSelect[j, 0]) ^ (Vector128.Shuffle(ef, index) & MdsSelect[j, 1]) ^ (Vector128.Shuffle(b5, index) & MdsSelect[j, 2]);
        }

        ulong both = z.AsUInt64().ToScalar();
        return ((uint)both, (uint)(both >> 32));
    }

    // The two g functions of a round: g(r0) and g(ROL(r1, 8)), then the PHT and the round keys (paper sections 4.2 and 4.4).
    private (uint F0, uint F1) RoundF(uint r0, uint r1, int round)
    {
        Vector128<byte> x = Vector128.CreateScalar(r0 | ((ulong)uint.RotateLeft(r1, 8) << 32)).AsByte();
        (uint t0, uint t1) = H(x, _s);
        return (t0 + t1 + _k[(2 * round) + 8], t0 + (2 * t1) + _k[(2 * round) + 9]);
    }

    internal override void EncryptBlock(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        uint r0 = BinaryPrimitives.ReadUInt32LittleEndian(source) ^ _k[0];
        uint r1 = BinaryPrimitives.ReadUInt32LittleEndian(source[4..]) ^ _k[1];
        uint r2 = BinaryPrimitives.ReadUInt32LittleEndian(source[8..]) ^ _k[2];
        uint r3 = BinaryPrimitives.ReadUInt32LittleEndian(source[12..]) ^ _k[3];
        for (int round = 0; round < 16; round++)
        {
            (uint f0, uint f1) = RoundF(r0, r1, round);
            (r0, r1, r2, r3) = (uint.RotateRight(r2 ^ f0, 1), uint.RotateLeft(r3, 1) ^ f1, r0, r1);
        }

        // The output whitening undoes the last swap (paper section 4.1).
        BinaryPrimitives.WriteUInt32LittleEndian(destination, r2 ^ _k[4]);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[4..], r3 ^ _k[5]);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[8..], r0 ^ _k[6]);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[12..], r1 ^ _k[7]);
    }

    internal override void DecryptBlock(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        uint r2 = BinaryPrimitives.ReadUInt32LittleEndian(source) ^ _k[4];
        uint r3 = BinaryPrimitives.ReadUInt32LittleEndian(source[4..]) ^ _k[5];
        uint r0 = BinaryPrimitives.ReadUInt32LittleEndian(source[8..]) ^ _k[6];
        uint r1 = BinaryPrimitives.ReadUInt32LittleEndian(source[12..]) ^ _k[7];
        for (int round = 15; round >= 0; round--)
        {
            // Invert one round: the state after it is (ROR(r2 ^ F0, 1), ROL(r3, 1) ^ F1, r0, r1).
            (uint f0, uint f1) = RoundF(r2, r3, round);
            (r0, r1, r2, r3) = (r2, r3, uint.RotateLeft(r0, 1) ^ f0, uint.RotateRight(r1 ^ f1, 1));
        }

        BinaryPrimitives.WriteUInt32LittleEndian(destination, r0 ^ _k[0]);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[4..], r1 ^ _k[1]);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[8..], r2 ^ _k[2]);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[12..], r3 ^ _k[3]);
    }

    public override void Dispose()
    {
        WordWipe.Clear(_k);
        WordWipe.Clear(_s);
    }
}
