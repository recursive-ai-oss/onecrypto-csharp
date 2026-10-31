using System.Runtime.CompilerServices;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// Camellia (RFC 3713) with 128-, 192- and 256-bit keys.
/// </summary>
/// <remarks>
/// <para>Side channels: the cipher is built on an 8-bit S-box, and a plain table lookup would let a cache observer see which
/// entries a secret byte selects. Here the eight S-box lookups of an F-function are one vector operation: each input byte is split
/// into nibbles and every one of the sixteen 16-entry rows of the table is read through a byte shuffle, keeping the row the high
/// nibble selects by mask. No address, branch or loop bound depends on the data. The key schedule runs the same F-function, so it is
/// covered too. Without byte-shuffle hardware the same vector operations run in software.</para>
/// </remarks>
internal sealed class CamelliaEngine : BlockEngine
{
    private readonly ulong[] _encryptKeys;
    private readonly ulong[] _decryptKeys;

    // The sixteen rows of SBOX1, row h holding the outputs for inputs 16h to 16h+15.
    private static readonly Vector128<byte> Row0 = Row(0), Row1 = Row(1), Row2 = Row(2), Row3 = Row(3), Row4 = Row(4), Row5 = Row(5), Row6 = Row(6), Row7 = Row(7),
        Row8 = Row(8), Row9 = Row(9), Row10 = Row(10), Row11 = Row(11), Row12 = Row(12), Row13 = Row(13), Row14 = Row(14), Row15 = Row(15);

    // Lanes (t1..t8 are lanes 0..7) whose S-box is SBOX4, SBOX2 and SBOX3. SBOX2 = SBOX1 rotated left by one bit on the output,
    // SBOX3 the same rotated right, SBOX4 = SBOX1 of the input rotated left by one bit (RFC 3713 section 2.4.1).
    private static readonly Vector128<byte> InputRotate = Lanes(3, 6);
    private static readonly Vector128<byte> OutputLeft = Lanes(1, 4);
    private static readonly Vector128<byte> OutputRight = Lanes(2, 5);
    private static readonly Vector128<byte> LowNibble = Vector128.Create((byte)0x0F);

    // The P-function of section 2.4.1 as six shuffles: output byte j is the XOR of the six input lanes named by the j-th entry of
    // each shuffle. Rows with five terms use index 0x80, which a shuffle turns into zero.
    private static readonly Vector128<byte>[] MixBuilt = BuildMix();
    private static readonly Vector128<byte> Mix0 = MixBuilt[0], Mix1 = MixBuilt[1], Mix2 = MixBuilt[2], Mix3 = MixBuilt[3], Mix4 = MixBuilt[4], Mix5 = MixBuilt[5];

    internal CamelliaEngine(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new ArgumentException("A Camellia key is 16, 24 or 32 bytes.", nameof(key));
        }

        bool shortKey = key.Length == 16;
        int count = shortKey ? 26 : 34;
        _encryptKeys = GC.AllocateUninitializedArray<ulong>(count, pinned: true);
        _decryptKeys = GC.AllocateUninitializedArray<ulong>(count, pinned: true);
        Schedule(key, shortKey);
    }

    internal override int BlockSize => 16;

    private static Vector128<byte> Lanes(int a, int b)
    {
        Span<byte> bytes = stackalloc byte[16]; // fixed size
        bytes[a] = 0xFF;
        bytes[b] = 0xFF;
        return Vector128.Create<byte>(bytes);
    }

    private static Vector128<byte> Row(int h) => Vector128.Create(CamelliaTables.SBox1.Slice(h * 16, 16));

    private static Vector128<byte>[] BuildMix()
    {
        // y1..y8 in terms of t1..t8, zero-based lanes (RFC 3713 section 2.4.1).
        int[][] terms =
        [
            [0, 2, 3, 5, 6, 7],
            [0, 1, 3, 4, 6, 7],
            [0, 1, 2, 4, 5, 7],
            [1, 2, 3, 4, 5, 6],
            [0, 1, 5, 6, 7],
            [1, 2, 4, 6, 7],
            [2, 3, 4, 5, 7],
            [0, 3, 4, 5, 6],
        ];
        var mix = new Vector128<byte>[6];
        Span<byte> indices = stackalloc byte[16]; // fixed size
        for (int k = 0; k < 6; k++)
        {
            indices.Fill(0x80);
            for (int j = 0; j < 8; j++)
            {
                if (k < terms[j].Length)
                {
                    indices[j] = (byte)terms[j][k];
                }
            }

            mix[k] = Vector128.Create<byte>(indices);
        }

        return mix;
    }

    /// <summary>The F-function of RFC 3713 section 2.4.1, without data-dependent memory access.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ulong F(ulong input, ulong subkey)
    {
        ulong x = input ^ subkey;
        // Lane 0 holds t1 (the most significant byte of x) ... lane 7 holds t8.
        Vector128<byte> t = Vector128.CreateScalar(BinaryPrimitives.ReverseEndianness(x)).AsByte();
        Vector128<byte> rotated = Vector128.ShiftLeft(t, 1) | Vector128.ShiftRightLogical(t, 7);
        t = Vector128.ConditionalSelect(InputRotate, rotated, t);

        // SBOX1[t] for every lane. Split into nibbles; the low nibble indexes each of the sixteen rows through a byte shuffle, and the
        // four bits of the high nibble then pick one row's answer through a tree of blends (bit 4 picks within pairs of rows, bit 5
        // within pairs of pairs, and so on). Every row is read for every lane whatever the data.
        Vector128<byte> low = t & LowNibble;
        Vector128<byte> m4 = Vector128.LessThan(Vector128.ShiftLeft(t, 3).AsSByte(), Vector128<sbyte>.Zero).AsByte();
        Vector128<byte> m5 = Vector128.LessThan(Vector128.ShiftLeft(t, 2).AsSByte(), Vector128<sbyte>.Zero).AsByte();
        Vector128<byte> m6 = Vector128.LessThan(Vector128.ShiftLeft(t, 1).AsSByte(), Vector128<sbyte>.Zero).AsByte();
        Vector128<byte> m7 = Vector128.LessThan(t.AsSByte(), Vector128<sbyte>.Zero).AsByte();
        Vector128<byte> r0 = Vector128.ConditionalSelect(m4, ByteShuffle.Lookup(Row1, low), ByteShuffle.Lookup(Row0, low));
        Vector128<byte> r1 = Vector128.ConditionalSelect(m4, ByteShuffle.Lookup(Row3, low), ByteShuffle.Lookup(Row2, low));
        Vector128<byte> r2 = Vector128.ConditionalSelect(m4, ByteShuffle.Lookup(Row5, low), ByteShuffle.Lookup(Row4, low));
        Vector128<byte> r3 = Vector128.ConditionalSelect(m4, ByteShuffle.Lookup(Row7, low), ByteShuffle.Lookup(Row6, low));
        Vector128<byte> r4 = Vector128.ConditionalSelect(m4, ByteShuffle.Lookup(Row9, low), ByteShuffle.Lookup(Row8, low));
        Vector128<byte> r5 = Vector128.ConditionalSelect(m4, ByteShuffle.Lookup(Row11, low), ByteShuffle.Lookup(Row10, low));
        Vector128<byte> r6 = Vector128.ConditionalSelect(m4, ByteShuffle.Lookup(Row13, low), ByteShuffle.Lookup(Row12, low));
        Vector128<byte> r7 = Vector128.ConditionalSelect(m4, ByteShuffle.Lookup(Row15, low), ByteShuffle.Lookup(Row14, low));
        r0 = Vector128.ConditionalSelect(m5, r1, r0);
        r2 = Vector128.ConditionalSelect(m5, r3, r2);
        r4 = Vector128.ConditionalSelect(m5, r5, r4);
        r6 = Vector128.ConditionalSelect(m5, r7, r6);
        r0 = Vector128.ConditionalSelect(m6, r2, r0);
        r4 = Vector128.ConditionalSelect(m6, r6, r4);
        Vector128<byte> s = Vector128.ConditionalSelect(m7, r4, r0);

        Vector128<byte> left = Vector128.ShiftLeft(s, 1) | Vector128.ShiftRightLogical(s, 7);
        Vector128<byte> right = Vector128.ShiftRightLogical(s, 1) | Vector128.ShiftLeft(s, 7);
        s = Vector128.ConditionalSelect(OutputLeft, left, Vector128.ConditionalSelect(OutputRight, right, s));

        Vector128<byte> y = ByteShuffle.Lookup(s, Mix0) ^ ByteShuffle.Lookup(s, Mix1) ^ ByteShuffle.Lookup(s, Mix2)
            ^ ByteShuffle.Lookup(s, Mix3) ^ ByteShuffle.Lookup(s, Mix4) ^ ByteShuffle.Lookup(s, Mix5);
        return BinaryPrimitives.ReverseEndianness(y.AsUInt64().ToScalar());
    }

    private static ulong FL(ulong input, ulong subkey)
    {
        uint x1 = (uint)(input >> 32);
        uint x2 = (uint)input;
        uint k1 = (uint)(subkey >> 32);
        uint k2 = (uint)subkey;
        x2 ^= uint.RotateLeft(x1 & k1, 1);
        x1 ^= x2 | k2;
        return ((ulong)x1 << 32) | x2;
    }

    private static ulong FLInverse(ulong input, ulong subkey)
    {
        uint y1 = (uint)(input >> 32);
        uint y2 = (uint)input;
        uint k1 = (uint)(subkey >> 32);
        uint k2 = (uint)subkey;
        y1 ^= y2 | k2;
        y2 ^= uint.RotateLeft(y1 & k1, 1);
        return ((ulong)y1 << 32) | y2;
    }

    // The sources KL, KR, KA, KB of RFC 3713 section 2.2 as (high, low) halves of a 128-bit value.
    private static (ulong Hi, ulong Lo) Rotate(ulong hi, ulong lo, int bits)
    {
        if (bits >= 64)
        {
            (hi, lo) = (lo, hi);
            bits -= 64;
        }

        if (bits == 0)
        {
            return (hi, lo);
        }

        return ((hi << bits) | (lo >> (64 - bits)), (lo << bits) | (hi >> (64 - bits)));
    }

    private void Schedule(ReadOnlySpan<byte> key, bool shortKey)
    {
        ulong klHi = BinaryPrimitives.ReadUInt64BigEndian(key);
        ulong klLo = BinaryPrimitives.ReadUInt64BigEndian(key[8..]);
        ulong krHi = 0;
        ulong krLo = 0;
        if (key.Length == 24)
        {
            krHi = BinaryPrimitives.ReadUInt64BigEndian(key[16..]);
            krLo = ~krHi;
        }
        else if (key.Length == 32)
        {
            krHi = BinaryPrimitives.ReadUInt64BigEndian(key[16..]);
            krLo = BinaryPrimitives.ReadUInt64BigEndian(key[24..]);
        }

        // KA and KB (RFC 3713 section 2.2).
        ulong d1 = klHi ^ krHi;
        ulong d2 = klLo ^ krLo;
        d2 ^= F(d1, 0xA09E667F3BCC908B);
        d1 ^= F(d2, 0xB67AE8584CAA73B2);
        d1 ^= klHi;
        d2 ^= klLo;
        d2 ^= F(d1, 0xC6EF372FE94F82BE);
        d1 ^= F(d2, 0x54FF53A5F1D36F1C);
        ulong kaHi = d1;
        ulong kaLo = d2;
        d1 = kaHi ^ krHi;
        d2 = kaLo ^ krLo;
        d2 ^= F(d1, 0x10E527FADE682D1D);
        d1 ^= F(d2, 0xB05688C2B3E6C1FD);
        ulong kbHi = d1;
        ulong kbLo = d2;

        // Source codes: 0 KL, 1 KR, 2 KA, 3 KB. Each subkey is one half of a source rotated left (section 2.2), listed in the
        // order the data-randomizing part uses them: whitening, six rounds, FL keys, six rounds, ..., whitening.
        (int Source, int Rotation, int Half)[] plan = shortKey ? Plan128 : Plan256;
        for (int i = 0; i < plan.Length; i++)
        {
            (int source, int rotation, int half) = plan[i];
            (ulong hi, ulong lo) = source switch
            {
                0 => (klHi, klLo),
                1 => (krHi, krLo),
                2 => (kaHi, kaLo),
                _ => (kbHi, kbLo),
            };
            (hi, lo) = Rotate(hi, lo, rotation);
            _encryptKeys[i] = half == 0 ? hi : lo;
        }

        // Decryption is encryption with the subkeys in reverse (section 2.3.3): the whitening pairs swap ends and everything
        // between them is reversed.
        int n = _encryptKeys.Length;
        _decryptKeys[0] = _encryptKeys[n - 2];
        _decryptKeys[1] = _encryptKeys[n - 1];
        _decryptKeys[n - 2] = _encryptKeys[0];
        _decryptKeys[n - 1] = _encryptKeys[1];
        for (int i = 0; i < n - 4; i++)
        {
            _decryptKeys[2 + i] = _encryptKeys[n - 3 - i];
        }
    }

    private static readonly (int Source, int Rotation, int Half)[] Plan128 =
    [
        (0, 0, 0), (0, 0, 1), // kw1 kw2
        (2, 0, 0), (2, 0, 1), (0, 15, 0), (0, 15, 1), (2, 15, 0), (2, 15, 1), // k1..k6
        (2, 30, 0), (2, 30, 1), // ke1 ke2
        (0, 45, 0), (0, 45, 1), (2, 45, 0), (0, 60, 1), (2, 60, 0), (2, 60, 1), // k7..k12
        (0, 77, 0), (0, 77, 1), // ke3 ke4
        (0, 94, 0), (0, 94, 1), (2, 94, 0), (2, 94, 1), (0, 111, 0), (0, 111, 1), // k13..k18
        (2, 111, 0), (2, 111, 1), // kw3 kw4
    ];

    private static readonly (int Source, int Rotation, int Half)[] Plan256 =
    [
        (0, 0, 0), (0, 0, 1), // kw1 kw2
        (3, 0, 0), (3, 0, 1), (1, 15, 0), (1, 15, 1), (2, 15, 0), (2, 15, 1), // k1..k6
        (1, 30, 0), (1, 30, 1), // ke1 ke2
        (3, 30, 0), (3, 30, 1), (0, 45, 0), (0, 45, 1), (2, 45, 0), (2, 45, 1), // k7..k12
        (0, 60, 0), (0, 60, 1), // ke3 ke4
        (1, 60, 0), (1, 60, 1), (3, 60, 0), (3, 60, 1), (0, 77, 0), (0, 77, 1), // k13..k18
        (2, 77, 0), (2, 77, 1), // ke5 ke6
        (1, 94, 0), (1, 94, 1), (2, 94, 0), (2, 94, 1), (0, 111, 0), (0, 111, 1), // k19..k24
        (3, 111, 0), (3, 111, 1), // kw3 kw4
    ];

    private static void Crypt(ulong[] keys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        ulong d1 = BinaryPrimitives.ReadUInt64BigEndian(source) ^ keys[0];
        ulong d2 = BinaryPrimitives.ReadUInt64BigEndian(source[8..]) ^ keys[1];
        int p = 2;
        int groups = keys.Length == 26 ? 3 : 4; // 18 or 24 rounds, six per group (RFC 3713 section 2.3)
        for (int g = 0; g < groups; g++)
        {
            for (int r = 0; r < 3; r++)
            {
                d2 ^= F(d1, keys[p++]);
                d1 ^= F(d2, keys[p++]);
            }

            if (g < groups - 1)
            {
                d1 = FL(d1, keys[p++]);
                d2 = FLInverse(d2, keys[p++]);
            }
        }

        d2 ^= keys[p];
        d1 ^= keys[p + 1];
        BinaryPrimitives.WriteUInt64BigEndian(destination, d2);
        BinaryPrimitives.WriteUInt64BigEndian(destination[8..], d1);
    }

    internal override void EncryptBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Crypt(_encryptKeys, source, destination);

    internal override void DecryptBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Crypt(_decryptKeys, source, destination);

    public override void Dispose()
    {
        WordWipe.Clear(_encryptKeys);
        WordWipe.Clear(_decryptKeys);
    }
}
