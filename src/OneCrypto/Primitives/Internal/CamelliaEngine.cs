using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// Camellia (RFC 3713) with 128-, 192- and 256-bit keys.
/// </summary>
/// <remarks>
/// <para>Side channels: the cipher is built on an 8-bit S-box, and a plain table lookup would let a cache observer see which
/// entries a secret byte selects. The F-function here is one vector operation on the eight S-box bytes, and no address, branch or
/// loop bound depends on the data; the key schedule runs the same F-function, so it is covered too.</para>
/// <para>Two ways to evaluate the S-box, with identical results (a test compares them on every input):
/// where the processor has AES instructions, SBOX1 is an affine transformation of the AES S-box (see docs/legacy-ciphers.md for the
/// derivation), so one AES round instruction with a zero key does the substitution between two affine maps done as nibble shuffles;
/// otherwise every one of the sixteen 16-entry rows of the table is read through a byte shuffle and the high nibble selects a row
/// through a tree of blends.</para>
/// <para>A vector holds the eight S-box bytes of two blocks (lanes 0 to 7 and 8 to 15), so the modes that can work on two blocks
/// at once (ECB, CBC decryption) use <see cref="EncryptTwoBlocks"/> and <see cref="DecryptTwoBlocks"/>.</para>
/// </remarks>
internal sealed class CamelliaEngine : BlockEngine
{
    private readonly ulong[] _encryptKeys;
    private readonly ulong[] _decryptKeys;
    private readonly bool _aes;

    // The same subkeys as byte vectors in F's lane order, both halves alike, so a round's key XOR is one load.
    private readonly Vector128<byte>[] _encryptVectors;
    private readonly Vector128<byte>[] _decryptVectors;

    // The sixteen rows of SBOX1, row h holding the outputs for inputs 16h to 16h+15.
    private static readonly Vector128<byte> Row0 = Row(0), Row1 = Row(1), Row2 = Row(2), Row3 = Row(3), Row4 = Row(4), Row5 = Row(5), Row6 = Row(6), Row7 = Row(7),
        Row8 = Row(8), Row9 = Row(9), Row10 = Row(10), Row11 = Row(11), Row12 = Row(12), Row13 = Row(13), Row14 = Row(14), Row15 = Row(15);

    private static readonly Vector128<byte> LowNibble = Vector128.Create((byte)0x0F);

    // Lanes (t1..t8 are lanes 0..7, and 8..15 for a second block) whose S-box is SBOX4 (rotate the input left by one bit), SBOX2
    // (rotate the output left) and SBOX3 (rotate the output right), RFC 3713 section 2.4.1. Natural lane order, and the order the AES
    // instruction leaves them in (its ShiftRows step moves lane j to lane AesLane(j)).
    private static readonly Vector128<byte> InputRotate = Lanes(false, 3, 6);
    private static readonly Vector128<byte> OutputLeft = Lanes(false, 1, 4);
    private static readonly Vector128<byte> OutputRight = Lanes(false, 2, 5);
    private static readonly Vector128<byte> OutputLeftAes = Lanes(true, 1, 4);
    private static readonly Vector128<byte> OutputRightAes = Lanes(true, 2, 5);

    // The P-function of section 2.4.1 as six shuffles: output byte j is the XOR of the six input lanes named by the j-th entry of
    // each shuffle. Rows with five terms use index 0x80, which a shuffle turns into zero.
    private static readonly Vector128<byte>[] MixBuilt = BuildMix(false);
    private static readonly Vector128<byte> Mix0 = MixBuilt[0], Mix1 = MixBuilt[1], Mix2 = MixBuilt[2], Mix3 = MixBuilt[3], Mix4 = MixBuilt[4], Mix5 = MixBuilt[5];
    private static readonly Vector128<byte>[] MixAesBuilt = BuildMix(true);
    private static readonly Vector128<byte> MixA0 = MixAesBuilt[0], MixA1 = MixAesBuilt[1], MixA2 = MixAesBuilt[2], MixA3 = MixAesBuilt[3], MixA4 = MixAesBuilt[4], MixA5 = MixAesBuilt[5];

    // The affine maps around the AES S-box, as nibble tables (low-nibble table includes the constant). Built once from SBOX1 and the
    // AES S-box, so nothing here is typed in by hand but the pre-map P and its constant.
    private static readonly Vector128<byte> PreLo, PreHi, PostLo, PostHi;

    static CamelliaEngine()
    {
        // SBOX1(x) = M2 * Inv(P x ^ 8) ^ 0x6E with Inv the inversion in the AES field (docs/legacy-ciphers.md); P's columns:
        ReadOnlySpan<byte> pColumns = [1, 25, 177, 171, 167, 147, 97, 217];
        Span<byte> preLo = stackalloc byte[16]; // fixed size
        Span<byte> preHi = stackalloc byte[16];
        for (int n = 0; n < 16; n++)
        {
            preLo[n] = (byte)(Apply(pColumns, n) ^ 8);
            preHi[n] = Apply(pColumns, n << 4);
        }

        PreLo = Vector128.Create<byte>(preLo);
        PreHi = Vector128.Create<byte>(preHi);

        // v -> SBOX1(x) where AES(P x ^ 8) = v is affine in v; read its matrix and constant off the 256 values.
        ReadOnlySpan<byte> sbox1 = CamelliaTables.SBox1;
        Span<byte> after = stackalloc byte[256];
        for (int x = 0; x < 256; x++)
        {
            after[AesSBox((byte)(Apply(pColumns, x) ^ 8))] = sbox1[x];
        }

        // after(v) = L(v) ^ c with L linear, so L(lo | hi << 4) ^ c = after(lo) ^ after(hi << 4) ^ c: the constant goes into the high table.
        byte constant = after[0];
        Span<byte> postLo = stackalloc byte[16];
        Span<byte> postHi = stackalloc byte[16];
        for (int n = 0; n < 16; n++)
        {
            postLo[n] = after[n];
            postHi[n] = (byte)(after[n << 4] ^ constant);
        }

        PostLo = Vector128.Create<byte>(postLo);
        PostHi = Vector128.Create<byte>(postHi);
    }

    private static byte Apply(ReadOnlySpan<byte> columns, int x)
    {
        int result = 0;
        for (int i = 0; i < 8; i++)
        {
            result ^= columns[i] & -((x >> i) & 1);
        }

        return (byte)result;
    }

    // The AES S-box from its definition (inversion in GF(2^8) modulo x^8+x^4+x^3+x+1, then the affine map), used only at start-up on
    // public constants to build tables.
    private static byte AesSBox(byte x)
    {
        int inverse = 0;
        if (x != 0)
        {
            for (int c = 1; c < 256; c++)
            {
                int product = 0;
                int a = x;
                for (int bit = 0; bit < 8; bit++)
                {
                    if (((c >> bit) & 1) != 0)
                    {
                        product ^= a;
                    }

                    a = (a << 1) ^ ((a & 0x80) != 0 ? 0x11B : 0);
                }

                if (product == 1)
                {
                    inverse = c;
                    break;
                }
            }
        }

        int b = inverse;
        int r = b ^ (((b << 1) | (b >> 7)) & 0xFF) ^ (((b << 2) | (b >> 6)) & 0xFF) ^ (((b << 3) | (b >> 5)) & 0xFF) ^ (((b << 4) | (b >> 4)) & 0xFF) ^ 0x63;
        return (byte)r;
    }

    internal CamelliaEngine(ReadOnlySpan<byte> key, bool allowAesInstructions = true)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new ArgumentException("A Camellia key is 16, 24 or 32 bytes.", nameof(key));
        }

        _aes = allowAesInstructions && ByteShuffle.HasAesRound;
        bool shortKey = key.Length == 16;
        int count = shortKey ? 26 : 34;
        _encryptKeys = GC.AllocateUninitializedArray<ulong>(count, pinned: true);
        _decryptKeys = GC.AllocateUninitializedArray<ulong>(count, pinned: true);
        _encryptVectors = GC.AllocateUninitializedArray<Vector128<byte>>(count, pinned: true);
        _decryptVectors = GC.AllocateUninitializedArray<Vector128<byte>>(count, pinned: true);
        Schedule(key, shortKey);
        for (int i = 0; i < count; i++)
        {
            _encryptVectors[i] = Vector128.Create(BinaryPrimitives.ReverseEndianness(_encryptKeys[i])).AsByte();
            _decryptVectors[i] = Vector128.Create(BinaryPrimitives.ReverseEndianness(_decryptKeys[i])).AsByte();
        }
    }

    internal override int BlockSize => 16;

    // Where the AES instruction's ShiftRows step puts lane j of its input: state byte 4c+r moves to 4((c-r) mod 4)+r.
    private static int AesLane(int j) => (((j - (4 * (j % 4))) % 16) + 16) % 16;

    private static Vector128<byte> Lanes(bool aes, int a, int b)
    {
        Span<byte> bytes = stackalloc byte[16]; // fixed size
        foreach (int j in new[] { a, b, a + 8, b + 8 })
        {
            bytes[aes ? AesLane(j) : j] = 0xFF;
        }

        return Vector128.Create<byte>(bytes);
    }

    private static Vector128<byte> Row(int h) => Vector128.Create(CamelliaTables.SBox1.Slice(h * 16, 16));

    private static Vector128<byte>[] BuildMix(bool aes)
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
                    int lower = terms[j][k];
                    indices[j] = (byte)(aes ? AesLane(lower) : lower);
                    indices[8 + j] = (byte)(aes ? AesLane(8 + lower) : 8 + lower);
                }
            }

            mix[k] = Vector128.Create<byte>(indices);
        }

        return mix;
    }

    private static Vector128<byte> RotateLeft1(Vector128<byte> v) => Vector128.ShiftLeft(v, 1) | Vector128.ShiftRightLogical(v, 7);

    private static Vector128<byte> RotateRight1(Vector128<byte> v) => Vector128.ShiftRightLogical(v, 1) | Vector128.ShiftLeft(v, 7);

    /// <summary>
    /// The F-function of RFC 3713 section 2.4.1 without data-dependent memory access, on values already XORed with their subkeys.
    /// Lane 0 holds t1 (the most significant byte) and lane 7 holds t8; lanes 8 to 15 hold the same for a second block. The result
    /// has the same layout.
    /// </summary>
    private Vector128<byte> F(Vector128<byte> t)
    {
        t = Vector128.ConditionalSelect(InputRotate, RotateLeft1(t), t);
        Vector128<byte> y;
        if (_aes)
        {
            // y = P t ^ 8 as two nibble lookups, the AES S-box through one round instruction with a zero key (SubBytes and
            // ShiftRows; lane j lands in lane AesLane(j)), then the post map as two more nibble lookups.
            Vector128<byte> pre = ByteShuffle.Lookup(PreLo, t & LowNibble) ^ ByteShuffle.Lookup(PreHi, Vector128.ShiftRightLogical(t, 4));
            Vector128<byte> sub = ByteShuffle.AesRound(pre);
            Vector128<byte> post = ByteShuffle.Lookup(PostLo, sub & LowNibble) ^ ByteShuffle.Lookup(PostHi, Vector128.ShiftRightLogical(sub, 4));
            post = Vector128.ConditionalSelect(OutputLeftAes, RotateLeft1(post), Vector128.ConditionalSelect(OutputRightAes, RotateRight1(post), post));
            y = ByteShuffle.Lookup(post, MixA0) ^ ByteShuffle.Lookup(post, MixA1) ^ ByteShuffle.Lookup(post, MixA2)
                ^ ByteShuffle.Lookup(post, MixA3) ^ ByteShuffle.Lookup(post, MixA4) ^ ByteShuffle.Lookup(post, MixA5);
            return y;
        }

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

        Vector128<byte> sh = s;
        sh = Vector128.ConditionalSelect(OutputLeft, RotateLeft1(sh), Vector128.ConditionalSelect(OutputRight, RotateRight1(sh), sh));
        y = ByteShuffle.Lookup(sh, Mix0) ^ ByteShuffle.Lookup(sh, Mix1) ^ ByteShuffle.Lookup(sh, Mix2)
            ^ ByteShuffle.Lookup(sh, Mix3) ^ ByteShuffle.Lookup(sh, Mix4) ^ ByteShuffle.Lookup(sh, Mix5);
        return y;
    }

    private static Vector128<byte> Lane(ulong value) => Vector128.CreateScalar(BinaryPrimitives.ReverseEndianness(value)).AsByte();

    private static Vector128<byte> Pair(ulong first, ulong second) => Vector128.Create(BinaryPrimitives.ReverseEndianness(first), BinaryPrimitives.ReverseEndianness(second)).AsByte();

    private static ulong Number(Vector128<byte> lanes, int half) => BinaryPrimitives.ReverseEndianness(lanes.AsUInt64().GetElement(half));

    /// <summary>The F-function on numbers, for the key schedule.</summary>
    private ulong F(ulong input, ulong subkey) => Number(F(Lane(input ^ subkey)), 0);

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

    // Encrypts or decrypts two blocks at once (they may be the same block twice): the Feistel halves of both blocks live in one vector
    // each, in the layout F uses, so one F call serves both.
    private void Crypt(ulong[] keys, Vector128<byte>[] vectors, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, Span<byte> firstOut, Span<byte> secondOut, bool both)
    {
        Vector128<byte> d1 = Pair(BinaryPrimitives.ReadUInt64BigEndian(first) ^ keys[0], BinaryPrimitives.ReadUInt64BigEndian(second) ^ keys[0]);
        Vector128<byte> d2 = Pair(BinaryPrimitives.ReadUInt64BigEndian(first[8..]) ^ keys[1], BinaryPrimitives.ReadUInt64BigEndian(second[8..]) ^ keys[1]);
        int p = 2;
        int groups = keys.Length == 26 ? 3 : 4; // 18 or 24 rounds, six per group (RFC 3713 section 2.3)
        for (int g = 0; g < groups; g++)
        {
            for (int r = 0; r < 3; r++)
            {
                d2 ^= F(d1 ^ vectors[p++]);
                d1 ^= F(d2 ^ vectors[p++]);
            }

            if (g < groups - 1)
            {
                ulong ke1 = keys[p++];
                ulong ke2 = keys[p++];
                d1 = Pair(FL(Number(d1, 0), ke1), FL(Number(d1, 1), ke1));
                d2 = Pair(FLInverse(Number(d2, 0), ke2), FLInverse(Number(d2, 1), ke2));
            }
        }

        BinaryPrimitives.WriteUInt64BigEndian(firstOut, Number(d2, 0) ^ keys[p]);
        BinaryPrimitives.WriteUInt64BigEndian(firstOut[8..], Number(d1, 0) ^ keys[p + 1]);
        if (both)
        {
            BinaryPrimitives.WriteUInt64BigEndian(secondOut, Number(d2, 1) ^ keys[p]);
            BinaryPrimitives.WriteUInt64BigEndian(secondOut[8..], Number(d1, 1) ^ keys[p + 1]);
        }
    }

    internal override void EncryptBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Crypt(_encryptKeys, _encryptVectors, source, source, destination, default, false);

    internal override void DecryptBlock(ReadOnlySpan<byte> source, Span<byte> destination) => Crypt(_decryptKeys, _decryptVectors, source, source, destination, default, false);

    internal override void EncryptTwoBlocks(ReadOnlySpan<byte> source, Span<byte> destination) =>
        Crypt(_encryptKeys, _encryptVectors, source[..16], source.Slice(16, 16), destination[..16], destination.Slice(16, 16), true);

    internal override void DecryptTwoBlocks(ReadOnlySpan<byte> source, Span<byte> destination) =>
        Crypt(_decryptKeys, _decryptVectors, source[..16], source.Slice(16, 16), destination[..16], destination.Slice(16, 16), true);

    public override void Dispose()
    {
        WordWipe.Clear(_encryptKeys);
        WordWipe.Clear(_decryptKeys);
        Array.Clear(_encryptVectors);
        Array.Clear(_decryptVectors);
    }
}
