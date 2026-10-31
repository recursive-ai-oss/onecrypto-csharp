using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Primitives.Fallback;

/// <summary>
/// ChaCha20-Poly1305 (RFC 8439), used only where the platform has none. Constant time by construction: ChaCha20 is add, rotate and
/// xor on 32-bit words, and Poly1305 is fixed-width limb arithmetic with explicit carries and a masked final reduction. No branch,
/// index or loop bound depends on the key, the nonce or the data; only the message and associated-data lengths, which are public,
/// decide the number of blocks. The tag is compared with <see cref="CryptographicOperations.FixedTimeEquals"/> after the whole
/// computation, and no plaintext is produced for a message whose tag does not match.
/// </summary>
internal static class ChaCha20Poly1305Managed
{
    internal const int KeySize = 32;
    internal const int NonceSize = 12;
    internal const int TagSize = 16;

    /// <summary>Encrypts and authenticates (RFC 8439 section 2.8).</summary>
    /// <param name="key">32 bytes.</param>
    /// <param name="nonce">12 bytes; never reuse one under a key.</param>
    /// <param name="plaintext">The message.</param>
    /// <param name="ciphertext">Receives the same number of bytes; may be the same buffer as the plaintext.</param>
    /// <param name="tag">Receives the 16-byte tag.</param>
    /// <param name="aad">Associated data, authenticated and not encrypted.</param>
    public static void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> aad)
    {
        Check(key, nonce, plaintext.Length, ciphertext.Length, tag.Length);
        Span<byte> polyKey = stackalloc byte[64]; // one ChaCha20 block, fixed size
        Block(key, 0, nonce, polyKey);
        Xor(key, nonce, plaintext, ciphertext);
        Authenticate(polyKey[..32], aad, ciphertext, tag);
        polyKey.Clear();
    }

    /// <summary>Verifies the tag, then decrypts (RFC 8439 section 2.8). Nothing is decrypted when the tag is wrong.</summary>
    /// <returns>False when authentication fails; <paramref name="plaintext"/> is then zeroed.</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        Check(key, nonce, ciphertext.Length, plaintext.Length, tag.Length);
        Span<byte> polyKey = stackalloc byte[64]; // fixed size
        Span<byte> expected = stackalloc byte[TagSize];
        Block(key, 0, nonce, polyKey);
        Authenticate(polyKey[..32], aad, ciphertext, expected);
        polyKey.Clear();
        bool ok = CryptographicOperations.FixedTimeEquals(expected, tag);
        if (!ok)
        {
            plaintext.Clear();
            return false;
        }

        Xor(key, nonce, ciphertext, plaintext);
        return true;
    }

    /// <summary>Poly1305 alone (RFC 8439 section 2.5) with a one-time key, so the RFC's own test vectors can be checked.</summary>
    internal static byte[] Poly1305Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        Span<byte> buffer = stackalloc byte[16]; // fixed size
        var mac = new Poly1305(key, buffer);
        mac.Update(message);
        byte[] tag = new byte[TagSize];
        mac.Finish(tag);
        return tag;
    }

    private static void Check(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, int inLength, int outLength, int tagLength)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException("The key must be 32 bytes.", nameof(key));
        }

        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException("The nonce must be 12 bytes.", nameof(nonce));
        }

        if (tagLength != TagSize)
        {
            throw new ArgumentException("The tag must be 16 bytes.");
        }

        if (outLength != inLength)
        {
            throw new ArgumentException("The output must be as long as the input.");
        }
    }

    // RFC 8439 section 2.8: the Poly1305 input is aad, padding to 16, ciphertext, padding to 16, then both lengths as 64-bit little-endian.
    private static void Authenticate(ReadOnlySpan<byte> polyKey, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, Span<byte> tag)
    {
        Span<byte> buffer = stackalloc byte[16]; // fixed size
        var mac = new Poly1305(polyKey, buffer);
        mac.Update(aad);
        mac.PadTo16(aad.Length);
        mac.Update(ciphertext);
        mac.PadTo16(ciphertext.Length);
        Span<byte> lengths = stackalloc byte[16]; // fixed size
        BinaryPrimitives.WriteUInt64LittleEndian(lengths, (ulong)aad.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)ciphertext.Length);
        mac.Update(lengths);
        mac.Finish(tag);
        buffer.Clear();
    }

    // ChaCha20 encryption with the block counter starting at 1 (RFC 8439 section 2.4); the counter is public.
    private static void Xor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> stream = stackalloc byte[64]; // fixed size
        uint counter = 1;
        int offset = 0;
        while (offset < input.Length)
        {
            Block(key, counter, nonce, stream);
            int n = Math.Min(64, input.Length - offset);
            for (int i = 0; i < n; i++)
            {
                output[offset + i] = (byte)(input[offset + i] ^ stream[i]);
            }

            offset += n;
            counter++;
        }

        stream.Clear();
    }

    /// <summary>The ChaCha20 block function (RFC 8439 section 2.3): 20 rounds, then the input added back.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)] // kept separate so its compiled form can be inspected
    internal static void Block(ReadOnlySpan<byte> key, uint counter, ReadOnlySpan<byte> nonce, Span<byte> output)
    {
        Span<uint> s = stackalloc uint[16]; // fixed size
        s[0] = 0x61707865;
        s[1] = 0x3320646e;
        s[2] = 0x79622d32;
        s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++)
        {
            s[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(4 * i)..]);
        }

        s[12] = counter;
        s[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce);
        s[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[4..]);
        s[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[8..]);

        uint x0 = s[0], x1 = s[1], x2 = s[2], x3 = s[3], x4 = s[4], x5 = s[5], x6 = s[6], x7 = s[7];
        uint x8 = s[8], x9 = s[9], x10 = s[10], x11 = s[11], x12 = s[12], x13 = s[13], x14 = s[14], x15 = s[15];
        for (int round = 0; round < 10; round++)
        {
            QuarterRound(ref x0, ref x4, ref x8, ref x12);
            QuarterRound(ref x1, ref x5, ref x9, ref x13);
            QuarterRound(ref x2, ref x6, ref x10, ref x14);
            QuarterRound(ref x3, ref x7, ref x11, ref x15);
            QuarterRound(ref x0, ref x5, ref x10, ref x15);
            QuarterRound(ref x1, ref x6, ref x11, ref x12);
            QuarterRound(ref x2, ref x7, ref x8, ref x13);
            QuarterRound(ref x3, ref x4, ref x9, ref x14);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(output, x0 + s[0]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[4..], x1 + s[1]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[8..], x2 + s[2]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[12..], x3 + s[3]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[16..], x4 + s[4]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[20..], x5 + s[5]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[24..], x6 + s[6]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[28..], x7 + s[7]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[32..], x8 + s[8]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[36..], x9 + s[9]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[40..], x10 + s[10]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[44..], x11 + s[11]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[48..], x12 + s[12]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[52..], x13 + s[13]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[56..], x14 + s[14]);
        BinaryPrimitives.WriteUInt32LittleEndian(output[60..], x15 + s[15]);
        s.Clear();
    }

    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b;
        d = uint.RotateLeft(d ^ a, 16);
        c += d;
        b = uint.RotateLeft(b ^ c, 12);
        a += b;
        d = uint.RotateLeft(d ^ a, 8);
        c += d;
        b = uint.RotateLeft(b ^ c, 7);
    }

    /// <summary>
    /// Poly1305 (RFC 8439 section 2.5) in radix 2^26: five limbs whose products fit 64 bits, so the 130-bit accumulator never
    /// needs a carry out of a machine word. The key is one-time (the first 32 bytes of ChaCha20 block 0).
    /// </summary>
    private ref struct Poly1305
    {
        private const ulong Mask = 0x3ffffff;
        private const ulong FullBlockBit = 1UL << 24; // 2^128 in limb 4 (limb 4 starts at bit 104)

        private readonly ulong _r0, _r1, _r2, _r3, _r4;
        private readonly ulong _padLow, _padHigh;
        private readonly Span<byte> _partial; // the caller's 16-byte buffer for an unfinished block
        private ulong _h0, _h1, _h2, _h3, _h4;
        private int _buffered;

        public Poly1305(ReadOnlySpan<byte> key, Span<byte> buffer)
        {
            // Clamp r (section 2.5.1) and split it into 26-bit limbs.
            ulong t0 = BinaryPrimitives.ReadUInt32LittleEndian(key);
            ulong t1 = BinaryPrimitives.ReadUInt32LittleEndian(key[3..]);
            ulong t2 = BinaryPrimitives.ReadUInt32LittleEndian(key[6..]);
            ulong t3 = BinaryPrimitives.ReadUInt32LittleEndian(key[9..]);
            ulong t4 = BinaryPrimitives.ReadUInt32LittleEndian(key[12..]);
            _r0 = t0 & 0x3ffffff;
            _r1 = (t1 >> 2) & 0x3ffff03;
            _r2 = (t2 >> 4) & 0x3ffc0ff;
            _r3 = (t3 >> 6) & 0x3f03fff;
            _r4 = (t4 >> 8) & 0x00fffff;
            _padLow = BinaryPrimitives.ReadUInt64LittleEndian(key[16..]);
            _padHigh = BinaryPrimitives.ReadUInt64LittleEndian(key[24..]);
            _h0 = _h1 = _h2 = _h3 = _h4 = 0;
            _partial = buffer;
            _buffered = 0;
        }

        public void Update(scoped ReadOnlySpan<byte> data)
        {
            while (data.Length > 0)
            {
                if (_buffered == 0 && data.Length >= 16)
                {
                    Block(data[..16], FullBlockBit);
                    data = data[16..];
                    continue;
                }

                int n = Math.Min(16 - _buffered, data.Length);
                data[..n].CopyTo(_partial[_buffered..]);
                _buffered += n;
                data = data[n..];
                if (_buffered == 16)
                {
                    Block(_partial, FullBlockBit);
                    _buffered = 0;
                }
            }
        }

        /// <summary>Zero-pads what has been fed so far to a multiple of 16 bytes; <paramref name="fed"/> is its length.</summary>
        public void PadTo16(int fed)
        {
            int pad = (16 - (fed & 15)) & 15;
            if (pad > 0)
            {
                Span<byte> zeros = stackalloc byte[16]; // fixed size
                zeros.Clear();
                Update(zeros[..pad]);
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)] // kept separate so its compiled form can be inspected
        public void Finish(Span<byte> tag)
        {
            if (_buffered > 0)
            {
                // A last block shorter than 16 bytes gets a 1 byte after it and no extra bit (section 2.5.1).
                _partial[_buffered] = 1;
                _partial[(_buffered + 1)..].Clear();
                Block(_partial, 0);
            }

            ulong h0 = _h0, h1 = _h1, h2 = _h2, h3 = _h3, h4 = _h4;
            ulong c = h1 >> 26; h1 &= Mask; h2 += c;
            c = h2 >> 26; h2 &= Mask; h3 += c;
            c = h3 >> 26; h3 &= Mask; h4 += c;
            c = h4 >> 26; h4 &= Mask; h0 += c * 5;
            c = h0 >> 26; h0 &= Mask; h1 += c;
            c = h1 >> 26; h1 &= Mask; h2 += c;
            c = h2 >> 26; h2 &= Mask; h3 += c;
            c = h3 >> 26; h3 &= Mask; h4 += c;
            c = h4 >> 26; h4 &= Mask; h0 += c * 5;
            c = h0 >> 26; h0 &= Mask; h1 += c;

            // g = h + 5 - 2^130; h is already reduced iff g went negative. The select is a mask, not a branch.
            ulong g0 = h0 + 5;
            c = g0 >> 26; g0 &= Mask;
            ulong g1 = h1 + c; c = g1 >> 26; g1 &= Mask;
            ulong g2 = h2 + c; c = g2 >> 26; g2 &= Mask;
            ulong g3 = h3 + c; c = g3 >> 26; g3 &= Mask;
            ulong g4 = h4 + c - (1UL << 26);
            ulong useG = (g4 >> 63) - 1; // all ones when g is non-negative, i.e. h >= 2^130 - 5
            g4 &= Mask;
            ulong keep = ~useG;
            h0 = (h0 & keep) | (g0 & useG);
            h1 = (h1 & keep) | (g1 & useG);
            h2 = (h2 & keep) | (g2 & useG);
            h3 = (h3 & keep) | (g3 & useG);
            h4 = (h4 & keep) | (g4 & useG);

            // (h + s) mod 2^128, s being the second half of the key.
            UInt128 h = (UInt128)h0 | ((UInt128)h1 << 26) | ((UInt128)h2 << 52) | ((UInt128)h3 << 78) | ((UInt128)h4 << 104);
            UInt128 s = ((UInt128)_padHigh << 64) | _padLow;
            UInt128 sum = h + s;
            BinaryPrimitives.WriteUInt64LittleEndian(tag, (ulong)sum);
            BinaryPrimitives.WriteUInt64LittleEndian(tag[8..], (ulong)(sum >> 64));
        }

        // h = (h + block) * r mod 2^130 - 5.
        [MethodImpl(MethodImplOptions.NoInlining)] // kept separate so its compiled form can be inspected
        private void Block(scoped ReadOnlySpan<byte> m, ulong hibit)
        {
            ulong t0 = BinaryPrimitives.ReadUInt32LittleEndian(m);
            ulong t1 = BinaryPrimitives.ReadUInt32LittleEndian(m[3..]);
            ulong t2 = BinaryPrimitives.ReadUInt32LittleEndian(m[6..]);
            ulong t3 = BinaryPrimitives.ReadUInt32LittleEndian(m[9..]);
            ulong t4 = BinaryPrimitives.ReadUInt32LittleEndian(m[12..]);
            ulong h0 = _h0 + (t0 & Mask);
            ulong h1 = _h1 + ((t1 >> 2) & Mask);
            ulong h2 = _h2 + ((t2 >> 4) & Mask);
            ulong h3 = _h3 + ((t3 >> 6) & Mask);
            ulong h4 = _h4 + ((t4 >> 8) | hibit);

            // 2^130 = 5 mod p, so limbs that overflow past limb 4 fold back multiplied by 5.
            ulong s1 = _r1 * 5, s2 = _r2 * 5, s3 = _r3 * 5, s4 = _r4 * 5;
            ulong d0 = (h0 * _r0) + (h1 * s4) + (h2 * s3) + (h3 * s2) + (h4 * s1);
            ulong d1 = (h0 * _r1) + (h1 * _r0) + (h2 * s4) + (h3 * s3) + (h4 * s2);
            ulong d2 = (h0 * _r2) + (h1 * _r1) + (h2 * _r0) + (h3 * s4) + (h4 * s3);
            ulong d3 = (h0 * _r3) + (h1 * _r2) + (h2 * _r1) + (h3 * _r0) + (h4 * s4);
            ulong d4 = (h0 * _r4) + (h1 * _r3) + (h2 * _r2) + (h3 * _r1) + (h4 * _r0);

            ulong c = d0 >> 26; h0 = d0 & Mask;
            d1 += c; c = d1 >> 26; h1 = d1 & Mask;
            d2 += c; c = d2 >> 26; h2 = d2 & Mask;
            d3 += c; c = d3 >> 26; h3 = d3 & Mask;
            d4 += c; c = d4 >> 26; h4 = d4 & Mask;
            h0 += c * 5; c = h0 >> 26; h0 &= Mask;
            h1 += c;
            _h0 = h0; _h1 = h1; _h2 = h2; _h3 = h3; _h4 = h4;
        }
    }
}
