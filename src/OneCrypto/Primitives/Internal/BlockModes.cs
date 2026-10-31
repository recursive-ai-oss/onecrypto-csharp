using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// ECB, CBC and CFB over a <see cref="BlockEngine"/>, with span in and span out. Buffers may be the same span (in place) or must not
/// overlap. No call allocates: the chaining registers are fixed-size stack buffers.
/// </summary>
internal static class BlockModes
{
    // The largest block any engine here has. Every stackalloc below is this size, a constant, so none can overflow the stack.
    private const int MaxBlock = 16;

    /// <summary>Rejects partly overlapping buffers: exact overlap (in place) is fine, anything else would corrupt the chain.</summary>
    internal static void CheckOverlap(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.Overlaps(destination, out int offset) && offset != 0)
        {
            throw new ArgumentException("The destination may be the source span (in place) or a span that does not overlap it.", nameof(destination));
        }
    }

    private static void CheckIv(BlockEngine engine, ReadOnlySpan<byte> iv)
    {
        if (iv.Length != engine.BlockSize)
        {
            throw new ArgumentException($"The IV must be {engine.BlockSize} bytes.", nameof(iv));
        }
    }

    private static void CheckWhole(BlockEngine engine, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.Length % engine.BlockSize != 0)
        {
            throw new ArgumentException($"The length must be a multiple of the {engine.BlockSize}-byte block size.", nameof(source));
        }

        if (destination.Length < source.Length)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }

        CheckOverlap(source, destination);
    }

    internal static void Ecb(BlockEngine engine, bool decrypt, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        CheckWhole(engine, source, destination);
        int bs = engine.BlockSize;
        for (int i = 0; i < source.Length; i += bs)
        {
            if (decrypt)
            {
                engine.DecryptBlock(source.Slice(i, bs), destination.Slice(i, bs));
            }
            else
            {
                engine.EncryptBlock(source.Slice(i, bs), destination.Slice(i, bs));
            }
        }
    }

    /// <summary>CBC encryption of whole blocks, no padding.</summary>
    private static void CbcEncryptBlocks(BlockEngine engine, ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        int bs = engine.BlockSize;
        Span<byte> chain = stackalloc byte[MaxBlock];
        Span<byte> block = stackalloc byte[MaxBlock];
        iv.CopyTo(chain);
        for (int i = 0; i < source.Length; i += bs)
        {
            for (int j = 0; j < bs; j++)
            {
                block[j] = (byte)(source[i + j] ^ chain[j]);
            }

            engine.EncryptBlock(block[..bs], destination.Slice(i, bs));
            destination.Slice(i, bs).CopyTo(chain);
        }

        CryptographicOperations.ZeroMemory(block);
        CryptographicOperations.ZeroMemory(chain);
    }

    /// <summary>CBC decryption of whole blocks, no padding. Works in place: each ciphertext block is saved before it is overwritten.</summary>
    private static void CbcDecryptBlocks(BlockEngine engine, ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        int bs = engine.BlockSize;
        Span<byte> chain = stackalloc byte[MaxBlock];
        Span<byte> saved = stackalloc byte[MaxBlock];
        iv.CopyTo(chain);
        for (int i = 0; i < source.Length; i += bs)
        {
            source.Slice(i, bs).CopyTo(saved);
            Span<byte> block = destination.Slice(i, bs);
            engine.DecryptBlock(source.Slice(i, bs), block);
            for (int j = 0; j < bs; j++)
            {
                block[j] ^= chain[j];
            }

            saved[..bs].CopyTo(chain);
        }

        CryptographicOperations.ZeroMemory(saved);
        CryptographicOperations.ZeroMemory(chain);
    }

    /// <summary>CBC encryption. PKCS #7 padding (RFC 5652 section 6.3) always adds 1 to the block size bytes, each holding the count.</summary>
    internal static int CbcEncrypt(BlockEngine engine, ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode padding)
    {
        CheckIv(engine, iv);
        int bs = engine.BlockSize;
        if (padding == PaddingMode.None)
        {
            CheckWhole(engine, source, destination);
            CbcEncryptBlocks(engine, source, iv, destination);
            return source.Length;
        }

        if (padding != PaddingMode.PKCS7)
        {
            throw new NotSupportedException("Only PaddingMode.PKCS7 and PaddingMode.None are supported.");
        }

        int whole = source.Length - (source.Length % bs);
        int total = whole + bs;
        if (destination.Length < total)
        {
            throw new ArgumentException("The destination is too short for the padded ciphertext.", nameof(destination));
        }

        if (source.Overlaps(destination))
        {
            throw new ArgumentException("Padded encryption needs a destination that does not overlap the source.", nameof(destination));
        }

        CbcEncryptBlocks(engine, source[..whole], iv, destination);
        Span<byte> last = stackalloc byte[MaxBlock];
        Span<byte> chain = stackalloc byte[MaxBlock];
        int tail = source.Length - whole;
        source[whole..].CopyTo(last);
        last[tail..bs].Fill((byte)(bs - tail));
        if (whole == 0)
        {
            iv.CopyTo(chain);
        }
        else
        {
            destination.Slice(whole - bs, bs).CopyTo(chain);
        }

        for (int j = 0; j < bs; j++)
        {
            last[j] ^= chain[j];
        }

        engine.EncryptBlock(last[..bs], destination.Slice(whole, bs));
        CryptographicOperations.ZeroMemory(last);
        CryptographicOperations.ZeroMemory(chain);
        return total;
    }

    /// <summary>
    /// CBC decryption. With PKCS #7 the padding is checked over the last block with masks and no early exit, and on failure the
    /// destination is zeroed before the exception so no plaintext leaves. The padded length is public, so the returned length is not
    /// a secret; whether the padding was valid is reported only by the exception.
    /// </summary>
    internal static int CbcDecrypt(BlockEngine engine, ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode padding)
    {
        CheckIv(engine, iv);
        if (padding != PaddingMode.None && padding != PaddingMode.PKCS7)
        {
            throw new NotSupportedException("Only PaddingMode.PKCS7 and PaddingMode.None are supported.");
        }

        int bs = engine.BlockSize;
        CheckWhole(engine, source, destination);
        if (padding == PaddingMode.PKCS7 && source.Length == 0)
        {
            throw new CryptographicException("The padding is invalid.");
        }

        CbcDecryptBlocks(engine, source, iv, destination);
        if (padding == PaddingMode.None)
        {
            return source.Length;
        }

        ReadOnlySpan<byte> last = destination.Slice(source.Length - bs, bs);
        uint count = last[bs - 1];
        // valid = 1 <= count <= bs and the last count bytes all equal count, evaluated for every position.
        uint bad = ((count - 1) | ((uint)bs - count)) >> 31; // count == 0 or count > bs
        for (int j = 0; j < bs; j++)
        {
            uint inPad = ((uint)(bs - 1 - j) - count) >> 31; // 1 when position j lies within the last count bytes
            uint differs = (uint)(last[j] ^ (byte)count);
            bad |= inPad & ((differs | (0u - differs)) >> 31);
        }

        if ((bad & 1) != 0)
        {
            destination[..source.Length].Clear();
            throw new CryptographicException("The padding is invalid.");
        }

        return source.Length - (int)count;
    }

    /// <summary>
    /// Full-block CFB (the segment size is the block size, as in NIST SP 800-38A CFB128 for 16-byte blocks). The last block may be
    /// short: its keystream is truncated.
    /// </summary>
    internal static void Cfb(BlockEngine engine, bool decrypt, ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        CheckIv(engine, iv);
        if (destination.Length < source.Length)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }

        CheckOverlap(source, destination);
        int bs = engine.BlockSize;
        Span<byte> register = stackalloc byte[MaxBlock];
        Span<byte> keystream = stackalloc byte[MaxBlock];
        iv.CopyTo(register);
        for (int i = 0; i < source.Length; i += bs)
        {
            int n = Math.Min(bs, source.Length - i); // public: depends on the length only
            engine.EncryptBlock(register[..bs], keystream[..bs]);
            if (decrypt && n == bs)
            {
                source.Slice(i, bs).CopyTo(register); // the feedback is the ciphertext, saved before an in-place write
            }

            for (int j = 0; j < n; j++)
            {
                destination[i + j] = (byte)(source[i + j] ^ keystream[j]);
            }

            if (!decrypt && n == bs)
            {
                destination.Slice(i, bs).CopyTo(register);
            }
        }

        CryptographicOperations.ZeroMemory(register);
        CryptographicOperations.ZeroMemory(keystream);
    }

    /// <summary>
    /// Decrypts OpenPGP symmetric-key encrypted data (RFC 9580 section 13.9, RFC 4880 section 13.9): CFB with an all-zero IV over the
    /// random prefix and the data. With <paramref name="resync"/> (the variant of the older, unprotected packet type) the feedback
    /// register is reloaded after the prefix and its two check bytes with the ciphertext bytes 3 to block size + 2.
    /// </summary>
    internal static void OpenPgpCfbDecrypt(BlockEngine engine, ReadOnlySpan<byte> source, Span<byte> destination, bool resync)
    {
        int bs = engine.BlockSize;
        Span<byte> zero = stackalloc byte[MaxBlock];
        zero = zero[..bs];
        if (!resync)
        {
            Cfb(engine, true, source, zero, destination);
            return;
        }

        if (source.Length < bs + 2)
        {
            throw new ArgumentException("The data is shorter than the random prefix and its check bytes.", nameof(source));
        }

        if (destination.Length < source.Length)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }

        CheckOverlap(source, destination);
        Span<byte> resynced = stackalloc byte[MaxBlock];
        resynced = resynced[..bs];
        source.Slice(2, bs).CopyTo(resynced); // saved first: an in-place decryption overwrites it
        Cfb(engine, true, source[..(bs + 2)], zero, destination[..(bs + 2)]);
        Cfb(engine, true, source[(bs + 2)..], resynced, destination[(bs + 2)..source.Length]);
    }
}
