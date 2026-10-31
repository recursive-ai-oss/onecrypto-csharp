using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// EAX authenticated encryption with AES (Bellare, Rogaway and Wagner, "The EAX Mode of Operation", FSE 2004), shaped like
/// <see cref="AesGcm"/>: construct once per key, then call <see cref="Encrypt"/> and <see cref="Decrypt"/> with spans.
/// </summary>
/// <remarks>
/// <para>The AES block function comes from the platform (<see cref="Aes"/>); this class is only the mode: CTR encryption plus three
/// tweaked OMAC (CMAC) computations over nonce, associated data and ciphertext. Nonces may have any length, including none; they must
/// never repeat under one key. The tag is 8 to 16 bytes.</para>
/// <para>Decryption checks the tag over the nonce, associated data and ciphertext, with <see cref="CryptographicOperations.FixedTimeEquals"/>,
/// before it produces any plaintext. If the check fails, the destination is zeroed and <see cref="AuthenticationTagMismatchException"/>
/// is thrown.</para>
/// <para>Buffers may be the same span (in place) or must not overlap. An instance is not safe for concurrent use. The key-dependent
/// subkeys are held in a pinned buffer that <see cref="Dispose"/> zeroes; the platform AES key stays inside its own handle.</para>
/// </remarks>
public sealed class AesEax : IDisposable
{
    private const int BlockSize = Block128.Size;

    // Bytes handed to the platform per call: a multiple of 16, small enough for the stack.
    private const int ChunkBytes = 2048;

    private readonly Aes _aes;
    private readonly PinnedSecret _subkeys; // K1 = 2L, K2 = 4L (EAX paper Figure 1, line 40), where L = E_K(0^n)
    private readonly int _tagSize;
    private bool _disposed;

    /// <summary>The smallest accepted tag size, in bytes.</summary>
    public const int MinTagSize = 8;

    /// <summary>The largest, and default, tag size, in bytes.</summary>
    public const int MaxTagSize = 16;

    /// <summary>Creates an EAX instance for an AES key.</summary>
    /// <param name="key">An AES key of 16, 24 or 32 bytes. It is copied; the caller still owns, and should zero, its own copy.</param>
    /// <param name="tagSizeInBytes">The tag length, 8 to 16 bytes. Defaults to 16.</param>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not a valid AES key size.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="tagSizeInBytes"/> is outside 8 to 16.</exception>
    /// <exception cref="PlatformNotSupportedException">The platform has no AES.</exception>
    public AesEax(ReadOnlySpan<byte> key, int tagSizeInBytes = MaxTagSize)
    {
        AeadChecks.ValidateKey(key);
        ArgumentOutOfRangeException.ThrowIfLessThan(tagSizeInBytes, MinTagSize);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(tagSizeInBytes, MaxTagSize);
        _tagSize = tagSizeInBytes;
        _aes = Aes.Create();
        _subkeys = new PinnedSecret(2 * BlockSize);
        try
        {
            _aes.SetKey(key);
            Span<byte> subkeys = _subkeys.Span;
            _aes.EncryptEcb(subkeys[..BlockSize], subkeys[..BlockSize], PaddingMode.None);
            Block128.Double(subkeys[..BlockSize], subkeys[..BlockSize]); // 2L
            Block128.Double(subkeys[..BlockSize], subkeys[BlockSize..]); // 4L
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>The tag length of this instance, in bytes.</summary>
    public int TagSizeInBytes => _tagSize;

    /// <summary>Encrypts <paramref name="plaintext"/> and writes the ciphertext and the authentication tag.</summary>
    /// <param name="nonce">Any length; unique per message under this key.</param>
    /// <param name="plaintext">The data to encrypt; may be empty.</param>
    /// <param name="ciphertext">Receives the ciphertext; exactly as long as <paramref name="plaintext"/>. May be the same span.</param>
    /// <param name="tag">Receives the tag; exactly <see cref="TagSizeInBytes"/> long.</param>
    /// <param name="associatedData">Authenticated but not encrypted; may be empty.</param>
    /// <exception cref="ArgumentException">A length is wrong, or the buffers partly overlap.</exception>
    /// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        ThrowIfDisposed();
        CheckArguments(plaintext, ciphertext, tag.Length);
        Span<byte> counter = stackalloc byte[BlockSize]; // fixed 16-byte buffers
        Span<byte> headerMac = stackalloc byte[BlockSize];
        Span<byte> fullTag = stackalloc byte[BlockSize];

        // EAX paper Figure 2: N' = OMAC^0(N); H' = OMAC^1(H); C = CTR_N'(M); C' = OMAC^2(C); Tag = N' xor C' xor H'
        Omac(0, nonce, counter);
        Omac(1, associatedData, headerMac);
        Ctr(counter, plaintext, ciphertext);
        Omac(2, ciphertext, fullTag);
        Combine(counter, headerMac, fullTag);
        fullTag[.._tagSize].CopyTo(tag);
        CryptographicOperations.ZeroMemory(counter);
        CryptographicOperations.ZeroMemory(headerMac);
        CryptographicOperations.ZeroMemory(fullTag);
    }

    /// <summary>Verifies the tag, then decrypts.</summary>
    /// <param name="nonce">The nonce used to encrypt.</param>
    /// <param name="ciphertext">The ciphertext, without the tag.</param>
    /// <param name="tag">The tag; exactly <see cref="TagSizeInBytes"/> long.</param>
    /// <param name="plaintext">Receives the plaintext; exactly as long as <paramref name="ciphertext"/>. May be the same span.</param>
    /// <param name="associatedData">The associated data used to encrypt.</param>
    /// <exception cref="AuthenticationTagMismatchException">Authentication failed. <paramref name="plaintext"/> has been zeroed.</exception>
    /// <exception cref="ArgumentException">A length is wrong, or the buffers partly overlap.</exception>
    /// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (!TryDecrypt(nonce, ciphertext, tag, plaintext, associatedData))
        {
            throw new AuthenticationTagMismatchException();
        }
    }

    /// <summary>Like <see cref="Decrypt"/>, but reports a failed authentication as <see langword="false"/> instead of throwing.</summary>
    /// <returns><see langword="true"/> if the tag is valid; otherwise <see langword="false"/> and <paramref name="plaintext"/> is zeroed.</returns>
    /// <exception cref="ArgumentException">A length is wrong, or the buffers partly overlap.</exception>
    /// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
    public bool TryDecrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        ThrowIfDisposed();
        CheckArguments(ciphertext, plaintext, tag.Length);
        Span<byte> counter = stackalloc byte[BlockSize]; // fixed 16-byte buffers
        Span<byte> headerMac = stackalloc byte[BlockSize];
        Span<byte> fullTag = stackalloc byte[BlockSize];

        // EAX paper Figure 2: the tag is computed over the ciphertext first; the plaintext is produced only if it matches.
        Omac(0, nonce, counter);
        Omac(1, associatedData, headerMac);
        Omac(2, ciphertext, fullTag);
        Combine(counter, headerMac, fullTag);
        bool valid = CryptographicOperations.FixedTimeEquals(fullTag[.._tagSize], tag);
        if (valid)
        {
            Ctr(counter, ciphertext, plaintext);
        }
        else
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        CryptographicOperations.ZeroMemory(counter);
        CryptographicOperations.ZeroMemory(headerMac);
        CryptographicOperations.ZeroMemory(fullTag);
        return valid;
    }

    /// <summary>Zeroes the subkeys and releases the platform key. Safe to call more than once.</summary>
    public void Dispose()
    {
        _disposed = true;
        _subkeys.Dispose();
        _aes.Dispose();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private void CheckArguments(ReadOnlySpan<byte> input, Span<byte> output, int tagLength)
    {
        if (tagLength != _tagSize)
        {
            throw new ArgumentException($"The tag must be {_tagSize} bytes, the size this instance was created with.", nameof(tagLength));
        }

        AeadChecks.ValidateBuffers(input, output);
    }

    /// <summary>fullTag = nonceMac xor headerMac xor fullTag (EAX paper Figure 2, line 14).</summary>
    private static void Combine(ReadOnlySpan<byte> nonceMac, ReadOnlySpan<byte> headerMac, Span<byte> fullTag)
    {
        (Block128.Load(nonceMac) ^ Block128.Load(headerMac) ^ Block128.Load(fullTag)).CopyTo(fullTag);
    }

    /// <summary>
    /// OMAC^t(M) = OMAC([t]_n || M) (EAX paper Figure 1). The block [t]_n and the message form one stream of whole blocks and a last
    /// block of 1 to 16 bytes; that last block is XORed with K1 (full) or padded with 10* and XORed with K2 (short), and the result
    /// is the last CBC output. The stream is assembled in a stack buffer and chained through the platform's CBC, one call per chunk.
    /// </summary>
    private void Omac(byte tweak, ReadOnlySpan<byte> message, Span<byte> result)
    {
        ReadOnlySpan<byte> subkeys = _subkeys.ReadOnlySpan;
        long total = BlockSize + (long)message.Length;
        int scratchLength = (int)Math.Min(ChunkBytes, ((total + BlockSize - 1) / BlockSize) * BlockSize);
        Span<byte> scratch = stackalloc byte[scratchLength]; // at most 2 KiB
        Span<byte> iv = stackalloc byte[BlockSize]; // fixed 16-byte buffer
        iv.Clear();

        int consumed = 0; // bytes of `message` placed so far
        bool first = true;
        while (true)
        {
            int filled = 0;
            if (first)
            {
                scratch[..BlockSize].Clear();
                scratch[BlockSize - 1] = tweak;
                filled = BlockSize;
                first = false;
            }

            int take = Math.Min(message.Length - consumed, scratch.Length - filled);
            message.Slice(consumed, take).CopyTo(scratch[filled..]);
            filled += take;
            consumed += take;

            bool last = consumed == message.Length;
            if (last)
            {
                // The last block is full when the stream length is a non-zero multiple of 16.
                int tail = filled % BlockSize;
                if (tail == 0)
                {
                    XorInto(scratch.Slice(filled - BlockSize, BlockSize), subkeys[..BlockSize]); // K1
                }
                else
                {
                    scratch[filled] = 0x80;
                    scratch.Slice(filled + 1, BlockSize - tail - 1).Clear();
                    filled += BlockSize - tail;
                    XorInto(scratch.Slice(filled - BlockSize, BlockSize), subkeys[BlockSize..]); // K2
                }
            }

            Span<byte> chunk = scratch[..filled];
            _aes.EncryptCbc(chunk, iv, chunk, PaddingMode.None);
            chunk.Slice(filled - BlockSize, BlockSize).CopyTo(iv);
            if (last)
            {
                break;
            }
        }

        iv.CopyTo(result);
        CryptographicOperations.ZeroMemory(scratch);
        CryptographicOperations.ZeroMemory(iv);
    }

    /// <summary>
    /// CTR mode with a 128-bit big-endian counter starting at <paramref name="start"/> (EAX paper Figure 1, CTR): counter blocks are
    /// built in a stack buffer, encrypted with the platform's ECB, and XORed over the data.
    /// </summary>
    private void Ctr(ReadOnlySpan<byte> start, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.IsEmpty)
        {
            return;
        }

        Span<byte> counter = stackalloc byte[BlockSize]; // fixed 16-byte buffer
        start.CopyTo(counter);
        Span<byte> stream = stackalloc byte[Math.Min(ChunkBytes, ((input.Length + BlockSize - 1) / BlockSize) * BlockSize)]; // at most 2 KiB
        int done = 0;
        while (done < input.Length)
        {
            int take = Math.Min(input.Length - done, stream.Length);
            int blocks = (take + BlockSize - 1) / BlockSize;
            for (int b = 0; b < blocks; b++)
            {
                counter.CopyTo(stream.Slice(b * BlockSize, BlockSize));
                Block128.Increment(counter);
            }

            Span<byte> keystream = stream[..(blocks * BlockSize)];
            _aes.EncryptEcb(keystream, keystream, PaddingMode.None);
            int whole = take / BlockSize * BlockSize;
            for (int i = 0; i < whole; i += BlockSize)
            {
                (Block128.Load(input[(done + i)..]) ^ Block128.Load(keystream[i..])).CopyTo(output[(done + i)..]);
            }

            for (int i = whole; i < take; i++)
            {
                output[done + i] = (byte)(input[done + i] ^ keystream[i]);
            }

            done += take;
        }

        CryptographicOperations.ZeroMemory(stream);
        CryptographicOperations.ZeroMemory(counter);
    }

    private static void XorInto(Span<byte> block, ReadOnlySpan<byte> key)
    {
        (Block128.Load(block) ^ Block128.Load(key)).CopyTo(block);
    }
}
