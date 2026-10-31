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
/// state (CMAC subkeys and precomputed blocks) is held in a pinned buffer that <see cref="Dispose"/> zeroes; the platform AES key stays inside its own handle.</para>
/// </remarks>
public sealed class AesEax : IDisposable
{
    private const int BlockSize = Block128.Size;

    // Bytes handed to the platform per call: a multiple of 16, small enough for the stack.
    private const int ChunkBytes = 2048;

    // Layout of the key-dependent state, in 16-byte blocks:
    //   K1 = 2L, K2 = 4L (EAX paper Figure 1, line 40), where L = E_K(0^n);
    //   X_t = E_K([t]_n) for t = 0, 1, 2: the CMAC state after the tweak block, the same for every message;
    //   Y_t = E_K([t]_n xor K1): the whole OMAC^t of the empty message, whose only block is the tweak block;
    //   the chaining value the CBC transform currently holds (its last output block).
    private const int K1 = 0;
    private const int K2 = 1;
    private const int X0 = 2;
    private const int Y0 = 5;
    private const int Chain = 8;
    private const int StateBlocks = 9;

    private readonly AesBlockEngine _aes;
    private readonly PinnedSecret _state;
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
    /// <exception cref="AlgorithmNotSupportedException">The platform has no AES.</exception>
    public AesEax(ReadOnlySpan<byte> key, int tagSizeInBytes = MaxTagSize)
    {
        AeadChecks.ValidateKey(key);
        ArgumentOutOfRangeException.ThrowIfLessThan(tagSizeInBytes, MinTagSize);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(tagSizeInBytes, MaxTagSize);
        _tagSize = tagSizeInBytes;
        _aes = new AesBlockEngine(key, ChunkBytes, needDecrypt: false, needCbcEncrypt: true);
        _state = new PinnedSecret(StateBlocks * BlockSize);
        try
        {
            Span<byte> state = _state.Span;
            Span<byte> buf = _aes.Buffer;
            // First call: L = E(0) and the three tweak blocks E([t]). The Y values need K1, which needs L, so they take a second call.
            buf[..BlockSize].Clear();
            for (int t = 0; t < 3; t++)
            {
                buf[((1 + t) * BlockSize) + BlockSize - 1] = (byte)t; // [t]_n: n-bit big-endian t
            }

            _aes.Encrypt(4 * BlockSize);
            Block128.Double(buf[..BlockSize], state.Slice(K1 * BlockSize, BlockSize)); // 2L
            Block128.Double(state.Slice(K1 * BlockSize, BlockSize), state.Slice(K2 * BlockSize, BlockSize)); // 4L
            buf.Slice(BlockSize, 3 * BlockSize).CopyTo(state[(X0 * BlockSize)..]);
            buf.Clear();
            Vector128<byte> k1 = Block128.Load(state[(K1 * BlockSize)..]);
            for (int t = 0; t < 3; t++)
            {
                buf[(t * BlockSize) + BlockSize - 1] = (byte)t;
                (Block128.Load(buf[(t * BlockSize)..]) ^ k1).CopyTo(buf.Slice(t * BlockSize, BlockSize));
            }

            _aes.Encrypt(3 * BlockSize);
            buf[..(3 * BlockSize)].CopyTo(state[(Y0 * BlockSize)..]);
            CryptographicOperations.ZeroMemory(buf);
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

    /// <summary>Zeroes the key-dependent state and releases the platform key. Safe to call more than once.</summary>
    public void Dispose()
    {
        _disposed = true;
        _state.Dispose();
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
    /// OMAC^t(M) = OMAC([t]_n || M) (EAX paper Figure 1). The state after the tweak block is the precomputed X_t, so the CBC chain
    /// starts from it over the blocks of M: the last block is XORed with K1 if it is full, or padded with 10* and XORed with K2 if
    /// it is short, and the result is the last CBC output. The empty message is the precomputed Y_t. The platform's CBC transform
    /// keeps its chaining value between calls, so the first block is XORed with X_t and with the value the transform holds, which
    /// makes its effective input M_1 xor X_t. Chunks of up to 2 KiB are chained through the platform in one call each.
    /// </summary>
    private void Omac(int tweak, ReadOnlySpan<byte> message, Span<byte> result)
    {
        Span<byte> state = _state.Span;
        if (message.IsEmpty)
        {
            state.Slice((Y0 + tweak) * BlockSize, BlockSize).CopyTo(result);
            return;
        }

        Span<byte> buf = _aes.Buffer;
        Vector128<byte> k1 = Block128.Load(state[(K1 * BlockSize)..]);
        Vector128<byte> k2 = Block128.Load(state[(K2 * BlockSize)..]);
        Vector128<byte> startMask = Block128.Load(state[((X0 + tweak) * BlockSize)..]) ^ Block128.Load(state[(Chain * BlockSize)..]);
        int consumed = 0;
        bool first = true;
        int filled;
        while (true)
        {
            int take = Math.Min(message.Length - consumed, buf.Length);
            message.Slice(consumed, take).CopyTo(buf);
            consumed += take;
            filled = take;
            bool last = consumed == message.Length;
            if (last)
            {
                int tail = filled % BlockSize;
                if (tail == 0)
                {
                    XorInto(buf.Slice(filled - BlockSize, BlockSize), k1); // the last block is full
                }
                else
                {
                    buf[filled] = 0x80;
                    buf.Slice(filled + 1, BlockSize - tail - 1).Clear();
                    filled += BlockSize - tail;
                    XorInto(buf.Slice(filled - BlockSize, BlockSize), k2);
                }
            }

            if (first)
            {
                XorInto(buf[..BlockSize], startMask);
                first = false;
            }

            _aes.CbcEncrypt(filled);
            buf.Slice(filled - BlockSize, BlockSize).CopyTo(state[(Chain * BlockSize)..]);
            if (last)
            {
                break;
            }
        }

        state.Slice(Chain * BlockSize, BlockSize).CopyTo(result);
        CryptographicOperations.ZeroMemory(buf);
    }

    /// <summary>
    /// CTR mode with a 128-bit big-endian counter starting at <paramref name="start"/> (EAX paper Figure 1, CTR): counter blocks are
    /// built in the engine buffer, encrypted with the platform's ECB, and XORed over the data.
    /// </summary>
    private void Ctr(ReadOnlySpan<byte> start, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.IsEmpty)
        {
            return;
        }

        Span<byte> counter = stackalloc byte[BlockSize]; // fixed 16-byte buffer
        start.CopyTo(counter);
        Span<byte> buf = _aes.Buffer;
        int done = 0;
        while (done < input.Length)
        {
            int take = Math.Min(input.Length - done, buf.Length);
            int blocks = (take + BlockSize - 1) / BlockSize;
            for (int b = 0; b < blocks; b++)
            {
                counter.CopyTo(buf.Slice(b * BlockSize, BlockSize));
                Block128.Increment(counter);
            }

            _aes.Encrypt(blocks * BlockSize);
            int whole = take / BlockSize * BlockSize;
            for (int i = 0; i < whole; i += BlockSize)
            {
                (Block128.Load(input[(done + i)..]) ^ Block128.Load(buf[i..])).CopyTo(output[(done + i)..]);
            }

            for (int i = whole; i < take; i++)
            {
                output[done + i] = (byte)(input[done + i] ^ buf[i]);
            }

            done += take;
        }

        CryptographicOperations.ZeroMemory(buf);
        CryptographicOperations.ZeroMemory(counter);
    }

    private static void XorInto(Span<byte> block, Vector128<byte> mask)
    {
        (Block128.Load(block) ^ mask).CopyTo(block);
    }
}
