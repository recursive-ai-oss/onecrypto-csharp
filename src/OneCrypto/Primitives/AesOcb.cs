using System.Numerics;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// OCB3 authenticated encryption with AES (RFC 7253), shaped like <see cref="AesGcm"/>: construct once per key, then call
/// <see cref="Encrypt"/> and <see cref="Decrypt"/> with spans.
/// </summary>
/// <remarks>
/// <para>The AES block function comes from the platform (<see cref="Aes"/>); this class is only the mode. Nonces are 1 to 15 bytes
/// (OpenPGP uses 15) and must never repeat under one key. The tag is 8 to 16 bytes; the tag length is bound into the nonce
/// formatting (RFC 7253 §4.2), so a key object accepts only the length it was created with.</para>
/// <para>Decryption verifies the tag over the whole message with <see cref="CryptographicOperations.FixedTimeEquals"/> before it
/// reports success. If verification fails, the destination is zeroed and <see cref="AuthenticationTagMismatchException"/> is thrown,
/// so no unauthenticated plaintext is left behind. Do not use the destination before <see cref="Decrypt"/> returns.</para>
/// <para>Buffers may be the same span (in place) or must not overlap. An instance is not safe for concurrent use. The key-dependent
/// table is held in a pinned buffer that <see cref="Dispose"/> zeroes; the platform AES key stays inside its own handle.</para>
/// </remarks>
public sealed class AesOcb : IDisposable
{
    private const int BlockSize = Block128.Size;

    // Blocks processed per platform AES call. A larger batch amortises the per-call cost; the scratch lives on the stack.
    private const int ChunkBlocks = 128;

    // L_*, L_$, then L_0 .. L_{LCount-1}. ntz of a 32-bit block counter is at most 31, so 32 entries cover any span.
    private const int LCount = 32;
    private const int LStar = 0;
    private const int LDollar = 1;
    private const int LFirst = 2;

    private readonly Aes _aes;
    private readonly PinnedSecret _l;
    private readonly int _tagSize;
    private bool _disposed;

    /// <summary>The smallest accepted nonce, in bytes (RFC 7253 §3.1: N_MIN).</summary>
    public const int MinNonceSize = 1;

    /// <summary>The largest accepted nonce, in bytes (RFC 7253 §3.1: N_MAX, 120 bits).</summary>
    public const int MaxNonceSize = 15;

    /// <summary>The smallest accepted tag size, in bytes.</summary>
    public const int MinTagSize = 8;

    /// <summary>The largest, and default, tag size, in bytes.</summary>
    public const int MaxTagSize = 16;

    /// <summary>Creates an OCB instance for an AES key.</summary>
    /// <param name="key">An AES key of 16, 24 or 32 bytes. It is copied; the caller still owns, and should zero, its own copy.</param>
    /// <param name="tagSizeInBytes">The tag length, 8 to 16 bytes. Defaults to 16.</param>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not a valid AES key size.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="tagSizeInBytes"/> is outside 8 to 16.</exception>
    /// <exception cref="PlatformNotSupportedException">The platform has no AES.</exception>
    public AesOcb(ReadOnlySpan<byte> key, int tagSizeInBytes = MaxTagSize)
    {
        AeadChecks.ValidateKey(key);
        ArgumentOutOfRangeException.ThrowIfLessThan(tagSizeInBytes, MinTagSize);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(tagSizeInBytes, MaxTagSize);
        _tagSize = tagSizeInBytes;
        _aes = Aes.Create();
        _l = new PinnedSecret((LFirst + LCount) * BlockSize);
        try
        {
            _aes.SetKey(key);
            // RFC 7253 §4.2: L_* = ENCIPHER(K, zeros(128)); L_$ = double(L_*); L_0 = double(L_$); L_i = double(L_{i-1})
            Span<byte> table = _l.Span;
            _aes.EncryptEcb(table[..BlockSize], table[..BlockSize], PaddingMode.None);
            for (int i = LDollar; i < LFirst + LCount; i++)
            {
                Block128.Double(table.Slice((i - 1) * BlockSize, BlockSize), table.Slice(i * BlockSize, BlockSize));
            }
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
    /// <param name="nonce">1 to 15 bytes, unique per message under this key.</param>
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
        CheckArguments(nonce, plaintext, ciphertext, tag.Length);
        Span<byte> fullTag = stackalloc byte[BlockSize]; // fixed 16-byte buffer
        Process(encrypt: true, nonce, plaintext, ciphertext, fullTag, associatedData);
        fullTag[.._tagSize].CopyTo(tag);
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
        CheckArguments(nonce, ciphertext, plaintext, tag.Length);
        Span<byte> fullTag = stackalloc byte[BlockSize]; // fixed 16-byte buffer
        Process(encrypt: false, nonce, ciphertext, plaintext, fullTag, associatedData);
        // RFC 7253 §4.3: the comparison covers the whole message and runs in constant time; only then is the result released.
        bool valid = CryptographicOperations.FixedTimeEquals(fullTag[.._tagSize], tag);
        CryptographicOperations.ZeroMemory(fullTag);
        if (!valid)
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        return valid;
    }

    /// <summary>Zeroes the key-dependent table and releases the platform key. Safe to call more than once.</summary>
    public void Dispose()
    {
        _disposed = true;
        _l.Dispose();
        _aes.Dispose();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private void CheckArguments(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output, int tagLength)
    {
        if (nonce.Length is < MinNonceSize or > MaxNonceSize)
        {
            throw new ArgumentException("An OCB nonce is 1 to 15 bytes.", nameof(nonce));
        }

        if (tagLength != _tagSize)
        {
            throw new ArgumentException($"The tag must be {_tagSize} bytes, the size this instance was created with.", nameof(tagLength));
        }

        AeadChecks.ValidateBuffers(input, output);
    }

    /// <summary>
    /// RFC 7253 §4.2 and §4.3 in one pass. Writes the output and leaves the full 16-byte tag in <paramref name="fullTag"/>.
    /// All lengths are public, so branching on them is fine; the data and key-derived blocks are only ever XORed and passed to AES.
    /// </summary>
    private void Process(
        bool encrypt,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> input,
        Span<byte> output,
        Span<byte> fullTag,
        ReadOnlySpan<byte> associatedData)
    {
        ReadOnlySpan<byte> table = _l.ReadOnlySpan;
        Vector128<byte> hash = Hash(associatedData, table);
        Vector128<byte> offset = InitialOffset(nonce);
        Vector128<byte> checksum = Vector128<byte>.Zero;

        int fullBlocks = input.Length / BlockSize;
        uint blockIndex = 0;
        int done = 0;
        Span<byte> offsets = stackalloc byte[Math.Min(fullBlocks, ChunkBlocks) * BlockSize]; // at most 2 KiB
        while (done < fullBlocks)
        {
            int n = Math.Min(fullBlocks - done, ChunkBlocks);
            ReadOnlySpan<byte> inChunk = input.Slice(done * BlockSize, n * BlockSize);
            Span<byte> outChunk = output.Slice(done * BlockSize, n * BlockSize);
            for (int j = 0; j < n; j++)
            {
                // RFC 7253 §4.2: Offset_i = Offset_{i-1} xor L_{ntz(i)}; the block counter is public.
                blockIndex++;
                offset ^= Block128.Load(table[((LFirst + BitOperations.TrailingZeroCount(blockIndex)) * BlockSize)..]);
                offset.CopyTo(offsets.Slice(j * BlockSize, BlockSize));
                Vector128<byte> block = Block128.Load(inChunk[(j * BlockSize)..]);
                if (encrypt)
                {
                    checksum ^= block;
                }

                (block ^ offset).CopyTo(outChunk.Slice(j * BlockSize, BlockSize));
            }

            if (encrypt)
            {
                _aes.EncryptEcb(outChunk, outChunk, PaddingMode.None);
            }
            else
            {
                _aes.DecryptEcb(outChunk, outChunk, PaddingMode.None);
            }

            for (int j = 0; j < n; j++)
            {
                Span<byte> slot = outChunk.Slice(j * BlockSize, BlockSize);
                Vector128<byte> result = Block128.Load(slot) ^ Block128.Load(offsets[(j * BlockSize)..]);
                result.CopyTo(slot);
                if (!encrypt)
                {
                    checksum ^= result;
                }
            }

            done += n;
        }

        CryptographicOperations.ZeroMemory(offsets);

        int rest = input.Length - (fullBlocks * BlockSize);
        Span<byte> work = stackalloc byte[BlockSize]; // fixed 16-byte buffer
        if (rest > 0)
        {
            // RFC 7253 §4.2: Offset_* = Offset_m xor L_*; Pad = ENCIPHER(K, Offset_*); C_* = P_* xor Pad[1..bitlen(P_*)]
            offset ^= Block128.Load(table[(LStar * BlockSize)..]);
            offset.CopyTo(work);
            _aes.EncryptEcb(work, work, PaddingMode.None);
            ReadOnlySpan<byte> inTail = input[(fullBlocks * BlockSize)..];
            Span<byte> outTail = output[(fullBlocks * BlockSize)..];
            Span<byte> padded = stackalloc byte[BlockSize]; // fixed 16-byte buffer
            if (encrypt)
            {
                // Checksum_* = Checksum_m xor (P_* || 1 || zeros): the one-bit is the 0x80 byte.
                inTail.CopyTo(padded);
                padded[rest] = 0x80;
                checksum ^= Block128.Load(padded);
            }

            for (int i = 0; i < rest; i++)
            {
                outTail[i] = (byte)(inTail[i] ^ work[i]);
            }

            if (!encrypt)
            {
                padded.Clear();
                outTail.CopyTo(padded);
                padded[rest] = 0x80;
                checksum ^= Block128.Load(padded);
            }

            CryptographicOperations.ZeroMemory(padded);
        }

        // Tag = ENCIPHER(K, Checksum xor Offset xor L_$) xor HASH(K, A)
        (checksum ^ offset ^ Block128.Load(table[(LDollar * BlockSize)..])).CopyTo(work);
        _aes.EncryptEcb(work, work, PaddingMode.None);
        (Block128.Load(work) ^ hash).CopyTo(fullTag);
        CryptographicOperations.ZeroMemory(work);
    }

    /// <summary>RFC 7253 §4.1 HASH(K, A): the associated data processed as offset-codebook blocks with their own offset chain.</summary>
    private Vector128<byte> Hash(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> table)
    {
        Vector128<byte> sum = Vector128<byte>.Zero;
        Vector128<byte> offset = Vector128<byte>.Zero;
        int fullBlocks = associatedData.Length / BlockSize;
        uint blockIndex = 0;
        int done = 0;
        Span<byte> scratch = stackalloc byte[Math.Min(fullBlocks, ChunkBlocks) * BlockSize]; // at most 2 KiB
        while (done < fullBlocks)
        {
            int n = Math.Min(fullBlocks - done, ChunkBlocks);
            ReadOnlySpan<byte> chunk = associatedData.Slice(done * BlockSize, n * BlockSize);
            Span<byte> work = scratch[..(n * BlockSize)];
            for (int j = 0; j < n; j++)
            {
                blockIndex++;
                offset ^= Block128.Load(table[((LFirst + BitOperations.TrailingZeroCount(blockIndex)) * BlockSize)..]);
                (Block128.Load(chunk[(j * BlockSize)..]) ^ offset).CopyTo(work.Slice(j * BlockSize, BlockSize));
            }

            _aes.EncryptEcb(work, work, PaddingMode.None);
            for (int j = 0; j < n; j++)
            {
                sum ^= Block128.Load(work[(j * BlockSize)..]);
            }

            done += n;
        }

        CryptographicOperations.ZeroMemory(scratch);

        int rest = associatedData.Length - (fullBlocks * BlockSize);
        if (rest > 0)
        {
            Span<byte> last = stackalloc byte[BlockSize]; // fixed 16-byte buffer
            associatedData[(fullBlocks * BlockSize)..].CopyTo(last);
            last[rest] = 0x80;
            offset ^= Block128.Load(table[(LStar * BlockSize)..]);
            (Block128.Load(last) ^ offset).CopyTo(last);
            _aes.EncryptEcb(last, last, PaddingMode.None);
            sum ^= Block128.Load(last);
            CryptographicOperations.ZeroMemory(last);
        }

        return sum;
    }

    /// <summary>
    /// RFC 7253 §4.2 nonce-dependent setup: Offset_0 is a 128-bit window, at a bit position taken from the nonce, of the stretched
    /// output of one AES call. The nonce is public, so the window position may select bytes.
    /// </summary>
    private Vector128<byte> InitialOffset(ReadOnlySpan<byte> nonce)
    {
        Span<byte> block = stackalloc byte[BlockSize]; // fixed 16-byte buffer
        block.Clear();
        // Nonce = num2str(TAGLEN mod 128, 7) || zeros(120 - bitlen(N)) || 1 || N
        block[0] = (byte)(((_tagSize * 8) % 128) << 1);
        block[BlockSize - 1 - nonce.Length] |= 1;
        nonce.CopyTo(block[(BlockSize - nonce.Length)..]);
        int bottom = block[BlockSize - 1] & 0x3F;
        block[BlockSize - 1] &= 0xC0;
        _aes.EncryptEcb(block, block, PaddingMode.None); // Ktop

        // Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]); Offset_0 = Stretch[1+bottom..128+bottom]
        Span<byte> stretch = stackalloc byte[24]; // fixed 24-byte buffer
        block.CopyTo(stretch);
        for (int i = 0; i < 8; i++)
        {
            stretch[16 + i] = (byte)(block[i] ^ block[i + 1]);
        }

        int byteShift = bottom >> 3;
        int bitShift = bottom & 7;
        for (int i = 0; i < BlockSize; i++)
        {
            block[i] = (byte)((stretch[i + byteShift] << bitShift) | (stretch[i + byteShift + 1] >> (8 - bitShift)));
        }

        Vector128<byte> offset = Block128.Load(block);
        CryptographicOperations.ZeroMemory(block);
        CryptographicOperations.ZeroMemory(stretch);
        return offset;
    }
}
