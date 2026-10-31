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

    private readonly AesBlockEngine _aes;
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
    /// <exception cref="AlgorithmNotSupportedException">The platform has no AES.</exception>
    public AesOcb(ReadOnlySpan<byte> key, int tagSizeInBytes = MaxTagSize)
    {
        AeadChecks.ValidateKey(key);
        ArgumentOutOfRangeException.ThrowIfLessThan(tagSizeInBytes, MinTagSize);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(tagSizeInBytes, MaxTagSize);
        _tagSize = tagSizeInBytes;
        _aes = new AesBlockEngine(key, (ChunkBlocks + 2) * BlockSize, needDecrypt: true, needCbcEncrypt: false);
        _l = new PinnedSecret((LFirst + LCount) * BlockSize);
        try
        {
            // RFC 7253 §4.2: L_* = ENCIPHER(K, zeros(128)); L_$ = double(L_*); L_0 = double(L_$); L_i = double(L_{i-1})
            Span<byte> table = _l.Span;
            _aes.Buffer[..BlockSize].Clear();
            _aes.Encrypt(BlockSize);
            _aes.Buffer[..BlockSize].CopyTo(table);
            CryptographicOperations.ZeroMemory(_aes.Buffer[..BlockSize]);
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
    /// RFC 7253 §4.2 and §4.3. Writes the output and leaves the full 16-byte tag in <paramref name="fullTag"/>.
    /// All lengths are public, so branching on them is fine; the data and key-derived blocks are only ever XORed and passed to AES.
    /// The platform is called as few times as the dependencies allow: once for the nonce block and the associated data together; then,
    /// when encrypting, once for the data, the final partial block's pad and the tag together (all their inputs are known up front);
    /// when decrypting, once for the data, then one each for the pad and the tag, which depend on the recovered plaintext.
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
        Span<byte> buf = _aes.Buffer;
        Vector128<byte> hash = HashAndInitialOffset(nonce, associatedData, table, out Vector128<byte> offset);
        Vector128<byte> checksum = Vector128<byte>.Zero;
        Vector128<byte> lStar = Block128.Load(table[(LStar * BlockSize)..]);
        Vector128<byte> lDollar = Block128.Load(table[(LDollar * BlockSize)..]);

        int fullBlocks = input.Length / BlockSize;
        int rest = input.Length - (fullBlocks * BlockSize);
        uint blockIndex = 0;
        int done = 0;
        Span<byte> offsets = stackalloc byte[Math.Min(fullBlocks, ChunkBlocks) * BlockSize]; // at most 2 KiB
        Span<byte> work = stackalloc byte[BlockSize]; // fixed 16-byte buffer
        do
        {
            int n = Math.Min(fullBlocks - done, ChunkBlocks);
            bool last = done + n == fullBlocks;
            for (int j = 0; j < n; j++)
            {
                // RFC 7253 §4.2: Offset_i = Offset_{i-1} xor L_{ntz(i)}; the block counter is public.
                blockIndex++;
                offset ^= Block128.Load(table[((LFirst + BitOperations.TrailingZeroCount(blockIndex)) * BlockSize)..]);
                offset.CopyTo(offsets.Slice(j * BlockSize, BlockSize));
                Vector128<byte> block = Block128.Load(input[((done + j) * BlockSize)..]);
                if (encrypt)
                {
                    checksum ^= block;
                }

                (block ^ offset).CopyTo(buf.Slice(j * BlockSize, BlockSize));
            }

            if (encrypt)
            {
                int count = n;
                int padSlot = -1;
                int tagSlot = -1;
                if (last)
                {
                    if (rest > 0)
                    {
                        // Offset_* = Offset_m xor L_*; Pad = ENCIPHER(K, Offset_*)
                        offset ^= lStar;
                        offset.CopyTo(buf.Slice(count * BlockSize, BlockSize));
                        padSlot = count++;
                        // Checksum_* = Checksum_m xor (P_* || 1 || zeros): the one-bit is the 0x80 byte.
                        work.Clear();
                        input[(fullBlocks * BlockSize)..].CopyTo(work);
                        work[rest] = 0x80;
                        checksum ^= Block128.Load(work);
                    }

                    // Tag = ENCIPHER(K, Checksum xor Offset xor L_$) xor HASH(K, A)
                    (checksum ^ offset ^ lDollar).CopyTo(buf.Slice(count * BlockSize, BlockSize));
                    tagSlot = count++;
                }

                _aes.Encrypt(count * BlockSize);
                for (int j = 0; j < n; j++)
                {
                    (Block128.Load(buf[(j * BlockSize)..]) ^ Block128.Load(offsets[(j * BlockSize)..])).CopyTo(output[((done + j) * BlockSize)..]);
                }

                if (padSlot >= 0)
                {
                    // C_* = P_* xor Pad[1..bitlen(P_*)]
                    for (int i = 0; i < rest; i++)
                    {
                        output[(fullBlocks * BlockSize) + i] = (byte)(input[(fullBlocks * BlockSize) + i] ^ buf[(padSlot * BlockSize) + i]);
                    }
                }

                if (tagSlot >= 0)
                {
                    (Block128.Load(buf[(tagSlot * BlockSize)..]) ^ hash).CopyTo(fullTag);
                }
            }
            else
            {
                if (n > 0)
                {
                    _aes.Decrypt(n * BlockSize);
                }

                for (int j = 0; j < n; j++)
                {
                    Vector128<byte> result = Block128.Load(buf[(j * BlockSize)..]) ^ Block128.Load(offsets[(j * BlockSize)..]);
                    result.CopyTo(output[((done + j) * BlockSize)..]);
                    checksum ^= result;
                }

                if (last)
                {
                    if (rest > 0)
                    {
                        offset ^= lStar;
                        offset.CopyTo(buf[..BlockSize]);
                        _aes.Encrypt(BlockSize);
                        for (int i = 0; i < rest; i++)
                        {
                            output[(fullBlocks * BlockSize) + i] = (byte)(input[(fullBlocks * BlockSize) + i] ^ buf[i]);
                        }

                        work.Clear();
                        output[(fullBlocks * BlockSize)..].CopyTo(work);
                        work[rest] = 0x80;
                        checksum ^= Block128.Load(work);
                    }

                    (checksum ^ offset ^ lDollar).CopyTo(buf[..BlockSize]);
                    _aes.Encrypt(BlockSize);
                    (Block128.Load(buf) ^ hash).CopyTo(fullTag);
                }
            }

            done += n;
        }
        while (done < fullBlocks);

        CryptographicOperations.ZeroMemory(buf);
        CryptographicOperations.ZeroMemory(offsets);
        CryptographicOperations.ZeroMemory(work);
    }

    /// <summary>
    /// RFC 7253 §4.1 HASH(K, A) (the associated data as offset-codebook blocks with their own offset chain) and §4.2 nonce setup,
    /// in one platform call per batch: the nonce block rides with the first batch of associated data. Offset_0 is a 128-bit window, at a
    /// bit position taken from the nonce, of the stretched output of that AES call. The nonce is public, so the window position may
    /// select bytes.
    /// </summary>
    private Vector128<byte> HashAndInitialOffset(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> table,
        out Vector128<byte> initialOffset)
    {
        Span<byte> buf = _aes.Buffer;
        // Nonce = num2str(TAGLEN mod 128, 7) || zeros(120 - bitlen(N)) || 1 || N; bottom = str2num(Nonce[123..128])
        buf[..BlockSize].Clear();
        buf[0] = (byte)(((_tagSize * 8) % 128) << 1);
        buf[BlockSize - 1 - nonce.Length] |= 1;
        nonce.CopyTo(buf[(BlockSize - nonce.Length)..]);
        int bottom = buf[BlockSize - 1] & 0x3F;
        buf[BlockSize - 1] &= 0xC0;

        int fullBlocks = associatedData.Length / BlockSize;
        int rest = associatedData.Length - (fullBlocks * BlockSize);
        int total = fullBlocks + (rest > 0 ? 1 : 0);
        Vector128<byte> sum = Vector128<byte>.Zero;
        Vector128<byte> offset = Vector128<byte>.Zero;
        Vector128<byte> lStar = Block128.Load(table[(LStar * BlockSize)..]);
        uint blockIndex = 0;
        int done = 0;
        bool first = true;
        initialOffset = default;
        do
        {
            int n = Math.Min(total - done, ChunkBlocks);
            int firstSlot = first ? 1 : 0; // slot 0 of the first call holds the nonce block
            for (int j = 0; j < n; j++)
            {
                int item = done + j;
                Span<byte> slot = buf.Slice((firstSlot + j) * BlockSize, BlockSize);
                if (item < fullBlocks)
                {
                    blockIndex++;
                    offset ^= Block128.Load(table[((LFirst + BitOperations.TrailingZeroCount(blockIndex)) * BlockSize)..]);
                    (Block128.Load(associatedData[(item * BlockSize)..]) ^ offset).CopyTo(slot);
                }
                else
                {
                    // A final partial block is padded with a one-bit and zeros and uses Offset_* (RFC 7253 §4.1).
                    slot.Clear();
                    associatedData[(fullBlocks * BlockSize)..].CopyTo(slot);
                    slot[rest] = 0x80;
                    offset ^= lStar;
                    (Block128.Load(slot) ^ offset).CopyTo(slot);
                }
            }

            _aes.Encrypt((firstSlot + n) * BlockSize);
            if (first)
            {
                initialOffset = StretchWindow(buf[..BlockSize], bottom);
            }

            for (int j = 0; j < n; j++)
            {
                sum ^= Block128.Load(buf[((firstSlot + j) * BlockSize)..]);
            }

            done += n;
            first = false;
        }
        while (done < total);

        CryptographicOperations.ZeroMemory(buf);
        return sum;
    }

    /// <summary>Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]); Offset_0 = Stretch[1+bottom..128+bottom] (RFC 7253 §4.2).</summary>
    private static Vector128<byte> StretchWindow(ReadOnlySpan<byte> ktop, int bottom)
    {
        Span<byte> stretch = stackalloc byte[24]; // fixed 24-byte buffer
        ktop.CopyTo(stretch);
        for (int i = 0; i < 8; i++)
        {
            stretch[16 + i] = (byte)(ktop[i] ^ ktop[i + 1]);
        }

        int byteShift = bottom >> 3;
        int bitShift = bottom & 7;
        Span<byte> window = stackalloc byte[BlockSize]; // fixed 16-byte buffer
        for (int i = 0; i < BlockSize; i++)
        {
            window[i] = (byte)((stretch[i + byteShift] << bitShift) | (stretch[i + byteShift + 1] >> (8 - bitShift)));
        }

        Vector128<byte> result = Block128.Load(window);
        CryptographicOperations.ZeroMemory(stretch);
        CryptographicOperations.ZeroMemory(window);
        return result;
    }
}
