using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// AES Key Wrap (RFC 3394; NIST SP 800-38F §6.2, KW): wraps key material of 16 to many bytes, in 8-byte units, under an AES key, with
/// an integrity check.
/// </summary>
/// <remarks>
/// <para>The AES block function comes from the platform (<see cref="Aes"/>); this class is only the wrapping loop. AES Key Wrap with
/// Padding (RFC 5649, SP 800-38F KWP), for data of any length, is in the platform as
/// <c>Aes.EncryptKeyWrapPadded</c> and <c>Aes.DecryptKeyWrapPadded</c>; use those, there is no second implementation here.</para>
/// <para>Unwrapping compares the recovered initial value with <see cref="CryptographicOperations.FixedTimeEquals"/>, and zeroes the
/// destination and reports failure if it differs. Input and output buffers must not overlap. An instance is not safe for concurrent
/// use. The platform AES key stays inside its own handle.</para>
/// </remarks>
public sealed class AesKeyWrap : IDisposable
{
    private const int Half = 8;

    // RFC 3394 §2.2.3.1: the default initial value.
    private static ReadOnlySpan<byte> DefaultIv => [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

    private readonly Aes _aes;
    private bool _disposed;

    /// <summary>The smallest key data that can be wrapped, in bytes (two 64-bit blocks, RFC 3394 §2).</summary>
    public const int MinKeyDataSize = 16;

    /// <summary>The number of bytes wrapping adds to the key data: the integrity block.</summary>
    public const int Overhead = Half;

    /// <summary>The largest key data accepted, in bytes. A wrap is 6n sequential AES calls, so this keeps one call bounded.</summary>
    public const int MaxKeyDataSize = 1 << 20;

    /// <summary>Creates a key-wrap instance for a key-encryption key.</summary>
    /// <param name="keyEncryptionKey">An AES key of 16, 24 or 32 bytes. It is copied; the caller still owns, and should zero, its own copy.</param>
    /// <exception cref="ArgumentException"><paramref name="keyEncryptionKey"/> is not a valid AES key size.</exception>
    /// <exception cref="PlatformNotSupportedException">The platform has no AES.</exception>
    public AesKeyWrap(ReadOnlySpan<byte> keyEncryptionKey)
    {
        AeadChecks.ValidateKey(keyEncryptionKey);
        _aes = Aes.Create();
        try
        {
            _aes.SetKey(keyEncryptionKey);
        }
        catch
        {
            _aes.Dispose();
            throw;
        }
    }

    /// <summary>Wraps key data (RFC 3394 §2.2.1).</summary>
    /// <param name="keyData">The key material: a multiple of 8 bytes, 16 to <see cref="MaxKeyDataSize"/>.</param>
    /// <param name="wrapped">Receives the wrapped key; exactly <paramref name="keyData"/> plus <see cref="Overhead"/> bytes. Must not overlap the input.</param>
    /// <exception cref="ArgumentException">A length is wrong, or the buffers overlap.</exception>
    /// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
    public void Wrap(ReadOnlySpan<byte> keyData, Span<byte> wrapped)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (keyData.Length is < MinKeyDataSize or > MaxKeyDataSize || keyData.Length % Half != 0)
        {
            throw new ArgumentException("Key data to wrap is a multiple of 8 bytes, at least 16.", nameof(keyData));
        }

        if (wrapped.Length != keyData.Length + Overhead)
        {
            throw new ArgumentException("The wrapped key is the key data plus 8 bytes.", nameof(wrapped));
        }

        if (keyData.Overlaps(wrapped))
        {
            throw new ArgumentException("The buffers must not overlap.", nameof(wrapped));
        }

        int n = keyData.Length / Half;
        DefaultIv.CopyTo(wrapped);
        keyData.CopyTo(wrapped[Half..]);
        Span<byte> block = stackalloc byte[2 * Half]; // fixed 16-byte buffer
        // For j = 0..5, i = 1..n: B = AES(A | R[i]); A = MSB64(B) xor t; R[i] = LSB64(B), with t = n*j + i (RFC 3394 §2.2.1)
        for (int j = 0; j < 6; j++)
        {
            for (int i = 1; i <= n; i++)
            {
                Span<byte> r = wrapped.Slice(i * Half, Half);
                wrapped[..Half].CopyTo(block);
                r.CopyTo(block[Half..]);
                _aes.EncryptEcb(block, block, PaddingMode.None);
                ulong t = (ulong)((n * j) + i);
                BinaryPrimitives.WriteUInt64BigEndian(wrapped, BinaryPrimitives.ReadUInt64BigEndian(block) ^ t);
                block[Half..].CopyTo(r);
            }
        }

        CryptographicOperations.ZeroMemory(block);
    }

    /// <summary>Unwraps key data and checks its integrity (RFC 3394 §2.2.2).</summary>
    /// <param name="wrapped">The wrapped key: a multiple of 8 bytes, at least 24.</param>
    /// <param name="keyData">Receives the key material; exactly <paramref name="wrapped"/> minus <see cref="Overhead"/> bytes. Must not overlap the input.</param>
    /// <exception cref="AuthenticationTagMismatchException">The integrity check failed; <paramref name="keyData"/> has been zeroed.</exception>
    /// <exception cref="ArgumentException">A length is wrong, or the buffers overlap.</exception>
    /// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
    public void Unwrap(ReadOnlySpan<byte> wrapped, Span<byte> keyData)
    {
        if (!TryUnwrap(wrapped, keyData))
        {
            throw new AuthenticationTagMismatchException();
        }
    }

    /// <summary>Like <see cref="Unwrap"/>, but reports a failed integrity check as <see langword="false"/> instead of throwing.</summary>
    /// <returns><see langword="true"/> if the integrity check passed; otherwise <see langword="false"/> and <paramref name="keyData"/> is zeroed.</returns>
    /// <exception cref="ArgumentException">A length is wrong, or the buffers overlap.</exception>
    /// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
    public bool TryUnwrap(ReadOnlySpan<byte> wrapped, Span<byte> keyData)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (wrapped.Length < MinKeyDataSize + Overhead || wrapped.Length > MaxKeyDataSize + Overhead || wrapped.Length % Half != 0)
        {
            throw new ArgumentException("A wrapped key is a multiple of 8 bytes, at least 24.", nameof(wrapped));
        }

        if (keyData.Length != wrapped.Length - Overhead)
        {
            throw new ArgumentException("The key data is the wrapped key minus 8 bytes.", nameof(keyData));
        }

        if (wrapped.Overlaps(keyData))
        {
            throw new ArgumentException("The buffers must not overlap.", nameof(keyData));
        }

        int n = keyData.Length / Half;
        Span<byte> a = stackalloc byte[Half]; // fixed buffers
        Span<byte> block = stackalloc byte[2 * Half];
        wrapped[..Half].CopyTo(a);
        wrapped[Half..].CopyTo(keyData);
        // For j = 5..0, i = n..1: B = AES^-1((A xor t) | R[i]); A = MSB64(B); R[i] = LSB64(B) (RFC 3394 §2.2.2)
        for (int j = 5; j >= 0; j--)
        {
            for (int i = n; i >= 1; i--)
            {
                Span<byte> r = keyData.Slice((i - 1) * Half, Half);
                ulong t = (ulong)((n * j) + i);
                BinaryPrimitives.WriteUInt64BigEndian(block, BinaryPrimitives.ReadUInt64BigEndian(a) ^ t);
                r.CopyTo(block[Half..]);
                _aes.DecryptEcb(block, block, PaddingMode.None);
                block[..Half].CopyTo(a);
                block[Half..].CopyTo(r);
            }
        }

        // RFC 3394 §2.2.2: the integrity check is that A equals the initial value; the comparison is constant-time.
        bool valid = CryptographicOperations.FixedTimeEquals(a, DefaultIv);
        CryptographicOperations.ZeroMemory(a);
        CryptographicOperations.ZeroMemory(block);
        if (!valid)
        {
            CryptographicOperations.ZeroMemory(keyData);
        }

        return valid;
    }

    /// <summary>Releases the platform key. Safe to call more than once.</summary>
    public void Dispose()
    {
        _disposed = true;
        _aes.Dispose();
    }
}
