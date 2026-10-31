using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// The Camellia block cipher (RFC 3713) with 128-, 192- and 256-bit keys, with the modes OpenPGP and CMS use: ECB, CBC (RFC 3657)
/// and CFB, as span one-shots shaped like the platform's <see cref="Aes"/>.
/// </summary>
/// <remarks>
/// <para>The platform has no Camellia. Camellia indexes an 8-bit S-box with secret bytes, so the implementation does not use table
/// indexing: it reads the whole table through byte shuffles and selects by mask, which keeps memory access and timing independent of
/// the data and the key (see the timing notes in the documentation). That costs speed against a table-driven implementation.</para>
/// <para>The key schedule is held in pinned arrays that <see cref="Dispose"/> zeroes. An instance is not safe for concurrent use.
/// Source and destination spans may be the same span (in place) or must not overlap; calls do not allocate.</para>
/// <para>ECB is exposed for building other modes and for test vectors; it does not hide patterns and should not be used to protect data.</para>
/// </remarks>
public sealed class Camellia : IDisposable
{
    private readonly CamelliaEngine _engine;

    /// <summary>The block size in bytes, 16.</summary>
    public const int BlockSize = 16;

    /// <summary>Creates a cipher for a key.</summary>
    /// <param name="key">16, 24 or 32 bytes. It is copied into the key schedule; the caller owns, and should zero, its own copy.</param>
    /// <exception cref="ArgumentException">The key is not 16, 24 or 32 bytes.</exception>
    public Camellia(ReadOnlySpan<byte> key) => _engine = new CamelliaEngine(key);

    /// <summary>Encrypts whole blocks independently (ECB).</summary>
    /// <param name="source">Plaintext, a multiple of 16 bytes.</param>
    /// <param name="destination">At least as long as <paramref name="source"/>.</param>
    /// <exception cref="ArgumentException">A length is wrong, or the spans partly overlap.</exception>
    public void EncryptEcb(ReadOnlySpan<byte> source, Span<byte> destination) => BlockModes.Ecb(_engine, false, source, destination);

    /// <summary>Decrypts whole blocks independently (ECB).</summary>
    /// <param name="source">Ciphertext, a multiple of 16 bytes.</param>
    /// <param name="destination">At least as long as <paramref name="source"/>.</param>
    /// <exception cref="ArgumentException">A length is wrong, or the spans partly overlap.</exception>
    public void DecryptEcb(ReadOnlySpan<byte> source, Span<byte> destination) => BlockModes.Ecb(_engine, true, source, destination);

    /// <summary>Encrypts in CBC mode (RFC 3657 for CMS).</summary>
    /// <param name="source">Plaintext. With <see cref="PaddingMode.None"/> a multiple of 16 bytes.</param>
    /// <param name="iv">The 16-byte initialisation vector; never reuse one under a key.</param>
    /// <param name="destination">With PKCS #7 padding, at least the source length rounded down to a block plus 16 bytes.</param>
    /// <param name="padding"><see cref="PaddingMode.PKCS7"/> (the default, RFC 5652 section 6.3) or <see cref="PaddingMode.None"/>.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">A length is wrong, or with padding the spans overlap.</exception>
    /// <exception cref="NotSupportedException">Another padding mode.</exception>
    public int EncryptCbc(ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode padding = PaddingMode.PKCS7)
        => BlockModes.CbcEncrypt(_engine, source, iv, destination, padding);

    /// <summary>Decrypts in CBC mode. Padding is checked without early exit; on failure nothing is released.</summary>
    /// <param name="source">Ciphertext, a multiple of 16 bytes.</param>
    /// <param name="iv">The 16-byte initialisation vector.</param>
    /// <param name="destination">At least as long as <paramref name="source"/>; may be the source.</param>
    /// <param name="padding"><see cref="PaddingMode.PKCS7"/> (the default) or <see cref="PaddingMode.None"/>.</param>
    /// <returns>The number of plaintext bytes at the start of <paramref name="destination"/>.</returns>
    /// <exception cref="CryptographicException">The padding is invalid; <paramref name="destination"/> is zeroed.</exception>
    /// <exception cref="ArgumentException">A length is wrong, or the spans partly overlap.</exception>
    public int DecryptCbc(ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode padding = PaddingMode.PKCS7)
        => BlockModes.CbcDecrypt(_engine, source, iv, destination, padding);

    /// <summary>Encrypts in CFB mode with a 128-bit segment. The last block may be short.</summary>
    /// <param name="source">Plaintext of any length.</param>
    /// <param name="iv">The 16-byte initialisation vector. OpenPGP data (RFC 9580 section 13.9) uses all zeros and a random prefix in the data.</param>
    /// <param name="destination">At least as long as <paramref name="source"/>.</param>
    /// <exception cref="ArgumentException">A length is wrong, or the spans partly overlap.</exception>
    public void EncryptCfb(ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination) => BlockModes.Cfb(_engine, false, source, iv, destination);

    /// <summary>Decrypts in CFB mode with a 128-bit segment. The last block may be short.</summary>
    /// <param name="source">Ciphertext of any length.</param>
    /// <param name="iv">The 16-byte initialisation vector.</param>
    /// <param name="destination">At least as long as <paramref name="source"/>.</param>
    /// <exception cref="ArgumentException">A length is wrong, or the spans partly overlap.</exception>
    public void DecryptCfb(ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination) => BlockModes.Cfb(_engine, true, source, iv, destination);

    /// <summary>
    /// Decrypts OpenPGP CFB data: zero IV over the random prefix and the data. The prefix and its two check bytes are decrypted too and
    /// left for the caller to verify.
    /// </summary>
    /// <param name="source">Ciphertext, at least 18 bytes with <paramref name="resync"/>.</param>
    /// <param name="destination">At least as long as <paramref name="source"/>.</param>
    /// <param name="resync"><see langword="false"/> for protected data (RFC 9580 section 13.9); <see langword="true"/> for the older
    /// unprotected packet, whose feedback register is reloaded after the prefix (RFC 4880 section 13.9).</param>
    /// <exception cref="ArgumentException">A length is wrong, or the spans partly overlap.</exception>
    public void DecryptOpenPgpCfb(ReadOnlySpan<byte> source, Span<byte> destination, bool resync = false) => BlockModes.OpenPgpCfbDecrypt(_engine, source, destination, resync);

    /// <summary>Zeroes the key schedule. Safe to call more than once.</summary>
    public void Dispose() => _engine.Dispose();
}
