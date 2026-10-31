using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// CAST5 (CAST-128, RFC 2144), for decryption only: a legacy cipher that OneCrypto reads but never writes. Old OpenPGP messages (cipher 3) and some PKCS #12 files use it.
/// </summary>
/// <remarks>
/// <para>There is deliberately no encryption method. CFB decryption runs the block function forwards, so the engine can encrypt
/// internally, but that is not part of the public surface.</para>
/// <para>The implementation avoids secret-indexed table lookups (see the timing notes in the documentation), which makes it slower than a
/// table-driven one. The key schedule is held in pinned arrays that <see cref="Dispose"/> zeroes. An instance is not safe for
/// concurrent use. Source and destination spans may be the same span (in place) or must not overlap; calls do not allocate.</para>
/// </remarks>
public sealed class Cast5 : IDisposable
{
    private readonly Cast5Engine _engine;

    /// <summary>The block size in bytes, 8.</summary>
    public const int BlockSize = 8;

    /// <summary>Creates a decryptor for a key.</summary>
    /// <param name="key">A key of 5 to 16 bytes. It is copied into the key schedule; the caller owns, and should zero, its own copy.</param>
    /// <exception cref="ArgumentException">The key is not 5 to 16 bytes.</exception>
    public Cast5(ReadOnlySpan<byte> key) => _engine = new Cast5Engine(key);

    /// <summary>Decrypts whole blocks independently (ECB).</summary>
    /// <param name="source">Ciphertext, a multiple of 8 bytes.</param>
    /// <param name="destination">At least as long as <paramref name="source"/>.</param>
    /// <exception cref="ArgumentException">A length is wrong, or the spans partly overlap.</exception>
    public void DecryptEcb(ReadOnlySpan<byte> source, Span<byte> destination) => BlockModes.Ecb(_engine, true, source, destination);

    /// <summary>Decrypts in CBC mode. Padding is checked without early exit; on failure nothing is released.</summary>
    /// <param name="source">Ciphertext, a multiple of 8 bytes.</param>
    /// <param name="iv">The 8-byte initialisation vector.</param>
    /// <param name="destination">At least as long as <paramref name="source"/>; may be the source.</param>
    /// <param name="padding"><see cref="PaddingMode.PKCS7"/> (the default) or <see cref="PaddingMode.None"/>.</param>
    /// <returns>The number of plaintext bytes at the start of <paramref name="destination"/>.</returns>
    /// <exception cref="CryptographicException">The padding is invalid; <paramref name="destination"/> is zeroed.</exception>
    /// <exception cref="ArgumentException">A length is wrong, or the spans partly overlap.</exception>
    public int DecryptCbc(ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode padding = PaddingMode.PKCS7)
        => BlockModes.CbcDecrypt(_engine, source, iv, destination, padding);

    /// <summary>Decrypts in CFB mode with a full-block segment. The last block may be short.</summary>
    /// <param name="source">Ciphertext of any length.</param>
    /// <param name="iv">The 8-byte initialisation vector.</param>
    /// <param name="destination">At least as long as <paramref name="source"/>.</param>
    /// <exception cref="ArgumentException">A length is wrong, or the spans partly overlap.</exception>
    public void DecryptCfb(ReadOnlySpan<byte> source, ReadOnlySpan<byte> iv, Span<byte> destination) => BlockModes.Cfb(_engine, true, source, iv, destination);

    /// <summary>
    /// Decrypts OpenPGP CFB data: zero IV over the random prefix and the data. The prefix and its two check bytes are decrypted too and
    /// left for the caller to verify.
    /// </summary>
    /// <param name="source">Ciphertext, at least 10 bytes with <paramref name="resync"/>.</param>
    /// <param name="destination">At least as long as <paramref name="source"/>.</param>
    /// <param name="resync"><see langword="false"/> for protected data (RFC 9580 section 13.9); <see langword="true"/> for the older
    /// unprotected packet, whose feedback register is reloaded after the prefix (RFC 4880 section 13.9).</param>
    /// <exception cref="ArgumentException">A length is wrong, or the spans partly overlap.</exception>
    public void DecryptOpenPgpCfb(ReadOnlySpan<byte> source, Span<byte> destination, bool resync = false) => BlockModes.OpenPgpCfbDecrypt(_engine, source, destination, resync);

    /// <summary>Zeroes the key schedule. Safe to call more than once.</summary>
    public void Dispose() => _engine.Dispose();
}
