using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Internal;

/// <summary>
/// The platform's AES, held as long-lived ECB (and optionally CBC) transforms with a fixed working buffer, for the block-cipher modes.
/// </summary>
/// <remarks>
/// The one-shot <c>Aes.EncryptEcb</c> sets up a cipher context and key schedule on every call, which costs more than the AES of a
/// short message. A transform keeps both, so each call here is only the cipher. The transform API takes arrays, so the engine owns one
/// array that callers fill, transform in place and read back. Not safe for concurrent use. The buffer holds message data, not key
/// material; callers zero the used part when they finish. The key stays inside the platform's handle.
/// </remarks>
internal sealed class AesBlockEngine : IDisposable
{
    private readonly Aes _aes;
    private readonly ICryptoTransform _encryptor;
    private readonly ICryptoTransform? _decryptor;
    private readonly ICryptoTransform? _cbcEncryptor;
    private readonly byte[] _buffer;

    /// <summary>Creates an engine for an AES key.</summary>
    /// <param name="key">16, 24 or 32 bytes.</param>
    /// <param name="bufferBytes">The size of the working buffer, a multiple of 16.</param>
    /// <param name="needDecrypt">Whether to keep an ECB decryptor.</param>
    /// <param name="needCbcEncrypt">Whether to keep a CBC encryptor, whose chaining value starts at zero and carries from call to call.</param>
    public AesBlockEngine(ReadOnlySpan<byte> key, int bufferBytes, bool needDecrypt, bool needCbcEncrypt)
    {
        AeadChecks.ValidateKey(key);
        // TODO: on a platform with no AES (the browser), Aes.Create throws PlatformNotSupportedException here and in the three mode
        // constructors. Replace it with the library-wide AlgorithmNotSupported exception, naming the algorithm and the platform, once
        // that exception type exists, and update the exception tags in the XML docs of AesOcb, AesEax and AesKeyWrap with it.
        _buffer = new byte[bufferBytes];
        _aes = Aes.Create();
        try
        {
            _aes.SetKey(key);
            _aes.Padding = PaddingMode.None;
            _aes.Mode = CipherMode.ECB;
            _encryptor = _aes.CreateEncryptor();
            if (needDecrypt)
            {
                _decryptor = _aes.CreateDecryptor();
            }

            if (needCbcEncrypt)
            {
                _aes.Mode = CipherMode.CBC;
                _aes.IV = new byte[16];
                _cbcEncryptor = _aes.CreateEncryptor();
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>The working buffer. Fill the first <c>count</c> bytes, then call one of the transforms with that count.</summary>
    public Span<byte> Buffer => _buffer;

    /// <summary>Encrypts the first <paramref name="count"/> bytes of <see cref="Buffer"/> in place, block by block (ECB).</summary>
    public void Encrypt(int count) => Transform(_encryptor, count);

    /// <summary>Decrypts the first <paramref name="count"/> bytes of <see cref="Buffer"/> in place, block by block (ECB).</summary>
    public void Decrypt(int count) => Transform(_decryptor ?? throw new InvalidOperationException("No decryptor."), count);

    /// <summary>
    /// CBC-encrypts the first <paramref name="count"/> bytes of <see cref="Buffer"/> in place. The chaining value is the last output block of
    /// the previous call (zero at the start), so the first block's effective input is that block XOR the previous chaining value.
    /// </summary>
    public void CbcEncrypt(int count) => Transform(_cbcEncryptor ?? throw new InvalidOperationException("No CBC encryptor."), count);

    private void Transform(ICryptoTransform transform, int count)
    {
        // Callers pass a whole number of blocks that fits the buffer; the transform would throw otherwise.
        int written = transform.TransformBlock(_buffer, 0, count, _buffer, 0);
        if (written != count)
        {
            throw new CryptographicException("The platform AES returned a short block.");
        }
    }

    /// <summary>Zeroes the buffer and releases the platform key. Safe to call more than once.</summary>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_buffer);
        _encryptor?.Dispose();
        _decryptor?.Dispose();
        _cbcEncryptor?.Dispose();
        _aes.Dispose();
    }
}
