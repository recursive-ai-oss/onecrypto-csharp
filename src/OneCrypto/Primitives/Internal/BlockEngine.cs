namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// A block cipher under one key. Engines own the key schedule and the two block directions; the modes (ECB, CBC, CFB and the
/// OpenPGP variant) are written once in <see cref="BlockModes"/>. The ciphers whose encryption is not offered publicly still need
/// <see cref="EncryptBlock"/> internally, because CFB decryption runs the block function forwards.
/// </summary>
internal abstract class BlockEngine : IDisposable
{
    /// <summary>The block size in bytes: 8 or 16.</summary>
    internal abstract int BlockSize { get; }

    /// <summary>Encrypts one block. <paramref name="source"/> and <paramref name="destination"/> are exactly one block and may be the same span.</summary>
    internal abstract void EncryptBlock(ReadOnlySpan<byte> source, Span<byte> destination);

    /// <summary>Decrypts one block. <paramref name="source"/> and <paramref name="destination"/> are exactly one block and may be the same span.</summary>
    internal abstract void DecryptBlock(ReadOnlySpan<byte> source, Span<byte> destination);

    /// <summary>Zeroes the key schedule.</summary>
    public abstract void Dispose();
}
