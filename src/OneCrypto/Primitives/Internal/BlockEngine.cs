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

    /// <summary>Encrypts two consecutive blocks (32 bytes); engines that can work on two blocks at once override it.</summary>
    internal virtual void EncryptTwoBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        EncryptBlock(source[..BlockSize], destination[..BlockSize]);
        EncryptBlock(source.Slice(BlockSize, BlockSize), destination.Slice(BlockSize, BlockSize));
    }

    /// <summary>Decrypts two consecutive blocks; see <see cref="EncryptTwoBlocks"/>. Only used for 16-byte blocks.</summary>
    internal virtual void DecryptTwoBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        DecryptBlock(source[..BlockSize], destination[..BlockSize]);
        DecryptBlock(source.Slice(BlockSize, BlockSize), destination.Slice(BlockSize, BlockSize));
    }

    /// <summary>Zeroes the key schedule.</summary>
    public abstract void Dispose();
}
