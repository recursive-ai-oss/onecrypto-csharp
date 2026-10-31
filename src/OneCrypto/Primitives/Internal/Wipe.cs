using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>Zeroes working memory that held secrets, including arrays whose byte length does not fit in a span.</summary>
internal static class Wipe
{
    // Chunks of 1 MiB keep each byte span far below the 2 GiB span limit; AsBytes on a whole multi-gigabyte array would overflow.
    private const int ChunkBytes = 1 << 20;

    public static void Array(ulong[] array)
    {
        const int Chunk = ChunkBytes / sizeof(ulong);
        for (int offset = 0; offset < array.Length; offset += Chunk)
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(array.AsSpan(offset, Math.Min(Chunk, array.Length - offset))));
        }
    }

    public static void Array(uint[] array)
    {
        const int Chunk = ChunkBytes / sizeof(uint);
        for (int offset = 0; offset < array.Length; offset += Chunk)
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(array.AsSpan(offset, Math.Min(Chunk, array.Length - offset))));
        }
    }
}
