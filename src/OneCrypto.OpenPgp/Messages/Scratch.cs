using System.Buffers;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// Pooled copy buffers for the streaming loops. Small messages would otherwise allocate a 64 KiB array per call; the buffers can hold plaintext,
/// so they are cleared when handed back. A buffer abandoned by an exception is simply left to the collector.
/// </summary>
internal static class Scratch
{
    internal const int Size = 64 * 1024;

    internal static byte[] Rent() => ArrayPool<byte>.Shared.Rent(Size);

    internal static void Return(byte[] buffer) => ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
}
