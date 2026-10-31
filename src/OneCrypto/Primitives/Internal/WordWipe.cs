using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>Zeroes word arrays that held key material.</summary>
internal static class WordWipe
{
    /// <summary>Zeroes the whole span. The cast covers exactly the bytes of the span, so there is no bound to get wrong.</summary>
    internal static void Clear(Span<uint> words) => CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(words));

    /// <summary>Zeroes the whole span.</summary>
    internal static void Clear(Span<ulong> words) => CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(words));
}
