using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// A 16-entry byte table lookup for 16 lanes at once. <c>Vector128.Shuffle</c> with indices the compiler cannot bound has to add
/// a range fix-up to every call; the table-lookup instructions of the two common architectures already return zero for an index
/// outside the table (a byte with its top bit set on x86, 16 and above on Arm), which is exactly the behaviour wanted, so they are
/// used directly. The choice of instruction is made from the platform's capabilities, which the compiler folds at compile time.
/// </summary>
internal static class ByteShuffle
{
    /// <summary>
    /// <c>result[i] = table[index[i]]</c> for an index of 0 to 15, and 0 for an index of 0x80 (the callers use no other value above 15).
    /// The lookup has no data-dependent timing or address on any of the three paths.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static Vector128<byte> Lookup(Vector128<byte> table, Vector128<byte> index)
    {
        if (Ssse3.IsSupported)
        {
            return Ssse3.Shuffle(table, index);
        }

        if (AdvSimd.Arm64.IsSupported)
        {
            return AdvSimd.Arm64.VectorTableLookup(table, index);
        }

        return Vector128.Shuffle(table, index);
    }
}
