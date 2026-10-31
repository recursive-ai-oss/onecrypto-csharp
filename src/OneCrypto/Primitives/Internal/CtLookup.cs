using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace RecursiveAI.OneCrypto.Primitives.Internal;

/// <summary>
/// Table lookups whose index is secret. A direct <c>table[index]</c> touches a cache line that depends on the index, which a
/// co-resident observer can learn; these read every entry of the table, whatever the index, and keep the one that matches.
/// </summary>
internal static class CtLookup
{
    /// <summary>The number of entries a table passed to <see cref="Word"/> has (an 8-bit index).</summary>
    internal const int Entries = 256;

    /// <summary>
    /// Returns <c>table[index]</c> for a 256-entry table of 32-bit words by comparing the index with every position, with no
    /// secret-dependent address, branch or loop bound. The platform's widest fixed-width vector does the comparing; where there is
    /// no vector hardware the same operations run in software, so the result and the access pattern do not change.
    /// </summary>
    /// <param name="table">At least 256 words; only the first 256 are read.</param>
    /// <param name="index">The secret index, 0 to 255.</param>
    [MethodImpl(MethodImplOptions.NoInlining)]
    internal static uint Word(ReadOnlySpan<uint> table, uint index)
    {
        if (Vector256.IsHardwareAccelerated)
        {
            Vector256<uint> wanted = Vector256.Create(index);
            Vector256<uint> position = Vector256.Create(0u, 1, 2, 3, 4, 5, 6, 7);
            Vector256<uint> step = Vector256.Create(8u);
            Vector256<uint> found = Vector256<uint>.Zero;
            for (int i = 0; i < Entries; i += 8)
            {
                found |= Vector256.Equals(position, wanted) & Vector256.Create(table.Slice(i, 8));
                position += step;
            }

            return Vector256.Sum(found); // exactly one position matched, so the sum is that entry
        }
        else
        {
            Vector128<uint> wanted = Vector128.Create(index);
            Vector128<uint> position = Vector128.Create(0u, 1, 2, 3);
            Vector128<uint> step = Vector128.Create(4u);
            Vector128<uint> found = Vector128<uint>.Zero;
            for (int i = 0; i < Entries; i += 4)
            {
                found |= Vector128.Equals(position, wanted) & Vector128.Create(table.Slice(i, 4));
                position += step;
            }

            return Vector128.Sum(found);
        }
    }
}
