using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// Argon2's compression function G on 256-bit vectors (RFC 9106 sections 3.5 and 3.6). One row of the 8 x 8 block of 16-byte
/// registers is the 4 x 4 matrix of 64-bit words the BLAKE2b round works on, so its four rows fit four vectors: the column step of
/// the round is one vector operation per line of GB, and the diagonal step is the same after rotating the lanes of three of the
/// vectors. The scalar version in <see cref="Argon2"/> is the reference; this one must give identical output (the tests compare them).
/// </summary>
/// <remarks>
/// Used only where AVX2 is available, chosen once from <see cref="Avx2.IsSupported"/>. No branch or index depends on the data:
/// it is straight-line arithmetic under loops whose counters depend only on the fixed block layout.
/// </remarks>
internal static class Argon2Avx2
{
    private const int BlockWords = 128;

    internal static bool IsSupported => Avx2.IsSupported;

    /// <summary>
    /// destination = G(x, y), or destination ^= G(x, y) when <paramref name="xorDestination"/> is set. <paramref name="r"/> and
    /// <paramref name="scratch"/> are 128-word work areas.
    /// </summary>
    // Bounds: every span is checked to hold 128 words on entry, and every offset below stays under 128 (loops over 4-word steps up
    // to 128, rows at 16 * row + up to 15, columns at 2 * column + up to 112 + 1), so the unchecked loads and stores stay inside.
    [MethodImpl(MethodImplOptions.NoInlining)]
    internal static void Compress(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> destination, Span<ulong> r, Span<ulong> scratch, bool xorDestination)
    {
        if (x.Length < BlockWords || y.Length < BlockWords || destination.Length < BlockWords || r.Length < BlockWords || scratch.Length < BlockWords)
        {
            throw new ArgumentException("Argon2 blocks are 128 words.");
        }

        Span<ulong> z = xorDestination ? scratch : destination;
        ref ulong px = ref MemoryMarshal.GetReference(x);
        ref ulong py = ref MemoryMarshal.GetReference(y);
        ref ulong pr = ref MemoryMarshal.GetReference(r);
        ref ulong pz = ref MemoryMarshal.GetReference(z);
        ref ulong pd = ref MemoryMarshal.GetReference(destination);

        // R = X xor Y, and Z starts as R.
        for (nuint i = 0; i < BlockWords; i += 4)
        {
            Vector256<ulong> v = Vector256.LoadUnsafe(ref px, i) ^ Vector256.LoadUnsafe(ref py, i);
            v.StoreUnsafe(ref pr, i);
            v.StoreUnsafe(ref pz, i);
        }

        // P on each row of eight registers: sixteen consecutive words.
        for (nuint row = 0; row < 8; row++)
        {
            nuint o = row * 16;
            Vector256<ulong> a = Vector256.LoadUnsafe(ref pz, o);
            Vector256<ulong> b = Vector256.LoadUnsafe(ref pz, o + 4);
            Vector256<ulong> c = Vector256.LoadUnsafe(ref pz, o + 8);
            Vector256<ulong> d = Vector256.LoadUnsafe(ref pz, o + 12);
            Round(ref a, ref b, ref c, ref d);
            a.StoreUnsafe(ref pz, o);
            b.StoreUnsafe(ref pz, o + 4);
            c.StoreUnsafe(ref pz, o + 8);
            d.StoreUnsafe(ref pz, o + 12);
        }

        // P on each column: the register at 2 * column of every row. Registers 0-1 of the round are rows 0-1 of the column, so each
        // vector takes two 16-byte pieces that sit 16 words apart.
        for (nuint column = 0; column < 8; column++)
        {
            nuint o = column * 2;
            Vector256<ulong> a = Vector256.Create(Vector128.LoadUnsafe(ref pz, o), Vector128.LoadUnsafe(ref pz, o + 16));
            Vector256<ulong> b = Vector256.Create(Vector128.LoadUnsafe(ref pz, o + 32), Vector128.LoadUnsafe(ref pz, o + 48));
            Vector256<ulong> c = Vector256.Create(Vector128.LoadUnsafe(ref pz, o + 64), Vector128.LoadUnsafe(ref pz, o + 80));
            Vector256<ulong> d = Vector256.Create(Vector128.LoadUnsafe(ref pz, o + 96), Vector128.LoadUnsafe(ref pz, o + 112));
            Round(ref a, ref b, ref c, ref d);
            a.GetLower().StoreUnsafe(ref pz, o);
            a.GetUpper().StoreUnsafe(ref pz, o + 16);
            b.GetLower().StoreUnsafe(ref pz, o + 32);
            b.GetUpper().StoreUnsafe(ref pz, o + 48);
            c.GetLower().StoreUnsafe(ref pz, o + 64);
            c.GetUpper().StoreUnsafe(ref pz, o + 80);
            d.GetLower().StoreUnsafe(ref pz, o + 96);
            d.GetUpper().StoreUnsafe(ref pz, o + 112);
        }

        // G outputs Z xor R; later passes also xor the old block.
        for (nuint i = 0; i < BlockWords; i += 4)
        {
            Vector256<ulong> v = Vector256.LoadUnsafe(ref pz, i) ^ Vector256.LoadUnsafe(ref pr, i);
            if (xorDestination)
            {
                v ^= Vector256.LoadUnsafe(ref pd, i);
            }

            v.StoreUnsafe(ref pd, i);
        }
    }

    // One application of P: GB on the four columns of the 4 x 4 matrix, then on its four diagonals, which are columns after
    // rotating the second, third and fourth rows left by one, two and three lanes.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round(ref Vector256<ulong> a, ref Vector256<ulong> b, ref Vector256<ulong> c, ref Vector256<ulong> d)
    {
        Gb(ref a, ref b, ref c, ref d);
        b = Avx2.Permute4x64(b, 0x39);
        c = Avx2.Permute4x64(c, 0x4E);
        d = Avx2.Permute4x64(d, 0x93);
        Gb(ref a, ref b, ref c, ref d);
        b = Avx2.Permute4x64(b, 0x93);
        c = Avx2.Permute4x64(c, 0x4E);
        d = Avx2.Permute4x64(d, 0x39);
    }

    // GB of RFC 9106 section 3.6 on four lanes at once; MulLow is trunc(a) * trunc(b), the 32 x 32 -> 64-bit product.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Gb(ref Vector256<ulong> a, ref Vector256<ulong> b, ref Vector256<ulong> c, ref Vector256<ulong> d)
    {
        a = a + b + Twice(MulLow(a, b));
        d = Rotate32(d ^ a);
        c = c + d + Twice(MulLow(c, d));
        Vector256<ulong> t = b ^ c;
        b = Vector256.ShiftRightLogical(t, 24) | Vector256.ShiftLeft(t, 40);
        a = a + b + Twice(MulLow(a, b));
        t = d ^ a;
        d = Vector256.ShiftRightLogical(t, 16) | Vector256.ShiftLeft(t, 48);
        c = c + d + Twice(MulLow(c, d));
        t = b ^ c;
        b = Vector256.ShiftRightLogical(t, 63) | Vector256.ShiftLeft(t, 1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> MulLow(Vector256<ulong> a, Vector256<ulong> b) => Avx2.Multiply(a.AsUInt32(), b.AsUInt32());

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> Twice(Vector256<ulong> v) => v + v;

    // Rotate each 64-bit lane right by 32: swap its two 32-bit halves.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> Rotate32(Vector256<ulong> v) => Avx2.Shuffle(v.AsUInt32(), 0xB1).AsUInt64();
}
