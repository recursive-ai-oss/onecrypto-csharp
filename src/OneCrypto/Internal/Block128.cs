using System.Buffers.Binary;
using System.Runtime.Intrinsics;

namespace RecursiveAI.OneCrypto.Internal;

/// <summary>
/// 128-bit block helpers shared by the block-cipher modes (OCB, EAX). Everything here is safe, bounds-checked C#; the XOR work uses the
/// fixed-width <see cref="Vector128{T}"/>, which has a software fallback on platforms without SIMD.
/// </summary>
internal static class Block128
{
    /// <summary>The block size of AES, in bytes.</summary>
    public const int Size = 16;

    /// <summary>Loads 16 bytes from the start of <paramref name="source"/>.</summary>
    public static Vector128<byte> Load(ReadOnlySpan<byte> source) => Vector128.Create(source);

    /// <summary>
    /// Doubling in GF(2^128) with the polynomial x^128 + x^7 + x^2 + x + 1 (RFC 7253 §2 <c>double</c>; the same operation scales the
    /// CMAC subkeys). The block is secret-derived, so the reduction is selected with a mask, never a branch.
    /// </summary>
    public static void Double(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        ulong hi = BinaryPrimitives.ReadUInt64BigEndian(source);
        ulong lo = BinaryPrimitives.ReadUInt64BigEndian(source[8..]);
        ulong reduce = 0x87UL & (0UL - (hi >> 63));
        BinaryPrimitives.WriteUInt64BigEndian(destination, (hi << 1) | (lo >> 63));
        BinaryPrimitives.WriteUInt64BigEndian(destination[8..], (lo << 1) ^ reduce);
    }

    /// <summary>
    /// Adds one to a 128-bit big-endian counter, wrapping at 2^128 (the counter of EAX's CTR mode, EAX paper §2 <c>X+t</c>).
    /// The counter is secret-derived, so the carry is computed arithmetically.
    /// </summary>
    public static void Increment(Span<byte> counter)
    {
        ulong hi = BinaryPrimitives.ReadUInt64BigEndian(counter);
        ulong lo = BinaryPrimitives.ReadUInt64BigEndian(counter[8..]);
        lo++;
        // carry is 1 exactly when the low half wrapped to zero: (lo | -lo) has its top bit set for every non-zero lo.
        hi += ((lo | (0UL - lo)) >> 63) ^ 1UL;
        BinaryPrimitives.WriteUInt64BigEndian(counter, hi);
        BinaryPrimitives.WriteUInt64BigEndian(counter[8..], lo);
    }
}
