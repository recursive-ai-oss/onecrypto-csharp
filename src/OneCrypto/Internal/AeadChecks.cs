namespace RecursiveAI.OneCrypto.Internal;

/// <summary>Argument checks shared by the AES modes in <c>Primitives</c>, so that they reject the same inputs the same way.</summary>
internal static class AeadChecks
{
    /// <summary>Requires an AES key of 16, 24 or 32 bytes.</summary>
    public static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new ArgumentException("An AES key is 16, 24 or 32 bytes.", nameof(key));
        }
    }

    /// <summary>
    /// Requires equal lengths, and that the buffers are either the same span (in place) or do not overlap at all. A partial overlap
    /// would let output bytes overwrite input bytes that have not been read yet.
    /// </summary>
    public static void ValidateBuffers(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length != output.Length)
        {
            throw new ArgumentException("The input and output must be the same length.", nameof(output));
        }

        if (input.Overlaps(output, out int offset) && offset != 0)
        {
            throw new ArgumentException("The input and output may be the same buffer or disjoint, not partly overlapping.", nameof(output));
        }
    }
}
