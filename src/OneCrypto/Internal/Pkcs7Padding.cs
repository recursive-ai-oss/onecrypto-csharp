namespace RecursiveAI.OneCrypto.Internal;

/// <summary>
/// PKCS #7 padding removal for CBC (RFC 5652 §6.3) without a secret-dependent branch, loop bound or exception. The platform's own unpadding
/// raises an exception on the bad-padding path only, which costs measurably more than the good path and so tells a caller who can time
/// the answer whether the padding was valid (the classic CBC padding oracle, RFC 3218 §2.3). Here the decrypted last block is read in full
/// whatever its content, every check is folded into one mask, and the verdict leaves through one return.
/// </summary>
internal static class Pkcs7Padding
{
    /// <summary>
    /// The length of the data without its padding, or -1 when the padding is not valid. <paramref name="decrypted"/> is the whole decrypted
    /// CBC message (a non-empty multiple of <paramref name="block"/> octets; both lengths are public). The work is the same for every
    /// content of the final block.
    /// </summary>
    internal static int UnpaddedLength(ReadOnlySpan<byte> decrypted, int block)
    {
        int n = decrypted.Length;
        if (n < block || n % block != 0)
        {
            return -1; // public lengths
        }

        uint pad = decrypted[n - 1];
        uint bad = IsZero(pad); // pad == 0
        uint over = (uint)(block - (int)pad) >> 31; // 1 when pad > block
        bad |= over;
        pad ^= (pad ^ (uint)block) & (0 - over); // keep the arithmetic below inside 1..block whatever the octet was
        for (int i = 0; i < block; i++)
        {
            uint inPad = (uint)(i - (int)pad) >> 31; // 1 when i < pad
            bad |= (0 - inPad) & (uint)(decrypted[n - 1 - i] ^ (byte)pad);
        }

        // -1 when bad, else the unpadded length, selected with a mask.
        int mask = -(int)((bad | (0 - bad)) >> 31);
        return ((n - (int)pad) & ~mask) | mask;
    }

    /// <summary>1 when the value is zero, else 0, without a branch.</summary>
    private static uint IsZero(uint v) => ((v | (0 - v)) >> 31) ^ 1;
}
