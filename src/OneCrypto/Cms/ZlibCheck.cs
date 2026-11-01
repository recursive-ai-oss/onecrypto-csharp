using System.Buffers.Binary;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// The Adler-32 checksum of RFC 1950 §8.2, used to decide whether a zlib stream arrived whole. The platform's inflater reports a stream that ends early as
/// a normal end of data, and CMS content is a bare OCTET STRING with no framing inside it, so nothing else would notice a missing tail.
/// </summary>
internal sealed class Adler32
{
    private const uint Modulus = 65521;
    private const int MaxRun = 5552; // the most octets that cannot overflow 32 bits before the reduction
    private uint _a = 1;
    private uint _b;

    public void Update(ReadOnlySpan<byte> data)
    {
        while (!data.IsEmpty)
        {
            int n = Math.Min(MaxRun, data.Length);
            for (int i = 0; i < n; i++)
            {
                _a += data[i];
                _b += _a;
            }

            _a %= Modulus;
            _b %= Modulus;
            data = data[n..];
        }
    }

    public uint Value => (_b << 16) | _a;

    /// <summary>
    /// RFC 1950 §2.2: a complete stream is a two-octet header, the deflate data and the big-endian Adler-32 of the uncompressed data. True when the compressed
    /// octets are long enough to hold all three and their last four octets are the checksum of what was inflated; a stream cut short ends in deflate
    /// data, which matches only by a one-in-2^32 chance.
    /// </summary>
    public bool Completes(long compressedLength, ReadOnlySpan<byte> lastFour) =>
        compressedLength >= 6 && lastFour.Length == 4 && BinaryPrimitives.ReadUInt32BigEndian(lastFour) == Value;
}
