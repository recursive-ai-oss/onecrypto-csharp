using System.Globalization;
using System.Security.Cryptography;
using OnePdf;

namespace RecursiveAI.OneCrypto.Pdf;

/// <summary>Where a signature's pieces sit in the file bytes, and a few encodings shared by the signer and the verifier.</summary>
internal static class PdfLayout
{
    /// <summary>
    /// Reads the /ByteRange of a signature (ISO 32000-2 §12.8.1: <c>[0 a b c]</c>, the first range is [0, a), the second [b, b+c), the
    /// hole [a, b) is the hex string of /Contents with its angle brackets). False unless the numbers describe a hole inside the file
    /// that holds a hex string.
    /// </summary>
    public static bool TryRanges(PdfSignature signature, ReadOnlySpan<byte> file, out long a, out long b, out long c)
    {
        a = b = c = 0;
        IReadOnlyList<long>? r = signature.ByteRange;
        if (r is null || r.Count != 4 || r[0] != 0)
        {
            return false;
        }

        a = r[1];
        b = r[2];
        c = r[3];
        // Written so that no sum can overflow: every term is first bounded by the file length.
        if (a < 0 || b <= a || c < 0 || b > file.Length || c > file.Length - b)
        {
            return false;
        }

        return file[(int)a] == (byte)'<' && file[(int)b - 1] == (byte)'>';
    }

    /// <summary>The octets the signature covers: the first range followed by the second (ISO 32000-2 §12.8.1).</summary>
    public static Stream SignedContent(ReadOnlyMemory<byte> file, long a, long b, long c) =>
        new ConcatenatedStream(file[..(int)a], file.Slice((int)b, (int)c));

    /// <summary>Hex-decodes the string between the brackets; false when it is not hex or has an odd length.</summary>
    public static bool TryContentsBytes(ReadOnlySpan<byte> file, long a, long b, out byte[] bytes)
    {
        ReadOnlySpan<byte> hex = file[((int)a + 1)..((int)b - 1)];
        bytes = [];
        if (hex.Length % 2 != 0)
        {
            return false;
        }

        byte[] result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            int hi = Nibble(hex[2 * i]);
            int lo = Nibble(hex[(2 * i) + 1]);
            if ((hi | lo) < 0)
            {
                return false;
            }

            result[i] = (byte)((hi << 4) | lo);
        }

        bytes = result;
        return true;
    }

    private static int Nibble(byte ch) => ch switch
    {
        >= (byte)'0' and <= (byte)'9' => ch - '0',
        >= (byte)'a' and <= (byte)'f' => ch - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => ch - 'A' + 10,
        _ => -1,
    };

    /// <summary>
    /// The length of the DER structure at the start of <paramref name="contents"/> (the signature is followed by zero padding in the
    /// reserved space), or the whole length when the header is not a definite-length SEQUENCE.
    /// </summary>
    public static int DerLength(ReadOnlySpan<byte> contents)
    {
        if (contents.Length < 2 || contents[0] != 0x30)
        {
            return contents.Length;
        }

        int first = contents[1];
        if (first < 0x80)
        {
            return Math.Min(contents.Length, 2 + first);
        }

        int n = first & 0x7F;
        if (n == 0 || n > 4 || contents.Length < 2 + n)
        {
            return contents.Length;
        }

        long len = 0;
        for (int i = 0; i < n; i++)
        {
            len = (len << 8) | contents[2 + i];
        }

        long total = 2 + n + len;
        return total > contents.Length ? contents.Length : (int)total;
    }

    /// <summary>
    /// The key of a /VRI entry (EN 319 142-1 §5.4.2.2): the upper-case hexadecimal SHA-1 of the signature
    /// (the CMS structure of /Contents). The hash only names the entry; nothing about trust depends on it.
    /// </summary>
    public static string VriKey(ReadOnlySpan<byte> contents, bool trim = true) =>
        Convert.ToHexString(CryptographicOperations.HashData(HashAlgorithmName.SHA1, trim ? contents[..DerLength(contents)] : contents));

    /// <summary>The PDF date string of an instant, in UTC (ISO 32000-2 §7.9.4).</summary>
    public static string PdfDate(DateTimeOffset t) => "D:" + t.UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "Z";

    /// <summary>A read-only stream over two memory ranges, so a signed range pair is hashed without being copied.</summary>
    private sealed class ConcatenatedStream : Stream
    {
        private readonly ReadOnlyMemory<byte> _first;
        private readonly ReadOnlyMemory<byte> _second;
        private long _position;

        public ConcatenatedStream(ReadOnlyMemory<byte> first, ReadOnlyMemory<byte> second)
        {
            _first = first;
            _second = second;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => _first.Length + (long)_second.Length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int done = 0;
            if (_position < _first.Length)
            {
                int n = Math.Min(buffer.Length, _first.Length - (int)_position);
                _first.Span.Slice((int)_position, n).CopyTo(buffer);
                _position += n;
                done += n;
            }

            if (done < buffer.Length && _position >= _first.Length && _position < Length)
            {
                int at = (int)(_position - _first.Length);
                int n = Math.Min(buffer.Length - done, _second.Length - at);
                _second.Span.Slice(at, n).CopyTo(buffer[done..]);
                _position += n;
                done += n;
            }

            return done;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
