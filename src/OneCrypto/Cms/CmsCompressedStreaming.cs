using System.IO.Compression;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

public sealed partial class CompressedData
{
    /// <summary>
    /// Decompresses a message read from a forward-only stream, in constant memory: the zlib data (RFC 3274 §2) is inflated as it arrives and written to
    /// <paramref name="output"/>. The output is bounded as in <see cref="Decompress"/>: it stops with <see cref="CmsError.LimitExceeded"/> when the output
    /// passes <see cref="CmsLimits.MaxDecompressedBytes"/> or <see cref="CmsLimits.MaxDecompressionRatio"/> times the compressed octets read so far (a
    /// compression bomb). <b>The output is not trustworthy until this returns</b>: when it throws, discard whatever was written.
    /// </summary>
    /// <param name="message">The ContentInfo octets, definite or indefinite length.</param>
    /// <param name="output">Where the decompressed content goes; it stays open.</param>
    /// <param name="limits">Limits, or null for the defaults.</param>
    /// <exception cref="CmsParseException">The message is not zlib CompressedData, is damaged, or a limit was exceeded.</exception>
    public static void DecompressStream(Stream message, Stream output, CmsLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(output);
        limits ??= CmsLimits.Default;
        try
        {
            var r = new Asn1StreamReader(message, Asn1Rules.Ber, limits.Asn1);
            int budget = CmsStream.SmallElementBudget;
            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "ContentInfo");
            if (CmsStream.Oid(CmsStream.Raw(r, r.ReadToken(), ref budget)) != CmsOids.CompressedData)
            {
                throw new CmsParseException("CompressedData", CmsError.UnexpectedContentType, "the ContentInfo does not hold CompressedData");
            }

            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Context(0, true), "ContentInfo");
            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "CompressedData");
            CmsStream.Raw(r, r.ReadToken(), ref budget); // version
            AlgorithmIdentifier alg = AlgorithmIdentifier.Parse(CmsStream.Raw(r, r.ReadToken(), ref budget));
            RequireZlib(alg);
            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "EncapsulatedContentInfo");
            CmsStream.Raw(r, r.ReadToken(), ref budget); // content type
            Asn1Token t = r.ReadToken();
            if (t.Kind != Asn1TokenKind.StartConstructed || t.Tag != Asn1Tag.Context(0, true))
            {
                throw new CmsParseException("CompressedData", CmsError.UnexpectedStructure, "there is no content");
            }

            Asn1Token o = r.ReadToken();
            Stream source = OpenContent(r, o);
            var counting = new CountingReadStream(source);
            using var z = new ZLibStream(counting, CompressionMode.Decompress);
            byte[] buffer = new byte[16 * 1024];
            long total = 0;
            int n;
            while ((n = z.Read(buffer, 0, buffer.Length)) > 0)
            {
                total += n;
                CheckBound(total, counting.Count, limits);
                output.Write(buffer, 0, n);
            }
        }
        catch (Asn1ParseException e)
        {
            throw new CmsParseException("CompressedData", e);
        }
        catch (InvalidDataException e)
        {
            throw new CmsParseException("CompressedData", CmsError.InvalidValue, e.Message);
        }
    }

    /// <summary>The asynchronous twin of <see cref="DecompressStream"/>; same bounds, reading and writing without blocking.</summary>
    /// <param name="message">The ContentInfo octets, definite or indefinite length.</param>
    /// <param name="output">Where the decompressed content goes; it stays open.</param>
    /// <param name="limits">Limits, or null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the operation between reads and writes.</param>
    public static async Task DecompressStreamAsync(Stream message, Stream output, CmsLimits? limits = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(output);
        limits ??= CmsLimits.Default;
        try
        {
            var r = new Asn1StreamReader(message, Asn1Rules.Ber, limits.Asn1);
            int budget = CmsStream.SmallElementBudget;
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "ContentInfo", cancellationToken).ConfigureAwait(false);
            byte[] oid;
            (oid, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false);
            if (CmsStream.Oid(oid) != CmsOids.CompressedData)
            {
                throw new CmsParseException("CompressedData", CmsError.UnexpectedContentType, "the ContentInfo does not hold CompressedData");
            }

            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Context(0, true), "ContentInfo", cancellationToken).ConfigureAwait(false);
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "CompressedData", cancellationToken).ConfigureAwait(false);
            (_, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false); // version
            byte[] algBytes;
            (algBytes, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false);
            RequireZlib(AlgorithmIdentifier.Parse(algBytes));
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "EncapsulatedContentInfo", cancellationToken).ConfigureAwait(false);
            (_, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false); // content type
            Asn1Token t = await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false);
            if (t.Kind != Asn1TokenKind.StartConstructed || t.Tag != Asn1Tag.Context(0, true))
            {
                throw new CmsParseException("CompressedData", CmsError.UnexpectedStructure, "there is no content");
            }

            Asn1Token o = await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false);
            Stream source = OpenContent(r, o);
            var counting = new CountingReadStream(source);
            await using var z = new ZLibStream(counting, CompressionMode.Decompress);
            byte[] buffer = new byte[16 * 1024];
            long total = 0;
            int n;
            while ((n = await z.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                total += n;
                CheckBound(total, counting.Count, limits);
                await output.WriteAsync(buffer.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Asn1ParseException e)
        {
            throw new CmsParseException("CompressedData", e);
        }
        catch (InvalidDataException e)
        {
            throw new CmsParseException("CompressedData", CmsError.InvalidValue, e.Message);
        }
    }

    private static void RequireZlib(AlgorithmIdentifier alg)
    {
        if (alg.Oid != CmsOids.ZlibCompress)
        {
            throw new CmsParseException("CompressedData", CmsError.Unsupported, $"the compression algorithm {alg.Oid} is not supported");
        }
    }

    /// <summary>RFC 3274 §1.1 and the same cap as <see cref="Decompress"/>, applied as the data arrives.</summary>
    private static void CheckBound(long decompressed, long compressedRead, CmsLimits limits)
    {
        long cap = Math.Min(limits.MaxDecompressedBytes, Math.Max(4096L, compressedRead * limits.MaxDecompressionRatio));
        if (decompressed > cap)
        {
            throw new CmsParseException("CompressedData", CmsError.LimitExceeded, "the decompressed size passes the limit");
        }
    }

    private static Stream OpenContent(Asn1StreamReader r, Asn1Token o)
    {
        if (o.Kind == Asn1TokenKind.Primitive && o.Tag == new Asn1Tag(Asn1Tags.OctetString))
        {
            return new PrimitiveContentStream(r);
        }

        if (o.Kind == Asn1TokenKind.StartConstructed && o.Tag == new Asn1Tag(Asn1Tags.OctetString))
        {
            return r.OpenOctetString(o);
        }

        throw CmsRead.Bad("EncapsulatedContentInfo", "the content is not an OCTET STRING");
    }

    /// <summary>The unread content of one primitive element as a stream.</summary>
    private sealed class PrimitiveContentStream(Asn1StreamReader reader) : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => reader.Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer) => reader.Read(buffer);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => reader.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            reader.ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>Counts the octets read through it, so the ratio bound can follow the compressed input.</summary>
    private sealed class CountingReadStream(Stream inner) : Stream
    {
        public long Count { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int n = inner.Read(buffer);
            Count += n;
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int n = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            Count += n;
            return n;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
