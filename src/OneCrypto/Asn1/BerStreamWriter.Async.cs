namespace RecursiveAI.OneCrypto.Asn1;

// The asynchronous writing path: the same bytes as the synchronous methods, written with WriteAsync so a slow sink never blocks a thread.
public sealed partial class BerStreamWriter
{
    private byte[]? _header;

    /// <summary>The asynchronous twin of <see cref="BeginIndefinite"/>.</summary>
    public async ValueTask BeginIndefiniteAsync(Asn1Tag tag, CancellationToken cancellationToken = default)
    {
        byte[] header = _header ??= new byte[Asn1Wire.MaxHeaderLength];
        int n = tag.WithConstructed(true).Encode(header);
        header[n++] = 0x80;
        await _stream.WriteAsync(header.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
        _open++;
    }

    /// <summary>The asynchronous twin of <see cref="End"/>.</summary>
    public async ValueTask EndAsync(CancellationToken cancellationToken = default)
    {
        if (_open == 0)
        {
            throw new InvalidOperationException("No indefinite-length element is open.");
        }

        await _stream.WriteAsync(new byte[] { 0, 0 }, cancellationToken).ConfigureAwait(false);
        _open--;
    }

    /// <summary>The asynchronous twin of <see cref="WriteDefinite"/>.</summary>
    public async ValueTask WriteDefiniteAsync(Asn1Tag tag, ReadOnlyMemory<byte> content, CancellationToken cancellationToken = default)
    {
        byte[] header = _header ??= new byte[Asn1Wire.MaxHeaderLength];
        int n = tag.Encode(header);
        n += Asn1Wire.EncodeLength(content.Length, header.AsSpan(n));
        await _stream.WriteAsync(header.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
        await _stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The asynchronous twin of <see cref="WriteEncodedValue"/>.</summary>
    public ValueTask WriteEncodedValueAsync(ReadOnlyMemory<byte> encoded, CancellationToken cancellationToken = default) =>
        _stream.WriteAsync(encoded, cancellationToken);

    /// <summary>The asynchronous twin of <see cref="WriteOctetStringFrom"/>: segments are read and written without blocking.</summary>
    public async ValueTask WriteOctetStringFromAsync(Stream source, int segmentSize = 1 << 16, Asn1Tag? tag = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentOutOfRangeException.ThrowIfLessThan(segmentSize, 1);
        await BeginIndefiniteAsync(tag ?? new Asn1Tag(Asn1Tags.OctetString), cancellationToken).ConfigureAwait(false);
        byte[] buffer = new byte[segmentSize];
        int n;
        while ((n = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            await WriteDefiniteAsync(new Asn1Tag(Asn1Tags.OctetString), buffer.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
        }

        await EndAsync(cancellationToken).ConfigureAwait(false);
    }
}
