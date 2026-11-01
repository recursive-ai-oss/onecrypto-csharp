using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Internal;

/// <summary>
/// A write-only stream in front of a CBC decryptor that runs without padding: it passes everything on except the last block, which it holds back
/// until <see cref="Complete"/> checks the PKCS #7 padding (RFC 5652 §6.3) in constant time and writes what is left of it. Doing the unpadding here
/// instead of in the platform keeps the bad-padding path from costing more than the good one (see <see cref="Pkcs7Padding"/>).
/// </summary>
internal sealed class Pkcs7UnpadSink : Stream
{
    private readonly Stream _out;
    private readonly int _block;
    private readonly byte[] _held;
    private readonly byte[] _next;
    private int _heldLength;

    internal Pkcs7UnpadSink(Stream output, int block)
    {
        _out = output;
        _block = block;
        _held = new byte[block];
        _next = new byte[block];
    }

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> data)
    {
        int total = _heldLength + data.Length;
        if (total <= _block)
        {
            data.CopyTo(_held.AsSpan(_heldLength));
            _heldLength = total;
            return;
        }

        int release = total - _block;
        int fromHeld = Math.Min(_heldLength, release);
        if (fromHeld > 0)
        {
            _out.Write(_held.AsSpan(0, fromHeld));
        }

        int fromData = release - fromHeld;
        if (fromData > 0)
        {
            _out.Write(data[..fromData]);
        }

        Hold(fromHeld, data[fromData..]);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        int total = _heldLength + data.Length;
        if (total <= _block)
        {
            data.Span.CopyTo(_held.AsSpan(_heldLength));
            _heldLength = total;
            return;
        }

        int release = total - _block;
        int fromHeld = Math.Min(_heldLength, release);
        if (fromHeld > 0)
        {
            await _out.WriteAsync(_held.AsMemory(0, fromHeld), cancellationToken).ConfigureAwait(false);
        }

        int fromData = release - fromHeld;
        if (fromData > 0)
        {
            await _out.WriteAsync(data[..fromData], cancellationToken).ConfigureAwait(false);
        }

        Hold(fromHeld, data.Span[fromData..]);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    // What stays back: the part of the old hold that was not released, then the rest of the new data. Always exactly one block.
    private void Hold(int fromHeld, ReadOnlySpan<byte> rest)
    {
        int keepOld = _heldLength - fromHeld;
        Span<byte> next = _next;
        _held.AsSpan(fromHeld, keepOld).CopyTo(next);
        rest.CopyTo(next[keepOld..]);
        next.CopyTo(_held);
        _heldLength = _block;
    }

    /// <summary>
    /// Checks the padding of the held last block and writes the data in front of it. False, with nothing more written, when the stream did not
    /// end on a whole block or the padding is not valid; the caller reports one failure for both.
    /// </summary>
    internal bool Complete()
    {
        int length = Verdict();
        if (length < 0)
        {
            return false;
        }

        _out.Write(_held.AsSpan(0, length));
        return true;
    }

    /// <summary>The asynchronous twin of <see cref="Complete"/>.</summary>
    internal async ValueTask<bool> CompleteAsync(CancellationToken cancellationToken)
    {
        int length = Verdict();
        if (length < 0)
        {
            return false;
        }

        await _out.WriteAsync(_held.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        return true;
    }

    private int Verdict()
    {
        int length = _heldLength == _block ? Pkcs7Padding.UnpaddedLength(_held, _block) : -1;
        return length;
    }

    public override void Flush()
    {
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CryptographicOperations.ZeroMemory(_held);
            CryptographicOperations.ZeroMemory(_next);
        }

        base.Dispose(disposing);
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}
