namespace RecursiveAI.OneCrypto.Asn1;

// The asynchronous reading path. Every method awaits the octets it needs into the same 16 KiB buffer the synchronous methods use
// and then runs the synchronous logic over what is buffered, so both forms decide identically and neither wraps the other.
public sealed partial class Asn1StreamReader
{
    /// <summary>Leaves at least <paramref name="want"/> octets buffered unless the stream ends first, like the synchronous refill.</summary>
    private async ValueTask FillAsync(int want, CancellationToken cancellationToken)
    {
        if (_bufLen - _bufPos >= want || _eof)
        {
            return;
        }

        if (_bufPos > 0)
        {
            Buffer.BlockCopy(_buf, _bufPos, _buf, 0, _bufLen - _bufPos);
            _bufLen -= _bufPos;
            _bufPos = 0;
        }

        while (_bufLen < want && !_eof)
        {
            int n = await _stream.ReadAsync(_buf.AsMemory(_bufLen, _buf.Length - _bufLen), cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                _eof = true;
            }

            _bufLen += n;
        }
    }

    private async ValueTask SkipPendingAsync(CancellationToken cancellationToken)
    {
        while (_pending > 0)
        {
            int want = (int)Math.Min(_pending, BufferSize);
            await FillAsync(want, cancellationToken).ConfigureAwait(false);
            int n = Math.Min(want, _bufLen - _bufPos);
            if (n == 0)
            {
                return; // truncated: the synchronous TryReadToken reports it
            }

            Consume(n);
            _pending -= n;
        }
    }

    /// <summary>
    /// The asynchronous twin of <see cref="TryReadToken"/>: awaits the octets a header needs, then decides exactly as the synchronous form does.
    /// </summary>
    /// <param name="cancellationToken">Cancels the wait for more input.</param>
    /// <returns>Whether a token was read, and the token. On false, <see cref="LastFailure"/> says why (none at a clean end).</returns>
    public async ValueTask<(bool Ok, Asn1Token Token)> TryReadTokenAsync(CancellationToken cancellationToken = default)
    {
        await SkipPendingAsync(cancellationToken).ConfigureAwait(false);
        await FillAsync(Asn1Wire.MaxHeaderLength, cancellationToken).ConfigureAwait(false);
        bool ok = TryReadToken(out Asn1Token t);
        return (ok, t);
    }

    /// <summary>The asynchronous twin of <see cref="ReadToken"/>.</summary>
    /// <exception cref="Asn1ParseException">The input is malformed or ends inside an element.</exception>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    public async ValueTask<Asn1Token> ReadTokenAsync(CancellationToken cancellationToken = default)
    {
        (bool ok, Asn1Token t) = await TryReadTokenAsync(cancellationToken).ConfigureAwait(false);
        return ok ? t : throw new Asn1ParseException(LastFailure.Error == Asn1Error.None ? Asn1Error.Truncated : LastFailure.Error, (int)Math.Min(_consumed, int.MaxValue));
    }

    /// <summary>
    /// The asynchronous twin of <see cref="Read(Span{byte})"/>: some of the unread content of the current primitive element, 0 when it is used up.
    /// </summary>
    /// <exception cref="Asn1ParseException">The stream ends inside the element.</exception>
    public async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
    {
        if (_pending == 0 || destination.IsEmpty)
        {
            return 0;
        }

        await FillAsync((int)Math.Min(Math.Min(_pending, destination.Length), BufferSize), cancellationToken).ConfigureAwait(false);
        return Read(destination.Span);
    }

    /// <summary>
    /// The asynchronous twin of <see cref="ReadContent"/>: copies out the whole unread content of the current primitive element, within
    /// <see cref="Asn1Limits.MaxCopiedLength"/>.
    /// </summary>
    /// <exception cref="Asn1ParseException">The content is over the limit or the stream ends inside it.</exception>
    public async ValueTask<byte[]> ReadContentAsync(CancellationToken cancellationToken = default)
    {
        if (_pending > _limits.MaxCopiedLength)
        {
            Fail(Asn1Error.LengthExceedsData, _consumed);
            throw LastFailure.ToException();
        }

        byte[] result = new byte[(int)_pending];
        int at = 0;
        while (at < result.Length)
        {
            int n = await ReadAsync(result.AsMemory(at), cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                throw new Asn1ParseException(Asn1Error.Truncated, (int)Math.Min(_consumed, int.MaxValue));
            }

            at += n;
        }

        return result;
    }
}
