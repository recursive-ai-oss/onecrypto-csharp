using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp;

// Async twins. The cryptography itself is synchronous CPU work; what these add is non-blocking I/O on the caller's streams. Input is
// copied asynchronously into a spool (memory up to a few MiB, then a temporary file), the synchronous pipeline runs over the spool, and the
// result is copied out asynchronously. Memory stays constant for any size, and nothing reaches the caller's output stream before the
// whole operation has succeeded, which is stricter than the synchronous form for chunked AEAD (it never shows a partial plaintext).

public static partial class PgpMessageReader
{
    /// <summary>Asynchronous <see cref="Read"/>. The plaintext is written to <paramref name="output"/> only after the whole message has been read and authenticated.</summary>
    /// <param name="input">The message, binary or armored.</param>
    /// <param name="output">Receives the plaintext; null to only check.</param>
    /// <param name="options">As for <see cref="Read"/>.</param>
    /// <param name="cancellationToken">Cancels the copy steps.</param>
    /// <returns>The same report as <see cref="Read"/>.</returns>
    /// <exception cref="PgpException">As for <see cref="Read"/>; <paramref name="output"/> has received nothing then.</exception>
    public static async Task<PgpReadResult> ReadAsync(Stream input, Stream? output, PgpReadOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(options);
        using SpoolStream source = await Spool(input, cancellationToken).ConfigureAwait(false);
        using var result = new SpoolStream();
        PgpReadResult r = Read(source, output is null ? null : result, options);
        await Drain(result, output, cancellationToken).ConfigureAwait(false);
        return r;
    }

    /// <summary>Asynchronous <see cref="VerifyDetached"/>.</summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signatures">The detached signature(s), binary or armored.</param>
    /// <param name="options">As for <see cref="VerifyDetached"/>.</param>
    /// <param name="cancellationToken">Cancels the copy steps.</param>
    public static async Task<PgpReadResult> VerifyDetachedAsync(Stream data, Stream signatures, PgpReadOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signatures);
        using SpoolStream d = await Spool(data, cancellationToken).ConfigureAwait(false);
        using SpoolStream s = await Spool(signatures, cancellationToken).ConfigureAwait(false);
        return VerifyDetached(d, s, options);
    }

    /// <summary>Asynchronous <see cref="VerifyCleartext"/>. The text is written only after verification has finished.</summary>
    /// <param name="input">The cleartext-signed message.</param>
    /// <param name="output">Receives the signed text; null to only verify.</param>
    /// <param name="options">As for <see cref="VerifyCleartext"/>.</param>
    /// <param name="cancellationToken">Cancels the copy steps.</param>
    public static async Task<PgpReadResult> VerifyCleartextAsync(Stream input, Stream? output, PgpReadOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        using SpoolStream source = await Spool(input, cancellationToken).ConfigureAwait(false);
        using var result = new SpoolStream();
        PgpReadResult r = VerifyCleartext(source, output is null ? null : result, options);
        await Drain(result, output, cancellationToken).ConfigureAwait(false);
        return r;
    }

    /// <summary>Asynchronous <see cref="ReadSigned"/>. The content is written only after verification has finished.</summary>
    /// <param name="input">The signed message.</param>
    /// <param name="output">Receives the signed content; null to only verify.</param>
    /// <param name="options">As for <see cref="ReadSigned"/>.</param>
    /// <param name="cancellationToken">Cancels the copy steps.</param>
    public static async Task<PgpReadResult> ReadSignedAsync(Stream input, Stream? output, PgpReadOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        using SpoolStream source = await Spool(input, cancellationToken).ConfigureAwait(false);
        using var result = new SpoolStream();
        PgpReadResult r = ReadSigned(source, output is null ? null : result, options);
        await Drain(result, output, cancellationToken).ConfigureAwait(false);
        return r;
    }

    internal static async Task<SpoolStream> Spool(Stream input, CancellationToken cancellationToken)
    {
        var spool = new SpoolStream();
        try
        {
            await input.CopyToAsync(spool, cancellationToken).ConfigureAwait(false);
            spool.Position = 0;
            return spool;
        }
        catch
        {
            spool.Dispose();
            throw;
        }
    }

    internal static async Task Drain(SpoolStream result, Stream? output, CancellationToken cancellationToken)
    {
        if (output is null)
        {
            return;
        }

        result.Position = 0;
        await result.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
    }
}

public static partial class PgpMessageWriter
{
    /// <summary>Asynchronous <see cref="Write"/>. The message is written to <paramref name="output"/> once it is complete.</summary>
    /// <param name="plaintext">The content.</param>
    /// <param name="output">Receives the message.</param>
    /// <param name="options">As for <see cref="Write"/>.</param>
    /// <param name="cancellationToken">Cancels the copy steps.</param>
    public static async Task WriteAsync(Stream plaintext, Stream output, PgpWriteOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(output);
        using SpoolStream source = await PgpMessageReader.Spool(plaintext, cancellationToken).ConfigureAwait(false);
        using var result = new SpoolStream();
        Write(source, result, options);
        await PgpMessageReader.Drain(result, output, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Asynchronous <see cref="SignDetached"/>.</summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="output">Receives the signature(s).</param>
    /// <param name="options">As for <see cref="SignDetached"/>.</param>
    /// <param name="cancellationToken">Cancels the copy steps.</param>
    /// <returns>The hash each signer used.</returns>
    public static async Task<IReadOnlyList<PgpHashAlgorithm>> SignDetachedAsync(Stream data, Stream output, PgpWriteOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(output);
        using SpoolStream source = await PgpMessageReader.Spool(data, cancellationToken).ConfigureAwait(false);
        using var result = new SpoolStream();
        IReadOnlyList<PgpHashAlgorithm> hashes = SignDetached(source, result, options);
        await PgpMessageReader.Drain(result, output, cancellationToken).ConfigureAwait(false);
        return hashes;
    }

    /// <summary>Asynchronous <see cref="SignCleartext"/>.</summary>
    /// <param name="text">The text to sign.</param>
    /// <param name="output">Receives the cleartext-signed message.</param>
    /// <param name="options">As for <see cref="SignCleartext"/>.</param>
    /// <param name="cancellationToken">Cancels the copy steps.</param>
    public static async Task SignCleartextAsync(Stream text, Stream output, PgpWriteOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(output);
        using SpoolStream source = await PgpMessageReader.Spool(text, cancellationToken).ConfigureAwait(false);
        using var result = new SpoolStream();
        SignCleartext(source, result, options);
        await PgpMessageReader.Drain(result, output, cancellationToken).ConfigureAwait(false);
    }
}
