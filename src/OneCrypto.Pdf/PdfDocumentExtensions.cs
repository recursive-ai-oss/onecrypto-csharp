using OnePdf;
using RecursiveAI.OneCrypto.Keys;

namespace RecursiveAI.OneCrypto.Pdf;

/// <summary>OneCrypto's PAdES signing and verification as calls on OnePDF's <see cref="PdfDocument"/>.</summary>
public static class PdfDocumentExtensions
{
    /// <summary>Signs the document at a PAdES baseline level with a OneCrypto key. See <see cref="PadesSigner.Sign"/>.</summary>
    /// <param name="document">A document opened with <see cref="PdfOpenOptions.AllowEditing"/>.</param>
    /// <param name="output">A writable stream.</param>
    /// <param name="key">The signing key.</param>
    /// <param name="certificate">The signer's certificate.</param>
    /// <param name="chain">Certificates to embed besides the signer's.</param>
    /// <param name="options">Level and choices, or null for B-B.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>What was written.</returns>
    public static PadesSignResult SignPades(this PdfDocument document, Stream output, ISigningKey key, Certificate certificate, IEnumerable<Certificate>? chain = null, PadesSignOptions? options = null, CancellationToken cancellationToken = default) =>
        PadesSigner.Sign(document, output, key, certificate, chain, options, cancellationToken);

    /// <summary>Asynchronous twin of <see cref="SignPades"/>.</summary>
    /// <param name="document">A document opened with <see cref="PdfOpenOptions.AllowEditing"/>.</param>
    /// <param name="output">A writable stream.</param>
    /// <param name="key">The signing key.</param>
    /// <param name="certificate">The signer's certificate.</param>
    /// <param name="chain">Certificates to embed besides the signer's.</param>
    /// <param name="options">Level and choices, or null for B-B.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>What was written.</returns>
    public static ValueTask<PadesSignResult> SignPadesAsync(this PdfDocument document, Stream output, ISigningKey key, Certificate certificate, IEnumerable<Certificate>? chain = null, PadesSignOptions? options = null, CancellationToken cancellationToken = default) =>
        PadesSigner.SignAsync(document, output, key, certificate, chain, options, cancellationToken);

    /// <summary>Verifies every signature and document time-stamp. See <see cref="PadesVerifier"/>.</summary>
    /// <param name="document">The document.</param>
    /// <param name="pdf">The bytes the document was opened from (OnePDF's model does not expose them).</param>
    /// <param name="options">Trust anchors, reference time, policy.</param>
    /// <param name="cancellationToken">Checked between signatures.</param>
    /// <returns>The report.</returns>
    public static PadesReport VerifyPades(this PdfDocument document, ReadOnlyMemory<byte> pdf, PadesVerifyOptions options, CancellationToken cancellationToken = default) =>
        PadesVerifier.Verify(document, pdf, options, cancellationToken);

    /// <summary>Asynchronous twin of <see cref="VerifyPades"/>; asks the options' sources for missing issuers and revocation data.</summary>
    /// <param name="document">The document.</param>
    /// <param name="pdf">The bytes the document was opened from.</param>
    /// <param name="options">Trust anchors, reference time, policy and sources.</param>
    /// <param name="cancellationToken">Cancels the lookups.</param>
    /// <returns>The report.</returns>
    public static ValueTask<PadesReport> VerifyPadesAsync(this PdfDocument document, ReadOnlyMemory<byte> pdf, PadesVerifyOptions options, CancellationToken cancellationToken = default) =>
        PadesVerifier.VerifyAsync(document, pdf, options, cancellationToken);
}
