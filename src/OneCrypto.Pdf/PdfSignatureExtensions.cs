using System.Diagnostics.CodeAnalysis;
using OnePdf;

namespace RecursiveAI.OneCrypto.Pdf;

/// <summary>Non-nullable ways to get at the bytes a OnePDF signature covers, for code that hashes them itself.</summary>
public static class PdfSignatureExtensions
{
    /// <summary>
    /// Opens the signed bytes as <see cref="PdfSignature.OpenSignedData"/> does, and raises a typed error where that returns null.
    /// The stream is read-only and valid only while the document is open.
    /// </summary>
    /// <param name="signature">The signature.</param>
    /// <returns>The ranges named by <c>/ByteRange</c>, concatenated.</returns>
    /// <exception cref="PadesException">The <c>/ByteRange</c> is missing, malformed, does not start at 0, overlaps itself or lies outside the file (<see cref="PadesException.Reason"/> is <see cref="PadesError.NotPresent"/>).</exception>
    public static Stream OpenSignedDataOrThrow(this PdfSignature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        return signature.OpenSignedData()
            ?? throw new PadesException(PadesError.NotPresent, "The signature's /ByteRange is missing, malformed, does not start at 0, overlaps itself or lies outside the file, so its signed bytes cannot be opened.");
    }

    /// <summary>The same as <see cref="PdfSignature.OpenSignedData"/> in the <c>Try</c> pattern: false when the signed bytes cannot be opened.</summary>
    /// <param name="signature">The signature.</param>
    /// <param name="signedData">The stream, valid only while the document is open.</param>
    /// <returns>True when the stream was opened.</returns>
    public static bool TryOpenSignedData(this PdfSignature signature, [NotNullWhen(true)] out Stream? signedData)
    {
        ArgumentNullException.ThrowIfNull(signature);
        signedData = signature.OpenSignedData();
        return signedData is not null;
    }
}
