using System.Security.Cryptography;
using OnePdf;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto.Pdf;

/// <summary>
/// A PDF signature in two steps: the file with its empty signature hole is written and the state needed to finish it is kept; the signature
/// is made later, by any key, possibly in another process or days afterwards (<see cref="PadesTwoPhase.Complete(Stream, PadesPendingSignature, ISigningKey, CancellationToken)"/>).
/// The state serialises to DER and carries no secret.
/// </summary>
public sealed class PadesPendingSignature
{
    /// <summary>Version of the serialised form.</summary>
    public const int FormatVersion = 1;

    /// <summary>The purpose label of the state, so a state made for something else is not taken for a PDF signature.</summary>
    public const string Purpose = "pades.pdf.signature";

    internal PadesPendingSignature(string fieldName, long holeStart, long holeEnd, string digestOid, byte[] digest, PreparedSignedData state)
    {
        FieldName = fieldName;
        HoleStart = holeStart;
        HoleEnd = holeEnd;
        DigestAlgorithm = digestOid;
        Digest = digest;
        State = state;
    }

    /// <summary>The name of the signature field in the file.</summary>
    public string FieldName { get; }

    /// <summary>Offset of the <c>&lt;</c> that opens the empty <c>/Contents</c> string.</summary>
    public long HoleStart { get; }

    /// <summary>Offset just after the <c>&gt;</c> that closes it.</summary>
    public long HoleEnd { get; }

    /// <summary>The OID of the digest algorithm the signer's message-digest attribute uses.</summary>
    public string DigestAlgorithm { get; }

    /// <summary>The digest of the file outside the hole under <see cref="DigestAlgorithm"/>; phase two refuses a file that no longer hashes to it.</summary>
    public byte[] Digest { get; }

    internal PreparedSignedData State { get; }

    /// <summary>What the key must sign (the DER signed attributes, or their digest for RSA and ECDSA), with the scheme and the public key it must verify against.</summary>
    public PreparedSignature ToSign => State.Signatures[0];

    /// <summary>
    /// The serialised state: <c>SEQUENCE { version, purpose UTF8String, field UTF8String, holeStart, holeEnd, digestAlgorithm OID, digest OCTET STRING,
    /// preparedSignedData OCTET STRING }</c>, DER.
    /// </summary>
    public byte[] Encode() => DerWriter.Sequence(
        DerWriter.SignedInteger(FormatVersion),
        DerWriter.Utf8String(Purpose),
        DerWriter.Utf8String(FieldName),
        DerWriter.SignedInteger(HoleStart),
        DerWriter.SignedInteger(HoleEnd),
        DerWriter.Oid(DigestAlgorithm),
        DerWriter.OctetString(Digest),
        DerWriter.OctetString(State.Encode()));

    /// <summary>Reads a serialised state.</summary>
    /// <exception cref="FormatException">The octets are not a state this version understands.</exception>
    public static PadesPendingSignature Decode(ReadOnlySpan<byte> encoded) =>
        TryDecode(encoded, out PadesPendingSignature? p, out string? error) ? p! : throw new FormatException(error);

    /// <summary>Reads a serialised state, returning false and the reason instead of throwing.</summary>
    /// <param name="encoded">The octets from <see cref="Encode"/>.</param>
    /// <param name="state">The state.</param>
    /// <param name="error">Why not.</param>
    /// <returns>True when the state was read.</returns>
    public static bool TryDecode(ReadOnlySpan<byte> encoded, out PadesPendingSignature? state, out string? error)
    {
        state = null;
        error = null;
        try
        {
            var r = new Asn1Reader(encoded, Asn1Rules.Der);
            Asn1Reader s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            int version = s.ReadInt32();
            if (version != FormatVersion)
            {
                error = $"The pending PDF signature is format version {version}; this library reads version {FormatVersion}.";
                return false;
            }

            if (s.ReadCharacterString(12) != Purpose)
            {
                error = "The state is not a pending PDF signature.";
                return false;
            }

            string field = s.ReadCharacterString(12);
            long start = s.ReadInt64();
            long end = s.ReadInt64();
            string digestOid = s.ReadObjectIdentifier();
            byte[] digest = s.ReadOctetStringBytes();
            byte[] inner = s.ReadOctetStringBytes();
            s.ThrowIfNotEmpty();
            if (start < 0 || end < start + 2)
            {
                error = "The hole offsets of the pending PDF signature are not valid.";
                return false;
            }

            if (!PreparedSignedData.TryDecode(inner, out PreparedSignedData? prepared, out error) || prepared!.Signatures.Count != 1)
            {
                error ??= "A pending PDF signature has exactly one signer.";
                return false;
            }

            state = new PadesPendingSignature(field, start, end, digestOid, digest, prepared);
            return true;
        }
        catch (Exception e) when (e is FormatException or ArgumentException or InvalidOperationException)
        {
            error = "The pending PDF signature is damaged: " + e.Message;
            return false;
        }
    }
}

/// <summary>
/// Signs a PDF in two steps with a OneCrypto key. Step one writes the incremental update with an empty signature hole and returns a
/// <see cref="PadesPendingSignature"/>; step two (any process, any time later) signs and fills the hole. Raise the result to B-T and above with
/// <see cref="PadesAugmenter"/>. Because core builds the SignerInfo, Ed25519, Ed448 and ML-DSA keys work as well as RSA and ECDSA.
/// </summary>
/// <remarks>
/// <para><b>Readers.</b> ISO/TS 32002 puts Ed25519 and Ed448 in PDF 2.0; ML-DSA in PDF is not standardised yet and is preview here. Readers that
/// predate those schemes report such a signature as unverifiable, whatever the bytes say: check the readers you target. OnePDF's own verifier
/// reports them as not checked; <see cref="PadesVerifier"/> verifies them and its report is the verdict for those signatures.</para>
/// </remarks>
public static class PadesTwoPhase
{
    /// <summary>Step one: writes the file with the empty signature hole to <paramref name="output"/>.</summary>
    /// <param name="document">The document, opened with <see cref="PdfOpenOptions.AllowEditing"/>.</param>
    /// <param name="output">A writable, seekable stream that receives the whole file.</param>
    /// <param name="certificate">The signer's certificate.</param>
    /// <param name="chain">Certificates to embed besides the signer's.</param>
    /// <param name="at">The moment of signing, for the policy and the state.</param>
    /// <param name="options">The field, page, appearance, hash, RSA padding and policy. The level is not used: augment afterwards.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The state to finish the signature with.</returns>
    /// <exception cref="PolicyViolationException">The policy refuses the signature algorithm or key.</exception>
    /// <exception cref="PdfSigningException">OnePDF refused the field or the reserve.</exception>
    public static PadesPendingSignature Prepare(PdfDocument document, Stream output, Certificate certificate, IEnumerable<Certificate>? chain, DateTimeOffset at, PadesSignOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(certificate);
        options ??= new PadesSignOptions();
        CmsSignerSpec spec = PadesSigner.BuildSpec(null, certificate, options);
        string digestOid = SignedData.DigestAlgorithmFor(spec, options.Policy);
        using var ms = new MemoryStream();
        PdfSignaturePlaceholder hole = document.AddSignaturePlaceholder(ms, PadesSigner.PlaceholderOptions(options), options.Pdf?.ContentsReserve ?? PadesSigner.DefaultReserve, cancellationToken);
        byte[] digest = PadesSigner.HashOutsideHole(ms, hole.HoleStart, hole.HoleEnd, digestOid);
        PreparedSignedData state = SignedData.PrepareDetachedFromDigest(digest, digestOid, [spec], at, new SignedDataOptions { Certificates = [.. chain ?? []], Policy = options.Policy });
        ms.Position = 0;
        ms.CopyTo(output);
        return new PadesPendingSignature(hole.FieldName, hole.HoleStart, hole.HoleEnd, digestOid, digest, state);
    }

    /// <summary>Step two with a key: signs what step one recorded and fills the hole of <paramref name="file"/> in place.</summary>
    /// <param name="file">The file step one wrote, opened read/write and seekable.</param>
    /// <param name="pending">The state from step one (or decoded from its serialised form).</param>
    /// <param name="key">A key whose public key is the certificate's.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="PadesException">The file is not the one step one wrote, or the hole is too small (the reserve was too low).</exception>
    /// <exception cref="InvalidSignatureException">The key's signature does not verify against the recorded public key.</exception>
    public static void Complete(Stream file, PadesPendingSignature pending, ISigningKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pending);
        ArgumentNullException.ThrowIfNull(key);
        Complete(file, pending, pending.ToSign.SignWith(key), cancellationToken);
    }

    /// <summary>Step two with a signature made elsewhere over <see cref="PadesPendingSignature.ToSign"/> (<see cref="PreparedSignature.ToSign"/>).</summary>
    /// <param name="file">The file step one wrote, opened read/write and seekable.</param>
    /// <param name="pending">The state from step one.</param>
    /// <param name="signature">The signature value; checked against the recorded public key before anything is written.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    public static void Complete(Stream file, PadesPendingSignature pending, ReadOnlySpan<byte> signature, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(pending);
        cancellationToken.ThrowIfCancellationRequested();
        if (!file.CanSeek || !file.CanRead || !file.CanWrite)
        {
            throw new ArgumentException("The stream must support seeking, reading and writing.", nameof(file));
        }

        // The file must still be the one the signature was prepared for, or the signature would cover other bytes than it was made over.
        long length = file.Length;
        if (pending.HoleEnd > length)
        {
            throw new PadesException(PadesError.UnsupportedFile, "The file is shorter than the signature hole recorded in the pending state.");
        }

        byte[] now = HashFile(file, pending);
        if (!CryptographicOperations.FixedTimeEquals(now, pending.Digest))
        {
            throw new PadesException(PadesError.UnsupportedFile, "The file does not hash to the digest the signature was prepared for.");
        }

        SignedData cms = pending.State.Complete(signature);
        PdfSignatureHole.Fill(file, pending.HoleStart, pending.HoleEnd, cms.Encoded.Span);
    }

    /// <summary>Step two on a file path.</summary>
    /// <param name="path">The file step one wrote.</param>
    /// <param name="pending">The state.</param>
    /// <param name="key">The signing key.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    public static void Complete(string path, PadesPendingSignature pending, ISigningKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        using var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Complete(file, pending, key, cancellationToken);
    }

    private static byte[] HashFile(Stream file, PadesPendingSignature pending)
    {
        long position = file.Position;
        try
        {
            file.Position = 0;
            byte[] all = new byte[file.Length];
            file.ReadExactly(all);
            using var ranges = new MemoryStream(all.Length);
            ranges.Write(all, 0, (int)pending.HoleStart);
            ranges.Write(all, (int)pending.HoleEnd, all.Length - (int)pending.HoleEnd);
            ranges.Position = 0;
            return SignedData.HashContent(pending.DigestAlgorithm, ranges);
        }
        finally
        {
            file.Position = position;
        }
    }
}
