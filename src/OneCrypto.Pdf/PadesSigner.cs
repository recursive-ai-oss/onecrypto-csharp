using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OnePdf;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Pdf;

/// <summary>
/// Signs a PDF at a PAdES baseline level with a OneCrypto key. OnePDF writes the field, the byte range and an empty signature hole; core builds
/// the CMS over the bytes outside the hole (PAdES baseline signed attributes: content type, message digest and ESS signing-certificate-v2, no
/// signing time; sub-filter <c>ETSI.CAdES.detached</c>, EN 319 142-1 §6.3) and the key signs it, so a software key, an operating-system key or any
/// other <see cref="ISigningKey"/> works the same way. The time-stamp authority and the revocation sources are the caller's functions.
/// </summary>
/// <remarks>
/// <para><b>Keys.</b> RSA (PKCS #1 v1.5 or PSS), ECDSA, Ed25519, Ed448 and ML-DSA. ISO/TS 32002 puts Ed25519 and Ed448 in PDF 2.0; ML-DSA in PDF is
/// not standardised and is preview. Readers that predate a scheme report the signature as unverifiable. <see cref="PadesVerifier"/> verifies all of
/// them; OnePDF's own verifier reports EdDSA and ML-DSA as not checked.</para>
/// <para><b>Levels.</b> B-B is the signature; B-T adds the signature time-stamp inside the signature; B-LT then appends the document security
/// store with the validation data of the signer's and the time-stamp authority's chains; B-LTA then appends a document time-stamp that
/// covers it all. Each step is an incremental update, so every earlier signature stays valid byte for byte.</para>
/// <para>For signing in two steps, possibly in different processes, see <see cref="PadesTwoPhase"/>.</para>
/// </remarks>
public static class PadesSigner
{
    /// <summary>Room reserved for the signature when the caller does not say (12 KiB): enough to add a time-stamp to a B-B signature later.</summary>
    internal const int DefaultReserve = 12 << 10;

    /// <summary>Signs <paramref name="document"/> and writes the result (the original bytes, then the updates) to <paramref name="output"/>.</summary>
    /// <param name="document">The document, opened with <see cref="PdfOpenOptions.AllowEditing"/>.</param>
    /// <param name="output">A writable stream; nothing is written unless every step succeeds.</param>
    /// <param name="key">The signing key; its public key must be the certificate's.</param>
    /// <param name="certificate">The signer's certificate.</param>
    /// <param name="chain">Certificates to embed besides the signer's (intermediates; the root is optional).</param>
    /// <param name="options">Level and choices, or null for B-B with SHA-256.</param>
    /// <param name="cancellationToken">Checked between steps. A blocking time-stamp function is passed the same token.</param>
    /// <returns>What was written.</returns>
    /// <exception cref="PadesException">The key, the level's inputs, the time-stamp answer, a chain or the reserved space is unusable (see <see cref="PadesException.Reason"/>).</exception>
    /// <exception cref="PolicyViolationException">The policy refuses the signature algorithm.</exception>
    /// <exception cref="PdfSigningException">OnePDF refused the field, the reserve or the time-stamp token.</exception>
    public static PadesSignResult Sign(PdfDocument document, Stream output, ISigningKey key, Certificate certificate, IEnumerable<Certificate>? chain = null, PadesSignOptions? options = null, CancellationToken cancellationToken = default) =>
        SignCore(document, output, key, certificate, chain, options ?? new PadesSignOptions(), cancellationToken).AsTask().GetAwaiter().GetResult();

    /// <summary>
    /// Like <see cref="Sign"/>, for callers with asynchronous time-stamp and revocation sources. OnePDF's signing is synchronous and calls
    /// the time-stamp function from inside, so the signing runs on a thread-pool thread and waits for the function there.
    /// </summary>
    /// <param name="document">The document, opened with <see cref="PdfOpenOptions.AllowEditing"/>.</param>
    /// <param name="output">A writable stream.</param>
    /// <param name="key">The signing key.</param>
    /// <param name="certificate">The signer's certificate.</param>
    /// <param name="chain">Certificates to embed besides the signer's.</param>
    /// <param name="options">Level and choices.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>What was written.</returns>
    public static ValueTask<PadesSignResult> SignAsync(PdfDocument document, Stream output, ISigningKey key, Certificate certificate, IEnumerable<Certificate>? chain = null, PadesSignOptions? options = null, CancellationToken cancellationToken = default) =>
        SignCore(document, output, key, certificate, chain, options ?? new PadesSignOptions(), cancellationToken);

    private static async ValueTask<PadesSignResult> SignCore(PdfDocument document, Stream output, ISigningKey key, Certificate certificate, IEnumerable<Certificate>? chain, PadesSignOptions options, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(certificate);
        if (options.Level == PadesLevel.None)
        {
            throw new PadesException(PadesError.InvalidArgument, "Level None is not a level to sign at.");
        }

        if (options.Level >= PadesLevel.Timestamped && options.Timestamp is null)
        {
            throw new PadesException(PadesError.NoTimestampFunction, $"Level {options.Level} needs a time-stamp function.");
        }

        if (options.Level >= PadesLevel.LongTerm && options.ValidationData is null)
        {
            throw new PadesException(PadesError.InvalidArgument, $"Level {options.Level} needs validation data (trust anchors, a reference time and revocation data or sources).");
        }

        CmsSignerSpec spec = BuildSpec(key, certificate, options);
        // New data: the policy judges the signature algorithm, the key and the digest before anything is written.
        string digestOid = SignedData.DigestAlgorithmFor(spec, options.Policy);
        SignedDataOptions cmsOptions = CmsOptions(chain);

        // OnePDF writes the field, the byte range and an empty /Contents hole; core builds the SignerInfo over the bytes outside the hole
        // (EN 319 142-1 §6.3: CAdES signed attributes with ESS signing-certificate-v2, no signing time) and the key signs it.
        using var ms = new MemoryStream();
        PdfSignaturePlaceholder hole = document.AddSignaturePlaceholder(ms, PlaceholderOptions(options), options.Pdf?.ContentsReserve ?? DefaultReserve, ct);
        ct.ThrowIfCancellationRequested();
        byte[] digest = HashOutsideHole(ms, hole.HoleStart, hole.HoleEnd, digestOid);
        SignedData cms = SignedData.CreateDetachedFromDigest(digest, digestOid, [spec], cmsOptions);
        PdfSignatureHole.Fill(ms, hole.HoleStart, hole.HoleEnd, cms.Encoded.Span);
        byte[] signed = ms.ToArray();
        string field = hole.FieldName;

        int revisions = 1;
        byte[] final = signed;
        if (options.Level >= PadesLevel.Timestamped)
        {
            var augment = new PadesAugmentOptions
            {
                Level = options.Level,
                Timestamp = options.Timestamp,
                TimestampHash = options.TimestampHash,
                ValidationData = options.ValidationData,
            };
            final = await PadesAugmenter.AugmentAsync(signed, augment, ct).ConfigureAwait(false);
            revisions += options.Level == PadesLevel.LongTermArchive ? 2 : options.Level == PadesLevel.LongTerm ? 1 : 0;
        }

        await output.WriteAsync(final, ct).ConfigureAwait(false);
        return new PadesSignResult(field, options.Level, revisions);
    }

    internal static CmsSignerSpec BuildSpec(ISigningKey? key, Certificate certificate, PadesSignOptions options)
    {
        SignatureSpec probe = SignatureSpec.DefaultFor(certificate.PublicKey);
        return probe.Kind switch
        {
            // RSA and ECDSA sign a digest of the signed attributes in the hash the caller picked; EdDSA and ML-DSA sign the attributes
            // themselves and bring their own digest algorithm (RFC 8419 §3.1, RFC 9882).
            SignatureKind.Ecdsa => new CmsSignerSpec { Certificate = certificate, Key = key, SignatureSpec = SignatureSpec.Ecdsa(options.Hash), DigestAlgorithm = HashOid(options.Hash) },
            SignatureKind.RsaPkcs1 or SignatureKind.RsaPss => new CmsSignerSpec
            {
                Certificate = certificate,
                Key = key,
                SignatureSpec = options.RsaPss ? SignatureSpec.RsaPss(options.Hash) : SignatureSpec.RsaPkcs1(options.Hash),
                DigestAlgorithm = HashOid(options.Hash),
            },
            _ => new CmsSignerSpec { Certificate = certificate, Key = key, SignatureSpec = probe },
        };
    }

    internal static string HashOid(HashAlgorithmName hash) =>
        hash == HashAlgorithmName.SHA256 ? KnownOids.Sha256 :
        hash == HashAlgorithmName.SHA384 ? KnownOids.Sha384 :
        hash == HashAlgorithmName.SHA512 ? KnownOids.Sha512 :
        hash == HashAlgorithmName.SHA1 ? KnownOids.Sha1 :
        throw new PadesException(PadesError.InvalidArgument, "The signature hash must be SHA-256, SHA-384 or SHA-512 (SHA-1 is refused by the default policy).");

    internal static SignedDataOptions CmsOptions(IEnumerable<Certificate>? chain) => new() { Certificates = [.. chain ?? []] };

    /// <summary>The placeholder's own options. Its digest is not used (the digest algorithm follows the key), so any SHA-2 will do.</summary>
    internal static PdfSigningOptions PlaceholderOptions(PadesSignOptions options)
    {
        PdfSigningOptions basis = options.Pdf ?? new PdfSigningOptions();
        return new PdfSigningOptions
        {
            FieldName = basis.FieldName,
            PageIndex = basis.PageIndex,
            Rectangle = basis.Rectangle,
            Appearance = basis.Appearance,
            Reason = basis.Reason,
            Location = basis.Location,
            ContactInfo = basis.ContactInfo,
            SignerName = basis.SignerName,
            SigningTime = basis.SigningTime ?? options.ReferenceTime ?? options.ValidationData?.ReferenceTime,
            Certify = basis.Certify,
            FieldLock = basis.FieldLock,
            Format = PdfSignatureFormat.PadesBaseline,
            SubFilter = "ETSI.CAdES.detached",
            Hash = HashAlgorithmName.SHA512,
        };
    }

    /// <summary>Hashes the two byte ranges (everything but the <c>/Contents</c> hole), ISO 32000-2 §12.8.1.</summary>
    internal static byte[] HashOutsideHole(MemoryStream file, long holeStart, long holeEnd, string digestOid)
    {
        ReadOnlyMemory<byte> bytes = file.GetBuffer().AsMemory(0, (int)file.Length);
        using Stream ranges = PdfLayout.SignedContent(bytes, holeStart, holeEnd, bytes.Length - holeEnd);
        return SignedData.HashContent(digestOid, ranges);
    }

    /// <summary>Bridges the caller's asynchronous function to OnePDF's synchronous callback, on the thread OnePDF is signing on.</summary>
    internal static PdfTimestampCallback Adapt(PadesTimestampFunction function, CancellationToken ct) => request =>
    {
        TimeStampRequest parsed = TimeStampRequest.Parse(request.RequestDer);
        return function(parsed, ct).AsTask().GetAwaiter().GetResult();
    };
}

/// <summary>
/// Raises a signed PDF to a higher PAdES level, or renews its archive time-stamp: adds the signature time-stamp to signatures that lack
/// one, appends the document security store, appends a document time-stamp. The bytes of the file before each step are untouched, except
/// that a signature time-stamp is written into the signature's own reserved <c>/Contents</c> space, which no byte range covers.
/// </summary>
/// <remarks>
/// A step that has nothing to do is skipped: signatures that already carry a time-stamp keep it, and a store that already holds every
/// needed object is not rewritten. Level <see cref="PadesLevel.LongTermArchive"/> always appends a new document time-stamp: calling it on a file that
/// already is B-LTA is the archive time-stamp renewal of EN 319 142-1 §6.3 — the new time-stamp covers the earlier one and the validation data of its authority.
/// </remarks>
public static class PadesAugmenter
{
    /// <summary>Augments <paramref name="pdf"/>.</summary>
    /// <param name="pdf">The signed file.</param>
    /// <param name="options">The level and the inputs it needs.</param>
    /// <param name="cancellationToken">Cancels the call and the sources.</param>
    /// <returns>The augmented file.</returns>
    /// <exception cref="PadesException">An input is missing, a chain cannot be built, a time-stamp is refused or there is no room (see <see cref="PadesException.Reason"/>).</exception>
    public static async ValueTask<byte[]> AugmentAsync(ReadOnlyMemory<byte> pdf, PadesAugmentOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Level == PadesLevel.None)
        {
            throw new PadesException(PadesError.InvalidArgument, "Level None is not a level to augment to.");
        }

        if (options.Level >= PadesLevel.Timestamped && options.Timestamp is null)
        {
            throw new PadesException(PadesError.NoTimestampFunction, $"Level {options.Level} needs a time-stamp function (B-LT needs the signature time-stamp B-T builds on).");
        }

        if (options.Level >= PadesLevel.LongTerm && options.ValidationData is null)
        {
            throw new PadesException(PadesError.InvalidArgument, $"Level {options.Level} needs validation data.");
        }

        byte[] current = pdf.ToArray();
        current = await AddSignatureTimestamps(current, options, cancellationToken).ConfigureAwait(false);
        if (options.Level >= PadesLevel.LongTerm)
        {
            current = await AddStore(current, options.ValidationData!, cancellationToken).ConfigureAwait(false);
        }

        if (options.Level == PadesLevel.LongTermArchive)
        {
            current = await AddDocumentTimestamp(current, options, cancellationToken).ConfigureAwait(false);
        }

        return current;
    }

    /// <summary>Synchronous twin of <see cref="AugmentAsync"/>; blocks on the time-stamp function and the sources.</summary>
    /// <param name="pdf">The signed file.</param>
    /// <param name="options">The level and the inputs it needs.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The augmented file.</returns>
    public static byte[] Augment(ReadOnlyMemory<byte> pdf, PadesAugmentOptions options, CancellationToken cancellationToken = default) =>
        AugmentAsync(pdf, options, cancellationToken).AsTask().GetAwaiter().GetResult();

    // ---- B-T: the signature time-stamp, written into the reserved /Contents space -----------------------------------------

    private static async ValueTask<byte[]> AddSignatureTimestamps(byte[] file, PadesAugmentOptions options, CancellationToken ct)
    {
        if (options.Level < PadesLevel.Timestamped)
        {
            return file;
        }

        using PdfDocument doc = OpenForAugment(file, editing: false);
        foreach (PdfSignature sig in doc.GetSignatures())
        {
            ct.ThrowIfCancellationRequested();
            if (sig.SubFilter is not ("adbe.pkcs7.detached" or "ETSI.CAdES.detached"))
            {
                continue;
            }

            if (!PdfLayout.TryRanges(sig, file, out long a, out long b, out _) || !PdfLayout.TryContentsBytes(file, a, b, out byte[] contents)
                || !SignedData.TryParse(contents, out SignedData? cms, null, allowTrailingZeros: true) || cms is null || cms.Signers.Count != 1)
            {
                throw new PadesException(PadesError.UnsupportedFile, $"The signature {sig.FieldName} cannot be read as a CMS signature with one signer.");
            }

            SignerInfo signer = cms.Signers[0];
            if (signer.FindUnsigned(CmsOids.SignatureTimeStampToken) is not null)
            {
                continue;
            }

            // RFC 3161 §2.4.1 and EN 319 122-1 §6.1.1: the imprint is the hash of the signature value octets.
            byte[] digest = CryptographicOperations.HashData(options.TimestampHash, signer.Signature.Span);
            TimeStampRequest request = TimeStampRequest.Create(new TimeStampRequestOptions
            {
                Hash = options.TimestampHash,
                MessageImprint = digest,
                Nonce = TimeStampRequest.NewNonce(),
                CertReq = true,
            });
            byte[] answer = await options.Timestamp!(request, ct).ConfigureAwait(false);
            TimeStampReport report = TimeStampVerifier.Verify(request, answer, new TimeStampVerifyOptions { Policy = options.ValidationData?.Policy ?? CryptoPolicy.Standard });
            CmsCheck? refused = report.Checks.FirstOrDefault(static c => c.Rule is "status" or "token" or "message-imprint" or "nonce" or "single-signer" or "signature" && c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported);
            if (refused is not null || report.Token is null)
            {
                throw new PadesException(PadesError.TimestampRefused, "The time-stamp answer was refused: " + (refused is null ? "no token" : refused.Rule + ": " + refused.Reason));
            }

            SignedData updated = cms.WithUnsignedAttribute(0, CmsAttributeEntry.Create(CmsOids.SignatureTimeStampToken, report.Token.Encoded.ToArray()));
            byte[] der = updated.Encoded.ToArray();
            long capacity = (b - a - 2) / 2;
            if (der.Length > capacity)
            {
                throw new PadesException(PadesError.NoRoom, $"The signature {sig.FieldName} reserved {capacity} octets and the time-stamped CMS needs {der.Length}.");
            }

            WriteHex(file, a, b, der);
        }

        return file;
    }

    private static void WriteHex(byte[] file, long a, long b, byte[] der)
    {
        const string Digits = "0123456789ABCDEF";
        int at = (int)a + 1;
        int end = (int)b - 1;
        for (int i = 0; i < der.Length; i++)
        {
            file[at++] = (byte)Digits[der[i] >> 4];
            file[at++] = (byte)Digits[der[i] & 15];
        }

        while (at < end)
        {
            file[at++] = (byte)'0';
        }
    }

    // ---- B-LT: the document security store ----------------------------------------------------------------------------------

    private static PdfDocument OpenForAugment(byte[] file, bool editing)
    {
        if (!PdfDocument.TryOpen(file, out PdfDocument? doc, out PdfException? error, new PdfOpenOptions { AllowEditing = editing }))
        {
            throw new PadesException(PadesError.UnsupportedFile, "The file cannot be opened: " + error.Message);
        }

        return doc;
    }

    private static async ValueTask<byte[]> AddStore(byte[] file, PadesValidationData data, CancellationToken ct)
    {
        using PdfDocument doc = OpenForAugment(file, editing: true);
        if (doc.GetSignatures().Count == 0)
        {
            throw new PadesException(PadesError.UnsupportedFile, "The file has no signature to add validation data for.");
        }

        DssStore existing = DssStore.Read(doc);
        List<PadesStore.Needs> needs = await PadesStore.CollectAsync(doc, file, data, ct).ConfigureAwait(false);
        if (!PadesStore.Apply(doc, existing, needs, data.ReferenceTime, data.WriteVri))
        {
            return file;
        }

        using var ms = new MemoryStream();
        doc.SaveIncremental(ms, cancellationToken: ct);
        return ms.ToArray();
    }

    // ---- B-LTA: the document time-stamp -----------------------------------------------------------------------------------

    private static async ValueTask<byte[]> AddDocumentTimestamp(byte[] file, PadesAugmentOptions options, CancellationToken ct)
    {
        using PdfDocument doc = OpenForAugment(file, editing: true);
        PdfTimestampCallback callback = PadesSigner.Adapt(options.Timestamp!, ct);
        return await Task.Run(() =>
        {
            using var ms = new MemoryStream();
            doc.AddDocumentTimestamp(ms, callback, new PdfTimestampOptions { Hash = options.TimestampHash }, ct);
            return ms.ToArray();
        }, ct).ConfigureAwait(false);
    }
}
