using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>The asynchronous reading helpers of the streaming CMS operations; they mirror <see cref="CmsStream"/> and share its rules.</summary>
internal static class CmsStreamAsync
{
    /// <summary>The asynchronous twin of <see cref="CmsStream.Raw"/>: reads the rest of the element that <paramref name="t"/> opened and returns it with definite lengths.</summary>
    public static async ValueTask<(byte[] Element, int Budget)> RawAsync(Asn1StreamReader r, Asn1Token t, int budget, CancellationToken cancellationToken)
    {
        if (t.Kind == Asn1TokenKind.Primitive)
        {
            if (t.Length > budget)
            {
                throw CmsRead.Limit("CMS", "an element around the content is too large");
            }

            byte[] c = await r.ReadContentAsync(cancellationToken).ConfigureAwait(false);
            return (CmsStream.Tlv(t.Tag, c), budget - (c.Length + 16));
        }

        if (t.Kind != Asn1TokenKind.StartConstructed)
        {
            throw CmsRead.Bad("CMS", "an element was expected");
        }

        var children = new List<byte[]>();
        int total = 0;
        while (true)
        {
            Asn1Token n = await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false);
            if (n.Kind == Asn1TokenKind.EndConstructed)
            {
                break;
            }

            (byte[] child, budget) = await RawAsync(r, n, budget, cancellationToken).ConfigureAwait(false);
            total += child.Length;
            children.Add(child);
        }

        var body = new byte[total];
        int at = 0;
        foreach (byte[] ch in children)
        {
            ch.CopyTo(body, at);
            at += ch.Length;
        }

        return (CmsStream.Tlv(t.Tag.WithConstructed(true), body), budget);
    }

    public static async ValueTask<Asn1Token> ExpectAsync(Asn1StreamReader r, Asn1TokenKind kind, Asn1Tag? tag, string what, CancellationToken cancellationToken)
    {
        Asn1Token t = await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false);
        if (t.Kind != kind || (tag is { } want && (t.Tag.TagClass != want.TagClass || t.Tag.TagNumber != want.TagNumber)))
        {
            throw CmsRead.Bad(what, "the message is not laid out as expected");
        }

        return t;
    }

    public static async ValueTask<byte[]> ReadAllAsync(Stream s, long max, CancellationToken cancellationToken)
    {
        var ms = new MemoryStream();
        byte[] buf = new byte[CmsStream.Chunk];
        int n;
        while ((n = await s.ReadAsync(buf, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + n > max)
            {
                throw CmsRead.Limit("CMS", "the message is larger than the limit");
            }

            ms.Write(buf, 0, n);
        }

        return ms.ToArray();
    }
}

public sealed partial class SignedData
{
    /// <summary>
    /// The asynchronous twin of <see cref="SignStream"/>: signs <paramref name="content"/> and writes the message as indefinite-length BER in constant
    /// memory, reading and writing without blocking a thread. Keys behind the key interfaces are asked through their async methods.
    /// </summary>
    /// <param name="content">The content, read once to its end.</param>
    /// <param name="output">Where the message goes; it stays open. After a cancellation it holds a partial message: discard it.</param>
    /// <param name="signers">One or more signers, all with signed attributes.</param>
    /// <param name="options">Choices, or null for an attached id-data message.</param>
    /// <param name="cancellationToken">Cancels the operation between reads and writes.</param>
    /// <exception cref="NotSupportedException">A signer does not use signed attributes, or its digest is unavailable.</exception>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    public static async Task SignStreamAsync(Stream content, Stream output, IReadOnlyList<CmsSignerSpec> signers, SignedDataOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(signers);
        options ??= new SignedDataOptions();
        var plans = new List<SignerPlan>();
        foreach (CmsSignerSpec s in signers)
        {
            if (!s.SignedAttributes)
            {
                throw new NotSupportedException("Streaming signing needs signed attributes: a signature over the bare content cannot be made in one pass.");
            }

            plans.Add(SignerPlan.For(s, options.Policy));
        }

        using var digests = new DigestSet(plans.Select(static p => p.DigestOid).Distinct());
        var w = new BerStreamWriter(output);
        await w.BeginIndefiniteAsync(Asn1Tag.Sequence, cancellationToken).ConfigureAwait(false);
        await w.WriteEncodedValueAsync(DerWriter.Oid(CmsOids.SignedData), cancellationToken).ConfigureAwait(false);
        await w.BeginIndefiniteAsync(Asn1Tag.Context(0, true), cancellationToken).ConfigureAwait(false);
        await w.BeginIndefiniteAsync(Asn1Tag.Sequence, cancellationToken).ConfigureAwait(false);
        await w.WriteEncodedValueAsync(DerWriter.SignedInteger(VersionOf(options, plans)), cancellationToken).ConfigureAwait(false);
        await w.WriteEncodedValueAsync(DigestAlgorithmSet(plans), cancellationToken).ConfigureAwait(false);
        await w.BeginIndefiniteAsync(Asn1Tag.Sequence, cancellationToken).ConfigureAwait(false);
        await w.WriteEncodedValueAsync(DerWriter.Oid(options.ContentType), cancellationToken).ConfigureAwait(false);
        byte[] buffer = new byte[CmsStream.Chunk];
        if (options.Detached)
        {
            await PumpAsync(content, buffer, digests, null, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await w.BeginIndefiniteAsync(Asn1Tag.Context(0, true), cancellationToken).ConfigureAwait(false);
            await w.BeginIndefiniteAsync(new Asn1Tag(Asn1Tags.OctetString), cancellationToken).ConfigureAwait(false);
            await PumpAsync(content, buffer, digests, w, cancellationToken).ConfigureAwait(false);
            await w.EndAsync(cancellationToken).ConfigureAwait(false);
            await w.EndAsync(cancellationToken).ConfigureAwait(false);
        }

        await w.EndAsync(cancellationToken).ConfigureAwait(false);
        foreach (byte[] part in CertificateParts(options, plans))
        {
            await w.WriteEncodedValueAsync(part, cancellationToken).ConfigureAwait(false);
        }

        Dictionary<string, byte[]> hashes = digests.Finish();
        var infos = new List<byte[]>();
        foreach (SignerPlan p in plans)
        {
            SignerPlan.Parts parts = p.Prepare(options.ContentType, hashes[p.DigestOid], default, countersignature: false);
            byte[] signature = await p.SignDataAsync(parts.Data, cancellationToken).ConfigureAwait(false);
            infos.Add(p.Finish(parts, signature));
        }

        await w.WriteEncodedValueAsync(DerWriter.Set([.. infos]), cancellationToken).ConfigureAwait(false);
        await w.EndAsync(cancellationToken).ConfigureAwait(false);
        await w.EndAsync(cancellationToken).ConfigureAwait(false);
        await w.EndAsync(cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask PumpAsync(Stream content, byte[] buffer, DigestSet digests, BerStreamWriter? w, CancellationToken cancellationToken)
    {
        int n;
        while ((n = await content.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            digests.Append(buffer.AsSpan(0, n));
            if (w is not null)
            {
                await w.WriteDefiniteAsync(new Asn1Tag(Asn1Tags.OctetString), buffer.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// The asynchronous twin of <see cref="VerifyStream"/>: verifies an attached SignedData read from a forward-only stream in constant memory. If
    /// <paramref name="contentOutput"/> is given the content is copied to it while being read; <b>it is not verified until this method returns a valid
    /// report</b>, so treat it as untrusted until then (and after a cancellation).
    /// </summary>
    /// <param name="message">The ContentInfo octets; read to the end of the element.</param>
    /// <param name="contentOutput">Where the content goes as it is read, or null to only hash it.</param>
    /// <param name="options">Verification options, or null.</param>
    /// <param name="limits">Limits, or null for the options' limits.</param>
    /// <param name="cancellationToken">Cancels the operation between reads and writes.</param>
    /// <exception cref="CmsParseException">The stream is not an attached SignedData, or exceeds a limit.</exception>
    /// <exception cref="OperationCanceledException">The token was cancelled.</exception>
    public static async Task<SignedDataReport> VerifyStreamAsync(Stream message, Stream? contentOutput = null, SignedDataVerifyOptions? options = null, CmsLimits? limits = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        options ??= new SignedDataVerifyOptions();
        limits ??= options.Limits ?? CmsLimits.Default;
        try
        {
            var r = new Asn1StreamReader(message, Asn1Rules.Ber, limits.Asn1);
            int budget = CmsStream.SmallElementBudget;
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "ContentInfo", cancellationToken).ConfigureAwait(false);
            byte[] oid;
            (oid, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false);
            if (CmsStream.Oid(oid) != CmsOids.SignedData)
            {
                throw new CmsParseException("SignedData", CmsError.UnexpectedContentType, "the ContentInfo does not hold SignedData");
            }

            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Context(0, true), "ContentInfo", cancellationToken).ConfigureAwait(false);
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "SignedData", cancellationToken).ConfigureAwait(false);
            byte[] version;
            (version, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false);
            byte[] das;
            (das, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false);
            var algs = new List<string>();
            var dr = new Asn1Reader(das, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader set = dr.ReadSet();
            while (set.HasData)
            {
                algs.Add(AlgorithmIdentifier.Parse(set.ReadEncodedValue().ToArray()).Oid);
            }

            using var digests = new DigestSet(algs.Distinct());
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "EncapsulatedContentInfo", cancellationToken).ConfigureAwait(false);
            byte[] type;
            (type, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false);
            Asn1Token t = await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false);
            if (t.Kind == Asn1TokenKind.EndConstructed)
            {
                throw new CmsParseException("SignedData", CmsError.UnexpectedStructure, "the message has no encapsulated content; parse it and use Verify with the content");
            }

            if (t.Kind != Asn1TokenKind.StartConstructed || t.Tag != Asn1Tag.Context(0, true))
            {
                throw CmsRead.Bad("EncapsulatedContentInfo", "the content is not in [0]");
            }

            Asn1Token o = await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false);
            byte[] buffer = new byte[CmsStream.Chunk];
            int n;
            if (o.Kind == Asn1TokenKind.Primitive && o.Tag == new Asn1Tag(Asn1Tags.OctetString))
            {
                while ((n = await r.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    digests.Append(buffer.AsSpan(0, n));
                    if (contentOutput is not null)
                    {
                        await contentOutput.WriteAsync(buffer.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            else if (o.Kind == Asn1TokenKind.StartConstructed && o.Tag == new Asn1Tag(Asn1Tags.OctetString))
            {
                Stream s = r.OpenOctetString(o);
                while ((n = await s.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    digests.Append(buffer.AsSpan(0, n));
                    if (contentOutput is not null)
                    {
                        await contentOutput.WriteAsync(buffer.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            else
            {
                throw CmsRead.Bad("EncapsulatedContentInfo", "the content is not an OCTET STRING");
            }

            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.EndConstructed, null, "EncapsulatedContentInfo", cancellationToken).ConfigureAwait(false);
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.EndConstructed, null, "EncapsulatedContentInfo", cancellationToken).ConfigureAwait(false);
            byte[]? certs = null;
            byte[]? crls = null;
            byte[]? signers = null;
            while (true)
            {
                Asn1Token next = await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false);
                if (next.Kind == Asn1TokenKind.EndConstructed)
                {
                    break;
                }

                byte[] el;
                (el, budget) = await CmsStreamAsync.RawAsync(r, next, budget, cancellationToken).ConfigureAwait(false);
                switch (el[0])
                {
                    case 0xA0: certs = el; break;
                    case 0xA1: crls = el; break;
                    case 0x31: signers = el; break;
                    default: throw CmsRead.Bad("SignedData", "an unexpected element follows the content");
                }
            }

            if (signers is null)
            {
                throw CmsRead.Bad("SignedData", "there is no signerInfos set");
            }

            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.EndConstructed, null, "ContentInfo", cancellationToken).ConfigureAwait(false);
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.EndConstructed, null, "ContentInfo", cancellationToken).ConfigureAwait(false);

            var parts = new List<byte[]> { version, das, DerWriter.Sequence(type) };
            if (certs is not null)
            {
                parts.Add(certs);
            }

            if (crls is not null)
            {
                parts.Add(crls);
            }

            parts.Add(signers);
            byte[] reduced = DerWriter.Sequence(DerWriter.Oid(CmsOids.SignedData), DerWriter.Context(0, DerWriter.Sequence([.. parts])));
            SignedData sd = Parse(reduced, limits: limits);
            return sd.VerifyWithDigests(digests.Finish(), options);
        }
        catch (Asn1ParseException e)
        {
            throw new CmsParseException("SignedData", e);
        }
        catch (X509ParseException e)
        {
            throw new CmsParseException("SignedData", CmsError.UnexpectedStructure, e.Message);
        }
    }
}

public sealed partial class EnvelopedData
{
    /// <summary>
    /// The asynchronous twin of <see cref="EncryptStream"/>: encrypts with AES-CBC and writes indefinite-length BER in constant memory. CBC does not
    /// authenticate; for streams you control prefer <see cref="AuthEnvelopedData.EncryptStreamAsync"/>.
    /// </summary>
    /// <param name="plaintext">The content, read to its end.</param>
    /// <param name="output">Where the message goes; it stays open. After a cancellation it holds a partial message: discard it.</param>
    /// <param name="recipients">One or more recipients.</param>
    /// <param name="options">Choices, or null for AES-256-CBC.</param>
    /// <param name="cancellationToken">Cancels the operation between reads and writes.</param>
    public static async Task EncryptStreamAsync(Stream plaintext, Stream output, IReadOnlyList<CmsRecipient> recipients, CmsEncryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(output);
        options ??= new CmsEncryptOptions();
        ContentCipher cipher = PrepareCipher(options, recipients, authenticated: false);
        byte[] cek = RandomNumberGenerator.GetBytes(cipher.KeyBytes);
        byte[] iv = RandomNumberGenerator.GetBytes(cipher.BlockBytes);
        var infos = new List<byte[]>();
        foreach (CmsRecipient r in recipients)
        {
            infos.Add(r.Build(cek));
        }

        var w = new BerStreamWriter(output);
        await w.BeginIndefiniteAsync(Asn1Tag.Sequence, cancellationToken).ConfigureAwait(false);
        await w.WriteEncodedValueAsync(DerWriter.Oid(CmsOids.EnvelopedData), cancellationToken).ConfigureAwait(false);
        await w.BeginIndefiniteAsync(Asn1Tag.Context(0, true), cancellationToken).ConfigureAwait(false);
        await w.BeginIndefiniteAsync(Asn1Tag.Sequence, cancellationToken).ConfigureAwait(false);
        await w.WriteEncodedValueAsync(DerWriter.SignedInteger(VersionFor(recipients, infos, options)), cancellationToken).ConfigureAwait(false);
        await w.WriteEncodedValueAsync(DerWriter.Set([.. infos]), cancellationToken).ConfigureAwait(false);
        await w.BeginIndefiniteAsync(Asn1Tag.Sequence, cancellationToken).ConfigureAwait(false);
        await w.WriteEncodedValueAsync(DerWriter.Oid(options.ContentType), cancellationToken).ConfigureAwait(false);
        await w.WriteEncodedValueAsync(CmsCiphers.Describe(cipher, iv, 0).Encoded, cancellationToken).ConfigureAwait(false);
        await w.BeginIndefiniteAsync(Asn1Tag.Context(0, true), cancellationToken).ConfigureAwait(false);
        try
        {
            using Aes aes = Aes.Create();
            using ICryptoTransform enc = aes.CreateEncryptor(cek, iv);
            var cs = new CryptoStream(new CmsStream.SegmentSink(w), enc, CryptoStreamMode.Write, leaveOpen: true);
            byte[] buffer = new byte[CmsStream.Chunk];
            int n;
            while ((n = await plaintext.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                await cs.WriteAsync(buffer.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
            }

            await cs.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }

        await w.EndAsync(cancellationToken).ConfigureAwait(false);
        await w.EndAsync(cancellationToken).ConfigureAwait(false);
        if (options.UnprotectedAttributes.Count > 0)
        {
            await w.WriteEncodedValueAsync(DerWriter.Retag(CmsAttributeEntry.EncodeSet(options.UnprotectedAttributes), 0xA1), cancellationToken).ConfigureAwait(false);
        }

        await w.EndAsync(cancellationToken).ConfigureAwait(false);
        await w.EndAsync(cancellationToken).ConfigureAwait(false);
        await w.EndAsync(cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The asynchronous twin of <see cref="DecryptStream"/>: decrypts a message read from a forward-only stream in constant memory. The recipient infos
    /// come first, so a key that matches none is refused before anything is written. CBC cannot be checked until its last block, so <b>plaintext reaches
    /// <paramref name="plaintextOutput"/> before the padding is known to be good</b> (only the final block is held back); when this method throws or is
    /// cancelled, discard whatever was written. A cancelled operation never finishes the final block.
    /// </summary>
    /// <param name="message">The ContentInfo octets, definite or indefinite length.</param>
    /// <param name="plaintextOutput">Where the plaintext goes; it stays open.</param>
    /// <param name="key">The recipient's key.</param>
    /// <param name="options">Options, or null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the operation between reads and writes.</param>
    /// <exception cref="CmsParseException">No recipient matches, the message is malformed, or decryption failed.</exception>
    public static async Task DecryptStreamAsync(Stream message, Stream plaintextOutput, CmsDecryptionKey key, CmsDecryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(plaintextOutput);
        ArgumentNullException.ThrowIfNull(key);
        options ??= new CmsDecryptOptions();
        CmsLimits limits = options.Limits;
        try
        {
            var r = new Asn1StreamReader(message, Asn1Rules.Ber, limits.Asn1);
            int budget = CmsStream.SmallElementBudget;
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "ContentInfo", cancellationToken).ConfigureAwait(false);
            byte[] oid;
            (oid, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false);
            if (CmsStream.Oid(oid) != CmsOids.EnvelopedData)
            {
                throw new CmsParseException("EnvelopedData", CmsError.UnexpectedContentType, "the ContentInfo does not hold EnvelopedData");
            }

            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Context(0, true), "ContentInfo", cancellationToken).ConfigureAwait(false);
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "EnvelopedData", cancellationToken).ConfigureAwait(false);
            (_, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false); // version
            Asn1Token t = await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false);
            if (t.Kind == Asn1TokenKind.StartConstructed && t.Tag == Asn1Tag.Context(0, true))
            {
                (_, budget) = await CmsStreamAsync.RawAsync(r, t, budget, cancellationToken).ConfigureAwait(false); // originatorInfo
                t = await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false);
            }

            byte[] recipientSet;
            (recipientSet, budget) = await CmsStreamAsync.RawAsync(r, t, budget, cancellationToken).ConfigureAwait(false);
            var rd = new Asn1Reader(recipientSet, Asn1Rules.Ber, limits.Asn1);
            IReadOnlyList<RecipientInfo> recipients = ReadRecipients(ref rd, recipientSet, limits);
            await CmsStreamAsync.ExpectAsync(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "EncryptedContentInfo", cancellationToken).ConfigureAwait(false);
            (_, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false); // content type
            byte[] algBytes;
            (algBytes, budget) = await CmsStreamAsync.RawAsync(r, await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false), budget, cancellationToken).ConfigureAwait(false);
            AlgorithmIdentifier alg = AlgorithmIdentifier.Parse(algBytes);
            if (!CmsCiphers.TryGet(alg.Oid, out ContentCipher cipher) || cipher.Authenticated || (cipher.Kind == CipherKind.TripleDesCbc && !options.AllowLegacyCiphers))
            {
                throw new CmsParseException("EnvelopedData", CmsError.Unsupported, $"the content-encryption algorithm {alg.Name} is not accepted");
            }

            CmsCiphers.ReadParameters(cipher, alg, out byte[] iv, out _);
            CmsPolicyChecks.BeforeDecrypt(options, cipher, key);
            if (!RecipientOpener.TryOpen(recipients, key, cipher.KeyBytes, options, out byte[] cek, out bool real, out bool matched))
            {
                throw matched ? DecryptionFailed("EnvelopedData") : new CmsParseException("EnvelopedData", CmsError.NoMatchingRecipient, "no recipient info matches the key");
            }

            try
            {
                t = await r.ReadTokenAsync(cancellationToken).ConfigureAwait(false);
                Stream? segments = null;
                if (t.Kind == Asn1TokenKind.StartConstructed && t.Tag == Asn1Tag.Context(0, true))
                {
                    segments = r.OpenOctetString(t, Asn1Tag.Context(0, true));
                }
                else if (t.Kind != Asn1TokenKind.Primitive || t.Tag != Asn1Tag.Context(0))
                {
                    throw CmsRead.Bad("EncryptedContentInfo", "there is no encrypted content");
                }

                bool ok = true;
                using Aes aes = Aes.Create();
                using ICryptoTransform dec = aes.CreateDecryptor(cek, iv);
                var cs = new CryptoStream(plaintextOutput, dec, CryptoStreamMode.Write, leaveOpen: true);
                byte[] buffer = new byte[CmsStream.Chunk];
                int n;
                while ((n = segments is null
                    ? await r.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)
                    : await segments.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    await cs.WriteAsync(buffer.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
                }

                // Only the normal end finishes the final block; a cancellation or a read error jumps past this and never releases it.
                try
                {
                    await cs.DisposeAsync().ConfigureAwait(false);
                }
                catch (CryptographicException)
                {
                    ok = false;
                }

                if (!ok || !real)
                {
                    throw DecryptionFailed("EnvelopedData");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(cek);
            }
        }
        catch (Asn1ParseException e)
        {
            throw new CmsParseException("EnvelopedData", e);
        }
        catch (X509ParseException e)
        {
            throw new CmsParseException("EnvelopedData", CmsError.UnexpectedStructure, e.Message);
        }
    }
}

public sealed partial class AuthEnvelopedData
{
    /// <summary>
    /// The asynchronous twin of <see cref="EncryptStream"/>. The platform's AES-GCM and AES-CCM are one-shot, so the content (at most
    /// <see cref="CmsLimits.MaxContentBytes"/>) is held in memory exactly as in the synchronous form; the reading and writing do not block.
    /// </summary>
    public static async Task EncryptStreamAsync(Stream plaintext, Stream output, IReadOnlyList<CmsRecipient> recipients, CmsEncryptOptions? options = null, CmsLimits? limits = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(output);
        byte[] data = await CmsStreamAsync.ReadAllAsync(plaintext, (limits ?? CmsLimits.Default).MaxContentBytes, cancellationToken).ConfigureAwait(false);
        try
        {
            await output.WriteAsync(Create(data, recipients, options).Encoded, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    /// <summary>
    /// The asynchronous twin of <see cref="DecryptStream"/>: reads the message (at most <see cref="CmsLimits.MaxContentBytes"/> of it), authenticates it
    /// and only then writes the plaintext. Nothing reaches <paramref name="plaintextOutput"/> unless the tag verifies, and nothing does after a cancellation
    /// before the write starts.
    /// </summary>
    public static async Task DecryptStreamAsync(Stream message, Stream plaintextOutput, CmsDecryptionKey key, CmsDecryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(plaintextOutput);
        CmsLimits limits = options?.Limits ?? CmsLimits.Default;
        byte[] data = await CmsStreamAsync.ReadAllAsync(message, limits.MaxContentBytes, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        byte[] plaintext = Parse(data, limits).Decrypt(key, options);
        try
        {
            await plaintextOutput.WriteAsync(plaintext, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
