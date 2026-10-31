using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>Helpers for the streaming CMS operations: forward-only reading of a message with indefinite lengths, and the segment writer.</summary>
internal static class CmsStream
{
    public const int Chunk = 1 << 16;

    /// <summary>The most memory the small elements around streamed content (recipients, certificates, signer infos) may take together.</summary>
    public const int SmallElementBudget = 64 << 20;

    public static byte[] Tlv(Asn1Tag tag, ReadOnlySpan<byte> content)
    {
        byte[] header = new byte[Asn1Wire.MaxHeaderLength];
        int n = tag.Encode(header);
        n += Asn1Wire.EncodeLength(content.Length, header.AsSpan(n));
        byte[] result = new byte[n + content.Length];
        header.AsSpan(0, n).CopyTo(result);
        content.CopyTo(result.AsSpan(n));
        return result;
    }

    /// <summary>
    /// Reads the rest of the element that <paramref name="t"/> opened and returns it with definite lengths. Contents are unchanged;
    /// this is only used for the small elements around streamed content, so the signed parts of a signer info keep their bytes.
    /// </summary>
    public static byte[] Raw(Asn1StreamReader r, Asn1Token t, ref int budget)
    {
        if (t.Kind == Asn1TokenKind.Primitive)
        {
            if (t.Length > budget)
            {
                throw CmsRead.Limit("CMS", "an element around the content is too large");
            }

            byte[] c = r.ReadContent();
            budget -= c.Length + 16;
            return Tlv(t.Tag, c);
        }

        if (t.Kind != Asn1TokenKind.StartConstructed)
        {
            throw CmsRead.Bad("CMS", "an element was expected");
        }

        var children = new List<byte[]>();
        int total = 0;
        while (true)
        {
            Asn1Token n = r.ReadToken();
            if (n.Kind == Asn1TokenKind.EndConstructed)
            {
                break;
            }

            byte[] child = Raw(r, n, ref budget);
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

        return Tlv(t.Tag.WithConstructed(true), body);
    }

    public static Asn1Token Expect(Asn1StreamReader r, Asn1TokenKind kind, Asn1Tag? tag, string what)
    {
        Asn1Token t = r.ReadToken();
        if (t.Kind != kind || (tag is { } want && (t.Tag.TagClass != want.TagClass || t.Tag.TagNumber != want.TagNumber)))
        {
            throw CmsRead.Bad(what, "the message is not laid out as expected");
        }

        return t;
    }

    public static string Oid(byte[] element)
    {
        var rd = new Asn1Reader(element, Asn1Rules.Ber);
        return rd.ReadObjectIdentifier();
    }

    public static byte[] ReadAll(Stream s, long max)
    {
        var ms = new MemoryStream();
        byte[] buf = new byte[Chunk];
        int n;
        while ((n = s.Read(buf, 0, buf.Length)) > 0)
        {
            if (ms.Length + n > max)
            {
                throw CmsRead.Limit("CMS", "the message is larger than the limit");
            }

            ms.Write(buf, 0, n);
        }

        return ms.ToArray();
    }

    /// <summary>A write-only stream that frames every write as one definite-length OCTET STRING segment.</summary>
    internal sealed class SegmentSink : Stream
    {
        private readonly BerStreamWriter _w;

        public SegmentSink(BerStreamWriter w) => _w = w;

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (!buffer.IsEmpty)
            {
                _w.WriteDefinite(new Asn1Tag(Asn1Tags.OctetString), buffer);
            }
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}

public sealed partial class SignedData
{
    /// <summary>
    /// Signs the content of <paramref name="content"/> and writes the message to <paramref name="output"/> as indefinite-length BER, in
    /// constant memory whatever the size: the content is hashed as it is copied out in segments. Every signer must use signed attributes
    /// (a signature over the content itself cannot be made in one pass). With <see cref="SignedDataOptions.Detached"/> the content is
    /// hashed and left out.
    /// </summary>
    /// <param name="content">The content, read once to its end.</param>
    /// <param name="output">Where the message goes; it stays open.</param>
    /// <param name="signers">One or more signers.</param>
    /// <param name="options">Choices, or null for an attached id-data message.</param>
    /// <exception cref="NotSupportedException">A signer does not use signed attributes, or its digest is unavailable.</exception>
    public static void SignStream(Stream content, Stream output, IReadOnlyList<CmsSignerSpec> signers, SignedDataOptions? options = null)
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

            plans.Add(SignerPlan.For(s));
        }

        using var digests = new DigestSet(plans.Select(static p => p.DigestOid).Distinct());
        var w = new BerStreamWriter(output);
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.Oid(CmsOids.SignedData));
        w.BeginIndefinite(Asn1Tag.Context(0, true));
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.SignedInteger(VersionOf(options, plans)));
        w.WriteEncodedValue(DigestAlgorithmSet(plans));
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.Oid(options.ContentType));
        byte[] buffer = new byte[CmsStream.Chunk];
        if (options.Detached)
        {
            Pump(content, buffer, digests, null);
        }
        else
        {
            w.BeginIndefinite(Asn1Tag.Context(0, true));
            w.BeginIndefinite(new Asn1Tag(Asn1Tags.OctetString));
            Pump(content, buffer, digests, w);
            w.End();
            w.End();
        }

        w.End();
        foreach (byte[] part in CertificateParts(options, plans))
        {
            w.WriteEncodedValue(part);
        }

        Dictionary<string, byte[]> hashes = digests.Finish();
        var infos = new List<byte[]>();
        foreach (SignerPlan p in plans)
        {
            infos.Add(p.Build(options.ContentType, hashes[p.DigestOid], default, countersignature: false));
        }

        w.WriteEncodedValue(DerWriter.Set([.. infos]));
        w.End();
        w.End();
        w.End();
        output.Flush();
    }

    private static void Pump(Stream content, byte[] buffer, DigestSet digests, BerStreamWriter? w)
    {
        int n;
        while ((n = content.Read(buffer, 0, buffer.Length)) > 0)
        {
            digests.Append(buffer.AsSpan(0, n));
            w?.WriteDefinite(new Asn1Tag(Asn1Tags.OctetString), buffer.AsSpan(0, n));
        }
    }

    /// <summary>
    /// Verifies an attached SignedData read from a forward-only stream, in constant memory: the encapsulated content (definite or
    /// indefinite length, primitive or segmented) is hashed as it passes, and the certificates and signer infos that follow it are
    /// read after. If <paramref name="contentOutput"/> is given, the content is copied to it while being read; <b>it is not verified until
    /// this method returns a valid report</b>, so treat it as untrusted until then. For a detached message, parse it and call
    /// <see cref="Verify(Stream, SignedDataVerifyOptions)"/> with the content stream.
    /// </summary>
    /// <param name="message">The ContentInfo octets; read to the end of the element.</param>
    /// <param name="contentOutput">Where the content goes as it is read, or null to only hash it.</param>
    /// <param name="options">Verification options, or null.</param>
    /// <param name="limits">Limits, or null for the options' limits.</param>
    /// <exception cref="CmsParseException">The stream is not an attached SignedData, or exceeds a limit.</exception>
    public static SignedDataReport VerifyStream(Stream message, Stream? contentOutput = null, SignedDataVerifyOptions? options = null, CmsLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(message);
        options ??= new SignedDataVerifyOptions();
        limits ??= options.Limits ?? CmsLimits.Default;
        try
        {
            var r = new Asn1StreamReader(message, Asn1Rules.Ber, limits.Asn1);
            int budget = CmsStream.SmallElementBudget;
            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "ContentInfo");
            byte[] oid = CmsStream.Raw(r, r.ReadToken(), ref budget);
            if (CmsStream.Oid(oid) != CmsOids.SignedData)
            {
                throw new CmsParseException("SignedData", CmsError.UnexpectedContentType, "the ContentInfo does not hold SignedData");
            }

            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Context(0, true), "ContentInfo");
            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "SignedData");
            byte[] version = CmsStream.Raw(r, r.ReadToken(), ref budget);
            byte[] das = CmsStream.Raw(r, r.ReadToken(), ref budget);
            var algs = new List<string>();
            var dr = new Asn1Reader(das, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader set = dr.ReadSet();
            while (set.HasData)
            {
                algs.Add(AlgorithmIdentifier.Parse(set.ReadEncodedValue().ToArray()).Oid);
            }

            using var digests = new DigestSet(algs.Distinct());
            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "EncapsulatedContentInfo");
            byte[] type = CmsStream.Raw(r, r.ReadToken(), ref budget);
            Asn1Token t = r.ReadToken();
            if (t.Kind == Asn1TokenKind.EndConstructed)
            {
                throw new CmsParseException("SignedData", CmsError.UnexpectedStructure, "the message has no encapsulated content; parse it and use Verify with the content");
            }

            if (t.Kind != Asn1TokenKind.StartConstructed || t.Tag != Asn1Tag.Context(0, true))
            {
                throw CmsRead.Bad("EncapsulatedContentInfo", "the content is not in [0]");
            }

            Asn1Token o = r.ReadToken();
            byte[] buffer = new byte[CmsStream.Chunk];
            if (o.Kind == Asn1TokenKind.Primitive && o.Tag == new Asn1Tag(Asn1Tags.OctetString))
            {
                int n;
                while ((n = r.Read(buffer)) > 0)
                {
                    digests.Append(buffer.AsSpan(0, n));
                    contentOutput?.Write(buffer, 0, n);
                }
            }
            else if (o.Kind == Asn1TokenKind.StartConstructed && o.Tag == new Asn1Tag(Asn1Tags.OctetString))
            {
                Stream s = r.OpenOctetString(o);
                int n;
                while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
                {
                    digests.Append(buffer.AsSpan(0, n));
                    contentOutput?.Write(buffer, 0, n);
                }
            }
            else
            {
                throw CmsRead.Bad("EncapsulatedContentInfo", "the content is not an OCTET STRING");
            }

            CmsStream.Expect(r, Asn1TokenKind.EndConstructed, null, "EncapsulatedContentInfo");
            CmsStream.Expect(r, Asn1TokenKind.EndConstructed, null, "EncapsulatedContentInfo");
            byte[]? certs = null;
            byte[]? crls = null;
            byte[]? signers = null;
            while (true)
            {
                Asn1Token n = r.ReadToken();
                if (n.Kind == Asn1TokenKind.EndConstructed)
                {
                    break;
                }

                byte[] el = CmsStream.Raw(r, n, ref budget);
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

            CmsStream.Expect(r, Asn1TokenKind.EndConstructed, null, "ContentInfo");
            CmsStream.Expect(r, Asn1TokenKind.EndConstructed, null, "ContentInfo");

            // The content has been hashed already; a SignedData without it carries the signers and certificates for the check.
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
    /// Encrypts the stream with AES-CBC and writes the message as indefinite-length BER, in constant memory whatever the size. The
    /// recipients get the key first; the ciphertext follows in segments. CBC does not authenticate: for streams you control prefer
    /// <see cref="AuthEnvelopedData.EncryptStream"/>.
    /// </summary>
    /// <param name="plaintext">The content, read to its end.</param>
    /// <param name="output">Where the message goes; it stays open.</param>
    /// <param name="recipients">One or more recipients.</param>
    /// <param name="options">Choices, or null for AES-256-CBC.</param>
    public static void EncryptStream(Stream plaintext, Stream output, IReadOnlyList<CmsRecipient> recipients, CmsEncryptOptions? options = null)
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
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.Oid(CmsOids.EnvelopedData));
        w.BeginIndefinite(Asn1Tag.Context(0, true));
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.SignedInteger(VersionFor(recipients, infos, options)));
        w.WriteEncodedValue(DerWriter.Set([.. infos]));
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.Oid(options.ContentType));
        w.WriteEncodedValue(CmsCiphers.Describe(cipher, iv, 0).Encoded.Span);
        w.BeginIndefinite(Asn1Tag.Context(0, true));
        try
        {
            using Aes aes = Aes.Create();
            using ICryptoTransform enc = aes.CreateEncryptor(cek, iv);
            using (var cs = new CryptoStream(new CmsStream.SegmentSink(w), enc, CryptoStreamMode.Write, leaveOpen: true))
            {
                byte[] buffer = new byte[CmsStream.Chunk];
                int n;
                while ((n = plaintext.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, n);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }

        w.End();
        w.End();
        if (options.UnprotectedAttributes.Count > 0)
        {
            w.WriteEncodedValue(DerWriter.Retag(CmsAttributeEntry.EncodeSet(options.UnprotectedAttributes), 0xA1));
        }

        w.End();
        w.End();
        w.End();
        output.Flush();
    }

    /// <summary>
    /// Decrypts a message read from a forward-only stream, in constant memory. The recipient infos come first, so a key that matches
    /// none is refused before anything is written. CBC cannot be checked until its last block, so <b>the plaintext reaches
    /// <paramref name="plaintextOutput"/> before the padding is known to be good</b>: only the final block is held back. When this method
    /// throws, discard whatever was written. A wrong key, bad padding and a failed RSA PKCS #1 v1.5 unwrap all end in the same
    /// <see cref="CmsError.DecryptionFailed"/> after the whole content was read, so the caller learns no more than from <see cref="Decrypt"/>.
    /// Use <see cref="AuthEnvelopedData"/> when authenticity matters.
    /// </summary>
    /// <param name="message">The ContentInfo octets, definite or indefinite length.</param>
    /// <param name="plaintextOutput">Where the plaintext goes; it stays open.</param>
    /// <param name="key">The recipient's key.</param>
    /// <param name="options">Options, or null for the defaults.</param>
    /// <exception cref="CmsParseException">No recipient matches, the message is malformed, or decryption failed.</exception>
    public static void DecryptStream(Stream message, Stream plaintextOutput, CmsDecryptionKey key, CmsDecryptOptions? options = null)
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
            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "ContentInfo");
            if (CmsStream.Oid(CmsStream.Raw(r, r.ReadToken(), ref budget)) != CmsOids.EnvelopedData)
            {
                throw new CmsParseException("EnvelopedData", CmsError.UnexpectedContentType, "the ContentInfo does not hold EnvelopedData");
            }

            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Context(0, true), "ContentInfo");
            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "EnvelopedData");
            CmsStream.Raw(r, r.ReadToken(), ref budget); // version
            Asn1Token t = r.ReadToken();
            if (t.Kind == Asn1TokenKind.StartConstructed && t.Tag == Asn1Tag.Context(0, true))
            {
                CmsStream.Raw(r, t, ref budget); // originatorInfo
                t = r.ReadToken();
            }

            byte[] recipientSet = CmsStream.Raw(r, t, ref budget);
            var rd = new Asn1Reader(recipientSet, Asn1Rules.Ber, limits.Asn1);
            IReadOnlyList<RecipientInfo> recipients = ReadRecipients(ref rd, recipientSet, limits);
            CmsStream.Expect(r, Asn1TokenKind.StartConstructed, Asn1Tag.Sequence, "EncryptedContentInfo");
            CmsStream.Raw(r, r.ReadToken(), ref budget); // content type
            AlgorithmIdentifier alg = AlgorithmIdentifier.Parse(CmsStream.Raw(r, r.ReadToken(), ref budget));
            if (!CmsCiphers.TryGet(alg.Oid, out ContentCipher cipher) || cipher.Authenticated || (cipher.Kind == CipherKind.TripleDesCbc && !options.AllowLegacyCiphers))
            {
                throw new CmsParseException("EnvelopedData", CmsError.Unsupported, $"the content-encryption algorithm {alg.Name} is not accepted");
            }

            CmsCiphers.ReadParameters(cipher, alg, out byte[] iv, out _);
            if (!RecipientOpener.TryOpen(recipients, key, cipher.KeyBytes, options, out byte[] cek, out bool real, out bool matched))
            {
                throw matched ? DecryptionFailed("EnvelopedData") : new CmsParseException("EnvelopedData", CmsError.NoMatchingRecipient, "no recipient info matches the key");
            }

            t = r.ReadToken();
            Stream? segments = null;
            if (t.Kind == Asn1TokenKind.StartConstructed && t.Tag == Asn1Tag.Context(0, true))
            {
                segments = r.OpenOctetString(t, Asn1Tag.Context(0, true));
            }
            else if (t.Kind != Asn1TokenKind.Primitive || t.Tag != Asn1Tag.Context(0))
            {
                CryptographicOperations.ZeroMemory(cek);
                throw CmsRead.Bad("EncryptedContentInfo", "there is no encrypted content");
            }

            bool ok = true;
            try
            {
                using Aes aes = Aes.Create();
                using ICryptoTransform dec = aes.CreateDecryptor(cek, iv);
                using var cs = new CryptoStream(plaintextOutput, dec, CryptoStreamMode.Write, leaveOpen: true);
                byte[] buffer = new byte[CmsStream.Chunk];
                int n;
                while ((n = segments is null ? r.Read(buffer) : segments.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, n);
                }

                cs.FlushFinalBlock();
            }
            catch (CryptographicException)
            {
                ok = false;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(cek);
            }

            if (!ok || !real)
            {
                throw DecryptionFailed("EnvelopedData");
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
    /// Reads the plaintext (at most <see cref="CmsLimits.MaxContentBytes"/>) and writes the message. The platform's AES-GCM and AES-CCM are
    /// one-shot, so this holds the content in memory; it exists so callers use one stream shape for every content type.
    /// </summary>
    public static void EncryptStream(Stream plaintext, Stream output, IReadOnlyList<CmsRecipient> recipients, CmsEncryptOptions? options = null, CmsLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(output);
        byte[] data = CmsStream.ReadAll(plaintext, (limits ?? CmsLimits.Default).MaxContentBytes);
        output.Write(Create(data, recipients, options).Encoded.Span);
        CryptographicOperations.ZeroMemory(data);
    }

    /// <summary>
    /// Reads the message (at most <see cref="CmsLimits.MaxContentBytes"/> of it), authenticates it and only then writes the plaintext. The
    /// platform's AEAD is one-shot, so peak memory is about twice the message size; nothing reaches <paramref name="plaintextOutput"/> unless
    /// the tag verifies.
    /// </summary>
    public static void DecryptStream(Stream message, Stream plaintextOutput, CmsDecryptionKey key, CmsDecryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(plaintextOutput);
        CmsLimits limits = options?.Limits ?? CmsLimits.Default;
        byte[] data = CmsStream.ReadAll(message, limits.MaxContentBytes);
        byte[] plaintext = Parse(data, limits).Decrypt(key, options);
        plaintextOutput.Write(plaintext);
        CryptographicOperations.ZeroMemory(plaintext);
    }
}
