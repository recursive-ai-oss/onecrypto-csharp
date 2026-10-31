using System.Linq;
using System.IO.Compression;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>The outcome of checking a message that carries a digest or a MAC (DigestedData, AuthenticatedData): one entry per rule.</summary>
public sealed class CmsIntegrityReport
{
    internal CmsIntegrityReport(IReadOnlyList<CmsCheck> checks)
    {
        Checks = checks;
    }

    /// <summary>The rules checked, in order, each with its status, reason and RFC section.</summary>
    public IReadOnlyList<CmsCheck> Checks { get; }

    /// <summary>True when no rule failed.</summary>
    public bool IsValid => Checks.All(static c => c.Status != CmsCheckStatus.Failed);
}

/// <summary>An <c>EncapsulatedContentInfo</c> (RFC 5652 §5.2) as the simple content types use it.</summary>
internal sealed class EncapsulatedContent
{
    public string ContentType { get; init; } = string.Empty;

    public ReadOnlyMemory<byte> Content { get; init; }

    public bool HasContent { get; init; }

    public byte[] Encoded { get; init; } = [];

    public static EncapsulatedContent Read(ref Asn1Reader r, ReadOnlyMemory<byte> root)
    {
        ReadOnlySpan<byte> whole = CmsRead.Peek(ref r);
        Asn1Reader enc = r.ReadSequence();
        string type = enc.ReadObjectIdentifier();
        ReadOnlyMemory<byte> content = default;
        bool has = false;
        if (enc.HasData)
        {
            Asn1Reader ex = enc.ReadSequence(Asn1Tag.Context(0, true));
            content = SignerInfo.ReadOctets(ref ex, root);
            ex.ThrowIfNotEmpty();
            has = true;
        }

        enc.ThrowIfNotEmpty();
        return new EncapsulatedContent { ContentType = type, Content = content, HasContent = has, Encoded = whole.ToArray() };
    }

    public static byte[] Encode(string type, ReadOnlySpan<byte> content, bool include = true) =>
        include
            ? DerWriter.Sequence(DerWriter.Oid(type), DerWriter.Context(0, DerWriter.OctetString(content)))
            : DerWriter.Sequence(DerWriter.Oid(type));
}

/// <summary>Shared reading of the outer ContentInfo and the version of the simple content types.</summary>
internal static class ContentTypeReader
{
    public static ReadOnlyMemory<byte> Open(ReadOnlyMemory<byte> encoded, CmsLimits limits, string oid, string name, out ReadOnlyMemory<byte> contentInfo)
    {
        ContentInfo ci = ContentInfo.Parse(encoded, limits);
        if (ci.ContentType != oid || ci.Content.IsEmpty)
        {
            throw new CmsParseException(name, CmsError.UnexpectedContentType, $"the ContentInfo holds {ci.ContentType}");
        }

        contentInfo = ci.Encoded;
        return ci.Content;
    }

    public static byte[] Wrap(string oid, byte[] body) => DerWriter.Sequence(DerWriter.Oid(oid), DerWriter.Context(0, body));
}

/// <summary>
/// A CMS <c>AuthEnvelopedData</c> (RFC 5083): content encrypted and authenticated in one step (AES-GCM, RFC 5084; AES-CCM), with
/// the key delivered to each recipient as in EnvelopedData. The authenticated attributes are the AEAD's associated data.
/// </summary>
public sealed partial class AuthEnvelopedData
{
    private readonly ReadOnlyMemory<byte> _authAttrsEncoded;

    private AuthEnvelopedData(int version, IReadOnlyList<RecipientInfo> recipients, EncryptedContentInfoData eci, IReadOnlyList<CmsAttributeEntry>? auth,
        ReadOnlyMemory<byte> authEncoded, ReadOnlyMemory<byte> mac, IReadOnlyList<CmsAttributeEntry>? unauth, ReadOnlyMemory<byte> encoded, CmsLimits limits)
    {
        Version = version;
        RecipientInfos = recipients;
        EncryptedContentType = eci.ContentType;
        ContentEncryptionAlgorithm = eci.Algorithm;
        EncryptedContent = eci.Ciphertext;
        HasEncryptedContent = eci.HasCiphertext;
        AuthenticatedAttributes = auth;
        _authAttrsEncoded = authEncoded;
        MessageAuthenticationCode = mac;
        UnauthenticatedAttributes = unauth;
        Encoded = encoded;
        Limits = limits;
    }

    /// <summary>The CMS version (0).</summary>
    public int Version { get; }

    /// <summary>The recipient infos in the order received.</summary>
    public IReadOnlyList<RecipientInfo> RecipientInfos { get; }

    /// <summary>The content type of the plaintext.</summary>
    public string EncryptedContentType { get; }

    /// <summary>The content-encryption algorithm with its parameters (nonce and tag length).</summary>
    public AlgorithmIdentifier ContentEncryptionAlgorithm { get; }

    /// <summary>The ciphertext, without the tag.</summary>
    public ReadOnlyMemory<byte> EncryptedContent { get; }

    /// <summary>False when the ciphertext is held elsewhere.</summary>
    public bool HasEncryptedContent { get; }

    /// <summary>The authentication tag.</summary>
    public ReadOnlyMemory<byte> MessageAuthenticationCode { get; }

    /// <summary>The authenticated attributes, or null.</summary>
    public IReadOnlyList<CmsAttributeEntry>? AuthenticatedAttributes { get; }

    /// <summary>The unauthenticated attributes, or null. They are not protected.</summary>
    public IReadOnlyList<CmsAttributeEntry>? UnauthenticatedAttributes { get; }

    /// <summary>The ContentInfo as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The limits the message was read with.</summary>
    public CmsLimits Limits { get; }

    /// <summary>Reads a ContentInfo holding AuthEnvelopedData.</summary>
    /// <exception cref="CmsParseException">The octets are not AuthEnvelopedData, or exceed a limit.</exception>
    public static AuthEnvelopedData Parse(ReadOnlyMemory<byte> encoded, CmsLimits? limits = null)
    {
        limits ??= CmsLimits.Default;
        ReadOnlyMemory<byte> root = ContentTypeReader.Open(encoded, limits, CmsOids.AuthEnvelopedData, "AuthEnvelopedData", out ReadOnlyMemory<byte> ci);
        return CmsRead.Run("AuthEnvelopedData", () => ReadBody(root, ci, limits));
    }

    /// <summary>Reads a ContentInfo holding AuthEnvelopedData, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out AuthEnvelopedData? value, CmsLimits? limits = null) => CmsRead.Try(() => Parse(encoded, limits), out value);

    private static AuthEnvelopedData ReadBody(ReadOnlyMemory<byte> root, ReadOnlyMemory<byte> ci, CmsLimits limits)
    {
        var top = new Asn1Reader(root.Span, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader s = top.ReadSequence();
        top.ThrowIfNotEmpty();
        int version = s.ReadInt32();
        if (version != 0)
        {
            throw CmsRead.Unsupported("AuthEnvelopedData", $"version {version}");
        }

        if (s.HasData && s.PeekTag() == Asn1Tag.Context(0))
        {
            s.ReadEncodedValue(); // originatorInfo: not needed to decrypt.
        }

        IReadOnlyList<RecipientInfo> recipients = EnvelopedData.ReadRecipients(ref s, root, limits);
        EncryptedContentInfoData eci = EncryptedContentInfoData.Read(ref s, root);
        List<CmsAttributeEntry>? auth = null;
        ReadOnlyMemory<byte> authEnc = default;
        if (s.HasData && s.PeekTag() == Asn1Tag.Context(1))
        {
            authEnc = CmsRead.Slice(root, CmsRead.Peek(ref s));
            auth = CmsAttributeEntry.ReadSet(ref s, root, limits, Asn1Tag.Context(1, true));
        }

        ReadOnlyMemory<byte> mac = SignerInfo.ReadOctets(ref s, root);
        List<CmsAttributeEntry>? unauth = null;
        if (s.HasData && s.PeekTag() == Asn1Tag.Context(2))
        {
            unauth = CmsAttributeEntry.ReadSet(ref s, root, limits, Asn1Tag.Context(2, true));
        }

        s.ThrowIfNotEmpty();
        return new AuthEnvelopedData(version, recipients, eci, auth, authEnc, mac, unauth, ci, limits);
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> for the recipients with AES-GCM (or the AEAD named in the options). The authenticated
    /// attributes of the options become the associated data; a content-type attribute is added when the content is not id-data (RFC 5083 §2.2).
    /// </summary>
    public static AuthEnvelopedData Create(ReadOnlySpan<byte> plaintext, IReadOnlyList<CmsRecipient> recipients, CmsEncryptOptions? options = null)
    {
        options ??= new CmsEncryptOptions();
        ContentCipher cipher = EnvelopedData.PrepareCipher(options, recipients, authenticated: true);
        byte[] cek = RandomNumberGenerator.GetBytes(cipher.KeyBytes);
        byte[] nonce = RandomNumberGenerator.GetBytes(cipher.Kind == CipherKind.Gcm ? 12 : 13);
        const int TagBytes = 16;

        var attrs = new List<CmsAttributeEntry>(options.AuthenticatedAttributes);
        if (options.ContentType != CmsOids.Data && CmsAttributeEntry.Find(attrs, CmsOids.ContentType) is null)
        {
            attrs.Add(CmsAttributeEntry.Create(CmsOids.ContentType, DerWriter.Oid(options.ContentType)));
        }

        byte[] authSet = attrs.Count > 0 ? CmsAttributeEntry.EncodeSet(attrs) : [];
        byte[] ciphertext = CmsCiphers.EncryptAead(cipher, cek, nonce, TagBytes, plaintext, authSet, out byte[] tag);
        AlgorithmIdentifier alg = CmsCiphers.Describe(cipher, nonce, TagBytes);
        byte[] eci = EncryptedContentInfoData.Encode(options.ContentType, alg, ciphertext);

        var infos = new List<byte[]>();
        foreach (CmsRecipient r in recipients)
        {
            infos.Add(r.Build(cek));
        }

        CryptographicOperations.ZeroMemory(cek);
        var parts = new List<byte[]> { DerWriter.SignedInteger(0), DerWriter.Set([.. infos]), eci };
        if (authSet.Length > 0)
        {
            parts.Add(DerWriter.Retag(authSet, 0xA1));
        }

        parts.Add(DerWriter.OctetString(tag));
        if (options.UnprotectedAttributes.Count > 0)
        {
            parts.Add(DerWriter.Retag(CmsAttributeEntry.EncodeSet(options.UnprotectedAttributes), 0xA2));
        }

        return Parse(ContentTypeReader.Wrap(CmsOids.AuthEnvelopedData, DerWriter.Sequence([.. parts])));
    }

    /// <summary>
    /// Decrypts and authenticates. The plaintext is released only after the tag verifies over the ciphertext and the authenticated
    /// attributes; the AEAD in the platform is one-shot, so the whole message is held in memory (bounded by
    /// <see cref="CmsLimits.MaxContentBytes"/>). Every failure after a recipient matched raises the same <see cref="CmsError.DecryptionFailed"/>.
    /// </summary>
    /// <exception cref="CmsParseException">No recipient matches, or decryption or authentication failed.</exception>
    public byte[] Decrypt(CmsDecryptionKey key, CmsDecryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        options ??= new CmsDecryptOptions { Limits = Limits };
        if (!CmsCiphers.TryGet(ContentEncryptionAlgorithm.Oid, out ContentCipher cipher) || !cipher.Authenticated)
        {
            throw new CmsParseException("AuthEnvelopedData", CmsError.Unsupported, $"the content-encryption algorithm {ContentEncryptionAlgorithm.Name} is not accepted");
        }

        if (!HasEncryptedContent || EncryptedContent.Length > options.Limits.MaxContentBytes)
        {
            throw new CmsParseException("AuthEnvelopedData", CmsError.UnexpectedStructure, "there is no encrypted content in the message, or it is too large");
        }

        CmsCiphers.ReadParameters(cipher, ContentEncryptionAlgorithm, out byte[] nonce, out int tagBytes);
        CmsPolicyChecks.BeforeDecrypt(options, cipher, key);
        if (!RecipientOpener.TryOpen(RecipientInfos, key, cipher.KeyBytes, options, out byte[] cek, out bool real, out bool matched))
        {
            throw matched ? EnvelopedData.DecryptionFailed("AuthEnvelopedData") : new CmsParseException("AuthEnvelopedData", CmsError.NoMatchingRecipient, "no recipient info matches the key");
        }

        // RFC 5083 §2.2: the associated data is the DER of the authenticated attributes with the SET OF tag; received bytes are retagged, not re-encoded.
        byte[] aad = [];
        bool attrsOk = true;
        if (AuthenticatedAttributes is not null)
        {
            aad = DerWriter.Retag(_authAttrsEncoded.ToArray(), 0x31);
            CmsAttributeEntry? ct = CmsAttributeEntry.Find(AuthenticatedAttributes, CmsOids.ContentType);
            attrsOk = ct is { Values.Count: 1 } && ct.Values[0].Span.SequenceEqual(DerWriter.Oid(EncryptedContentType));
        }
        else if (EncryptedContentType != CmsOids.Data)
        {
            attrsOk = false; // RFC 5083 §2.1: authenticated attributes (with the content type) are required for any other type.
        }

        byte[] plaintext = [];
        bool ok = MessageAuthenticationCode.Length == tagBytes
            && CmsCiphers.TryDecryptAead(cipher, cek, nonce, EncryptedContent.Span, MessageAuthenticationCode.Span, aad, out plaintext);
        CryptographicOperations.ZeroMemory(cek);
        if (!ok || !real || !attrsOk)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw EnvelopedData.DecryptionFailed("AuthEnvelopedData");
        }

        return plaintext;
    }
}

/// <summary>Choices for building an AuthenticatedData.</summary>
public sealed class AuthenticatedDataOptions
{
    /// <summary>The content type of the data (default id-data).</summary>
    public string ContentType { get; init; } = CmsOids.Data;

    /// <summary>The MAC algorithm, HMAC with SHA-256 by default (also SHA-384 and SHA-512).</summary>
    public string MacAlgorithm { get; init; } = CmsOids.HmacSha256;

    /// <summary>Carry the content-type and message-digest attributes and MAC over them (default true, RFC 5652 §9.2).</summary>
    public bool AuthenticatedAttributes { get; init; } = true;

    /// <summary>Leave the content out of the message (the caller supplies it when verifying).</summary>
    public bool Detached { get; init; }
}

/// <summary>A CMS <c>AuthenticatedData</c> (RFC 5652 §9): content with a MAC whose key is delivered to each recipient like an EnvelopedData key.</summary>
public sealed class AuthenticatedData
{
    private readonly ReadOnlyMemory<byte> _authAttrsEncoded;

    private AuthenticatedData(int version, IReadOnlyList<RecipientInfo> recipients, AlgorithmIdentifier mac, AlgorithmIdentifier? digest, EncapsulatedContent content,
        IReadOnlyList<CmsAttributeEntry>? auth, ReadOnlyMemory<byte> authEnc, ReadOnlyMemory<byte> tag, IReadOnlyList<CmsAttributeEntry>? unauth, ReadOnlyMemory<byte> encoded, CmsLimits limits)
    {
        Version = version;
        RecipientInfos = recipients;
        MacAlgorithm = mac;
        DigestAlgorithm = digest;
        ContentType = content.ContentType;
        Content = content.Content;
        HasContent = content.HasContent;
        AuthenticatedAttributes = auth;
        _authAttrsEncoded = authEnc;
        Mac = tag;
        UnauthenticatedAttributes = unauth;
        Encoded = encoded;
        Limits = limits;
    }

    /// <summary>The CMS version.</summary>
    public int Version { get; }

    /// <summary>The recipient infos.</summary>
    public IReadOnlyList<RecipientInfo> RecipientInfos { get; }

    /// <summary>The MAC algorithm.</summary>
    public AlgorithmIdentifier MacAlgorithm { get; }

    /// <summary>The digest algorithm used for the message-digest attribute, or null.</summary>
    public AlgorithmIdentifier? DigestAlgorithm { get; }

    /// <summary>The content type.</summary>
    public string ContentType { get; }

    /// <summary>The content octets; empty when <see cref="HasContent"/> is false.</summary>
    public ReadOnlyMemory<byte> Content { get; }

    /// <summary>False for a detached message.</summary>
    public bool HasContent { get; }

    /// <summary>The authenticated attributes, or null.</summary>
    public IReadOnlyList<CmsAttributeEntry>? AuthenticatedAttributes { get; }

    /// <summary>The MAC value.</summary>
    public ReadOnlyMemory<byte> Mac { get; }

    /// <summary>The unauthenticated attributes, or null.</summary>
    public IReadOnlyList<CmsAttributeEntry>? UnauthenticatedAttributes { get; }

    /// <summary>The ContentInfo as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The limits the message was read with.</summary>
    public CmsLimits Limits { get; }

    /// <summary>Reads a ContentInfo holding AuthenticatedData.</summary>
    /// <exception cref="CmsParseException">The octets are not AuthenticatedData, or exceed a limit.</exception>
    public static AuthenticatedData Parse(ReadOnlyMemory<byte> encoded, CmsLimits? limits = null)
    {
        limits ??= CmsLimits.Default;
        ReadOnlyMemory<byte> root = ContentTypeReader.Open(encoded, limits, CmsOids.AuthenticatedData, "AuthenticatedData", out ReadOnlyMemory<byte> ci);
        return CmsRead.Run("AuthenticatedData", () =>
        {
            var top = new Asn1Reader(root.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader s = top.ReadSequence();
            top.ThrowIfNotEmpty();
            int version = s.ReadInt32();
            if (version is < 0 or > 3)
            {
                throw CmsRead.Unsupported("AuthenticatedData", $"version {version}");
            }

            if (s.HasData && s.PeekTag() == Asn1Tag.Context(0))
            {
                s.ReadEncodedValue();
            }

            IReadOnlyList<RecipientInfo> recipients = EnvelopedData.ReadRecipients(ref s, root, limits);
            AlgorithmIdentifier mac = CmsRead.Alg(ref s, root);
            AlgorithmIdentifier? digest = null;
            if (s.HasData && s.PeekTag() == Asn1Tag.Context(1, true))
            {
                // [1] IMPLICIT AlgorithmIdentifier: re-read the contents as a SEQUENCE.
                ReadOnlySpan<byte> raw = s.ReadEncodedValue();
                digest = AlgorithmIdentifier.Parse(DerWriter.Retag(raw.ToArray(), 0x30));
            }

            EncapsulatedContent content = EncapsulatedContent.Read(ref s, root);
            List<CmsAttributeEntry>? auth = null;
            ReadOnlyMemory<byte> authEnc = default;
            if (s.HasData && s.PeekTag() == Asn1Tag.Context(2))
            {
                authEnc = CmsRead.Slice(root, CmsRead.Peek(ref s));
                auth = CmsAttributeEntry.ReadSet(ref s, root, limits, Asn1Tag.Context(2, true));
            }

            ReadOnlyMemory<byte> tag = SignerInfo.ReadOctets(ref s, root);
            List<CmsAttributeEntry>? unauth = null;
            if (s.HasData && s.PeekTag() == Asn1Tag.Context(3))
            {
                unauth = CmsAttributeEntry.ReadSet(ref s, root, limits, Asn1Tag.Context(3, true));
            }

            s.ThrowIfNotEmpty();
            return new AuthenticatedData(version, recipients, mac, digest, content, auth, authEnc, tag, unauth, ci, limits);
        });
    }

    /// <summary>Reads a ContentInfo holding AuthenticatedData, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out AuthenticatedData? value, CmsLimits? limits = null) => CmsRead.Try(() => Parse(encoded, limits), out value);

    private static HashAlgorithmName HashOf(string macOid) => macOid switch
    {
        CmsOids.HmacSha256 => HashAlgorithmName.SHA256,
        CmsOids.HmacSha384 => HashAlgorithmName.SHA384,
        CmsOids.HmacSha512 => HashAlgorithmName.SHA512,
        CmsOids.HmacSha1 or "1.2.840.113549.2.7" => HashAlgorithmName.SHA1,
        _ => default,
    };

    private static string DigestOidFor(string macOid) => macOid switch
    {
        CmsOids.HmacSha384 => KnownOids.Sha384,
        CmsOids.HmacSha512 => KnownOids.Sha512,
        _ => KnownOids.Sha256,
    };

    /// <summary>Builds an AuthenticatedData: a random MAC key, delivered to the recipients, over the content (or the attributes that carry its digest).</summary>
    public static AuthenticatedData Create(ReadOnlySpan<byte> content, IReadOnlyList<CmsRecipient> recipients, AuthenticatedDataOptions? options = null)
    {
        options ??= new AuthenticatedDataOptions();
        ArgumentNullException.ThrowIfNull(recipients);
        if (recipients.Count == 0)
        {
            throw new ArgumentException("There must be at least one recipient.", nameof(recipients));
        }

        if (recipients.Any(static r => r.IsLegacy))
        {
            throw new NotSupportedException("RSA PKCS #1 v1.5 key transport is legacy and is not written for AuthenticatedData.");
        }

        HashAlgorithmName hash = HashOf(options.MacAlgorithm);
        if (hash == default || hash == HashAlgorithmName.SHA1)
        {
            throw new NotSupportedException($"The MAC algorithm {options.MacAlgorithm} cannot be written.");
        }

        byte[] key = RandomNumberGenerator.GetBytes(HashOutputBytes(hash));
        string digestOid = DigestOidFor(options.MacAlgorithm);
        byte[] macInput = content.ToArray();
        byte[]? authSet = null;
        if (options.AuthenticatedAttributes)
        {
            CmsDigest.TryHash(digestOid, content, out byte[] digest);
            authSet = CmsAttributeEntry.EncodeSet(
            [
                CmsAttributeEntry.Create(CmsOids.ContentType, DerWriter.Oid(options.ContentType)),
                CmsAttributeEntry.Create(CmsOids.MessageDigest, DerWriter.OctetString(digest)),
            ]);
            macInput = authSet;
        }

        byte[] tag = Hmac(hash, key, macInput);
        var infos = new List<byte[]>();
        foreach (CmsRecipient r in recipients)
        {
            infos.Add(r.Build(key));
        }

        CryptographicOperations.ZeroMemory(key);
        var parts = new List<byte[]>
        {
            DerWriter.SignedInteger(0),
            DerWriter.Set([.. infos]),
            AlgorithmIdentifier.Create(options.MacAlgorithm).Encoded.ToArray(),
        };
        if (authSet is not null)
        {
            parts.Add(DerWriter.Retag(AlgorithmIdentifier.Create(digestOid).Encoded.ToArray(), 0xA1));
        }

        parts.Add(EncapsulatedContent.Encode(options.ContentType, content, !options.Detached));
        if (authSet is not null)
        {
            parts.Add(DerWriter.Retag(authSet, 0xA2));
        }

        parts.Add(DerWriter.OctetString(tag));
        return Parse(ContentTypeReader.Wrap(CmsOids.AuthenticatedData, DerWriter.Sequence([.. parts])));
    }

    private static byte[] Hmac(HashAlgorithmName hash, byte[] key, byte[] data)
    {
        using IncrementalHash h = IncrementalHash.CreateHMAC(hash, key);
        h.AppendData(data);
        return h.GetHashAndReset();
    }

    private static int HashOutputBytes(HashAlgorithmName h) => h == HashAlgorithmName.SHA384 ? 48 : h == HashAlgorithmName.SHA512 ? 64 : 32;

    /// <summary>
    /// Recovers the MAC key with <paramref name="key"/> and checks the MAC, and with attributes the content type and message digest too
    /// (RFC 5652 §9.2, §9.3). The MAC is compared in constant time.
    /// </summary>
    /// <param name="key">The recipient's key.</param>
    /// <param name="detachedContent">The content when the message does not carry it.</param>
    /// <param name="options">Decryption options for recipient handling (the limits and v1.5 acceptance).</param>
    public CmsIntegrityReport Verify(CmsDecryptionKey key, ReadOnlySpan<byte> detachedContent = default, CmsDecryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        options ??= new CmsDecryptOptions { Limits = Limits };
        var checks = new List<CmsCheck>();
        HashAlgorithmName hash = HashOf(MacAlgorithm.Oid);
        if (hash == default)
        {
            checks.Add(new CmsCheck("mac-algorithm", CmsCheckStatus.Failed, $"The MAC algorithm {MacAlgorithm.Oid} is not supported.", "RFC 5652 §9.1"));
            return new CmsIntegrityReport(checks);
        }

        if (hash == HashAlgorithmName.SHA1)
        {
            checks.Add(new CmsCheck("mac-algorithm", CmsCheckStatus.Warning, "HMAC-SHA-1 is legacy.", "RFC 5652 §9.1"));
        }

        CmsPolicyChecks.BeforeDecrypt(options, null, key);
        if (!RecipientOpener.TryOpen(RecipientInfos, key, 0, options, out byte[] macKey, out _, out bool matched))
        {
            checks.Add(new CmsCheck("recipient", CmsCheckStatus.Failed, matched ? "The MAC key could not be recovered." : "No recipient info matches the key.", "RFC 5652 §9.1"));
            return new CmsIntegrityReport(checks);
        }

        ReadOnlySpan<byte> data = HasContent ? Content.Span : detachedContent;
        if (!HasContent && detachedContent.IsEmpty)
        {
            checks.Add(new CmsCheck("content", CmsCheckStatus.Failed, "The message has no content; supply the detached content.", "RFC 5652 §9.1"));
            return new CmsIntegrityReport(checks);
        }

        byte[] macInput;
        if (AuthenticatedAttributes is null)
        {
            macInput = data.ToArray();
        }
        else
        {
            macInput = DerWriter.Retag(_authAttrsEncoded.ToArray(), 0x31);
            CmsAttributeEntry? ct = CmsAttributeEntry.Find(AuthenticatedAttributes, CmsOids.ContentType);
            checks.Add(ct is { Values.Count: 1 } && ct.Values[0].Span.SequenceEqual(DerWriter.Oid(ContentType))
                ? new CmsCheck("content-type", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §11.1")
                : new CmsCheck("content-type", CmsCheckStatus.Failed, "The content-type attribute is missing or differs from the content type.", "RFC 5652 §11.1"));
            CmsAttributeEntry? md = CmsAttributeEntry.Find(AuthenticatedAttributes, CmsOids.MessageDigest);
            bool digestOk = false;
            if (md is { Values.Count: 1 } && DigestAlgorithm is not null && CmsDigest.TryHash(DigestAlgorithm.Oid, data, out byte[] computed))
            {
                byte[] expected = DerWriter.OctetString(computed);
                digestOk = md.Values[0].Length == expected.Length && CryptographicOperations.FixedTimeEquals(md.Values[0].Span, expected);
            }

            checks.Add(digestOk
                ? new CmsCheck("message-digest", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §11.2")
                : new CmsCheck("message-digest", CmsCheckStatus.Failed, "The message-digest attribute is missing or does not match the content.", "RFC 5652 §11.2"));
        }

        byte[] expectedMac = Hmac(hash, macKey, macInput);
        CryptographicOperations.ZeroMemory(macKey);
        bool macOk = expectedMac.Length == Mac.Length && CryptographicOperations.FixedTimeEquals(expectedMac, Mac.Span);
        checks.Add(macOk
            ? new CmsCheck("mac", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §9.2")
            : new CmsCheck("mac", CmsCheckStatus.Failed, "The MAC does not match.", "RFC 5652 §9.2"));
        return new CmsIntegrityReport(checks);
    }
}

/// <summary>A CMS <c>DigestedData</c> (RFC 5652 §7): content with its digest. It proves integrity against accident only; anyone can recompute it.</summary>
public sealed class DigestedData
{
    private DigestedData(int version, AlgorithmIdentifier alg, EncapsulatedContent content, ReadOnlyMemory<byte> digest, ReadOnlyMemory<byte> encoded)
    {
        Version = version;
        DigestAlgorithm = alg;
        ContentType = content.ContentType;
        Content = content.Content;
        HasContent = content.HasContent;
        Digest = digest;
        Encoded = encoded;
    }

    /// <summary>The CMS version (0, or 2 for a content type other than id-data).</summary>
    public int Version { get; }

    /// <summary>The digest algorithm.</summary>
    public AlgorithmIdentifier DigestAlgorithm { get; }

    /// <summary>The content type.</summary>
    public string ContentType { get; }

    /// <summary>The content octets.</summary>
    public ReadOnlyMemory<byte> Content { get; }

    /// <summary>False for a detached message.</summary>
    public bool HasContent { get; }

    /// <summary>The digest value as received.</summary>
    public ReadOnlyMemory<byte> Digest { get; }

    /// <summary>The ContentInfo as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>Reads a ContentInfo holding DigestedData.</summary>
    /// <exception cref="CmsParseException">The octets are not DigestedData, or exceed a limit.</exception>
    public static DigestedData Parse(ReadOnlyMemory<byte> encoded, CmsLimits? limits = null)
    {
        limits ??= CmsLimits.Default;
        ReadOnlyMemory<byte> root = ContentTypeReader.Open(encoded, limits, CmsOids.DigestedData, "DigestedData", out ReadOnlyMemory<byte> ci);
        return CmsRead.Run("DigestedData", () =>
        {
            var top = new Asn1Reader(root.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader s = top.ReadSequence();
            top.ThrowIfNotEmpty();
            int version = s.ReadInt32();
            if (version is not (0 or 2))
            {
                throw CmsRead.Unsupported("DigestedData", $"version {version}");
            }

            AlgorithmIdentifier alg = CmsRead.Alg(ref s, root);
            EncapsulatedContent content = EncapsulatedContent.Read(ref s, root);
            ReadOnlyMemory<byte> digest = SignerInfo.ReadOctets(ref s, root);
            s.ThrowIfNotEmpty();
            return new DigestedData(version, alg, content, digest, ci);
        });
    }

    /// <summary>Reads a ContentInfo holding DigestedData, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out DigestedData? value, CmsLimits? limits = null) => CmsRead.Try(() => Parse(encoded, limits), out value);

    /// <summary>Builds a DigestedData with SHA-256 unless <paramref name="digestAlgorithm"/> names another digest.</summary>
    public static DigestedData Create(ReadOnlySpan<byte> content, string contentType = CmsOids.Data, string digestAlgorithm = KnownOids.Sha256, bool detached = false)
    {
        if (!CmsDigest.TryHash(digestAlgorithm, content, out byte[] digest))
        {
            throw new NotSupportedException($"The digest algorithm {digestAlgorithm} is not supported.");
        }

        byte[] body = DerWriter.Sequence(
            DerWriter.SignedInteger(contentType == CmsOids.Data ? 0 : 2),
            AlgorithmIdentifier.Create(digestAlgorithm).Encoded.ToArray(),
            EncapsulatedContent.Encode(contentType, content, !detached),
            DerWriter.OctetString(digest));
        return Parse(ContentTypeReader.Wrap(CmsOids.DigestedData, body));
    }

    /// <summary>Recomputes the digest over the content (or <paramref name="detachedContent"/>) and compares it in constant time.</summary>
    public CmsIntegrityReport Verify(ReadOnlySpan<byte> detachedContent = default)
    {
        if (!HasContent && detachedContent.IsEmpty)
        {
            return new CmsIntegrityReport([new CmsCheck("content", CmsCheckStatus.Failed, "The message has no content; supply the detached content.", "RFC 5652 §7")]);
        }

        if (!CmsDigest.TryHash(DigestAlgorithm.Oid, HasContent ? Content.Span : detachedContent, out byte[] computed))
        {
            return new CmsIntegrityReport([new CmsCheck("digest-algorithm", CmsCheckStatus.Failed, $"The digest algorithm {DigestAlgorithm.Oid} is not supported.", "RFC 5652 §7")]);
        }

        bool ok = computed.Length == Digest.Length && CryptographicOperations.FixedTimeEquals(computed, Digest.Span);
        return new CmsIntegrityReport([ok
            ? new CmsCheck("digest", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §7")
            : new CmsCheck("digest", CmsCheckStatus.Failed, "The digest does not match the content.", "RFC 5652 §7")]);
    }
}

/// <summary>A CMS <c>EncryptedData</c> (RFC 5652 §8): content encrypted with a key the parties already share, with no recipient infos.</summary>
public sealed class EncryptedData
{
    private EncryptedData(int version, EncryptedContentInfoData eci, IReadOnlyList<CmsAttributeEntry>? unprotected, ReadOnlyMemory<byte> encoded, CmsLimits limits)
    {
        Version = version;
        ContentType = eci.ContentType;
        ContentEncryptionAlgorithm = eci.Algorithm;
        EncryptedContent = eci.Ciphertext;
        HasEncryptedContent = eci.HasCiphertext;
        UnprotectedAttributes = unprotected;
        Encoded = encoded;
        Limits = limits;
    }

    /// <summary>The CMS version (0, or 2 with unprotected attributes).</summary>
    public int Version { get; }

    /// <summary>The content type of the plaintext.</summary>
    public string ContentType { get; }

    /// <summary>The content-encryption algorithm with its parameters.</summary>
    public AlgorithmIdentifier ContentEncryptionAlgorithm { get; }

    /// <summary>The encrypted content.</summary>
    public ReadOnlyMemory<byte> EncryptedContent { get; }

    /// <summary>False when the ciphertext is held elsewhere.</summary>
    public bool HasEncryptedContent { get; }

    /// <summary>The unprotected attributes, or null.</summary>
    public IReadOnlyList<CmsAttributeEntry>? UnprotectedAttributes { get; }

    /// <summary>The ContentInfo as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The limits the message was read with.</summary>
    public CmsLimits Limits { get; }

    /// <summary>Reads a ContentInfo holding EncryptedData.</summary>
    /// <exception cref="CmsParseException">The octets are not EncryptedData, or exceed a limit.</exception>
    public static EncryptedData Parse(ReadOnlyMemory<byte> encoded, CmsLimits? limits = null)
    {
        limits ??= CmsLimits.Default;
        ReadOnlyMemory<byte> root = ContentTypeReader.Open(encoded, limits, CmsOids.EncryptedData, "EncryptedData", out ReadOnlyMemory<byte> ci);
        return CmsRead.Run("EncryptedData", () =>
        {
            var top = new Asn1Reader(root.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader s = top.ReadSequence();
            top.ThrowIfNotEmpty();
            int version = s.ReadInt32();
            if (version is not (0 or 2))
            {
                throw CmsRead.Unsupported("EncryptedData", $"version {version}");
            }

            EncryptedContentInfoData eci = EncryptedContentInfoData.Read(ref s, root);
            List<CmsAttributeEntry>? unprotected = null;
            if (s.HasData && s.PeekTag() == Asn1Tag.Context(1))
            {
                unprotected = CmsAttributeEntry.ReadSet(ref s, root, limits, Asn1Tag.Context(1, true));
            }

            s.ThrowIfNotEmpty();
            return new EncryptedData(version, eci, unprotected, ci, limits);
        });
    }

    /// <summary>Reads a ContentInfo holding EncryptedData, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out EncryptedData? value, CmsLimits? limits = null) => CmsRead.Try(() => Parse(encoded, limits), out value);

    /// <summary>Encrypts with AES-CBC (256-bit by default; the key length must match the algorithm in the options). Not authenticated: prefer AuthEnvelopedData.</summary>
    public static EncryptedData Create(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, CmsEncryptOptions? options = null)
    {
        options ??= new CmsEncryptOptions();
        ContentCipher cipher = CmsCiphers.Require(options.ContentEncryption ?? CmsOids.Aes256Cbc);
        if (cipher.Kind != CipherKind.Cbc || key.Length != cipher.KeyBytes)
        {
            throw new ArgumentException($"EncryptedData is written with AES-CBC and a {cipher.KeyBytes}-octet key for {cipher.Name}.", nameof(key));
        }

        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] ct = CmsCiphers.EncryptCbc(cipher, key, iv, plaintext);
        var parts = new List<byte[]>
        {
            DerWriter.SignedInteger(options.UnprotectedAttributes.Count > 0 ? 2 : 0),
            EncryptedContentInfoData.Encode(options.ContentType, CmsCiphers.Describe(cipher, iv, 0), ct),
        };
        if (options.UnprotectedAttributes.Count > 0)
        {
            parts.Add(DerWriter.Retag(CmsAttributeEntry.EncodeSet(options.UnprotectedAttributes), 0xA1));
        }

        return Parse(ContentTypeReader.Wrap(CmsOids.EncryptedData, DerWriter.Sequence([.. parts])));
    }

    /// <summary>Decrypts with the shared key. A wrong key or damaged content raises <see cref="CmsError.DecryptionFailed"/> and releases nothing.</summary>
    /// <exception cref="CmsParseException">Decryption failed or the algorithm is not accepted.</exception>
    public byte[] Decrypt(ReadOnlySpan<byte> key, CmsDecryptOptions? options = null)
    {
        options ??= new CmsDecryptOptions { Limits = Limits };
        if (!CmsCiphers.TryGet(ContentEncryptionAlgorithm.Oid, out ContentCipher cipher) || cipher.Authenticated || (cipher.Kind == CipherKind.TripleDesCbc && !options.AllowLegacyCiphers))
        {
            throw new CmsParseException("EncryptedData", CmsError.Unsupported, $"the content-encryption algorithm {ContentEncryptionAlgorithm.Name} is not accepted");
        }

        if (!HasEncryptedContent || EncryptedContent.Length > options.Limits.MaxContentBytes)
        {
            throw new CmsParseException("EncryptedData", CmsError.UnexpectedStructure, "there is no encrypted content in the message, or it is too large");
        }

        CmsCiphers.ReadParameters(cipher, ContentEncryptionAlgorithm, out byte[] iv, out _);
        if (key.Length != cipher.KeyBytes || !CmsCiphers.TryDecryptCbc(cipher, key, iv, EncryptedContent.Span, out byte[] plaintext))
        {
            throw EnvelopedData.DecryptionFailed("EncryptedData");
        }

        return plaintext;
    }
}

/// <summary>A CMS <c>CompressedData</c> (RFC 3274): content compressed with zlib. Decompression is bounded by <see cref="CmsLimits"/>.</summary>
public sealed partial class CompressedData
{
    private CompressedData(int version, AlgorithmIdentifier alg, EncapsulatedContent content, ReadOnlyMemory<byte> encoded, CmsLimits limits)
    {
        Version = version;
        CompressionAlgorithm = alg;
        ContentType = content.ContentType;
        CompressedContent = content.Content;
        HasContent = content.HasContent;
        Encoded = encoded;
        Limits = limits;
    }

    /// <summary>The CMS version (0).</summary>
    public int Version { get; }

    /// <summary>The compression algorithm (zlib, RFC 3274 §2).</summary>
    public AlgorithmIdentifier CompressionAlgorithm { get; }

    /// <summary>The content type of the uncompressed data.</summary>
    public string ContentType { get; }

    /// <summary>The compressed octets.</summary>
    public ReadOnlyMemory<byte> CompressedContent { get; }

    /// <summary>False when the content is absent.</summary>
    public bool HasContent { get; }

    /// <summary>The ContentInfo as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The limits the message was read with.</summary>
    public CmsLimits Limits { get; }

    /// <summary>Reads a ContentInfo holding CompressedData.</summary>
    /// <exception cref="CmsParseException">The octets are not CompressedData, or exceed a limit.</exception>
    public static CompressedData Parse(ReadOnlyMemory<byte> encoded, CmsLimits? limits = null)
    {
        limits ??= CmsLimits.Default;
        ReadOnlyMemory<byte> root = ContentTypeReader.Open(encoded, limits, CmsOids.CompressedData, "CompressedData", out ReadOnlyMemory<byte> ci);
        return CmsRead.Run("CompressedData", () =>
        {
            var top = new Asn1Reader(root.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader s = top.ReadSequence();
            top.ThrowIfNotEmpty();
            int version = s.ReadInt32();
            if (version != 0)
            {
                throw CmsRead.Unsupported("CompressedData", $"version {version}");
            }

            AlgorithmIdentifier alg = CmsRead.Alg(ref s, root);
            EncapsulatedContent content = EncapsulatedContent.Read(ref s, root);
            s.ThrowIfNotEmpty();
            return new CompressedData(version, alg, content, ci, limits);
        });
    }

    /// <summary>Reads a ContentInfo holding CompressedData, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out CompressedData? value, CmsLimits? limits = null) => CmsRead.Try(() => Parse(encoded, limits), out value);

    /// <summary>Compresses with zlib at the default level.</summary>
    public static CompressedData Create(ReadOnlySpan<byte> content, string contentType = CmsOids.Data)
    {
        var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            z.Write(content);
        }

        byte[] body = DerWriter.Sequence(
            DerWriter.SignedInteger(0),
            AlgorithmIdentifier.Create(CmsOids.ZlibCompress).Encoded.ToArray(),
            EncapsulatedContent.Encode(contentType, ms.ToArray()));
        return Parse(ContentTypeReader.Wrap(CmsOids.CompressedData, body));
    }

    /// <summary>
    /// Decompresses, stopping with <see cref="CmsError.LimitExceeded"/> when the output passes <see cref="CmsLimits.MaxDecompressedBytes"/> or
    /// <see cref="CmsLimits.MaxDecompressionRatio"/> times the compressed size (a compression bomb).
    /// </summary>
    /// <exception cref="CmsParseException">The algorithm is not zlib, the data is damaged, or a limit was exceeded.</exception>
    public byte[] Decompress(CmsLimits? limits = null)
    {
        limits ??= Limits;
        if (CompressionAlgorithm.Oid != CmsOids.ZlibCompress)
        {
            throw new CmsParseException("CompressedData", CmsError.Unsupported, $"the compression algorithm {CompressionAlgorithm.Oid} is not supported");
        }

        if (!HasContent)
        {
            throw new CmsParseException("CompressedData", CmsError.UnexpectedStructure, "there is no content");
        }

        long cap = Math.Min(limits.MaxDecompressedBytes, Math.Max(4096L, (long)CompressedContent.Length * limits.MaxDecompressionRatio));
        var output = new MemoryStream();
        try
        {
            using var z = new ZLibStream(new MemoryStream(CompressedContent.ToArray(), writable: false), CompressionMode.Decompress);
            byte[] buffer = new byte[16 * 1024];
            int n;
            while ((n = z.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length + n > cap)
                {
                    throw new CmsParseException("CompressedData", CmsError.LimitExceeded, "the decompressed size passes the limit");
                }

                output.Write(buffer, 0, n);
            }
        }
        catch (IOException e)
        {
            throw new CmsParseException("CompressedData", CmsError.InvalidValue, e.Message);
        }

        return output.ToArray();
    }
}
