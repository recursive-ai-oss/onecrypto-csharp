using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>Choices for building encrypted CMS messages.</summary>
public sealed class CmsEncryptOptions
{
    /// <summary>The content type of the plaintext (default id-data).</summary>
    public string ContentType { get; init; } = CmsOids.Data;

    /// <summary>
    /// The content-encryption algorithm. The default is AES-256-CBC for EnvelopedData and EncryptedData, and AES-256-GCM for AuthEnvelopedData.
    /// </summary>
    public string? ContentEncryption { get; init; }

    /// <summary>Allow writing legacy forms (RSA PKCS #1 v1.5 key transport). Reading them is governed by <see cref="CmsDecryptOptions"/>.</summary>
    public bool AllowLegacy { get; init; }

    /// <summary>Unprotected (or unauthenticated) attributes to add.</summary>
    public IReadOnlyList<CmsAttributeEntry> UnprotectedAttributes { get; init; } = [];

    /// <summary>Authenticated attributes for AuthEnvelopedData; they are the AEAD's associated data. Content-type is added when the type is not id-data.</summary>
    public IReadOnlyList<CmsAttributeEntry> AuthenticatedAttributes { get; init; } = [];

    /// <summary>
    /// The policy for new data (default <see cref="Policy.CryptoPolicy.Standard"/>): it judges the content cipher and each recipient's public key
    /// (RSA under 2048 bits is refused, 3072 under Strict). Standard flags CBC content encryption and still writes it; Strict refuses it.
    /// </summary>
    public Policy.CryptoPolicy? Policy { get; init; }
}

/// <summary>Choices for opening encrypted CMS messages. The defaults refuse legacy ciphers.</summary>
public sealed class CmsDecryptOptions
{
    /// <summary>Limits applied while reading and decrypting.</summary>
    public CmsLimits Limits { get; init; } = CmsLimits.Default;

    /// <summary>Accept Triple-DES content (legacy, default false).</summary>
    public bool AllowLegacyCiphers { get; init; }

    /// <summary>Accept RSA PKCS #1 v1.5 key transport (default true; its failures are made indistinguishable, RFC 3218 §2.3).</summary>
    public bool AllowPkcs1V15KeyTransport { get; init; } = true;

    /// <summary>
    /// The policy that judges the message's content cipher and the key that opens it. Null applies none. Standard flags CBC content encryption (no
    /// integrity of its own) and decrypts it; Strict refuses it. A refusal throws <see cref="Policy.PolicyViolationException"/> before any key is used.
    /// </summary>
    public Policy.CryptoPolicy? Policy { get; init; }

    /// <summary>The instant the policy is asked about. Required when <see cref="Policy"/> is set; the library never reads a clock.</summary>
    public DateTimeOffset? ReferenceTime { get; init; }
}

/// <summary>The <c>EncryptedContentInfo</c> (RFC 5652 §6.1) shared by EnvelopedData, AuthEnvelopedData and EncryptedData.</summary>
internal sealed class EncryptedContentInfoData
{
    public string ContentType { get; init; } = string.Empty;

    public AlgorithmIdentifier Algorithm { get; init; } = null!;

    public ReadOnlyMemory<byte> Ciphertext { get; init; }

    public bool HasCiphertext { get; init; }

    public static EncryptedContentInfoData Read(ref Asn1Reader r, ReadOnlyMemory<byte> root)
    {
        Asn1Reader s = r.ReadSequence();
        string type = s.ReadObjectIdentifier();
        AlgorithmIdentifier alg = CmsRead.Alg(ref s, root);
        ReadOnlyMemory<byte> data = default;
        bool has = false;
        if (s.HasData)
        {
            // [0] IMPLICIT OCTET STRING, primitive or (BER) constructed.
            data = s.PeekTag().IsConstructed ? s.ReadOctetStringBytes(Asn1Tag.Context(0, true)) : CmsRead.Slice(root, s.ReadOctetString(Asn1Tag.Context(0)));
            has = true;
        }

        s.ThrowIfNotEmpty();
        return new EncryptedContentInfoData { ContentType = type, Algorithm = alg, Ciphertext = data, HasCiphertext = has };
    }

    public static byte[] Encode(string contentType, AlgorithmIdentifier alg, ReadOnlySpan<byte> ciphertext) =>
        DerWriter.Sequence(DerWriter.Oid(contentType), alg.Encoded.ToArray(), DerWriter.ContextPrimitive(0, ciphertext));
}

/// <summary>Opens recipient infos with a key and returns the content-encryption key.</summary>
internal static class RecipientOpener
{
    /// <summary>
    /// Tries the recipient infos meant for <paramref name="key"/>. When the key is an RSA key and every key transport fails, a random key of the
    /// right length comes back with <paramref name="real"/> false, so decryption runs on and fails the same way whatever went wrong (RFC 3218 §2.3).
    /// </summary>
    public static bool TryOpen(IReadOnlyList<RecipientInfo> recipients, CmsDecryptionKey key, int cekLength, CmsDecryptOptions options, out byte[] cek, out bool real, out bool matched)
    {
        cek = [];
        real = false;
        matched = false;
        bool transportFailed = false;
        foreach (RecipientInfo ri in recipients)
        {
            byte[]? found = null;
            try
            {
                switch (ri)
                {
                    case KeyTransRecipientInfo kt when key.Certificate is null || kt.Identifier.Matches(key.Certificate):
                        if (kt.KeyEncryptionAlgorithm.Oid == KnownOids.RsaEncryption && !options.AllowPkcs1V15KeyTransport)
                        {
                            break;
                        }

                        matched = true;
                        found = key.UnwrapKeyTransport(kt.KeyEncryptionAlgorithm, kt.EncryptedKey.Span);
                        transportFailed |= found is null || (cekLength > 0 && found.Length != cekLength);
                        break;
                    case KeyAgreeRecipientInfo ka:
                        found = OpenAgreement(ka, key, ref matched);
                        break;
                    case KekRecipientInfo kek:
                        found = OpenKek(kek, key, ref matched);
                        break;
                    case PasswordRecipientInfo pw:
                        found = OpenPassword(pw, key, options, ref matched);
                        break;
                    case KemRecipientInfo kem when key.Certificate is null || kem.Identifier.Matches(key.Certificate):
                        matched = true;
                        found = OpenKem(kem, key);
                        break;
                    default:
                        break;
                }
            }
            catch (Exception e) when (e is CryptographicException or ArgumentException or Asn1ParseException or X509ParseException or NotSupportedException or CmsParseException)
            {
                found = null;
            }

            if (found is not null && (cekLength == 0 || found.Length == cekLength))
            {
                cek = found;
                real = true;
                return true;
            }
        }

        if (transportFailed && cekLength > 0)
        {
            cek = RandomNumberGenerator.GetBytes(cekLength);
            return true;
        }

        return false;
    }

    private static byte[]? OpenAgreement(KeyAgreeRecipientInfo ka, CmsDecryptionKey key, ref bool matched)
    {
        if (ka.OriginatorKey is null)
        {
            return null;
        }

        foreach (RecipientEncryptedKey rek in ka.RecipientEncryptedKeys)
        {
            if (key.Certificate is not null && !rek.Identifier.Matches(key.Certificate))
            {
                continue;
            }

            matched = true;
            byte[]? z = key.DeriveAgreementSecret(ka.OriginatorKey);
            if (z is null)
            {
                continue;
            }

            AlgorithmIdentifier wrap = AlgorithmIdentifier.Parse(ka.KeyEncryptionAlgorithm.Parameters);
            int kekBytes = CmsCiphers.WrapKeyBytes(wrap.Oid);
            if (kekBytes == 0)
            {
                continue;
            }

            byte[] kek = CmsCiphers.AgreementKek(ka.KeyEncryptionAlgorithm.Oid, z, wrap, ka.Ukm.Span, kekBytes);
            CryptographicOperations.ZeroMemory(z);
            byte[]? cek = CmsCiphers.Unwrap(wrap.Oid, kek, rek.EncryptedKey.Span);
            CryptographicOperations.ZeroMemory(kek);
            if (cek is not null)
            {
                return cek;
            }
        }

        return null;
    }

    private static byte[]? OpenKek(KekRecipientInfo ri, CmsDecryptionKey key, ref bool matched)
    {
        byte[]? kek = key.GetKeyEncryptionKey(ri.KeyIdentifier.Span);
        if (kek is null)
        {
            return null;
        }

        matched = true;
        byte[]? cek = CmsCiphers.WrapKeyBytes(ri.KeyEncryptionAlgorithm.Oid) == kek.Length ? CmsCiphers.Unwrap(ri.KeyEncryptionAlgorithm.Oid, kek, ri.EncryptedKey.Span) : null;
        CryptographicOperations.ZeroMemory(kek);
        return cek;
    }

    private static byte[]? OpenPassword(PasswordRecipientInfo ri, CmsDecryptionKey key, CmsDecryptOptions options, ref bool matched)
    {
        if (ri.KeyDerivationAlgorithm is not { Oid: CmsOids.Pbkdf2 } kdf || ri.KeyEncryptionAlgorithm.Oid != CmsOids.PwriKek)
        {
            return null;
        }

        // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER, keyLength INTEGER OPTIONAL, prf AlgorithmIdentifier DEFAULT hmacWithSHA1 }
        var r = new Asn1Reader(kdf.Parameters.Span, Asn1Rules.Ber, options.Limits.Asn1);
        Asn1Reader p = r.ReadSequence();
        ReadOnlySpan<byte> salt = p.ReadOctetString();
        int iterations = p.ReadInt32();
        if (p.HasData && p.PeekTag() == new Asn1Tag(Asn1Tags.IntegerType))
        {
            p.ReadInt32();
        }

        string prf = CmsOids.HmacSha1;
        if (p.HasData)
        {
            prf = AlgorithmIdentifier.Parse(p.ReadEncodedValue().ToArray()).Oid;
        }

        HashAlgorithmName hash = prf switch
        {
            CmsOids.HmacSha1 or "1.2.840.113549.2.7" => HashAlgorithmName.SHA1,
            CmsOids.HmacSha256 => HashAlgorithmName.SHA256,
            CmsOids.HmacSha384 => HashAlgorithmName.SHA384,
            CmsOids.HmacSha512 => HashAlgorithmName.SHA512,
            _ => default,
        };
        if (hash == default || iterations < 1 || iterations > options.Limits.MaxPbkdf2Iterations)
        {
            return null;
        }

        // The parameter of id-alg-PWRI-KEK names the cipher that wraps the key; AES-CBC (16-octet blocks) is the one supported.
        AlgorithmIdentifier cipherAlg = AlgorithmIdentifier.Parse(ri.KeyEncryptionAlgorithm.Parameters);
        if (!CmsCiphers.TryGet(cipherAlg.Oid, out ContentCipher c) || c.Kind != CipherKind.Cbc)
        {
            return null;
        }

        CmsCiphers.ReadParameters(c, cipherAlg, out byte[] iv, out _);
        byte[]? kek = key.DerivePasswordKey(salt, iterations, hash, c.KeyBytes);
        if (kek is null)
        {
            return null;
        }

        matched = true;
        byte[]? cek = CmsCiphers.Rfc3211Unwrap(kek, iv, ri.EncryptedKey.Span);
        CryptographicOperations.ZeroMemory(kek);
        return cek;
    }

    private static byte[]? OpenKem(KemRecipientInfo ri, CmsDecryptionKey key)
    {
        byte[]? ss = key.Decapsulate(ri.Kem, ri.KemCiphertext.Span);
        if (ss is null)
        {
            return null;
        }

        int kekBytes = CmsCiphers.WrapKeyBytes(ri.Wrap.Oid);
        if (kekBytes == 0 || kekBytes != ri.KekLength)
        {
            return null;
        }

        byte[] kek = CmsCiphers.KemKek(ri.Kdf.Oid, ss, ri.Wrap, ri.KekLength, ri.Ukm.Span);
        CryptographicOperations.ZeroMemory(ss);
        byte[]? cek = CmsCiphers.Unwrap(ri.Wrap.Oid, kek, ri.EncryptedKey.Span);
        CryptographicOperations.ZeroMemory(kek);
        return cek;
    }

    /// <summary>The version of EnvelopedData and AuthEnvelopedData's recipient-dependent rule (RFC 5652 §6.1).</summary>
    public static int EnvelopedVersion(IEnumerable<int> recipientVersions, IEnumerable<RecipientKind> kinds, bool hasUnprotectedAttrs)
    {
        if (kinds.Any(static k => k is RecipientKind.Password or RecipientKind.Other))
        {
            return 3;
        }

        return !hasUnprotectedAttrs && recipientVersions.All(static v => v == 0) ? 0 : 2;
    }
}

/// <summary>The kinds of RecipientInfo, for choosing a message version.</summary>
internal enum RecipientKind
{
    KeyTransport,
    KeyAgreement,
    Kek,
    Password,
    Other,
}

/// <summary>
/// A CMS <c>EnvelopedData</c> (RFC 5652 §6): content encrypted with a random key that each recipient gets in their own way. Kept as received.
/// </summary>
public sealed partial class EnvelopedData
{
    private EnvelopedData(int version, ReadOnlyMemory<byte> originator, IReadOnlyList<RecipientInfo> recipients, string contentType, AlgorithmIdentifier alg,
        ReadOnlyMemory<byte> ciphertext, bool hasCiphertext, IReadOnlyList<CmsAttributeEntry>? unprotected, ReadOnlyMemory<byte> encoded, CmsLimits limits)
    {
        Version = version;
        OriginatorInfo = originator;
        RecipientInfos = recipients;
        EncryptedContentType = contentType;
        ContentEncryptionAlgorithm = alg;
        EncryptedContent = ciphertext;
        HasEncryptedContent = hasCiphertext;
        UnprotectedAttributes = unprotected;
        Encoded = encoded;
        Limits = limits;
    }

    /// <summary>The CMS version.</summary>
    public int Version { get; }

    /// <summary>The originatorInfo element as received (certificates and revocation lists of the sender); empty when absent.</summary>
    public ReadOnlyMemory<byte> OriginatorInfo { get; }

    /// <summary>The recipient infos in the order received.</summary>
    public IReadOnlyList<RecipientInfo> RecipientInfos { get; }

    /// <summary>The content type of the plaintext.</summary>
    public string EncryptedContentType { get; }

    /// <summary>The content-encryption algorithm with its parameters (IV).</summary>
    public AlgorithmIdentifier ContentEncryptionAlgorithm { get; }

    /// <summary>The encrypted content octets; empty when <see cref="HasEncryptedContent"/> is false.</summary>
    public ReadOnlyMemory<byte> EncryptedContent { get; }

    /// <summary>False when the encrypted content is held elsewhere.</summary>
    public bool HasEncryptedContent { get; }

    /// <summary>The unprotected attributes, or null.</summary>
    public IReadOnlyList<CmsAttributeEntry>? UnprotectedAttributes { get; }

    /// <summary>The ContentInfo as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The limits the message was read with.</summary>
    public CmsLimits Limits { get; }

    /// <summary>Reads a ContentInfo holding EnvelopedData.</summary>
    /// <exception cref="CmsParseException">The octets are not EnvelopedData, or exceed a limit.</exception>
    public static EnvelopedData Parse(ReadOnlyMemory<byte> encoded, CmsLimits? limits = null)
    {
        limits ??= CmsLimits.Default;
        ContentInfo ci = ContentInfo.Parse(encoded, limits);
        if (ci.ContentType != CmsOids.EnvelopedData || ci.Content.IsEmpty)
        {
            throw new CmsParseException("EnvelopedData", CmsError.UnexpectedContentType, $"the ContentInfo holds {ci.ContentType}");
        }

        ReadOnlyMemory<byte> root = ci.Content;
        return CmsRead.Run("EnvelopedData", () => ReadBody(root, ci.Encoded, limits));
    }

    /// <summary>Reads a ContentInfo holding EnvelopedData, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out EnvelopedData? value, CmsLimits? limits = null) => CmsRead.Try(() => Parse(encoded, limits), out value);

    private static EnvelopedData ReadBody(ReadOnlyMemory<byte> root, ReadOnlyMemory<byte> ci, CmsLimits limits)
    {
        var top = new Asn1Reader(root.Span, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader s = top.ReadSequence();
        top.ThrowIfNotEmpty();
        int version = s.ReadInt32();
        if (version is < 0 or > 4)
        {
            throw CmsRead.Unsupported("EnvelopedData", $"version {version}");
        }

        ReadOnlyMemory<byte> originator = default;
        if (s.HasData && s.PeekTag() == Asn1Tag.Context(0))
        {
            originator = CmsRead.Slice(root, s.ReadEncodedValue());
        }

        IReadOnlyList<RecipientInfo> recipients = ReadRecipients(ref s, root, limits);
        EncryptedContentInfoData eci = EncryptedContentInfoData.Read(ref s, root);
        List<CmsAttributeEntry>? unprotected = null;
        if (s.HasData && s.PeekTag() == Asn1Tag.Context(1))
        {
            unprotected = CmsAttributeEntry.ReadSet(ref s, root, limits, Asn1Tag.Context(1, true));
        }

        s.ThrowIfNotEmpty();
        return new EnvelopedData(version, originator, recipients, eci.ContentType, eci.Algorithm, eci.Ciphertext, eci.HasCiphertext, unprotected, ci, limits);
    }

    internal static List<RecipientInfo> ReadRecipients(ref Asn1Reader s, ReadOnlyMemory<byte> root, CmsLimits limits)
    {
        Asn1Reader set = s.ReadSet();
        var list = new List<RecipientInfo>();
        while (set.HasData)
        {
            if (list.Count >= limits.MaxRecipients)
            {
                throw CmsRead.Limit("RecipientInfos", $"more than {limits.MaxRecipients} recipients");
            }

            list.Add(RecipientInfo.Read(ref set, root, limits));
        }

        if (list.Count == 0)
        {
            throw CmsRead.Bad("RecipientInfos", "there is no recipient");
        }

        return list;
    }

    internal static RecipientKind KindOf(RecipientInfo r) => r switch
    {
        KeyTransRecipientInfo => RecipientKind.KeyTransport,
        KeyAgreeRecipientInfo => RecipientKind.KeyAgreement,
        KekRecipientInfo => RecipientKind.Kek,
        PasswordRecipientInfo => RecipientKind.Password,
        _ => RecipientKind.Other,
    };

    /// <summary>Encrypts <paramref name="plaintext"/> for the recipients and returns the message (definite-length DER).</summary>
    /// <param name="plaintext">The content.</param>
    /// <param name="recipients">One or more recipients.</param>
    /// <param name="options">Choices, or null for AES-256-CBC.</param>
    public static EnvelopedData Create(ReadOnlySpan<byte> plaintext, IReadOnlyList<CmsRecipient> recipients, CmsEncryptOptions? options = null)
    {
        options ??= new CmsEncryptOptions();
        ContentCipher cipher = PrepareCipher(options, recipients, authenticated: false);
        byte[] cek = RandomNumberGenerator.GetBytes(cipher.KeyBytes);
        byte[] iv = RandomNumberGenerator.GetBytes(cipher.BlockBytes);
        byte[] ciphertext = CmsCiphers.EncryptCbc(cipher, cek, iv, plaintext);
        AlgorithmIdentifier alg = CmsCiphers.Describe(cipher, iv, 0);
        byte[] eci = EncryptedContentInfoData.Encode(options.ContentType, alg, ciphertext);
        return Assemble(recipients, cek, eci, options);
    }

    internal static ContentCipher PrepareCipher(CmsEncryptOptions options, IReadOnlyList<CmsRecipient> recipients, bool authenticated)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        if (recipients.Count == 0)
        {
            throw new ArgumentException("There must be at least one recipient.", nameof(recipients));
        }

        if (!options.AllowLegacy && recipients.Any(static r => r.IsLegacy))
        {
            throw new NotSupportedException("RSA PKCS #1 v1.5 key transport is legacy: set CmsEncryptOptions.AllowLegacy to write it.");
        }

        ContentCipher cipher = CmsCiphers.Require(options.ContentEncryption ?? (authenticated ? CmsOids.Aes256Gcm : CmsOids.Aes256Cbc));
        if (cipher.Kind == CipherKind.TripleDesCbc || cipher.Authenticated != authenticated)
        {
            throw new NotSupportedException($"{cipher.Name} cannot be written in this content type.");
        }

        // New data: the cipher and every recipient's key go through the policy before a key is generated.
        Policy.CryptoPolicy policy = options.Policy ?? Policy.CryptoPolicy.Standard;
        var decisions = new List<Policy.PolicyDecision>(CmsPolicyChecks.Cipher(policy, cipher, Policy.CryptoUse.Encrypt).Decisions);
        decisions.AddRange(CmsPolicyChecks.Recipients(policy, recipients).Decisions);
        CmsPolicyChecks.ThrowIfRejected(new Policy.PolicyReport(decisions));

        return cipher;
    }

    /// <summary>Wraps the key for every recipient and assembles the EnvelopedData ContentInfo.</summary>
    internal static EnvelopedData Assemble(IReadOnlyList<CmsRecipient> recipients, byte[] cek, byte[] encryptedContentInfo, CmsEncryptOptions options)
    {
        var infos = new List<byte[]>();
        foreach (CmsRecipient r in recipients)
        {
            infos.Add(r.Build(cek));
        }

        CryptographicOperations.ZeroMemory(cek);
        byte[] body = AssembleBody(recipients, infos, encryptedContentInfo, options);
        return Parse(DerWriter.Sequence(DerWriter.Oid(CmsOids.EnvelopedData), DerWriter.Context(0, body)));
    }

    internal static int VersionFor(IReadOnlyList<CmsRecipient> recipients, List<byte[]> infos, CmsEncryptOptions options)
    {
        var kinds = new List<RecipientKind>();
        foreach (byte[] i in infos)
        {
            kinds.Add(i[0] switch { 0x30 => RecipientKind.KeyTransport, 0xA1 => RecipientKind.KeyAgreement, 0xA2 => RecipientKind.Kek, 0xA3 => RecipientKind.Password, _ => RecipientKind.Other });
        }

        return RecipientOpener.EnvelopedVersion(recipients.Select(static r => r.Version), kinds, options.UnprotectedAttributes.Count > 0);
    }

    internal static byte[] AssembleBody(IReadOnlyList<CmsRecipient> recipients, List<byte[]> infos, byte[] encryptedContentInfo, CmsEncryptOptions options)
    {
        int version = VersionFor(recipients, infos, options);
        var parts = new List<byte[]> { DerWriter.SignedInteger(version), DerWriter.Set([.. infos]), encryptedContentInfo };
        if (options.UnprotectedAttributes.Count > 0)
        {
            parts.Add(DerWriter.Retag(CmsAttributeEntry.EncodeSet(options.UnprotectedAttributes), 0xA1));
        }

        return DerWriter.Sequence([.. parts]);
    }

    /// <summary>
    /// Decrypts the content with the key. Nothing is returned unless every check passes: a wrong key, damaged key transport (made
    /// indistinguishable from any other failure, RFC 3218 §2.3), bad padding and every other failure all raise the same
    /// <see cref="CmsParseException"/> with <see cref="CmsError.DecryptionFailed"/>. CBC does not authenticate the content: prefer
    /// <see cref="AuthEnvelopedData"/> when you control the sender.
    /// </summary>
    /// <exception cref="CmsParseException">No recipient matches the key (<see cref="CmsError.NoMatchingRecipient"/>), or decryption failed.</exception>
    public byte[] Decrypt(CmsDecryptionKey key, CmsDecryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        options ??= new CmsDecryptOptions { Limits = Limits };
        if (!CmsCiphers.TryGet(ContentEncryptionAlgorithm.Oid, out ContentCipher cipher) || cipher.Authenticated || (cipher.Kind == CipherKind.TripleDesCbc && !options.AllowLegacyCiphers))
        {
            throw new CmsParseException("EnvelopedData", CmsError.Unsupported, $"the content-encryption algorithm {ContentEncryptionAlgorithm.Name} is not accepted");
        }

        if (!HasEncryptedContent || EncryptedContent.Length > options.Limits.MaxContentBytes)
        {
            throw new CmsParseException("EnvelopedData", CmsError.UnexpectedStructure, "there is no encrypted content in the message, or it is too large");
        }

        CmsCiphers.ReadParameters(cipher, ContentEncryptionAlgorithm, out byte[] iv, out _);
        CmsPolicyChecks.BeforeDecrypt(options, cipher, key);
        if (!RecipientOpener.TryOpen(RecipientInfos, key, cipher.KeyBytes, options, out byte[] cek, out bool real, out bool matched))
        {
            throw matched ? DecryptionFailed("EnvelopedData") : new CmsParseException("EnvelopedData", CmsError.NoMatchingRecipient, "no recipient info matches the key");
        }

        bool ok = CmsCiphers.TryDecryptCbc(cipher, cek, iv, EncryptedContent.Span, out byte[] plaintext);
        CryptographicOperations.ZeroMemory(cek);
        if (!ok || !real)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw DecryptionFailed("EnvelopedData");
        }

        return plaintext;
    }

    internal static CmsParseException DecryptionFailed(string what) => new(what, CmsError.DecryptionFailed, "the message could not be decrypted");
}
