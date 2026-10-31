using System.Linq;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// A <c>SignerInfo</c> (RFC 5652 §5.3), kept as the exact octets received. The signature covers the signed attributes as
/// <see cref="SignedAttributesEncoded"/> carries them (re-tagged as a SET), never a re-serialisation.
/// </summary>
public sealed class SignerInfo
{
    private IReadOnlyList<SignerInfo>? _countersignatures;

    private SignerInfo(int version, CmsIdentifier id, AlgorithmIdentifier digest, IReadOnlyList<CmsAttributeEntry>? signed, ReadOnlyMemory<byte> signedEncoded,
        AlgorithmIdentifier signatureAlgorithm, ReadOnlyMemory<byte> signature, IReadOnlyList<CmsAttributeEntry>? unsigned, ReadOnlyMemory<byte> unsignedEncoded, ReadOnlyMemory<byte> encoded)
    {
        Version = version;
        Identifier = id;
        DigestAlgorithm = digest;
        SignedAttributes = signed;
        SignedAttributesEncoded = signedEncoded;
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
        UnsignedAttributes = unsigned;
        UnsignedAttributesEncoded = unsignedEncoded;
        Encoded = encoded;
    }

    /// <summary>The CMS version: 1 for issuer and serial number, 3 for a subject key identifier.</summary>
    public int Version { get; }

    /// <summary>Names the signer's certificate.</summary>
    public CmsIdentifier Identifier { get; }

    /// <summary>The digest algorithm for the content (and for the signed attributes' message digest).</summary>
    public AlgorithmIdentifier DigestAlgorithm { get; }

    /// <summary>The signed attributes, or null when the signature covers the content directly.</summary>
    public IReadOnlyList<CmsAttributeEntry>? SignedAttributes { get; }

    /// <summary>The <c>[0] IMPLICIT</c> signed attributes element as received; empty when there are none.</summary>
    public ReadOnlyMemory<byte> SignedAttributesEncoded { get; }

    /// <summary>The signature algorithm identifier.</summary>
    public AlgorithmIdentifier SignatureAlgorithm { get; }

    /// <summary>The signature value octets.</summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>The unsigned attributes, or null when there are none.</summary>
    public IReadOnlyList<CmsAttributeEntry>? UnsignedAttributes { get; }

    /// <summary>The <c>[1] IMPLICIT</c> unsigned attributes element as received; empty when there are none.</summary>
    public ReadOnlyMemory<byte> UnsignedAttributesEncoded { get; }

    /// <summary>The whole SignerInfo.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The first signed attribute of the type, or null.</summary>
    public CmsAttributeEntry? FindSigned(string oid) => CmsAttributeEntry.Find(SignedAttributes, oid);

    /// <summary>The first unsigned attribute of the type, or null.</summary>
    public CmsAttributeEntry? FindUnsigned(string oid) => CmsAttributeEntry.Find(UnsignedAttributes, oid);

    /// <summary>The countersignatures in the unsigned attributes (RFC 5652 §11.4); values that are not SignerInfos are skipped.</summary>
    public IReadOnlyList<SignerInfo> Countersignatures => _countersignatures ??= ReadCountersignatures();

    private List<SignerInfo> ReadCountersignatures()
    {
        var list = new List<SignerInfo>();
        if (UnsignedAttributes is null)
        {
            return list;
        }

        foreach (CmsAttributeEntry a in UnsignedAttributes)
        {
            if (a.Oid != CmsOids.Countersignature)
            {
                continue;
            }

            foreach (ReadOnlyMemory<byte> v in a.Values)
            {
                if (TryParse(v, out SignerInfo? s))
                {
                    list.Add(s!);
                }
            }
        }

        return list;
    }

    /// <summary>
    /// The octets the signature covers when signed attributes are present: the attributes as a DER-tagged SET OF (RFC 5652 §5.4).
    /// Indefinite lengths in the received form are made definite, nothing else is changed. Null when there are no signed attributes.
    /// </summary>
    public byte[]? SignedAttributesToVerify()
    {
        if (SignedAttributesEncoded.IsEmpty)
        {
            return null;
        }

        byte[] retagged = (byte[])SignedAttributesEncoded.ToArray();
        retagged[0] = 0x31;
        return BerToDer.TryConvert(retagged, out byte[] der) ? der : null;
    }

    /// <summary>Reads a SignerInfo.</summary>
    /// <exception cref="CmsParseException">The octets are not a SignerInfo.</exception>
    public static SignerInfo Parse(ReadOnlyMemory<byte> encoded, CmsLimits? limits = null)
    {
        limits ??= CmsLimits.Default;
        return CmsRead.Run("SignerInfo", () =>
        {
            var r = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            SignerInfo s = Read(ref r, encoded, limits);
            r.ThrowIfNotEmpty();
            return s;
        });
    }

    /// <summary>Reads a SignerInfo, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out SignerInfo? signerInfo, CmsLimits? limits = null) =>
        CmsRead.Try(() => Parse(encoded, limits), out signerInfo);

    internal static SignerInfo Read(ref Asn1Reader r, ReadOnlyMemory<byte> root, CmsLimits limits)
    {
        ReadOnlySpan<byte> whole = r.ReadEncodedValue();
        var outer = new Asn1Reader(whole, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader s = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        int version = s.ReadInt32();
        if (version is not (1 or 3))
        {
            throw CmsRead.Unsupported("SignerInfo", $"version {version}");
        }

        CmsIdentifier sid = CmsIdentifier.Read(ref s, root);
        AlgorithmIdentifier digest = CmsRead.Alg(ref s, root);
        List<CmsAttributeEntry>? signed = null;
        ReadOnlyMemory<byte> signedEnc = default;
        if (s.HasData && s.PeekTag() == Asn1Tag.Context(0))
        {
            ReadOnlySpan<byte> attrs = CmsRead.Peek(ref s);
            signedEnc = CmsRead.Slice(root, attrs);
            signed = CmsAttributeEntry.ReadSet(ref s, root, limits, Asn1Tag.Context(0, true));
        }

        AlgorithmIdentifier sigAlg = CmsRead.Alg(ref s, root);
        ReadOnlyMemory<byte> signature = ReadOctets(ref s, root);
        List<CmsAttributeEntry>? unsigned = null;
        ReadOnlyMemory<byte> unsignedEnc = default;
        if (s.HasData && s.PeekTag() == Asn1Tag.Context(1))
        {
            ReadOnlySpan<byte> attrs = CmsRead.Peek(ref s);
            unsignedEnc = CmsRead.Slice(root, attrs);
            unsigned = CmsAttributeEntry.ReadSet(ref s, root, limits, Asn1Tag.Context(1, true));
        }

        s.ThrowIfNotEmpty();
        return new SignerInfo(version, sid, digest, signed, signedEnc, sigAlg, signature, unsigned, unsignedEnc, CmsRead.Slice(root, whole));
    }

    /// <summary>Reads an OCTET STRING in either form; a constructed one is joined into a new array.</summary>
    internal static ReadOnlyMemory<byte> ReadOctets(ref Asn1Reader r, ReadOnlyMemory<byte> root)
    {
        if (r.PeekTag().IsConstructed)
        {
            return r.ReadOctetStringBytes();
        }

        return CmsRead.Slice(root, r.ReadOctetString());
    }

    /// <summary>Encodes a SignerInfo from its parts; the attribute sets are passed already tagged <c>[0]</c> and <c>[1]</c> (used by the builders).</summary>
    internal static byte[] Encode(int version, CmsIdentifier sid, byte[] digestAlgorithm, byte[]? signedAttributesSet, byte[] signatureAlgorithm, byte[] signature, byte[]? unsignedAttributesSet)
    {
        var parts = new List<byte[]> { DerWriter.SignedInteger(version), sid.Encoded.ToArray(), digestAlgorithm };
        if (signedAttributesSet is not null)
        {
            parts.Add(signedAttributesSet);
        }

        parts.Add(signatureAlgorithm);
        parts.Add(DerWriter.OctetString(signature));
        if (unsignedAttributesSet is not null)
        {
            parts.Add(unsignedAttributesSet);
        }

        return DerWriter.Sequence([.. parts]);
    }
}

/// <summary>
/// A CMS <c>SignedData</c> (RFC 5652 §5) with the ContentInfo around it, kept as received. The encapsulated content, certificates and
/// signer infos are slices of the original octets.
/// </summary>
public sealed partial class SignedData
{
    private readonly ReadOnlyMemory<byte> _digestAlgorithmsEncoded;
    private readonly ReadOnlyMemory<byte> _encapsulatedEncoded;
    private readonly ReadOnlyMemory<byte> _certificatesEncoded;
    private readonly ReadOnlyMemory<byte> _crlsEncoded;
    private readonly IReadOnlyList<ReadOnlyMemory<byte>> _certificateElements;
    private readonly IReadOnlyList<ReadOnlyMemory<byte>> _crlElements;
    private IReadOnlyList<Certificate>? _certificates;
    private IReadOnlyList<CertificateRevocationList>? _crls;

    private SignedData(int version, IReadOnlyList<AlgorithmIdentifier> digestAlgorithms, string contentType, ReadOnlyMemory<byte> content, bool hasContent,
        IReadOnlyList<ReadOnlyMemory<byte>> certs, IReadOnlyList<ReadOnlyMemory<byte>> crls, IReadOnlyList<SignerInfo> signers, ReadOnlyMemory<byte> encoded,
        ReadOnlyMemory<byte> digestAlgsEnc, ReadOnlyMemory<byte> encapEnc, ReadOnlyMemory<byte> certsEnc, ReadOnlyMemory<byte> crlsEnc, CmsLimits limits)
    {
        Version = version;
        DigestAlgorithms = digestAlgorithms;
        EncapsulatedContentType = contentType;
        EncapsulatedContent = content;
        HasEncapsulatedContent = hasContent;
        _certificateElements = certs;
        _crlElements = crls;
        Signers = signers;
        Encoded = encoded;
        _digestAlgorithmsEncoded = digestAlgsEnc;
        _encapsulatedEncoded = encapEnc;
        _certificatesEncoded = certsEnc;
        _crlsEncoded = crlsEnc;
        Limits = limits;
    }

    /// <summary>The CMS version.</summary>
    public int Version { get; }

    /// <summary>The digest algorithms the signers use, as listed.</summary>
    public IReadOnlyList<AlgorithmIdentifier> DigestAlgorithms { get; }

    /// <summary>The content type of the encapsulated content (id-data for a plain message, id-ct-TSTInfo for a time-stamp token).</summary>
    public string EncapsulatedContentType { get; }

    /// <summary>The encapsulated content octets (the OCTET STRING value); empty when <see cref="HasEncapsulatedContent"/> is false.</summary>
    public ReadOnlyMemory<byte> EncapsulatedContent { get; }

    /// <summary>False when the signature is detached.</summary>
    public bool HasEncapsulatedContent { get; }

    /// <summary>Every element of the certificate set as received, whatever its choice.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> CertificateElements => _certificateElements;

    /// <summary>The X.509 certificates in the set. Entries that are not certificates, or that cannot be read, are left out (they stay in <see cref="CertificateElements"/>).</summary>
    public IReadOnlyList<Certificate> Certificates => _certificates ??= ReadCertificates();

    /// <summary>The X.509 revocation lists in the set; other revocation formats stay in <see cref="RevocationElements"/>.</summary>
    public IReadOnlyList<CertificateRevocationList> Crls => _crls ??= ReadCrls();

    /// <summary>Every element of the revocation set as received.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> RevocationElements => _crlElements;

    /// <summary>The SignerInfos in the order received.</summary>
    public IReadOnlyList<SignerInfo> Signers { get; }

    /// <summary>The ContentInfo as received.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The limits the message was read with; operations on it use them too.</summary>
    public CmsLimits Limits { get; }

    private List<Certificate> ReadCertificates()
    {
        var list = new List<Certificate>();
        foreach (ReadOnlyMemory<byte> e in _certificateElements)
        {
            if (e.Span[0] == 0x30 && Certificate.TryParse(e, out Certificate? c))
            {
                list.Add(c!);
            }
        }

        return list;
    }

    private List<CertificateRevocationList> ReadCrls()
    {
        var list = new List<CertificateRevocationList>();
        foreach (ReadOnlyMemory<byte> e in _crlElements)
        {
            if (e.Span[0] == 0x30 && CertificateRevocationList.TryParse(e, out CertificateRevocationList? c))
            {
                list.Add(c!);
            }
        }

        return list;
    }

    /// <summary>Reads a ContentInfo holding SignedData.</summary>
    /// <param name="encoded">The octets; BER with indefinite lengths is accepted.</param>
    /// <param name="limits">Limits, or null for the defaults.</param>
    /// <param name="allowTrailingZeros">Accept zero padding after the element (a PDF <c>/Contents</c> string).</param>
    /// <exception cref="CmsParseException">The octets are not SignedData, or exceed a limit.</exception>
    public static SignedData Parse(ReadOnlyMemory<byte> encoded, CmsLimits? limits = null, bool allowTrailingZeros = false)
    {
        limits ??= CmsLimits.Default;
        ContentInfo ci = ContentInfo.Parse(encoded, limits, allowTrailingZeros);
        if (ci.ContentType != CmsOids.SignedData)
        {
            throw new CmsParseException("SignedData", CmsError.UnexpectedContentType, $"the ContentInfo holds {ci.ContentType}");
        }

        return FromContentInfo(ci, limits);
    }

    /// <summary>Reads a ContentInfo holding SignedData, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out SignedData? signedData, CmsLimits? limits = null, bool allowTrailingZeros = false) =>
        CmsRead.Try(() => Parse(encoded, limits, allowTrailingZeros), out signedData);

    /// <summary>Reads the SignedData inside an already parsed ContentInfo.</summary>
    public static SignedData FromContentInfo(ContentInfo contentInfo, CmsLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(contentInfo);
        limits ??= CmsLimits.Default;
        if (contentInfo.ContentType != CmsOids.SignedData || contentInfo.Content.IsEmpty)
        {
            throw new CmsParseException("SignedData", CmsError.UnexpectedContentType, "the ContentInfo does not hold SignedData");
        }

        ReadOnlyMemory<byte> root = contentInfo.Content;
        return CmsRead.Run("SignedData", () => ReadBody(root, contentInfo.Encoded, limits));
    }

    private static SignedData ReadBody(ReadOnlyMemory<byte> root, ReadOnlyMemory<byte> ciEncoded, CmsLimits limits)
    {
        var top = new Asn1Reader(root.Span, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader r = top.ReadSequence();
        top.ThrowIfNotEmpty();
        int version = r.ReadInt32();
        if (version is < 1 or > 5)
        {
            throw CmsRead.Unsupported("SignedData", $"version {version}");
        }

        ReadOnlySpan<byte> daSpan = CmsRead.Peek(ref r);
        var algs = new List<AlgorithmIdentifier>();
        Asn1Reader das = r.ReadSet();
        while (das.HasData)
        {
            if (algs.Count >= limits.MaxSigners * 2)
            {
                throw CmsRead.Limit("SignedData", "too many digest algorithms");
            }

            algs.Add(CmsRead.Alg(ref das, root));
        }

        ReadOnlySpan<byte> encapSpan = CmsRead.Peek(ref r);
        Asn1Reader enc = r.ReadSequence();
        string contentType = enc.ReadObjectIdentifier();
        ReadOnlyMemory<byte> content = default;
        bool hasContent = false;
        if (enc.HasData)
        {
            Asn1Reader ex = enc.ReadSequence(Asn1Tag.Context(0, true));
            content = SignerInfo.ReadOctets(ref ex, root);
            ex.ThrowIfNotEmpty();
            hasContent = true;
        }

        enc.ThrowIfNotEmpty();
        var certs = new List<ReadOnlyMemory<byte>>();
        ReadOnlyMemory<byte> certsEnc = default;
        if (r.HasData && r.PeekTag() == Asn1Tag.Context(0))
        {
            certsEnc = CmsRead.Slice(root, CmsRead.Peek(ref r));
            ReadSet(ref r, root, Asn1Tag.Context(0, true), certs, limits.MaxCertificates, "certificates");
        }

        var crls = new List<ReadOnlyMemory<byte>>();
        ReadOnlyMemory<byte> crlsEnc = default;
        if (r.HasData && r.PeekTag() == Asn1Tag.Context(1))
        {
            crlsEnc = CmsRead.Slice(root, CmsRead.Peek(ref r));
            ReadSet(ref r, root, Asn1Tag.Context(1, true), crls, limits.MaxCertificates, "revocation lists");
        }

        Asn1Reader sis = r.ReadSet();
        var signers = new List<SignerInfo>();
        while (sis.HasData)
        {
            if (signers.Count >= limits.MaxSigners)
            {
                throw CmsRead.Limit("SignedData", $"more than {limits.MaxSigners} signers");
            }

            signers.Add(SignerInfo.Read(ref sis, root, limits));
        }

        r.ThrowIfNotEmpty();
        return new SignedData(version, algs, contentType, content, hasContent, certs, crls, signers, ciEncoded, CmsRead.Slice(root, daSpan), CmsRead.Slice(root, encapSpan), certsEnc, crlsEnc, limits);
    }

    private static void ReadSet(ref Asn1Reader r, ReadOnlyMemory<byte> root, Asn1Tag tag, List<ReadOnlyMemory<byte>> into, int max, string what)
    {
        Asn1Reader set = r.ReadSequence(tag);
        while (set.HasData)
        {
            if (into.Count >= max)
            {
                throw CmsRead.Limit("SignedData", $"more than {max} {what}");
            }

            into.Add(CmsRead.Slice(root, set.ReadEncodedValue()));
        }
    }
}
