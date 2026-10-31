using System.Linq;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>Reading helpers shared by the CMS models.</summary>
internal static class CmsRead
{
    public static CmsParseException Bad(string what, string message) => new(what, CmsError.UnexpectedStructure, message);

    public static CmsParseException Limit(string what, string message) => new(what, CmsError.LimitExceeded, message);

    public static CmsParseException Unsupported(string what, string message) => new(what, CmsError.Unsupported, message);

    public static ReadOnlyMemory<byte> Slice(ReadOnlyMemory<byte> root, ReadOnlySpan<byte> sub) => X509Read.Slice(root, sub);

    /// <summary>Runs <paramref name="parse"/>, turning ASN.1 and PKI parse failures into <see cref="CmsParseException"/> for <paramref name="what"/>.</summary>
    public static T Run<T>(string what, Func<T> parse)
    {
        try
        {
            return parse();
        }
        catch (Asn1ParseException e)
        {
            throw new CmsParseException(what, e);
        }
        catch (X509ParseException e)
        {
            throw new CmsParseException(what, CmsError.UnexpectedStructure, e.Message);
        }
    }

    public static bool Try<T>(Func<T> parse, out T? value)
        where T : class
    {
        try
        {
            value = parse();
            return true;
        }
        catch (CmsParseException)
        {
            value = null;
            return false;
        }
    }

    /// <summary>The whole next element, left unread.</summary>
    public static ReadOnlySpan<byte> Peek(ref Asn1Reader r) => r.TryPeekEncodedValue(out ReadOnlySpan<byte> v) ? v : throw r.LastFailure.ToException();

    public static AlgorithmIdentifier Alg(ref Asn1Reader r, ReadOnlyMemory<byte> root) => AlgorithmIdentifier.Read(ref r, root);

    /// <summary>Strips leading zero octets of an INTEGER's magnitude so two encodings of one number compare equal.</summary>
    public static ReadOnlySpan<byte> TrimZeros(ReadOnlySpan<byte> s)
    {
        while (s.Length > 1 && s[0] == 0)
        {
            s = s[1..];
        }

        return s;
    }

    public static CmsParseException Rethrow(string what, Exception e) => e switch
    {
        Asn1ParseException a => new CmsParseException(what, a),
        _ => new CmsParseException(what, CmsError.UnexpectedStructure, e.Message),
    };
}

/// <summary>One CMS <c>Attribute</c> (RFC 5652 §2): an object identifier and the encodings of its values.</summary>
public sealed class CmsAttributeEntry
{
    internal CmsAttributeEntry(string oid, IReadOnlyList<ReadOnlyMemory<byte>> values, ReadOnlyMemory<byte> encoded)
    {
        Oid = oid;
        Values = values;
        Encoded = encoded;
    }

    /// <summary>The attribute type in dotted form.</summary>
    public string Oid { get; }

    /// <summary>The attribute values, each a complete encoded element, in the order received.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Values { get; }

    /// <summary>The whole <c>Attribute</c> SEQUENCE as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>Builds an attribute from already-encoded values.</summary>
    /// <param name="oid">The attribute type.</param>
    /// <param name="values">One or more complete encoded elements.</param>
    public static CmsAttributeEntry Create(string oid, params ReadOnlySpan<byte[]> values)
    {
        ArgumentException.ThrowIfNullOrEmpty(oid);
        if (values.IsEmpty)
        {
            throw new ArgumentException("An attribute needs at least one value (RFC 5652 §2).", nameof(values));
        }

        byte[] set = DerWriter.SetOf(values.ToArray());
        byte[] enc = DerWriter.Sequence(DerWriter.Oid(oid), set);
        var list = new List<ReadOnlyMemory<byte>>();
        foreach (byte[] v in values)
        {
            list.Add(v);
        }

        return new CmsAttributeEntry(oid, list, enc);
    }

    internal static CmsAttributeEntry Read(ref Asn1Reader r, ReadOnlyMemory<byte> root, CmsLimits limits)
    {
        ReadOnlySpan<byte> whole = r.ReadEncodedValue();
        var inner = new Asn1Reader(whole, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader seq = inner.ReadSequence();
        inner.ThrowIfNotEmpty();
        string oid = seq.ReadObjectIdentifier();
        Asn1Reader set = seq.ReadSet();
        seq.ThrowIfNotEmpty();
        var values = new List<ReadOnlyMemory<byte>>();
        while (set.HasData)
        {
            if (values.Count >= limits.MaxAttributeValues)
            {
                throw CmsRead.Limit("Attribute", $"more than {limits.MaxAttributeValues} values");
            }

            ReadOnlySpan<byte> v = set.ReadEncodedValue();
            if (v.Length > limits.MaxAttributeBytes)
            {
                throw CmsRead.Limit("Attribute", "a value is larger than the limit");
            }

            values.Add(CmsRead.Slice(root, v));
        }

        return new CmsAttributeEntry(oid, values, CmsRead.Slice(root, whole));
    }

    /// <summary>Reads a SET OF Attribute (the reader is on the set element, whatever its tag).</summary>
    internal static List<CmsAttributeEntry> ReadSet(ref Asn1Reader r, ReadOnlyMemory<byte> root, CmsLimits limits, Asn1Tag tag)
    {
        Asn1Reader set = r.ReadSet(tag);
        var list = new List<CmsAttributeEntry>();
        while (set.HasData)
        {
            if (list.Count >= limits.MaxAttributes)
            {
                throw CmsRead.Limit("Attributes", $"more than {limits.MaxAttributes} attributes");
            }

            list.Add(Read(ref set, root, limits));
        }

        return list;
    }

    /// <summary>The DER SET OF for the attributes (tag 0x31), members sorted as X.690 §11.6 requires. This is the form a signature over signed attributes covers.</summary>
    internal static byte[] EncodeSet(IEnumerable<CmsAttributeEntry> attributes)
    {
        var members = new List<byte[]>();
        foreach (CmsAttributeEntry a in attributes)
        {
            members.Add(a.Encoded.ToArray());
        }

        return DerWriter.SetOf(members);
    }

    internal static CmsAttributeEntry? Find(IReadOnlyList<CmsAttributeEntry>? list, string oid)
    {
        if (list is null)
        {
            return null;
        }

        foreach (CmsAttributeEntry a in list)
        {
            if (a.Oid == oid)
            {
                return a;
            }
        }

        return null;
    }
}

/// <summary>How a <see cref="CmsIdentifier"/> names a certificate.</summary>
public enum CmsIdentifierKind
{
    /// <summary>issuerAndSerialNumber.</summary>
    IssuerAndSerialNumber,

    /// <summary>subjectKeyIdentifier.</summary>
    SubjectKeyIdentifier,
}

/// <summary>
/// A <c>SignerIdentifier</c> or <c>RecipientIdentifier</c> (RFC 5652 §5.3, §6.2.1): either the issuer name and serial number of a
/// certificate, or its subject key identifier.
/// </summary>
public sealed class CmsIdentifier
{
    internal CmsIdentifier(CmsIdentifierKind kind, ReadOnlyMemory<byte> issuer, ReadOnlyMemory<byte> serial, ReadOnlyMemory<byte> ski, ReadOnlyMemory<byte> encoded)
    {
        Kind = kind;
        Issuer = issuer;
        SerialNumber = serial;
        SubjectKeyIdentifier = ski;
        Encoded = encoded;
    }

    /// <summary>Which form this is.</summary>
    public CmsIdentifierKind Kind { get; }

    /// <summary>The issuer <c>Name</c> as received (empty for a key identifier).</summary>
    public ReadOnlyMemory<byte> Issuer { get; }

    /// <summary>The serial number INTEGER content octets (empty for a key identifier).</summary>
    public ReadOnlyMemory<byte> SerialNumber { get; }

    /// <summary>The key identifier octets (empty for issuer and serial number).</summary>
    public ReadOnlyMemory<byte> SubjectKeyIdentifier { get; }

    /// <summary>The identifier element as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The identifier for <paramref name="certificate"/>. A key identifier needs the certificate's subjectKeyIdentifier extension.</summary>
    public static CmsIdentifier ForCertificate(Certificate certificate, CmsIdentifierKind kind = CmsIdentifierKind.IssuerAndSerialNumber)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (kind == CmsIdentifierKind.SubjectKeyIdentifier)
        {
            ReadOnlyMemory<byte> ski = certificate.SubjectKeyIdentifier?.KeyIdentifier
                ?? throw new ArgumentException("The certificate has no subjectKeyIdentifier extension.", nameof(certificate));
            return FromKeyIdentifier(ski);
        }

        byte[] issuer = certificate.Issuer.Encoded.ToArray();
        byte[] serial = DerWriter.Tlv(0x02, certificate.SerialNumber.ToArray());
        byte[] enc = DerWriter.Sequence(issuer, serial);
        return new CmsIdentifier(kind, issuer, certificate.SerialNumber, default, enc);
    }

    /// <summary>The key-identifier form for the given identifier octets.</summary>
    public static CmsIdentifier FromKeyIdentifier(ReadOnlyMemory<byte> keyIdentifier) =>
        new(CmsIdentifierKind.SubjectKeyIdentifier, default, default, keyIdentifier.ToArray(), DerWriter.ContextPrimitive(0, keyIdentifier.Span));

    /// <summary>True when this identifier names <paramref name="certificate"/>.</summary>
    public bool Matches(Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (Kind == CmsIdentifierKind.SubjectKeyIdentifier)
        {
            return certificate.SubjectKeyIdentifier is { } s && s.KeyIdentifier.Span.SequenceEqual(SubjectKeyIdentifier.Span);
        }

        if (!CmsRead.TrimZeros(SerialNumber.Span).SequenceEqual(CmsRead.TrimZeros(certificate.SerialNumber.Span)))
        {
            return false;
        }

        // The issuer is compared by name rules (RFC 5280 §7.1) because senders re-encode names; identical octets are the common case.
        return Issuer.Span.SequenceEqual(certificate.Issuer.Encoded.Span)
            || (DistinguishedName.TryParse(Issuer, out DistinguishedName? n) && n!.Matches(certificate.Issuer));
    }

    internal static CmsIdentifier Read(ref Asn1Reader r, ReadOnlyMemory<byte> root)
    {
        ReadOnlySpan<byte> whole = r.PeekTag() == Asn1Tag.Context(0) ? r.ReadEncodedValue() : default;
        if (!whole.IsEmpty)
        {
            var inner = new Asn1Reader(whole, Asn1Rules.Ber);
            ReadOnlySpan<byte> ski = inner.ReadOctetString(Asn1Tag.Context(0));
            return new CmsIdentifier(CmsIdentifierKind.SubjectKeyIdentifier, default, default, CmsRead.Slice(root, ski), CmsRead.Slice(root, whole));
        }

        whole = r.ReadEncodedValue();
        var rd = new Asn1Reader(whole, Asn1Rules.Ber);
        Asn1Reader seq = rd.ReadSequence();
        ReadOnlySpan<byte> issuer = seq.ReadEncodedValue();
        ReadOnlySpan<byte> serial = seq.ReadIntegerBytes();
        seq.ThrowIfNotEmpty();
        return new CmsIdentifier(CmsIdentifierKind.IssuerAndSerialNumber, CmsRead.Slice(root, issuer), CmsRead.Slice(root, serial), default, CmsRead.Slice(root, whole));
    }
}

/// <summary>
/// A <c>ContentInfo</c> (RFC 5652 §3): a content type and the content it names, kept as the exact octets received.
/// </summary>
public sealed class ContentInfo
{
    private ContentInfo(string contentType, ReadOnlyMemory<byte> content, ReadOnlyMemory<byte> encoded)
    {
        ContentType = contentType;
        Content = content;
        Encoded = encoded;
    }

    /// <summary>The content type in dotted form.</summary>
    public string ContentType { get; }

    /// <summary>The content element (inside the explicit <c>[0]</c>) as received; empty when the ContentInfo has none.</summary>
    public ReadOnlyMemory<byte> Content { get; }

    /// <summary>The whole ContentInfo as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>Builds a ContentInfo around an encoded content element.</summary>
    public static ContentInfo Create(string contentType, ReadOnlySpan<byte> content)
    {
        ArgumentException.ThrowIfNullOrEmpty(contentType);
        byte[] enc = content.IsEmpty
            ? DerWriter.Sequence(DerWriter.Oid(contentType))
            : DerWriter.Sequence(DerWriter.Oid(contentType), DerWriter.Context(0, content.ToArray()));
        return Parse(enc);
    }

    /// <summary>Reads a ContentInfo. BER with indefinite lengths is accepted.</summary>
    /// <param name="encoded">The octets.</param>
    /// <param name="limits">Limits, or null for the defaults.</param>
    /// <param name="allowTrailingZeros">Accept zero octets after the element, as a PDF <c>/Contents</c> string pads them.</param>
    /// <exception cref="CmsParseException">The octets are not a ContentInfo.</exception>
    public static ContentInfo Parse(ReadOnlyMemory<byte> encoded, CmsLimits? limits = null, bool allowTrailingZeros = false)
    {
        limits ??= CmsLimits.Default;
        return CmsRead.Run("ContentInfo", () =>
        {
            var r = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            ReadOnlySpan<byte> whole = r.ReadEncodedValue();
            if (r.HasData && !(allowTrailingZeros && !r.Remaining.ContainsAnyExcept((byte)0)))
            {
                throw CmsRead.Bad("ContentInfo", "data after the ContentInfo");
            }

            var inner = new Asn1Reader(whole, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader seq = inner.ReadSequence();
            string oid = seq.ReadObjectIdentifier();
            ReadOnlySpan<byte> content = default;
            if (seq.HasData)
            {
                Asn1Reader ex = seq.ReadSequence(Asn1Tag.Context(0, true));
                content = ex.ReadEncodedValue();
                ex.ThrowIfNotEmpty();
            }

            seq.ThrowIfNotEmpty();
            return new ContentInfo(oid, CmsRead.Slice(encoded, content), CmsRead.Slice(encoded, whole));
        });
    }

    /// <summary>Reads a ContentInfo, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out ContentInfo? contentInfo, CmsLimits? limits = null, bool allowTrailingZeros = false) =>
        CmsRead.Try(() => Parse(encoded, limits, allowTrailingZeros), out contentInfo);
}
