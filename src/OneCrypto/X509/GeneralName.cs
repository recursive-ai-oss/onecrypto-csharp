using System.Linq;
using System.Text;
using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto;

/// <summary>The alternatives of <c>GeneralName</c> (RFC 5280 §4.2.1.6), numbered by their context tag.</summary>
public enum GeneralNameKind
{
    /// <summary>otherName [0]: an object identifier and a value of that type.</summary>
    OtherName = 0,
    /// <summary>rfc822Name [1]: an e-mail address.</summary>
    Rfc822Name = 1,
    /// <summary>dNSName [2].</summary>
    DnsName = 2,
    /// <summary>x400Address [3]; kept undecoded.</summary>
    X400Address = 3,
    /// <summary>directoryName [4].</summary>
    DirectoryName = 4,
    /// <summary>ediPartyName [5]; kept undecoded.</summary>
    EdiPartyName = 5,
    /// <summary>uniformResourceIdentifier [6].</summary>
    Uri = 6,
    /// <summary>iPAddress [7]: 4 or 16 octets (8 or 32 in a name constraint, address then mask).</summary>
    IPAddress = 7,
    /// <summary>registeredID [8]: an object identifier.</summary>
    RegisteredId = 8,
}

/// <summary>A <c>GeneralName</c>. The encoding as received is kept; the accessors decode the alternative that applies.</summary>
public sealed class GeneralName : IEquatable<GeneralName>
{
    private GeneralName(GeneralNameKind kind, ReadOnlyMemory<byte> encoded, ReadOnlyMemory<byte> content)
    {
        Kind = kind;
        Encoded = encoded;
        Content = content;
    }

    /// <summary>Which alternative this is.</summary>
    public GeneralNameKind Kind { get; }

    /// <summary>The element exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The content octets of the element (for directoryName and otherName this holds the inner encoding).</summary>
    public ReadOnlyMemory<byte> Content { get; }

    /// <summary>The text of an rfc822Name, dNSName or URI (IA5String octets read as Latin-1), the dotted identifier of a registeredID, otherwise null.</summary>
    public string? Value => Kind switch
    {
        GeneralNameKind.Rfc822Name or GeneralNameKind.DnsName or GeneralNameKind.Uri => Encoding.Latin1.GetString(Content.Span),
        GeneralNameKind.RegisteredId => Asn1Content.IsValidOid(Content.Span) ? Asn1Content.OidToString(Content.Span, allow128Bits: true) : null,
        _ => null,
    };

    /// <summary>The octets of an iPAddress, or empty for other alternatives.</summary>
    public ReadOnlyMemory<byte> IPAddressBytes => Kind == GeneralNameKind.IPAddress ? Content : ReadOnlyMemory<byte>.Empty;

    /// <summary>The name of a directoryName, otherwise null.</summary>
    /// <exception cref="X509ParseException">The inner Name is malformed.</exception>
    public DistinguishedName? DirectoryName => Kind == GeneralNameKind.DirectoryName ? DistinguishedName.Parse(Content) : null;

    /// <summary>The type identifier of an otherName, otherwise null.</summary>
    public string? OtherNameType
    {
        get
        {
            if (Kind != GeneralNameKind.OtherName)
            {
                return null;
            }

            var r = new Asn1Reader(Content.Span, Asn1Rules.Ber);
            return r.TryReadObjectIdentifier(out string oid) ? oid : null;
        }
    }

    /// <summary>The value of an otherName: the element inside its explicit [0] wrapper, otherwise empty.</summary>
    public ReadOnlyMemory<byte> OtherNameValue
    {
        get
        {
            if (Kind != GeneralNameKind.OtherName)
            {
                return default;
            }

            var r = new Asn1Reader(Content.Span, Asn1Rules.Ber);
            if (!r.TrySkipValue() || !r.TryReadAnyContent(out _, out ReadOnlySpan<byte> inner))
            {
                return default;
            }

            return X509Read.Slice(Content, inner);
        }
    }

    private static GeneralName Make(GeneralNameKind kind, bool constructed, ReadOnlySpan<byte> content)
    {
        byte tag = (byte)(0x80 | (constructed ? 0x20 : 0) | (int)kind);
        byte[] enc = DerWriter.Tlv(tag, content.ToArray());
        return Parse(enc);
    }

    /// <summary>A dNSName. The text must be ASCII.</summary>
    public static GeneralName Dns(string name) => Make(GeneralNameKind.DnsName, false, Ascii(name));

    /// <summary>An rfc822Name. The text must be ASCII.</summary>
    public static GeneralName Email(string address) => Make(GeneralNameKind.Rfc822Name, false, Ascii(address));

    /// <summary>A uniformResourceIdentifier. The text must be ASCII.</summary>
    public static GeneralName FromUri(string uri) => Make(GeneralNameKind.Uri, false, Ascii(uri));

    /// <summary>An iPAddress from 4 or 16 octets (8 or 32 for a name constraint).</summary>
    public static GeneralName FromIPAddress(ReadOnlySpan<byte> address) => Make(GeneralNameKind.IPAddress, false, address);

    /// <summary>A directoryName.</summary>
    public static GeneralName FromDirectoryName(DistinguishedName name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return Make(GeneralNameKind.DirectoryName, true, name.Encoded.Span);
    }

    /// <summary>A registeredID.</summary>
    public static GeneralName FromRegisteredId(string oid) => Make(GeneralNameKind.RegisteredId, false, DerWriter.Oid(oid).AsSpan(2));

    /// <summary>An otherName with the given type identifier and a complete encoded value element.</summary>
    public static GeneralName Other(string typeOid, ReadOnlySpan<byte> encodedValue) =>
        Make(GeneralNameKind.OtherName, true, [.. DerWriter.Oid(typeOid), .. DerWriter.Context(0, encodedValue.ToArray())]);

    private static byte[] Ascii(string s)
    {
        ArgumentNullException.ThrowIfNull(s);
        byte[] b = Encoding.Latin1.GetBytes(s);
        if (b.Any(x => x > 0x7F) || s.Any(c => c > 0x7F))
        {
            throw new ArgumentException("The value must be ASCII (IA5String).", nameof(s));
        }

        return b;
    }

    /// <summary>Reads a GeneralName from its encoding.</summary>
    /// <exception cref="X509ParseException">The octets are not a GeneralName.</exception>
    public static GeneralName Parse(ReadOnlyMemory<byte> encoded)
    {
        try
        {
            var r = new Asn1Reader(encoded.Span, Asn1Rules.Ber);
            GeneralName g = Read(ref r, encoded);
            r.ThrowIfNotEmpty();
            return g;
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("GeneralName", e);
        }
    }

    internal static GeneralName Read(ref Asn1Reader r, ReadOnlyMemory<byte> root)
    {
        ReadOnlySpan<byte> whole = r.ReadEncodedValue();
        var inner = new Asn1Reader(whole, Asn1Rules.Ber, r.Limits);
        if (!inner.TryReadAnyContent(out Asn1Tag tag, out ReadOnlySpan<byte> content) || tag.TagClass != Asn1TagClass.ContextSpecific || tag.TagNumber > 8)
        {
            throw X509Read.Bad("GeneralName", "not one of the nine alternatives");
        }

        var kind = (GeneralNameKind)tag.TagNumber;
        bool mustBeConstructed = kind is GeneralNameKind.OtherName or GeneralNameKind.X400Address or GeneralNameKind.DirectoryName or GeneralNameKind.EdiPartyName;
        if (tag.IsConstructed != mustBeConstructed)
        {
            throw X509Read.Bad("GeneralName", $"{kind} has the wrong form");
        }

        switch (kind)
        {
            case GeneralNameKind.IPAddress when content.Length is not (4 or 8 or 16 or 32):
                throw X509Read.Invalid("GeneralName", "an iPAddress must be 4, 8, 16 or 32 octets");
            case GeneralNameKind.OtherName:
                var o = new Asn1Reader(content, Asn1Rules.Ber, r.Limits);
                o.ReadObjectIdentifierBytes();
                o.ReadEncodedValue();
                break;
            case GeneralNameKind.DirectoryName:
                DistinguishedName.Validate(content, X509Limits.Default);
                break;
            case GeneralNameKind.RegisteredId when !Asn1Content.IsValidOid(content):
                throw X509Read.Invalid("GeneralName", "bad registeredID");
        }

        return new GeneralName(kind, X509Read.Slice(root, whole), X509Read.Slice(root, content));
    }

    /// <summary>Reads the elements of a GeneralNames SEQUENCE body (the reader is positioned inside the sequence).</summary>
    internal static List<GeneralName> ReadList(ref Asn1Reader body, ReadOnlyMemory<byte> root, X509Limits limits)
    {
        var list = new List<GeneralName>();
        while (body.HasData)
        {
            if (list.Count >= limits.MaxListEntries)
            {
                throw X509Read.Limit("GeneralNames", "too many names");
            }

            list.Add(Read(ref body, root));
        }

        return list;
    }

    /// <inheritdoc/>
    public bool Equals(GeneralName? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as GeneralName);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }

    /// <summary>A readable form such as <c>DNS:example.org</c>, <c>IP:192.0.2.1</c> or <c>DirName:CN=x</c>.</summary>
    public override string ToString()
    {
        switch (Kind)
        {
            case GeneralNameKind.DnsName: return "DNS:" + Value;
            case GeneralNameKind.Rfc822Name: return "email:" + Value;
            case GeneralNameKind.Uri: return "URI:" + Value;
            case GeneralNameKind.RegisteredId: return "RID:" + Value;
            case GeneralNameKind.IPAddress:
                ReadOnlySpan<byte> b = Content.Span;
                return b.Length == 4 || b.Length == 16
                    ? "IP:" + new System.Net.IPAddress(b)
                    : "IP:" + Convert.ToHexString(b);
            case GeneralNameKind.DirectoryName:
                return "DirName:" + (DistinguishedName.TryParse(Content, out DistinguishedName? d) ? d!.ToString() : string.Empty);
            case GeneralNameKind.OtherName: return "othername:" + OtherNameType;
            default: return Kind.ToString();
        }
    }
}
