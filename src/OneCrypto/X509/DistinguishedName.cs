using System.Linq;
using System.Globalization;
using System.Text;
using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto;

/// <summary>One <c>AttributeTypeAndValue</c> of a name (RFC 5280 §4.1.2.4): an attribute type and its value, kept as the element received.</summary>
public sealed class AttributeTypeAndValue
{
    internal AttributeTypeAndValue(string type, ReadOnlyMemory<byte> value)
    {
        Type = type;
        Value = value;
    }

    /// <summary>The attribute type's dotted object identifier.</summary>
    public string Type { get; }

    /// <summary>The complete encoded value element (tag, length, content).</summary>
    public ReadOnlyMemory<byte> Value { get; }

    /// <summary>The universal tag number of the value (for example 12 for UTF8String), or -1 when it is not a universal element.</summary>
    public int ValueTag => Value.Length > 0 && (Value.Span[0] & 0xC0) == 0 && (Value.Span[0] & 0x1F) != 0x1F ? Value.Span[0] & 0x1F : -1;

    /// <summary>The value as text when it is one of the ASN.1 string types, otherwise null. T61String and GeneralString decode as Latin-1.</summary>
    public string? Text
    {
        get
        {
            int tag = ValueTag;
            if (tag is not (Asn1Tags.Utf8String or Asn1Tags.PrintableString or Asn1Tags.Ia5String or Asn1Tags.T61String or Asn1Tags.VisibleString
                or Asn1Tags.NumericString or Asn1Tags.BmpString or Asn1Tags.UniversalString or Asn1Tags.GeneralString))
            {
                return null;
            }

            var r = new Asn1Reader(Value.Span, Asn1Rules.Ber);
            return r.TryReadCharacterString(tag, out string s) ? s : null;
        }
    }

    /// <summary>The attribute type as a keyword when RFC 4514 §3 defines one, otherwise the dotted identifier.</summary>
    public string TypeName => DistinguishedName.Keyword(Type) ?? Type;

    /// <inheritdoc/>
    public override string ToString() => TypeName + "=" + DistinguishedName.EscapeValue(this);
}

/// <summary>A <c>RelativeDistinguishedName</c>: a set of one or more attributes (a multi-valued RDN has several).</summary>
public sealed class RelativeDistinguishedName
{
    internal RelativeDistinguishedName(IReadOnlyList<AttributeTypeAndValue> attributes, ReadOnlyMemory<byte> encoded)
    {
        Attributes = attributes;
        Encoded = encoded;
    }

    /// <summary>The attributes in the order they were received.</summary>
    public IReadOnlyList<AttributeTypeAndValue> Attributes { get; }

    /// <summary>The SET exactly as received.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <inheritdoc/>
    public override string ToString() => string.Join('+', Attributes.Select(a => a.ToString()));
}

/// <summary>
/// An X.501 <c>Name</c> (RFC 5280 §4.1.2.4): a sequence of relative distinguished names. Keeps its octets; the decoded form is built on first use.
/// </summary>
public sealed class DistinguishedName : IEquatable<DistinguishedName>
{
    private RelativeDistinguishedName[]? _rdns;

    private DistinguishedName(ReadOnlyMemory<byte> encoded)
    {
        Encoded = encoded;
    }

    /// <summary>The empty name (a SEQUENCE with no elements).</summary>
    public static DistinguishedName Empty { get; } = new(new byte[] { 0x30, 0x00 });

    /// <summary>The name's SEQUENCE exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>True for a name with no relative distinguished names.</summary>
    public bool IsEmpty => Encoded.Length == 2;

    /// <summary>The relative distinguished names in encoded order (most significant first).</summary>
    public IReadOnlyList<RelativeDistinguishedName> Rdns => _rdns ??= Decode(Encoded, X509Limits.Default);

    /// <summary>
    /// Checks the structure of DER <paramref name="encoded"/> (the octets of an X.501 Name, as they appear in a certificate) and wraps it. Decoding of the
    /// parts is deferred. The input is bytes; for text such as <c>"CN=Example,O=Org"</c> use <see cref="FromString"/> or <see cref="Parse(string)"/>.
    /// </summary>
    /// <exception cref="X509ParseException">The octets are not a Name or exceed the limits.</exception>
    public static DistinguishedName Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, X509Limits.Default);

    /// <summary>The same as <see cref="Parse(ReadOnlyMemory{byte})"/>, named for its input: DER octets of an X.501 Name, not text.</summary>
    /// <param name="der">The Name's SEQUENCE.</param>
    /// <exception cref="X509ParseException">The octets are not a Name or exceed the limits.</exception>
    public static DistinguishedName FromDer(ReadOnlyMemory<byte> der) => Parse(der, X509Limits.Default);

    /// <summary>The same as <see cref="Parse(ReadOnlyMemory{byte}, X509Limits)"/>, named for its input: DER octets of an X.501 Name, not text.</summary>
    /// <param name="der">The Name's SEQUENCE.</param>
    /// <param name="limits">The limits to enforce.</param>
    /// <exception cref="X509ParseException">The octets are not a Name or exceed the limits.</exception>
    public static DistinguishedName FromDer(ReadOnlyMemory<byte> der, X509Limits limits) => Parse(der, limits);

    /// <summary>Like <see cref="FromDer(ReadOnlyMemory{byte})"/> but returns false on failure.</summary>
    public static bool TryFromDer(ReadOnlyMemory<byte> der, out DistinguishedName? name) => TryParse(der, out name);

    /// <summary>Reads an RFC 4514 string; the same as <see cref="FromString"/>. The input is text, not DER (for DER use <see cref="FromDer(ReadOnlyMemory{byte})"/>).</summary>
    /// <param name="rfc4514">The text, such as <c>"CN=Example,O=Org"</c>.</param>
    /// <exception cref="FormatException">The text is not a valid RFC 4514 string.</exception>
    public static DistinguishedName Parse(string rfc4514) => FromString(rfc4514);

    /// <summary>Like <see cref="FromString"/> but returns false when the text is not a valid RFC 4514 string.</summary>
    public static bool TryFromString(string rfc4514, out DistinguishedName? name)
    {
        ArgumentNullException.ThrowIfNull(rfc4514);
        try
        {
            name = FromString(rfc4514);
            return true;
        }
        catch (Exception e) when (e is FormatException or ArgumentException)
        {
            name = null;
            return false;
        }
    }

    /// <summary>Checks the structure of <paramref name="encoded"/> against <paramref name="limits"/>.</summary>
    public static DistinguishedName Parse(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxNameLength)
        {
            throw X509Read.Limit("Name", $"{encoded.Length} octets exceed the limit of {limits.MaxNameLength}.");
        }

        try
        {
            Validate(encoded.Span, limits);
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("Name", e);
        }

        return new DistinguishedName(encoded);
    }

    /// <summary>Like <see cref="Parse(ReadOnlyMemory{byte})"/> but returns false on failure.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out DistinguishedName? name)
    {
        try
        {
            name = Parse(encoded);
            return true;
        }
        catch (X509ParseException)
        {
            name = null;
            return false;
        }
    }

    // Walks the structure once without allocating: Name ::= SEQUENCE OF SET SIZE (1..MAX) OF SEQUENCE { type OID, value ANY }.
    internal static void Validate(ReadOnlySpan<byte> encoded, X509Limits limits)
    {
        var outer = new Asn1Reader(encoded, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader name = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        int rdns = 0;
        while (name.HasData)
        {
            if (++rdns > limits.MaxNameElements)
            {
                throw X509Read.Limit("Name", "too many relative distinguished names");
            }

            Asn1Reader set = name.ReadSet();
            int attrs = 0;
            while (set.HasData)
            {
                if (++attrs > limits.MaxNameElements)
                {
                    throw X509Read.Limit("Name", "too many attributes in one relative distinguished name");
                }

                Asn1Reader atv = set.ReadSequence();
                atv.ReadObjectIdentifierBytes();
                atv.SkipValue();
                atv.ThrowIfNotEmpty();
            }

            if (attrs == 0)
            {
                throw X509Read.Bad("Name", "empty relative distinguished name");
            }
        }
    }

    private static RelativeDistinguishedName[] Decode(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        var result = new List<RelativeDistinguishedName>();
        try
        {
            var outer = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader name = outer.ReadSequence();
            while (name.HasData)
            {
                name.TryPeekEncodedValue(out ReadOnlySpan<byte> setBytes);
                Asn1Reader set = name.ReadSet();
                var attrs = new List<AttributeTypeAndValue>();
                while (set.HasData)
                {
                    Asn1Reader atv = set.ReadSequence();
                    string type = atv.ReadObjectIdentifier();
                    attrs.Add(new AttributeTypeAndValue(type, X509Read.Slice(encoded, atv.ReadEncodedValue())));
                }

                result.Add(new RelativeDistinguishedName(attrs, X509Read.Slice(encoded, setBytes)));
            }
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("Name", e);
        }

        return [.. result];
    }

    /// <summary>RFC 4514 keywords for attribute types (§3).</summary>
    internal static string? Keyword(string oid) => oid switch
    {
        KnownOids.CommonName => "CN",
        KnownOids.Locality => "L",
        KnownOids.State => "ST",
        KnownOids.Organization => "O",
        KnownOids.OrganizationalUnit => "OU",
        KnownOids.Country => "C",
        "2.5.4.9" => "STREET",
        KnownOids.DomainComponent => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        _ => null,
    };

    private static string? OidForKeyword(string k) => k.ToUpperInvariant() switch
    {
        "CN" => KnownOids.CommonName,
        "L" => KnownOids.Locality,
        "ST" => KnownOids.State,
        "S" => KnownOids.State,
        "O" => KnownOids.Organization,
        "OU" => KnownOids.OrganizationalUnit,
        "C" => KnownOids.Country,
        "STREET" => "2.5.4.9",
        "DC" => KnownOids.DomainComponent,
        "UID" => "0.9.2342.19200300.100.1.1",
        "SERIALNUMBER" => KnownOids.SerialNumber,
        "EMAILADDRESS" => KnownOids.EmailAddress,
        "E" => KnownOids.EmailAddress,
        _ => null,
    };

    /// <summary>Renders one attribute value as RFC 4514 §2.4 prescribes: escaped text for string types, <c>#</c> and the hex of the encoding otherwise.</summary>
    internal static string EscapeValue(AttributeTypeAndValue a)
    {
        string? text = a.Text;
        if (text is null)
        {
            return "#" + Convert.ToHexString(a.Value.Span);
        }

        var sb = new StringBuilder(text.Length + 4);
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            bool escape = c is '"' or '+' or ',' or ';' or '<' or '>' or '\\'
                || (i == 0 && (c is ' ' or '#'))
                || (i == text.Length - 1 && c == ' ');
            if (c == '\0')
            {
                sb.Append("\\00");
            }
            else
            {
                if (escape)
                {
                    sb.Append('\\');
                }

                sb.Append(c);
            }
        }

        return sb.ToString();
    }

    /// <summary>The name in RFC 4514 string form: relative names in reverse order, separated by commas. The empty name is the empty string.</summary>
    public override string ToString()
    {
        IReadOnlyList<RelativeDistinguishedName> rdns;
        try
        {
            rdns = Rdns;
        }
        catch (X509ParseException)
        {
            return string.Empty;
        }

        var sb = new StringBuilder();
        for (int i = rdns.Count - 1; i >= 0; i--)
        {
            if (sb.Length > 0)
            {
                sb.Append(',');
            }

            sb.Append(rdns[i]);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Builds a name from attribute type and text pairs, listed most significant first (the order of the encoding, the reverse of the RFC 4514 string).
    /// Each pair becomes its own single-valued relative name. Country is a PrintableString, e-mail address and domain component are IA5String,
    /// everything else is UTF8String.
    /// </summary>
    /// <param name="attributes">Pairs of dotted attribute type and value.</param>
    public static DistinguishedName Create(params ReadOnlySpan<(string Type, string Value)> attributes)
    {
        var rdns = new List<IReadOnlyList<(string, string)>>();
        foreach ((string, string) a in attributes)
        {
            rdns.Add([a]);
        }

        return Build(rdns);
    }

    private static DistinguishedName Build(List<IReadOnlyList<(string Type, string Value)>> rdns)
    {
        var items = new List<byte[]>();
        foreach (IReadOnlyList<(string Type, string Value)> rdn in rdns)
        {
            var members = new List<byte[]>();
            foreach ((string type, string value) in rdn)
            {
                int tag = type switch
                {
                    KnownOids.Country or KnownOids.SerialNumber => Asn1Tags.PrintableString,
                    KnownOids.EmailAddress or KnownOids.DomainComponent => Asn1Tags.Ia5String,
                    _ => Asn1Tags.Utf8String,
                };
                byte[] content = tag == Asn1Tags.Utf8String ? Encoding.UTF8.GetBytes(value) : Encoding.ASCII.GetBytes(value);
                if (tag != Asn1Tags.Utf8String && content.Any(b => b > 0x7F))
                {
                    throw new ArgumentException($"The value for {type} must be ASCII.", nameof(rdns));
                }

                byte[] typeOid;
                try
                {
                    typeOid = DerWriter.Oid(type);
                }
                catch (OverflowException e)
                {
                    // A negative or oversized arc is malformed text, the same class of error as a non-numeric one.
                    throw new FormatException($"The attribute type '{type}' is not an object identifier.", e);
                }

                members.Add(DerWriter.Sequence(typeOid, DerWriter.Tlv((byte)tag, content)));
            }

            items.Add(DerWriter.SetOf(members));
        }

        return new DistinguishedName(DerWriter.Sequence([.. items]));
    }

    /// <summary>Reads an RFC 4514 <b>string</b> ("CN=Example,O=Org"; for DER octets see <see cref="FromDer(ReadOnlyMemory{byte})"/>): keywords or dotted types, backslash escapes, <c>#hex</c> values and <c>+</c> for multi-valued names.</summary>
    /// <exception cref="FormatException">The text is not a valid RFC 4514 string.</exception>
    public static DistinguishedName FromString(string rfc4514)
    {
        ArgumentNullException.ThrowIfNull(rfc4514);
        var rdns = new List<IReadOnlyList<(string, string)>>();
        if (rfc4514.Length == 0)
        {
            return Empty;
        }

        // Split on unescaped commas; the string lists the least significant name first.
        var parts = new List<string>();
        var cur = new StringBuilder();
        for (int i = 0; i < rfc4514.Length; i++)
        {
            char c = rfc4514[i];
            if (c == '\\' && i + 1 < rfc4514.Length)
            {
                cur.Append(c).Append(rfc4514[++i]);
            }
            else if (c == ',')
            {
                parts.Add(cur.ToString());
                cur.Clear();
            }
            else
            {
                cur.Append(c);
            }
        }

        parts.Add(cur.ToString());
        for (int p = parts.Count - 1; p >= 0; p--)
        {
            var members = new List<(string, string)>();
            foreach (string atv in SplitUnescaped(parts[p], '+'))
            {
                int eq = atv.IndexOf('=', StringComparison.Ordinal);
                if (eq <= 0)
                {
                    throw new FormatException("Expected type=value in a name component.");
                }

                string key = atv[..eq].Trim();
                string type = OidForKeyword(key) ?? (key.Length > 0 && char.IsAsciiDigit(key[0]) ? key : throw new FormatException($"Unknown attribute type '{key}'."));
                members.Add((type, Unescape(atv[(eq + 1)..])));
            }

            rdns.Add(members);
        }

        return Build(rdns);
    }

    private static List<string> SplitUnescaped(string s, char sep)
    {
        var list = new List<string>();
        var cur = new StringBuilder();
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '\\' && i + 1 < s.Length)
            {
                cur.Append(s[i]).Append(s[++i]);
            }
            else if (s[i] == sep)
            {
                list.Add(cur.ToString());
                cur.Clear();
            }
            else
            {
                cur.Append(s[i]);
            }
        }

        list.Add(cur.ToString());
        return list;
    }

    private static string Unescape(string v)
    {
        var bytes = new List<byte>();
        var sb = new StringBuilder();
        void Flush()
        {
            if (bytes.Count > 0)
            {
                sb.Append(Encoding.UTF8.GetString([.. bytes]));
                bytes.Clear();
            }
        }

        for (int i = 0; i < v.Length; i++)
        {
            char c = v[i];
            if (c != '\\')
            {
                Flush();
                sb.Append(c);
                continue;
            }

            if (++i >= v.Length)
            {
                throw new FormatException("A name value ends in a lone backslash.");
            }

            if (i + 1 < v.Length && char.IsAsciiHexDigit(v[i]) && char.IsAsciiHexDigit(v[i + 1]))
            {
                bytes.Add(byte.Parse(v.AsSpan(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                i++;
            }
            else
            {
                Flush();
                sb.Append(v[i]);
            }
        }

        Flush();
        return sb.ToString().Trim(' ');
    }

    /// <summary>
    /// True when the two names are the same name under RFC 5280 §7.1: attribute types equal, string values equal after case folding and
    /// collapsing of white space, other values equal octet for octet, relative names equal as sets.
    /// </summary>
    public bool Matches(DistinguishedName? other)
    {
        if (other is null)
        {
            return false;
        }

        if (Encoded.Span.SequenceEqual(other.Encoded.Span))
        {
            return true;
        }

        IReadOnlyList<RelativeDistinguishedName> a, b;
        try
        {
            a = Rdns;
            b = other.Rdns;
        }
        catch (X509ParseException)
        {
            return false;
        }

        if (a.Count != b.Count)
        {
            return false;
        }

        for (int i = 0; i < a.Count; i++)
        {
            if (a[i].Attributes.Count != b[i].Attributes.Count)
            {
                return false;
            }

            var rest = b[i].Attributes.ToList();
            foreach (AttributeTypeAndValue x in a[i].Attributes)
            {
                int found = rest.FindIndex(y => AttributeMatches(x, y));
                if (found < 0)
                {
                    return false;
                }

                rest.RemoveAt(found);
            }
        }

        return true;
    }

    private static bool AttributeMatches(AttributeTypeAndValue x, AttributeTypeAndValue y)
    {
        if (x.Type != y.Type)
        {
            return false;
        }

        string? tx = x.Text, ty = y.Text;
        if (tx is null || ty is null)
        {
            return x.Value.Span.SequenceEqual(y.Value.Span);
        }

        return Fold(tx) == Fold(ty);
    }

    // RFC 5280 §7.1 asks for the RFC 4518 string preparation; trimming, collapsing inner white space and case folding is its practical core.
    private static string Fold(string s)
    {
        var sb = new StringBuilder(s.Length);
        bool space = true;
        foreach (char c in s)
        {
            if (c == ' ' || c == '\t')
            {
                if (!space)
                {
                    sb.Append(' ');
                }

                space = true;
            }
            else
            {
                sb.Append(char.ToUpperInvariant(c));
                space = false;
            }
        }

        return sb.ToString().TrimEnd(' ');
    }

    /// <summary>Equality of the encodings. Use <see cref="Matches"/> for name comparison as RFC 5280 defines it.</summary>
    public bool Equals(DistinguishedName? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as DistinguishedName);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }
}
