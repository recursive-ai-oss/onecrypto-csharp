namespace RecursiveAI.OneCrypto.Asn1;

/// <summary>The class of an ASN.1 tag (ITU-T X.690 clause 8.1.2.2).</summary>
public enum Asn1TagClass
{
    /// <summary>Universal: the type is defined by X.680 itself.</summary>
    Universal = 0,

    /// <summary>Application.</summary>
    Application = 1,

    /// <summary>Context-specific, the class of the tags in most protocol modules.</summary>
    ContextSpecific = 2,

    /// <summary>Private.</summary>
    Private = 3,
}

/// <summary>The encoding rules a reader enforces or a writer produces (ITU-T X.690 clauses 8, 9, 10 and 11).</summary>
public enum Asn1Rules
{
    /// <summary>Basic Encoding Rules: any valid encoding, including indefinite lengths and constructed strings.</summary>
    Ber = 0,

    /// <summary>Canonical Encoding Rules (X.690 clause 9).</summary>
    Cer = 1,

    /// <summary>Distinguished Encoding Rules (X.690 clause 10 and 11): exactly one encoding per value, definite lengths only.</summary>
    Der = 2,
}

/// <summary>
/// An ASN.1 tag: class, number and the primitive/constructed bit. Equality compares the class and the number only, because
/// whether an element is constructed is a property of its encoding, not of its identity.
/// </summary>
public readonly struct Asn1Tag : IEquatable<Asn1Tag>
{
    // For the parsers, which have already checked the number.
    internal Asn1Tag(Asn1TagClass tagClass, int number, bool constructed, bool _)
    {
        TagClass = tagClass;
        TagNumber = number;
        IsConstructed = constructed;
    }

    /// <summary>Creates a tag. <paramref name="number"/> must not be negative.</summary>
    public Asn1Tag(Asn1TagClass tagClass, int number, bool constructed = false)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(number);
        TagClass = tagClass;
        TagNumber = number;
        IsConstructed = constructed;
    }

    /// <summary>Creates the universal tag with the given number.</summary>
    public Asn1Tag(int universalNumber, bool constructed = false)
        : this(Asn1TagClass.Universal, universalNumber, constructed)
    {
    }

    /// <summary>The tag class.</summary>
    public Asn1TagClass TagClass { get; }

    /// <summary>The tag number (0 or more; values of 31 and over use the high-tag-number form on the wire).</summary>
    public int TagNumber { get; }

    /// <summary>Whether the constructed bit is set.</summary>
    public bool IsConstructed { get; }

    /// <summary>A universal tag.</summary>
    public static Asn1Tag Universal(int number, bool constructed = false) => new(Asn1TagClass.Universal, number, constructed);

    /// <summary>A context-specific tag, primitive by default, as used for implicit tagging of primitives.</summary>
    public static Asn1Tag Context(int number, bool constructed = false) => new(Asn1TagClass.ContextSpecific, number, constructed);

    /// <summary>SEQUENCE, always constructed.</summary>
    public static Asn1Tag Sequence => new(Asn1Tags.Sequence, true);

    /// <summary>SET and SET OF, always constructed.</summary>
    public static Asn1Tag Set => new(Asn1Tags.Set, true);

    /// <summary>The same tag with the constructed bit set as given.</summary>
    public Asn1Tag WithConstructed(bool constructed) => new(TagClass, TagNumber, constructed);

    /// <summary>True when class and number match, ignoring the constructed bit.</summary>
    public bool Equals(Asn1Tag other) => TagClass == other.TagClass && TagNumber == other.TagNumber;

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Asn1Tag t && Equals(t);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine((int)TagClass, TagNumber);

    /// <summary>Equality on class and number.</summary>
    public static bool operator ==(Asn1Tag left, Asn1Tag right) => left.Equals(right);

    /// <summary>Inequality on class and number.</summary>
    public static bool operator !=(Asn1Tag left, Asn1Tag right) => !left.Equals(right);

    /// <inheritdoc />
    public override string ToString() => $"{TagClass} {TagNumber}{(IsConstructed ? " constructed" : string.Empty)}";

    /// <summary>The number of octets the identifier takes on the wire.</summary>
    public int EncodedLength
    {
        get
        {
            if (TagNumber < 31)
            {
                return 1;
            }

            int n = 1;
            for (int v = TagNumber; v != 0; v >>= 7)
            {
                n++;
            }

            return n;
        }
    }

    /// <summary>Writes the identifier octets (X.690 clause 8.1.2) and returns how many were written.</summary>
    public int Encode(Span<byte> destination)
    {
        int len = EncodedLength;
        if (destination.Length < len)
        {
            throw new ArgumentException("The destination is too small.", nameof(destination));
        }

        byte first = (byte)(((int)TagClass << 6) | (IsConstructed ? 0x20 : 0));
        if (TagNumber < 31)
        {
            destination[0] = (byte)(first | TagNumber);
            return 1;
        }

        destination[0] = (byte)(first | 0x1F);
        for (int i = len - 1, v = TagNumber; i >= 1; i--, v >>= 7)
        {
            destination[i] = (byte)((v & 0x7F) | (i == len - 1 ? 0 : 0x80));
        }

        return len;
    }
}

/// <summary>Universal tag numbers (X.680 clause 8, table 1) for the types the formats in this library use.</summary>
public static class Asn1Tags
{
    /// <summary>BOOLEAN.</summary>
    public const int Boolean = 1;

    /// <summary>INTEGER.</summary>
    public const int IntegerType = 2;

    /// <summary>BIT STRING.</summary>
    public const int BitString = 3;

    /// <summary>OCTET STRING.</summary>
    public const int OctetString = 4;

    /// <summary>NULL.</summary>
    public const int Null = 5;

    /// <summary>OBJECT IDENTIFIER.</summary>
    public const int ObjectIdentifier = 6;

    /// <summary>ENUMERATED.</summary>
    public const int Enumerated = 10;

    /// <summary>UTF8String.</summary>
    public const int Utf8String = 12;

    /// <summary>NumericString.</summary>
    public const int NumericString = 18;

    /// <summary>PrintableString.</summary>
    public const int PrintableString = 19;

    /// <summary>T61String (TeletexString).</summary>
    public const int T61String = 20;

    /// <summary>IA5String.</summary>
    public const int Ia5String = 22;

    /// <summary>UTCTime.</summary>
    public const int UtcTime = 23;

    /// <summary>GeneralizedTime.</summary>
    public const int GeneralizedTime = 24;

    /// <summary>VisibleString.</summary>
    public const int VisibleString = 26;

    /// <summary>GeneralString.</summary>
    public const int GeneralString = 27;

    /// <summary>UniversalString (UCS-4, big endian).</summary>
    public const int UniversalString = 28;

    /// <summary>BMPString (UCS-2, big endian).</summary>
    public const int BmpString = 30;

    /// <summary>SEQUENCE and SEQUENCE OF.</summary>
    public const int Sequence = 16;

    /// <summary>SET and SET OF.</summary>
    public const int Set = 17;
}
