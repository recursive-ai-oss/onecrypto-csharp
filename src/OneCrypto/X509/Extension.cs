using System.Linq;
using System.Collections;
using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto;

/// <summary>The typed value of an extension: it knows its identifier, reads itself from the extension's value octets and writes them back.</summary>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface IExtensionValue<TSelf>
    where TSelf : class, IExtensionValue<TSelf>
{
    /// <summary>The extension's object identifier.</summary>
    static abstract string ExtensionOid { get; }

    /// <summary>Reads the value from the content of the extension's <c>extnValue</c> OCTET STRING.</summary>
    /// <exception cref="X509ParseException">The value is malformed.</exception>
    static abstract TSelf Parse(ReadOnlyMemory<byte> value);

    /// <summary>Writes the value as DER, ready to be the content of an <c>extnValue</c>.</summary>
    byte[] Encode();
}

/// <summary>
/// One <c>Extension</c> (RFC 5280 §4.1.2.9): identifier, criticality and value octets, kept as received. Unknown extensions are
/// preserved; typed access goes through <see cref="ExtensionCollection.Get{T}"/>.
/// </summary>
public sealed class Extension
{
    private Extension(string oid, bool critical, ReadOnlyMemory<byte> value, ReadOnlyMemory<byte> encoded)
    {
        Oid = oid;
        Critical = critical;
        Value = value;
        Encoded = encoded;
    }

    /// <summary>The extension's dotted object identifier.</summary>
    public string Oid { get; }

    /// <summary>The critical flag (false when absent).</summary>
    public bool Critical { get; }

    /// <summary>The content of the <c>extnValue</c> OCTET STRING: the DER of the extension's own type.</summary>
    public ReadOnlyMemory<byte> Value { get; }

    /// <summary>The whole Extension SEQUENCE.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>Builds an extension from a typed value.</summary>
    public static Extension Create<T>(T value, bool critical)
        where T : class, IExtensionValue<T>
    {
        ArgumentNullException.ThrowIfNull(value);
        return Create(T.ExtensionOid, critical, value.Encode());
    }

    /// <summary>Builds an extension from an identifier and the DER of its value.</summary>
    public static Extension Create(string oid, bool critical, ReadOnlySpan<byte> value)
    {
        byte[] v = value.ToArray();
        byte[] enc = critical
            ? DerWriter.Sequence(DerWriter.Oid(oid), DerWriter.Boolean(true), DerWriter.OctetString(v))
            : DerWriter.Sequence(DerWriter.Oid(oid), DerWriter.OctetString(v));
        return Read(enc);
    }

    private static Extension Read(byte[] enc)
    {
        var r = new Asn1Reader(enc, Asn1Rules.Ber);
        return Read(ref r, enc);
    }

    internal static Extension Read(ref Asn1Reader r, ReadOnlyMemory<byte> root)
    {
        ReadOnlySpan<byte> whole = r.ReadEncodedValue();
        var outer = new Asn1Reader(whole, Asn1Rules.Ber, r.Limits);
        Asn1Reader seq = outer.ReadSequence();
        string oid = seq.ReadObjectIdentifier();
        bool critical = false;
        if (seq.TryPeekTag(out Asn1Tag t) && t == new Asn1Tag(Asn1Tags.Boolean))
        {
            critical = seq.ReadBoolean();
        }

        ReadOnlySpan<byte> value = seq.ReadOctetString();
        seq.ThrowIfNotEmpty();
        return new Extension(oid, critical, X509Read.Slice(root, value), X509Read.Slice(root, whole));
    }

    /// <inheritdoc/>
    public override string ToString() => Critical ? Oid + " (critical)" : Oid;
}

/// <summary>The <c>Extensions</c> of a certificate, revocation list or OCSP message, in encoded order.</summary>
public sealed class ExtensionCollection : IReadOnlyList<Extension>
{
    private readonly Extension[] _items;

    private ExtensionCollection(Extension[] items)
    {
        _items = items;
    }

    /// <summary>A collection with no extensions.</summary>
    public static ExtensionCollection Empty { get; } = new([]);

    /// <summary>Wraps extensions built by the caller.</summary>
    public static ExtensionCollection Create(IEnumerable<Extension> extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);
        return new([.. extensions]);
    }

    /// <inheritdoc/>
    public int Count => _items.Length;

    /// <inheritdoc/>
    public Extension this[int index] => _items[index];

    /// <summary>True when two extensions have the same identifier (RFC 5280 §4.2 forbids it; the collection keeps both).</summary>
    public bool HasDuplicates => _items.Select(e => e.Oid).Distinct(StringComparer.Ordinal).Count() != _items.Length;

    /// <summary>The first extension with the identifier, or null.</summary>
    public Extension? Find(string oid) => Array.Find(_items, e => e.Oid == oid);

    /// <summary>True when an extension with the identifier is present.</summary>
    public bool Contains(string oid) => Find(oid) is not null;

    /// <summary>The typed value of the extension <typeparamref name="T"/>, or null when it is absent.</summary>
    /// <exception cref="X509ParseException">The extension is present but malformed.</exception>
    public T? Get<T>()
        where T : class, IExtensionValue<T>
    {
        Extension? e = Find(T.ExtensionOid);
        return e is null ? null : T.Parse(e.Value);
    }

    /// <summary>Like <see cref="Get{T}"/> but reports malformed values as false; <paramref name="value"/> is null when absent or malformed.</summary>
    public bool TryGet<T>(out T? value)
        where T : class, IExtensionValue<T>
    {
        try
        {
            value = Get<T>();
            return true;
        }
        catch (X509ParseException)
        {
            value = null;
            return false;
        }
    }

    /// <summary>The critical flag of the extension, or null when it is absent.</summary>
    public bool? IsCritical(string oid) => Find(oid)?.Critical;

    /// <inheritdoc/>
    public IEnumerator<Extension> GetEnumerator() => ((IEnumerable<Extension>)_items).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => _items.GetEnumerator();

    /// <summary>Checks the framing of a <c>SEQUENCE OF Extension</c> body without allocating.</summary>
    internal static void Validate(ReadOnlySpan<byte> sequenceEncoded, X509Limits limits, string what)
    {
        var outer = new Asn1Reader(sequenceEncoded, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader seq = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        int n = 0;
        while (seq.HasData)
        {
            if (++n > limits.MaxExtensions)
            {
                throw X509Read.Limit(what, "too many extensions");
            }

            Extension.Read(ref seq, ReadOnlyMemory<byte>.Empty);
        }
    }

    /// <summary>Decodes a <c>SEQUENCE OF Extension</c>.</summary>
    internal static ExtensionCollection Decode(ReadOnlyMemory<byte> sequenceEncoded, X509Limits limits, string what)
    {
        if (sequenceEncoded.IsEmpty)
        {
            return Empty;
        }

        try
        {
            var outer = new Asn1Reader(sequenceEncoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader seq = outer.ReadSequence();
            var list = new List<Extension>();
            while (seq.HasData)
            {
                if (list.Count >= limits.MaxExtensions)
                {
                    throw X509Read.Limit(what, "too many extensions");
                }

                list.Add(Extension.Read(ref seq, sequenceEncoded));
            }

            return new([.. list]);
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException(what, e);
        }
    }

    /// <summary>Writes the collection as <c>SEQUENCE OF Extension</c>.</summary>
    internal byte[] Encode() => DerWriter.Sequence([.. _items.Select(e => e.Encoded.ToArray())]);
}
