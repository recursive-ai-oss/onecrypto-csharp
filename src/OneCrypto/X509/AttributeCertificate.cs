using System.Linq;
using System.Numerics;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

/// <summary>One attribute of an attribute certificate (RFC 5755 §4.2.7): its type and value elements.</summary>
/// <param name="Type">The attribute type's dotted object identifier.</param>
/// <param name="Values">The value elements as received, each complete with tag and length.</param>
public sealed record AttributeCertificateEntry(string Type, IReadOnlyList<ReadOnlyMemory<byte>> Values);

/// <summary>
/// An X.509 attribute certificate (RFC 5755), read only: the models expose the framing, the serial number, the validity period, the
/// attributes and the extensions, and keep the holder and issuer elements as received. Issuing attribute certificates is not offered.
/// </summary>
public sealed class AttributeCertificate : IEquatable<AttributeCertificate>
{
    private readonly ReadOnlyMemory<byte> _extensions;
    private readonly ReadOnlyMemory<byte> _algEnc;
    private readonly X509Limits _limits;
    private ExtensionCollection? _extensionList;
    private AlgorithmIdentifier? _alg;
    private AlgorithmIdentifier? _tbsAlg;
    private readonly ReadOnlyMemory<byte> _tbsAlgEnc;

    private AttributeCertificate(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        _limits = limits;
        Encoded = encoded;
        try
        {
            var top = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader ac = top.ReadSequence();
            top.ThrowIfNotEmpty();
            ReadOnlySpan<byte> infoEnc = ac.ReadEncodedValue();
            AcInfo = X509Read.Slice(encoded, infoEnc);
            _algEnc = X509Read.Algorithm(ac.ReadEncodedValue(), encoded, limits);
            Signature = X509Read.Slice(encoded, ac.ReadBitString(out int unused));
            SignatureUnusedBits = unused;
            ac.ThrowIfNotEmpty();

            var ir = new Asn1Reader(infoEnc, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader info = ir.ReadSequence();
            int version = info.ReadInt32();
            if (version != 1)
            {
                throw new X509ParseException("AttributeCertificate", X509Error.UnsupportedVersion, $"version {version + 1} is not 2");
            }

            Holder = X509Read.Slice(encoded, info.ReadEncodedValue());
            Issuer = X509Read.Slice(encoded, info.ReadEncodedValue());
            _tbsAlgEnc = X509Read.Algorithm(info.ReadEncodedValue(), encoded, limits);
            SerialNumber = X509Read.Slice(encoded, info.ReadIntegerBytes());
            Asn1Reader validity = info.ReadSequence();
            NotBefore = validity.ReadGeneralizedTime();
            NotAfter = validity.ReadGeneralizedTime();
            validity.ThrowIfNotEmpty();
            Asn1Reader attrs = info.ReadSequence();
            var list = new List<AttributeCertificateEntry>();
            while (attrs.HasData)
            {
                if (list.Count >= limits.MaxListEntries)
                {
                    throw X509Read.Limit("AttributeCertificate", "too many attributes");
                }

                Asn1Reader a = attrs.ReadSequence();
                string type = a.ReadObjectIdentifier();
                Asn1Reader vals = a.ReadSet();
                var values = new List<ReadOnlyMemory<byte>>();
                while (vals.HasData)
                {
                    values.Add(X509Read.Slice(encoded, vals.ReadEncodedValue()));
                }

                a.ThrowIfNotEmpty();
                list.Add(new AttributeCertificateEntry(type, values));
            }

            Attributes = list;
            if (info.TryPeekTag(out Asn1Tag t) && t == new Asn1Tag(Asn1Tags.BitString))
            {
                IssuerUniqueId = X509Read.Slice(encoded, info.ReadBitString(out _));
            }

            if (info.HasData)
            {
                ReadOnlySpan<byte> exts = info.ReadEncodedValue();
                ExtensionCollection.Validate(exts, limits, "AttributeCertificate");
                _extensions = X509Read.Slice(encoded, exts);
            }

            info.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("AttributeCertificate", e);
        }
    }

    /// <summary>The whole attribute certificate as received.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The <c>acinfo</c> element exactly as received: the octets the signature covers.</summary>
    public ReadOnlyMemory<byte> AcInfo { get; }

    /// <summary>The <c>holder</c> element as received (RFC 5755 §4.2.2).</summary>
    public ReadOnlyMemory<byte> Holder { get; }

    /// <summary>The <c>issuer</c> element as received (RFC 5755 §4.2.3).</summary>
    public ReadOnlyMemory<byte> Issuer { get; }

    /// <summary>The signature algorithm named inside <c>acinfo</c>.</summary>
    public AlgorithmIdentifier TbsSignatureAlgorithm => _tbsAlg ??= AlgorithmIdentifier.Parse(_tbsAlgEnc);

    /// <summary>The signature algorithm named outside <c>acinfo</c>.</summary>
    public AlgorithmIdentifier SignatureAlgorithm => _alg ??= AlgorithmIdentifier.Parse(_algEnc);

    /// <summary>The serial number as INTEGER content octets.</summary>
    public ReadOnlyMemory<byte> SerialNumber { get; }

    /// <summary>The serial number as a number.</summary>
    public BigInteger SerialNumberValue => new(SerialNumber.Span, isUnsigned: false, isBigEndian: true);

    /// <summary>The start of the validity period.</summary>
    public DateTimeOffset NotBefore { get; }

    /// <summary>The end of the validity period.</summary>
    public DateTimeOffset NotAfter { get; }

    /// <summary>The attributes the certificate holds (roles, groups, clearances) in encoded order.</summary>
    public IReadOnlyList<AttributeCertificateEntry> Attributes { get; }

    /// <summary>The issuer unique identifier bits, or empty.</summary>
    public ReadOnlyMemory<byte> IssuerUniqueId { get; }

    /// <summary>The extensions in encoded order, possibly empty.</summary>
    public ExtensionCollection Extensions => _extensionList ??= ExtensionCollection.Decode(_extensions, _limits, "AttributeCertificate");

    /// <summary>The signature value (the BIT STRING content).</summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>Unused bits of the signature BIT STRING as received.</summary>
    public int SignatureUnusedBits { get; }

    /// <summary>Checks the signature with the attribute authority's public key over the received <c>acinfo</c> octets.</summary>
    public SignatureVerification VerifySignature(PublicKeyInfo issuerKey)
    {
        ArgumentNullException.ThrowIfNull(issuerKey);
        try
        {
            AlgorithmIdentifier outer = SignatureAlgorithm;
            if (!outer.Encoded.Span.SequenceEqual(_tbsAlgEnc.Span))
            {
                return new(SignatureStatus.Invalid, outer.Name, "The signature algorithm outside acinfo differs from the one inside.", "RFC 5755 §4.1");
            }

            return SignatureUnusedBits != 0
                ? new(SignatureStatus.Invalid, outer.Name, "The signature BIT STRING has unused bits.", "RFC 5755 §4.1")
                : issuerKey.VerifySignature(outer, AcInfo.Span, Signature.Span);
        }
        catch (X509ParseException e)
        {
            return new(SignatureStatus.Malformed, string.Empty, e.Message, "RFC 5755 §4.1");
        }
    }

    /// <summary>Reads an attribute certificate with the default limits.</summary>
    /// <exception cref="X509ParseException">The octets are not an attribute certificate.</exception>
    public static AttributeCertificate Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, X509Limits.Default);

    /// <summary>Reads an attribute certificate with the given limits.</summary>
    public static AttributeCertificate Parse(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxEncodedSize)
        {
            throw X509Read.Limit("AttributeCertificate", $"{encoded.Length} octets exceed the limit of {limits.MaxEncodedSize}.");
        }

        return new AttributeCertificate(encoded, limits);
    }

    /// <summary>Reads an attribute certificate, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out AttributeCertificate? certificate)
    {
        try
        {
            certificate = Parse(encoded);
            return true;
        }
        catch (X509ParseException)
        {
            certificate = null;
            return false;
        }
    }

    /// <summary>Reads the first <c>ATTRIBUTE CERTIFICATE</c> block of PEM text.</summary>
    public static AttributeCertificate FromPem(string pem)
    {
        ArgumentNullException.ThrowIfNull(pem);
        foreach (PemBlock b in X509Read.Pem("AttributeCertificate", pem))
        {
            if (b.Label == "ATTRIBUTE CERTIFICATE")
            {
                return Parse(new ReadOnlyMemory<byte>(b.Data));
            }
        }

        throw X509Read.Bad("AttributeCertificate", "no ATTRIBUTE CERTIFICATE block in the text");
    }

    /// <inheritdoc/>
    public bool Equals(AttributeCertificate? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as AttributeCertificate);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }
}
