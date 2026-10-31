using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

/// <summary>The status code of an OCSP response (RFC 6960 §4.2.1).</summary>
public enum OcspResponseStatus
{
    /// <summary>successful (0): the response carries response bytes.</summary>
    Successful = 0,

    /// <summary>malformedRequest (1).</summary>
    MalformedRequest = 1,

    /// <summary>internalError (2).</summary>
    InternalError = 2,

    /// <summary>tryLater (3).</summary>
    TryLater = 3,

    /// <summary>sigRequired (5).</summary>
    SigRequired = 5,

    /// <summary>unauthorized (6).</summary>
    Unauthorized = 6,
}

/// <summary>The status of one certificate in an OCSP response (RFC 6960 §4.2.2.3).</summary>
public enum OcspCertStatus
{
    /// <summary>good: not revoked (it does not say the certificate was ever issued).</summary>
    Good,

    /// <summary>revoked, with a time and optionally a reason.</summary>
    Revoked,

    /// <summary>unknown: the responder does not know the certificate.</summary>
    Unknown,
}

/// <summary>An OCSP <c>CertID</c> (RFC 6960 §4.1.1): which certificate a request or response is about.</summary>
public sealed class OcspCertId : IEquatable<OcspCertId>
{
    private OcspCertId(ReadOnlyMemory<byte> encoded, AlgorithmIdentifier hash, ReadOnlyMemory<byte> nameHash, ReadOnlyMemory<byte> keyHash, ReadOnlyMemory<byte> serial)
    {
        Encoded = encoded;
        HashAlgorithm = hash;
        IssuerNameHash = nameHash;
        IssuerKeyHash = keyHash;
        SerialNumber = serial;
    }

    /// <summary>The element exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The hash algorithm of the two hashes.</summary>
    public AlgorithmIdentifier HashAlgorithm { get; }

    /// <summary>The hash of the DER of the issuer name in the certificate.</summary>
    public ReadOnlyMemory<byte> IssuerNameHash { get; }

    /// <summary>The hash of the issuer's public key bits (the BIT STRING content, without tag, length or unused-bits octet).</summary>
    public ReadOnlyMemory<byte> IssuerKeyHash { get; }

    /// <summary>The certificate's serial number as INTEGER content octets.</summary>
    public ReadOnlyMemory<byte> SerialNumber { get; }

    /// <summary>The serial number as a number.</summary>
    public BigInteger SerialNumberValue => new(SerialNumber.Span, isUnsigned: false, isBigEndian: true);

    /// <summary>Builds the identifier for <paramref name="certificate"/> issued by <paramref name="issuer"/>. The hash defaults to SHA-1, which every responder must accept (RFC 6960 §4.3).</summary>
    public static OcspCertId Create(Certificate certificate, Certificate issuer, HashAlgorithmName? hash = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);
        HashAlgorithmName h = hash ?? HashAlgorithmName.SHA1;
        string oid = h.Name switch
        {
            "SHA1" => KnownOids.Sha1,
            "SHA256" => KnownOids.Sha256,
            "SHA384" => KnownOids.Sha384,
            "SHA512" => KnownOids.Sha512,
            _ => throw new ArgumentException("Unsupported hash " + h.Name, nameof(hash)),
        };
        AlgorithmIdentifier alg = AlgorithmIdentifier.WithNull(oid);
        byte[] nameHash = CryptographicOperations.HashData(h, certificate.Issuer.Encoded.Span);
        byte[] keyHash = CryptographicOperations.HashData(h, issuer.PublicKey.KeyBits.Span);
        byte[] enc = DerWriter.Sequence(alg.Encoded.ToArray(), DerWriter.OctetString(nameHash), DerWriter.OctetString(keyHash), BuildHelpers.UnsignedInt(certificate.SerialNumber.Span));
        return Parse(enc);
    }

    /// <summary>True when this identifier names <paramref name="certificate"/> as issued by <paramref name="issuer"/>: the hashes are recomputed with this identifier's own hash algorithm.</summary>
    public bool Matches(Certificate certificate, Certificate issuer)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);
        if (!SignatureAlgorithms.TryHash(HashAlgorithm.Oid, out HashAlgorithmName h))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(CryptographicOperations.HashData(h, certificate.Issuer.Encoded.Span), IssuerNameHash.Span)
            && CryptographicOperations.FixedTimeEquals(CryptographicOperations.HashData(h, issuer.PublicKey.KeyBits.Span), IssuerKeyHash.Span)
            && TrimZeros(SerialNumber.Span).SequenceEqual(TrimZeros(certificate.SerialNumber.Span));
    }

    private static ReadOnlySpan<byte> TrimZeros(ReadOnlySpan<byte> s)
    {
        while (s.Length > 1 && s[0] == 0)
        {
            s = s[1..];
        }

        return s;
    }

    /// <summary>Reads a CertID.</summary>
    /// <exception cref="X509ParseException">The octets are not a CertID.</exception>
    public static OcspCertId Parse(ReadOnlyMemory<byte> encoded)
    {
        try
        {
            var r = new Asn1Reader(encoded.Span, Asn1Rules.Ber);
            OcspCertId id = Read(ref r, encoded);
            r.ThrowIfNotEmpty();
            return id;
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("CertID", e);
        }
    }

    internal static OcspCertId Read(ref Asn1Reader r, ReadOnlyMemory<byte> root)
    {
        ReadOnlySpan<byte> whole = r.ReadEncodedValue();
        var o = new Asn1Reader(whole, Asn1Rules.Ber, r.Limits);
        Asn1Reader seq = o.ReadSequence();
        AlgorithmIdentifier alg = AlgorithmIdentifier.Read(ref seq, root);
        ReadOnlySpan<byte> nameHash = seq.ReadOctetString();
        ReadOnlySpan<byte> keyHash = seq.ReadOctetString();
        ReadOnlySpan<byte> serial = seq.ReadIntegerBytes();
        seq.ThrowIfNotEmpty();
        return new OcspCertId(X509Read.Slice(root, whole), alg, X509Read.Slice(root, nameHash), X509Read.Slice(root, keyHash), X509Read.Slice(root, serial));
    }

    /// <inheritdoc/>
    public bool Equals(OcspCertId? other) =>
        other is not null
        && HashAlgorithm.Oid == other.HashAlgorithm.Oid
        && IssuerNameHash.Span.SequenceEqual(other.IssuerNameHash.Span)
        && IssuerKeyHash.Span.SequenceEqual(other.IssuerKeyHash.Span)
        && TrimZeros(SerialNumber.Span).SequenceEqual(TrimZeros(other.SerialNumber.Span));

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as OcspCertId);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.Add(HashAlgorithm.Oid, StringComparer.Ordinal);
        h.AddBytes(IssuerKeyHash.Span);
        h.AddBytes(TrimZeros(SerialNumber.Span));
        return h.ToHashCode();
    }
}

/// <summary>Shared reading steps for the OCSP messages.</summary>
internal static class OcspRead
{
    /// <summary>Reads <c>[tag] EXPLICIT SEQUENCE OF Certificate</c> when it is next.</summary>
    public static List<Certificate> Certificates(ref Asn1Reader seq, ReadOnlyMemory<byte> root, X509Limits limits, int contextTag)
    {
        var list = new List<Certificate>();
        if (seq.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(contextTag))
        {
            Asn1Reader w = seq.ReadSequence(Asn1Tag.Context(contextTag, true));
            Asn1Reader certs = w.ReadSequence();
            w.ThrowIfNotEmpty();
            while (certs.HasData)
            {
                if (list.Count >= limits.MaxEmbeddedCertificates)
                {
                    throw X509Read.Limit("OCSP", "too many embedded certificates");
                }

                list.Add(Certificate.Parse(X509Read.Slice(root, certs.ReadEncodedValue()), limits));
            }
        }

        return list;
    }

    /// <summary>Reads <c>[tag] EXPLICIT Extensions</c> when it is next, returning the extensions SEQUENCE slice.</summary>
    public static ReadOnlyMemory<byte> Extensions(ref Asn1Reader seq, ReadOnlyMemory<byte> root, X509Limits limits, int contextTag, string what)
    {
        if (seq.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(contextTag))
        {
            Asn1Reader w = seq.ReadSequence(Asn1Tag.Context(contextTag, true));
            ReadOnlySpan<byte> list = w.ReadEncodedValue();
            w.ThrowIfNotEmpty();
            ExtensionCollection.Validate(list, limits, what);
            return X509Read.Slice(root, list);
        }

        return default;
    }
}
