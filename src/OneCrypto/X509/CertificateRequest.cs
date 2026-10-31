using System.Linq;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

/// <summary>One attribute of a certification request (RFC 2986 §4): a type and its values, kept as received.</summary>
/// <param name="Type">The attribute type's dotted object identifier.</param>
/// <param name="Values">The value elements, each complete with tag and length.</param>
public sealed record CsrAttributeInfo(string Type, IReadOnlyList<ReadOnlyMemory<byte>> Values);

/// <summary>
/// A PKCS #10 certification request (RFC 2986). Immutable and lossless: the encoding is kept and the signature is checked over the
/// received <c>certificationRequestInfo</c> octets.
/// </summary>
public sealed class CertificateSigningRequest : IEquatable<CertificateSigningRequest>
{
    private readonly ReadOnlyMemory<byte> _info;
    private readonly ReadOnlyMemory<byte> _subject;
    private readonly ReadOnlyMemory<byte> _attributes;
    private readonly ReadOnlyMemory<byte> _algEnc;
    private readonly X509Limits _limits;
    private DistinguishedName? _subjectName;
    private AlgorithmIdentifier? _alg;
    private IReadOnlyList<CsrAttributeInfo>? _attrList;

    private CertificateSigningRequest(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        _limits = limits;
        Encoded = encoded;
        try
        {
            var top = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader req = top.ReadSequence();
            top.ThrowIfNotEmpty();
            ReadOnlySpan<byte> info = req.ReadEncodedValue();
            _info = X509Read.Slice(encoded, info);
            _algEnc = X509Read.Algorithm(req.ReadEncodedValue(), encoded, limits);
            Signature = X509Read.Slice(encoded, req.ReadBitString(out int unused));
            SignatureUnusedBits = unused;
            req.ThrowIfNotEmpty();

            var ir = new Asn1Reader(info, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader body = ir.ReadSequence();
            int version = body.ReadInt32();
            if (version != 0)
            {
                throw new X509ParseException("CertificationRequest", X509Error.UnsupportedVersion, $"version {version + 1} is not 1");
            }

            ReadOnlySpan<byte> subject = body.ReadEncodedValue();
            DistinguishedName.Validate(subject, limits);
            _subject = X509Read.Slice(encoded, subject);
            PublicKey = PublicKeyInfo.Read(ref body, encoded);
            if (body.HasData)
            {
                Asn1Reader attrs = body.ReadSet(Asn1Tag.Context(0, true));
                _attributes = X509Read.Slice(encoded, attrs.Remaining);
                int n = 0;
                while (attrs.HasData)
                {
                    if (++n > limits.MaxListEntries)
                    {
                        throw X509Read.Limit("CertificationRequest", "too many attributes");
                    }

                    Asn1Reader a = attrs.ReadSequence();
                    a.ReadObjectIdentifierBytes();
                    Asn1Reader values = a.ReadSet();
                    while (values.HasData)
                    {
                        values.SkipValue();
                    }

                    a.ThrowIfNotEmpty();
                }
            }

            body.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("CertificationRequest", e);
        }
    }

    /// <summary>The whole request exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The <c>certificationRequestInfo</c> element exactly as received: the octets the signature covers.</summary>
    public ReadOnlyMemory<byte> CertificationRequestInfo => _info;

    /// <summary>The requested subject name.</summary>
    public DistinguishedName Subject => _subjectName ??= DistinguishedName.Parse(_subject, _limits);

    /// <summary>The public key the certificate is requested for.</summary>
    public PublicKeyInfo PublicKey { get; }

    /// <summary>The signature algorithm.</summary>
    public AlgorithmIdentifier SignatureAlgorithm => _alg ??= AlgorithmIdentifier.Parse(_algEnc);

    /// <summary>The signature value (the BIT STRING content).</summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>Unused bits of the signature BIT STRING as received.</summary>
    public int SignatureUnusedBits { get; }

    /// <summary>The attributes in encoded order.</summary>
    public IReadOnlyList<CsrAttributeInfo> Attributes => _attrList ??= ReadAttributes();

    /// <summary>The extensions asked for in the PKCS #9 extensionRequest attribute, or an empty collection.</summary>
    /// <exception cref="X509ParseException">The attribute is malformed.</exception>
    public ExtensionCollection RequestedExtensions
    {
        get
        {
            CsrAttributeInfo? a = Attributes.FirstOrDefault(x => x.Type == KnownOids.ExtensionRequest);
            return a is null || a.Values.Count == 0 ? ExtensionCollection.Empty : ExtensionCollection.Decode(a.Values[0], _limits, "CertificationRequest");
        }
    }

    private List<CsrAttributeInfo> ReadAttributes()
    {
        var list = new List<CsrAttributeInfo>();
        try
        {
            var r = new Asn1Reader(_attributes.Span, Asn1Rules.Ber, _limits.Asn1);
            while (r.HasData)
            {
                Asn1Reader a = r.ReadSequence();
                string type = a.ReadObjectIdentifier();
                Asn1Reader vals = a.ReadSet();
                var values = new List<ReadOnlyMemory<byte>>();
                while (vals.HasData)
                {
                    values.Add(X509Read.Slice(Encoded, vals.ReadEncodedValue()));
                }

                list.Add(new CsrAttributeInfo(type, values));
            }
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("CertificationRequest", e);
        }

        return list;
    }

    /// <summary>Reads a request with the default limits.</summary>
    /// <exception cref="X509ParseException">The octets are not a certification request.</exception>
    public static CertificateSigningRequest Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, X509Limits.Default);

    /// <summary>Reads a request with the given limits.</summary>
    public static CertificateSigningRequest Parse(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxEncodedSize)
        {
            throw X509Read.Limit("CertificationRequest", $"{encoded.Length} octets exceed the limit of {limits.MaxEncodedSize}.");
        }

        return new CertificateSigningRequest(encoded, limits);
    }

    /// <summary>Reads a request, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out CertificateSigningRequest? request)
    {
        try
        {
            request = Parse(encoded);
            return true;
        }
        catch (X509ParseException)
        {
            request = null;
            return false;
        }
    }

    /// <summary>Reads the first <c>CERTIFICATE REQUEST</c> block of PEM text.</summary>
    public static CertificateSigningRequest FromPem(string pem)
    {
        ArgumentNullException.ThrowIfNull(pem);
        foreach (PemBlock b in X509Read.Pem("CertificationRequest", pem))
        {
            if (b.Label is "CERTIFICATE REQUEST" or "NEW CERTIFICATE REQUEST")
            {
                return Parse(new ReadOnlyMemory<byte>(b.Data));
            }
        }

        throw X509Read.Bad("CertificationRequest", "no CERTIFICATE REQUEST block in the text");
    }

    /// <summary>The request as a <c>CERTIFICATE REQUEST</c> PEM block (RFC 7468 §7).</summary>
    public string ToPem() => PemCodec.Write("CERTIFICATE REQUEST", Encoded.Span);

    /// <summary>Checks the request's signature with the key it carries: proof that the requester holds the private key (RFC 2986 §3).</summary>
    public SignatureVerification VerifySignature()
    {
        if (SignatureUnusedBits != 0)
        {
            return new(SignatureStatus.Invalid, string.Empty, "The signature BIT STRING has unused bits.", "RFC 2986 §4.2");
        }

        try
        {
            return PublicKey.VerifySignature(SignatureAlgorithm, _info.Span, Signature.Span);
        }
        catch (X509ParseException e)
        {
            return new(SignatureStatus.Malformed, string.Empty, e.Message, "RFC 2986 §4.2");
        }
    }

    /// <inheritdoc/>
    public bool Equals(CertificateSigningRequest? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CertificateSigningRequest);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }
}

/// <summary>What goes into a certification request.</summary>
public sealed class CertificateSigningRequestOptions
{
    /// <summary>The requested subject name.</summary>
    public required DistinguishedName Subject { get; init; }

    /// <summary>Extensions to request (subjectAltName, keyUsage and so on) in an extensionRequest attribute. Empty adds no attribute.</summary>
    public IReadOnlyList<Extension> Extensions { get; init; } = [];

    /// <summary>Further attributes, each as the type and the encoded value elements.</summary>
    public IReadOnlyList<CsrAttributeInfo> Attributes { get; init; } = [];
}

/// <summary>Creates PKCS #10 requests.</summary>
public static class CertificateSigningRequestBuilder
{
    /// <summary>Phase one of creating a request in two steps: returns the state to sign with the key that <paramref name="signerKey"/> describes (the requested key).</summary>
    public static PreparedSignature Prepare(CertificateSigningRequestOptions options, PublicKeyInfo signerKey, SignatureSpec spec, CryptoPolicy policy, DateTimeOffset at) =>
        X509TwoPhase.Prepare(PurposeRequest, signerKey, spec, policy, at, s => Create(options, s));

    /// <summary>Phase two: checks the signature and returns the request.</summary>
    /// <exception cref="InvalidSignatureException">The signature does not verify.</exception>
    public static CertificateSigningRequest Complete(PreparedSignature prepared, ReadOnlySpan<byte> signature) =>
        CertificateSigningRequest.Parse(X509TwoPhase.Complete(prepared, PurposeRequest, signature));

    private const string PurposeRequest = "x509.request";

    /// <summary>Creates a request for the signer's own public key, signed with it.</summary>
    public static CertificateSigningRequest Create(CertificateSigningRequestOptions options, X509Signer signer)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signer);
        var attrs = new List<byte[]>();
        if (options.Extensions.Count > 0)
        {
            attrs.Add(DerWriter.Sequence(DerWriter.Oid(KnownOids.ExtensionRequest), DerWriter.Set(BuildHelpers.Extensions(options.Extensions))));
        }

        foreach (CsrAttributeInfo a in options.Attributes)
        {
            attrs.Add(DerWriter.Sequence(DerWriter.Oid(a.Type), DerWriter.SetOf(a.Values.Select(v => v.ToArray()))));
        }

        byte[] info = DerWriter.Sequence(
            DerWriter.SignedInteger(0),
            options.Subject.Encoded.ToArray(),
            signer.PublicKey.Encoded.ToArray(),
            DerWriter.Tlv(0xA0, [.. attrs]));
        return CertificateSigningRequest.Parse(new ReadOnlyMemory<byte>(BuildHelpers.Signed(info, signer)));
    }
}
