using System.Linq;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

/// <summary>One <c>Request</c> of an OCSP request list: the certificate asked about and its single-request extensions.</summary>
public sealed class OcspSingleRequest
{
    private readonly ReadOnlyMemory<byte> _extensions;
    private readonly X509Limits _limits;
    private ExtensionCollection? _extensionList;

    internal OcspSingleRequest(OcspCertId id, ReadOnlyMemory<byte> extensions, X509Limits limits)
    {
        CertId = id;
        _extensions = extensions;
        _limits = limits;
    }

    /// <summary>The certificate being asked about.</summary>
    public OcspCertId CertId { get; }

    /// <summary>The single-request extensions, possibly empty.</summary>
    public ExtensionCollection Extensions => _extensionList ??= ExtensionCollection.Decode(_extensions, _limits, "OCSPRequest");
}

/// <summary>An OCSP request (RFC 6960 §4.1), optionally signed. Immutable and lossless; a signature covers the received <c>tbsRequest</c> octets.</summary>
public sealed class OcspRequest : IEquatable<OcspRequest>
{
    private readonly ReadOnlyMemory<byte> _extensions;
    private readonly ReadOnlyMemory<byte> _algEnc;
    private readonly X509Limits _limits;
    private ExtensionCollection? _extensionList;
    private AlgorithmIdentifier? _alg;

    private OcspRequest(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        _limits = limits;
        Encoded = encoded;
        try
        {
            var top = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader req = top.ReadSequence();
            top.ThrowIfNotEmpty();
            ReadOnlySpan<byte> tbsEnc = req.ReadEncodedValue();
            TbsRequest = X509Read.Slice(encoded, tbsEnc);
            var tr = new Asn1Reader(tbsEnc, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader tbs = tr.ReadSequence();
            Version = 1;
            if (tbs.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(0))
            {
                Asn1Reader w = tbs.ReadSequence(Asn1Tag.Context(0, true));
                int v = w.ReadInt32();
                w.ThrowIfNotEmpty();
                if (v != 0)
                {
                    throw new X509ParseException("OCSPRequest", X509Error.UnsupportedVersion, $"version {v + 1} is not 1");
                }
            }

            if (tbs.TryPeekTag(out t) && t == Asn1Tag.Context(1))
            {
                Asn1Reader w = tbs.ReadSequence(Asn1Tag.Context(1, true));
                RequestorName = GeneralName.Read(ref w, encoded);
                w.ThrowIfNotEmpty();
            }

            Asn1Reader list = tbs.ReadSequence();
            var requests = new List<OcspSingleRequest>();
            while (list.HasData)
            {
                if (requests.Count >= limits.MaxListEntries)
                {
                    throw X509Read.Limit("OCSPRequest", "too many requests");
                }

                Asn1Reader one = list.ReadSequence();
                OcspCertId id = OcspCertId.Read(ref one, encoded);
                ReadOnlyMemory<byte> ext = OcspRead.Extensions(ref one, encoded, limits, 0, "OCSPRequest");
                one.ThrowIfNotEmpty();
                requests.Add(new OcspSingleRequest(id, ext, limits));
            }

            Requests = requests;
            _extensions = OcspRead.Extensions(ref tbs, encoded, limits, 2, "OCSPRequest");
            tbs.ThrowIfNotEmpty();

            Certificates = [];
            if (req.TryPeekTag(out t) && t == Asn1Tag.Context(0))
            {
                Asn1Reader w = req.ReadSequence(Asn1Tag.Context(0, true));
                Asn1Reader sig = w.ReadSequence();
                w.ThrowIfNotEmpty();
                _algEnc = X509Read.Algorithm(sig.ReadEncodedValue(), encoded, limits);
                Signature = X509Read.Slice(encoded, sig.ReadBitString(out int unused));
                SignatureUnusedBits = unused;
                Certificates = OcspRead.Certificates(ref sig, encoded, limits, 0);
                sig.ThrowIfNotEmpty();
                IsSigned = true;
            }

            req.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("OCSPRequest", e);
        }
    }

    /// <summary>The whole request exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The <c>tbsRequest</c> element exactly as received: the octets a signature covers.</summary>
    public ReadOnlyMemory<byte> TbsRequest { get; }

    /// <summary>The version: always 1 (v1) in RFC 6960.</summary>
    public int Version { get; }

    /// <summary>The requestor's name, or null.</summary>
    public GeneralName? RequestorName { get; }

    /// <summary>The certificates asked about, in encoded order.</summary>
    public IReadOnlyList<OcspSingleRequest> Requests { get; }

    /// <summary>The request extensions, possibly empty.</summary>
    public ExtensionCollection Extensions => _extensionList ??= ExtensionCollection.Decode(_extensions, _limits, "OCSPRequest");

    /// <summary>The nonce (RFC 6960 §4.4.1, RFC 8954), or null when the request has none.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public ReadOnlyMemory<byte>? Nonce => Extensions.Get<OcspNonce>()?.Nonce;

    /// <summary>True when the request carries a signature.</summary>
    public bool IsSigned { get; }

    /// <summary>The signature algorithm, or null when unsigned.</summary>
    public AlgorithmIdentifier? SignatureAlgorithm => IsSigned ? _alg ??= AlgorithmIdentifier.Parse(_algEnc) : null;

    /// <summary>The signature value, or empty when unsigned.</summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>Unused bits of the signature BIT STRING as received.</summary>
    public int SignatureUnusedBits { get; }

    /// <summary>Certificates sent with the signature to help the responder verify it.</summary>
    public IReadOnlyList<Certificate> Certificates { get; }

    /// <summary>Checks the signature of a signed request with the requestor's public key over the received <c>tbsRequest</c> octets.</summary>
    public SignatureVerification VerifySignature(PublicKeyInfo requestorKey)
    {
        ArgumentNullException.ThrowIfNull(requestorKey);
        if (!IsSigned)
        {
            return new(SignatureStatus.Invalid, string.Empty, "The request is not signed.", "RFC 6960 §4.1.2");
        }

        try
        {
            return requestorKey.VerifySignature(SignatureAlgorithm!, TbsRequest.Span, Signature.Span);
        }
        catch (X509ParseException e)
        {
            return new(SignatureStatus.Malformed, string.Empty, e.Message, "RFC 6960 §4.1.2");
        }
    }

    /// <summary>Reads a request with the default limits.</summary>
    /// <exception cref="X509ParseException">The octets are not an OCSP request.</exception>
    public static OcspRequest Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, X509Limits.Default);

    /// <summary>Reads a request with the given limits.</summary>
    public static OcspRequest Parse(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxEncodedSize)
        {
            throw X509Read.Limit("OCSPRequest", $"{encoded.Length} octets exceed the limit of {limits.MaxEncodedSize}.");
        }

        return new OcspRequest(encoded, limits);
    }

    /// <summary>Reads a request, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out OcspRequest? request)
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

    /// <inheritdoc/>
    public bool Equals(OcspRequest? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as OcspRequest);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }
}

/// <summary>What goes into an OCSP request.</summary>
public sealed class OcspRequestOptions
{
    /// <summary>The certificates to ask about. At least one.</summary>
    public required IReadOnlyList<OcspCertId> Requests { get; init; }

    /// <summary>A nonce to bind the response to this request (RFC 8954: 1 to 32 octets), or empty for none.</summary>
    public ReadOnlyMemory<byte> Nonce { get; init; }

    /// <summary>The requestor's name, required when the request is signed (RFC 6960 §4.1.2).</summary>
    public GeneralName? RequestorName { get; init; }

    /// <summary>Further request extensions.</summary>
    public IReadOnlyList<Extension> Extensions { get; init; } = [];
}

/// <summary>Creates OCSP requests.</summary>
public static class OcspRequestBuilder
{
    /// <summary>Creates a request. With a <paramref name="signer"/> the request is signed and <paramref name="certificates"/> are sent along.</summary>
    /// <exception cref="ArgumentException">There is nothing to ask about, or the nonce is longer than 32 octets.</exception>
    public static OcspRequest Create(OcspRequestOptions options, X509Signer? signer = null, IEnumerable<Certificate>? certificates = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Requests.Count == 0)
        {
            throw new ArgumentException("A request asks about at least one certificate.", nameof(options));
        }

        if (options.Nonce.Length > 32)
        {
            throw new ArgumentException("A nonce is at most 32 octets (RFC 8954 §2.1).", nameof(options));
        }

        var exts = new List<Extension>(options.Extensions);
        if (!options.Nonce.IsEmpty)
        {
            exts.Add(Extension.Create(new OcspNonce(options.Nonce), false));
        }

        byte[] tbs = DerWriter.Sequence(
            options.RequestorName is null ? [] : DerWriter.Context(1, options.RequestorName.Encoded.ToArray()),
            DerWriter.Sequence([.. options.Requests.Select(r => DerWriter.Sequence(r.Encoded.ToArray()))]),
            exts.Count > 0 ? DerWriter.Context(2, BuildHelpers.Extensions(exts)) : []);
        if (signer is null)
        {
            return OcspRequest.Parse(new ReadOnlyMemory<byte>(DerWriter.Sequence(tbs)));
        }

        byte[] sig = signer.Sign(tbs);
        byte[] certs = certificates is null ? [] : DerWriter.Context(0, DerWriter.Sequence([.. certificates.Select(c => c.Encoded.ToArray())]));
        byte[] signature = DerWriter.Sequence(signer.SignatureAlgorithm.Encoded.ToArray(), X509Signer.BitString(sig), certs);
        return OcspRequest.Parse(new ReadOnlyMemory<byte>(DerWriter.Sequence(tbs, DerWriter.Context(0, signature))));
    }
}
