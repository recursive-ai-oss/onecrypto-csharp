using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

/// <summary>Who signed a basic OCSP response: a name or the hash of a key (RFC 6960 §4.2.1).</summary>
/// <param name="Name">The responder's name when identified by name, otherwise null.</param>
/// <param name="KeyHash">The SHA-1 of the responder's public key bits when identified by key, otherwise empty.</param>
public sealed record OcspResponderId(DistinguishedName? Name, ReadOnlyMemory<byte> KeyHash = default)
{
    /// <summary>True when this identifier names the holder of <paramref name="certificate"/>: by subject name, or by the SHA-1 of its key bits.</summary>
    public bool Matches(Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (Name is not null)
        {
            return Name.Matches(certificate.Subject);
        }

        return CryptographicOperations.HashData(HashAlgorithmName.SHA1, certificate.PublicKey.KeyBits.Span).AsSpan().SequenceEqual(KeyHash.Span);
    }

    internal byte[] Write() => Name is not null
        ? DerWriter.Context(1, Name.Encoded.ToArray())
        : DerWriter.Context(2, DerWriter.OctetString(KeyHash.Span));
}

/// <summary>One <c>SingleResponse</c> of a basic OCSP response (RFC 6960 §4.2.1).</summary>
public sealed class OcspSingleResponse
{
    private readonly ReadOnlyMemory<byte> _extensions;
    private readonly X509Limits _limits;
    private ExtensionCollection? _extensionList;

    internal OcspSingleResponse(
        OcspCertId id,
        OcspCertStatus status,
        DateTimeOffset? revocationTime,
        RevocationReason? reason,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        ReadOnlyMemory<byte> extensions,
        X509Limits limits)
    {
        CertId = id;
        Status = status;
        RevocationTime = revocationTime;
        RevocationReason = reason;
        ThisUpdate = thisUpdate;
        NextUpdate = nextUpdate;
        _extensions = extensions;
        _limits = limits;
    }

    /// <summary>The certificate this answer is about.</summary>
    public OcspCertId CertId { get; }

    /// <summary>good, revoked or unknown.</summary>
    public OcspCertStatus Status { get; }

    /// <summary>When the certificate was revoked, for a revoked status.</summary>
    public DateTimeOffset? RevocationTime { get; }

    /// <summary>The reason, for a revoked status that gives one.</summary>
    public RevocationReason? RevocationReason { get; }

    /// <summary>The time the status was known to be correct at (RFC 6960 §2.4).</summary>
    public DateTimeOffset ThisUpdate { get; }

    /// <summary>When newer information is available, or null: then newer information is always available (RFC 6960 §4.2.2.1).</summary>
    public DateTimeOffset? NextUpdate { get; }

    /// <summary>The single-response extensions, possibly empty.</summary>
    public ExtensionCollection Extensions => _extensionList ??= ExtensionCollection.Decode(_extensions, _limits, "SingleResponse");
}

/// <summary>A <c>BasicOCSPResponse</c> (RFC 6960 §4.2.1). Immutable and lossless; the signature covers the received <c>tbsResponseData</c> octets.</summary>
public sealed class OcspBasicResponse : IEquatable<OcspBasicResponse>
{
    private readonly ReadOnlyMemory<byte> _extensions;
    private readonly ReadOnlyMemory<byte> _algEnc;
    private readonly X509Limits _limits;
    private ExtensionCollection? _extensionList;
    private AlgorithmIdentifier? _alg;

    private OcspBasicResponse(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        _limits = limits;
        Encoded = encoded;
        try
        {
            var top = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader basic = top.ReadSequence();
            top.ThrowIfNotEmpty();
            ReadOnlySpan<byte> tbsEnc = basic.ReadEncodedValue();
            TbsResponseData = X509Read.Slice(encoded, tbsEnc);
            _algEnc = X509Read.Slice(encoded, basic.ReadEncodedValue());
            Signature = X509Read.Slice(encoded, basic.ReadBitString(out int unused));
            SignatureUnusedBits = unused;
            Certificates = OcspRead.Certificates(ref basic, encoded, limits, 0);
            basic.ThrowIfNotEmpty();

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
                    throw new X509ParseException("BasicOCSPResponse", X509Error.UnsupportedVersion, $"version {v + 1} is not 1");
                }
            }

            Asn1Tag tag = tbs.PeekTag();
            if (tag == Asn1Tag.Context(1))
            {
                Asn1Reader w = tbs.ReadSequence(Asn1Tag.Context(1, true));
                ReadOnlySpan<byte> name = w.ReadEncodedValue();
                w.ThrowIfNotEmpty();
                DistinguishedName.Validate(name, limits);
                ResponderId = new OcspResponderId(DistinguishedName.Parse(X509Read.Slice(encoded, name), limits));
            }
            else if (tag == Asn1Tag.Context(2))
            {
                Asn1Reader w = tbs.ReadSequence(Asn1Tag.Context(2, true));
                ResponderId = new OcspResponderId(null, X509Read.Slice(encoded, w.ReadOctetString()));
                w.ThrowIfNotEmpty();
            }
            else
            {
                throw X509Read.Bad("BasicOCSPResponse", "the responder is neither byName nor byKey");
            }

            ProducedAt = tbs.ReadGeneralizedTime();
            Asn1Reader list = tbs.ReadSequence();
            var responses = new List<OcspSingleResponse>();
            while (list.HasData)
            {
                if (responses.Count >= limits.MaxListEntries)
                {
                    throw X509Read.Limit("BasicOCSPResponse", "too many responses");
                }

                responses.Add(ReadSingle(ref list, encoded, limits));
            }

            Responses = responses;
            _extensions = OcspRead.Extensions(ref tbs, encoded, limits, 1, "BasicOCSPResponse");
            tbs.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("BasicOCSPResponse", e);
        }
    }

    private static OcspSingleResponse ReadSingle(ref Asn1Reader list, ReadOnlyMemory<byte> root, X509Limits limits)
    {
        Asn1Reader one = list.ReadSequence();
        OcspCertId id = OcspCertId.Read(ref one, root);
        Asn1Tag t = one.PeekTag();
        OcspCertStatus status;
        DateTimeOffset? revoked = null;
        RevocationReason? reason = null;
        if (t == Asn1Tag.Context(0))
        {
            one.ReadNull(Asn1Tag.Context(0));
            status = OcspCertStatus.Good;
        }
        else if (t == Asn1Tag.Context(1))
        {
            Asn1Reader info = one.ReadSequence(Asn1Tag.Context(1, true));
            status = OcspCertStatus.Revoked;
            revoked = info.ReadGeneralizedTime();
            if (info.TryPeekTag(out Asn1Tag rt) && rt == Asn1Tag.Context(0))
            {
                Asn1Reader w = info.ReadSequence(Asn1Tag.Context(0, true));
                int code = w.ReadEnumerated();
                w.ThrowIfNotEmpty();
                reason = Enum.IsDefined((RevocationReason)code) ? (RevocationReason)code : throw X509Read.Invalid("SingleResponse", "unknown reason code " + code);
            }

            info.ThrowIfNotEmpty();
        }
        else if (t == Asn1Tag.Context(2))
        {
            one.ReadNull(Asn1Tag.Context(2));
            status = OcspCertStatus.Unknown;
        }
        else
        {
            throw X509Read.Bad("SingleResponse", "the status is not good, revoked or unknown");
        }

        DateTimeOffset thisUpdate = one.ReadGeneralizedTime();
        DateTimeOffset? next = null;
        if (one.TryPeekTag(out t) && t == Asn1Tag.Context(0))
        {
            Asn1Reader w = one.ReadSequence(Asn1Tag.Context(0, true));
            next = w.ReadGeneralizedTime();
            w.ThrowIfNotEmpty();
        }

        ReadOnlyMemory<byte> ext = OcspRead.Extensions(ref one, root, limits, 1, "SingleResponse");
        one.ThrowIfNotEmpty();
        return new OcspSingleResponse(id, status, revoked, reason, thisUpdate, next, ext, limits);
    }

    /// <summary>The whole basic response exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The <c>tbsResponseData</c> element exactly as received: the octets the signature covers.</summary>
    public ReadOnlyMemory<byte> TbsResponseData { get; }

    /// <summary>The version: 1.</summary>
    public int Version { get; }

    /// <summary>Who the responder says it is.</summary>
    public OcspResponderId ResponderId { get; } = null!;

    /// <summary>When the responder produced this response.</summary>
    public DateTimeOffset ProducedAt { get; }

    /// <summary>The answers, one per certificate asked about.</summary>
    public IReadOnlyList<OcspSingleResponse> Responses { get; } = [];

    /// <summary>The response extensions, possibly empty.</summary>
    public ExtensionCollection Extensions => _extensionList ??= ExtensionCollection.Decode(_extensions, _limits, "BasicOCSPResponse");

    /// <summary>The nonce echoed from the request, or null.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public ReadOnlyMemory<byte>? Nonce => Extensions.Get<OcspNonce>()?.Nonce;

    /// <summary>The signature algorithm.</summary>
    public AlgorithmIdentifier SignatureAlgorithm => _alg ??= AlgorithmIdentifier.Parse(_algEnc);

    /// <summary>The signature value (the BIT STRING content).</summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>Unused bits of the signature BIT STRING as received.</summary>
    public int SignatureUnusedBits { get; }

    /// <summary>The certificates the responder sent (typically its own signing certificate), in encoded order.</summary>
    public IReadOnlyList<Certificate> Certificates { get; }

    /// <summary>Checks the signature with the responder's public key over the received <c>tbsResponseData</c> octets.</summary>
    /// <remarks>Whether that key may sign for the certificate's issuer is path validation (RFC 6960 §4.2.2.2).</remarks>
    public SignatureVerification VerifySignature(PublicKeyInfo responderKey)
    {
        ArgumentNullException.ThrowIfNull(responderKey);
        if (SignatureUnusedBits != 0)
        {
            return new(SignatureStatus.Invalid, string.Empty, "The signature BIT STRING has unused bits.", "RFC 6960 §4.2.1");
        }

        try
        {
            return responderKey.VerifySignature(SignatureAlgorithm, TbsResponseData.Span, Signature.Span);
        }
        catch (X509ParseException e)
        {
            return new(SignatureStatus.Malformed, string.Empty, e.Message, "RFC 6960 §4.2.1");
        }
    }

    /// <summary>Reads a basic response.</summary>
    /// <exception cref="X509ParseException">The octets are not a BasicOCSPResponse.</exception>
    public static OcspBasicResponse Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, X509Limits.Default);

    /// <summary>Reads a basic response with the given limits.</summary>
    public static OcspBasicResponse Parse(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxEncodedSize)
        {
            throw X509Read.Limit("BasicOCSPResponse", $"{encoded.Length} octets exceed the limit of {limits.MaxEncodedSize}.");
        }

        return new OcspBasicResponse(encoded, limits);
    }

    /// <inheritdoc/>
    public bool Equals(OcspBasicResponse? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as OcspBasicResponse);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }
}

/// <summary>An <c>OCSPResponse</c> (RFC 6960 §4.2.1): a status and, when successful, response bytes (normally a basic response).</summary>
public sealed class OcspResponse : IEquatable<OcspResponse>
{
    private readonly X509Limits _limits;
    private OcspBasicResponse? _basic;

    private OcspResponse(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        _limits = limits;
        Encoded = encoded;
        try
        {
            var top = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader resp = top.ReadSequence();
            top.ThrowIfNotEmpty();
            int status = resp.ReadEnumerated();
            if (!Enum.IsDefined((OcspResponseStatus)status))
            {
                throw X509Read.Invalid("OCSPResponse", "unknown response status " + status);
            }

            Status = (OcspResponseStatus)status;
            ResponseType = string.Empty;
            if (resp.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(0))
            {
                Asn1Reader w = resp.ReadSequence(Asn1Tag.Context(0, true));
                Asn1Reader bytes = w.ReadSequence();
                w.ThrowIfNotEmpty();
                ResponseType = bytes.ReadObjectIdentifier();
                Response = X509Read.Slice(encoded, bytes.ReadOctetString());
                bytes.ThrowIfNotEmpty();
            }

            resp.ThrowIfNotEmpty();
            // RFC 6960 §4.2.1: response bytes accompany a successful status and no other.
            if ((Status == OcspResponseStatus.Successful) != !Response.IsEmpty)
            {
                throw X509Read.Bad("OCSPResponse", Status == OcspResponseStatus.Successful ? "a successful response without response bytes" : "response bytes with an unsuccessful status");
            }
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("OCSPResponse", e);
        }
    }

    /// <summary>The whole response exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The status code.</summary>
    public OcspResponseStatus Status { get; }

    /// <summary>The identifier of the response bytes' type (<see cref="KnownOids.OcspBasic"/> for the basic response), empty without response bytes.</summary>
    public string ResponseType { get; }

    /// <summary>The content of the response OCTET STRING, empty for an unsuccessful status.</summary>
    public ReadOnlyMemory<byte> Response { get; }

    /// <summary>The basic response, or null when there are no response bytes or they are of another type.</summary>
    /// <exception cref="X509ParseException">The response bytes are not a well-formed BasicOCSPResponse.</exception>
    public OcspBasicResponse? BasicResponse =>
        ResponseType == KnownOids.OcspBasic && !Response.IsEmpty ? _basic ??= OcspBasicResponse.Parse(Response, _limits) : null;

    /// <summary>Reads a response with the default limits.</summary>
    /// <exception cref="X509ParseException">The octets are not an OCSP response.</exception>
    public static OcspResponse Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, X509Limits.Default);

    /// <summary>Reads a response with the given limits.</summary>
    public static OcspResponse Parse(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxEncodedSize)
        {
            throw X509Read.Limit("OCSPResponse", $"{encoded.Length} octets exceed the limit of {limits.MaxEncodedSize}.");
        }

        return new OcspResponse(encoded, limits);
    }

    /// <summary>Reads a response, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out OcspResponse? response)
    {
        try
        {
            response = Parse(encoded);
            return true;
        }
        catch (X509ParseException)
        {
            response = null;
            return false;
        }
    }

    /// <inheritdoc/>
    public bool Equals(OcspResponse? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as OcspResponse);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }
}

/// <summary>The answer for one certificate in a response being built.</summary>
/// <param name="CertId">The certificate the answer is about.</param>
/// <param name="Status">good, revoked or unknown.</param>
/// <param name="ThisUpdate">The time the status is known correct at.</param>
/// <param name="NextUpdate">When newer information is due, or null.</param>
/// <param name="RevocationTime">When the certificate was revoked (required for revoked).</param>
/// <param name="Reason">The revocation reason, or null.</param>
/// <param name="Extensions">Single-response extensions, or null.</param>
public sealed record OcspSingleResponseInfo(
    OcspCertId CertId,
    OcspCertStatus Status,
    DateTimeOffset ThisUpdate,
    DateTimeOffset? NextUpdate = null,
    DateTimeOffset? RevocationTime = null,
    RevocationReason? Reason = null,
    IReadOnlyList<Extension>? Extensions = null);

/// <summary>What goes into a basic OCSP response being built.</summary>
public sealed class OcspResponseOptions
{
    /// <summary>The responder's identity as it appears in the response.</summary>
    public required OcspResponderId Responder { get; init; }

    /// <summary>When the response is produced.</summary>
    public required DateTimeOffset ProducedAt { get; init; }

    /// <summary>The answers.</summary>
    public required IReadOnlyList<OcspSingleResponseInfo> Responses { get; init; }

    /// <summary>The request's nonce to echo, or empty.</summary>
    public ReadOnlyMemory<byte> Nonce { get; init; }

    /// <summary>Certificates to send with the response (usually the responder's signing certificate).</summary>
    public IReadOnlyList<Certificate> Certificates { get; init; } = [];

    /// <summary>Further response extensions.</summary>
    public IReadOnlyList<Extension> Extensions { get; init; } = [];
}

/// <summary>Creates OCSP responses (the message layer; hosting and policy are the caller's).</summary>
public static class OcspResponseBuilder
{
    /// <summary>Creates a successful response holding a signed basic response.</summary>
    /// <exception cref="ArgumentException">A revoked answer has no revocation time.</exception>
    public static OcspResponse CreateSuccessful(OcspResponseOptions options, X509Signer signer)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signer);
        var exts = new List<Extension>(options.Extensions);
        if (!options.Nonce.IsEmpty)
        {
            exts.Add(Extension.Create(new OcspNonce(options.Nonce), false));
        }

        var singles = new List<byte[]>();
        foreach (OcspSingleResponseInfo r in options.Responses)
        {
            byte[] status;
            switch (r.Status)
            {
                case OcspCertStatus.Good:
                    status = [0x80, 0];
                    break;
                case OcspCertStatus.Unknown:
                    status = [0x82, 0];
                    break;
                default:
                    if (r.RevocationTime is not DateTimeOffset when)
                    {
                        throw new ArgumentException("A revoked answer needs a revocation time.", nameof(options));
                    }

                    status = DerWriter.Context(1, DerWriter.GeneralizedTime(when), r.Reason is RevocationReason code ? DerWriter.Context(0, DerWriter.Tlv(0x0A, [(byte)code])) : []);
                    break;
            }

            singles.Add(DerWriter.Sequence(
                r.CertId.Encoded.ToArray(),
                status,
                DerWriter.GeneralizedTime(r.ThisUpdate),
                r.NextUpdate is DateTimeOffset next ? DerWriter.Context(0, DerWriter.GeneralizedTime(next)) : [],
                r.Extensions is { Count: > 0 } ? DerWriter.Context(1, BuildHelpers.Extensions(r.Extensions)) : []));
        }

        byte[] tbs = DerWriter.Sequence(
            options.Responder.Write(),
            DerWriter.GeneralizedTime(options.ProducedAt),
            DerWriter.Sequence([.. singles]),
            exts.Count > 0 ? DerWriter.Context(1, BuildHelpers.Extensions(exts)) : []);
        byte[] sig = signer.Sign(tbs);
        byte[] basic = DerWriter.Sequence(
            tbs,
            signer.SignatureAlgorithm.Encoded.ToArray(),
            X509Signer.BitString(sig),
            options.Certificates.Count > 0 ? DerWriter.Context(0, DerWriter.Sequence([.. options.Certificates.Select(c => c.Encoded.ToArray())])) : []);
        byte[] bytes = DerWriter.Sequence(DerWriter.Oid(KnownOids.OcspBasic), DerWriter.OctetString(basic));
        return OcspResponse.Parse(new ReadOnlyMemory<byte>(DerWriter.Sequence(DerWriter.Tlv(0x0A, [0]), DerWriter.Context(0, bytes))));
    }

    /// <summary>Creates a response that carries only an error status.</summary>
    /// <exception cref="ArgumentException">The status is <see cref="OcspResponseStatus.Successful"/>.</exception>
    public static OcspResponse CreateError(OcspResponseStatus status)
    {
        if (status == OcspResponseStatus.Successful)
        {
            throw new ArgumentException("A successful response has response bytes; use CreateSuccessful.", nameof(status));
        }

        return OcspResponse.Parse(new ReadOnlyMemory<byte>(DerWriter.Sequence(DerWriter.Tlv(0x0A, [(byte)status]))));
    }
}
