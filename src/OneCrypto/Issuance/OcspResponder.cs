using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Issuance;

/// <summary>What a revocation status source knows about one certificate, and for how long the answer holds (RFC 6960 §4.2.2.1).</summary>
/// <param name="Status">good, revoked or unknown.</param>
/// <param name="ThisUpdate">The time the status is known to be correct at.</param>
/// <param name="NextUpdate">When newer information will be available, or null for "always" (RFC 6960 §2.4). A response whose nextUpdate has passed is not served.</param>
/// <param name="RevocationTime">When the certificate was revoked (required for revoked).</param>
/// <param name="Reason">The reason, or null for none.</param>
public sealed record RevocationStatus(OcspCertStatus Status, DateTimeOffset ThisUpdate, DateTimeOffset? NextUpdate = null, DateTimeOffset? RevocationTime = null, RevocationReason? Reason = null)
{
    /// <summary>A "good" status.</summary>
    public static RevocationStatus Good(DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate = null) => new(OcspCertStatus.Good, thisUpdate, nextUpdate);

    /// <summary>A "revoked" status.</summary>
    public static RevocationStatus Revoked(DateTimeOffset revoked, RevocationReason? reason, DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate = null) =>
        new(OcspCertStatus.Revoked, thisUpdate, nextUpdate, revoked, reason);

    /// <summary>An "unknown" status: the source does not know the certificate.</summary>
    public static RevocationStatus Unknown(DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate = null) => new(OcspCertStatus.Unknown, thisUpdate, nextUpdate);
}

/// <summary>
/// Where an OCSP responder, a CRL publisher or a validator gets revocation facts from: a database, a CRL, a CA's issued-certificate log. The library asks and never
/// stores; the host decides what "good" means (usually "issued and not revoked").
/// </summary>
public interface IRevocationStatusSource
{
    /// <summary>The status of the certificate <paramref name="id"/> names, or null when the source does not know it (answered as unknown). The issuer hashes in the id have already been matched to the responder's CA.</summary>
    /// <param name="id">The certificate asked about.</param>
    /// <param name="now">The time of the request, for sources that compute thisUpdate and nextUpdate.</param>
    RevocationStatus? Lookup(OcspCertId id, DateTimeOffset now);
}

/// <summary>A small in-memory <see cref="IRevocationStatusSource"/> for a development CA and for tests. Serial numbers not set are unknown.</summary>
public sealed class InMemoryRevocationSource : IRevocationStatusSource
{
    private readonly Dictionary<string, RevocationStatus> _entries = [];
    private readonly TimeSpan _window;

    /// <summary>Creates a source whose answers hold for <paramref name="window"/> after the request (thisUpdate = the request time, nextUpdate = that plus the window).</summary>
    public InMemoryRevocationSource(TimeSpan window)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);
        _window = window;
    }

    private static string Key(ReadOnlySpan<byte> serial)
    {
        while (serial.Length > 1 && serial[0] == 0)
        {
            serial = serial[1..];
        }

        return Convert.ToHexString(serial);
    }

    /// <summary>Records the certificate with this serial number as issued and not revoked.</summary>
    public void SetGood(ReadOnlySpan<byte> serial)
    {
        lock (_entries)
        {
            _entries[Key(serial)] = new RevocationStatus(OcspCertStatus.Good, default);
        }
    }

    /// <summary>Records the certificate with this serial number as revoked.</summary>
    public void SetRevoked(ReadOnlySpan<byte> serial, DateTimeOffset revoked, RevocationReason? reason = null)
    {
        lock (_entries)
        {
            _entries[Key(serial)] = new RevocationStatus(OcspCertStatus.Revoked, default, null, revoked, reason);
        }
    }

    /// <inheritdoc/>
    public RevocationStatus? Lookup(OcspCertId id, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(id);
        RevocationStatus? e;
        lock (_entries)
        {
            _entries.TryGetValue(Key(id.SerialNumber.Span), out e);
        }

        return e is null ? null : e with { ThisUpdate = now, NextUpdate = now + _window };
    }
}

/// <summary>Responses signed ahead of time (RFC 5019 §2.2.2), looked up by certificate id. A responder serves one for a request without a nonce while it is current.</summary>
public interface IPreproducedOcspResponses
{
    /// <summary>The stored response for the certificate, or null. The responder checks that it covers the certificate and is current.</summary>
    OcspResponse? Find(OcspCertId id);
}

/// <summary>A simple in-memory store of preproduced responses.</summary>
public sealed class InMemoryPreproducedResponses : IPreproducedOcspResponses
{
    private readonly Dictionary<string, OcspResponse> _items = [];

    /// <summary>Stores <paramref name="response"/> for <paramref name="id"/>, replacing an older one.</summary>
    public void Set(OcspCertId id, OcspResponse response)
    {
        ArgumentNullException.ThrowIfNull(id);
        ArgumentNullException.ThrowIfNull(response);
        lock (_items)
        {
            _items[Convert.ToHexString(id.Encoded.Span)] = response;
        }
    }

    /// <inheritdoc/>
    public OcspResponse? Find(OcspCertId id)
    {
        ArgumentNullException.ThrowIfNull(id);
        lock (_items)
        {
            return _items.TryGetValue(Convert.ToHexString(id.Encoded.Span), out OcspResponse? r) ? r : null;
        }
    }
}

/// <summary>How the responder names itself in a response (RFC 6960 §4.2.2.3).</summary>
public enum OcspResponderIdKind
{
    /// <summary>byKey: the SHA-1 hash of the responder's public key bits. Shorter and survives a rename.</summary>
    ByKey,

    /// <summary>byName: the responder certificate's subject name.</summary>
    ByName,
}

/// <summary>Configuration of an <see cref="OcspResponder"/>.</summary>
public sealed class OcspResponderOptions
{
    /// <summary>The CA whose certificates the responder answers for.</summary>
    public required Certificate Issuer { get; init; }

    /// <summary>
    /// The certificate whose key signs responses: the <see cref="Issuer"/> itself (the CA answers directly), or a delegated responder certificate the CA issued with
    /// id-kp-OCSPSigning (RFC 6960 §4.2.2.2). Delegated certificates are included in every response.
    /// </summary>
    public required Certificate ResponderCertificate { get; init; }

    /// <summary>Signs the responses; its public key must be the responder certificate's.</summary>
    public required X509Signer Signer { get; init; }

    /// <summary>The signature scheme for two-phase signing (<see cref="OcspResponder.Prepare"/>). Defaults to the signer's own when it came from a key.</summary>
    public SignatureSpec? SignatureSpec { get; init; }

    /// <summary>Where the facts come from.</summary>
    public required IRevocationStatusSource Source { get; init; }

    /// <summary>How the responder names itself (default byKey).</summary>
    public OcspResponderIdKind ResponderId { get; init; } = OcspResponderIdKind.ByKey;

    /// <summary>Optional responses signed ahead of time.</summary>
    public IPreproducedOcspResponses? Preproduced { get; init; }

    /// <summary>The most certificate ids one request may ask about (default 16); more is answered as malformedRequest.</summary>
    public int MaxRequests { get; init; } = 16;

    /// <summary>True to answer <c>sigRequired</c> to an unsigned request (RFC 6960 §2.3).</summary>
    public bool RequireSignedRequests { get; init; }

    /// <summary>Decides whether the requestor may ask; false is answered as <c>unauthorized</c>. It is where a signed request's signature is checked (<see cref="OcspRequest.VerifySignature"/>) and the requestor is matched to the host's list. Null allows everyone.</summary>
    public Func<OcspRequest, bool>? AuthorizeRequest { get; init; }

    /// <summary>The crypto policy the responder holds itself to when signing (default <see cref="CryptoPolicy.Standard"/>).</summary>
    public CryptoPolicy Policy { get; init; } = CryptoPolicy.Standard;

    /// <summary>The limits applied to incoming requests (default 64 KiB).</summary>
    public X509Limits Limits { get; init; } = new X509Limits { MaxEncodedSize = 1 << 16 };
}

/// <summary>
/// The first half of an OCSP response made in two steps, or the error response that stands in for it. Sign <see cref="Signature"/> with the responder key anywhere, then
/// <see cref="Complete"/>. The state serialises, so the second step can run in another process.
/// </summary>
public sealed class PreparedOcspResponse
{
    private const string Purpose = "ocsp.response";
    private readonly List<byte[]> _certs;

    private PreparedOcspResponse(OcspResponse? immediate, PreparedSignature? signature, List<byte[]> certs)
    {
        Immediate = immediate;
        Signature = signature;
        _certs = certs;
    }

    /// <summary>The response to send as it is (an error status or a preproduced answer); null when a response is to be signed.</summary>
    public OcspResponse? Immediate { get; }

    /// <summary>What to sign; null when <see cref="Immediate"/> is set.</summary>
    public PreparedSignature? Signature { get; }

    internal static PreparedOcspResponse Ready(OcspResponse r) => new(r, null, []);

    internal static PreparedOcspResponse Pending(PreparedSignature s, List<byte[]> certs) => new(null, s, certs);

    /// <summary>Phase two: checks the signature against the responder's key and assembles the response.</summary>
    /// <exception cref="InvalidOperationException">There is nothing to complete: <see cref="Immediate"/> is the answer.</exception>
    /// <exception cref="InvalidSignatureException">The signature does not verify.</exception>
    public OcspResponse Complete(ReadOnlySpan<byte> signature)
    {
        if (Signature is null)
        {
            throw new InvalidOperationException("The response is already complete; send Immediate.");
        }

        byte[] sig = Signature.Complete(signature);
        byte[] basic = DerWriter.Sequence(
            Signature.Data.ToArray(),
            Signature.Spec.ToAlgorithmIdentifier(Signature.PublicKey).Encoded.ToArray(),
            X509Signer.BitString(sig),
            _certs.Count > 0 ? DerWriter.Context(0, DerWriter.Sequence([.. _certs])) : []);
        byte[] bytes = DerWriter.Sequence(DerWriter.Oid(KnownOids.OcspBasic), DerWriter.OctetString(basic));
        return OcspResponse.Parse(new ReadOnlyMemory<byte>(DerWriter.Sequence(DerWriter.Tlv(0x0A, [0]), DerWriter.Context(0, bytes))));
    }

    /// <summary>The serialised state: <c>SEQUENCE { version INTEGER 1, signature OCTET STRING (a PreparedSignature), certificates SEQUENCE OF Certificate }</c> (DER).</summary>
    /// <exception cref="InvalidOperationException">There is no state: <see cref="Immediate"/> is the answer.</exception>
    public byte[] Encode() => Signature is null
        ? throw new InvalidOperationException("The response is already complete; there is no state to keep.")
        : DerWriter.Sequence(DerWriter.SignedInteger(1), DerWriter.OctetString(Signature.Encode()), DerWriter.Sequence([.. _certs]));

    /// <summary>Reads a serialised state.</summary>
    /// <exception cref="FormatException">The octets are not a state this version understands.</exception>
    public static PreparedOcspResponse Decode(ReadOnlySpan<byte> encoded)
    {
        try
        {
            var r = new Asn1Reader(encoded, Asn1Rules.Der);
            Asn1Reader s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            if (s.ReadInt32() != 1)
            {
                throw new FormatException("The prepared response is of an unknown format version.");
            }

            PreparedSignature sig = PreparedSignature.Decode(s.ReadOctetString());
            if (sig.Purpose != Purpose)
            {
                throw new FormatException("The prepared signature is not for an OCSP response.");
            }

            Asn1Reader list = s.ReadSequence();
            var certs = new List<byte[]>();
            while (list.HasData)
            {
                if (certs.Count >= 64)
                {
                    throw new FormatException("Too many certificates in the prepared response.");
                }

                byte[] c = list.ReadEncodedValue().ToArray();
                _ = Certificate.Parse(c);
                certs.Add(c);
            }

            s.ThrowIfNotEmpty();
            return new PreparedOcspResponse(null, sig, certs);
        }
        catch (Exception e) when (e is Asn1ParseException or X509ParseException)
        {
            throw new FormatException("The prepared response is damaged: " + e.Message, e);
        }
    }
}

/// <summary>
/// An OCSP responder (RFC 6960) as a message handler: request octets in, a signed response out, with no network, no clock and no database of its own. The host owns
/// transport (HTTP POST or GET, RFC 6960 Appendix A), caching headers and the revocation source. Errors a client can cause are answered with the RFC's status codes
/// (<c>malformedRequest</c>, <c>sigRequired</c>, <c>unauthorized</c>, <c>tryLater</c>, <c>internalError</c>), never with an exception.
/// </summary>
public sealed class OcspResponder
{
    private readonly OcspResponderOptions _o;
    private readonly SignatureSpec? _spec;
    private readonly OcspResponderId _id;
    private readonly bool _delegated;

    /// <summary>Creates a responder.</summary>
    /// <exception cref="ArgumentException">The responder certificate is neither the issuer nor a certificate the issuer signed with id-kp-OCSPSigning (RFC 6960 §4.2.2.2), or the signer's key is not its key.</exception>
    public OcspResponder(OcspResponderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _o = options;
        Certificate resp = options.ResponderCertificate;
        if (!resp.PublicKey.Equals(options.Signer.PublicKey))
        {
            throw new ArgumentException("The signer's key is not the responder certificate's key.", nameof(options));
        }

        _delegated = !resp.Equals(options.Issuer);
        if (_delegated)
        {
            // RFC 6960 §4.2.2.2: a delegated responder is a certificate the CA issued itself, with id-kp-OCSPSigning.
            if (!resp.Issuer.Matches(options.Issuer.Subject) || !resp.VerifySignature(options.Issuer).IsValid)
            {
                throw new ArgumentException("The responder certificate was not issued by the CA it answers for.", nameof(options));
            }

            if (resp.ExtendedKeyUsage is not { } eku || !eku.Purposes.Contains(KnownOids.OcspSigning))
            {
                throw new ArgumentException("A delegated responder certificate needs the id-kp-OCSPSigning extended key usage (RFC 6960 §4.2.2.2).", nameof(options));
            }
        }

        _id = options.ResponderId == OcspResponderIdKind.ByName
            ? new OcspResponderId(resp.Subject)
            : new OcspResponderId(null, CryptographicOperations.HashData(HashAlgorithmName.SHA1, resp.PublicKey.KeyBits.Span));
        _spec = options.SignatureSpec ?? options.Signer.Spec;
    }

    /// <summary>Answers a request, signing with the configured signer.</summary>
    /// <param name="request">The request octets exactly as received (the body of a POST, or the decoded GET path).</param>
    /// <param name="now">The time of the request; it becomes <c>producedAt</c>. The responder reads no clock.</param>
    /// <returns>The response to send, with <c>Content-Type: application/ocsp-response</c>. Never throws for bad input.</returns>
    public OcspResponse Handle(ReadOnlyMemory<byte> request, DateTimeOffset now)
    {
        OcspResponseOptions? plan = Plan(request, now, out OcspResponse? immediate);
        if (plan is null)
        {
            return immediate!;
        }

        try
        {
            return OcspResponseBuilder.CreateSuccessful(plan, _o.Signer);
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException or AlgorithmNotSupportedException or ArgumentException or InvalidOperationException)
        {
            return OcspResponseBuilder.CreateError(OcspResponseStatus.InternalError);
        }
    }

    /// <summary>Phase one of answering a request in two steps. Returns a ready answer (an error, or a preproduced response) or the state to sign; the key may live anywhere.</summary>
    /// <exception cref="InvalidOperationException">No signature scheme is configured and the signer does not carry one.</exception>
    public PreparedOcspResponse Prepare(ReadOnlyMemory<byte> request, DateTimeOffset now)
    {
        SignatureSpec spec = _spec ?? throw new InvalidOperationException("Set OcspResponderOptions.SignatureSpec for two-phase signing.");
        OcspResponseOptions? plan = Plan(request, now, out OcspResponse? immediate);
        if (plan is null)
        {
            return PreparedOcspResponse.Ready(immediate!);
        }

        try
        {
            PreparedSignature p = X509TwoPhase.Prepare("ocsp.response", _o.ResponderCertificate.PublicKey, spec, _o.Policy, now, s => OcspResponseBuilder.CreateSuccessful(plan, s));
            return PreparedOcspResponse.Pending(p, [.. plan.Certificates.Select(static c => c.Encoded.ToArray())]);
        }
        catch (PolicyViolationException)
        {
            return PreparedOcspResponse.Ready(OcspResponseBuilder.CreateError(OcspResponseStatus.InternalError));
        }
    }

    /// <summary>
    /// Signs a response for the given certificates now, without a nonce, so it can be stored and served later (RFC 5019 §2.2.2). Store it with
    /// <see cref="InMemoryPreproducedResponses.Set"/> or your own <see cref="IPreproducedOcspResponses"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The source gave no usable answer, or the responder cannot sign.</exception>
    public OcspResponse Preproduce(IEnumerable<OcspCertId> ids, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(ids);
        var list = ids.ToList();
        OcspResponseOptions? plan = Answer(list, default, now, out OcspResponseStatus? error);
        if (plan is null)
        {
            throw new InvalidOperationException($"No response can be produced ({error}).");
        }

        return OcspResponseBuilder.CreateSuccessful(plan, _o.Signer);
    }

    private OcspResponseOptions? Plan(ReadOnlyMemory<byte> bytes, DateTimeOffset now, out OcspResponse? immediate)
    {
        immediate = null;
        OcspRequest request;
        try
        {
            request = OcspRequest.Parse(bytes, _o.Limits);
        }
        catch (X509ParseException)
        {
            immediate = OcspResponseBuilder.CreateError(OcspResponseStatus.MalformedRequest);
            return null;
        }

        if (request.Requests.Count == 0 || request.Requests.Count > _o.MaxRequests)
        {
            immediate = OcspResponseBuilder.CreateError(OcspResponseStatus.MalformedRequest);
            return null;
        }

        // RFC 8954 §2.1: a nonce is 1 to 32 octets; anything else is a malformed request.
        ReadOnlyMemory<byte> nonce = default;
        try
        {
            if (request.Nonce is { } n)
            {
                if (n.Length is 0 or > 32)
                {
                    immediate = OcspResponseBuilder.CreateError(OcspResponseStatus.MalformedRequest);
                    return null;
                }

                nonce = n;
            }
        }
        catch (X509ParseException)
        {
            immediate = OcspResponseBuilder.CreateError(OcspResponseStatus.MalformedRequest);
            return null;
        }

        if (_o.RequireSignedRequests && !request.IsSigned)
        {
            immediate = OcspResponseBuilder.CreateError(OcspResponseStatus.SigRequired);
            return null;
        }

        try
        {
            if (_o.AuthorizeRequest is { } allow && !allow(request))
            {
                immediate = OcspResponseBuilder.CreateError(OcspResponseStatus.Unauthorized);
                return null;
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            immediate = OcspResponseBuilder.CreateError(OcspResponseStatus.InternalError);
            return null;
        }

        // RFC 5019 §2.2.4: a request without a nonce can be answered from a response signed earlier.
        if (nonce.IsEmpty && request.Requests.Count == 1 && _o.Preproduced?.Find(request.Requests[0].CertId) is { } stored && IsServable(stored, request.Requests[0].CertId, now))
        {
            immediate = stored;
            return null;
        }

        OcspResponseOptions? plan = Answer([.. request.Requests.Select(static r => r.CertId)], nonce, now, out OcspResponseStatus? error);
        if (plan is null)
        {
            immediate = OcspResponseBuilder.CreateError(error!.Value);
        }

        return plan;
    }

    private bool IsServable(OcspResponse stored, OcspCertId id, DateTimeOffset now)
    {
        try
        {
            if (stored.Status != OcspResponseStatus.Successful || stored.BasicResponse is not { } basic)
            {
                return false;
            }

            OcspSingleResponse? s = basic.Responses.FirstOrDefault(r => r.CertId.Equals(id));
            return s is not null && s.ThisUpdate <= now && (s.NextUpdate is null || s.NextUpdate > now) && basic.VerifySignature(_o.ResponderCertificate.PublicKey).IsValid;
        }
        catch (X509ParseException)
        {
            return false;
        }
    }

    /// <summary>Looks every certificate up and builds the response contents, or says which error status to answer.</summary>
    private OcspResponseOptions? Answer(List<OcspCertId> ids, ReadOnlyMemory<byte> nonce, DateTimeOffset now, out OcspResponseStatus? error)
    {
        error = null;
        Certificate resp = _o.ResponderCertificate;
        if (now < resp.NotBefore || now > resp.NotAfter || !_o.Policy.CheckSignature(_o.Signer.SignatureAlgorithm, resp.PublicKey, CryptoUse.Sign, now).IsAllowed)
        {
            error = OcspResponseStatus.InternalError;
            return null;
        }

        var singles = new List<OcspSingleResponseInfo>();
        int served = 0;
        foreach (OcspCertId id in ids)
        {
            if (!ServesIssuerOf(id))
            {
                // RFC 6960 §2.2: unknown means the responder does not know the certificate; the CA is not one it answers for.
                singles.Add(new OcspSingleResponseInfo(id, OcspCertStatus.Unknown, now));
                continue;
            }

            served++;
            RevocationStatus? st;
            try
            {
                st = _o.Source.Lookup(id, now);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                error = OcspResponseStatus.InternalError;
                return null;
            }

            st ??= RevocationStatus.Unknown(now);
            if (st.NextUpdate is { } next && next <= now)
            {
                // A response that is already stale would mislead the client; ask it to come back (RFC 6960 §2.3, RFC 5019 §2.2.3).
                error = OcspResponseStatus.TryLater;
                return null;
            }

            if (st.ThisUpdate > now || (st.Status == OcspCertStatus.Revoked && st.RevocationTime is null))
            {
                error = OcspResponseStatus.InternalError;
                return null;
            }

            singles.Add(new OcspSingleResponseInfo(id, st.Status, st.ThisUpdate, st.NextUpdate, st.RevocationTime, st.Reason));
        }

        if (served == 0)
        {
            // RFC 6960 §2.3 and RFC 5019 §2.2.3: the responder is not authoritative for any certificate asked about.
            error = OcspResponseStatus.Unauthorized;
            return null;
        }

        return new OcspResponseOptions
        {
            Responder = _id,
            ProducedAt = now,
            Responses = singles,
            Nonce = nonce,
            Certificates = _delegated ? [resp] : [],
        };
    }

    /// <summary>True when the id's issuer name and key hashes are those of this responder's CA (RFC 6960 §4.1.1).</summary>
    private bool ServesIssuerOf(OcspCertId id)
    {
        if (!SignatureAlgorithms.TryHash(id.HashAlgorithm.Oid, out HashAlgorithmName hash) || hash.Name is not ("SHA1" or "SHA256" or "SHA384" or "SHA512"))
        {
            return false;
        }

        byte[] nameHash = CryptographicOperations.HashData(hash, _o.Issuer.Subject.Encoded.Span);
        byte[] keyHash = CryptographicOperations.HashData(hash, _o.Issuer.PublicKey.KeyBits.Span);
        return id.IssuerNameHash.Span.SequenceEqual(nameHash) && id.IssuerKeyHash.Span.SequenceEqual(keyHash);
    }
}
