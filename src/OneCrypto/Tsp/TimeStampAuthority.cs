using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Tsp;

/// <summary>
/// Hands out the serial numbers of time-stamp tokens. Each number must be positive, at most 20 octets, and never reused by the authority (RFC 3161 §2.4.2:
/// the serial number is unique per authority). Where tokens are issued by several processes the implementation has to coordinate (a database sequence, a
/// block per process); the library cannot know.
/// </summary>
public interface ITimeStampSerialSource
{
    /// <summary>The next serial number as unsigned big-endian octets. Throwing is reported to the client as a <c>systemFailure</c>, never as a token.</summary>
    byte[] NextSerial();
}

/// <summary>A serial source of random 128-bit numbers. Collisions are negligible, but unlike a counter this does not prove uniqueness; use it for a single issuer that cannot persist a counter.</summary>
public sealed class RandomTimeStampSerialSource : ITimeStampSerialSource
{
    /// <inheritdoc/>
    public byte[] NextSerial()
    {
        byte[] b = RandomNumberGenerator.GetBytes(16);
        b[0] &= 0x7F;
        b[0] |= 0x01;
        return b;
    }
}

/// <summary>An in-memory counter serial source starting at a given number. It survives only as long as the process; persist the last value to continue after a restart.</summary>
public sealed class CounterTimeStampSerialSource : ITimeStampSerialSource
{
    private long _next;

    /// <summary>Creates a counter whose first serial number is <paramref name="start"/> (at least 1).</summary>
    public CounterTimeStampSerialSource(long start = 1)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(start, 1);
        _next = start - 1;
    }

    /// <inheritdoc/>
    public byte[] NextSerial()
    {
        long v = Interlocked.Increment(ref _next);
        byte[] b = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(b, v);
        int skip = 0;
        while (skip < 7 && b[skip] == 0)
        {
            skip++;
        }

        return b[skip..];
    }
}

/// <summary>Configuration of a <see cref="TimeStampAuthority"/>.</summary>
public sealed class TimeStampAuthorityOptions
{
    /// <summary>The authority's certificate. It must carry a critical extended key usage naming only id-kp-timeStamping (RFC 3161 §2.3).</summary>
    public required Certificate Certificate { get; init; }

    /// <summary>Signs the tokens. Its public key must be the certificate's. For two-phase signing in a process that has no private key, a delegate signer that is never called is enough.</summary>
    public required X509Signer Signer { get; init; }

    /// <summary>The signature scheme for two-phase signing (<see cref="TimeStampAuthority.Prepare"/>). Defaults to the signer's own when it came from a key.</summary>
    public SignatureSpec? SignatureSpec { get; init; }

    /// <summary>The policy OID written when the request names none (RFC 3161 §2.4.2).</summary>
    public required string DefaultPolicy { get; init; }

    /// <summary>The policies a request may ask for besides the default. A request for any other policy is refused with <c>unacceptedPolicy</c>.</summary>
    public IReadOnlyList<string> AcceptedPolicies { get; init; } = [];

    /// <summary>The imprint hashes accepted (default SHA-256, SHA-384, SHA-512). Anything else is refused with <c>badAlg</c>; SHA-1 is not on the default list.</summary>
    public IReadOnlyList<HashAlgorithmName> AcceptedHashes { get; init; } = [HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512];

    /// <summary>The accuracy to state in each token, or null to state none.</summary>
    public TimeStampAccuracy? Accuracy { get; init; }

    /// <summary>True to promise that tokens are ordered by genTime (RFC 3161 §2.4.2). Only set it when the host's clock and serial source make that true.</summary>
    public bool Ordering { get; init; }

    /// <summary>Fractional-second digits (0 to 6) written in genTime. Default 0 (whole seconds), which suits an accuracy of one second or more.</summary>
    public int GenTimeFractionDigits { get; init; }

    /// <summary>True (the default) to write the <c>tsa</c> field with the certificate's subject name.</summary>
    public bool IncludeTsaName { get; init; } = true;

    /// <summary>Certificates to add after the authority's own when the client asked for certificates (intermediates, usually). The root is better left out.</summary>
    public IReadOnlyList<Certificate> ChainCertificates { get; init; } = [];

    /// <summary>The crypto policy the authority holds itself to when signing (default <see cref="CryptoPolicy.Standard"/>).</summary>
    public CryptoPolicy Policy { get; init; } = CryptoPolicy.Standard;

    /// <summary>The limits applied to incoming requests.</summary>
    public TimeStampLimits Limits { get; init; } = TimeStampLimits.Default;
}

/// <summary>
/// The first half of a time-stamp token issued in two steps, or the refusal that stands in for it. <see cref="Signature"/> says what to sign; once the signature
/// exists anywhere, <see cref="Complete"/> checks it and returns the response. The state serialises (<see cref="Encode"/>), so the second step can run in another
/// process, later.
/// </summary>
public sealed class PreparedTimeStamp
{
    private const string Purpose = "tsp.token";
    private readonly byte[] _tstInfo;
    private readonly bool _certReq;
    private readonly List<byte[]> _certs;

    private PreparedTimeStamp(TimeStampResponse? rejection, PreparedSignature? signature, byte[] tstInfo, bool certReq, List<byte[]> certs)
    {
        Rejection = rejection;
        Signature = signature;
        _tstInfo = tstInfo;
        _certReq = certReq;
        _certs = certs;
    }

    /// <summary>The response to send when the request was refused; null when a token is to be signed.</summary>
    public TimeStampResponse? Rejection { get; }

    /// <summary>What to sign (see <see cref="PreparedSignature.ToSign"/>); null when the request was refused.</summary>
    public PreparedSignature? Signature { get; }

    /// <summary>The TSTInfo that will be stamped; empty when the request was refused.</summary>
    public ReadOnlyMemory<byte> TstInfoEncoded => _tstInfo;

    internal static PreparedTimeStamp Refused(TimeStampResponse r) => new(r, null, [], false, []);

    internal static PreparedTimeStamp Pending(PreparedSignature s, byte[] tstInfo, bool certReq, List<byte[]> certs) => new(null, s, tstInfo, certReq, certs);

    /// <summary>Phase two: checks the signature against the key the state was prepared for and returns the finished response.</summary>
    /// <exception cref="InvalidOperationException">The request was refused, so there is nothing to complete.</exception>
    /// <exception cref="InvalidSignatureException">The signature does not verify.</exception>
    public TimeStampResponse Complete(ReadOnlySpan<byte> signature)
    {
        if (Signature is null)
        {
            throw new InvalidOperationException("The request was refused; send Rejection instead.");
        }

        byte[] sig = Signature.Complete(signature);
        PublicKeyInfo key = Signature.PublicKey;
        AlgorithmIdentifier alg = Signature.Spec.ToAlgorithmIdentifier(key);
        byte[] expected = Signature.Data.ToArray();
        var replay = X509Signer.FromDelegate(alg, key, d => d.AsSpan().SequenceEqual(expected) ? sig : throw new InvalidOperationException("The token is not the one that was prepared."));
        var certs = _certs.Select(static c => Certificate.Parse(c)).ToList();
        byte[] token = TimeStampAuthority.BuildToken(certs[0], certs, _certReq, _tstInfo, replay);
        return TimeStampAuthority.Granted(token);
    }

    /// <summary>The serialised state: <c>SEQUENCE { version INTEGER 1, signature OCTET STRING (a PreparedSignature), tstInfo OCTET STRING, certReq BOOLEAN, certificates SEQUENCE OF Certificate }</c> (DER).</summary>
    /// <exception cref="InvalidOperationException">The request was refused; there is no state to keep.</exception>
    public byte[] Encode() => Signature is null
        ? throw new InvalidOperationException("The request was refused; there is no state to keep.")
        : DerWriter.Sequence(DerWriter.SignedInteger(1), DerWriter.OctetString(Signature.Encode()), DerWriter.OctetString(_tstInfo), DerWriter.Boolean(_certReq), DerWriter.Sequence([.. _certs]));

    /// <summary>Reads a serialised state.</summary>
    /// <exception cref="FormatException">The octets are not a state this version understands.</exception>
    public static PreparedTimeStamp Decode(ReadOnlySpan<byte> encoded)
    {
        try
        {
            var r = new Asn1Reader(encoded, Asn1Rules.Der);
            Asn1Reader s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            if (s.ReadInt32() != 1)
            {
                throw new FormatException("The prepared time-stamp is of an unknown format version.");
            }

            PreparedSignature sig = PreparedSignature.Decode(s.ReadOctetString());
            if (sig.Purpose != Purpose)
            {
                throw new FormatException("The prepared signature is not for a time-stamp token.");
            }

            byte[] tst = s.ReadOctetStringBytes();
            bool certReq = s.ReadBoolean();
            Asn1Reader list = s.ReadSequence();
            var certs = new List<byte[]>();
            while (list.HasData)
            {
                if (certs.Count >= 64)
                {
                    throw new FormatException("Too many certificates in the prepared time-stamp.");
                }

                certs.Add(list.ReadEncodedValue().ToArray());
            }

            s.ThrowIfNotEmpty();
            if (certs.Count == 0)
            {
                throw new FormatException("The prepared time-stamp has no certificate.");
            }

            _ = TstInfo.Parse(tst);
            _ = Certificate.Parse(certs[0]);
            return new PreparedTimeStamp(null, sig, tst, certReq, certs);
        }
        catch (Exception e) when (e is Asn1ParseException or X509ParseException or TimeStampParseException)
        {
            throw new FormatException("The prepared time-stamp is damaged: " + e.Message, e);
        }
    }
}

/// <summary>
/// An RFC 3161 time-stamp authority as a message handler: a request in, a response out, with no network, no clock and no storage of its own. The host reads the
/// bytes off its transport (HTTP <c>application/timestamp-query</c>, TCP, a queue), passes the current time, and sends back what the handler returns. A request it
/// cannot or will not serve is answered with a rejection status and <c>PKIFailureInfo</c> bits (RFC 3161 §2.4.2), never an exception.
/// </summary>
public sealed class TimeStampAuthority
{
    private readonly TimeStampAuthorityOptions _o;
    private readonly ITimeStampSerialSource _serials;
    private readonly HashSet<string> _hashOids;
    private readonly HashSet<string> _policies;
    private readonly SignatureSpec? _spec;

    /// <summary>Creates a handler.</summary>
    /// <param name="options">The certificate, key and policies.</param>
    /// <param name="serials">Where serial numbers come from. The handler never makes its own.</param>
    /// <exception cref="ArgumentException">The certificate is not a time-stamping certificate (RFC 3161 §2.3), does not match the signer's key, or the options are inconsistent.</exception>
    public TimeStampAuthority(TimeStampAuthorityOptions options, ITimeStampSerialSource serials)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(serials);
        _o = options;
        _serials = serials;
        if (!options.Certificate.PublicKey.Equals(options.Signer.PublicKey))
        {
            throw new ArgumentException("The signer's key is not the certificate's key.", nameof(options));
        }

        // RFC 3161 §2.3: one critical extended key usage extension naming only id-kp-timeStamping.
        Extension? eku = options.Certificate.Extensions.Find(KnownOids.ExtendedKeyUsage);
        if (eku is null || !eku.Critical || ExtendedKeyUsage.Parse(eku.Value).Purposes is not [KnownOids.TimeStamping])
        {
            throw new ArgumentException("A time-stamping certificate needs a critical extended key usage extension that names only id-kp-timeStamping (RFC 3161 §2.3).", nameof(options));
        }

        if (options.GenTimeFractionDigits is < 0 or > 6)
        {
            throw new ArgumentException("GenTimeFractionDigits is 0 to 6.", nameof(options));
        }

        _hashOids = [];
        foreach (HashAlgorithmName h in options.AcceptedHashes)
        {
            _hashOids.Add(TimeStampRequest.ImprintOid(h) ?? throw new ArgumentException($"{h.Name} cannot be a time-stamp imprint hash.", nameof(options)));
        }

        _policies = [options.DefaultPolicy, .. options.AcceptedPolicies];
        _spec = options.SignatureSpec ?? options.Signer.Spec;
    }

    /// <summary>Answers a request with a response, signing with the configured signer.</summary>
    /// <param name="request">The request octets exactly as received.</param>
    /// <param name="now">The time to stamp. The handler reads no clock; the host decides what time it trusts.</param>
    /// <returns>A granted response with a token, or a rejection. It never throws for bad input or an unusable signer.</returns>
    public TimeStampResponse Handle(ReadOnlyMemory<byte> request, DateTimeOffset now)
    {
        PreparedTimeStamp? refusal = null;
        (TimeStampRequest? req, byte[]? tst) = Decide(request, now, out refusal);
        if (refusal is not null)
        {
            return refusal.Rejection!;
        }

        try
        {
            byte[] token = BuildToken(_o.Certificate, Chain(), req!.CertReq, tst!, _o.Signer);
            return Granted(token);
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException or AlgorithmNotSupportedException or ArgumentException or InvalidOperationException)
        {
            return Reject(TimeStampFailure.SystemFailure, "The authority could not sign the token.");
        }
    }

    /// <summary>
    /// Phase one of answering a request in two steps. Returns the refusal to send, or the state to sign; the key may live anywhere (a token, a remote service, another
    /// process). The signature scheme is <see cref="TimeStampAuthorityOptions.SignatureSpec"/>, or the signer's own.
    /// </summary>
    /// <exception cref="InvalidOperationException">No signature scheme is configured and the signer does not carry one.</exception>
    public PreparedTimeStamp Prepare(ReadOnlyMemory<byte> request, DateTimeOffset now)
    {
        SignatureSpec spec = _spec ?? throw new InvalidOperationException("Set TimeStampAuthorityOptions.SignatureSpec for two-phase signing.");
        (TimeStampRequest? req, byte[]? tst) = Decide(request, now, out PreparedTimeStamp? refusal);
        if (refusal is not null)
        {
            return refusal;
        }

        List<Certificate> chain = Chain();
        PreparedSignature prepared;
        try
        {
            prepared = X509TwoPhase.Prepare("tsp.token", _o.Certificate.PublicKey, spec, _o.Policy, now, s => BuildToken(_o.Certificate, chain, req!.CertReq, tst!, s));
        }
        catch (PolicyViolationException)
        {
            return PreparedTimeStamp.Refused(Reject(TimeStampFailure.SystemFailure, "The authority's signature algorithm is not allowed by its policy."));
        }

        return PreparedTimeStamp.Pending(prepared, tst!, req!.CertReq, [.. chain.Select(static c => c.Encoded.ToArray())]);
    }

    private List<Certificate> Chain() => [_o.Certificate, .. _o.ChainCertificates];

    /// <summary>Checks the request and builds the TSTInfo, or says why not (RFC 3161 §2.4.2, failure bits).</summary>
    private (TimeStampRequest?, byte[]?) Decide(ReadOnlyMemory<byte> request, DateTimeOffset now, out PreparedTimeStamp? refusal)
    {
        refusal = null;
        TimeStampRequest req;
        try
        {
            req = TimeStampRequest.Parse(request, _o.Limits);
        }
        catch (TimeStampParseException)
        {
            refusal = Refuse(TimeStampFailure.BadDataFormat, "The request is not a well-formed TimeStampReq.");
            return (null, null);
        }

        string hashOid = req.HashAlgorithm.Oid;
        if (!_hashOids.Contains(hashOid) || !TspRead.TryImprintHash(hashOid, out _, out int len))
        {
            refusal = Refuse(TimeStampFailure.BadAlg, "The hash algorithm of the message imprint is not accepted.");
            return (null, null);
        }

        if (req.MessageImprint.Length != len)
        {
            refusal = Refuse(TimeStampFailure.BadDataFormat, "The message imprint does not have the length of its hash algorithm.");
            return (null, null);
        }

        if (req.Policy is { } wanted && !_policies.Contains(wanted))
        {
            refusal = Refuse(TimeStampFailure.UnacceptedPolicy, "The requested policy is not supported.");
            return (null, null);
        }

        try
        {
            // A critical extension the handler does not understand must be refused; a non-critical one may be ignored (RFC 5280 §4.2 rule, applied here).
            if (req.Extensions.Any(static e => e.Critical))
            {
                refusal = Refuse(TimeStampFailure.UnacceptedExtension, "The request carries a critical extension this authority does not support.");
                return (null, null);
            }
        }
        catch (X509ParseException)
        {
            refusal = Refuse(TimeStampFailure.BadDataFormat, "The request extensions are malformed.");
            return (null, null);
        }

        if (now < _o.Certificate.NotBefore || now > _o.Certificate.NotAfter)
        {
            refusal = Refuse(TimeStampFailure.TimeNotAvailable, "The authority's certificate is not valid at the current time.");
            return (null, null);
        }

        if (!_o.Policy.CheckSignature(_o.Signer.SignatureAlgorithm, _o.Certificate.PublicKey, CryptoUse.Sign, now).IsAllowed)
        {
            refusal = Refuse(TimeStampFailure.SystemFailure, "The authority's signature algorithm is not allowed by its policy.");
            return (null, null);
        }

        byte[] serial;
        try
        {
            serial = _serials.NextSerial();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            refusal = Refuse(TimeStampFailure.SystemFailure, "No serial number is available.");
            return (null, null);
        }

        if (serial.Length is 0 or > 20 || serial.All(static b => b == 0))
        {
            refusal = Refuse(TimeStampFailure.SystemFailure, "The serial source returned an unusable number.");
            return (null, null);
        }

        GeneralName? tsa = _o.IncludeTsaName ? GeneralName.FromDirectoryName(_o.Certificate.Subject) : null;
        byte[] tst = TstInfo.Encode(req.Policy ?? _o.DefaultPolicy, req.HashAlgorithm, req.MessageImprint.Span, serial, now, _o.GenTimeFractionDigits, _o.Accuracy, _o.Ordering,
            req.HasNonce ? req.Nonce.Span : default, tsa);
        return (req, tst);
    }

    private static PreparedTimeStamp Refuse(TimeStampFailure failure, string text) => PreparedTimeStamp.Refused(Reject(failure, text));

    /// <summary>A rejection response (status 2) with the failure bits.</summary>
    internal static TimeStampResponse Reject(TimeStampFailure failure, string text) =>
        TimeStampResponse.Parse(DerWriter.Sequence(TimeStampResponse.EncodeStatus(TimeStampStatus.Rejection, failure, text)));

    internal static TimeStampResponse Granted(byte[] token) =>
        TimeStampResponse.Parse(DerWriter.Sequence(TimeStampResponse.EncodeStatus(TimeStampStatus.Granted, TimeStampFailure.None, null), token));

    /// <summary>The token: a SignedData over the TSTInfo with a signing-certificate-v2 attribute, no signing time (RFC 3161 §2.4.2, RFC 5816 §2).</summary>
    internal static byte[] BuildToken(Certificate signer, IReadOnlyList<Certificate> chain, bool certReq, byte[] tstInfo, X509Signer sign)
    {
        SignedData sd = SignedData.Create(tstInfo,
            [new CmsSignerSpec { Certificate = signer, Signer = sign, SigningCertificate = EssSigningCertificate.V2, SigningTime = null }],
            new SignedDataOptions
            {
                ContentType = CmsOids.TstInfo,
                IncludeSignerCertificates = certReq,
                Certificates = certReq ? [.. chain.Skip(1)] : [],
            });
        return sd.Encoded.ToArray();
    }
}
