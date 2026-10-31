using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// A SignedData signed in two steps. Phase one (<see cref="SignedData.Prepare"/> or <see cref="SignedData.PrepareStream"/>) builds everything
/// but the signature values and records what each signer must sign, as one <see cref="PreparedSignature"/> per signer (purpose
/// <c>cms.signerinfo</c>). The signatures are made anywhere (another process, a token, a remote service, days later) and phase two
/// (<see cref="Complete(IReadOnlyList{byte[]})"/>) checks each against the signer's public key before assembling the message, so a damaged,
/// swapped or wrong-key signature is refused and nothing is written from it.
/// </summary>
/// <remarks>
/// <para>The state serialises (<see cref="Encode"/>, <see cref="Decode"/>) as versioned DER (<c>docs/cms.md</c>). It holds the signed attributes
/// and, for attached content prepared from memory, the content itself: treat it like the document it covers. It never holds a private key.</para>
/// <para>For content prepared from a stream the state keeps only the digests. A detached message completes with <see cref="Complete(IReadOnlyList{byte[]})"/>;
/// an attached one with <see cref="CompleteStream"/>, which reads the content again and refuses to finish if it no longer hashes to what was signed.</para>
/// </remarks>
public sealed class PreparedSignedData
{
    /// <summary>The version of the serialised form this library writes and reads.</summary>
    public const int FormatVersion = 1;

    /// <summary>The purpose recorded in each signer's <see cref="PreparedSignature"/>.</summary>
    public const string SignerPurpose = "cms.signerinfo";

    private const string StatePurpose = "cms.signeddata";

    private readonly SignerState[] _signers;
    private readonly int _cmsVersion;
    private readonly byte[] _digestAlgorithms;
    private readonly string _contentType;
    private readonly byte[] _encapsulated;
    private readonly bool _contentRetained;
    private readonly bool _detached;
    private readonly byte[][] _certificateParts;
    private readonly SortedDictionary<string, byte[]> _contentDigests;

    private sealed record SignerState(PreparedSignature Prepared, Certificate Certificate, CmsIdentifierKind Identifier, string DigestOid, bool HasAttributes, byte[]? UnsignedSet);

    private PreparedSignedData(SignerState[] signers, int cmsVersion, byte[] digestAlgorithms, string contentType, byte[] encapsulated, bool contentRetained, bool detached, byte[][] certificateParts, SortedDictionary<string, byte[]> contentDigests)
    {
        _signers = signers;
        _cmsVersion = cmsVersion;
        _digestAlgorithms = digestAlgorithms;
        _contentType = contentType;
        _encapsulated = encapsulated;
        _contentRetained = contentRetained;
        _detached = detached;
        _certificateParts = certificateParts;
        _contentDigests = contentDigests;
    }

    /// <summary>The first-phase state of each signer, in signer order. Sign <see cref="PreparedSignature.ToSign"/> of each, then complete.</summary>
    public IReadOnlyList<PreparedSignature> Signatures => _signers.Select(static s => s.Prepared).ToArray();

    /// <summary>True when the message will carry its content (the content was prepared from memory, or <see cref="CompleteStream"/> writes it).</summary>
    public bool IsAttached => !_detached;

    internal static PreparedSignedData Create(IReadOnlyList<SignedData.SignerPlan> plans, SignedDataOptions options, DateTimeOffset at, Func<SignedData.SignerPlan, byte[]> digestOf,
        ReadOnlySpan<byte> content, bool retained, SortedDictionary<string, byte[]> digests)
    {
        CryptoPolicy policy = options.Policy ?? CryptoPolicy.Standard;
        var states = new List<SignerState>();
        foreach (SignedData.SignerPlan p in plans)
        {
            if (p.Scheme is null)
            {
                throw new ArgumentException("Two-phase signing needs a signature spec: give the signer a Key or a SignatureSpec, not a bare delegate.");
            }

            if (!p.PublicKey.Equals(p.Spec.Certificate.PublicKey))
            {
                throw new ArgumentException("The signer's key is not the key in the signer's certificate.");
            }

            SignedData.SignerPlan.Parts parts = p.Prepare(options.ContentType, digestOf(p), content, countersignature: false);
            PreparedSignature prepared = PreparedSignature.Prepare(p.PublicKey, p.Scheme, parts.Data, policy, at, SignerPurpose);
            byte[]? unsignedSet = p.Spec.UnsignedAttributes.Count > 0 ? CmsAttributeEntry.EncodeSet(p.Spec.UnsignedAttributes) : null;
            states.Add(new SignerState(prepared, p.Spec.Certificate, p.Spec.Identifier, p.DigestOid, parts.AttributeSet is not null, unsignedSet));
        }

        var planList = plans.ToList();
        byte[] encapsulated = DerWriter.Sequence(DerWriter.Oid(options.ContentType), options.Detached || !retained ? [] : DerWriter.Context(0, DerWriter.OctetString(content)));
        return new PreparedSignedData([.. states], SignedData.VersionOf(options, planList), SignedData.DigestAlgorithmSet(planList), options.ContentType, encapsulated, retained,
            options.Detached, [.. SignedData.CertificateParts(options, planList)], digests);
    }

    /// <summary>
    /// Phase two: checks each signature against its signer's public key and assembles the message (definite-length DER).
    /// </summary>
    /// <param name="signatures">One signature per signer, in signer order, in the encoding of the signer's <see cref="PreparedSignature.Spec"/>.</param>
    /// <exception cref="InvalidSignatureException">A signature does not verify against the key it was prepared for.</exception>
    /// <exception cref="ArgumentException">The number of signatures differs from the number of signers.</exception>
    /// <exception cref="InvalidOperationException">The message is attached but its content was prepared from a stream: use <see cref="CompleteStream"/>.</exception>
    public SignedData Complete(IReadOnlyList<byte[]> signatures)
    {
        if (!_detached && !_contentRetained)
        {
            throw new InvalidOperationException("The content was prepared from a stream and is not held here: use CompleteStream to write the attached message.");
        }

        byte[] body = Assemble(Infos(signatures), _encapsulated);
        return SignedData.Parse(DerWriter.Sequence(DerWriter.Oid(CmsOids.SignedData), DerWriter.Context(0, body)));
    }

    /// <summary>Phase two for a single signer.</summary>
    public SignedData Complete(ReadOnlySpan<byte> signature) => Complete([signature.ToArray()]);

    /// <summary>
    /// Phase two for attached content prepared from a stream: checks the signatures, then writes the message to <paramref name="output"/> as
    /// indefinite-length BER in constant memory, copying <paramref name="content"/> in segments and hashing it as it goes. When the content no longer
    /// hashes to what was signed this throws at the end; <b>discard the output then</b>.
    /// </summary>
    /// <param name="signatures">One signature per signer.</param>
    /// <param name="content">The same content that was prepared, read to its end.</param>
    /// <param name="output">Where the message goes; it stays open.</param>
    /// <exception cref="InvalidSignatureException">A signature does not verify.</exception>
    /// <exception cref="CryptographicException">The content differs from the prepared content.</exception>
    public void CompleteStream(IReadOnlyList<byte[]> signatures, Stream content, Stream output)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(output);
        if (_detached || _contentRetained)
        {
            throw new InvalidOperationException("This message does not stream its content: use Complete.");
        }

        List<byte[]> infos = Infos(signatures);
        using var digests = new SignedData.DigestSet(_contentDigests.Keys);
        var w = new BerStreamWriter(output);
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.Oid(CmsOids.SignedData));
        w.BeginIndefinite(Asn1Tag.Context(0, true));
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.SignedInteger(_cmsVersion));
        w.WriteEncodedValue(_digestAlgorithms);
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.Oid(_contentType));
        w.BeginIndefinite(Asn1Tag.Context(0, true));
        w.BeginIndefinite(new Asn1Tag(Asn1Tags.OctetString));
        byte[] buffer = new byte[CmsStream.Chunk];
        int n;
        while ((n = content.Read(buffer, 0, buffer.Length)) > 0)
        {
            digests.Append(buffer.AsSpan(0, n));
            w.WriteDefinite(new Asn1Tag(Asn1Tags.OctetString), buffer.AsSpan(0, n));
        }

        w.End();
        w.End();
        w.End();
        foreach (byte[] part in _certificateParts)
        {
            w.WriteEncodedValue(part);
        }

        w.WriteEncodedValue(DerWriter.Set([.. infos]));
        w.End();
        w.End();
        w.End();
        output.Flush();

        // The signatures cover digests taken in phase one; content that changed since would give a message that fails verification.
        Dictionary<string, byte[]> now = digests.Finish();
        foreach (KeyValuePair<string, byte[]> expected in _contentDigests)
        {
            if (!now.TryGetValue(expected.Key, out byte[]? actual) || !CryptographicOperations.FixedTimeEquals(actual, expected.Value))
            {
                throw new CryptographicException("The content differs from the content that was prepared for signing; discard the output.");
            }
        }
    }

    private List<byte[]> Infos(IReadOnlyList<byte[]> signatures)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        if (signatures.Count != _signers.Length)
        {
            throw new ArgumentException($"The message has {_signers.Length} signer(s); {signatures.Count} signature(s) were given.", nameof(signatures));
        }

        var infos = new List<byte[]>();
        for (int i = 0; i < _signers.Length; i++)
        {
            SignerState s = _signers[i];
            byte[] sig = s.Prepared.Complete(signatures[i]);
            var spec = new CmsSignerSpec { Certificate = s.Certificate, SignatureSpec = s.Prepared.Spec, Identifier = s.Identifier, DigestAlgorithm = s.DigestOid };
            var plan = SignedData.SignerPlan.Restore(spec, s.DigestOid, s.Prepared, s.UnsignedSet);
            infos.Add(plan.Finish(new SignedData.SignerPlan.Parts(s.HasAttributes ? s.Prepared.Data.ToArray() : null, s.Prepared.Data.ToArray()), sig));
        }

        return infos;
    }

    private byte[] Assemble(List<byte[]> infos, byte[] encapsulated)
    {
        var parts = new List<byte[]> { DerWriter.SignedInteger(_cmsVersion), _digestAlgorithms, encapsulated };
        parts.AddRange(_certificateParts);
        parts.Add(DerWriter.Set([.. infos]));
        return DerWriter.Sequence([.. parts]);
    }

    /// <summary>
    /// The serialised state: <c>SEQUENCE { version, purpose UTF8String, contentType OID, detached BOOLEAN, retained BOOLEAN, cmsVersion, digestAlgorithms,
    /// encapsulated, certificateParts SEQUENCE OF OCTET STRING, contentDigests SEQUENCE OF SEQUENCE { OID, OCTET STRING }, signers SEQUENCE OF SEQUENCE
    /// { prepared, certificate, identifierKind, digestOid, hasAttributes, unsignedAttributes } }</c>, DER.
    /// </summary>
    public byte[] Encode() => DerWriter.Sequence(
        DerWriter.SignedInteger(FormatVersion),
        DerWriter.Utf8String(StatePurpose),
        DerWriter.Oid(_contentType),
        DerWriter.Boolean(_detached),
        DerWriter.Boolean(_contentRetained),
        DerWriter.SignedInteger(_cmsVersion),
        DerWriter.OctetString(_digestAlgorithms),
        DerWriter.OctetString(_encapsulated),
        DerWriter.Sequence([.. _certificateParts.Select(static p => DerWriter.OctetString(p))]),
        DerWriter.Sequence([.. _contentDigests.Select(static d => DerWriter.Sequence(DerWriter.Oid(d.Key), DerWriter.OctetString(d.Value)))]),
        DerWriter.Sequence([.. _signers.Select(static s => DerWriter.Sequence(
            DerWriter.OctetString(s.Prepared.Encode()),
            DerWriter.OctetString(s.Certificate.Encoded.Span),
            DerWriter.SignedInteger((int)s.Identifier),
            DerWriter.Oid(s.DigestOid),
            DerWriter.Boolean(s.HasAttributes),
            DerWriter.OctetString(s.UnsignedSet ?? [])))]));

    /// <summary>Reads a serialised state.</summary>
    /// <exception cref="FormatException">The octets are not a state this library version understands.</exception>
    public static PreparedSignedData Decode(ReadOnlySpan<byte> encoded) =>
        TryDecode(encoded, out PreparedSignedData? p, out string? error) ? p! : throw new FormatException(error);

    /// <summary>Reads a serialised state, returning false and the reason instead of throwing.</summary>
    public static bool TryDecode(ReadOnlySpan<byte> encoded, out PreparedSignedData? state, out string? error)
    {
        state = null;
        error = null;
        try
        {
            var r = new Asn1Reader(encoded, Asn1Rules.Der);
            Asn1Reader s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            int version = s.ReadInt32();
            if (version != FormatVersion)
            {
                error = $"The prepared SignedData is format version {version}; this library reads version {FormatVersion}.";
                return false;
            }

            if (s.ReadCharacterString(12) != StatePurpose)
            {
                error = "The state is not a prepared SignedData.";
                return false;
            }

            string contentType = s.ReadObjectIdentifier();
            bool detached = s.ReadBoolean();
            bool retained = s.ReadBoolean();
            int cmsVersion = s.ReadInt32();
            byte[] digestAlgs = s.ReadOctetStringBytes();
            byte[] encapsulated = s.ReadOctetStringBytes();
            var certParts = new List<byte[]>();
            Asn1Reader cp = s.ReadSequence();
            while (cp.HasData)
            {
                certParts.Add(cp.ReadOctetStringBytes());
            }

            var digests = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
            Asn1Reader dg = s.ReadSequence();
            while (dg.HasData)
            {
                Asn1Reader d = dg.ReadSequence();
                string digestOid = d.ReadObjectIdentifier();
                if (digests.Count > 0 && string.CompareOrdinal(digests.Keys.Max(), digestOid) >= 0)
                {
                    // One canonical encoding per state: the digests are written in ordinal order, so a state re-encodes to the octets it was read from.
                    error = "The digests of the prepared SignedData are not in order.";
                    return false;
                }

                digests[digestOid] = d.ReadOctetStringBytes();
            }

            var signers = new List<SignerState>();
            Asn1Reader sg = s.ReadSequence();
            while (sg.HasData)
            {
                Asn1Reader e = sg.ReadSequence();
                PreparedSignature p = PreparedSignature.Decode(e.ReadOctetStringBytes());
                Certificate cert = Certificate.Parse(e.ReadOctetStringBytes());
                int kind = e.ReadInt32();
                string digestOid = e.ReadObjectIdentifier();
                bool hasAttrs = e.ReadBoolean();
                byte[] unsignedSet = e.ReadOctetStringBytes();
                e.ThrowIfNotEmpty();
                if (p.Purpose != SignerPurpose || !Enum.IsDefined((CmsIdentifierKind)kind) || !p.PublicKey.Equals(cert.PublicKey) || !CmsDigest.IsSupported(digestOid))
                {
                    error = "A signer in the prepared SignedData is not valid.";
                    return false;
                }

                signers.Add(new SignerState(p, cert, (CmsIdentifierKind)kind, digestOid, hasAttrs, unsignedSet.Length == 0 ? null : unsignedSet));
            }

            s.ThrowIfNotEmpty();
            if (signers.Count == 0)
            {
                error = "The prepared SignedData has no signer.";
                return false;
            }

            state = new PreparedSignedData([.. signers], cmsVersion, digestAlgs, contentType, encapsulated, retained, detached, [.. certParts], digests);
            return true;
        }
        catch (Exception e) when (e is Asn1ParseException or X509ParseException or FormatException or ArgumentException)
        {
            error = "The prepared SignedData is damaged: " + e.Message;
            return false;
        }
    }
}

public sealed partial class SignedData
{
    /// <summary>
    /// Phase one of a two-signature-step SignedData for content in memory. Each signer needs a <see cref="CmsSignerSpec.Certificate"/> and either a key
    /// or a <see cref="CmsSignerSpec.SignatureSpec"/>; the key itself is not used here. The policy in <paramref name="options"/> (default Standard) decides
    /// whether the signature may be made.
    /// </summary>
    /// <param name="content">The content octets (kept in the state when the message is attached).</param>
    /// <param name="signers">One or more signers.</param>
    /// <param name="options">Choices, or null for an attached id-data message.</param>
    /// <param name="at">The moment of signing, for the policy and the state.</param>
    /// <exception cref="PolicyViolationException">The policy refuses a signer's algorithm or key.</exception>
    public static PreparedSignedData Prepare(ReadOnlySpan<byte> content, IReadOnlyList<CmsSignerSpec> signers, DateTimeOffset at, SignedDataOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(signers);
        options ??= new SignedDataOptions();
        List<SignerPlan> plans = [.. signers.Select(s => SignerPlan.For(s, options.Policy))];
        var digests = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (SignerPlan p in plans)
        {
            digests[p.DigestOid] = Digest(p.DigestOid, content);
        }

        return PreparedSignedData.Create(plans, options, at, p => digests[p.DigestOid], content, retained: true, digests);
    }

    /// <summary>
    /// Phase one for content read from a stream: the content is hashed in constant memory and only the digests are kept. Every signer must use signed
    /// attributes. Complete a detached message with <see cref="PreparedSignedData.Complete(IReadOnlyList{byte[]})"/> and an attached one with
    /// <see cref="PreparedSignedData.CompleteStream"/>.
    /// </summary>
    /// <param name="content">The content, read to its end.</param>
    /// <param name="signers">One or more signers.</param>
    /// <param name="at">The moment of signing, for the policy and the state.</param>
    /// <param name="options">Choices, or null for an attached id-data message.</param>
    public static PreparedSignedData PrepareStream(Stream content, IReadOnlyList<CmsSignerSpec> signers, DateTimeOffset at, SignedDataOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(signers);
        options ??= new SignedDataOptions();
        if (signers.Any(static s => !s.SignedAttributes))
        {
            throw new NotSupportedException("Streaming needs signed attributes: a signature over the bare content cannot be made without holding it.");
        }

        List<SignerPlan> plans = [.. signers.Select(s => SignerPlan.For(s, options.Policy))];
        using var set = new DigestSet(plans.Select(static p => p.DigestOid).Distinct());
        byte[] buffer = new byte[CmsStream.Chunk];
        int n;
        while ((n = content.Read(buffer, 0, buffer.Length)) > 0)
        {
            set.Append(buffer.AsSpan(0, n));
        }

        var digests = new SortedDictionary<string, byte[]>(set.Finish(), StringComparer.Ordinal);
        return PreparedSignedData.Create(plans, options, at, p => digests[p.DigestOid], default, retained: false, digests);
    }
}
