using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto.Keys;

/// <summary>What the signer is handed in the first phase.</summary>
public enum SigningInput
{
    /// <summary>The digest of the data under the spec's hash (RSA, ECDSA). The data may stay home.</summary>
    Digest = 1,
    /// <summary>The data itself (EdDSA, ML-DSA, and any scheme where the signer hashes).</summary>
    Message = 2,
}

/// <summary>
/// The first half of a signature made in two steps. It records what must be signed, with which scheme and for which public key, and it serialises
/// (<see cref="Encode"/>) so the second step can run in another process, on another machine or days later. The second step
/// (<see cref="Complete"/>) takes a signature produced anywhere and accepts it only if it verifies against the recorded public key.
/// </summary>
/// <remarks>
/// <para>The encoding is DER, versioned (<see cref="FormatVersion"/>), documented in <c>docs/keys.md</c>, and read without reflection. It contains the data to be
/// signed when the scheme needs it (<see cref="Data"/>): treat a state like the document it covers. It never contains a private key.</para>
/// <para>Phase one: <see cref="Prepare"/> (or <see cref="PrepareDigest"/>). Phase two: sign <see cref="ToSign"/> anywhere with the key for <see cref="PublicKey"/>
/// under <see cref="Spec"/>, then <see cref="Complete"/>.</para>
/// </remarks>
public sealed class PreparedSignature
{
    /// <summary>The version of the serialised form this library writes and reads.</summary>
    public const int FormatVersion = 1;

    private readonly byte[] _toSign;
    private readonly byte[] _data;
    private readonly byte[] _publicKey;

    private PreparedSignature(string purpose, SignatureSpec spec, PublicKeyInfo key, SigningInput input, byte[] toSign, byte[] data)
    {
        Purpose = purpose;
        Spec = spec;
        PublicKey = key;
        _publicKey = key.Encoded.ToArray();
        Input = input;
        _toSign = toSign;
        _data = data;
    }

    /// <summary>What the signature is for, as the preparing code names it (<c>raw</c>, <c>x509.certificate</c>, …). Completion code checks it, so a certificate state cannot complete a CRL.</summary>
    public string Purpose { get; }

    /// <summary>How the signature is made.</summary>
    public SignatureSpec Spec { get; }

    /// <summary>The public key the finished signature must verify against.</summary>
    public PublicKeyInfo PublicKey { get; }

    /// <summary>Whether <see cref="ToSign"/> is a digest or the message.</summary>
    public SigningInput Input { get; }

    /// <summary>The octets the signer signs: the digest for RSA and ECDSA, the message for the rest.</summary>
    public ReadOnlyMemory<byte> ToSign => _toSign;

    /// <summary>The data the signature covers, kept when known (empty after <see cref="PrepareDigest"/>). For an X.509 structure this is the to-be-signed DER.</summary>
    public ReadOnlyMemory<byte> Data => _data;

    /// <summary>
    /// Phase one for data in hand. RSA and ECDSA specs yield a digest to sign, the others the message.
    /// </summary>
    /// <param name="signerKey">The public key of the key that will sign.</param>
    /// <param name="spec">The scheme.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="policy">The policy that decides whether this signature may be made.</param>
    /// <param name="at">The reference time for the policy (the moment of signing).</param>
    /// <param name="purpose">What the signature is for. Default <c>raw</c>.</param>
    /// <exception cref="PolicyViolationException">The policy rejects the hash or the key.</exception>
    /// <exception cref="ArgumentException">The spec does not fit the key.</exception>
    public static PreparedSignature Prepare(PublicKeyInfo signerKey, SignatureSpec spec, ReadOnlySpan<byte> data, CryptoPolicy policy, DateTimeOffset at, string purpose = "raw")
    {
        Check(signerKey, spec, policy, at);
        byte[] copy = data.ToArray();
        return spec.SignsDigest
            ? new(purpose, spec, signerKey, SigningInput.Digest, CryptographicOperations.HashData(spec.Hash, copy), copy)
            : new(purpose, spec, signerKey, SigningInput.Message, copy, copy);
    }

    /// <summary>Phase one for a digest computed elsewhere (a huge file, hashed in a stream). Only RSA and ECDSA specs.</summary>
    /// <exception cref="ArgumentException">The spec signs the message, or the digest length does not fit the hash.</exception>
    public static PreparedSignature PrepareDigest(PublicKeyInfo signerKey, SignatureSpec spec, ReadOnlySpan<byte> digest, CryptoPolicy policy, DateTimeOffset at, string purpose = "raw")
    {
        Check(signerKey, spec, policy, at);
        if (!spec.SignsDigest)
        {
            throw new ArgumentException($"{spec} signs the message; give the data to Prepare.", nameof(spec));
        }

        if (digest.Length != SignatureSpec.DigestSize(spec.Hash))
        {
            throw new ArgumentException("The digest length does not match the hash.", nameof(digest));
        }

        return new(purpose, spec, signerKey, SigningInput.Digest, digest.ToArray(), []);
    }

    private static void Check(PublicKeyInfo key, SignatureSpec spec, CryptoPolicy policy, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(policy);
        if (!spec.FitsKey(key))
        {
            throw new ArgumentException($"{spec} does not fit a {key.Algorithm.Name} key.", nameof(spec));
        }

        PolicyReport report = policy.CheckSignature(spec, key, CryptoUse.Sign, at);
        if (!report.IsAllowed)
        {
            throw new PolicyViolationException(report);
        }
    }

    /// <summary>
    /// Phase two. Checks <paramref name="signature"/> against the recorded public key and returns it, or throws. A signature made with another key, over other
    /// data, or in another encoding is refused here, before anything is assembled from it.
    /// </summary>
    /// <exception cref="InvalidSignatureException">The signature does not verify; <see cref="InvalidSignatureException.Result"/> says why.</exception>
    public byte[] Complete(ReadOnlySpan<byte> signature)
    {
        SignatureVerification v = Verify(signature);
        return v.IsValid ? signature.ToArray() : throw new InvalidSignatureException(v);
    }

    /// <summary>Phase two without the exception: false and the verification result when the signature is refused.</summary>
    public bool TryComplete(ReadOnlySpan<byte> signature, out byte[] completed, out SignatureVerification result)
    {
        result = Verify(signature);
        completed = result.IsValid ? signature.ToArray() : [];
        return result.IsValid;
    }

    /// <summary>Checks a signature against the recorded key without accepting it.</summary>
    public SignatureVerification Verify(ReadOnlySpan<byte> signature) =>
        Input == SigningInput.Digest && _data.Length == 0
            ? SignatureGlue.VerifyDigest(Spec, PublicKey, _toSign, signature)
            : Spec.Verify(PublicKey, _data, signature);

    /// <summary>Signs with a key in this process and completes: for tests, for keys that are available after all, and as the reference for what a remote signer must do.</summary>
    /// <exception cref="ArgumentException">The key's public key is not the recorded one.</exception>
    public byte[] SignWith(ISigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (!key.PublicKey.Equals(PublicKey))
        {
            throw new ArgumentException("The key is not the one this signature was prepared for.", nameof(key));
        }

        return Complete(Input == SigningInput.Digest ? key.SignDigest(_toSign, Spec) : key.Sign(_toSign, Spec));
    }

    /// <summary>The async form of <see cref="SignWith"/>.</summary>
    public async ValueTask<byte[]> SignWithAsync(ISigningKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (!key.PublicKey.Equals(PublicKey))
        {
            throw new ArgumentException("The key is not the one this signature was prepared for.", nameof(key));
        }

        byte[] sig = Input == SigningInput.Digest
            ? await key.SignDigestAsync(_toSign, Spec, cancellationToken).ConfigureAwait(false)
            : await key.SignAsync(_toSign, Spec, cancellationToken).ConfigureAwait(false);
        return Complete(sig);
    }

    /// <summary>
    /// The serialised state: <c>SEQUENCE { version INTEGER, purpose UTF8String, spec SEQUENCE, publicKey SubjectPublicKeyInfo, input ENUMERATED,
    /// toSign OCTET STRING, data OCTET STRING }</c>, DER (see <c>docs/keys.md</c>).
    /// </summary>
    public byte[] Encode() => DerWriter.Sequence(
        DerWriter.SignedInteger(FormatVersion),
        DerWriter.Utf8String(Purpose),
        Spec.Encode(),
        _publicKey,
        DerWriter.Tlv(0x0A, [(byte)Input]),
        DerWriter.OctetString(_toSign),
        DerWriter.OctetString(_data));

    /// <summary>Reads a serialised state.</summary>
    /// <exception cref="FormatException">The octets are not a state this library version understands (damaged, or a newer version).</exception>
    public static PreparedSignature Decode(ReadOnlySpan<byte> encoded) =>
        TryDecode(encoded, out PreparedSignature? p, out string? error) ? p! : throw new FormatException(error);

    /// <summary>Reads a serialised state, returning false and the reason instead of throwing.</summary>
    public static bool TryDecode(ReadOnlySpan<byte> encoded, out PreparedSignature? state, out string? error)
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
                error = $"The prepared signature is format version {version}; this library reads version {FormatVersion}.";
                return false;
            }

            string purpose = s.ReadCharacterString(12);
            SignatureSpec spec = SignatureSpec.Decode(ref s);
            PublicKeyInfo key = PublicKeyInfo.Parse(s.ReadEncodedValue().ToArray());
            int input = s.ReadEnumerated();
            byte[] toSign = s.ReadOctetStringBytes();
            byte[] data = s.ReadOctetStringBytes();
            s.ThrowIfNotEmpty();
            if (!spec.FitsKey(key))
            {
                error = "The prepared signature's scheme does not fit its public key.";
                return false;
            }

            if (input is not (1 or 2) || (input == 1) != spec.SignsDigest)
            {
                error = "The prepared signature's input kind does not fit its scheme.";
                return false;
            }

            if (input == 1 && toSign.Length != SignatureSpec.DigestSize(spec.Hash))
            {
                error = "The prepared signature's digest length does not fit its hash.";
                return false;
            }

            if (input == 1 && data.Length != 0 && !CryptographicOperations.FixedTimeEquals(CryptographicOperations.HashData(spec.Hash, data), toSign))
            {
                error = "The prepared signature's data does not match its digest.";
                return false;
            }

            if (input == 2 && !toSign.AsSpan().SequenceEqual(data))
            {
                error = "The prepared signature's message and data differ.";
                return false;
            }

            state = new PreparedSignature(purpose, spec, key, (SigningInput)input, toSign, data);
            return true;
        }
        catch (Exception e) when (e is Asn1ParseException or X509ParseException or ArgumentException)
        {
            error = "The prepared signature is damaged: " + e.Message;
            return false;
        }
    }
}

/// <summary>Thrown by <see cref="PreparedSignature.Complete"/> when a signature does not verify against the key it was prepared for.</summary>
public sealed class InvalidSignatureException : CryptographicException
{
    /// <summary>Creates the exception from a failed verification.</summary>
    public InvalidSignatureException(SignatureVerification result)
        : base($"The signature is not accepted: {result.Reason} ({result.Status}, {result.Reference})")
    {
        Result = result;
    }

    /// <summary>What the verification found.</summary>
    public SignatureVerification Result { get; }
}
