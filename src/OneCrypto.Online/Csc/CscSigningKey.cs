using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;

namespace RecursiveAI.OneCrypto.Online.Csc;

/// <summary>How a <see cref="CscSigningKey"/> gets the authentication values an explicit authorization asks for.</summary>
public sealed class CscKeyOptions
{
    /// <summary>
    /// Called before each authorization of an <c>explicit</c> credential to collect the PIN, OTP or password the credential asks for
    /// (<see cref="CscCredentialInfo.AuthObjects"/>). The values are sent once, to <c>credentials/authorize</c>, and kept nowhere. Null means the caller has none,
    /// which is right only for a credential that asks for no authentication objects. Interactive prompts belong here: they pass straight through to the user.
    /// </summary>
    public Func<CscCredentialInfo, CancellationToken, ValueTask<IReadOnlyList<CscAuthObject>>>? AuthDataProvider { get; init; }

    /// <summary>
    /// Release the service's signature unchecked when the platform cannot verify its scheme at all. Default false: such a signature is refused with
    /// <see cref="AlgorithmNotSupportedException"/>. Setting it true weakens the check, because a faulty or hostile service's output is then passed on without being
    /// compared with the credential's public key. Has no effect where the scheme can be verified.
    /// </summary>
    public bool AllowUncheckedSignatures { get; init; }

    /// <summary>Treat every scheme as one the platform cannot verify; for tests of the refusal.</summary>
    internal bool SimulateVerificationGap { get; init; }
}

/// <summary>
/// A credential of a remote signing service as a signing key. The private key never leaves the service: a signature is requested by sending the digest. This is
/// the two-phase shape natively: the library (or <see cref="PreparedSignature"/>) prepares the digest locally, and the remote call signs it. Each signature
/// is authorized first (one <c>credentials/authorize</c> call that carries the digest, so the activation data is bound to it), signed with
/// <c>signatures/signHash</c>, and checked against the credential's certificate before it is returned; a signature that does not verify is never released.
/// RSA PKCS #1 v1.5, RSA-PSS and ECDSA are supported. EdDSA and ML-DSA sign the message, which this API cannot do, so <see cref="Supports(SignatureSpec)"/> is false for them.
/// </summary>
/// <remarks>
/// The synchronous methods wait for the network call; use the asynchronous ones where a synchronization context could deadlock.
/// Failures are <see cref="CscSigningException"/>, whose reasons never contain a token, an activation value or an authentication value.
/// </remarks>
public sealed class CscSigningKey : ISigningKey
{
    private const string RsaEncryption = "1.2.840.113549.1.1.1";
    private readonly CscClient _client;
    private readonly CscKeyOptions _options;
    private readonly HashSet<string> _listed;

    internal CscSigningKey(CscClient client, CscCredentialInfo credential, Certificate certificate, PublicKeyInfo publicKey, CscKeyOptions options, CscServiceInfo? service)
    {
        _client = client;
        Credential = credential;
        Certificate = certificate;
        PublicKey = publicKey;
        _options = options;
        _listed = [.. credential.KeyAlgorithms, .. service?.SignAlgorithms ?? []];
        DefaultSpec = SignatureSpec.DefaultFor(publicKey);
    }

    /// <summary>What the service says about the credential.</summary>
    public CscCredentialInfo Credential { get; }

    /// <summary>The end-entity certificate of the credential.</summary>
    public Certificate Certificate { get; }

    /// <summary>The certificates the service returned, the end-entity certificate first.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Chain => Credential.Certificates;

    /// <inheritdoc />
    public PublicKeyInfo PublicKey { get; }

    /// <inheritdoc />
    public KeyCapabilities Capabilities => KeyCapabilities.Sign;

    /// <inheritdoc />
    public SignatureSpec DefaultSpec { get; }

    /// <inheritdoc />
    public bool Supports(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return spec.SignsDigest && spec.FitsKey(PublicKey) && spec.Hash.Name is "SHA1" or "SHA256" or "SHA384" or "SHA512"
            && !(spec.Kind == SignatureKind.RsaPss && PublicKey.KeyAlgorithm != KeyAlgorithm.Rsa && PublicKey.KeyAlgorithm != KeyAlgorithm.RsaPss);
    }

    /// <inheritdoc />
    public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec)
    {
        RequireSupported(spec);
        return SignDigest(CryptographicOperations.HashData(spec.Hash, data), spec);
    }

    /// <inheritdoc />
    public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec) => SignDigestAsync(digest.ToArray(), spec).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        RequireSupported(spec);
        return SignDigestAsync(CryptographicOperations.HashData(spec.Hash, data.Span), spec, cancellationToken);
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> SignDigestAsync(ReadOnlyMemory<byte> digest, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        byte[][] r = await SignDigestsAsync([digest.ToArray()], spec, cancellationToken).ConfigureAwait(false);
        return r[0];
    }

    /// <summary>
    /// Signs several digests with one authorization (one <c>credentials/authorize</c> carrying all of them, one <c>signatures/signHash</c>), for batches such as a
    /// set of documents. At most <see cref="CscCredentialInfo.Multisign"/> digests.
    /// </summary>
    /// <param name="digests">The digests, each made with the spec's hash.</param>
    /// <param name="spec">The scheme.</param>
    /// <param name="cancellationToken">Cancels the calls.</param>
    /// <returns>The signatures, in the order of <paramref name="digests"/>, each verified against the credential's public key.</returns>
    /// <exception cref="NotSupportedException">The spec is not supported by this key.</exception>
    /// <exception cref="ArgumentException">A digest has the wrong length, or there are more than the credential allows.</exception>
    /// <exception cref="CscSigningException">The service or the network failed, the authorization is not complete, or a signature does not verify.</exception>
    public async ValueTask<byte[][]> SignDigestsAsync(IReadOnlyList<byte[]> digests, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(digests);
        RequireSupported(spec);
        if (digests.Count == 0 || digests.Count > Credential.Multisign)
        {
            throw new ArgumentException($"The credential authorizes 1 to {Credential.Multisign} signatures at a time.", nameof(digests));
        }

        int size = spec.Hash.Name switch { "SHA1" => 20, "SHA256" => 32, "SHA384" => 48, _ => 64 };
        foreach (byte[] d in digests)
        {
            if (d.Length != size)
            {
                throw new ArgumentException("A digest does not have the length of the spec's hash.", nameof(digests));
            }
        }

        string hashOid = HashOid(spec.Hash);
        string sad = await AuthorizeAsync(digests, hashOid, cancellationToken).ConfigureAwait(false);

        (string algo, byte[] algoParams) = Algorithm(spec);
        CscResult<IReadOnlyList<byte[]>> signed = await _client.SignHashAsync(Credential.CredentialId, sad, digests, hashOid, algo, algoParams, cancellationToken).ConfigureAwait(false);
        if (!signed.IsSuccess)
        {
            throw new CscSigningException(signed.Outcome, signed.Reason, signed.Error);
        }

        var result = new byte[digests.Count][];
        for (int i = 0; i < result.Length; i++)
        {
            byte[]? normalised = Normalise(signed.Value![i], spec);
            SignatureStatus status = normalised is null ? SignatureStatus.Invalid : (_options.SimulateVerificationGap ? SignatureStatus.AlgorithmNotSupported : spec.VerifyDigest(PublicKey, digests[i], normalised).Status);
            if (status is SignatureStatus.AlgorithmNotSupported)
            {
                if (!_options.AllowUncheckedSignatures)
                {
                    throw new AlgorithmNotSupportedException(spec.ToString(), System.Runtime.InteropServices.RuntimeInformation.OSDescription, "the platform cannot verify this signature against the credential's public key; CscKeyOptions.AllowUncheckedSignatures releases it unchecked");
                }
            }
            else if (status is not SignatureStatus.Valid)
            {
                throw new CscSigningException(CscOutcome.BadSignature, "the service returned a signature that does not verify against the credential's certificate key");
            }

            result[i] = normalised!;
        }

        return result;
    }

    /// <summary>Does nothing: the key lives at the service, and nothing is held here that needs releasing.</summary>
    public void Dispose()
    {
    }

    private async ValueTask<string> AuthorizeAsync(IReadOnlyList<byte[]> digests, string hashOid, CancellationToken cancellationToken)
    {
        if (Credential.AuthMode == CscAuthMode.OAuth2Code)
        {
            ICscTokenSource tokens = _client.Tokens ?? throw new CscSigningException(CscOutcome.CredentialUnusable, "the credential is authorized through OAuth 2.0 and the client has no token source");
            // The digests go to the authorization server whatever the SCAL (they are optional for SCAL 1), so the token is always bound to what is signed.
            var request = new CscCredentialTokenRequest(Credential.CredentialId, digests, hashOid, Credential.Scal == 2);
            CscAccessToken? token = await tokens.GetCredentialTokenAsync(request, cancellationToken).ConfigureAwait(false);
            if (token is null || (token.ExpiresAt is { } e && e <= _client.Now))
            {
                throw new CscSigningException(CscOutcome.TokenUnavailable, "the token source gave no credential access token (or an expired one)");
            }

            return token.Value;
        }

        IReadOnlyList<CscAuthObject> authData = [];
        if (_options.AuthDataProvider is { } provider)
        {
            authData = await provider(Credential, cancellationToken).ConfigureAwait(false);
        }
        else if (Credential.AuthObjects.Count > 0)
        {
            throw new CscSigningException(CscOutcome.CredentialUnusable, "the credential asks for authentication values and no CscKeyOptions.AuthDataProvider was given");
        }

        CscResult<CscAuthorization> auth = await _client.AuthorizeAsync(Credential.CredentialId, digests, hashOid, authData, null, cancellationToken).ConfigureAwait(false);
        if (!auth.IsSuccess)
        {
            throw new CscSigningException(auth.Outcome, auth.Reason, auth.Error);
        }

        return auth.Value!.Sad!;
    }

    private void RequireSupported(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (!Supports(spec))
        {
            throw new NotSupportedException($"A remote signing credential signs digests only (RSA, RSA-PSS, ECDSA with SHA-1 or SHA-2) and this key cannot do {spec}.");
        }
    }

    private static string HashOid(HashAlgorithmName h) => h.Name switch
    {
        "SHA1" => KnownOids.Sha1,
        "SHA256" => KnownOids.Sha256,
        "SHA384" => KnownOids.Sha384,
        _ => KnownOids.Sha512,
    };

    /// <summary>
    /// The <c>signAlgo</c> (and <c>signAlgoParams</c>) for a spec. The hash-specific identifier (sha256WithRSAEncryption, ecdsa-with-SHA256, id-RSASSA-PSS with its
    /// parameters) is used; a service that lists only <c>rsaEncryption</c> gets that with the <c>hashAlgorithmOID</c> that is always sent (CSC API §11.13).
    /// </summary>
    private (string Oid, byte[] Parameters) Algorithm(SignatureSpec spec)
    {
        AlgorithmIdentifier id = (spec.Kind == SignatureKind.Ecdsa ? SignatureSpec.Ecdsa(spec.Hash) : spec).ToAlgorithmIdentifier(PublicKey);
        if (spec.Kind == SignatureKind.RsaPkcs1 && _listed.Count > 0 && !_listed.Contains(id.Oid) && _listed.Contains(RsaEncryption))
        {
            return (RsaEncryption, []);
        }

        // Only RSASSA-PSS carries parameters in signAlgoParams; NULL parameters of the RSA identifiers are implied.
        return (id.Oid, spec.Kind == SignatureKind.RsaPss ? id.Parameters.ToArray() : []);
    }

    /// <summary>
    /// Brings an ECDSA answer into the spec's encoding. The API does not say whether a service returns DER or the fixed-width <c>r || s</c>; a signature of
    /// exactly twice the field size is the latter (a DER signature is always longer), and either is accepted. Other schemes pass unchanged.
    /// </summary>
    private byte[]? Normalise(byte[] signature, SignatureSpec spec)
    {
        if (spec.Kind != SignatureKind.Ecdsa)
        {
            return signature;
        }

        int n = (PublicKey.KeySizeBits + 7) / 8;
        if (n == 0)
        {
            return null;
        }

        byte[]? raw = signature.Length == 2 * n ? signature : DerToRaw(signature, n);
        if (raw is null)
        {
            return null;
        }

        return spec.Format == EcdsaSignatureFormat.Rfc4754 ? raw : RawToDer(raw, n);
    }

    private static byte[] RawToDer(byte[] raw, int n) => DerWriter.Sequence(DerWriter.UnsignedInteger(raw.AsSpan(0, n)), DerWriter.UnsignedInteger(raw.AsSpan(n, n)));

    private static byte[]? DerToRaw(byte[] der, int n)
    {
        // SEQUENCE { INTEGER r, INTEGER s }, definite lengths, minimal (RFC 3279 §2.2.3 as DER). Anything else is refused and the caller treats it as a bad signature.
        int pos = 0;
        if (!Header(der, ref pos, 0x30, out int seqLen) || pos + seqLen != der.Length)
        {
            return null;
        }

        var raw = new byte[2 * n];
        for (int part = 0; part < 2; part++)
        {
            if (!Header(der, ref pos, 0x02, out int len) || len == 0 || pos + len > der.Length)
            {
                return null;
            }

            ReadOnlySpan<byte> v = der.AsSpan(pos, len);
            pos += len;
            if ((v[0] & 0x80) != 0 || (len > 1 && v[0] == 0 && (v[1] & 0x80) == 0))
            {
                return null;
            }

            while (v.Length > 1 && v[0] == 0)
            {
                v = v[1..];
            }

            if (v.Length > n)
            {
                return null;
            }

            v.CopyTo(raw.AsSpan((part * n) + (n - v.Length)));
        }

        return pos == der.Length ? raw : null;
    }

    private static bool Header(byte[] b, ref int pos, byte tag, out int length)
    {
        length = 0;
        if (pos + 2 > b.Length || b[pos] != tag)
        {
            return false;
        }

        int l = b[pos + 1];
        pos += 2;
        if (l < 0x80)
        {
            length = l;
            return true;
        }

        if (l != 0x81 || pos >= b.Length || b[pos] < 0x80)
        {
            return false;
        }

        length = b[pos++];
        return true;
    }
}
