using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Keys.Agents;

/// <summary>
/// A private key that lives in gpg-agent. The key object holds a keygrip and the public key; every operation is one round trip to the agent, which prompts for the
/// passphrase if it must (the prompt is the agent's own, through its pinentry) and may use a smartcard. Nothing here ever sees key material.
/// Get one from <see cref="GpgAgentClient.GetKey"/> or <see cref="GpgAgentClient.FindKey"/>.
/// </summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("browser")]
public abstract class GpgAgentKey : IKey
{
    private readonly string? _description;

    internal GpgAgentKey(GpgAgentClient client, string keygrip, PublicKeyInfo publicKey, string? description)
    {
        Agent = client;
        Keygrip = keygrip;
        PublicKey = publicKey;
        _description = description;
    }

    /// <summary>The agent this key belongs to.</summary>
    public GpgAgentClient Agent { get; }

    /// <summary>The key's keygrip, 40 upper-case hexadecimal digits.</summary>
    public string Keygrip { get; }

    /// <inheritdoc/>
    public PublicKeyInfo PublicKey { get; }

    /// <inheritdoc/>
    public abstract KeyCapabilities Capabilities { get; }

    /// <summary>Does nothing: the key object owns no secret and no connection.</summary>
    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }

    // ---- creation from READKEY ----

    internal static GpgAgentKey FromPublicKeySExp(GpgAgentClient client, string keygrip, byte[] sexp, string? description)
    {
        try
        {
            return ParsePublicKeySExp(client, keygrip, sexp, description);
        }
        catch (X509ParseException e)
        {
            throw new AgentProtocolException("The agent's public key is not a usable key: " + e.Message, e);
        }
    }

    private static GpgAgentKey ParsePublicKeySExp(GpgAgentClient client, string keygrip, byte[] sexp, string? description)
    {
        if (!SExp.TryParse(sexp, out SExp? root, out string? error) || root!.Name != "public-key" || root.Items!.Count < 2)
        {
            throw new AgentProtocolException("The agent's public key is not a public-key S-expression" + (error is null ? "." : ": " + error));
        }

        SExp algo = root.Items[1];
        PublicKeyInfo pk;
        switch (algo.Name)
        {
            case "rsa":
                byte[]? n = algo.ValueOf("n"), e = algo.ValueOf("e");
                if (n is null || e is null || n.Length is 0 or > 1100 || e.Length is 0 or > 16)
                {
                    throw new AgentProtocolException("The agent's RSA public key is incomplete or has an odd size.");
                }

                pk = PublicKeyInfo.Parse(DerWriter.Sequence(
                    DerWriter.Sequence(DerWriter.Oid(KnownOids.RsaEncryption), DerWriter.Null()),
                    BitString(DerWriter.Sequence(DerWriter.UnsignedInteger(n), DerWriter.UnsignedInteger(e)))));
                return new GpgAgentRsaKey(client, keygrip, pk, description);
            case "ecc":
                string curve = algo.Find("curve")?.Items is { Count: 2 } c && c[1].Text is { } cn ? cn : throw new AgentProtocolException("The agent's EC public key names no curve.");
                byte[] q = algo.ValueOf("q") ?? throw new AgentProtocolException("The agent's EC public key has no point.");
                return FromEc(client, keygrip, curve, q, description);
            default:
                throw new AlgorithmNotSupportedException($"gpg-agent key type {algo.Name ?? "(unnamed)"}", System.Runtime.InteropServices.RuntimeInformation.OSDescription, "only RSA and elliptic-curve keys are handled");
        }
    }

    private static GpgAgentKey FromEc(GpgAgentClient client, string keygrip, string curve, byte[] q, string? description)
    {
        // Libgcrypt names curves its own way; these are the spellings it uses and their usual aliases.
        string name = curve.ToLowerInvariant().Replace(" ", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal);
        string? oid = name switch
        {
            "nistp256" or "prime256v1" or "secp256r1" => KnownOids.P256,
            "nistp384" or "secp384r1" => KnownOids.P384,
            "nistp521" or "secp521r1" => KnownOids.P521,
            "brainpoolp256r1" => KnownOids.BrainpoolP256r1,
            "brainpoolp384r1" => KnownOids.BrainpoolP384r1,
            "brainpoolp512r1" => KnownOids.BrainpoolP512r1,
            _ => null,
        };
        if (oid is not null)
        {
            // An uncompressed point (SEC 1 §2.3.3).
            if (q.Length < 33 || q[0] != 4 || q.Length % 2 != 1)
            {
                throw new AgentProtocolException("The agent's EC point is not an uncompressed point.");
            }

            PublicKeyInfo ec = PublicKeyInfo.Parse(DerWriter.Sequence(
                DerWriter.Sequence(DerWriter.Oid(KnownOids.EcPublicKey), DerWriter.Oid(oid)),
                BitString(q)));
            return new GpgAgentEcKey(client, keygrip, ec, description);
        }

        (string algOid, int size, bool signs) = name switch
        {
            "ed25519" => (KnownOids.Ed25519, 32, true),
            "curve25519" or "x25519" => (KnownOids.X25519, 32, false),
            "ed448" => (KnownOids.Ed448, 57, true),
            "x448" or "curve448" => (KnownOids.X448, 56, false),
            _ => ((string)null!, 0, false),
        };
        if (algOid is null)
        {
            throw new AlgorithmNotSupportedException($"gpg-agent curve {curve}", System.Runtime.InteropServices.RuntimeInformation.OSDescription, "this curve is not handled");
        }

        // Libgcrypt prefixes these points with 0x40 (its native point format for the Montgomery and Edwards curves).
        byte[] raw = q.Length == size + 1 && q[0] == 0x40 ? q[1..] : q;
        if (raw.Length != size)
        {
            throw new AgentProtocolException($"The agent's {curve} point has the wrong size.");
        }

        PublicKeyInfo pk = PublicKeyInfo.Parse(DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(algOid)), BitString(raw)));
        return signs ? new GpgAgentEdKey(client, keygrip, pk, description) : new GpgAgentMontgomeryKey(client, keygrip, pk, description);
    }

    private static byte[] BitString(byte[] content)
    {
        var withUnused = new byte[content.Length + 1];
        content.CopyTo(withUnused, 1);
        return DerWriter.Tlv(0x03, withUnused);
    }

    // 17 and 32849 are the no-secret-key answers; gpg-agent 2.4.4 answers READKEY/PKSIGN for
    // an unknown but well-formed keygrip with 261 (invalid value passed to IPC), while a
    // malformed grip gets a distinct parameter error, so 261 means not found here.
    internal static bool IsNoKey(AgentRefusedException e) => e.Code is 17 or 32849 or 261;

    // ---- shared protocol steps ----

    internal static int HashNumber(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1" => 2,
        "SHA256" => 8,
        "SHA384" => 9,
        "SHA512" => 10,
        _ => 0,
    };

    /// <summary>SIGKEY, SETHASH and PKSIGN. A digest goes in as a hash value; a message (EdDSA) goes in through the agent's <c>TBSDATA</c> inquiry.</summary>
    internal async Task<SExp> PkSignAsync(int hashNumber, byte[] value, bool isMessage, CancellationToken cancellationToken)
    {
        bool tooBig = false;
        int announced = -1;
        try
        {
            AssuanReply reply = await Agent.RunAsync(async (s, ct) =>
            {
                await s.CommandAsync("SIGKEY " + Keygrip, null, ct).ConfigureAwait(false);
                if (_description is not null)
                {
                    await s.CommandAsync("SETKEYDESC " + GpgAgentClient.Escape(_description), null, ct).ConfigureAwait(false);
                }

                if (isMessage)
                {
                    await s.CommandAsync("SETHASH --inquire", (kw, _, max) =>
                    {
                        announced = max;
                        if (kw != "TBSDATA")
                        {
                            return null;
                        }

                        if (max >= 0 && value.Length > max)
                        {
                            tooBig = true;
                            return null;
                        }

                        return value;
                    }, ct).ConfigureAwait(false);
                }
                else
                {
                    await s.CommandAsync($"SETHASH {hashNumber} {Convert.ToHexString(value)}", null, ct).ConfigureAwait(false);
                }

                return await s.CommandAsync("PKSIGN", null, ct).ConfigureAwait(false);
            }, cancellationToken).ConfigureAwait(false);
            return Parse(reply.Data, "sig-val");
        }
        catch (AgentRefusedException) when (tooBig)
        {
            throw new AgentLimitException($"The agent takes at most {announced} octets of message for a pure EdDSA signature; this message has {value.Length}.");
        }
        catch (AgentRefusedException e) when (IsNoKey(e))
        {
            throw new AgentKeyNotFoundException($"The agent has no secret key with keygrip {Keygrip}.");
        }
    }

    /// <summary>SETKEY and PKDECRYPT: hands the agent an <c>enc-val</c> S-expression and returns the <c>value</c> it answers with. The caller wipes the result.</summary>
    internal async Task<byte[]> PkDecryptAsync(byte[] encVal, CancellationToken cancellationToken)
    {
        AssuanReply reply;
        try
        {
            reply = await Agent.RunAsync(async (s, ct) =>
            {
                await s.CommandAsync("SETKEY " + Keygrip, null, ct).ConfigureAwait(false);
                if (_description is not null)
                {
                    await s.CommandAsync("SETKEYDESC " + GpgAgentClient.Escape(_description), null, ct).ConfigureAwait(false);
                }

                return await s.CommandAsync("PKDECRYPT", (kw, _, _) => kw == "CIPHERTEXT" ? encVal : null, ct).ConfigureAwait(false);
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (AgentRefusedException e) when (IsNoKey(e))
        {
            throw new AgentKeyNotFoundException($"The agent has no secret key with keygrip {Keygrip}.");
        }
        catch (AgentRefusedException e) when (!e.IsCancelled && !e.IsBadPassphrase && e.ErrorSource != 5)
        {
            // A ciphertext the agent could not undo. Like RSA decryption everywhere, it does not say why (RFC 8017 §7.2.2 on error oracles).
            throw new CryptographicException("The ciphertext could not be decrypted.");
        }

        try
        {
            if (!SExp.TryParse(reply.Data, out SExp? root, out string? error) || root!.Name != "value" || root.Items!.Count != 2 || root.Items[1].Atom is null)
            {
                throw new AgentProtocolException("The agent's decryption result is not a value S-expression" + (error is null ? "." : ": " + error));
            }

            byte[] value = root.Items[1].Atom!.AsSpan().ToArray();
            root.Wipe();
            return value;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(reply.Data);
        }
    }

    private static SExp Parse(byte[] data, string expected)
    {
        if (!SExp.TryParse(data, out SExp? root, out string? error) || root!.Name != expected)
        {
            throw new AgentProtocolException($"The agent's reply is not a {expected} S-expression" + (error is null ? "." : ": " + error));
        }

        return root;
    }

    /// <summary>Turns the agent's <c>sig-val</c> into the signature the spec asks for, after checking its shape.</summary>
    internal static byte[] ReadSignature(SExp sigVal, string algorithm, PublicKeyInfo key, SignatureSpec spec)
    {
        SExp? body = sigVal.Items!.Count == 2 ? sigVal.Items[1] : null;
        if (body is null || body.Name != algorithm)
        {
            throw new AgentProtocolException($"The agent answered with a {body?.Name ?? "(none)"} signature where {algorithm} was expected.");
        }

        switch (algorithm)
        {
            case "rsa":
                byte[] s = body.ValueOf("s") ?? throw new AgentProtocolException("The agent's RSA signature has no s value.");
                int size = (key.KeySizeBits + 7) / 8;
                if (s.Length > size)
                {
                    throw new AgentProtocolException("The agent's RSA signature is longer than the key.");
                }

                // The agent writes the integer without leading zeros; the signature is as long as the modulus (RFC 8017 §8.2.1 step 3).
                var padded = new byte[size];
                s.CopyTo(padded, size - s.Length);
                return padded;
            case "ecdsa":
                int n = (key.KeySizeBits + 7) / 8;
                byte[] r = Strip(body.ValueOf("r") ?? throw new AgentProtocolException("The agent's ECDSA signature has no r value."));
                byte[] ss = Strip(body.ValueOf("s") ?? throw new AgentProtocolException("The agent's ECDSA signature has no s value."));
                if (r.Length > n || ss.Length > n)
                {
                    throw new AgentProtocolException("The agent's ECDSA signature is longer than the curve allows.");
                }

                var p1363 = new byte[2 * n];
                r.CopyTo(p1363, n - r.Length);
                ss.CopyTo(p1363, (2 * n) - ss.Length);
                if (spec.Format == EcdsaSignatureFormat.Rfc4754)
                {
                    return p1363;
                }

                return ToDer(p1363, n);
            default:
                int half = key.KeyAlgorithm == KeyAlgorithm.Ed448 ? 57 : 32;
                byte[] er = body.ValueOf("r") ?? throw new AgentProtocolException("The agent's EdDSA signature has no r value."), es = body.ValueOf("s") ?? throw new AgentProtocolException("The agent's EdDSA signature has no s value.");
                if (er.Length != half || es.Length != half)
                {
                    throw new AgentProtocolException("The agent's EdDSA signature has the wrong size.");
                }

                var sig = new byte[2 * half];
                er.CopyTo(sig, 0);
                es.CopyTo(sig, half);
                return sig;
        }
    }

    private static byte[] ToDer(byte[] p1363, int n) => DerWriter.Sequence(DerWriter.UnsignedInteger(p1363.AsSpan(0, n)), DerWriter.UnsignedInteger(p1363.AsSpan(n)));

    private static byte[] Strip(byte[] v)
    {
        int i = 0;
        while (i < v.Length - 1 && v[i] == 0)
        {
            i++;
        }

        return v[i..];
    }

    internal byte[] CheckSignature(SignatureSpec spec, byte[] signature, ReadOnlySpan<byte> signedInput, bool isDigest)
    {
        if (!Agent.Options.VerifySignatures)
        {
            return signature;
        }

        SignatureVerification v = isDigest ? spec.VerifyDigest(PublicKey, signedInput, signature) : spec.Verify(PublicKey, signedInput, signature);
        SignatureStatus status = Agent.Options.SimulateVerificationGap ? SignatureStatus.AlgorithmNotSupported : v.Status;
        return status switch
        {
            SignatureStatus.Valid => signature,
            // The platform cannot check it: refused unless the caller opted out.
            SignatureStatus.AlgorithmNotSupported when Agent.Options.AllowUncheckedSignatures => signature,
            SignatureStatus.AlgorithmNotSupported => throw new AlgorithmNotSupportedException(spec.ToString(), System.Runtime.InteropServices.RuntimeInformation.OSDescription, "the platform cannot verify this signature against the key's public key; AllowUncheckedSignatures releases it unchecked"),
            _ => throw new AgentProtocolException("The signature the agent returned does not verify against the key's public key: " + v.Reason),
        };
    }

    internal static byte[] Hash(HashAlgorithmName hash, ReadOnlySpan<byte> data) => CryptographicOperations.HashData(hash, data);

    internal static NotSupportedException NotThis(string what, string key) => new($"{what} is not available for a gpg-agent {key} key.");
}

/// <summary>An RSA key in gpg-agent: PKCS #1 v1.5 signatures and PKCS #1 v1.5 or OAEP decryption.</summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("browser")]
public sealed class GpgAgentRsaKey : GpgAgentKey, IRsaKey
{
    internal GpgAgentRsaKey(GpgAgentClient client, string keygrip, PublicKeyInfo publicKey, string? description)
        : base(client, keygrip, publicKey, description)
    {
    }

    /// <inheritdoc/>
    public override KeyCapabilities Capabilities => KeyCapabilities.Sign | KeyCapabilities.Decrypt;

    /// <inheritdoc/>
    public SignatureSpec DefaultSpec => SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256);

    /// <inheritdoc/>
    /// <remarks>PKCS #1 v1.5 with SHA-1, SHA-256, SHA-384 or SHA-512. RSA-PSS is not offered.</remarks>
    public bool Supports(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return spec.Kind == SignatureKind.RsaPkcs1 && HashNumber(spec.Hash) != 0;
    }

    /// <inheritdoc/>
    public bool Supports(DecryptionSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return spec.Kind == DecryptionKind.RsaPkcs1 || (spec.Kind == DecryptionKind.RsaOaep && HashNumber(spec.Hash) != 0);
    }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec) => SignAsync(data.ToArray(), spec).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc/>
    public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec) => SignDigestAsync(digest.ToArray(), spec).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc/>
    public async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        Require(spec);
        return await SignDigestCoreAsync(Hash(spec.Hash, data.Span), spec, data, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask<byte[]> SignDigestAsync(ReadOnlyMemory<byte> digest, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        Require(spec);
        return await SignDigestCoreAsync(digest.ToArray(), spec, default, cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]> SignDigestCoreAsync(byte[] digest, SignatureSpec spec, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (digest.Length != DigestSize(spec.Hash))
        {
            throw new ArgumentException("The digest is not the size of the spec's hash.", nameof(digest));
        }

        SExp sig = await PkSignAsync(HashNumber(spec.Hash), digest, isMessage: false, cancellationToken).ConfigureAwait(false);
        byte[] result = ReadSignature(sig, "rsa", PublicKey, spec);
        return data.IsEmpty ? CheckSignature(spec, result, digest, isDigest: true) : CheckSignature(spec, result, data.Span, isDigest: false);
    }

    private static int DigestSize(HashAlgorithmName h) => h.Name switch { "SHA1" => 20, "SHA256" => 32, "SHA384" => 48, _ => 64 };

    private void Require(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (!Supports(spec))
        {
            throw NotThis(spec.ToString(), "RSA");
        }
    }

    /// <inheritdoc/>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, DecryptionSpec spec) => DecryptAsync(ciphertext.ToArray(), spec).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc/>
    public async ValueTask<byte[]> DecryptAsync(ReadOnlyMemory<byte> ciphertext, DecryptionSpec spec, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (!Supports(spec))
        {
            throw NotThis(spec.ToString(), "RSA");
        }

        int size = (PublicKey.KeySizeBits + 7) / 8;
        if (ciphertext.Length != size)
        {
            // RFC 8017 §7.2.2 step 1: the ciphertext is as long as the modulus.
            throw new CryptographicException("The ciphertext is not the size of the key.");
        }

        // The agent unpads: libgcrypt's pkcs1 and oaep flags, so no secret-dependent padding check happens here.
        byte[] rsaPart = SExpWriter.List(SExpWriter.Atom("rsa"), SExpWriter.List(SExpWriter.Atom("a"), SExpWriter.Atom(ciphertext.Span)));
        byte[] encVal = spec.Kind == DecryptionKind.RsaPkcs1
            ? SExpWriter.List(SExpWriter.Atom("enc-val"), SExpWriter.List(SExpWriter.Atom("flags"), SExpWriter.Atom("pkcs1")), rsaPart)
            : SExpWriter.List(
                SExpWriter.Atom("enc-val"),
                SExpWriter.List(SExpWriter.Atom("flags"), SExpWriter.Atom("oaep")),
                SExpWriter.List(SExpWriter.Atom("hash-algo"), SExpWriter.Atom(spec.Hash.Name!.ToLowerInvariant())),
                rsaPart);
        return await PkDecryptAsync(encVal, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>An elliptic-curve key on a NIST or Brainpool curve in gpg-agent: ECDSA signatures and ECDH agreement.</summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("browser")]
public sealed class GpgAgentEcKey : GpgAgentKey, ISigningKey, IAgreementKey
{
    internal GpgAgentEcKey(GpgAgentClient client, string keygrip, PublicKeyInfo publicKey, string? description)
        : base(client, keygrip, publicKey, description)
    {
    }

    /// <inheritdoc/>
    public override KeyCapabilities Capabilities => KeyCapabilities.Sign | KeyCapabilities.Agree;

    /// <inheritdoc/>
    public SignatureSpec DefaultSpec => SignatureSpec.DefaultFor(PublicKey);

    /// <inheritdoc/>
    public bool Supports(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return spec.Kind == SignatureKind.Ecdsa && HashNumber(spec.Hash) != 0;
    }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec) => SignAsync(data.ToArray(), spec).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc/>
    public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec) => SignDigestAsync(digest.ToArray(), spec).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc/>
    public async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        Require(spec);
        return await SignCoreAsync(Hash(spec.Hash, data.Span), spec, data, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask<byte[]> SignDigestAsync(ReadOnlyMemory<byte> digest, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        Require(spec);
        return await SignCoreAsync(digest.ToArray(), spec, default, cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]> SignCoreAsync(byte[] digest, SignatureSpec spec, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        SExp sig = await PkSignAsync(HashNumber(spec.Hash), digest, isMessage: false, cancellationToken).ConfigureAwait(false);
        byte[] result = ReadSignature(sig, "ecdsa", PublicKey, spec);
        return data.IsEmpty ? CheckSignature(spec, result, digest, isDigest: true) : CheckSignature(spec, result, data.Span, isDigest: false);
    }

    private void Require(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (!Supports(spec))
        {
            throw NotThis(spec.ToString(), "EC");
        }
    }

    /// <inheritdoc/>
    public byte[] Agree(PublicKeyInfo peer) => AgreeAsync(peer).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc/>
    public async ValueTask<byte[]> AgreeAsync(PublicKeyInfo peer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(peer);
        if (peer.KeyAlgorithm != KeyAlgorithm.EllipticCurve || peer.CurveOid != PublicKey.CurveOid)
        {
            throw new ArgumentException("The peer's key is not on the same curve.", nameof(peer));
        }

        int size = (PublicKey.KeySizeBits + 7) / 8;
        ReadOnlySpan<byte> point = peer.KeyBits.Span;
        if (point.Length != 1 + (2 * size) || point[0] != 4)
        {
            throw new ArgumentException("The peer's point is not an uncompressed point on the curve.", nameof(peer));
        }

        byte[] encVal = SExpWriter.List(SExpWriter.Atom("enc-val"), SExpWriter.List(SExpWriter.Atom("ecdh"), SExpWriter.List(SExpWriter.Atom("e"), SExpWriter.Atom(point))));
        byte[] value = await PkDecryptAsync(encVal, cancellationToken).ConfigureAwait(false);
        try
        {
            // The agent answers with the shared point, uncompressed; the shared secret is its x-coordinate (SEC 1 §3.3.1).
            if (value.Length == 1 + (2 * size) && value[0] == 4)
            {
                return value.AsSpan(1, size).ToArray();
            }

            if (value.Length == size)
            {
                return (byte[])value.Clone();
            }

            throw new AgentProtocolException("The agent's ECDH result has an unexpected shape.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}

/// <summary>An Ed25519 or Ed448 key in gpg-agent: signatures over messages.</summary>
/// <remarks>
/// The agent takes the whole message in one inquiry, which gpg-agent 2.4 limits to 2048 octets: longer messages throw <see cref="AgentLimitException"/>.
/// OpenPGP and CMS sign a digest or a short attribute block, so they fit; to sign a large file with a pure EdDSA key, sign its hash and say so in the protocol that carries it.
/// </remarks>
[System.Runtime.Versioning.UnsupportedOSPlatform("browser")]
public sealed class GpgAgentEdKey : GpgAgentKey, ISigningKey
{
    internal GpgAgentEdKey(GpgAgentClient client, string keygrip, PublicKeyInfo publicKey, string? description)
        : base(client, keygrip, publicKey, description)
    {
    }

    /// <inheritdoc/>
    public override KeyCapabilities Capabilities => KeyCapabilities.Sign;

    /// <inheritdoc/>
    public SignatureSpec DefaultSpec => SignatureSpec.DefaultFor(PublicKey);

    /// <inheritdoc/>
    public bool Supports(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return PublicKey.KeyAlgorithm == KeyAlgorithm.Ed25519 ? spec.Kind == SignatureKind.Ed25519 : spec.Kind == SignatureKind.Ed448 && spec.Context.IsEmpty;
    }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec) => SignAsync(data.ToArray(), spec).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc/>
    public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec) => throw new NotSupportedException("EdDSA signs the message, not a digest.");

    /// <inheritdoc/>
    public async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (!Supports(spec))
        {
            throw NotThis(spec.ToString(), PublicKey.Algorithm.Name);
        }

        byte[] message = data.ToArray();
        SExp sig = await PkSignAsync(0, message, isMessage: true, cancellationToken).ConfigureAwait(false);
        byte[] result = ReadSignature(sig, "eddsa", PublicKey, spec);
        return CheckSignature(spec, result, message, isDigest: false);
    }

    /// <inheritdoc/>
    public ValueTask<byte[]> SignDigestAsync(ReadOnlyMemory<byte> digest, SignatureSpec spec, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("EdDSA signs the message, not a digest.");
}

/// <summary>An X25519 (Cv25519) or X448 key in gpg-agent: key agreement.</summary>
[System.Runtime.Versioning.UnsupportedOSPlatform("browser")]
public sealed class GpgAgentMontgomeryKey : GpgAgentKey, IAgreementKey
{
    internal GpgAgentMontgomeryKey(GpgAgentClient client, string keygrip, PublicKeyInfo publicKey, string? description)
        : base(client, keygrip, publicKey, description)
    {
    }

    /// <inheritdoc/>
    public override KeyCapabilities Capabilities => KeyCapabilities.Agree;

    /// <inheritdoc/>
    public byte[] Agree(PublicKeyInfo peer) => AgreeAsync(peer).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc/>
    public async ValueTask<byte[]> AgreeAsync(PublicKeyInfo peer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(peer);
        if (peer.KeyAlgorithm != PublicKey.KeyAlgorithm)
        {
            throw new ArgumentException("The peer's key is of another family.", nameof(peer));
        }

        int size = PublicKey.KeyAlgorithm == KeyAlgorithm.X448 ? 56 : 32;
        ReadOnlySpan<byte> u = peer.KeyBits.Span;
        if (u.Length != size)
        {
            throw new ArgumentException("The peer's public key has the wrong size.", nameof(peer));
        }

        // Libgcrypt's point format for these curves carries a 0x40 prefix; the agent answers in the same format.
        var point = new byte[size + 1];
        point[0] = 0x40;
        u.CopyTo(point.AsSpan(1));
        byte[] encVal = SExpWriter.List(SExpWriter.Atom("enc-val"), SExpWriter.List(SExpWriter.Atom("ecdh"), SExpWriter.List(SExpWriter.Atom("e"), SExpWriter.Atom(point))));
        byte[] value = await PkDecryptAsync(encVal, cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] secret;
            if (value.Length == size + 1 && value[0] == 0x40)
            {
                secret = value.AsSpan(1).ToArray();
            }
            else if (value.Length == size)
            {
                secret = (byte[])value.Clone();
            }
            else
            {
                throw new AgentProtocolException("The agent's key-agreement result has an unexpected shape.");
            }

            // RFC 7748 §6.1: an all-zero result means the peer sent a low-order point.
            if (CryptographicOperations.FixedTimeEquals(secret, new byte[size]))
            {
                CryptographicOperations.ZeroMemory(secret);
                throw new CryptographicException("The key agreement produced an all-zero secret.");
            }

            return secret;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
