using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Ssh;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Keys.Agents;

/// <summary>How to reach and talk to an ssh-agent.</summary>
public sealed class SshAgentOptions
{
    /// <summary>The agent's socket. Null means the <c>SSH_AUTH_SOCK</c> environment variable.</summary>
    public string? SocketPath { get; init; }

    /// <summary>How long to wait for the socket to accept a connection. Default 5 seconds.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// How long one request may take after connecting before it fails with <see cref="AgentUnavailableException"/>. Default 2 minutes: an agent that asks the user to
    /// confirm a use (<c>ssh-add -c</c>) or touch a token waits for that. <see cref="Timeout.InfiniteTimeSpan"/> waits for ever.
    /// </summary>
    public TimeSpan OperationTimeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>Check every signature the agent returns against the key's public key before handing it on. Default true.</summary>
    public bool VerifySignatures { get; init; } = true;

    /// <summary>
    /// Release a signature unchecked when the platform cannot verify its scheme at all (for example a curve or post-quantum scheme the operating system lacks).
    /// Default false: such a signature is refused with <see cref="AlgorithmNotSupportedException"/>. Setting it true weakens the check, because a faulty or hostile
    /// signer's output is then passed on without being compared with the public key. Has no effect where the scheme can be verified, or when <see cref="VerifySignatures"/> is false.
    /// </summary>
    public bool AllowUncheckedSignatures { get; init; }

    /// <summary>Treat every scheme as one the platform cannot verify; for tests of the refusal.</summary>
    internal bool SimulateVerificationGap { get; init; }

    /// <summary>The largest message accepted from the agent, and the largest request sent to it. Default 256 KiB, the limit OpenSSH's agent applies.</summary>
    public int MaxMessageBytes { get; init; } = 256 * 1024;
}

/// <summary>A key an ssh-agent offers: what <c>ssh-add -L</c> lists.</summary>
/// <param name="PublicKey">The public key (for a certificate, the certified key), or null when the type is not one this library reads.</param>
/// <param name="KeyBlob">The key as the agent sent it: an SSH public key blob (RFC 4253 §6.6) or an OpenSSH certificate. It is what a signing request names.</param>
/// <param name="Comment">The agent's comment for the key, usually the file name or an email address.</param>
public sealed record SshAgentIdentity(SshPublicKey? PublicKey, ReadOnlyMemory<byte> KeyBlob, string Comment);

/// <summary>
/// A client for an ssh-agent (OpenSSH's, or anything speaking the SSH agent protocol: draft-ietf-sshm-ssh-agent, OpenSSH's <c>PROTOCOL.agent</c>) over its local socket. It lists the
/// agent's keys and has the agent sign; the private keys stay in the agent. Use <see cref="SshAgentKey"/> wherever a signing key is needed, and
/// <see cref="SshAgentKey.SignToSshSignature"/> for what SSHSIG and SSH authentication carry.
/// </summary>
/// <remarks>Each request opens its own short connection, so one client is safe to share between threads. A key the agent holds under confirmation constraints makes the agent ask the user; the call waits for the answer.</remarks>
[System.Runtime.Versioning.UnsupportedOSPlatform("browser")]
public sealed class SshAgentClient
{
    private const byte Failure = 5, RequestIdentities = 11, IdentitiesAnswer = 12, SignRequest = 13, SignResponse = 14;

    private readonly SshAgentOptions _options;

    /// <summary>Creates a client. Nothing connects until the first request.</summary>
    /// <param name="options">Socket and limits; null means the defaults.</param>
    public SshAgentClient(SshAgentOptions? options = null)
    {
        _options = options ?? new SshAgentOptions();
    }

    internal SshAgentOptions Options => _options;

    /// <summary>The socket this client talks to: the option, else <c>SSH_AUTH_SOCK</c>.</summary>
    /// <exception cref="AgentUnavailableException">Neither is set.</exception>
    public string SocketPath
    {
        get
        {
            string? p = _options.SocketPath ?? Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
            return string.IsNullOrEmpty(p) ? throw new AgentUnavailableException(null, "No ssh-agent socket: SSH_AUTH_SOCK is not set and no socket path was given.") : p;
        }
    }

    /// <summary>Lists the agent's keys (<c>SSH_AGENTC_REQUEST_IDENTITIES</c>).</summary>
    /// <exception cref="AgentException">The agent is not there, refused, or answered badly.</exception>
    public IReadOnlyList<SshAgentIdentity> ListIdentities() => ListIdentitiesAsync().AsTask().GetAwaiter().GetResult();

    /// <summary>The async form of <see cref="ListIdentities"/>.</summary>
    public async ValueTask<IReadOnlyList<SshAgentIdentity>> ListIdentitiesAsync(CancellationToken cancellationToken = default)
    {
        byte[] body = await ExchangeAsync([RequestIdentities], IdentitiesAnswer, cancellationToken).ConfigureAwait(false);
        return ParseIdentities(body);
    }

    internal static List<SshAgentIdentity> ParseIdentities(ReadOnlySpan<byte> body)
    {
        try
        {
            var r = new SshReader(body, "ssh-agent identities");
            r.ReadByte();
            uint count = r.ReadUInt32();
            // Each entry takes at least eight octets (two length prefixes), so the count cannot exceed what the message could hold.
            if (count > (uint)(body.Length / 8))
            {
                throw new AgentProtocolException("The agent announced more keys than its reply can hold.");
            }

            var list = new List<SshAgentIdentity>((int)count);
            for (uint i = 0; i < count; i++)
            {
                byte[] blob = r.ReadString().ToArray();
                string comment = System.Text.Encoding.UTF8.GetString(r.ReadString());
                list.Add(new SshAgentIdentity(Parse(blob), blob, comment));
            }

            r.ThrowIfNotEmpty();
            return list;
        }
        catch (SshParseException e)
        {
            throw new AgentProtocolException("The agent's key list is malformed: " + e.Message, e);
        }
    }

    private static SshPublicKey? Parse(byte[] blob)
    {
        if (SshPublicKey.TryParse(blob, out SshPublicKey? k))
        {
            return k;
        }

        return SshCertificate.TryParse(blob, out SshCertificate? cert) ? cert!.PublicKey : null;
    }

    /// <summary>Opens the agent's key for an SSH public key (<c>ssh-add -L</c> line, an <c>.pub</c> file, a certificate's key).</summary>
    /// <exception cref="AgentKeyNotFoundException">The agent does not offer the key.</exception>
    /// <exception cref="AlgorithmNotSupportedException">The key is a kind the agent interface here does not sign for (security-key types, DSA).</exception>
    public SshAgentKey GetKey(SshPublicKey publicKey) => GetKeyAsync(publicKey).AsTask().GetAwaiter().GetResult();

    /// <summary>The async form of <see cref="GetKey"/>.</summary>
    public async ValueTask<SshAgentKey> GetKeyAsync(SshPublicKey publicKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        foreach (SshAgentIdentity id in await ListIdentitiesAsync(cancellationToken).ConfigureAwait(false))
        {
            if (id.PublicKey is not null && id.PublicKey.Equals(publicKey))
            {
                return new SshAgentKey(this, id);
            }
        }

        throw new AgentKeyNotFoundException($"The ssh-agent does not hold {publicKey}.");
    }

    /// <summary>Opens the agent's key for an X.509 public key (for example a certificate's), or returns null.</summary>
    public SshAgentKey? FindKey(PublicKeyInfo publicKey) => FindKeyAsync(publicKey).AsTask().GetAwaiter().GetResult();

    /// <summary>The async form of <see cref="FindKey"/>.</summary>
    public async ValueTask<SshAgentKey?> FindKeyAsync(PublicKeyInfo publicKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        foreach (SshAgentIdentity id in await ListIdentitiesAsync(cancellationToken).ConfigureAwait(false))
        {
            if (id.PublicKey is null)
            {
                continue;
            }

            try
            {
                if (id.PublicKey.ToPublicKeyInfo().Equals(publicKey))
                {
                    return new SshAgentKey(this, id);
                }
            }
            catch (Exception e) when (e is NotSupportedException or SshParseException or ArgumentException)
            {
                // A key type with no X.509 form cannot be the one asked for.
            }
        }

        return null;
    }

    /// <summary>
    /// Has the agent sign <paramref name="data"/> with the key whose blob is <paramref name="keyBlob"/> and returns the SSH signature (RFC 4253 §6.6: a string naming the
    /// algorithm and a string holding the signature) exactly as the agent made it, unchecked. <paramref name="flags"/> is 2 for <c>rsa-sha2-256</c> and 4 for <c>rsa-sha2-512</c>.
    /// </summary>
    /// <exception cref="AgentRefusedException">The agent returned a failure (the key is not held, the user refused, a constraint forbids the use).</exception>
    /// <exception cref="AgentLimitException">The data does not fit one agent message.</exception>
    public async ValueTask<byte[]> SignRawAsync(ReadOnlyMemory<byte> keyBlob, ReadOnlyMemory<byte> data, uint flags, CancellationToken cancellationToken = default)
    {
        if ((long)keyBlob.Length + data.Length + 32 > _options.MaxMessageBytes)
        {
            throw new AgentLimitException($"The data does not fit one ssh-agent message (limit {_options.MaxMessageBytes} octets).");
        }

        using var w = new SshWriter();
        w.WriteByte(SignRequest);
        w.WriteString(keyBlob.Span);
        w.WriteString(data.Span);
        w.WriteUInt32(flags);
        byte[] body = await ExchangeAsync(w.ToArray(), SignResponse, cancellationToken).ConfigureAwait(false);
        try
        {
            var r = new SshReader(body, "ssh-agent signature");
            r.ReadByte();
            byte[] sig = r.ReadString().ToArray();
            r.ThrowIfNotEmpty();
            return sig;
        }
        catch (SshParseException e)
        {
            throw new AgentProtocolException("The agent's signature reply is malformed: " + e.Message, e);
        }
    }

    /// <summary>Sends one request message and returns the reply body, which must be of the expected type; a failure reply becomes <see cref="AgentRefusedException"/>.</summary>
    internal async Task<byte[]> ExchangeAsync(byte[] request, byte expectedType, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string path = SocketPath;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (_options.OperationTimeout != Timeout.InfiniteTimeSpan)
        {
            timeout.CancelAfter(_options.OperationTimeout);
        }

        try
        {
            using Stream stream = await AssuanSession.ConnectSocketAsync(path, _options.ConnectTimeout, timeout.Token).ConfigureAwait(false);
            return await ExchangeAsync(stream, request, expectedType, _options.MaxMessageBytes, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AgentUnavailableException(path, $"The agent did not answer within {_options.OperationTimeout}.");
        }
    }

    /// <summary>The wire exchange over an open stream: length-prefixed request, length-prefixed reply bounded by <paramref name="maxMessage"/>.</summary>
    internal static async Task<byte[]> ExchangeAsync(Stream stream, byte[] request, byte expectedType, int maxMessage, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)request.Length);
        try
        {
            await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            uint length = BinaryPrimitives.ReadUInt32BigEndian(header);
            if (length == 0 || length > (uint)maxMessage)
            {
                throw new AgentProtocolException($"The agent announced a reply of {length} octets; the limit is {maxMessage}.");
            }

            var body = new byte[length];
            await stream.ReadExactlyAsync(body, cancellationToken).ConfigureAwait(false);
            if (body[0] == Failure)
            {
                throw new AgentRefusedException(0, string.Empty);
            }

            if (body[0] != expectedType)
            {
                throw new AgentProtocolException($"The agent answered with message type {body[0]} where {expectedType} was expected.");
            }

            return body;
        }
        catch (EndOfStreamException e)
        {
            throw new AgentProtocolException("The agent closed the connection before it finished its reply.", e);
        }
        catch (IOException e)
        {
            throw new AgentProtocolException("The connection to the agent broke: " + e.Message, e);
        }
    }
}

/// <summary>
/// A signing key held by an ssh-agent: RSA (<c>rsa-sha2-256</c> and <c>rsa-sha2-512</c>; the SHA-1 <c>ssh-rsa</c> signature is never requested), ECDSA on the NIST curves and Ed25519.
/// Get one from <see cref="SshAgentClient.GetKey"/>.
/// </summary>
/// <remarks>The agent hashes the data itself, so <see cref="SignDigest"/> is not available; RSA signs with PKCS #1 v1.5 only and ECDSA with the curve's own hash (SHA-256, SHA-384, SHA-512).</remarks>
[System.Runtime.Versioning.UnsupportedOSPlatform("browser")]
public sealed class SshAgentKey : ISigningKey
{
    private readonly SshAgentClient _client;
    private readonly SshAgentIdentity _identity;

    internal SshAgentKey(SshAgentClient client, SshAgentIdentity identity)
    {
        _client = client;
        _identity = identity;
        SshKey = identity.PublicKey!;
        switch (SshKey.Type)
        {
            case SshKeyType.Rsa or SshKeyType.Ed25519 or SshKeyType.EcdsaP256 or SshKeyType.EcdsaP384 or SshKeyType.EcdsaP521:
                break;
            default:
                throw new AlgorithmNotSupportedException($"ssh-agent key type {SshKey.TypeName}", System.Runtime.InteropServices.RuntimeInformation.OSDescription, "only RSA, ECDSA and Ed25519 keys are signed for");
        }

        PublicKey = SshKey.ToPublicKeyInfo();
    }

    /// <summary>The key as an SSH public key (for a certificate, the certified key).</summary>
    public SshPublicKey SshKey { get; }

    /// <summary>The agent's comment for the key.</summary>
    public string Comment => _identity.Comment;

    /// <inheritdoc/>
    public PublicKeyInfo PublicKey { get; }

    /// <inheritdoc/>
    public KeyCapabilities Capabilities => KeyCapabilities.Sign;

    /// <inheritdoc/>
    public SignatureSpec DefaultSpec => SshKey.Type == SshKeyType.Rsa ? SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA512) : SignatureSpec.DefaultFor(PublicKey);

    /// <inheritdoc/>
    public bool Supports(SignatureSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return SshKey.Type switch
        {
            SshKeyType.Ed25519 => spec.Kind == SignatureKind.Ed25519,
            SshKeyType.Rsa => spec.Kind == SignatureKind.RsaPkcs1 && (spec.Hash == HashAlgorithmName.SHA256 || spec.Hash == HashAlgorithmName.SHA512),
            SshKeyType.EcdsaP256 => spec.Kind == SignatureKind.Ecdsa && spec.Hash == HashAlgorithmName.SHA256,
            SshKeyType.EcdsaP384 => spec.Kind == SignatureKind.Ecdsa && spec.Hash == HashAlgorithmName.SHA384,
            SshKeyType.EcdsaP521 => spec.Kind == SignatureKind.Ecdsa && spec.Hash == HashAlgorithmName.SHA512,
            _ => false,
        };
    }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec) => SignAsync(data.ToArray(), spec).AsTask().GetAwaiter().GetResult();

    /// <summary>Not available: the agent hashes the data itself.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec) => throw new NotSupportedException("An ssh-agent hashes the data itself; it cannot sign a digest.");

    /// <inheritdoc/>
    public ValueTask<byte[]> SignDigestAsync(ReadOnlyMemory<byte> digest, SignatureSpec spec, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("An ssh-agent hashes the data itself; it cannot sign a digest.");

    /// <inheritdoc/>
    public async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return (await SignCoreAsync(data, spec, cancellationToken).ConfigureAwait(false)).Signature;
    }

    private async Task<(byte[] Blob, byte[] Signature)> SignCoreAsync(ReadOnlyMemory<byte> data, SignatureSpec spec, CancellationToken cancellationToken)
    {
        if (!Supports(spec))
        {
            throw new NotSupportedException($"{spec} is not available for an ssh-agent {SshKey.TypeName} key.");
        }

        byte[] blob = await _client.SignRawAsync(_identity.KeyBlob, data, FlagsFor(spec), cancellationToken).ConfigureAwait(false);
        byte[] signature = ToSpecEncoding(blob, spec);
        if (_client.Options.VerifySignatures)
        {
            SignatureVerification v = spec.Verify(PublicKey, data.Span, signature);
            SignatureStatus status = _client.Options.SimulateVerificationGap ? SignatureStatus.AlgorithmNotSupported : v.Status;
            if (status is SignatureStatus.AlgorithmNotSupported && !_client.Options.AllowUncheckedSignatures)
            {
                throw new AlgorithmNotSupportedException(spec.ToString(), System.Runtime.InteropServices.RuntimeInformation.OSDescription, "the platform cannot verify this signature against the key's public key; AllowUncheckedSignatures releases it unchecked");
            }

            if (status is not (SignatureStatus.Valid or SignatureStatus.AlgorithmNotSupported))
            {
                throw new AgentProtocolException("The signature the agent returned does not verify against the key's public key: " + v.Reason);
            }
        }

        return (blob, signature);
    }

    /// <summary>
    /// Has the agent sign <paramref name="data"/> and returns the SSH signature blob (the string naming the algorithm followed by the string holding the signature, RFC 4253 §6.6), the
    /// form SSHSIG (OpenSSH <c>PROTOCOL.sshsig</c>) and SSH user authentication carry. The signature is checked against the key's public key unless the options turn that off.
    /// </summary>
    /// <param name="data">What to sign: for SSHSIG, the signed-data structure that wraps the message hash.</param>
    /// <param name="spec">How to sign; null means <see cref="DefaultSpec"/> (RSA with SHA-512).</param>
    public byte[] SignToSshSignature(ReadOnlySpan<byte> data, SignatureSpec? spec = null) => SignToSshSignatureAsync(data.ToArray(), spec).AsTask().GetAwaiter().GetResult();

    /// <summary>The async form of <see cref="SignToSshSignature"/>.</summary>
    public async ValueTask<byte[]> SignToSshSignatureAsync(ReadOnlyMemory<byte> data, SignatureSpec? spec = null, CancellationToken cancellationToken = default)
    {
        return (await SignCoreAsync(data, spec ?? DefaultSpec, cancellationToken).ConfigureAwait(false)).Blob;
    }

    private static uint FlagsFor(SignatureSpec spec) =>
        spec.Kind != SignatureKind.RsaPkcs1 ? 0u : spec.Hash == HashAlgorithmName.SHA256 ? 2u : 4u;

    /// <summary>Checks the algorithm name the agent put on the signature and turns the signature into the spec's encoding.</summary>
    private byte[] ToSpecEncoding(byte[] blob, SignatureSpec spec)
    {
        try
        {
            var r = new SshReader(blob, "SSH signature");
            string name = r.ReadAscii();
            ReadOnlySpan<byte> sig = r.ReadString();
            r.ThrowIfNotEmpty();
            string expected = spec.Kind switch
            {
                SignatureKind.RsaPkcs1 => spec.Hash == HashAlgorithmName.SHA256 ? "rsa-sha2-256" : "rsa-sha2-512",
                _ => SshKey.TypeName,
            };
            if (name != expected)
            {
                // Above all an agent that answers a request for rsa-sha2-* with a SHA-1 ssh-rsa signature (draft-ietf-sshm-ssh-agent §3.6.1).
                throw new AgentProtocolException($"The agent signed with {name} where {expected} was requested.");
            }

            if (spec.Kind != SignatureKind.Ecdsa)
            {
                return sig.ToArray();
            }

            // RFC 5656 §3.1.2: the ECDSA signature blob holds two mpints, r and s.
            var er = new SshReader(sig, "SSH ECDSA signature");
            ReadOnlySpan<byte> rr = er.ReadMpint(), ss = er.ReadMpint();
            er.ThrowIfNotEmpty();
            int n = (PublicKey.KeySizeBits + 7) / 8;
            if (rr.Length > n || ss.Length > n)
            {
                throw new AgentProtocolException("The agent's ECDSA signature is longer than the curve allows.");
            }

            if (spec.Format == EcdsaSignatureFormat.Der)
            {
                return DerWriter.Sequence(DerWriter.UnsignedInteger(rr), DerWriter.UnsignedInteger(ss));
            }

            var p1363 = new byte[2 * n];
            rr.CopyTo(p1363.AsSpan(n - rr.Length, rr.Length));
            ss.CopyTo(p1363.AsSpan((2 * n) - ss.Length, ss.Length));
            return p1363;
        }
        catch (SshParseException e)
        {
            throw new AgentProtocolException("The agent's signature is malformed: " + e.Message, e);
        }
    }

    /// <summary>Does nothing: the key object owns no secret and no connection.</summary>
    public void Dispose() => GC.SuppressFinalize(this);
}
