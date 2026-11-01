using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// Reads OpenPGP messages: decrypts, decompresses, writes the literal data and verifies the signatures found along the way (RFC 9580 §10.3). Input may be
/// binary or ASCII-armored. Plaintext of integrity-protected messages is released only after it authenticates: SEIPD v1 is checked whole before any
/// output (it spools to a temporary file beyond a few MiB); SEIPD v2 and OCB Encrypted Data release each chunk after its tag verifies, and a damaged,
/// reordered or truncated stream makes the read throw <see cref="PgpException"/> with <see cref="PgpFailure.CannotDecrypt"/> at the point it is detected.
/// </summary>
public static partial class PgpMessageReader
{
    /// <summary>
    /// Reads a message, writing the literal data to <paramref name="output"/> (may be null to discard it).
    /// </summary>
    /// <param name="input">The message, binary or armored. Cleartext-signed messages are handled by <see cref="VerifyCleartext"/>.</param>
    /// <param name="output">Receives the plaintext; null to discard.</param>
    /// <param name="options">Keys, passwords, reference time and policy.</param>
    /// <returns>What was found: whether it was encrypted, the literal data description and a verdict for every signature.</returns>
    /// <exception cref="PgpException">The message is malformed, cannot be decrypted, or breaks a limit; the failure class says which.</exception>
    /// <exception cref="OpenPgpParseException">A packet is malformed.</exception>
    public static PgpReadResult Read(Stream input, Stream? output, PgpReadOptions options)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(options);
        using var p = new MessageProcessor(options, output);
        using Stream binary = PgpInput.OpenBinary(input, out _);
        return p.Run(binary);
    }

    /// <summary>Verifies detached signatures over <paramref name="data"/>.</summary>
    /// <param name="data">The signed data, read once.</param>
    /// <param name="signatures">One or more signature packets, binary or armored.</param>
    /// <param name="options">Certificates, reference time and policy.</param>
    /// <exception cref="PgpException">The signature input holds no signature packet.</exception>
    public static PgpReadResult VerifyDetached(Stream data, Stream signatures, PgpReadOptions options)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signatures);
        ArgumentNullException.ThrowIfNull(options);
        CryptoPolicy policy = options.Policy ?? CryptoPolicy.Standard;
        using Stream binary = PgpInput.OpenBinary(signatures, out _);
        var sigs = new List<SignaturePacket>();
        using (var reader = new PacketReader(binary, options.Limits, leaveOpen: true))
        {
            Packet? pk;
            while ((pk = reader.ReadPacket()) is not null)
            {
                if (pk is SignaturePacket sp)
                {
                    sigs.Add(sp);
                }
                else if (pk is not (MarkerPacket or PaddingPacket))
                {
                    throw new PgpException(PgpFailure.MalformedMessage, "A detached signature holds only signature packets.");
                }
            }
        }

        if (sigs.Count == 0)
        {
            throw new PgpException(PgpFailure.MalformedMessage, "No signature packet found.");
        }

        var hashers = new List<SigHasher?>();
        foreach (SignaturePacket s in sigs)
        {
            hashers.Add(s.Type is SignatureType.Binary or SignatureType.Text ? new SigHasher(HashOrNull(s), s.Salt.Span, s.Type == SignatureType.Text) : null);
        }

        byte[] buf = Scratch.Rent();
        int n;
        while ((n = data.Read(buf, 0, buf.Length)) > 0)
        {
            foreach (SigHasher? h in hashers)
            {
                h?.Append(buf.AsSpan(0, n));
            }
        }

        Scratch.Return(buf);

        var result = new PgpReadResult();
        for (int i = 0; i < sigs.Count; i++)
        {
            byte[]? digest = hashers[i]?.Finish(sigs[i].Version, sigs[i].SignedHeader.Span);
            hashers[i]?.Dispose();
            result.SignatureList.Add(SignatureChecker.Check(sigs[i], digest, options.Certificates, policy, options.Now));
        }

        return result;
    }

    private static PgpHashAlgorithm HashOrNull(SignaturePacket s) => s.Hash;

    /// <summary>
    /// Verifies a cleartext-signed message (RFC 9580 §7) and writes the text, without the dash escaping and without the final line ending, to
    /// <paramref name="output"/>.
    /// </summary>
    /// <exception cref="PgpException">The framing is malformed.</exception>
    public static PgpReadResult VerifyCleartext(Stream input, Stream? output, PgpReadOptions options)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(options);
        return Cleartext.Verify(input, output, options);
    }

    /// <summary>
    /// Reads an inline-signed message in either form: the cleartext framework (RFC 9580 §7) or a signed message packet sequence, binary or armored.
    /// </summary>
    public static PgpReadResult ReadSigned(Stream input, Stream? output, PgpReadOptions options)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(options);
        using Stream peek = PgpInput.Peek(input, 128, out byte[] head);
        return LooksCleartext(head) ? VerifyCleartext(peek, output, options) : Read(peek, output, options);
    }

    /// <summary>True when the input starts like a cleartext-signed message. The stream is consumed; pass a copy or a buffered stream.</summary>
    internal static bool LooksCleartext(ReadOnlySpan<byte> head)
    {
        ReadOnlySpan<byte> marker = "-----BEGIN PGP SIGNED MESSAGE-----"u8;
        int i = 0;
        while (i < head.Length && head[i] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
        {
            i++;
        }

        return head[i..].StartsWith(marker);
    }
}

/// <summary>Opens input that may be armored or binary.</summary>
internal static class PgpInput
{
    internal static Stream OpenBinary(Stream input, out bool armored)
    {
        int first = input.ReadByte();
        if (first < 0)
        {
            armored = false;
            return Stream.Null;
        }

        var head = new PrefixStream([(byte)first], input);
        armored = Armor.LooksArmored((byte)first);
        return armored ? new ArmorReadStream(head, ArmorReadOptions.Lenient, leaveOpen: true) : head;
    }

    /// <summary>Reads up to <paramref name="count"/> octets and returns a stream that replays them before the rest.</summary>
    internal static Stream Peek(Stream input, int count, out byte[] head)
    {
        byte[] b = new byte[count];
        int got = 0;
        while (got < count)
        {
            int n = input.Read(b, got, count - got);
            if (n == 0)
            {
                break;
            }

            got += n;
        }

        head = b.AsSpan(0, got).ToArray();
        return new PrefixStream(head, input);
    }
}

/// <summary>A stream that yields some octets first and then another stream.</summary>
internal sealed class PrefixStream : Stream
{
    private readonly byte[] _prefix;
    private readonly Stream _rest;
    private int _pos;

    internal PrefixStream(byte[] prefix, Stream rest)
    {
        _prefix = prefix;
        _rest = rest;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (_pos < _prefix.Length)
        {
            int n = Math.Min(buffer.Length, _prefix.Length - _pos);
            _prefix.AsSpan(_pos, n).CopyTo(buffer);
            _pos += n;
            return n;
        }

        return _rest.Read(buffer);
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>Counts what passes through, for the decompression-ratio limit.</summary>
internal sealed class CountingStream : Stream
{
    private readonly Stream _inner;

    internal CountingStream(Stream inner) => _inner = inner;

    internal long Count { get; private set; }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        int n = _inner.Read(buffer);
        Count += n;
        return n;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>Limits how far a decompressor may expand: a fixed allowance plus a ratio of the compressed octets consumed.</summary>
internal sealed class InflateLimitStream : Stream
{
    private const long Allowance = 1 << 20;
    private const long Ratio = 1032; // DEFLATE cannot exceed about 1032:1 on valid data
    private readonly Stream _inflater;
    private readonly CountingStream _compressed;
    private long _out;

    internal InflateLimitStream(Stream inflater, CountingStream compressed)
    {
        _inflater = inflater;
        _compressed = compressed;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        int n = _inflater.Read(buffer);
        _out += n;
        if (_out > Allowance + (_compressed.Count * Ratio))
        {
            throw new PgpException(PgpFailure.LimitExceeded, "The compressed data expands beyond the allowed ratio.");
        }

        return n;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inflater.Dispose();
        }

        base.Dispose(disposing);
    }
}

internal sealed class MessageProcessor : IDisposable
{
    private readonly PgpReadOptions _o;
    private readonly CryptoPolicy _policy;
    private readonly Stream? _out;
    private readonly PgpReadResult _r = new();
    private readonly OpenPgpLimits _limits;
    private readonly Dictionary<PgpKey, PgpSecretKey?> _unlocked = [];
    private bool _sawLiteral;
    private bool _lockedSeen;

    internal MessageProcessor(PgpReadOptions o, Stream? output)
    {
        _o = o;
        _policy = o.Policy ?? CryptoPolicy.Standard;
        _out = output;
        _limits = o.Limits ?? OpenPgpLimits.Default;
    }

    internal PgpReadResult Run(Stream binary)
    {
        ProcessLayer(binary, 0);
        if (!_sawLiteral)
        {
            throw new PgpException(PgpFailure.MalformedMessage, "The message holds no literal data.");
        }

        if (_o.Require == PgpRequirement.Encrypted && !_r.WasEncrypted)
        {
            throw new PgpException(PgpFailure.MalformedMessage, "The message is not encrypted.");
        }

        if (_o.Require == PgpRequirement.NotEncrypted && _r.WasEncrypted)
        {
            throw new PgpException(PgpFailure.MalformedMessage, "The message is encrypted.");
        }

        return _r;
    }

    private sealed class OpsEntry
    {
        internal required OnePassSignaturePacket Op;
        internal required SigHasher Hasher;
        internal bool Matched;
    }

    private sealed class PrefixEntry
    {
        internal required SignaturePacket Sig;
        internal required SigHasher Hasher;
    }

    private void ProcessLayer(Stream s, int depth)
    {
        if (depth > _o.MaxNesting)
        {
            throw new PgpException(PgpFailure.LimitExceeded, "The message nests too deeply.");
        }

        using var reader = new PacketReader(s, _limits, leaveOpen: true);
        var pkesks = new List<PublicKeyEncryptedSessionKeyPacket>();
        var skesks = new List<SymmetricKeyEncryptedSessionKeyPacket>();
        var ops = new List<OpsEntry>();
        var prefix = new List<PrefixEntry>();
        var prefixPending = new List<SignaturePacket>();
        bool layerLiteral = false;
        bool terminal = false;
        PacketFrame? f;
        int count = 0;
        while ((f = reader.ReadFrame()) is not null)
        {
            if (++count > _limits.MaxPackets)
            {
                throw new PgpException(PgpFailure.LimitExceeded, "The message has too many packets.");
            }

            if (terminal && f.Tag is not (PacketTag.Padding or PacketTag.Marker or PacketTag.Signature))
            {
                throw new PgpException(PgpFailure.MalformedMessage, "Unexpected packet after the message body (RFC 9580 §10.3).");
            }

            switch (f.Tag)
            {
                case PacketTag.PublicKeyEncryptedSessionKey:
                    if (f.ReadPacket() is PublicKeyEncryptedSessionKeyPacket pk)
                    {
                        pkesks.Add(pk);
                    }

                    break;
                case PacketTag.SymmetricKeyEncryptedSessionKey:
                    if (f.ReadPacket() is SymmetricKeyEncryptedSessionKeyPacket sk)
                    {
                        skesks.Add(sk);
                    }

                    break;
                case PacketTag.SymmetricallyEncryptedIntegrityProtectedData:
                case PacketTag.OcbEncryptedData:
                case PacketTag.SymmetricallyEncryptedData:
                    {
                        using Stream plain = OpenEncrypted(f, pkesks, skesks);
                        ProcessLayer(plain, depth + 1);
                        terminal = true;
                        break;
                    }

                case PacketTag.CompressedData:
                    {
                        using Stream plain = OpenCompressed(f);
                        ProcessLayer(plain, depth + 1);
                        terminal = true;
                        break;
                    }

                case PacketTag.OnePassSignature:
                    {
                        if (f.ReadPacket() is OnePassSignaturePacket op)
                        {
                            bool text = op.SignatureTypeId == (byte)SignatureType.Text;
                            ops.Add(new OpsEntry { Op = op, Hasher = new SigHasher(op.Hash, op.Salt.Span, text) });
                        }

                        break;
                    }

                case PacketTag.Signature:
                    {
                        if (f.ReadPacket() is not SignaturePacket sig)
                        {
                            break;
                        }

                        if (!layerLiteral && ops.Count == 0)
                        {
                            prefixPending.Add(sig);
                        }
                        else
                        {
                            Finish(sig, ops, prefix);
                        }

                        break;
                    }

                case PacketTag.LiteralData:
                    {
                        if (_sawLiteral || layerLiteral)
                        {
                            throw new PgpException(PgpFailure.MalformedMessage, "The message holds more than one literal packet.");
                        }

                        layerLiteral = true;
                        _sawLiteral = true;
                        foreach (SignaturePacket ps in prefixPending)
                        {
                            prefix.Add(new PrefixEntry { Sig = ps, Hasher = new SigHasher(ps.Hash, ps.Salt.Span, ps.Type == SignatureType.Text) });
                        }

                        prefixPending.Clear();
                        CopyLiteral(f, ops, prefix);
                        break;
                    }

                case PacketTag.Padding:
                case PacketTag.Marker:
                    break;
                default:
                    throw new PgpException(PgpFailure.MalformedMessage, $"Unexpected packet type {(byte)f.Tag} in a message.");
            }
        }

        foreach (OpsEntry e in ops)
        {
            if (!e.Matched)
            {
                _r.SignatureList.Add(new PgpSignatureResult(PgpSigStub(e.Op), PgpSignatureStatus.Invalid, null, null,
                    ["A one-pass signature header has no matching signature packet; the message may be truncated."]));
            }

            e.Hasher.Dispose();
        }

        foreach (PrefixEntry pe in prefix)
        {
            pe.Hasher.Dispose();
        }
    }

    private static SignaturePacket PgpSigStub(OnePassSignaturePacket op)
    {
        // A signature object is needed to report on; rebuild an empty v4 stub carrying the one-pass header's identifiers.
        byte[] body = [4, op.SignatureTypeId, 0, (byte)op.Hash, 0, 0, 0, 0, 0, 0];
        return (SignaturePacket)Packet.Create((byte)PacketTag.Signature, body);
    }

    private void Finish(SignaturePacket sig, List<OpsEntry> ops, List<PrefixEntry> prefix)
    {
        byte[]? digest = null;
        foreach (OpsEntry e in ops)
        {
            if (e.Matched || !OpMatches(e.Op, sig))
            {
                continue;
            }

            e.Matched = true;
            if (sig.Version != 6 || e.Op.Salt.Span.SequenceEqual(sig.Salt.Span))
            {
                digest = e.Hasher.Finish(sig.Version, sig.SignedHeader.Span);
            }

            break;
        }

        if (digest is null)
        {
            foreach (PrefixEntry p in prefix)
            {
                if (ReferenceEquals(p.Sig, sig))
                {
                    digest = p.Hasher.Finish(sig.Version, sig.SignedHeader.Span);
                }
            }
        }

        _r.SignatureList.Add(SignatureChecker.Check(sig, digest, CertificatePool(), _policy, _o.Now));
    }

    private IReadOnlyList<PgpCertificate> CertificatePool() =>
        _o.SecretKeys.Count == 0 ? _o.Certificates : [.. _o.Certificates, .. _o.SecretKeys];

    private static bool OpMatches(OnePassSignaturePacket op, SignaturePacket sig)
    {
        if (op.SignatureTypeId != sig.SignatureTypeId || op.Hash != sig.Hash || op.Algorithm != sig.Algorithm)
        {
            return false;
        }

        if (op.Version == 6)
        {
            return sig.IssuerFingerprint is { } fp && fp.Length > 1 && fp.Span[1..].SequenceEqual(op.Fingerprint.Span);
        }

        return sig.IssuerKeyId is not { } id || id.Span.SequenceEqual(op.KeyId.Span);
    }

    private void CopyLiteral(PacketFrame f, List<OpsEntry> ops, List<PrefixEntry> prefix)
    {
        Stream body = f.Body;
        LiteralDataHeader h = LiteralDataHeader.Read(body);
        _r.LiteralFormat = h.Format;
        _r.LiteralFileName = h.FileName.ToArray();
        _r.LiteralDate = h.Date;
        byte[] buf = Scratch.Rent();
        int n;
        while ((n = body.Read(buf, 0, buf.Length)) > 0)
        {
            foreach (OpsEntry e in ops)
            {
                e.Hasher.Append(buf.AsSpan(0, n));
            }

            foreach (PrefixEntry p in prefix)
            {
                p.Hasher.Append(buf.AsSpan(0, n));
            }

            _out?.Write(buf, 0, n);
        }

        Scratch.Return(buf);
    }

    // ---- compression ----

    private static Stream OpenCompressed(PacketFrame f)
    {
        Stream body = f.Body;
        int algo = body.ReadByte();
        var counted = new CountingStream(body);
        switch ((CompressionAlgorithm)algo)
        {
            case CompressionAlgorithm.Uncompressed:
                return counted;
            case CompressionAlgorithm.Zip:
                return new InflateLimitStream(new DeflateStream(counted, CompressionMode.Decompress), counted);
            case CompressionAlgorithm.Zlib:
                return new InflateLimitStream(new ZLibStream(counted, CompressionMode.Decompress), counted);
            default:
                throw new PgpException(PgpFailure.Unsupported, $"The compression algorithm {algo} is not supported.");
        }
    }

    // ---- encryption ----

    private readonly record struct Candidate(SymmetricAlgorithm? Cipher, byte[] Key);

    private Stream OpenEncrypted(PacketFrame f, List<PublicKeyEncryptedSessionKeyPacket> pkesks, List<SymmetricKeyEncryptedSessionKeyPacket> skesks)
    {
        _r.WasEncrypted = true;
        if (f.Tag == PacketTag.SymmetricallyEncryptedData)
        {
            if (!_o.AllowUnauthenticatedEncryption)
            {
                throw new PgpException(PgpFailure.UnauthenticatedEncryption, "The message is encrypted without integrity protection and the options do not allow that.");
            }

        }

        List<Candidate> candidates = Candidates(pkesks, skesks, f);
        if (candidates.Count == 0)
        {
            if (_lockedSeen)
            {
                throw new PgpException(PgpFailure.KeyIsProtected, "A secret key that could open the message is protected and no password unlocks it.");
            }

            throw new PgpException(pkesks.Count + skesks.Count == 0 ? PgpFailure.CannotDecrypt : PgpFailure.NoDecryptionKey,
                "No supplied key or password opens the message.");
        }

        Stream body = f.Body;
        if (f.Tag == PacketTag.SymmetricallyEncryptedData)
        {
            return OpenSed(body, candidates);
        }

        int version = body.ReadByte();
        if (f.Tag == PacketTag.OcbEncryptedData)
        {
            return OpenOcbEd(body, version, candidates);
        }

        if (version == 2)
        {
            return OpenSeipd2(body, candidates);
        }

        if (version == 1)
        {
            return OpenSeipd1(body, candidates);
        }

        throw new PgpException(PgpFailure.Unsupported, "Unknown SEIPD version.");
    }

    private List<Candidate> Candidates(List<PublicKeyEncryptedSessionKeyPacket> pkesks, List<SymmetricKeyEncryptedSessionKeyPacket> skesks, PacketFrame frame)
    {
        _ = frame;
        var list = new List<Candidate>();
        foreach ((SymmetricAlgorithm c, byte[] k) in _o.SessionKeysWithCipher)
        {
            list.Add(new Candidate(c, k));
        }

        foreach (byte[] sk in _o.SessionKeys)
        {
            list.Add(new Candidate(null, sk));
        }

        foreach (PublicKeyEncryptedSessionKeyPacket p in pkesks)
        {
            foreach (PgpCertificate cert in _o.SecretKeys)
            {
                foreach (PgpKey key in cert.Keys)
                {
                    if (key.Packet is not SecretKeyPacket || !Targets(p, key))
                    {
                        continue;
                    }

                    PgpSecretKey? unlocked = Unlock(key);
                    if (unlocked is null)
                    {
                        continue;
                    }

                    SessionKeys.Recovered? rec = SessionKeys.Decrypt(unlocked, p);
                    if (rec is { } r)
                    {
                        list.Add(new Candidate(r.Cipher, r.Key));
                    }
                }
            }
        }

        foreach (SymmetricKeyEncryptedSessionKeyPacket s in skesks)
        {
            foreach (byte[] pw in _o.MessagePasswords)
            {
                Candidate? c = FromSkesk(s, pw);
                if (c is { } cc)
                {
                    list.Add(cc);
                }
            }
        }

        return list;
    }

    private static bool Targets(PublicKeyEncryptedSessionKeyPacket p, PgpKey key)
    {
        if (p.Version == 3)
        {
            ReadOnlySpan<byte> id = p.KeyId.Span;
            bool wildcard = true;
            foreach (byte b in id)
            {
                wildcard &= b == 0;
            }

            return wildcard || id.SequenceEqual(key.KeyId);
        }

        return p.RecipientKeyVersion is null || p.RecipientFingerprint.Span.SequenceEqual(key.Fingerprint);
    }

    private PgpSecretKey? Unlock(PgpKey key)
    {
        if (_unlocked.TryGetValue(key, out PgpSecretKey? have))
        {
            return have;
        }

        if (!PgpSecretKey.TryUnlock(key, _o.KeyPasswords, out PgpSecretKey? got, _policy.KdfLimits))
        {
            _lockedSeen = true;
        }

        _unlocked[key] = got;
        return got;
    }

    private Candidate? FromSkesk(SymmetricKeyEncryptedSessionKeyPacket s, byte[] password)
    {
        try
        {
            int keySize = PgpAlgorithms.KeySize(s.Cipher);
            byte[] kdf = PgpAlgorithms.S2k(s.S2k, password, keySize, _policy.KdfLimits);
            if (s.Version == 4)
            {
                if (s.EncryptedSessionKey.IsEmpty)
                {
                    return new Candidate(s.Cipher, kdf);
                }

                byte[] buf = s.EncryptedSessionKey.ToArray();
                PgpAlgorithms.CfbDecrypt(s.Cipher, kdf, new byte[16], buf);
                CryptographicOperations.ZeroMemory(kdf);
                if (buf.Length < 2)
                {
                    return null;
                }

                return new Candidate((SymmetricAlgorithm)buf[0], buf.AsSpan(1).ToArray());
            }

            if (s.Version == 6)
            {
                // RFC 9580 §5.3.2: the KEK is HKDF-SHA256 over the S2K output with info = packet tag, version, cipher and AEAD.
                AeadAlgorithm aead = s.Aead!.Value;
                byte[] info = [0xC3, 6, (byte)s.Cipher, (byte)aead];
                byte[] kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, kdf, keySize, [], info);
                CryptographicOperations.ZeroMemory(kdf);
                ReadOnlySpan<byte> data = s.EncryptedSessionKey.Span;
                if (data.Length < 16 + 16)
                {
                    return null;
                }

                byte[] key = new byte[data.Length - 16];
                using var a = new PgpAlgorithms.Aead(aead, kek);
                CryptographicOperations.ZeroMemory(kek);
                return a.TryDecrypt(s.Iv.Span, data[..^16], data[^16..], key, info) ? new Candidate(null, key) : null;
            }

            if (s.Version == 5)
            {
                // LibrePGP §5.3: version 5 uses the S2K output directly as the AEAD key (OCB); the additional data is 0xC3, 5, cipher, mode.
                AeadAlgorithm aead = s.Aead!.Value;
                byte[] info = [0xC3, 5, (byte)s.Cipher, (byte)aead];
                ReadOnlySpan<byte> data = s.EncryptedSessionKey.Span;
                if (data.Length < 16 + 16)
                {
                    CryptographicOperations.ZeroMemory(kdf);
                    return null;
                }

                byte[] key = new byte[data.Length - 16];
                using var a = new PgpAlgorithms.Aead(aead, kdf);
                CryptographicOperations.ZeroMemory(kdf);
                return a.TryDecrypt(s.Iv.Span, data[..^16], data[^16..], key, info) ? new Candidate(null, key) : null;
            }

            return null;
        }
        catch (PgpException e) when (e.Failure == PgpFailure.Unsupported)
        {
            return null;
        }
    }

    private static byte[] ReadUpTo(Stream s, int count)
    {
        byte[] b = new byte[count];
        int got = 0;
        while (got < count)
        {
            int n = s.Read(b, got, count - got);
            if (n == 0)
            {
                break;
            }

            got += n;
        }

        return got == count ? b : b.AsSpan(0, got).ToArray();
    }

    private AeadChunkReader OpenSeipd2(Stream body, List<Candidate> candidates)
    {
        byte[] head = ReadUpTo(body, 3 + 32);
        if (head.Length < 35)
        {
            throw new PgpException(PgpFailure.CannotDecrypt, "The encrypted data could not be decrypted.");
        }

        var cipher = (SymmetricAlgorithm)head[0];
        var aead = (AeadAlgorithm)head[1];
        byte chunkOctet = head[2];
        if (chunkOctet > 16)
        {
            throw new PgpException(PgpFailure.LimitExceeded, "The chunk size is larger than RFC 9580 §5.13.2 allows.");
        }

        _ = PgpAlgorithms.KeySize(cipher);
        _ = PgpAlgorithms.NonceSize(aead);
        return OpenAead(body, candidates, key => AeadFraming.ForSeipd2(cipher, aead, chunkOctet, key, head.AsSpan(3)), key => key.Length == PgpAlgorithms.KeySize(cipher), cipher);
    }

    private AeadChunkReader OpenOcbEd(Stream body, int version, List<Candidate> candidates)
    {
        if (version != 1)
        {
            throw new PgpException(PgpFailure.Unsupported, "Unknown OCB Encrypted Data version.");
        }

        byte[] head = ReadUpTo(body, 3);
        if (head.Length < 3)
        {
            throw new PgpException(PgpFailure.CannotDecrypt, "The encrypted data could not be decrypted.");
        }

        var cipher = (SymmetricAlgorithm)head[0];
        var aead = (AeadAlgorithm)head[1];
        byte chunkOctet = head[2];
        if (aead is not (AeadAlgorithm.Ocb or AeadAlgorithm.Eax) || chunkOctet > 16)
        {
            throw new PgpException(PgpFailure.LimitExceeded, "The OCB Encrypted Data parameters are not acceptable.");
        }

        int ivSize = PgpAlgorithms.NonceSize(aead);
        byte[] iv = ReadUpTo(body, ivSize);
        if (iv.Length < ivSize)
        {
            throw new PgpException(PgpFailure.CannotDecrypt, "The encrypted data could not be decrypted.");
        }

        // LibrePGP §5.16: the session key is the key itself; the associated data is the new-format tag, version, cipher, mode, chunk size and chunk index.
        byte[] adHead = [0xD4, 1, (byte)cipher, (byte)aead, chunkOctet];
        return OpenAead(body, candidates, key => new AeadFraming(aead, chunkOctet, key, iv, adHead, true), key => key.Length == PgpAlgorithms.KeySize(cipher), cipher);
    }

    private AeadChunkReader OpenAead(Stream body, List<Candidate> candidates, Func<byte[], AeadFraming> framingFor, Func<byte[], bool> keyFits, SymmetricAlgorithm cipher)
    {
        // Read enough to authenticate the first chunk with each candidate key, then replay it in front of the rest.
        AeadFraming probeSample = framingFor(candidates[0].Key.Length == PgpAlgorithms.KeySize(cipher) ? candidates[0].Key : new byte[PgpAlgorithms.KeySize(cipher)]);
        byte[] window = ReadUpTo(body, probeSample.ChunkSize + 32);
        foreach (Candidate c in candidates)
        {
            if (!keyFits(c.Key))
            {
                continue;
            }

            AeadFraming framing = framingFor(c.Key);
            try
            {
                using var probe = new AeadChunkReader(new MemoryStream(window), framing);
                _ = probe.ReadByte();
            }
            catch (PgpException)
            {
                continue;
            }

            _r.SessionKey = (byte[])c.Key.Clone();
            _r.SessionKeyCipher = cipher;
            return new AeadChunkReader(new PrefixStream(window, body), framing);
        }

        throw new PgpException(PgpFailure.CannotDecrypt, "The encrypted data could not be decrypted.");
    }

    /// <summary>Opens old Symmetrically Encrypted Data. The caller has opted in; the plaintext is not authenticated and the report says so.</summary>
    private SedDecryptStream OpenSed(Stream body, List<Candidate> candidates)
    {
        byte[] head = ReadUpTo(body, 18);
        foreach (Candidate c in candidates)
        {
            if (c.Cipher is not { } cipher || !Supported(cipher) || c.Key.Length != PgpAlgorithms.KeySize(cipher))
            {
                continue;
            }

            SedDecryptStream? s = SedDecryptStream.TryOpen(head, body, cipher, c.Key);
            if (s is not null)
            {
                _r.SessionKey = (byte[])c.Key.Clone();
                _r.SessionKeyCipher = cipher;
                return s;
            }
        }

        throw new PgpException(PgpFailure.CannotDecrypt, "The encrypted data could not be decrypted.");
    }

    private SpoolStream OpenSeipd1(Stream body, List<Candidate> candidates)
    {
        // RFC 9580 §5.13.1: the random prefix is one block, followed by two repeated octets. Which cipher it is comes from the candidates,
        // so read enough for the widest block.
        byte[] head = ReadUpTo(body, 18);
        if (head.Length < 10)
        {
            throw new PgpException(PgpFailure.CannotDecrypt, "The encrypted data could not be decrypted.");
        }

        Candidate? chosen = null;
        foreach (Candidate c in candidates)
        {
            if (c.Cipher is not { } cipher || !Supported(cipher) || c.Key.Length != PgpAlgorithms.KeySize(cipher) || head.Length < PgpAlgorithms.BlockSize(cipher) + 2)
            {
                continue;
            }

            // RFC 9580 §5.13.1: the two octets after the random block repeat its last two; a cheap filter among several candidate keys.
            int bsz = PgpAlgorithms.BlockSize(cipher);
            byte[] t = head.AsSpan(0, bsz + 2).ToArray();
            PgpAlgorithms.CfbDecrypt(cipher, c.Key, new byte[16], t);
            if (t[bsz - 2] == t[bsz] && t[bsz - 1] == t[bsz + 1])
            {
                chosen = c;
                break;
            }
        }

        if (chosen is not { } ch)
        {
            // Without the cipher (a bare session key) we cannot even try; with a mismatch nothing opens it.
            throw new PgpException(PgpFailure.CannotDecrypt, "The encrypted data could not be decrypted.");
        }

        var spool = new SpoolStream();
        SymmetricAlgorithm chCipher = ch.Cipher!.Value;
        int blk = PgpAlgorithms.BlockSize(chCipher);
        byte[] iv = new byte[16];
        using IncrementalHash sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        // The 18 octets already read are part of the CFB stream, so they go back in front of the rest.
        body = new PrefixStream(head, body);
        byte[] tail = new byte[22];
        int tailLen = 0;
        byte[] buf = Scratch.Rent();
        int carryLen = 0;
        while (true)
        {
            // CFB runs over whole blocks except at the very end, so a partial block is carried to the next read.
            int n = body.Read(buf, carryLen, buf.Length - carryLen);
            if (n == 0)
            {
                break;
            }

            int total = carryLen + n;
            int whole = total - (total % blk);
            PgpAlgorithms.CfbDecrypt(chCipher, ch.Key, iv, buf.AsSpan(0, whole));
            Absorb(buf.AsSpan(0, whole), tail, ref tailLen, sha1, spool);
            carryLen = total - whole;
            buf.AsSpan(whole, carryLen).CopyTo(buf);
        }

        if (carryLen > 0)
        {
            byte[] last = buf.AsSpan(0, carryLen).ToArray();
            PgpAlgorithms.CfbDecrypt(chCipher, ch.Key, iv, last);
            Absorb(last, tail, ref tailLen, sha1, spool);
        }

        Scratch.Return(buf);

        if (tailLen != 22 || tail[0] != 0xD3 || tail[1] != 0x14)
        {
            spool.Dispose();
            throw new PgpException(PgpFailure.CannotDecrypt, "The encrypted data could not be decrypted.");
        }

        sha1.AppendData(tail.AsSpan(0, 2));
        byte[] digest = sha1.GetHashAndReset();
        if (!CryptographicOperations.FixedTimeEquals(digest, tail.AsSpan(2, 20)))
        {
            spool.Dispose();
            throw new PgpException(PgpFailure.CannotDecrypt, "The encrypted data could not be decrypted.");
        }

        _r.SessionKey = (byte[])ch.Key.Clone();
        _r.SessionKeyCipher = ch.Cipher;
        _r.CheckedBeforeRelease = true;
        // The first block and two check octets are the random prefix, not message content.
        spool.Position = blk + 2;
        return spool;
    }

    private static bool Supported(SymmetricAlgorithm c) => c is SymmetricAlgorithm.Idea or SymmetricAlgorithm.TripleDes or SymmetricAlgorithm.Cast5 or SymmetricAlgorithm.Blowfish
        or SymmetricAlgorithm.Aes128 or SymmetricAlgorithm.Aes192 or SymmetricAlgorithm.Aes256 or SymmetricAlgorithm.Twofish
        or SymmetricAlgorithm.Camellia128 or SymmetricAlgorithm.Camellia192 or SymmetricAlgorithm.Camellia256;

    // Hashes everything except the last 22 octets (the MDC packet) and spools the same octets.
    private static void Absorb(ReadOnlySpan<byte> data, byte[] tail, ref int tailLen, IncrementalHash sha1, Stream spool)
    {
        if (data.IsEmpty)
        {
            return;
        }

        // Merge the held-back tail with the new data, keep the final 22 octets, release the rest.
        int total = tailLen + data.Length;
        if (total <= 22)
        {
            data.CopyTo(tail.AsSpan(tailLen));
            tailLen = total;
            return;
        }

        int release = total - 22;
        int fromTail = Math.Min(tailLen, release);
        if (fromTail > 0)
        {
            sha1.AppendData(tail.AsSpan(0, fromTail));
            spool.Write(tail.AsSpan(0, fromTail));
        }

        int fromData = release - fromTail;
        if (fromData > 0)
        {
            sha1.AppendData(data[..fromData]);
            spool.Write(data[..fromData]);
        }

        // New tail: what remains of the old tail, then the rest of the data.
        byte[] newTail = new byte[22];
        int keepOld = tailLen - fromTail;
        tail.AsSpan(fromTail, keepOld).CopyTo(newTail);
        data[fromData..].CopyTo(newTail.AsSpan(keepOld));
        newTail.CopyTo(tail, 0);
        tailLen = 22;
    }

    public void Dispose()
    {
        foreach (PgpSecretKey? k in _unlocked.Values)
        {
            k?.Dispose();
        }

        _unlocked.Clear();
    }
}
