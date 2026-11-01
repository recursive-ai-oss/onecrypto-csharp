using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>One signature in the making: the header is fixed up front (so a one-pass header can be written first), the hash is fed the data, and
/// <see cref="Complete"/> signs the digest.</summary>
internal sealed class SignatureBuilder : IDisposable
{
    private readonly PgpSecretKey _key;
    private readonly PgpHashAlgorithm _hash;
    private readonly SignatureType _type;

    internal SignatureBuilder(PgpSecretKey key, SignatureType type, PgpHashAlgorithm? hash, DateTimeOffset now, CryptoPolicy policy)
    {
        _key = key;
        _type = type;
        KeyPacket kp = key.Key.Packet;
        _hash = hash ?? DefaultHash(kp);
        PolicyDecision d = policy.CheckHash(PgpAlgorithms.HashName(_hash), CryptoUse.Sign, now);
        if (d.Verdict == PolicyVerdict.Rejected)
        {
            throw new PgpException(PgpFailure.PolicyViolation, d.Reason);
        }

        Version = kp.Version == 6 ? (byte)6 : (byte)4;
        if (kp.Version is not (4 or 6))
        {
            throw new PgpException(PgpFailure.Unsupported, "Only version 4 and version 6 keys sign.");
        }

        Salt = Version == 6 ? RandomNumberGenerator.GetBytes(SignatureEngine.SaltLength(_hash)) : [];
        var hashed = new List<SignatureSubpacket>
        {
            SignatureSubpacket.Create((byte)SubpacketType.SignatureCreationTime, false, PgpTime.FourOctets(now)),
            SignatureSubpacket.Create((byte)SubpacketType.IssuerFingerprint, false, new byte[] { kp.Version }.Concat(kp.GetFingerprint()).ToArray()),
        };
        var unhashed = new List<SignatureSubpacket>();
        if (Version == 4)
        {
            unhashed.Add(SignatureSubpacket.Create((byte)SubpacketType.IssuerKeyId, false, kp.GetKeyId()));
        }

        byte[] hashedRaw = SubpacketArea.Create(hashed).Raw.ToArray();
        _unhashedRaw = SubpacketArea.Create(unhashed).Raw.ToArray();
        var head = new List<byte> { Version, (byte)type, (byte)kp.Algorithm, (byte)_hash };
        if (Version == 6)
        {
            head.AddRange(BigEndian32(hashedRaw.Length));
        }
        else
        {
            head.AddRange(BigEndian16(hashedRaw.Length));
        }

        head.AddRange(hashedRaw);
        SignedHeader = head.ToArray();
        Hasher = new SigHasher(_hash, Salt, type == SignatureType.Text);
    }

    private readonly byte[] _unhashedRaw;

    internal byte Version { get; }

    internal byte[] Salt { get; }

    internal byte[] SignedHeader { get; }

    internal SigHasher Hasher { get; }

    internal PgpHashAlgorithm Hash => _hash;

    internal PgpKey Key => _key.Key;

    private static byte[] BigEndian32(int v)
    {
        byte[] b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, (uint)v);
        return b;
    }

    private static byte[] BigEndian16(int v)
    {
        byte[] b = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(b, (ushort)v);
        return b;
    }

    // Default hashes: SHA-512 for the curve and RSA families, and the hash that matches the NIST curve's size for ECDSA.
    private static PgpHashAlgorithm DefaultHash(KeyPacket kp)
    {
        if (kp.Algorithm == PublicKeyAlgorithm.Ecdsa && SignatureEngine.Curves.TryFind(kp.Material.CurveOid.Span, out int size))
        {
            return size switch
            {
                32 => PgpHashAlgorithm.Sha256,
                48 => PgpHashAlgorithm.Sha384,
                _ => PgpHashAlgorithm.Sha512,
            };
        }

        return PgpHashAlgorithm.Sha512;
    }

    /// <summary>Finishes the hash, signs the digest through the key's <see cref="ISigningKey"/> and returns the signature packet.</summary>
    internal Packet Complete()
    {
        byte[] digest = Hasher.Finish(Version, SignedHeader);
        ISigningKey signer = _key.SigningKey;
        HashAlgorithmName hn = PgpAlgorithms.HashName(_hash);
        KeyPacket kp = _key.Key.Packet;
        byte[] material;
        switch (kp.Algorithm)
        {
            case PublicKeyAlgorithm.Ed25519:
                material = signer.Sign(digest, SignatureSpec.Ed25519());
                break;
            case PublicKeyAlgorithm.Ed448:
                material = signer.Sign(digest, SignatureSpec.Ed448());
                break;
            case PublicKeyAlgorithm.EdDsaLegacy:
                {
                    byte[] raw = signer.Sign(digest, SignatureSpec.Ed25519());
                    material = [.. SignatureEngine.Mpi(raw.AsSpan(0, 32)), .. SignatureEngine.Mpi(raw.AsSpan(32, 32))];
                    break;
                }

            case PublicKeyAlgorithm.Rsa:
            case PublicKeyAlgorithm.RsaSignOnly:
                material = SignatureEngine.Mpi(signer.SignDigest(digest, SignatureSpec.RsaPkcs1(hn)));
                break;
            case PublicKeyAlgorithm.Ecdsa:
                {
                    byte[] rs = signer.SignDigest(digest, SignatureSpec.Ecdsa(hn, EcdsaSignatureFormat.Rfc4754));
                    int half = rs.Length / 2;
                    material = [.. SignatureEngine.Mpi(rs.AsSpan(0, half)), .. SignatureEngine.Mpi(rs.AsSpan(half))];
                    break;
                }

            default:
                throw new PgpException(PgpFailure.KeyCannotPerform, $"The key algorithm {(byte)kp.Algorithm} cannot sign.");
        }

        var body = new List<byte>(SignedHeader);
        if (Version == 6)
        {
            body.AddRange(BigEndian32(_unhashedRaw.Length));
        }
        else
        {
            body.AddRange(BigEndian16(_unhashedRaw.Length));
        }

        body.AddRange(_unhashedRaw);
        body.Add(digest[0]);
        body.Add(digest[1]);
        if (Version == 6)
        {
            body.Add((byte)Salt.Length);
            body.AddRange(Salt);
        }

        body.AddRange(material);
        return Packet.Create((byte)PacketTag.Signature, body.ToArray());
    }

    /// <summary>The one-pass signature header for this signature (RFC 9580 §5.4).</summary>
    internal Packet OnePass(bool last)
    {
        KeyPacket kp = _key.Key.Packet;
        var body = new List<byte> { Version == 6 ? (byte)6 : (byte)3, (byte)_type, (byte)_hash, (byte)kp.Algorithm };
        if (Version == 6)
        {
            body.Add((byte)Salt.Length);
            body.AddRange(Salt);
            body.AddRange(kp.GetFingerprint());
        }
        else
        {
            body.AddRange(kp.GetKeyId());
        }

        body.Add(last ? (byte)1 : (byte)0);
        return Packet.Create((byte)PacketTag.OnePassSignature, body.ToArray());
    }

    public void Dispose() => Hasher.Dispose();
}

/// <summary>Settings for writing signed and encrypted messages.</summary>
public sealed class PgpWriteOptions
{
    /// <summary>The signing time and the time recipients' keys are judged at. Required; there is no default clock.</summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>Keys that sign the message (inline, one-pass) or the data (detached and cleartext).</summary>
    public IReadOnlyList<PgpSecretKey> Signers { get; init; } = [];

    /// <summary>Certificates to encrypt to. A subkey that is valid at <see cref="Now"/> and may encrypt is chosen from each.</summary>
    public IReadOnlyList<PgpCertificate> Recipients { get; init; } = [];

    /// <summary>Passwords (UTF-8 octets) that can also open the message.</summary>
    public IReadOnlyList<byte[]> Passwords { get; init; } = [];

    /// <summary>True to treat the data as text: the literal packet is format 't' and signatures are text signatures (canonical line endings).</summary>
    public bool Text { get; init; }

    /// <summary>The hash for new signatures; chosen from the signing key when null.</summary>
    public PgpHashAlgorithm? SignatureHash { get; init; }

    /// <summary>The file name recorded in the literal packet (at most 255 octets). Empty by default.</summary>
    public byte[] FileName { get; init; } = [];

    /// <summary>The date recorded in the literal packet (seconds since 1970). Zero by default.</summary>
    public uint LiteralDate { get; init; }

    /// <summary>True to wrap the output in ASCII armor. Default false.</summary>
    public bool Armor { get; init; }

    /// <summary>The policy for new signatures. <see cref="CryptoPolicy.Standard"/> when null.</summary>
    public CryptoPolicy? Policy { get; init; }

    /// <summary>The compression for the literal data. Default <see cref="CompressionAlgorithm.Uncompressed"/>.</summary>
    public CompressionAlgorithm Compression { get; init; }

    /// <summary>True to force integrity protection with SEIPD v1 (MDC) instead of choosing from the recipients' features. Default false.</summary>
    public bool ForceSeipd1 { get; init; }
}

/// <summary>Writes OpenPGP messages: signed (one-pass), encrypted, or both, streaming in constant memory.</summary>
public static class PgpMessageWriter
{
    // 2^12 * 64 = 256 KiB chunks.
    private const byte ChunkOctet = 12;

    /// <summary>
    /// Writes <paramref name="plaintext"/> as a message: literal data, wrapped in one-pass signatures when <see cref="PgpWriteOptions.Signers"/> are given,
    /// and encrypted when recipients or passwords are given. With neither, only a literal packet (and signatures) is written.
    /// </summary>
    /// <exception cref="PgpException">A recipient has no usable encryption key, a key cannot sign, or the policy refuses the choice.</exception>
    public static void Write(Stream plaintext, Stream output, PgpWriteOptions options)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(options);
        CryptoPolicy policy = options.Policy ?? CryptoPolicy.Standard;
        ArmorWriteStream? armor = options.Armor ? new ArmorWriteStream(output, "PGP MESSAGE", leaveOpen: true) : null;
        Stream sink = armor ?? output;
        try
        {
            bool encrypt = options.Recipients.Count + options.Passwords.Count > 0;
            if (encrypt)
            {
                WriteEncrypted(plaintext, sink, options, policy);
            }
            else
            {
                WriteInner(plaintext, sink, options, policy);
            }

            armor?.Complete();
        }
        finally
        {
            armor?.Dispose();
        }
    }

    private static void WriteEncrypted(Stream plaintext, Stream sink, PgpWriteOptions o, CryptoPolicy policy)
    {
        var keys = new List<PgpKey>();
        foreach (PgpCertificate c in o.Recipients)
        {
            keys.Add(EncryptionKey(c, o.Now));
        }

        // Defaults come from the recipients' keys (RFC 9580 §5.2.3.32): v2 SEIPD only when every key announces it or is itself version 6.
        bool v2 = !o.ForceSeipd1 && keys.All(k => k.Packet.Version == 6 || (k.Features(o.Now) & 0x08) != 0);
        if (v2 && keys.Any(k => k.Packet.Version == 5))
        {
            v2 = false;
        }

        SymmetricAlgorithm cipher = SymmetricAlgorithm.Aes256;
        AeadAlgorithm aead = AeadAlgorithm.Ocb;
        if (v2)
        {
            (cipher, aead) = ChooseSuite(keys, o.Now);
        }

        PolicyDecision pd = policy.CheckContentCipher("AES-" + (PgpAlgorithms.KeySize(cipher) * 8), CryptoUse.Encrypt);
        if (pd.Verdict == PolicyVerdict.Rejected)
        {
            throw new PgpException(PgpFailure.PolicyViolation, pd.Reason);
        }

        byte[] sessionKey = RandomNumberGenerator.GetBytes(PgpAlgorithms.KeySize(cipher));
        try
        {
            foreach (PgpKey k in keys)
            {
                SessionKeys.Encrypt(k, sessionKey, cipher, v2 ? 6 : 3).WriteTo(sink);
            }

            foreach (byte[] pw in o.Passwords)
            {
                Skesk(pw, sessionKey, cipher, aead, v2, policy).WriteTo(sink);
            }

            if (v2)
            {
                byte[] salt = RandomNumberGenerator.GetBytes(32);
                AeadFraming framing = AeadFraming.ForSeipd2(cipher, aead, ChunkOctet, sessionKey, salt);
                using var body = new PacketBodyWriter(sink, PacketTag.SymmetricallyEncryptedIntegrityProtectedData);
                body.Write([2, (byte)cipher, (byte)aead, ChunkOctet]);
                body.Write(salt);
                using (var enc = new AeadChunkWriter(body, framing))
                {
                    WriteInner(plaintext, enc, o, policy);
                    // RFC 9580 §5.14: padding hides the length; the packet goes inside the encrypted layer after the message.
                    byte[] pad = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(16, 256));
                    Packet.Create((byte)PacketTag.Padding, pad).WriteTo(enc);
                    enc.Complete();
                }

                body.Complete();
            }
            else
            {
                using var body = new PacketBodyWriter(sink, PacketTag.SymmetricallyEncryptedIntegrityProtectedData);
                body.Write([1]);
                using (var enc = new CfbMdcWriter(body, sessionKey))
                {
                    WriteInner(plaintext, enc, o, policy);
                    enc.Complete();
                }

                body.Complete();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKey);
        }
    }

    private static PgpKey EncryptionKey(PgpCertificate c, DateTimeOffset now)
    {
        PgpKey? best = null;
        foreach (PgpKey k in c.Keys)
        {
            PgpKeyState st = k.StateAt(now);
            bool algOk = k.Algorithm is PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaEncryptOnly or PublicKeyAlgorithm.Ecdh or PublicKeyAlgorithm.X25519 or PublicKeyAlgorithm.X448;
            if (!st.IsValid || !algOk || (st.Usage & (PgpKeyUsage.EncryptCommunications | PgpKeyUsage.EncryptStorage)) == 0)
            {
                continue;
            }

            if (best is null || k.Packet.CreationTime > best.Packet.CreationTime)
            {
                best = k;
            }
        }

        return best ?? throw new PgpException(PgpFailure.KeyCannotPerform, "The certificate has no valid key that can encrypt.");
    }

    // RFC 9580 §5.2.3.15: pick the first suite every recipient that lists preferences accepts; AES-256/OCB when nobody lists any.
    private static (SymmetricAlgorithm, AeadAlgorithm) ChooseSuite(List<PgpKey> keys, DateTimeOffset now)
    {
        (SymmetricAlgorithm, AeadAlgorithm)[] order =
        [
            (SymmetricAlgorithm.Aes256, AeadAlgorithm.Ocb), (SymmetricAlgorithm.Aes128, AeadAlgorithm.Ocb),
            (SymmetricAlgorithm.Aes256, AeadAlgorithm.Eax), (SymmetricAlgorithm.Aes128, AeadAlgorithm.Eax),
            (SymmetricAlgorithm.Aes256, AeadAlgorithm.Gcm), (SymmetricAlgorithm.Aes128, AeadAlgorithm.Gcm),
        ];
        foreach ((SymmetricAlgorithm c, AeadAlgorithm a) in order)
        {
            bool all = true;
            foreach (PgpKey k in keys)
            {
                ReadOnlyMemory<byte> prefs = k.PreferredAeadSuites(now);
                if (prefs.IsEmpty)
                {
                    // RFC 9580 §9.6: without a list, AES-128 with OCB is the only suite a recipient is known to support.
                    all &= c == SymmetricAlgorithm.Aes128 && a == AeadAlgorithm.Ocb || (c == SymmetricAlgorithm.Aes256 && a == AeadAlgorithm.Ocb && k.Packet.Version == 6);
                    continue;
                }

                bool found = false;
                for (int i = 0; i + 1 < prefs.Length; i += 2)
                {
                    found |= prefs.Span[i] == (byte)c && prefs.Span[i + 1] == (byte)a;
                }

                all &= found;
            }

            if (all)
            {
                return (c, a);
            }
        }

        return (SymmetricAlgorithm.Aes128, AeadAlgorithm.Ocb);
    }

    private static Packet Skesk(byte[] password, byte[] sessionKey, SymmetricAlgorithm cipher, AeadAlgorithm aead, bool v2, CryptoPolicy policy)
    {
        int keySize = PgpAlgorithms.KeySize(cipher);
        if (v2)
        {
            // RFC 9580 §3.7.1.4: Argon2id with the second recommended parameter set (t=3, p=4, 64 MiB) keeps the cost modest on small machines.
            byte[] s2kBytes = [(byte)S2kType.Argon2, .. RandomNumberGenerator.GetBytes(16), 3, 4, 16];
            S2kSpecifier s2k = S2kSpecifier.Parse(s2kBytes, out _);
            byte[] kdf = PgpAlgorithms.S2k(s2k, password, keySize, policy.KdfLimits);
            byte[] info = [0xC3, 6, (byte)cipher, (byte)aead];
            byte[] kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, kdf, keySize, [], info);
            CryptographicOperations.ZeroMemory(kdf);
            byte[] iv = RandomNumberGenerator.GetBytes(PgpAlgorithms.NonceSize(aead));
            byte[] ct = new byte[sessionKey.Length];
            byte[] tag = new byte[16];
            using (var a = new PgpAlgorithms.Aead(aead, kek))
            {
                a.Encrypt(iv, sessionKey, ct, tag, info);
            }

            CryptographicOperations.ZeroMemory(kek);
            int fields = 1 + 1 + 1 + s2kBytes.Length + iv.Length;
            return Packet.Create((byte)PacketTag.SymmetricKeyEncryptedSessionKey,
                (byte[])[6, (byte)fields, (byte)cipher, (byte)aead, (byte)s2kBytes.Length, .. s2kBytes, .. iv, .. ct, .. tag]);
        }
        else
        {
            byte[] s2kBytes = [(byte)S2kType.IteratedSalted, (byte)PgpHashAlgorithm.Sha256, .. RandomNumberGenerator.GetBytes(8), 0xCA];
            S2kSpecifier s2k = S2kSpecifier.Parse(s2kBytes, out _);
            byte[] kdf = PgpAlgorithms.S2k(s2k, password, keySize, policy.KdfLimits);
            byte[] enc = [(byte)cipher, .. sessionKey];
            PgpAlgorithms.CfbEncrypt(kdf, new byte[16], enc);
            CryptographicOperations.ZeroMemory(kdf);
            return Packet.Create((byte)PacketTag.SymmetricKeyEncryptedSessionKey, (byte[])[4, (byte)cipher, .. s2kBytes, .. enc]);
        }
    }

    /// <summary>The inner message: optional compression, optional one-pass signatures around a streamed literal packet.</summary>
    private static void WriteInner(Stream plaintext, Stream sink, PgpWriteOptions o, CryptoPolicy policy)
    {
        if (o.Compression != CompressionAlgorithm.Uncompressed)
        {
            throw new PgpException(PgpFailure.Unsupported, "Writing compressed data is not supported yet.");
        }

        var builders = new List<SignatureBuilder>();
        try
        {
            SignatureType sigType = o.Text ? SignatureType.Text : SignatureType.Binary;
            foreach (PgpSecretKey k in o.Signers)
            {
                builders.Add(new SignatureBuilder(k, sigType, o.SignatureHash, o.Now, policy));
            }

            for (int i = 0; i < builders.Count; i++)
            {
                builders[i].OnePass(last: i == builders.Count - 1).WriteTo(sink);
            }

            using (var lit = new PacketBodyWriter(sink, PacketTag.LiteralData))
            {
                lit.Write([o.Text ? (byte)'t' : (byte)'b', (byte)o.FileName.Length]);
                lit.Write(o.FileName);
                byte[] date = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(date, o.LiteralDate);
                lit.Write(date);
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = plaintext.Read(buf, 0, buf.Length)) > 0)
                {
                    foreach (SignatureBuilder b in builders)
                    {
                        b.Hasher.Append(buf.AsSpan(0, n));
                    }

                    lit.Write(buf.AsSpan(0, n));
                }

                lit.Complete();
            }

            // RFC 9580 §10.3: the signatures follow in the reverse order of their one-pass headers.
            for (int i = builders.Count - 1; i >= 0; i--)
            {
                builders[i].Complete().WriteTo(sink);
            }
        }
        finally
        {
            foreach (SignatureBuilder b in builders)
            {
                b.Dispose();
            }
        }
    }

    /// <summary>Writes a detached signature over <paramref name="data"/> by every signer in <see cref="PgpWriteOptions.Signers"/>.</summary>
    /// <exception cref="PgpException">No signer is given, or a key cannot sign.</exception>
    public static void SignDetached(Stream data, Stream output, PgpWriteOptions options)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(options);
        if (options.Signers.Count == 0)
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "No signing key was given.");
        }

        CryptoPolicy policy = options.Policy ?? CryptoPolicy.Standard;
        SignatureType sigType = options.Text ? SignatureType.Text : SignatureType.Binary;
        var builders = options.Signers.Select(k => new SignatureBuilder(k, sigType, options.SignatureHash, options.Now, policy)).ToList();
        try
        {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = data.Read(buf, 0, buf.Length)) > 0)
            {
                foreach (SignatureBuilder b in builders)
                {
                    b.Hasher.Append(buf.AsSpan(0, n));
                }
            }

            ArmorWriteStream? armor = options.Armor ? new ArmorWriteStream(output, "PGP SIGNATURE", leaveOpen: true) : null;
            Stream sink = armor ?? output;
            foreach (SignatureBuilder b in builders)
            {
                b.Complete().WriteTo(sink);
            }

            armor?.Complete();
            armor?.Dispose();
        }
        finally
        {
            foreach (SignatureBuilder b in builders)
            {
                b.Dispose();
            }
        }
    }

    /// <summary>
    /// Writes a cleartext-signed message (RFC 9580 §7): the dash-escaped text, then armored signatures by every signer. Trailing spaces and tabs on
    /// each line are not signed, and the final line ending is not part of the text. Version 4 signatures name their hash in a <c>Hash:</c> header.
    /// </summary>
    public static void SignCleartext(Stream text, Stream output, PgpWriteOptions options)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(options);
        if (options.Signers.Count == 0)
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "No signing key was given.");
        }

        CryptoPolicy policy = options.Policy ?? CryptoPolicy.Standard;
        var builders = options.Signers.Select(k => new SignatureBuilder(k, SignatureType.Text, options.SignatureHash, options.Now, policy)).ToList();
        try
        {
            var sb = new System.Text.StringBuilder("-----BEGIN PGP SIGNED MESSAGE-----\n");
            foreach (PgpHashAlgorithm h in builders.Where(b => b.Version == 4).Select(b => b.Hash).Distinct())
            {
                sb.Append("Hash: ").Append(HashHeaderName(h)).Append('\n');
            }

            sb.Append('\n');
            output.Write(System.Text.Encoding.ASCII.GetBytes(sb.ToString()));
            Cleartext.WriteBody(text, output, builders);
            using var armor = new ArmorWriteStream(output, "PGP SIGNATURE", leaveOpen: true);
            foreach (SignatureBuilder b in builders)
            {
                b.Complete().WriteTo(armor);
            }

            armor.Complete();
        }
        finally
        {
            foreach (SignatureBuilder b in builders)
            {
                b.Dispose();
            }
        }
    }

    internal static string HashHeaderName(PgpHashAlgorithm h) => h switch
    {
        PgpHashAlgorithm.Md5 => "MD5",
        PgpHashAlgorithm.Sha1 => "SHA1",
        PgpHashAlgorithm.Ripemd160 => "RIPEMD160",
        PgpHashAlgorithm.Sha256 => "SHA256",
        PgpHashAlgorithm.Sha384 => "SHA384",
        PgpHashAlgorithm.Sha512 => "SHA512",
        PgpHashAlgorithm.Sha224 => "SHA224",
        PgpHashAlgorithm.Sha3256 => "SHA3-256",
        PgpHashAlgorithm.Sha3512 => "SHA3-512",
        _ => throw new PgpException(PgpFailure.Unsupported, "No Hash header name for this hash."),
    };
}
