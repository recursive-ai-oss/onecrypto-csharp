namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>
/// Public Key Encrypted Session Key packet (RFC 9580 §5.1): version 3 (with a key ID) or version 6 (with a version and fingerprint, or
/// anonymous). The algorithm-specific values are split out for the algorithms RFC 9580, RFC 9980 and LibrePGP define.
/// </summary>
public sealed class PublicKeyEncryptedSessionKeyPacket : Packet
{
    internal PublicKeyEncryptedSessionKeyPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded, OpenPgpLimits limits)
        : base((byte)PacketTag.PublicKeyEncryptedSessionKey, body, header, encoded)
    {
        var c = new PacketCursor(body);
        Version = c.Byte("pkesk version");
        if (Version == 3)
        {
            KeyId = c.Take(8, "pkesk key id");
        }
        else
        {
            // RFC 9580 §5.1.2: a count, then (when not zero) the key version and fingerprint of the recipient.
            byte count = c.Byte("pkesk recipient size");
            if (count > 0)
            {
                ReadOnlyMemory<byte> recipient = c.Take(count, "pkesk recipient");
                RecipientKeyVersion = recipient.Span[0];
                RecipientFingerprint = recipient[1..];
            }
        }

        Algorithm = (PublicKeyAlgorithm)c.Byte("pkesk algorithm");
        Material = c.Rest();
        Values = ParseValues(Algorithm, Material, Version, limits.MaxMpiBits);
    }

    /// <summary>The packet version: 3 or 6.</summary>
    public byte Version { get; }

    /// <summary>For v3: the recipient's eight-octet key ID; all zeros means anonymous. Empty for v6.</summary>
    public ReadOnlyMemory<byte> KeyId { get; }

    /// <summary>For v6: the recipient key's version, or null for an anonymous recipient.</summary>
    public byte? RecipientKeyVersion { get; }

    /// <summary>For v6: the recipient fingerprint; empty for an anonymous recipient.</summary>
    public ReadOnlyMemory<byte> RecipientFingerprint { get; }

    /// <summary>The public-key algorithm used to encrypt the session key.</summary>
    public PublicKeyAlgorithm Algorithm { get; }

    /// <summary>The algorithm-specific octets as stored.</summary>
    public ReadOnlyMemory<byte> Material { get; }

    /// <summary>
    /// The values of <see cref="Material"/> for algorithms this layer knows, without length prefixes: RSA the encrypted integer; Elgamal two integers; ECDH the ephemeral
    /// point then the wrapped key; X25519, X448 and the ML-KEM combinations the ephemeral key(s) then the wrapped key (for a v3 packet that field starts with the
    /// symmetric algorithm octet). Empty for other algorithms.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Values { get; }

    private static List<ReadOnlyMemory<byte>> ParseValues(PublicKeyAlgorithm algorithm, ReadOnlyMemory<byte> material, byte version, int maxMpiBits)
    {
        var c = new PacketCursor(material);
        var values = new List<ReadOnlyMemory<byte>>(3);
        switch (algorithm)
        {
            case PublicKeyAlgorithm.Rsa:
            case PublicKeyAlgorithm.RsaEncryptOnly:
                values.Add(c.Mpi("rsa encrypted session key", maxMpiBits));
                break;
            case PublicKeyAlgorithm.ElGamal:
                values.Add(c.Mpi("elgamal value", maxMpiBits));
                values.Add(c.Mpi("elgamal value", maxMpiBits));
                break;
            case PublicKeyAlgorithm.Ecdh:
                values.Add(c.Mpi("ephemeral point", maxMpiBits));
                values.Add(c.Take(c.Byte("wrapped key length"), "wrapped key"));
                break;
            case PublicKeyAlgorithm.X25519:
                values.Add(c.Take(32, "ephemeral key"));
                values.Add(c.Take(c.Byte("wrapped key length"), "wrapped key"));
                break;
            case PublicKeyAlgorithm.X448:
                values.Add(c.Take(56, "ephemeral key"));
                values.Add(c.Take(c.Byte("wrapped key length"), "wrapped key"));
                break;
            case PublicKeyAlgorithm.MlKem768X25519:
                values.Add(c.Take(32, "ephemeral key"));
                values.Add(c.Take(1088, "ml-kem ciphertext"));
                values.Add(c.Take(c.Byte("wrapped key length"), "wrapped key"));
                break;
            case PublicKeyAlgorithm.MlKem1024X448:
                values.Add(c.Take(56, "ephemeral key"));
                values.Add(c.Take(1568, "ml-kem ciphertext"));
                values.Add(c.Take(c.Byte("wrapped key length"), "wrapped key"));
                break;
            case PublicKeyAlgorithm.LibrePgpKyber:
                // LibrePGP §5.1: point, counted ML-KEM ciphertext, the AES algorithm octet, then a counted wrapped key.
                values.Add(c.Mpi("ephemeral point", maxMpiBits));
                values.Add(c.TakeCounted32("kyber ciphertext"));
                values.Add(c.Take(1, "kyber session key algorithm"));
                values.Add(c.Take(c.Byte("wrapped key length"), "wrapped key"));
                break;
            default:
                _ = version;
                return [];
        }

        if (!c.AtEnd)
        {
            throw c.Fail(OpenPgpError.TrailingData, "pkesk material");
        }

        return values;
    }
}

/// <summary>
/// Symmetric Key Encrypted Session Key packet (RFC 9580 §5.3): version 4 (CFB), 5 (LibrePGP, OCB) and 6 (AEAD). Only the fields are
/// decoded; deriving keys and unwrapping belongs to the message layer.
/// </summary>
public sealed class SymmetricKeyEncryptedSessionKeyPacket : Packet
{
    internal SymmetricKeyEncryptedSessionKeyPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base((byte)PacketTag.SymmetricKeyEncryptedSessionKey, body, header, encoded)
    {
        var c = new PacketCursor(body);
        Version = c.Byte("skesk version");
        if (Version == 6)
        {
            byte count = c.Byte("skesk field count");
            var f = new PacketCursor(c.Take(count, "skesk fields"), c.Offset);
            Cipher = (SymmetricAlgorithm)f.Byte("skesk cipher");
            Aead = (AeadAlgorithm)f.Byte("skesk aead");
            byte s2kLength = f.Byte("skesk s2k length");
            S2k = S2kSpecifier.Read(ref f, s2kLength);
            Iv = f.Take(SecretKeyPacket.AeadNonceLength(Aead.Value) is var n and > 0 ? n : throw f.Fail(OpenPgpError.InvalidField, "skesk aead"), "skesk iv");
            if (!f.AtEnd)
            {
                throw f.Fail(OpenPgpError.InvalidField, "skesk field count");
            }

            EncryptedSessionKey = c.Rest();
        }
        else
        {
            Cipher = (SymmetricAlgorithm)c.Byte("skesk cipher");
            if (Version == 5)
            {
                Aead = (AeadAlgorithm)c.Byte("skesk aead");
            }

            S2k = S2kSpecifier.Read(ref c, null);
            if (Version == 5)
            {
                int ivLength = SecretKeyPacket.AeadNonceLength(Aead!.Value);
                if (ivLength == 0)
                {
                    throw c.Fail(OpenPgpError.InvalidField, "skesk aead");
                }

                Iv = c.Take(ivLength, "skesk iv");
            }

            EncryptedSessionKey = c.Rest();
        }
    }

    /// <summary>The packet version: 4, 5 (LibrePGP) or 6.</summary>
    public byte Version { get; }

    /// <summary>The symmetric algorithm that wraps the session key (v4: also the message cipher when no session key follows).</summary>
    public SymmetricAlgorithm Cipher { get; }

    /// <summary>The AEAD algorithm for v5 and v6; null for v4.</summary>
    public AeadAlgorithm? Aead { get; }

    /// <summary>The string-to-key specifier.</summary>
    public S2kSpecifier S2k { get; }

    /// <summary>The AEAD starting vector (v5, v6); empty for v4.</summary>
    public ReadOnlyMemory<byte> Iv { get; }

    /// <summary>The encrypted session key, with the AEAD tag at its end for v5 and v6; empty for v4 when the S2K output is the session key itself.</summary>
    public ReadOnlyMemory<byte> EncryptedSessionKey { get; }
}

/// <summary>One-Pass Signature packet (RFC 9580 §5.4), versions 3 and 6.</summary>
public sealed class OnePassSignaturePacket : Packet
{
    internal OnePassSignaturePacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base((byte)PacketTag.OnePassSignature, body, header, encoded)
    {
        var c = new PacketCursor(body);
        Version = c.Byte("ops version");
        SignatureTypeId = c.Byte("ops signature type");
        Hash = (PgpHashAlgorithm)c.Byte("ops hash");
        Algorithm = (PublicKeyAlgorithm)c.Byte("ops algorithm");
        if (Version == 6)
        {
            Salt = c.Take(c.Byte("ops salt length"), "ops salt");
            Fingerprint = c.Take(32, "ops fingerprint");
        }
        else
        {
            KeyId = c.Take(8, "ops key id");
        }

        IsLast = c.Byte("ops nested flag") != 0;
        if (!c.AtEnd)
        {
            throw c.Fail(OpenPgpError.TrailingData, "one-pass signature");
        }
    }

    /// <summary>The packet version: 3 or 6.</summary>
    public byte Version { get; }

    /// <summary>The signature type octet.</summary>
    public byte SignatureTypeId { get; }

    /// <summary>The hash algorithm.</summary>
    public PgpHashAlgorithm Hash { get; }

    /// <summary>The public-key algorithm.</summary>
    public PublicKeyAlgorithm Algorithm { get; }

    /// <summary>For v6: the signature salt; empty otherwise.</summary>
    public ReadOnlyMemory<byte> Salt { get; }

    /// <summary>For v3: the signer's key ID; empty for v6.</summary>
    public ReadOnlyMemory<byte> KeyId { get; }

    /// <summary>For v6: the signer's 32-octet fingerprint; empty for v3.</summary>
    public ReadOnlyMemory<byte> Fingerprint { get; }

    /// <summary>True when the last octet is non-zero: no further One-Pass Signature packet follows for this data (RFC 9580 calls the flag "nested" and reads zero as "another follows").</summary>
    public bool IsLast { get; }
}

/// <summary>The fixed fields at the front of a Symmetrically Encrypted and Integrity Protected Data packet body (RFC 9580 §5.13), for streaming readers.</summary>
/// <param name="Version">1 or 2.</param>
/// <param name="Cipher">Version 2: the symmetric algorithm; otherwise <see cref="SymmetricAlgorithm.Plaintext"/>.</param>
/// <param name="Aead">Version 2: the AEAD algorithm; otherwise null.</param>
/// <param name="ChunkSizeOctet">Version 2: the chunk size octet (chunks are 2^(c+6) octets); otherwise 0.</param>
/// <param name="Salt">Version 2: the 32-octet salt; otherwise empty.</param>
/// <param name="HeaderLength">The number of body octets the fields occupy.</param>
public readonly record struct SeipdHeader(byte Version, SymmetricAlgorithm Cipher, AeadAlgorithm? Aead, byte ChunkSizeOctet, ReadOnlyMemory<byte> Salt, int HeaderLength)
{
    /// <summary>Reads the fields from the front of a SEIPD packet body that is streamed rather than buffered, leaving the stream at the ciphertext.</summary>
    /// <param name="body">The packet body.</param>
    /// <exception cref="OpenPgpParseException">The body ends inside the fields.</exception>
    public static SeipdHeader Read(Stream body)
    {
        ArgumentNullException.ThrowIfNull(body);
        int version = body.ReadByte();
        if (version < 0)
        {
            throw new OpenPgpParseException(OpenPgpError.Truncated, 0, "seipd version");
        }

        if (version != 2)
        {
            return new SeipdHeader((byte)version, SymmetricAlgorithm.Plaintext, null, 0, default, 1);
        }

        byte[] rest = new byte[3 + 32];
        int got = 0;
        while (got < rest.Length)
        {
            int n = body.Read(rest, got, rest.Length - got);
            if (n == 0)
            {
                throw new OpenPgpParseException(OpenPgpError.Truncated, 1, "seipd v2 header");
            }

            got += n;
        }

        return new SeipdHeader(2, (SymmetricAlgorithm)rest[0], (AeadAlgorithm)rest[1], rest[2], rest.AsMemory(3), 36);
    }

    internal static SeipdHeader Parse(ReadOnlyMemory<byte> body)
    {
        var c = new PacketCursor(body);
        byte version = c.Byte("seipd version");
        if (version != 2)
        {
            return new SeipdHeader(version, SymmetricAlgorithm.Plaintext, null, 0, default, 1);
        }

        var cipher = (SymmetricAlgorithm)c.Byte("seipd cipher");
        var aead = (AeadAlgorithm)c.Byte("seipd aead");
        byte chunk = c.Byte("seipd chunk size");
        ReadOnlyMemory<byte> salt = c.Take(32, "seipd salt");
        return new SeipdHeader(2, cipher, aead, chunk, salt, c.Position);
    }
}

/// <summary>Symmetrically Encrypted and Integrity Protected Data packet (RFC 9580 §5.13), version 1 (CFB with an MDC) or 2 (chunked AEAD).</summary>
public sealed class SymmetricallyEncryptedIntegrityProtectedDataPacket : Packet
{
    internal SymmetricallyEncryptedIntegrityProtectedDataPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded, SeipdHeader fields)
        : base((byte)PacketTag.SymmetricallyEncryptedIntegrityProtectedData, body, header, encoded)
    {
        Fields = fields;
    }

    /// <summary>The version and, for v2, the cipher, AEAD algorithm, chunk size octet and salt.</summary>
    public SeipdHeader Fields { get; }

    /// <summary>The ciphertext after the fields (for v2, the chunks and the final tag).</summary>
    public ReadOnlyMemory<byte> Data => Body[Fields.HeaderLength..];
}

/// <summary>OCB Encrypted Data packet (LibrePGP §5.16, tag 20): OCB or EAX chunks with a final tag. Read as a packet only.</summary>
public sealed class OcbEncryptedDataPacket : Packet
{
    internal OcbEncryptedDataPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base((byte)PacketTag.OcbEncryptedData, body, header, encoded)
    {
        var c = new PacketCursor(body);
        Version = c.Byte("ocbed version");
        Cipher = (SymmetricAlgorithm)c.Byte("ocbed cipher");
        Aead = (AeadAlgorithm)c.Byte("ocbed mode");
        ChunkSizeOctet = c.Byte("ocbed chunk size");
        int ivLength = SecretKeyPacket.AeadNonceLength(Aead);
        if (ivLength == 0)
        {
            throw c.Fail(OpenPgpError.InvalidField, "ocbed mode");
        }

        Iv = c.Take(ivLength, "ocbed iv");
        Data = c.Rest();
    }

    /// <summary>The packet version (1).</summary>
    public byte Version { get; }

    /// <summary>The symmetric algorithm.</summary>
    public SymmetricAlgorithm Cipher { get; }

    /// <summary>The mode: OCB (2) or EAX (1).</summary>
    public AeadAlgorithm Aead { get; }

    /// <summary>The chunk size octet; chunks are 2^(c+6) octets.</summary>
    public byte ChunkSizeOctet { get; }

    /// <summary>The starting initialisation vector (15 octets for OCB, 16 for EAX).</summary>
    public ReadOnlyMemory<byte> Iv { get; }

    /// <summary>The encrypted chunks followed by the final tag.</summary>
    public ReadOnlyMemory<byte> Data { get; }
}

internal static class PacketFactory
{
    /// <summary>Builds the typed packet for a tag and body. Tags and versions with no decoder become <see cref="UnrecognizedPacket"/>.</summary>
    internal static Packet Create(byte tagId, ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded, OpenPgpLimits? limits = null)
    {
        limits ??= OpenPgpLimits.Default;
        byte first = body.IsEmpty ? (byte)0 : body.Span[0];
        switch ((PacketTag)tagId)
        {
            case PacketTag.PublicKey:
            case PacketTag.PublicSubkey:
                {
                    KeyPacket.KeyFields? f = KeyPacket.ReadPublicPart(body, false, limits);
                    return f is null ? new UnrecognizedPacket(tagId, body, header, encoded) : new PublicKeyPacket(tagId, body, header, encoded, f.Value);
                }

            case PacketTag.SecretKey:
            case PacketTag.SecretSubkey:
                {
                    KeyPacket.KeyFields? f = KeyPacket.ReadPublicPart(body, true, limits);
                    return f is null ? new UnrecognizedPacket(tagId, body, header, encoded) : SecretKeyPacket.Parse(tagId, body, header, encoded, f.Value, limits);
                }

            case PacketTag.Signature:
                return first is 3 or 4 or 5 or 6 ? new SignaturePacket(body, header, encoded, limits) : new UnrecognizedPacket(tagId, body, header, encoded);
            case PacketTag.PublicKeyEncryptedSessionKey:
                return first is 3 or 6 ? new PublicKeyEncryptedSessionKeyPacket(body, header, encoded, limits) : new UnrecognizedPacket(tagId, body, header, encoded);
            case PacketTag.SymmetricKeyEncryptedSessionKey:
                if (first is not (4 or 5 or 6))
                {
                    return new UnrecognizedPacket(tagId, body, header, encoded);
                }

                try
                {
                    return new SymmetricKeyEncryptedSessionKeyPacket(body, header, encoded);
                }
                catch (OpenPgpParseException e) when (e.Error == OpenPgpError.InvalidField && first != 6)
                {
                    // RFC 9580 §5.3.1: without a length field, a string-to-key type we do not know hides where the packet's fields end, so the
                    // packet is kept as it was read and ignored when looking for a session key.
                    return new UnrecognizedPacket(tagId, body, header, encoded);
                }
            case PacketTag.OnePassSignature:
                return first is 3 or 6 ? new OnePassSignaturePacket(body, header, encoded) : new UnrecognizedPacket(tagId, body, header, encoded);
            case PacketTag.CompressedData:
                if (body.IsEmpty)
                {
                    throw new OpenPgpParseException(OpenPgpError.Truncated, 0, "compression algorithm");
                }

                return new CompressedDataPacket(body, header, encoded);
            case PacketTag.SymmetricallyEncryptedData:
                return new SymmetricallyEncryptedDataPacket(body, header, encoded);
            case PacketTag.Marker:
                return new MarkerPacket(body, header, encoded);
            case PacketTag.LiteralData:
                return new LiteralDataPacket(body, header, encoded, LiteralDataHeader.Parse(body));
            case PacketTag.Trust:
                return new TrustPacket(body, header, encoded);
            case PacketTag.UserId:
                return new UserIdPacket(body, header, encoded);
            case PacketTag.UserAttribute:
                return new UserAttributePacket(body, header, encoded, ParseUserAttribute(body));
            case PacketTag.SymmetricallyEncryptedIntegrityProtectedData:
                if (body.IsEmpty)
                {
                    throw new OpenPgpParseException(OpenPgpError.Truncated, 0, "seipd version");
                }

                return first is 1 or 2
                    ? new SymmetricallyEncryptedIntegrityProtectedDataPacket(body, header, encoded, SeipdHeader.Parse(body))
                    : new UnrecognizedPacket(tagId, body, header, encoded);
            case PacketTag.ModificationDetectionCode:
                if (body.Length != 20)
                {
                    throw new OpenPgpParseException(OpenPgpError.InvalidField, 0, "mdc length");
                }

                return new ModificationDetectionCodePacket(body, header, encoded);
            case PacketTag.OcbEncryptedData:
                return first == 1 ? new OcbEncryptedDataPacket(body, header, encoded) : new UnrecognizedPacket(tagId, body, header, encoded);
            case PacketTag.Padding:
                return new PaddingPacket(body, header, encoded);
            default:
                return new UnrecognizedPacket(tagId, body, header, encoded);
        }
    }

    private static List<UserAttributeSubpacket> ParseUserAttribute(ReadOnlyMemory<byte> body)
    {
        // RFC 9580 §5.12: subpackets with the same length encoding as signature subpackets.
        var list = new List<UserAttributeSubpacket>();
        var c = new PacketCursor(body);
        while (!c.AtEnd)
        {
            long length;
            int first = c.Byte("attribute length");
            if (first < 192)
            {
                length = first;
            }
            else if (first < 255)
            {
                length = ((first - 192) << 8) + c.Byte("attribute length") + 192;
            }
            else
            {
                length = c.U32("attribute length");
            }

            if (length < 1 || length > c.Remaining)
            {
                throw c.Fail(OpenPgpError.InvalidField, "attribute subpacket length");
            }

            byte type = c.Byte("attribute type");
            list.Add(new UserAttributeSubpacket(type, c.Take((int)length - 1, "attribute data")));
        }

        return list;
    }
}
