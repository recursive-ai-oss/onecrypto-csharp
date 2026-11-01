using System.Buffers.Binary;
using System.Collections;

namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>
/// One signature subpacket (RFC 9580 §5.2.3.7): a type, the critical bit and the data. A parsed subpacket keeps its exact encoding,
/// including a length field that is longer than it needs to be.
/// </summary>
public sealed class SignatureSubpacket
{
    internal SignatureSubpacket(byte typeOctet, ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> raw)
    {
        TypeOctet = typeOctet;
        Data = data;
        Raw = raw;
    }

    /// <summary>The type octet as stored: the critical bit (0x80) and the type ID.</summary>
    public byte TypeOctet { get; }

    /// <summary>The type ID (the type octet without the critical bit).</summary>
    public byte TypeId => (byte)(TypeOctet & 0x7F);

    /// <summary>The type as an enum value; IDs with no name convert too.</summary>
    public SubpacketType Type => (SubpacketType)TypeId;

    /// <summary>True when the signer marked the subpacket critical: an evaluator that does not recognise it should treat the signature as in error.</summary>
    public bool IsCritical => (TypeOctet & 0x80) != 0;

    /// <summary>The subpacket data after the type octet.</summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>The subpacket as encoded: length field, type octet and data.</summary>
    public ReadOnlyMemory<byte> Raw { get; }

    /// <summary>True for the subpacket types this layer decodes (the types RFC 9580, RFC 9980 and LibrePGP define, including the reserved ones that deployed implementations write).</summary>
    public bool IsRecognized => TypeId is 2 or 3 or 4 or 5 or 6 or 7 or 9 or 11 or 12 or 16 or 20 or 21 or 22 or 23 or 24 or 25 or 26 or 27 or 28
        or 29 or 30 or 31 or 32 or 33 or 34 or 35 or 37 or 38 or 39;

    /// <summary>Creates a subpacket with the shortest length encoding.</summary>
    /// <param name="type">The type ID, 0 to 127.</param>
    /// <param name="critical">True to set the critical bit.</param>
    /// <param name="data">The data.</param>
    public static SignatureSubpacket Create(byte type, bool critical, ReadOnlyMemory<byte> data)
    {
        if (type > 127)
        {
            throw new ArgumentOutOfRangeException(nameof(type), "A subpacket type is 0 to 127.");
        }

        long length = 1L + data.Length;
        byte[] raw;
        int at;
        if (length < 192)
        {
            raw = new byte[1 + length];
            raw[0] = (byte)length;
            at = 1;
        }
        else if (length <= 16319)
        {
            raw = new byte[2 + length];
            long v = length - 192;
            raw[0] = (byte)((v >> 8) + 192);
            raw[1] = (byte)(v & 0xFF);
            at = 2;
        }
        else
        {
            raw = new byte[5 + length];
            raw[0] = 255;
            BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(1), (uint)length);
            at = 5;
        }

        byte typeOctet = (byte)(type | (critical ? 0x80 : 0));
        raw[at] = typeOctet;
        data.Span.CopyTo(raw.AsSpan(at + 1));
        return new SignatureSubpacket(typeOctet, raw.AsMemory(at + 1), raw);
    }
}

/// <summary>
/// A signature's hashed or unhashed subpacket area (RFC 9580 §5.2.3.7): the subpackets in order, with the exact octets of the area.
/// </summary>
public sealed class SubpacketArea : IReadOnlyList<SignatureSubpacket>
{
    private readonly SignatureSubpacket[] _items;

    private SubpacketArea(ReadOnlyMemory<byte> raw, SignatureSubpacket[] items)
    {
        Raw = raw;
        _items = items;
    }

    /// <summary>An area with no subpackets.</summary>
    public static SubpacketArea Empty { get; } = new(default, []);

    /// <summary>The area's octets, without the leading count.</summary>
    public ReadOnlyMemory<byte> Raw { get; }

    /// <inheritdoc />
    public int Count => _items.Length;

    /// <inheritdoc />
    public SignatureSubpacket this[int index] => _items[index];

    /// <inheritdoc />
    public IEnumerator<SignatureSubpacket> GetEnumerator() => ((IEnumerable<SignatureSubpacket>)_items).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => _items.GetEnumerator();

    /// <summary>The first subpacket of a type, or null.</summary>
    /// <param name="type">The type.</param>
    public SignatureSubpacket? Find(SubpacketType type)
    {
        foreach (SignatureSubpacket s in _items)
        {
            if (s.TypeId == (byte)type)
            {
                return s;
            }
        }

        return null;
    }

    /// <summary>Every subpacket of a type, in order.</summary>
    /// <param name="type">The type.</param>
    public IEnumerable<SignatureSubpacket> FindAll(SubpacketType type)
    {
        foreach (SignatureSubpacket s in _items)
        {
            if (s.TypeId == (byte)type)
            {
                yield return s;
            }
        }
    }

    /// <summary>The subpackets marked critical whose type this layer does not recognise (RFC 9580 §5.2.3.7: an evaluator SHOULD treat the signature as in error).</summary>
    public IReadOnlyList<SignatureSubpacket> UnrecognizedCritical() => _items.Where(s => s.IsCritical && !s.IsRecognized).ToArray();

    /// <summary>Builds an area from subpackets, in the given order.</summary>
    /// <param name="subpackets">The subpackets.</param>
    public static SubpacketArea Create(IEnumerable<SignatureSubpacket> subpackets)
    {
        ArgumentNullException.ThrowIfNull(subpackets);
        SignatureSubpacket[] items = subpackets.ToArray();
        int total = 0;
        foreach (SignatureSubpacket s in items)
        {
            total += s.Raw.Length;
        }

        byte[] raw = new byte[total];
        int at = 0;
        foreach (SignatureSubpacket s in items)
        {
            s.Raw.Span.CopyTo(raw.AsSpan(at));
            at += s.Raw.Length;
        }

        return Parse(raw, OpenPgpLimits.Default);
    }

    internal static SubpacketArea Parse(ReadOnlyMemory<byte> area, OpenPgpLimits limits)
    {
        if (area.IsEmpty)
        {
            return Empty;
        }

        var list = new List<SignatureSubpacket>();
        var c = new PacketCursor(area);
        while (!c.AtEnd)
        {
            if (list.Count >= limits.MaxSubpackets)
            {
                throw c.Fail(OpenPgpError.TooManySubpackets);
            }

            int start = c.Position;
            long length;
            int first = c.Byte("subpacket length");
            if (first < 192)
            {
                length = first;
            }
            else if (first < 255)
            {
                length = ((first - 192) << 8) + c.Byte("subpacket length") + 192;
            }
            else
            {
                length = c.U32("subpacket length");
            }

            if (length < 1)
            {
                throw c.Fail(OpenPgpError.InvalidField, "subpacket length");
            }

            if (length > c.Remaining)
            {
                throw c.Fail(OpenPgpError.LengthExceedsData, "subpacket");
            }

            byte typeOctet = c.Byte("subpacket type");
            ReadOnlyMemory<byte> data = c.Take((int)length - 1, "subpacket data");
            list.Add(new SignatureSubpacket(typeOctet, data, c.Since(start)));
        }

        return new SubpacketArea(area, list.ToArray());
    }
}

/// <summary>The algorithm-specific values of a signature (RFC 9580 §5.2.3.1 to §5.2.3.5, RFC 9980 §5.3.1, §6.2.1).</summary>
public sealed class SignatureMaterial
{
    internal SignatureMaterial(ReadOnlyMemory<byte> raw, IReadOnlyList<ReadOnlyMemory<byte>> values, bool known)
    {
        Raw = raw;
        Values = values;
        IsKnown = known;
    }

    /// <summary>The octets as stored.</summary>
    public ReadOnlyMemory<byte> Raw { get; }

    /// <summary>The values without length prefixes: RSA the signature integer; DSA, ECDSA and EdDSALegacy r then s; Ed25519 and Ed448 the signature; the post-quantum combinations the EdDSA signature then the ML-DSA signature; SLH-DSA the signature.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Values { get; }

    /// <summary>False for an algorithm this layer cannot split.</summary>
    public bool IsKnown { get; }

    internal static SignatureMaterial Parse(PublicKeyAlgorithm algorithm, ReadOnlyMemory<byte> data, int maxMpiBits)
    {
        var c = new PacketCursor(data);
        var values = new List<ReadOnlyMemory<byte>>(2);
        switch (algorithm)
        {
            case PublicKeyAlgorithm.Rsa:
            case PublicKeyAlgorithm.RsaEncryptOnly:
            case PublicKeyAlgorithm.RsaSignOnly:
                values.Add(c.Mpi("rsa signature", maxMpiBits));
                break;
            case PublicKeyAlgorithm.Dsa:
            case PublicKeyAlgorithm.Ecdsa:
            case PublicKeyAlgorithm.EdDsaLegacy:
                values.Add(c.Mpi("signature r", maxMpiBits));
                values.Add(c.Mpi("signature s", maxMpiBits));
                break;
            case PublicKeyAlgorithm.Ed25519:
                values.Add(c.Take(64, "ed25519 signature"));
                break;
            case PublicKeyAlgorithm.Ed448:
                values.Add(c.Take(114, "ed448 signature"));
                break;
            case PublicKeyAlgorithm.MlDsa65Ed25519:
                values.Add(c.Take(64, "ed25519 signature"));
                values.Add(c.Take(3309, "ml-dsa-65 signature"));
                break;
            case PublicKeyAlgorithm.MlDsa87Ed448:
                values.Add(c.Take(114, "ed448 signature"));
                values.Add(c.Take(4627, "ml-dsa-87 signature"));
                break;
            case PublicKeyAlgorithm.SlhDsaShake128s:
                values.Add(c.Take(7856, "slh-dsa signature"));
                break;
            case PublicKeyAlgorithm.SlhDsaShake128f:
                values.Add(c.Take(17088, "slh-dsa signature"));
                break;
            case PublicKeyAlgorithm.SlhDsaShake256s:
                values.Add(c.Take(29792, "slh-dsa signature"));
                break;
            default:
                return new SignatureMaterial(data, [], false);
        }

        if (!c.AtEnd)
        {
            throw c.Fail(OpenPgpError.TrailingData, "signature material");
        }

        return new SignatureMaterial(data, values, true);
    }
}

/// <summary>
/// Signature packet (RFC 9580 §5.2): versions 3, 4 and 6, and LibrePGP's 5 (read only). Fields are decoded over the body without copying;
/// the hashed octets a verifier needs are exposed as stored.
/// </summary>
public sealed class SignaturePacket : Packet
{
    internal SignaturePacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded, OpenPgpLimits limits)
        : base((byte)PacketTag.Signature, body, header, encoded)
    {
        var c = new PacketCursor(body);
        Version = c.Byte("signature version");
        if (Version == 3)
        {
            // RFC 9580 §5.2.2: version 3 has a fixed five-octet block of hashed material, then the issuer.
            if (c.Byte("hashed material length") != 5)
            {
                throw c.Fail(OpenPgpError.InvalidField, "v3 hashed material length");
            }

            ReadOnlyMemory<byte> hashed = c.Take(5, "v3 hashed material");
            SignedHeader = hashed;
            SignatureTypeId = hashed.Span[0];
            V3CreationTime = BinaryPrimitives.ReadUInt32BigEndian(hashed.Span[1..]);
            V3IssuerKeyId = c.Take(8, "v3 issuer");
            Algorithm = (PublicKeyAlgorithm)c.Byte("signature algorithm");
            Hash = (PgpHashAlgorithm)c.Byte("hash algorithm");
            HashedSubpackets = SubpacketArea.Empty;
            UnhashedSubpackets = SubpacketArea.Empty;
        }
        else
        {
            // Versions 4 and 6 (and LibrePGP 5): type, algorithms, then the two subpacket areas with a 2-octet (v4, and LibrePGP v5 per its §5.2.3) or 4-octet (v6, RFC 9580 §5.2.3) count.
            SignatureTypeId = c.Byte("signature type");
            Algorithm = (PublicKeyAlgorithm)c.Byte("signature algorithm");
            Hash = (PgpHashAlgorithm)c.Byte("hash algorithm");
            bool wide = Version >= 6;
            ReadOnlyMemory<byte> hashedArea = AreaOf(ref c, wide, "hashed subpackets");
            SignedHeader = body[..c.Position];
            ReadOnlyMemory<byte> unhashedArea = AreaOf(ref c, wide, "unhashed subpackets");
            HashedSubpackets = SubpacketArea.Parse(hashedArea, limits);
            UnhashedSubpackets = SubpacketArea.Parse(unhashedArea, limits);
        }

        HashPrefix = c.Take(2, "hash prefix");
        if (Version == 6)
        {
            byte saltLength = c.Byte("salt length");
            Salt = c.Take(saltLength, "salt");
        }

        Material = SignatureMaterial.Parse(Algorithm, c.Rest(), limits.MaxMpiBits);
    }

    private static ReadOnlyMemory<byte> AreaOf(ref PacketCursor c, bool wide, string what)
    {
        if (wide)
        {
            return c.TakeCounted32(what);
        }

        ushort n = c.U16(what);
        return c.Take(n, what);
    }

    /// <summary>The signature version: 3, 4, 5 (LibrePGP, read only) or 6.</summary>
    public byte Version { get; }

    /// <summary>The signature type octet (see <see cref="Type"/> for the named values).</summary>
    public byte SignatureTypeId { get; }

    /// <summary>The signature type as an enum value; unnamed values convert too.</summary>
    public SignatureType Type => (SignatureType)SignatureTypeId;

    /// <summary>The public-key algorithm.</summary>
    public PublicKeyAlgorithm Algorithm { get; }

    /// <summary>The hash algorithm.</summary>
    public PgpHashAlgorithm Hash { get; }

    /// <summary>For a v3 signature: the creation time in seconds since 1970-01-01 UTC.</summary>
    public uint V3CreationTime { get; }

    /// <summary>For a v3 signature: the issuer's eight-octet key ID; empty for later versions.</summary>
    public ReadOnlyMemory<byte> V3IssuerKeyId { get; }

    /// <summary>The hashed subpackets (empty for v3).</summary>
    public SubpacketArea HashedSubpackets { get; }

    /// <summary>The unhashed subpackets, which the signature does not protect (empty for v3).</summary>
    public SubpacketArea UnhashedSubpackets { get; }

    /// <summary>
    /// The octets a verifier feeds to the hash after the signed data and before the trailer (RFC 9580 §5.2.4): for v3 the type and creation time; for
    /// v4, v5 and v6 the body from the version octet through the hashed subpackets.
    /// </summary>
    public ReadOnlyMemory<byte> SignedHeader { get; }

    /// <summary>The left 16 bits of the signed hash value.</summary>
    public ReadOnlyMemory<byte> HashPrefix { get; }

    /// <summary>For v6: the random salt that is hashed before the data (RFC 9580 §5.2.3); empty otherwise.</summary>
    public ReadOnlyMemory<byte> Salt { get; }

    /// <summary>The algorithm-specific signature values.</summary>
    public SignatureMaterial Material { get; }

    /// <summary>The signature creation time (seconds since 1970-01-01 UTC): the v3 field, or the hashed subpacket; null if absent.</summary>
    public uint? CreationTime => Version == 3 ? V3CreationTime : ReadU32(HashedSubpackets.Find(SubpacketType.SignatureCreationTime));

    /// <summary>Seconds after the creation time at which the signature expires (hashed subpacket); null if it does not.</summary>
    public uint? ExpirationSeconds => ReadU32(HashedSubpackets.Find(SubpacketType.SignatureExpirationTime));

    /// <summary>Seconds after the key's creation time at which the key expires (hashed subpacket); null if absent.</summary>
    public uint? KeyExpirationSeconds => ReadU32(HashedSubpackets.Find(SubpacketType.KeyExpirationTime));

    /// <summary>The issuer key ID: the v3 field, or the Issuer Key ID subpacket in either area; null if absent.</summary>
    public ReadOnlyMemory<byte>? IssuerKeyId
    {
        get
        {
            if (Version == 3)
            {
                return V3IssuerKeyId;
            }

            SignatureSubpacket? s = HashedSubpackets.Find(SubpacketType.IssuerKeyId) ?? UnhashedSubpackets.Find(SubpacketType.IssuerKeyId);
            return s is { Data.Length: 8 } ? s.Data : null;
        }
    }

    /// <summary>The issuer fingerprint (version octet then fingerprint) from the Issuer Fingerprint subpacket in either area; null if absent.</summary>
    public ReadOnlyMemory<byte>? IssuerFingerprint
    {
        get
        {
            SignatureSubpacket? s = HashedSubpackets.Find(SubpacketType.IssuerFingerprint) ?? UnhashedSubpackets.Find(SubpacketType.IssuerFingerprint);
            return s is { Data.Length: > 1 } ? s.Data : null;
        }
    }

    /// <summary>The key flags octets (hashed subpacket); null if absent. The first octet holds the common flags (0x01 certify, 0x02 sign, 0x04 encrypt communications, 0x08 encrypt storage, 0x20 authenticate).</summary>
    public ReadOnlyMemory<byte>? KeyFlags => HashedSubpackets.Find(SubpacketType.KeyFlags)?.Data;

    /// <summary>The Features octets (hashed subpacket); null if absent. Bit 0x01 is SEIPD v1, 0x08 is SEIPD v2.</summary>
    public ReadOnlyMemory<byte>? Features => HashedSubpackets.Find(SubpacketType.Features)?.Data;

    /// <summary>The preferred symmetric algorithms, most preferred first (hashed subpacket); null if absent.</summary>
    public ReadOnlyMemory<byte>? PreferredSymmetricAlgorithms => HashedSubpackets.Find(SubpacketType.PreferredSymmetricAlgorithms)?.Data;

    /// <summary>The preferred hash algorithms, most preferred first (hashed subpacket); null if absent.</summary>
    public ReadOnlyMemory<byte>? PreferredHashAlgorithms => HashedSubpackets.Find(SubpacketType.PreferredHashAlgorithms)?.Data;

    /// <summary>The preferred compression algorithms, most preferred first (hashed subpacket); null if absent.</summary>
    public ReadOnlyMemory<byte>? PreferredCompressionAlgorithms => HashedSubpackets.Find(SubpacketType.PreferredCompressionAlgorithms)?.Data;

    /// <summary>The preferred AEAD ciphersuites as (symmetric, AEAD) octet pairs (hashed subpacket); null if absent.</summary>
    public ReadOnlyMemory<byte>? PreferredAeadCiphersuites => HashedSubpackets.Find(SubpacketType.PreferredAeadCiphersuites)?.Data;

    /// <summary>True when the hashed Primary User ID subpacket is present and set.</summary>
    public bool IsPrimaryUserId => HashedSubpackets.Find(SubpacketType.PrimaryUserId) is { Data.Length: > 0 } s && s.Data.Span[0] != 0;

    /// <summary>The Exportable Certification flag (hashed subpacket); true when absent (RFC 9580 §5.2.3.19).</summary>
    public bool Exportable => HashedSubpackets.Find(SubpacketType.ExportableCertification) is not { Data.Length: > 0 } s || s.Data.Span[0] != 0;

    /// <summary>The Revocable flag (hashed subpacket); true when absent (RFC 9580 §5.2.3.20).</summary>
    public bool Revocable => HashedSubpackets.Find(SubpacketType.Revocable) is not { Data.Length: > 0 } s || s.Data.Span[0] != 0;

    /// <summary>The Trust Signature level and amount (hashed subpacket); null if absent.</summary>
    public (byte Level, byte Amount)? TrustSignature =>
        HashedSubpackets.Find(SubpacketType.TrustSignature) is { Data.Length: 2 } s ? (s.Data.Span[0], s.Data.Span[1]) : null;

    /// <summary>The Reason for Revocation code and text (hashed subpacket); null if absent.</summary>
    public (byte Code, ReadOnlyMemory<byte> Reason)? ReasonForRevocation =>
        HashedSubpackets.Find(SubpacketType.ReasonForRevocation) is { Data.Length: > 0 } s ? (s.Data.Span[0], s.Data[1..]) : null;

    /// <summary>The notations (hashed subpackets; RFC 9580 §5.2.3.24), each as flags, name and value octets.</summary>
    /// <exception cref="OpenPgpParseException">A notation subpacket is malformed.</exception>
    public IReadOnlyList<SignatureNotation> Notations
    {
        get
        {
            var list = new List<SignatureNotation>();
            foreach (SignatureSubpacket s in HashedSubpackets.FindAll(SubpacketType.NotationData))
            {
                var c = new PacketCursor(s.Data);
                ReadOnlyMemory<byte> flags = c.Take(4, "notation flags");
                ushort nameLength = c.U16("notation name length");
                ushort valueLength = c.U16("notation value length");
                list.Add(new SignatureNotation(flags, c.Take(nameLength, "notation name"), c.Take(valueLength, "notation value")));
            }

            return list;
        }
    }

    /// <summary>The embedded signatures (RFC 9580 §5.2.3.34), from either area, decoded as signature packet bodies.</summary>
    /// <exception cref="OpenPgpParseException">An embedded signature is malformed.</exception>
    public IReadOnlyList<SignaturePacket> EmbeddedSignatures
    {
        get
        {
            var list = new List<SignaturePacket>();
            foreach (SubpacketArea area in new[] { HashedSubpackets, UnhashedSubpackets })
            {
                foreach (SignatureSubpacket s in area.FindAll(SubpacketType.EmbeddedSignature))
                {
                    list.Add(new SignaturePacket(s.Data, null, default, OpenPgpLimits.Default));
                }
            }

            return list;
        }
    }

    private static uint? ReadU32(SignatureSubpacket? s) => s is { Data.Length: 4 } ? BinaryPrimitives.ReadUInt32BigEndian(s.Data.Span) : null;
}

/// <summary>A Notation Data subpacket (RFC 9580 §5.2.3.24).</summary>
/// <param name="Flags">The four flag octets; the high bit of the first marks human-readable text.</param>
/// <param name="Name">The name octets (UTF-8).</param>
/// <param name="Value">The value octets.</param>
public readonly record struct SignatureNotation(ReadOnlyMemory<byte> Flags, ReadOnlyMemory<byte> Name, ReadOnlyMemory<byte> Value)
{
    /// <summary>True when the value is human-readable UTF-8.</summary>
    public bool IsHumanReadable => (Flags.Span[0] & 0x80) != 0;
}
