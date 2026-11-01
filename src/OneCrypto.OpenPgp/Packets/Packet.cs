namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>
/// One OpenPGP packet (RFC 9580 §4). A packet read from input keeps the exact octets it was read from, so writing it back reproduces the
/// input byte for byte, whatever length encoding, old or new format, partial chunks or non-minimal lengths it used. Typed subclasses decode
/// their fields over the body without copying; a packet whose tag or version this layer does not know is an <see cref="UnrecognizedPacket"/>
/// and is preserved the same way. Packets are immutable.
/// </summary>
public abstract class Packet
{
    private readonly ReadOnlyMemory<byte> _encoded;

    internal Packet(byte tagId, ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
    {
        TagId = tagId;
        Body = body;
        OriginalHeader = header;
        _encoded = encoded;
    }

    /// <summary>The packet tag as received (0 to 63).</summary>
    public byte TagId { get; }

    /// <summary>The packet tag as an enum value; tags with no name convert too.</summary>
    public PacketTag Tag => (PacketTag)TagId;

    /// <summary>The packet body: for partial body lengths, the chunks joined, without the length octets between them.</summary>
    public ReadOnlyMemory<byte> Body { get; }

    /// <summary>The header as it was read, or null for a packet built in memory.</summary>
    public PacketHeader? OriginalHeader { get; }

    /// <summary>The packet's complete encoding as it was read (header, any chunk length octets, and body); empty for a packet built in memory.</summary>
    public ReadOnlyMemory<byte> OriginalEncoding => _encoded;

    /// <summary>True when this packet was read from input and <see cref="OriginalEncoding"/> is available.</summary>
    public bool HasOriginalEncoding => OriginalHeader is not null;

    /// <summary>
    /// Writes the packet. By default a packet read from input is written exactly as read, and one built in memory with a canonical header.
    /// With <paramref name="canonical"/> the header is always the new format with the shortest definite length (body octets are unchanged).
    /// </summary>
    /// <param name="destination">Where to write.</param>
    /// <param name="canonical">True to re-encode the header canonically.</param>
    public void WriteTo(Stream destination, bool canonical = false)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (HasOriginalEncoding && !canonical)
        {
            destination.Write(_encoded.Span);
            return;
        }

        destination.Write(PacketHeader.EncodeCanonical(TagId, Body.Length));
        destination.Write(Body.Span);
    }

    /// <summary>The encoding of the packet; see <see cref="WriteTo"/>.</summary>
    /// <param name="canonical">True to re-encode the header canonically.</param>
    public byte[] ToArray(bool canonical = false)
    {
        if (HasOriginalEncoding && !canonical)
        {
            return _encoded.ToArray();
        }

        byte[] header = PacketHeader.EncodeCanonical(TagId, Body.Length);
        byte[] result = new byte[header.Length + Body.Length];
        header.CopyTo(result, 0);
        Body.Span.CopyTo(result.AsSpan(header.Length));
        return result;
    }

    /// <summary>Creates a typed packet from a tag and a body, with a canonical header when written.</summary>
    /// <param name="tagId">The packet tag, 0 to 63.</param>
    /// <param name="body">The body octets (not copied).</param>
    /// <exception cref="OpenPgpParseException">The body is malformed for a packet type this layer decodes.</exception>
    public static Packet Create(byte tagId, ReadOnlyMemory<byte> body)
    {
        if (tagId > 63)
        {
            throw new ArgumentOutOfRangeException(nameof(tagId), "A packet tag is 0 to 63.");
        }

        return PacketFactory.Create(tagId, body, null, default);
    }

    /// <summary>Reads exactly one packet from <paramref name="encoded"/>; anything after it is an error.</summary>
    /// <param name="encoded">The packet's encoding.</param>
    /// <param name="limits">Resource limits; <see cref="OpenPgpLimits.Default"/> when null.</param>
    /// <exception cref="OpenPgpParseException">The input is not exactly one well-formed packet.</exception>
    public static Packet Parse(ReadOnlyMemory<byte> encoded, OpenPgpLimits? limits = null)
    {
        using var reader = new PacketReader(encoded, limits);
        Packet p = reader.ReadPacket() ?? throw new OpenPgpParseException(OpenPgpError.Truncated, 0, "no packet");
        if (reader.ReadFrame() is not null)
        {
            throw new OpenPgpParseException(OpenPgpError.TrailingData, reader.Position);
        }

        return p;
    }
}

/// <summary>A packet with a tag this layer does not decode (reserved, private or future), or a known tag with a version it does not know. Preserved as received.</summary>
public sealed class UnrecognizedPacket : Packet
{
    internal UnrecognizedPacket(byte tagId, ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base(tagId, body, header, encoded)
    {
    }

    /// <summary>The first body octet, which is the version for every versioned packet type; null for an empty body.</summary>
    public int? FirstOctet => Body.IsEmpty ? null : Body.Span[0];
}

/// <summary>Marker packet (RFC 9580 §5.8): the three octets "PGP", to be ignored.</summary>
public sealed class MarkerPacket : Packet
{
    internal MarkerPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base((byte)PacketTag.Marker, body, header, encoded)
    {
    }
}

/// <summary>Trust packet (RFC 9580 §5.10): implementation-specific data kept with a keyring, opaque here.</summary>
public sealed class TrustPacket : Packet
{
    internal TrustPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base((byte)PacketTag.Trust, body, header, encoded)
    {
    }
}

/// <summary>Padding packet (RFC 9580 §5.14): random octets, to be ignored.</summary>
public sealed class PaddingPacket : Packet
{
    internal PaddingPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base((byte)PacketTag.Padding, body, header, encoded)
    {
    }
}

/// <summary>User ID packet (RFC 9580 §5.11): UTF-8 text, usually a name and an email address.</summary>
public sealed class UserIdPacket : Packet
{
    internal UserIdPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base((byte)PacketTag.UserId, body, header, encoded)
    {
    }

    /// <summary>The User ID octets exactly as stored (they are certified as octets, so they are never normalised).</summary>
    public ReadOnlyMemory<byte> Value => Body;

    /// <summary>The text, decoding invalid UTF-8 with replacement characters. Use <see cref="Value"/> for anything that is hashed or compared.</summary>
    public string Text => System.Text.Encoding.UTF8.GetString(Body.Span);

    /// <summary>Creates a User ID packet from text.</summary>
    /// <param name="text">The User ID.</param>
    public static UserIdPacket FromText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return new UserIdPacket(System.Text.Encoding.UTF8.GetBytes(text), null, default);
    }
}

/// <summary>One subpacket of a User Attribute packet (RFC 9580 §5.12).</summary>
/// <param name="Type">The subpacket type (1 is an image).</param>
/// <param name="Data">The subpacket data after the type octet.</param>
public readonly record struct UserAttributeSubpacket(byte Type, ReadOnlyMemory<byte> Data);

/// <summary>User Attribute packet (RFC 9580 §5.12): a list of typed subpackets, usually one image.</summary>
public sealed class UserAttributePacket : Packet
{
    internal UserAttributePacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded, IReadOnlyList<UserAttributeSubpacket> subpackets)
        : base((byte)PacketTag.UserAttribute, body, header, encoded)
    {
        Subpackets = subpackets;
    }

    /// <summary>The subpackets in order.</summary>
    public IReadOnlyList<UserAttributeSubpacket> Subpackets { get; }
}

/// <summary>Modification Detection Code packet (RFC 9580 §5.14 as written for version 1 SEIPD): the 20-octet SHA-1 that ends a decrypted version 1 message.</summary>
public sealed class ModificationDetectionCodePacket : Packet
{
    internal ModificationDetectionCodePacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base((byte)PacketTag.ModificationDetectionCode, body, header, encoded)
    {
    }

    /// <summary>The 20 hash octets.</summary>
    public ReadOnlyMemory<byte> Digest => Body;
}

/// <summary>Compressed Data packet (RFC 9580 §5.6): an algorithm octet then the compressed packet stream.</summary>
public sealed class CompressedDataPacket : Packet
{
    internal CompressedDataPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base((byte)PacketTag.CompressedData, body, header, encoded)
    {
    }

    /// <summary>The compression algorithm octet.</summary>
    public CompressionAlgorithm Algorithm => (CompressionAlgorithm)Body.Span[0];

    /// <summary>The compressed data.</summary>
    public ReadOnlyMemory<byte> Data => Body[1..];
}

/// <summary>
/// Symmetrically Encrypted Data packet (RFC 9580 §5.7): obsolete, unauthenticated CFB data. Exposed so that it can be recognised and
/// refused (or, on an explicit opt-in, read); this layer does nothing with the contents.
/// </summary>
public sealed class SymmetricallyEncryptedDataPacket : Packet
{
    internal SymmetricallyEncryptedDataPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded)
        : base((byte)PacketTag.SymmetricallyEncryptedData, body, header, encoded)
    {
    }

    /// <summary>The ciphertext.</summary>
    public ReadOnlyMemory<byte> Data => Body;
}

/// <summary>Literal Data packet (RFC 9580 §5.9).</summary>
public sealed class LiteralDataPacket : Packet
{
    internal LiteralDataPacket(ReadOnlyMemory<byte> body, PacketHeader? header, ReadOnlyMemory<byte> encoded, LiteralDataHeader literal)
        : base((byte)PacketTag.LiteralData, body, header, encoded)
    {
        Literal = literal;
    }

    /// <summary>The format, file name and date.</summary>
    public LiteralDataHeader Literal { get; }

    /// <summary>The data octets.</summary>
    public ReadOnlyMemory<byte> Data => Body[Literal.HeaderLength..];
}

/// <summary>The fixed part of a Literal Data packet (RFC 9580 §5.9): format, file name and date.</summary>
/// <param name="Format">The format octet: 'b' binary, 'u' UTF-8 text, 'm' MIME (RFC 9580 §5.9), 't' legacy text, 'l' local (LibrePGP).</param>
/// <param name="FileName">The file name octets (at most 255); a single "_CONSOLE" asked for display-only handling in old implementations.</param>
/// <param name="Date">The modification time as seconds since 1970-01-01 UTC, or 0 for none.</param>
/// <param name="HeaderLength">The number of body octets the header occupies; the data follows.</param>
public readonly record struct LiteralDataHeader(byte Format, ReadOnlyMemory<byte> FileName, uint Date, int HeaderLength)
{
    /// <summary>Reads the header from the front of a literal packet body that is streamed rather than buffered.</summary>
    /// <param name="body">The packet body, positioned at its first octet; left positioned at the first data octet.</param>
    /// <exception cref="OpenPgpParseException">The body ends inside the header.</exception>
    public static LiteralDataHeader Read(Stream body)
    {
        ArgumentNullException.ThrowIfNull(body);
        byte[] head = new byte[2];
        ReadFully(body, head);
        byte[] name = new byte[head[1]];
        ReadFully(body, name);
        byte[] date = new byte[4];
        ReadFully(body, date);
        return new LiteralDataHeader(head[0], name, System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(date), 2 + name.Length + 4);
    }

    internal static LiteralDataHeader Parse(ReadOnlyMemory<byte> body)
    {
        var c = new PacketCursor(body);
        byte format = c.Byte("literal format");
        byte nameLength = c.Byte("literal file name length");
        ReadOnlyMemory<byte> name = c.Take(nameLength, "literal file name");
        uint date = c.U32("literal date");
        return new LiteralDataHeader(format, name, date, c.Position);
    }

    private static void ReadFully(Stream s, byte[] buffer)
    {
        int got = 0;
        while (got < buffer.Length)
        {
            int n = s.Read(buffer, got, buffer.Length - got);
            if (n == 0)
            {
                throw new OpenPgpParseException(OpenPgpError.Truncated, 0, "literal header");
            }

            got += n;
        }
    }
}
