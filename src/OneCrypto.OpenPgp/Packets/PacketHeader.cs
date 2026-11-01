using System.Buffers.Binary;

namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>A packet header as read (RFC 9580 §4.2): the format, the tag, how the length was encoded and the length.</summary>
/// <param name="Format">Old or new format.</param>
/// <param name="TagId">The packet tag (0 to 63).</param>
/// <param name="LengthKind">How the body length is encoded.</param>
/// <param name="BodyLength">The body length in octets for a definite length; for partial body lengths the length of the first chunk; -1 for an old-format indeterminate length.</param>
/// <param name="HeaderLength">The number of octets the header occupies (the tag octet and the length octets of the first length field).</param>
public readonly record struct PacketHeader(PacketHeaderFormat Format, byte TagId, PacketLengthKind LengthKind, long BodyLength, int HeaderLength)
{
    /// <summary>The tag as an enum value; unnamed tags convert too.</summary>
    public PacketTag Tag => (PacketTag)TagId;

    /// <summary>True when the body is sent in partial chunks (new format, RFC 9580 §4.2.1.4).</summary>
    public bool IsPartial => LengthKind == PacketLengthKind.NewPartial;

    /// <summary>True when the body runs to the end of the input (old format, indeterminate length).</summary>
    public bool IsIndeterminate => LengthKind == PacketLengthKind.OldIndeterminate;

    /// <summary>True when the packet type may be sent with partial body lengths: data packets only (RFC 9580 §4.2.1.4).</summary>
    public static bool AllowsPartialLengths(byte tagId) =>
        tagId is (byte)PacketTag.LiteralData or (byte)PacketTag.CompressedData or (byte)PacketTag.SymmetricallyEncryptedData
            or (byte)PacketTag.SymmetricallyEncryptedIntegrityProtectedData or (byte)PacketTag.OcbEncryptedData;

    /// <summary>Encodes a canonical header: the new format with the shortest definite length (RFC 9580 §4.2.1.1 to §4.2.1.3).</summary>
    /// <param name="tagId">The packet tag, 0 to 63.</param>
    /// <param name="bodyLength">The body length, 0 to 4,294,967,295.</param>
    public static byte[] EncodeCanonical(byte tagId, long bodyLength)
    {
        if (tagId > 63)
        {
            throw new ArgumentOutOfRangeException(nameof(tagId), "A packet tag is 0 to 63.");
        }

        if (bodyLength is < 0 or > uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(bodyLength), "A packet body is at most 4,294,967,295 octets.");
        }

        byte ctb = (byte)(0xC0 | tagId);
        if (bodyLength < 192)
        {
            return [ctb, (byte)bodyLength];
        }

        if (bodyLength <= 8383)
        {
            long v = bodyLength - 192;
            return [ctb, (byte)((v >> 8) + 192), (byte)(v & 0xFF)];
        }

        byte[] five = new byte[6];
        five[0] = ctb;
        five[1] = 0xFF;
        BinaryPrimitives.WriteUInt32BigEndian(five.AsSpan(2), (uint)bodyLength);
        return five;
    }
}
