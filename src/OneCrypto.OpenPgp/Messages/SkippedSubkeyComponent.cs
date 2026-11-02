using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// A subkey the library could not use, kept with the signatures that follow it so the key still writes back byte for byte (RFC 9580 §10.1
/// lets an implementation ignore subkeys it cannot use). It is not part of <see cref="TransferableKey.Subkeys"/>.
/// </summary>
public sealed class SkippedSubkeyComponent
{
    internal SkippedSubkeyComponent(UnrecognizedPacket packet)
    {
        Packet = packet;
    }

    /// <summary>The subkey packet as received.</summary>
    public UnrecognizedPacket Packet { get; }

    /// <summary>True when the packet is a Secret Subkey (its secret material is not decoded).</summary>
    public bool IsSecret => Packet.TagId == (byte)PacketTag.SecretSubkey;

    /// <summary>The first body octet, which is the key version for every key packet; null for an empty body.</summary>
    public int? Version => Packet.FirstOctet;

    /// <summary>Why the subkey was skipped: the parse failure, or an unsupported key version.</summary>
    public string Reason => Packet.DecodeFailure is { } f ? f.Message : $"unsupported key version {Packet.FirstOctet?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "(none)"}";

    /// <summary>The signatures that follow the subkey, in order.</summary>
    public IReadOnlyList<SignaturePacket> Signatures => SignatureList;

    /// <summary>Every packet that follows the subkey before the next component and is not a signature.</summary>
    public IReadOnlyList<Packet> OtherPackets => OtherList;

    internal List<SignaturePacket> SignatureList { get; } = [];

    internal List<Packet> OtherList { get; } = [];
}
