using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>Version 3 keys are read only; no tool of ours or of the oracles still writes them, so the key is assembled here.</summary>
public class V3KeyTests
{
    [Fact]
    public void AVersion3RsaKeyHasAnMd5FingerprintAndTheLowModulusBitsAsKeyId()
    {
        byte[] n = new byte[128];
        new Random(3).NextBytes(n);
        n[0] |= 0x80;
        byte[] e = [0x01, 0x00, 0x01];
        var body = new List<byte> { 3, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 1 };
        body.AddRange([0x04, 0x00]); // 1024 bits
        body.AddRange(n);
        body.AddRange([0x00, 0x11]); // 17 bits
        body.AddRange(e);
        var packet = new List<byte> { 0x98 | 0, (byte)body.Count }; // old format, tag 6, one-octet length
        packet.AddRange(body);

        IReadOnlyList<Packet> packets = PacketParser.ParseAll(packet.ToArray());
        var key = Assert.IsAssignableFrom<PublicKeyPacket>(Assert.Single(packets));
        Assert.Equal(3, key.Version);

        // MD5 over the modulus and exponent values without their length prefixes (the format fixes this hash).
#pragma warning disable CA5351
        byte[] expected = MD5.HashData([.. n, .. e]);
#pragma warning restore CA5351
        Assert.Equal(Convert.ToHexString(expected), key.FingerprintHex);
        Assert.Equal(Convert.ToHexString(n.AsSpan(120)), key.KeyIdHex);

        using var ms = new MemoryStream();
        PacketParser.Write(packets, ms);
        Assert.Equal(packet.ToArray(), ms.ToArray());
    }
}
