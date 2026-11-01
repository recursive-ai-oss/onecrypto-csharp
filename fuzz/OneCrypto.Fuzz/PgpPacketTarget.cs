using System.Runtime.CompilerServices;
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace OneCrypto.Fuzz;

/// <summary>
/// OpenPGP packet layer. The first byte picks the surface: the in-memory packet parser (every accepted input must write back byte for
/// byte, and every typed field is read), the stream reader with its frame operations, the transferable-key grouping, the armor decoder
/// (accepted armor must encode and decode to the same data), or the armor stream read in tiny pieces. Only
/// <see cref="OpenPgpParseException"/> may come out; a rewrite that differs from the input is reported as an <see cref="InvalidOperationException"/>.
/// </summary>
internal static class PgpPacketTarget
{
    private static readonly OpenPgpLimits Small = new() { MaxPacketBodyLength = 1 << 20, MaxPackets = 4096, MaxSubpackets = 256, MaxArmorLineLength = 2048, MaxArmoredBytes = 1 << 22 };

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        try
        {
            switch (data[0] % 5)
            {
                case 0:
                    Memory(rest);
                    break;
                case 1:
                    Streamed(rest, data[0]);
                    break;
                case 2:
                    Keys(rest);
                    break;
                case 3:
                    ArmorBlock(rest, (data[0] & 0x80) != 0);
                    break;
                default:
                    ArmorStream(rest, data[0]);
                    break;
            }
        }
        catch (OpenPgpParseException)
        {
        }
    }

    private static void Memory(byte[] input)
    {
        IReadOnlyList<Packet> packets;
        try
        {
            packets = PacketParser.ParseAll(input, Small);
        }
        catch (OpenPgpParseException)
        {
            if (PacketParser.TryParseAll(input, out _, out _, Small))
            {
                throw new InvalidOperationException("TryParseAll accepted what ParseAll refused");
            }

            throw;
        }

        using var ms = new MemoryStream();
        PacketParser.Write(packets, ms);
        if (!ms.ToArray().AsSpan().SequenceEqual(input))
        {
            throw new InvalidOperationException("a parsed packet stream did not write back identically");
        }

        foreach (Packet p in packets)
        {
            Touch(p);
            _ = p.ToArray(canonical: true);
        }
    }

    private static void Touch(Packet p)
    {
        switch (p)
        {
            case KeyPacket k:
                _ = k.GetFingerprint();
                _ = k.GetKeyId();
                _ = k.Material.Values.Count;
                if (k is SecretKeyPacket sk)
                {
                    _ = sk.ToPublic().GetFingerprint();
                    _ = sk.Protection.Iv;
                }

                break;
            case SignaturePacket s:
                _ = s.CreationTime;
                _ = s.ExpirationSeconds;
                _ = s.IssuerKeyId;
                _ = s.IssuerFingerprint;
                _ = s.KeyFlags;
                _ = s.IsPrimaryUserId;
                _ = s.HashedSubpackets.UnrecognizedCritical();
                _ = s.Notations;
                _ = s.EmbeddedSignatures;
                _ = s.TrustSignature;
                _ = s.ReasonForRevocation;
                break;
            case LiteralDataPacket l:
                _ = l.Data.Length;
                break;
            case UserIdPacket u:
                _ = u.Text;
                break;
        }
    }

    private static void Streamed(byte[] input, byte mode)
    {
        // The stream reader cannot slice its input; it must see the same packets the memory parser sees.
        int expected = -1;
        try
        {
            expected = PacketParser.ParseAll(input, Small).Count;
        }
        catch (OpenPgpParseException)
        {
        }

        using var reader = new PacketReader(new MemoryStream(input), Small);
        int n = 0;
        using var raw = new MemoryStream();
        PacketFrame? f;
        while ((f = reader.ReadFrame()) is not null)
        {
            n++;
            switch ((mode >> 3) % 4)
            {
                case 0:
                    f.ReadPacket().WriteTo(raw);
                    break;
                case 1:
                    f.CopyRawTo(raw);
                    break;
                case 2:
                    {
                        // read the body a few bytes at a time, then leave the rest for the next ReadFrame to skip
                        byte[] b = new byte[1 + (mode & 7)];
                        _ = f.Body.Read(b, 0, b.Length);
                        break;
                    }

                default:
                    break;
            }
        }

        if (expected >= 0 && n != expected)
        {
            throw new InvalidOperationException("the stream reader and the memory parser disagree about the packet count");
        }

        if (((mode >> 3) % 4) is 0 or 1 && !raw.ToArray().AsSpan().SequenceEqual(input))
        {
            throw new InvalidOperationException("the stream reader did not write back identically");
        }
    }

    private static void Keys(byte[] input)
    {
        IReadOnlyList<Packet> packets = PacketParser.ParseAll(input, Small);
        foreach (TransferableKey k in TransferableKey.ParseAll(packets))
        {
            _ = k.Users.Count;
            _ = k.Subkeys.Count;
            if (k.IsSecret)
            {
                _ = k.ToPublic().Packets.Count;
            }
        }
    }

    private static void ArmorBlock(byte[] input, bool strict)
    {
        ArmorBlock block = Armor.Decode(input, strict ? ArmorReadOptions.Strict : ArmorReadOptions.Lenient, Small);
        string text = Armor.Encode(block.Kind == ArmorKind.Unknown || block.Kind == ArmorKind.MessagePart ? block.Label : Armor.LabelOf(block.Kind)!, block.Data);
        ArmorBlock again = Armor.Decode(Encoding.ASCII.GetBytes(text), ArmorReadOptions.Strict, Small);
        if (!again.Data.AsSpan().SequenceEqual(block.Data) || again.Label != block.Label)
        {
            throw new InvalidOperationException("armor did not survive encode and decode");
        }
    }

    private static void ArmorStream(byte[] input, byte mode)
    {
        using var r = new ArmorReadStream(new MemoryStream(input), mode % 2 == 0 ? ArmorReadOptions.Lenient : ArmorReadOptions.Strict, Small);
        byte[] b = new byte[1 + (mode >> 1) % 13];
        while (r.Read(b, 0, b.Length) > 0)
        {
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        yield return [0, 0xC0 | 10, 3, (byte)'P', (byte)'G', (byte)'P'];
        yield return [1, 0xC0 | 9, 0xE0 | 1, 1, 2, 3, 1, 2, 3];
        yield return [2, 0x99, 0, 3, 4, 0, 0, 0, 0, 22];
        yield return [3, .. Encoding.ASCII.GetBytes(Armor.Encode(ArmorKind.Message, new byte[40]))];
        yield return [4, .. Encoding.ASCII.GetBytes(Armor.Encode(ArmorKind.PublicKey, new byte[100], new ArmorWriteOptions { Checksum = true }))];
        string dir = Path.Combine(Path.GetDirectoryName(ThisFile())!, "..", "..", "testdata", "openpgp", "rfc9580");
        if (!Directory.Exists(dir))
        {
            yield break;
        }

        foreach (string file in Directory.GetFiles(dir, "*.asc"))
        {
            byte[] armored = File.ReadAllBytes(file);
            yield return [3, .. armored];
            byte[] binary = Armor.Decode(armored).Data;
            foreach (byte mode in new byte[] { 0, 1, 2 })
            {
                yield return [mode, .. binary];
            }
        }
    }

    private static string ThisFile([CallerFilePath] string path = "") => path;
}
