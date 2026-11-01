using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.Cli.Sop;

/// <summary>
/// <c>inline-detach</c>: splits an inline-signed message into its data (standard output) and its signature packets (<c>--signatures-out</c>). Nothing is
/// verified. Handles the packet form (binary or armored) and the Cleartext Signature Framework (RFC 9580 section 7).
/// </summary>
internal static class InlineDetach
{
    private const string CleartextHeader = "-----BEGIN PGP SIGNED MESSAGE-----";
    private const string SignatureHeader = "-----BEGIN PGP SIGNATURE-----";

    public static int Run(Options o, SopIo io)
    {
        bool noArmor = o.Flag("--no-armor");
        string? sigOut = o.Value("--signatures-out");
        o.RejectUnknown();
        o.NoPositionals();
        if (sigOut is null)
        {
            throw new SopException(SopExit.MissingArg, "--signatures-out is required");
        }

        // An output that exists is refused before any input is consumed.
        using Stream signatures = SopIo.OpenOutput(sigOut);
        var sigBytes = new MemoryStream();
        int first = io.Stdin.ReadByte();
        if (first < 0)
        {
            throw new SopException(SopExit.BadData, "empty input");
        }

        var input = new PrefixStream([(byte)first], io.Stdin);
        if (Armor.LooksArmored((byte)first))
        {
            // Armor is either a signed message or the start of a cleartext signed message; the header line tells which.
            byte[] line = ReadLine(input);
            string text = Encoding.ASCII.GetString(line).TrimEnd();
            if (text == CleartextHeader)
            {
                Cleartext(input, io.Stdout, sigBytes);
            }
            else
            {
                Packets(new ArmorReadStream(new PrefixStream(line, input), ArmorReadOptions.Strict), io.Stdout, sigBytes);
            }
        }
        else
        {
            Packets(input, io.Stdout, sigBytes);
        }

        // The signatures go out last, so that a failure partway through leaves the data stream and the signatures file consistent.
        if (noArmor)
        {
            signatures.Write(sigBytes.GetBuffer(), 0, (int)sigBytes.Length);
        }
        else
        {
            using var armor = new ArmorWriteStream(signatures, "PGP SIGNATURE", leaveOpen: true);
            armor.Write(sigBytes.GetBuffer(), 0, (int)sigBytes.Length);
        }

        return SopExit.Ok;
    }

    private static void Packets(Stream binary, Stream data, MemoryStream signatures)
    {
        // Draft section 7.5: either signatures then one literal, or one-pass signatures, one literal and as many signatures.
        using var reader = new PacketReader(binary);
        int ops = 0, before = 0, after = 0;
        bool literal = false;
        PacketFrame? f;
        while ((f = reader.ReadFrame()) is not null)
        {
            switch (f.Tag)
            {
                case PacketTag.OnePassSignature when !literal && before == 0:
                    ops++;
                    f.ReadPacket();
                    break;
                case PacketTag.Signature:
                    f.CopyRawTo(signatures);
                    if (literal)
                    {
                        after++;
                    }
                    else
                    {
                        before++;
                    }

                    break;
                case PacketTag.LiteralData when !literal:
                    literal = true;
                    LiteralDataHeader.Read(f.Body);
                    f.Body.CopyTo(data);
                    break;
                case PacketTag.Marker or PacketTag.Padding:
                    f.ReadPacket();
                    break;
                default:
                    throw new SopException(SopExit.BadData, "the input is not an inline-signed message");
            }
        }

        bool shape = literal && (ops > 0 ? before == 0 && after == ops : before > 0 && after == 0);
        if (!shape)
        {
            throw new SopException(SopExit.BadData, "the input is not an inline-signed message");
        }
    }

    private static void Cleartext(Stream input, Stream data, MemoryStream signatures)
    {
        // RFC 9580 section 7: the header line, Hash headers, a blank line, dash-escaped text, then an armored signature. The line ending before the
        // signature's header line belongs to the framework, not to the text, so the last line ending is held back.
        string? line = ReadAsciiLine(input);
        while (line is not null && line.Length > 0)
        {
            if (!line.StartsWith("Hash: ", StringComparison.Ordinal))
            {
                throw new SopException(SopExit.BadData, "unexpected header in the cleartext signed message");
            }

            line = ReadAsciiLine(input);
        }

        if (line is null)
        {
            throw new SopException(SopExit.BadData, "the cleartext signed message ends in its headers");
        }

        byte[]? pending = null;
        byte[] pendingEnding = [];
        while (true)
        {
            byte[] raw = ReadLine(input);
            if (raw.Length == 0)
            {
                throw new SopException(SopExit.BadData, "the cleartext signed message has no signature");
            }

            SplitEnding(raw, out byte[] content, out byte[] ending);
            if (Encoding.ASCII.GetString(content).TrimEnd() == SignatureHeader)
            {
                var rest = new PrefixStream(raw, input);
                using var armored = new ArmorReadStream(rest, ArmorReadOptions.Strict);
                using var reader = new PacketReader(armored);
                PacketFrame? f;
                int count = 0;
                while ((f = reader.ReadFrame()) is not null)
                {
                    if (f.Tag != PacketTag.Signature)
                    {
                        throw new SopException(SopExit.BadData, "the signature block holds more than signatures");
                    }

                    f.CopyRawTo(signatures);
                    count++;
                }

                if (count == 0)
                {
                    throw new SopException(SopExit.BadData, "the signature block holds no signatures");
                }

                return;
            }

            if (pending is not null)
            {
                data.Write(pending);
                data.Write(pendingEnding);
            }

            // Dash-escaping (section 7.1): a line that begins with a dash was written with "- " in front.
            pending = content.Length >= 2 && content[0] == (byte)'-' && content[1] == (byte)' ' ? content[2..] : content;
            pendingEnding = ending;
        }
    }

    private static void SplitEnding(byte[] raw, out byte[] content, out byte[] ending)
    {
        int n = raw.Length;
        int endLen = n >= 2 && raw[n - 2] == '\r' && raw[n - 1] == '\n' ? 2 : n >= 1 && raw[n - 1] == '\n' ? 1 : 0;
        content = raw[..(n - endLen)];
        ending = raw[(n - endLen)..];
    }

    private static string? ReadAsciiLine(Stream s)
    {
        byte[] raw = ReadLine(s);
        if (raw.Length == 0)
        {
            return null;
        }

        SplitEnding(raw, out byte[] content, out _);
        return Encoding.Latin1.GetString(content);
    }

    /// <summary>Reads up to and including the next line feed (or the end of the input) and returns the bytes.</summary>
    private static byte[] ReadLine(Stream s)
    {
        var ms = new MemoryStream();
        int b;
        while ((b = s.ReadByte()) >= 0)
        {
            ms.WriteByte((byte)b);
            if (b == '\n')
            {
                break;
            }

            if (ms.Length > 1 << 20)
            {
                throw new SopException(SopExit.BadData, "a line is longer than 1 MiB");
            }
        }

        return ms.ToArray();
    }
}
