using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>The cleartext signature framework of RFC 9580 §7.</summary>
internal static class Cleartext
{
    private const int MaxLine = 1 << 20;

    private static readonly byte[] Begin = "-----BEGIN PGP SIGNED MESSAGE-----"u8.ToArray();
    private static readonly byte[] SigBegin = "-----BEGIN PGP SIGNATURE-----"u8.ToArray();

    /// <summary>Reads one line (without its terminator) and says whether a terminator was present. Returns false at end of input.</summary>
    private static bool ReadLine(Stream s, List<byte> line, out bool terminated)
    {
        line.Clear();
        terminated = false;
        bool any = false;
        while (true)
        {
            int b = s.ReadByte();
            if (b < 0)
            {
                return any;
            }

            any = true;
            if (b == '\n')
            {
                terminated = true;
                if (line.Count > 0 && line[^1] == '\r')
                {
                    line.RemoveAt(line.Count - 1);
                }

                return true;
            }

            if (line.Count >= MaxLine)
            {
                throw new PgpException(PgpFailure.LimitExceeded, "A line in the cleartext message is too long.");
            }

            line.Add((byte)b);
        }
    }

    private static int StrippedLength(List<byte> line)
    {
        int n = line.Count;
        while (n > 0 && line[n - 1] is (byte)' ' or (byte)'\t')
        {
            n--;
        }

        return n;
    }

    private static bool Is(List<byte> line, byte[] marker)
    {
        int n = StrippedLength(line);
        return n == marker.Length && line.GetRange(0, n).ToArray().AsSpan().SequenceEqual(marker);
    }

    /// <summary>Writes the dash-escaped body and feeds each builder the canonical text; returns after the separating line ending.</summary>
    internal static void WriteBody(Stream text, Stream output, List<SignatureBuilder> builders)
    {
        var line = new List<byte>();
        bool first = true;
        var buffered = new BufferedStream(text, 64 * 1024);
        while (ReadLine(buffered, line, out _))
        {
            int n = StrippedLength(line);
            byte[] stripped = line.GetRange(0, n).ToArray();
            if (!first)
            {
                foreach (SignatureBuilder b in builders)
                {
                    b.Hasher.Append("\n"u8);
                }
            }

            foreach (SignatureBuilder b in builders)
            {
                b.Hasher.Append(stripped);
            }

            // RFC 9580 §7.2: a line that starts with a hyphen is escaped; the digest is over the unescaped text.
            if (line.Count > 0 && line[0] == (byte)'-')
            {
                output.Write("- "u8);
            }

            output.Write(line.ToArray());
            output.WriteByte((byte)'\n');
            first = false;
        }
    }

    internal static PgpReadResult Verify(Stream input, Stream? output, PgpReadOptions options)
    {
        CryptoPolicy policy = options.Policy ?? CryptoPolicy.Standard;
        var buffered = new BufferedStream(input, 64 * 1024);
        var line = new List<byte>();
        // Skip anything before the header, as the armor reader does.
        bool found = false;
        while (ReadLine(buffered, line, out _))
        {
            if (Is(line, Begin))
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            throw new PgpException(PgpFailure.MalformedMessage, "No cleartext signature header found.");
        }

        // RFC 9580 §7.1: only well-formed Hash headers may sit between the header and the empty line; anything else voids the message.
        while (true)
        {
            if (!ReadLine(buffered, line, out _))
            {
                throw new PgpException(PgpFailure.MalformedMessage, "The cleartext header is not closed by an empty line.");
            }

            if (StrippedLength(line) == 0)
            {
                break;
            }

            string h = Encoding.ASCII.GetString(line.ToArray()).TrimEnd();
            if (!h.StartsWith("Hash: ", StringComparison.Ordinal))
            {
                throw new PgpException(PgpFailure.MalformedMessage, "An armor header other than Hash appears in a cleartext signed message (RFC 9580 §7.1).");
            }
        }

        using var canonical = new SpoolStream();
        bool firstLine = true;
        bool sawSig = false;
        while (ReadLine(buffered, line, out _))
        {
            if (Is(line, SigBegin))
            {
                sawSig = true;
                break;
            }

            ReadOnlySpan<byte> raw = line.ToArray();
            ReadOnlySpan<byte> unescaped = raw.Length >= 2 && raw[0] == (byte)'-' && raw[1] == (byte)' ' ? raw[2..] : raw;
            int n = unescaped.Length;
            while (n > 0 && unescaped[n - 1] is (byte)' ' or (byte)'\t')
            {
                n--;
            }

            if (!firstLine)
            {
                canonical.WriteByte((byte)'\n');
                output?.WriteByte((byte)'\n');
            }

            canonical.Write(unescaped[..n]);
            output?.Write(unescaped);
            firstLine = false;
        }

        if (!sawSig)
        {
            throw new PgpException(PgpFailure.MalformedMessage, "The cleartext message has no signature block.");
        }

        using var sigBytes = new MemoryStream();
        sigBytes.Write(SigBegin);
        sigBytes.WriteByte((byte)'\n');
        byte[] rest = new byte[16 * 1024];
        int got;
        while ((got = buffered.Read(rest, 0, rest.Length)) > 0)
        {
            sigBytes.Write(rest, 0, got);
            if (sigBytes.Length > 8 << 20)
            {
                throw new PgpException(PgpFailure.LimitExceeded, "The signature block is too large.");
            }
        }

        ArmorBlock block = Armor.Decode(sigBytes.ToArray(), ArmorReadOptions.Lenient);
        var sigs = new List<SignaturePacket>();
        foreach (Packet p in PacketParser.ParseAll(block.Data, options.Limits))
        {
            if (p is SignaturePacket sp)
            {
                sigs.Add(sp);
            }
        }

        if (sigs.Count == 0)
        {
            throw new PgpException(PgpFailure.MalformedMessage, "The signature block holds no signature.");
        }

        var result = new PgpReadResult();
        foreach (SignaturePacket s in sigs)
        {
            byte[]? digest = null;
            if (s.Type == SignatureType.Text)
            {
                using var h = new SigHasher(s.Hash, s.Salt.Span, text: true);
                canonical.Position = 0;
                byte[] buf = Scratch.Rent();
                int n;
                while ((n = canonical.Read(buf, 0, buf.Length)) > 0)
                {
                    h.Append(buf.AsSpan(0, n));
                }

                Scratch.Return(buf);

                // A cleartext signature stands for a text literal packet with no name and no date (draft-koch-librepgp §5.2.4).
                digest = h.FinishOrNull(s.Version, s.SignedHeader.Span, "t\0\0\0\0\0"u8);
            }

            result.SignatureList.Add(SignatureChecker.Check(s, digest, options.Certificates, policy, options.Now));
        }

        return result;
    }
}
