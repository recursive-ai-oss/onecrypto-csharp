using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.Cli.Sop;

/// <summary>armor, dearmor and extract-cert: the subcommands that need only the packet layer.</summary>
internal static class PacketCommands
{
    /// <summary>
    /// Opens OpenPGP input that may be binary or armored (draft section 11.4). A first octet with bit 7 clear cannot start a packet, so it is taken as armor and read
    /// strictly: no text before the header line, one block, nothing but white space after the tail line.
    /// </summary>
    public static Stream OpenBinary(Stream input, out bool wasArmored)
    {
        int first = input.ReadByte();
        if (first < 0)
        {
            throw new SopException(SopExit.BadData, "empty input");
        }

        var head = new PrefixStream([(byte)first], input);
        wasArmored = Armor.LooksArmored((byte)first);
        return wasArmored ? new ArmorReadStream(head, ArmorReadOptions.Strict) : head;
    }

    public static int RunArmor(Options o, SopIo io)
    {
        o.RejectUnknown();
        o.NoPositionals();
        using Stream binary = OpenBinary(io.Stdin, out _);
        using var reader = new PacketReader(binary);
        PacketFrame first = reader.ReadFrame() ?? throw new SopException(SopExit.BadData, "no OpenPGP packets in the input");
        string label;
        MemoryStream? spooled = null;
        switch (first.Tag)
        {
            case PacketTag.SecretKey:
                label = "PGP PRIVATE KEY BLOCK";
                break;
            case PacketTag.PublicKey:
                label = "PGP PUBLIC KEY BLOCK";
                break;
            case PacketTag.PublicKeyEncryptedSessionKey:
            case PacketTag.SymmetricKeyEncryptedSessionKey:
            case PacketTag.OnePassSignature:
                label = "PGP MESSAGE";
                break;
            case PacketTag.Signature:
                // Only signature packets make a SIGNATURE; anything else after them makes an inline-signed message. That needs the whole stream.
                spooled = new MemoryStream();
                bool onlySignatures = true;
                PacketFrame? f = first;
                while (f is not null)
                {
                    onlySignatures &= f.Tag == PacketTag.Signature;
                    f.CopyRawTo(spooled);
                    f = reader.ReadFrame();
                }

                label = onlySignatures ? "PGP SIGNATURE" : "PGP MESSAGE";
                break;
            default:
                throw new SopException(SopExit.BadData, "the first packet is not one a sop object starts with");
        }

        using var armor = new ArmorWriteStream(io.Stdout, label, leaveOpen: true);
        if (spooled is not null)
        {
            spooled.Position = 0;
            spooled.CopyTo(armor);
        }
        else
        {
            PacketFrame? f = first;
            while (f is not null)
            {
                f.CopyRawTo(armor);
                f = reader.ReadFrame();
            }
        }

        armor.Complete();
        return SopExit.Ok;
    }

    public static int RunDearmor(Options o, SopIo io)
    {
        o.RejectUnknown();
        o.NoPositionals();
        using Stream binary = OpenBinary(io.Stdin, out _);
        using var reader = new PacketReader(binary);
        PacketFrame? f = reader.ReadFrame() ?? throw new SopException(SopExit.BadData, "no OpenPGP packets in the input");
        if (f.Tag is not (PacketTag.SecretKey or PacketTag.PublicKey or PacketTag.PublicKeyEncryptedSessionKey
            or PacketTag.SymmetricKeyEncryptedSessionKey or PacketTag.OnePassSignature or PacketTag.Signature))
        {
            throw new SopException(SopExit.BadData, "the first packet is not one a sop object starts with");
        }

        while (f is not null)
        {
            f.CopyRawTo(io.Stdout);
            f = reader.ReadFrame();
        }

        return SopExit.Ok;
    }

    public static int RunExtractCert(Options o, SopIo io)
    {
        bool noArmor = o.Flag("--no-armor");
        o.RejectUnknown();
        o.NoPositionals();
        using Stream binary = OpenBinary(io.Stdin, out _);
        IReadOnlyList<Packet> packets = PacketParser.ParseAll(binary);
        IReadOnlyList<TransferableKey> keys = TransferableKey.ParseAll(packets);
        if (keys.Count == 0)
        {
            throw new SopException(SopExit.BadData, "no keys in the input");
        }

        // Section 7.3: KEYS holds secret keys. A certificate in KEYS is the wrong kind of object, and saying so beats quietly passing it through.
        if (keys.Any(k => !k.IsSecret))
        {
            throw new SopException(SopExit.BadData, "the input holds a certificate, not a secret key");
        }

        Stream output = io.Stdout;
        ArmorWriteStream? armor = noArmor ? null : new ArmorWriteStream(io.Stdout, "PGP PUBLIC KEY BLOCK", leaveOpen: true);
        try
        {
            Stream target = armor ?? output;
            foreach (TransferableKey key in keys)
            {
                key.ToPublic().WriteTo(target);
            }

            armor?.Complete();
        }
        finally
        {
            armor?.Dispose();
        }

        return SopExit.Ok;
    }
}

/// <summary>A stream that yields some bytes already read, then the rest of another stream.</summary>
internal sealed class PrefixStream : Stream
{
    private readonly byte[] _prefix;
    private readonly Stream _rest;
    private int _pos;

    public PrefixStream(byte[] prefix, Stream rest)
    {
        _prefix = prefix;
        _rest = rest;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (_pos < _prefix.Length)
        {
            int n = Math.Min(buffer.Length, _prefix.Length - _pos);
            _prefix.AsSpan(_pos, n).CopyTo(buffer);
            _pos += n;
            return n;
        }

        return _rest.Read(buffer);
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
