namespace RecursiveAI.OneCrypto.OpenPgp.Packets;

/// <summary>
/// A string-to-key specifier (RFC 9580 §3.7.1) as it appears in a Symmetric-Key Encrypted Session Key packet or a protected secret key.
/// Only the fields are decoded here; deriving a key from a passphrase belongs to the layer above. A specifier of a type this layer does not
/// know is kept as received, with <see cref="IsKnown"/> false.
/// </summary>
public sealed class S2kSpecifier
{
    internal S2kSpecifier(ReadOnlyMemory<byte> raw, byte typeId, PgpHashAlgorithm hash, ReadOnlyMemory<byte> salt, byte countOctet,
        byte passes, byte parallelism, byte memoryExponent, byte gnuMode, ReadOnlyMemory<byte> cardSerial, bool known)
    {
        Raw = raw;
        TypeId = typeId;
        Hash = hash;
        Salt = salt;
        CountOctet = countOctet;
        Passes = passes;
        Parallelism = parallelism;
        MemoryExponent = memoryExponent;
        GnuMode = gnuMode;
        CardSerial = cardSerial;
        IsKnown = known;
    }

    /// <summary>The specifier's octets exactly as read, including the type octet.</summary>
    public ReadOnlyMemory<byte> Raw { get; }

    /// <summary>The type octet.</summary>
    public byte TypeId { get; }

    /// <summary>The type, when it is one this layer knows; <see cref="IsKnown"/> says whether.</summary>
    public S2kType Type => (S2kType)TypeId;

    /// <summary>False for a type this layer does not decode; only <see cref="Raw"/> and <see cref="TypeId"/> are meaningful then.</summary>
    public bool IsKnown { get; }

    /// <summary>The hash algorithm (simple, salted, iterated and the GnuPG extension); <see cref="PgpHashAlgorithm.None"/> otherwise.</summary>
    public PgpHashAlgorithm Hash { get; }

    /// <summary>The salt: 8 octets (salted, iterated) or 16 (Argon2); empty otherwise.</summary>
    public ReadOnlyMemory<byte> Salt { get; }

    /// <summary>The coded iteration count octet of an iterated specifier.</summary>
    public byte CountOctet { get; }

    /// <summary>The decoded iteration count in octets (RFC 9580 §3.7.1.3: (16 + (c &amp; 15)) &lt;&lt; ((c &gt;&gt; 4) + 6)); zero unless iterated.</summary>
    public long IterationCount => Type == S2kType.IteratedSalted && IsKnown ? (16L + (CountOctet & 15)) << ((CountOctet >> 4) + 6) : 0;

    /// <summary>Argon2 passes t.</summary>
    public byte Passes { get; }

    /// <summary>Argon2 degree of parallelism p.</summary>
    public byte Parallelism { get; }

    /// <summary>Argon2 encoded memory size: m = 2^MemoryExponent KiB.</summary>
    public byte MemoryExponent { get; }

    /// <summary>For the GnuPG extension: 1 for a stub with no secret key, 2 for a key on a card.</summary>
    public byte GnuMode { get; }

    /// <summary>For the GnuPG extension with a card: the card serial number.</summary>
    public ReadOnlyMemory<byte> CardSerial { get; }

    /// <summary>Reads one specifier from the front of <paramref name="data"/>.</summary>
    /// <param name="data">The octets that start with the specifier.</param>
    /// <param name="length">The specifier's length in octets.</param>
    /// <exception cref="OpenPgpParseException">The data is truncated or the type is not one this layer knows.</exception>
    public static S2kSpecifier Parse(ReadOnlyMemory<byte> data, out int length)
    {
        var c = new PacketCursor(data);
        S2kSpecifier s = Read(ref c, null);
        length = c.Position;
        return s;
    }

    internal static S2kSpecifier Read(ref PacketCursor c, int? knownLength)
    {
        int start = c.Position;
        if (knownLength is int n)
        {
            // A counted field (RFC 9580 §5.3.2, §5.5.3): the field is exactly n octets even when its type is unknown.
            var sub = new PacketCursor(c.Take(n, "s2k"), c.Offset);
            S2kSpecifier s = ReadKnownOrOpaque(ref sub, true);
            if (!sub.AtEnd)
            {
                throw sub.Fail(OpenPgpError.InvalidField, "s2k length");
            }

            return s;
        }

        S2kSpecifier r = ReadKnownOrOpaque(ref c, false);
        _ = start;
        return r;
    }

    private static S2kSpecifier ReadKnownOrOpaque(ref PacketCursor c, bool opaqueAllowed)
    {
        int start = c.Position;
        byte type = c.Byte("s2k type");
        PgpHashAlgorithm hash = PgpHashAlgorithm.None;
        ReadOnlyMemory<byte> salt = default;
        ReadOnlyMemory<byte> card = default;
        byte count = 0, t = 0, p = 0, m = 0, gnu = 0;
        switch (type)
        {
            case (byte)S2kType.Simple:
                hash = (PgpHashAlgorithm)c.Byte("s2k hash");
                break;
            case (byte)S2kType.Salted:
                hash = (PgpHashAlgorithm)c.Byte("s2k hash");
                salt = c.Take(8, "s2k salt");
                break;
            case (byte)S2kType.IteratedSalted:
                hash = (PgpHashAlgorithm)c.Byte("s2k hash");
                salt = c.Take(8, "s2k salt");
                count = c.Byte("s2k count");
                break;
            case (byte)S2kType.Argon2:
                salt = c.Take(16, "s2k salt");
                t = c.Byte("argon2 passes");
                p = c.Byte("argon2 parallelism");
                m = c.Byte("argon2 memory");
                break;
            case (byte)S2kType.GnuExtension:
                hash = (PgpHashAlgorithm)c.Byte("s2k hash");
                ReadOnlyMemory<byte> tag = c.Take(3, "gnu marker");
                if (!tag.Span.SequenceEqual("GNU"u8))
                {
                    throw c.Fail(OpenPgpError.InvalidField, "unknown private-use s2k");
                }

                gnu = c.Byte("gnu mode");
                if (gnu == 2)
                {
                    byte len = c.Byte("card serial length");
                    card = c.Take(len, "card serial");
                }

                break;
            default:
                if (!opaqueAllowed)
                {
                    throw c.Fail(OpenPgpError.InvalidField, "unknown s2k type " + type);
                }

                c.Rest();
                return new S2kSpecifier(c.Since(start), type, hash, salt, count, t, p, m, gnu, card, false);
        }

        return new S2kSpecifier(c.Since(start), type, hash, salt, count, t, p, m, gnu, card, true);
    }
}
