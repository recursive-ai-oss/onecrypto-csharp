using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.GnuPG;

/// <summary>The kind of a keybox blob, from the type octet at offset 4 of every blob.</summary>
public enum KeyboxBlobType : byte
{
    /// <summary>A blob whose space is free (a deleted entry). Its content is not interpreted.</summary>
    Empty = 0,

    /// <summary>The first blob of the file: magic, creation and maintenance times.</summary>
    Header = 1,

    /// <summary>A transferable OpenPGP key (public) with an index of its fingerprints and user IDs.</summary>
    OpenPgp = 2,

    /// <summary>An X.509 certificate (as written by <c>gpgsm</c>) with an index of its names.</summary>
    X509 = 3,
}

/// <summary>The blob flags GnuPG's <c>kbxutil</c> names, plus the raw 16-bit value.</summary>
[Flags]
public enum KeyboxBlobAttributes : ushort
{
    /// <summary>No flag set.</summary>
    None = 0,

    /// <summary>The blob holds secret key material (<c>kbxutil</c> prints "secret").</summary>
    Secret = 1,

    /// <summary>The blob is ephemeral: a key that is not part of the user's keyring proper (<c>kbxutil</c> prints "ephemeral").</summary>
    Ephemeral = 2,
}

/// <summary>One blob of a keybox: its position in the file, its raw octets and its type. Subclasses decode the types this library reads.</summary>
public abstract class KeyboxBlob
{
    internal KeyboxBlob(KeyboxBlobType type, byte version, long offset, ReadOnlyMemory<byte> raw)
    {
        Type = type;
        Version = version;
        Offset = offset;
        Raw = raw;
    }

    /// <summary>The blob type. A type this reader does not know is <see cref="KeyboxUnknownBlob"/> with the raw value in <see cref="TypeValue"/>.</summary>
    public KeyboxBlobType Type { get; }

    /// <summary>The type octet as stored.</summary>
    public byte TypeValue => Raw.Span[4];

    /// <summary>The blob format version octet (offset 5).</summary>
    public byte Version { get; }

    /// <summary>Offset of the blob in the file.</summary>
    public long Offset { get; }

    /// <summary>All octets of the blob as read, including the length field and the trailing checksum.</summary>
    public ReadOnlyMemory<byte> Raw { get; }

    /// <summary>The blob length in octets (the first four octets, big-endian).</summary>
    public int Length => Raw.Length;
}

/// <summary>A blob of a type this reader does not decode (or an empty blob). It is kept as read so that a file can be written back.</summary>
public sealed class KeyboxUnknownBlob : KeyboxBlob
{
    internal KeyboxUnknownBlob(KeyboxBlobType type, byte version, long offset, ReadOnlyMemory<byte> raw)
        : base(type, version, offset, raw)
    {
    }
}

/// <summary>The header blob: the first blob of every keybox (<c>KBXf</c> magic).</summary>
public sealed class KeyboxHeaderBlob : KeyboxBlob
{
    internal KeyboxHeaderBlob(byte version, long offset, ReadOnlyMemory<byte> raw, ushort flags, uint created, uint maintenance)
        : base(KeyboxBlobType.Header, version, offset, raw)
    {
        Flags = flags;
        CreatedAtSeconds = created;
        LastMaintenanceSeconds = maintenance;
    }

    /// <summary>The header flags as stored. Bit 1 (value 2) is the one <c>kbxutil</c> names "openpgp": the file holds OpenPGP keys.</summary>
    public ushort Flags { get; }

    /// <summary>True when the flag <c>kbxutil</c> names "openpgp" is set. GnuPG's own tools use it to tell a keybox from a plain keyring.</summary>
    public bool ContainsOpenPgp => (Flags & 2) != 0;

    /// <summary>Creation time of the file, seconds since the Unix epoch (octets 16 to 19).</summary>
    public uint CreatedAtSeconds { get; }

    /// <summary>Time of the last maintenance run, seconds since the Unix epoch (octets 20 to 23).</summary>
    public uint LastMaintenanceSeconds { get; }

    /// <summary>The creation time.</summary>
    public DateTimeOffset CreatedAt => DateTimeOffset.FromUnixTimeSeconds(CreatedAtSeconds);

    /// <summary>The time of the last maintenance run.</summary>
    public DateTimeOffset LastMaintenance => DateTimeOffset.FromUnixTimeSeconds(LastMaintenanceSeconds);
}

/// <summary>An entry of a key blob's key table: the fingerprint of a key in the blob.</summary>
public sealed class KeyboxKeyInfo
{
    internal KeyboxKeyInfo(byte[] fingerprint, byte[] keyId, ushort flags)
    {
        Fingerprint = fingerprint;
        KeyId = keyId;
        Flags = flags;
    }

    /// <summary>The fingerprint: 20 octets for a SHA-1 fingerprint (version 4 keys, X.509 certificates), 32 for a SHA-256 fingerprint.</summary>
    public ReadOnlyMemory<byte> Fingerprint { get; }

    /// <summary>The 64-bit key ID the entry points at (the last 8 octets of a 20-octet fingerprint), or empty when the entry has none (blob version 2).</summary>
    public ReadOnlyMemory<byte> KeyId { get; }

    /// <summary>The per-key flags as stored. GnuPG 2.5 sets 0x0080 on its Kyber subkeys; no other meaning is established.</summary>
    public ushort Flags { get; }

    /// <summary>The fingerprint as upper-case hexadecimal.</summary>
    public string FingerprintHex => Convert.ToHexString(Fingerprint.Span);
}

/// <summary>An entry of a key blob's name table: a user ID of an OpenPGP key, or the issuer or subject name of an X.509 certificate.</summary>
public sealed class KeyboxNameInfo
{
    internal KeyboxNameInfo(ReadOnlyMemory<byte> name, ushort flags, byte validity)
    {
        Name = name;
        Flags = flags;
        Validity = validity;
    }

    /// <summary>The octets of the name as stored in the blob (UTF-8 for OpenPGP user IDs).</summary>
    public ReadOnlyMemory<byte> Name { get; }

    /// <summary>The name as text (invalid UTF-8 is replaced).</summary>
    public string Text => System.Text.Encoding.UTF8.GetString(Name.Span);

    /// <summary>The per-name flags as stored; no meaning is established.</summary>
    public ushort Flags { get; }

    /// <summary>The cached validity octet as stored. GnuPG 2.4 and 2.5 write 0 here; the trust database holds the computed validity.</summary>
    public byte Validity { get; }
}

/// <summary>
/// An OpenPGP or X.509 blob: an index (key table, names, signature expiry times, trust fields) over the data it carries. The index is
/// advisory; the data is authoritative, and the fields are exposed as stored.
/// </summary>
public abstract class KeyboxKeyBlob : KeyboxBlob
{
    internal KeyboxKeyBlob(KeyboxBlobType type, byte version, long offset, ReadOnlyMemory<byte> raw)
        : base(type, version, offset, raw)
    {
    }

    /// <summary>The blob flags as stored.</summary>
    public ushort FlagsValue { get; internal set; }

    /// <summary>The flags <c>kbxutil</c> names.</summary>
    public KeyboxBlobAttributes Flags => (KeyboxBlobAttributes)(FlagsValue & 3);

    /// <summary>Offset of the data (the OpenPGP packets or the certificate) from the start of the blob.</summary>
    public int DataOffset { get; internal set; }

    /// <summary>Length of the data.</summary>
    public int DataLength { get; internal set; }

    /// <summary>The OpenPGP packet stream (the key's transferable form) or the DER certificate.</summary>
    public ReadOnlyMemory<byte> Data => Raw.Slice(DataOffset, DataLength);

    /// <summary>The key table: one entry per key in the blob (primary key first, then subkeys), or the single certificate.</summary>
    public IReadOnlyList<KeyboxKeyInfo> Keys { get; internal set; } = [];

    /// <summary>The serial number octets (X.509), empty otherwise.</summary>
    public ReadOnlyMemory<byte> SerialNumber { get; internal set; }

    /// <summary>User IDs (OpenPGP) or issuer then subject (X.509).</summary>
    public IReadOnlyList<KeyboxNameInfo> Names { get; internal set; } = [];

    /// <summary>The signature-expiry table as stored, one 32-bit value per signature. 0 is what <c>kbxutil</c> prints as "not checked".</summary>
    public IReadOnlyList<uint> SignatureExpirations { get; internal set; } = [];

    /// <summary>The owner-trust octet as stored. GnuPG 2.4 and 2.5 write 0: owner trust lives in the trust database (see <see cref="TrustDb"/>).</summary>
    public byte OwnerTrust { get; internal set; }

    /// <summary>The cached validity of all user IDs, as stored (0 as written by GnuPG 2.4 and 2.5).</summary>
    public byte AllValidity { get; internal set; }

    /// <summary>Seconds since the epoch after which the validity must be recomputed, as stored.</summary>
    public uint RecheckAfter { get; internal set; }

    /// <summary>The latest signature time in the blob, as stored.</summary>
    public uint LatestTimestamp { get; internal set; }

    /// <summary>When the blob was created, seconds since the epoch.</summary>
    public uint CreatedAtSeconds { get; internal set; }

    /// <summary>The "reserved space" field as stored.</summary>
    public uint ReservedSpace { get; internal set; }

    /// <summary>The 20 octets that end the blob: SHA-1 over every earlier octet of the blob. It guards against damage, not against tampering.</summary>
    public ReadOnlyMemory<byte> Checksum => Raw.Slice(Raw.Length - 20, 20);

    /// <summary>True when <see cref="Checksum"/> equals the SHA-1 of the rest of the blob.</summary>
    public bool ChecksumValid { get; internal set; }

    /// <summary>The time the blob was created.</summary>
    public DateTimeOffset CreatedAt => DateTimeOffset.FromUnixTimeSeconds(CreatedAtSeconds);
}

/// <summary>A blob carrying an OpenPGP transferable key.</summary>
public sealed class KeyboxOpenPgpBlob : KeyboxKeyBlob
{
    internal KeyboxOpenPgpBlob(byte version, long offset, ReadOnlyMemory<byte> raw)
        : base(KeyboxBlobType.OpenPgp, version, offset, raw)
    {
    }

    /// <summary>The fingerprint of the primary key as the key table lists it, or empty when the blob has no keys.</summary>
    public ReadOnlyMemory<byte> PrimaryFingerprint => Keys.Count == 0 ? default : Keys[0].Fingerprint;

    /// <summary>Decodes the packets of the blob into a transferable key. The packets are those stored in the blob, unchanged.</summary>
    /// <param name="limits">Limits for the packet reader; null for <see cref="OpenPgpLimits.Default"/>.</param>
    /// <exception cref="OpenPgpParseException">The data is not a well-formed packet sequence.</exception>
    /// <exception cref="GnuPGFormatException">The packets do not form exactly one transferable key.</exception>
    public TransferableKey ReadKey(OpenPgpLimits? limits = null)
    {
        IReadOnlyList<Packet> packets = PacketParser.ParseAll(Data, limits);
        IReadOnlyList<TransferableKey> keys = TransferableKey.ParseAll(packets);
        if (keys.Count != 1)
        {
            throw new GnuPGFormatException(GnuPGError.BadOpenPgp, Offset + DataOffset, keys.Count == 0 ? "no key in blob" : "more than one key in blob");
        }

        return keys[0];
    }
}

/// <summary>A blob carrying an X.509 certificate. It is not decoded further: <see cref="KeyboxKeyBlob.Data"/> is the DER certificate.</summary>
public sealed class KeyboxX509Blob : KeyboxKeyBlob
{
    internal KeyboxX509Blob(byte version, long offset, ReadOnlyMemory<byte> raw)
        : base(KeyboxBlobType.X509, version, offset, raw)
    {
    }

    /// <summary>The DER certificate.</summary>
    public ReadOnlyMemory<byte> Certificate => Data;

    /// <summary>The issuer name as the blob stores it (RFC 2253 style text).</summary>
    public string? Issuer => Names.Count > 0 ? Names[0].Text : null;

    /// <summary>The subject name as the blob stores it.</summary>
    public string? Subject => Names.Count > 1 ? Names[1].Text : null;
}

/// <summary>
/// A GnuPG keybox (<c>pubring.kbx</c>): a sequence of blobs, the first being the header. Read here with every offset and length checked
/// against the blob that holds it; the blobs keep their raw octets, so <see cref="Write"/> reproduces the input. The layout was established
/// from keyboxes written by GnuPG 2.2 to 2.5 and the field names GnuPG's <c>kbxutil</c> prints; see <c>docs/gnupg-home.md</c>.
/// </summary>
public sealed class Keybox
{
    private Keybox(IReadOnlyList<KeyboxBlob> blobs)
    {
        Blobs = blobs;
    }

    /// <summary>Every blob in file order, the header first.</summary>
    public IReadOnlyList<KeyboxBlob> Blobs { get; }

    /// <summary>The header blob, or null when the file does not start with one.</summary>
    public KeyboxHeaderBlob? Header => Blobs.Count > 0 ? Blobs[0] as KeyboxHeaderBlob : null;

    /// <summary>The OpenPGP blobs in file order.</summary>
    public IEnumerable<KeyboxOpenPgpBlob> OpenPgpBlobs => Blobs.OfType<KeyboxOpenPgpBlob>();

    /// <summary>The X.509 blobs in file order.</summary>
    public IEnumerable<KeyboxX509Blob> X509Blobs => Blobs.OfType<KeyboxX509Blob>();

    /// <summary>Reads a keybox.</summary>
    /// <param name="data">The file contents.</param>
    /// <param name="limits">Limits; null for <see cref="GnuPGLimits.Default"/>.</param>
    /// <exception cref="GnuPGFormatException">The first blob is not a header with the <c>KBXf</c> magic, a blob is shorter than its fixed part, or an offset, length or count points outside its blob.</exception>
    public static Keybox Parse(ReadOnlyMemory<byte> data, GnuPGLimits? limits = null)
    {
        limits ??= GnuPGLimits.Default;
        var blobs = new List<KeyboxBlob>();
        int pos = 0;
        while (pos < data.Length)
        {
            if (blobs.Count >= limits.MaxBlobs)
            {
                throw new GnuPGFormatException(GnuPGError.LimitExceeded, pos, "too many blobs");
            }

            if (data.Length - pos < 6)
            {
                throw new GnuPGFormatException(GnuPGError.Truncated, pos, "blob header");
            }

            uint length = BinaryPrimitives.ReadUInt32BigEndian(data.Span[pos..]);
            if (length < 6)
            {
                throw new GnuPGFormatException(GnuPGError.BadHeader, pos, "blob length");
            }

            if (length > limits.MaxBlobLength)
            {
                throw new GnuPGFormatException(GnuPGError.LimitExceeded, pos, "blob length");
            }

            if (length > data.Length - pos)
            {
                throw new GnuPGFormatException(GnuPGError.Truncated, pos, "blob extends past the end of the file");
            }

            ReadOnlyMemory<byte> raw = data.Slice(pos, (int)length);
            KeyboxBlob blob = ParseBlob(raw, pos, blobs.Count == 0);
            blobs.Add(blob);
            pos += (int)length;
        }

        if (blobs.Count == 0)
        {
            throw new GnuPGFormatException(GnuPGError.Truncated, 0, "empty keybox");
        }

        return new Keybox(blobs);
    }

    /// <summary>Reads a keybox without throwing for malformed input.</summary>
    /// <param name="data">The file contents.</param>
    /// <param name="keybox">The keybox, or null.</param>
    /// <param name="failure">The reason when this returns false.</param>
    /// <param name="limits">Limits; null for <see cref="GnuPGLimits.Default"/>.</param>
    /// <returns>True when the file was read.</returns>
    public static bool TryParse(ReadOnlyMemory<byte> data, out Keybox? keybox, out GnuPGFailure failure, GnuPGLimits? limits = null)
    {
        try
        {
            keybox = Parse(data, limits);
            failure = default;
            return true;
        }
        catch (GnuPGFormatException e)
        {
            keybox = null;
            failure = e.Failure;
            return false;
        }
    }

    /// <summary>Writes the blobs as read.</summary>
    /// <param name="destination">Where to write.</param>
    public void Write(Stream destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        foreach (KeyboxBlob blob in Blobs)
        {
            destination.Write(blob.Raw.Span);
        }
    }

    private static KeyboxBlob ParseBlob(ReadOnlyMemory<byte> raw, long offset, bool first)
    {
        ReadOnlySpan<byte> b = raw.Span;
        byte typeValue = b[4];
        byte version = b[5];
        if (first && typeValue != (byte)KeyboxBlobType.Header)
        {
            throw new GnuPGFormatException(GnuPGError.BadHeader, offset, "the first blob is not a header blob");
        }

        switch (typeValue)
        {
            case (byte)KeyboxBlobType.Header:
                return ParseHeader(raw, offset, version);
            case (byte)KeyboxBlobType.OpenPgp:
            {
                var blob = new KeyboxOpenPgpBlob(version, offset, raw);
                ParseKeyBlob(blob, offset);
                return blob;
            }

            case (byte)KeyboxBlobType.X509:
            {
                var blob = new KeyboxX509Blob(version, offset, raw);
                ParseKeyBlob(blob, offset);
                return blob;
            }

            case (byte)KeyboxBlobType.Empty:
                return new KeyboxUnknownBlob(KeyboxBlobType.Empty, version, offset, raw);
            default:
                return new KeyboxUnknownBlob((KeyboxBlobType)typeValue, version, offset, raw);
        }
    }

    private static KeyboxHeaderBlob ParseHeader(ReadOnlyMemory<byte> raw, long offset, byte version)
    {
        ReadOnlySpan<byte> b = raw.Span;
        if (b.Length < 24)
        {
            throw new GnuPGFormatException(GnuPGError.Truncated, offset, "header blob");
        }

        // The magic "KBXf" follows the type, version and 16-bit flags.
        if (b[8] != (byte)'K' || b[9] != (byte)'B' || b[10] != (byte)'X' || b[11] != (byte)'f')
        {
            throw new GnuPGFormatException(GnuPGError.BadHeader, offset + 8, "keybox magic");
        }

        return new KeyboxHeaderBlob(
            version,
            offset,
            raw,
            BinaryPrimitives.ReadUInt16BigEndian(b[6..]),
            BinaryPrimitives.ReadUInt32BigEndian(b[16..]),
            BinaryPrimitives.ReadUInt32BigEndian(b[20..]));
    }

    private static void ParseKeyBlob(KeyboxKeyBlob blob, long fileOffset)
    {
        ReadOnlyMemory<byte> raw = blob.Raw;
        ReadOnlySpan<byte> b = raw.Span;
        int length = b.Length;

        // Fixed part: length(4) type(1) version(1) flags(2) dataOffset(4) dataLength(4) keyCount(2) keyInfoLength(2).
        if (length < 20 + 20)
        {
            throw new GnuPGFormatException(GnuPGError.Truncated, fileOffset, "key blob");
        }

        int end = length - 20; // the 20 octets of checksum close the blob
        blob.FlagsValue = BinaryPrimitives.ReadUInt16BigEndian(b[6..]);
        uint dataOffset = BinaryPrimitives.ReadUInt32BigEndian(b[8..]);
        uint dataLength = BinaryPrimitives.ReadUInt32BigEndian(b[12..]);
        if (dataOffset > end || dataLength > end - dataOffset)
        {
            throw new GnuPGFormatException(GnuPGError.OutOfBounds, fileOffset + 8, "data");
        }

        blob.DataOffset = (int)dataOffset;
        blob.DataLength = (int)dataLength;

        var c = new BlobCursor(raw, end, fileOffset, 16);
        int keyCount = c.U16("key count");
        int keyInfoLength = c.U16("key info length");
        var keys = new List<KeyboxKeyInfo>(Math.Min(keyCount, 64));
        for (int i = 0; i < keyCount; i++)
        {
            ReadOnlySpan<byte> e = c.Take(keyInfoLength, "key info");
            keys.Add(ReadKeyInfo(blob, e, b));
        }

        blob.Keys = keys;

        int serialLength = c.U16("serial length");
        int serialStart = c.Position;
        c.Take(serialLength, "serial number");
        blob.SerialNumber = raw.Slice(serialStart, serialLength);

        int nameCount = c.U16("name count");
        int nameInfoLength = c.U16("name info length");
        if (nameCount > 0 && nameInfoLength < 12)
        {
            throw new GnuPGFormatException(GnuPGError.BadHeader, fileOffset + c.Position, "name info length");
        }

        var names = new List<KeyboxNameInfo>(Math.Min(nameCount, 64));
        for (int i = 0; i < nameCount; i++)
        {
            ReadOnlySpan<byte> e = c.Take(nameInfoLength, "name info");
            uint nameOffset = BinaryPrimitives.ReadUInt32BigEndian(e);
            uint nameLength = BinaryPrimitives.ReadUInt32BigEndian(e[4..]);
            if (nameOffset > end || nameLength > end - nameOffset)
            {
                throw new GnuPGFormatException(GnuPGError.OutOfBounds, fileOffset + c.Position, "name");
            }

            names.Add(new KeyboxNameInfo(raw.Slice((int)nameOffset, (int)nameLength), BinaryPrimitives.ReadUInt16BigEndian(e[8..]), e[10]));
        }

        blob.Names = names;

        int sigCount = c.U16("signature count");
        int sigInfoLength = c.U16("signature info length");
        if (sigCount > 0 && sigInfoLength < 4)
        {
            throw new GnuPGFormatException(GnuPGError.BadHeader, fileOffset + c.Position, "signature info length");
        }

        var sigs = new List<uint>(Math.Min(sigCount, 256));
        for (int i = 0; i < sigCount; i++)
        {
            sigs.Add(BinaryPrimitives.ReadUInt32BigEndian(c.Take(sigInfoLength, "signature info")));
        }

        blob.SignatureExpirations = sigs;

        // Trust fields: owner trust(1) validity(1) reserved(2) recheck-after(4) latest timestamp(4) created(4) reserved space(4).
        ReadOnlySpan<byte> t = c.Take(20, "trust fields");
        blob.OwnerTrust = t[0];
        blob.AllValidity = t[1];
        blob.RecheckAfter = BinaryPrimitives.ReadUInt32BigEndian(t[4..]);
        blob.LatestTimestamp = BinaryPrimitives.ReadUInt32BigEndian(t[8..]);
        blob.CreatedAtSeconds = BinaryPrimitives.ReadUInt32BigEndian(t[12..]);
        blob.ReservedSpace = BinaryPrimitives.ReadUInt32BigEndian(t[16..]);
        if (c.Position > blob.DataOffset)
        {
            throw new GnuPGFormatException(GnuPGError.OutOfBounds, fileOffset + c.Position, "index overlaps data");
        }

        Span<byte> digest = stackalloc byte[20]; // fixed small buffer
#pragma warning disable CA5350 // The keybox checksum is SHA-1 by definition; it detects damage and protects nothing.
        SHA1.HashData(b[..end], digest);
#pragma warning restore CA5350
        blob.ChecksumValid = CryptographicOperations.FixedTimeEquals(digest, b[end..]);
    }

    private static KeyboxKeyInfo ReadKeyInfo(KeyboxKeyBlob blob, ReadOnlySpan<byte> e, ReadOnlySpan<byte> blobBytes)
    {
        if (blob.Version >= 2 && e.Length >= 34)
        {
            // Version 2: a 32-octet fingerprint field (a 20-octet fingerprint is zero-padded) then the 16-bit flags.
            int fprLength = 20;
            for (int i = 20; i < 32; i++)
            {
                if (e[i] != 0)
                {
                    fprLength = 32;
                    break;
                }
            }

            return new KeyboxKeyInfo(e[..fprLength].ToArray(), [], BinaryPrimitives.ReadUInt16BigEndian(e[32..]));
        }

        if (e.Length < 28)
        {
            throw new GnuPGFormatException(GnuPGError.BadHeader, blob.Offset, "key info length");
        }

        // Version 1: 20-octet fingerprint, offset of the key ID within the blob, 16-bit flags, 16 reserved bits.
        uint kidOffset = BinaryPrimitives.ReadUInt32BigEndian(e[20..]);
        byte[] keyId = kidOffset <= blobBytes.Length - 28 && kidOffset + 8 <= blobBytes.Length - 20 ? blobBytes.Slice((int)kidOffset, 8).ToArray() : [];
        return new KeyboxKeyInfo(e[..20].ToArray(), keyId, BinaryPrimitives.ReadUInt16BigEndian(e[24..]));
    }

    private struct BlobCursor
    {
        private readonly ReadOnlyMemory<byte> _raw;
        private readonly int _end;
        private readonly long _fileOffset;

        public BlobCursor(ReadOnlyMemory<byte> raw, int end, long fileOffset, int position)
        {
            _raw = raw;
            _end = end;
            _fileOffset = fileOffset;
            Position = position;
        }

        public int Position { get; private set; }

        public ReadOnlySpan<byte> Take(int count, string what)
        {
            if (count < 0 || count > _end - Position)
            {
                throw new GnuPGFormatException(GnuPGError.OutOfBounds, _fileOffset + Position, what);
            }

            ReadOnlySpan<byte> s = _raw.Span.Slice(Position, count);
            Position += count;
            return s;
        }

        public int U16(string what) => BinaryPrimitives.ReadUInt16BigEndian(Take(2, what));
    }
}
