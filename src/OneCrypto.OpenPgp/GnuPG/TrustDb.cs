using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace RecursiveAI.OneCrypto.OpenPgp.GnuPG;

/// <summary>The owner-trust values GnuPG stores and exports. Other values are possible; <see cref="OwnerTrustEntry.Value"/> keeps the stored octet.</summary>
public enum OwnerTrustLevel : byte
{
    /// <summary>No owner trust recorded (0).</summary>
    Unknown = 0,

    /// <summary>"I don't know or won't say" (2); <c>gpg --with-colons</c> prints no letter or <c>q</c>.</summary>
    Undefined = 2,

    /// <summary>"I do NOT trust" (3); colons letter <c>n</c>.</summary>
    Never = 3,

    /// <summary>"I trust marginally" (4); colons letter <c>m</c>.</summary>
    Marginal = 4,

    /// <summary>"I trust fully" (5); colons letter <c>f</c>.</summary>
    Full = 5,

    /// <summary>"I trust ultimately" (6); colons letter <c>u</c>.</summary>
    Ultimate = 6,
}

/// <summary>The owner trust GnuPG records for one primary key, from a trust record of the trust database or a line of an owner-trust export.</summary>
public sealed class OwnerTrustEntry
{
    internal OwnerTrustEntry(byte[] fingerprint, byte value, byte depth, byte minOwnerTrust, byte flags, uint validList)
    {
        Fingerprint = fingerprint;
        Value = value;
        Depth = depth;
        MinOwnerTrust = minOwnerTrust;
        Flags = flags;
        ValidList = validList;
    }

    /// <summary>The fingerprint of the primary key: 20 octets in the trust database; an export may also carry a longer one.</summary>
    public ReadOnlyMemory<byte> Fingerprint { get; }

    /// <summary>The fingerprint as upper-case hexadecimal.</summary>
    public string FingerprintHex => Convert.ToHexString(Fingerprint.Span);

    /// <summary>The owner-trust octet as stored.</summary>
    public byte Value { get; }

    /// <summary>The owner trust as <see cref="OwnerTrustLevel"/> (values GnuPG does not name are cast through).</summary>
    public OwnerTrustLevel Level => (OwnerTrustLevel)Value;

    /// <summary>The depth octet of the trust record (0 in an export line).</summary>
    public byte Depth { get; }

    /// <summary>The minimum-owner-trust octet of the trust record (0 in an export line).</summary>
    public byte MinOwnerTrust { get; }

    /// <summary>The flags octet of the trust record (0 in an export line).</summary>
    public byte Flags { get; }

    /// <summary>Record number of the first validity record of this key (0 in an export line).</summary>
    public uint ValidList { get; }
}

/// <summary>
/// GnuPG's trust database (<c>trustdb.gpg</c>): fixed 40-octet records, the first being the version record. Only the owner-trust records
/// are decoded; computing validity from them is the trust model's job and is not done here.
/// </summary>
public sealed class TrustDb
{
    private const int RecordLength = 40;
    private const byte VersionRecord = 1;
    private const byte TrustRecord = 12;

    private TrustDb(IReadOnlyList<OwnerTrustEntry> entries, byte version, byte marginals, byte completes, byte depth, byte model, byte minLevel, uint created, uint nextCheck, int recordCount)
    {
        OwnerTrust = entries;
        Version = version;
        MarginalsNeeded = marginals;
        CompletesNeeded = completes;
        MaxCertDepth = depth;
        TrustModel = model;
        MinCertLevel = minLevel;
        CreatedAtSeconds = created;
        NextCheckSeconds = nextCheck;
        RecordCount = recordCount;
    }

    /// <summary>The owner-trust records in file order.</summary>
    public IReadOnlyList<OwnerTrustEntry> OwnerTrust { get; }

    /// <summary>The database version octet (3 in the files GnuPG 2.2 to 2.5 write).</summary>
    public byte Version { get; }

    /// <summary>How many marginally trusted keys are needed to certify a key (the "marginals needed" setting recorded in the version record).</summary>
    public byte MarginalsNeeded { get; }

    /// <summary>How many fully trusted keys are needed (the "completes needed" setting).</summary>
    public byte CompletesNeeded { get; }

    /// <summary>The trust-path depth recorded in the version record.</summary>
    public byte MaxCertDepth { get; }

    /// <summary>The trust model octet of the version record (1 is the classic "pgp" model in files GnuPG writes by default).</summary>
    public byte TrustModel { get; }

    /// <summary>The minimum certification level recorded in the version record.</summary>
    public byte MinCertLevel { get; }

    /// <summary>When the database was created, seconds since the epoch.</summary>
    public uint CreatedAtSeconds { get; }

    /// <summary>The "next check" time of the version record, seconds since the epoch.</summary>
    public uint NextCheckSeconds { get; }

    /// <summary>The number of 40-octet records in the file.</summary>
    public int RecordCount { get; }

    /// <summary>The owner trust recorded for a fingerprint, or null.</summary>
    /// <param name="fingerprint">The primary key's fingerprint; only the first 20 octets are compared with the database's 20-octet records.</param>
    public OwnerTrustEntry? Find(ReadOnlySpan<byte> fingerprint)
    {
        ReadOnlySpan<byte> f = fingerprint.Length > 20 ? fingerprint[..20] : fingerprint;
        foreach (OwnerTrustEntry e in OwnerTrust)
        {
            if (e.Fingerprint.Span.SequenceEqual(f)) // public data
            {
                return e;
            }
        }

        return null;
    }

    /// <summary>Reads a trust database.</summary>
    /// <param name="data">The file contents.</param>
    /// <param name="limits">Limits; null for <see cref="GnuPGLimits.Default"/>.</param>
    /// <exception cref="GnuPGFormatException">The length is not a multiple of 40, the first record is not a version record with the <c>gpg</c> magic, or a limit is exceeded.</exception>
    public static TrustDb Parse(ReadOnlySpan<byte> data, GnuPGLimits? limits = null)
    {
        limits ??= GnuPGLimits.Default;
        if (data.Length < RecordLength || data.Length % RecordLength != 0)
        {
            throw new GnuPGFormatException(GnuPGError.Truncated, data.Length, "trust database length");
        }

        int count = data.Length / RecordLength;
        if (count > limits.MaxTrustRecords)
        {
            throw new GnuPGFormatException(GnuPGError.LimitExceeded, 0, "trust records");
        }

        ReadOnlySpan<byte> v = data[..RecordLength];
        if (v[0] != VersionRecord || v[1] != (byte)'g' || v[2] != (byte)'p' || v[3] != (byte)'g')
        {
            throw new GnuPGFormatException(GnuPGError.BadHeader, 0, "trust database version record");
        }

        var entries = new List<OwnerTrustEntry>();
        for (int i = 1; i < count; i++)
        {
            ReadOnlySpan<byte> r = data.Slice(i * RecordLength, RecordLength);
            if (r[0] == TrustRecord)
            {
                entries.Add(new OwnerTrustEntry(r[2..22].ToArray(), r[22], r[23], r[24], r[25], BinaryPrimitives.ReadUInt32BigEndian(r[26..])));
            }
        }

        return new TrustDb(entries, v[4], v[5], v[6], v[7], v[8], v[9], BinaryPrimitives.ReadUInt32BigEndian(v[12..]), BinaryPrimitives.ReadUInt32BigEndian(v[16..]), count);
    }

    /// <summary>Reads a trust database without throwing for malformed input.</summary>
    /// <param name="data">The file contents.</param>
    /// <param name="db">The database, or null.</param>
    /// <param name="failure">The reason when this returns false.</param>
    /// <param name="limits">Limits; null for <see cref="GnuPGLimits.Default"/>.</param>
    /// <returns>True when the file was read.</returns>
    public static bool TryParse(ReadOnlySpan<byte> data, out TrustDb? db, out GnuPGFailure failure, GnuPGLimits? limits = null)
    {
        try
        {
            db = Parse(data, limits);
            failure = default;
            return true;
        }
        catch (GnuPGFormatException e)
        {
            db = null;
            failure = e.Failure;
            return false;
        }
    }
}

/// <summary>The text GnuPG's <c>--export-ownertrust</c> writes and <c>--import-ownertrust</c> reads: one <c>FINGERPRINT:LEVEL:</c> line per key, with <c>#</c> comments.</summary>
public static class OwnerTrustExport
{
    /// <summary>Reads an owner-trust export.</summary>
    /// <param name="text">The text.</param>
    /// <param name="limits">Limits; null for <see cref="GnuPGLimits.Default"/>.</param>
    /// <returns>The entries in order. Depth, minimum trust, flags and valid list are 0.</returns>
    /// <exception cref="GnuPGFormatException">A line is not a comment, blank, or <c>HEX:decimal:</c> with a 40- or 64-digit fingerprint and a level of 0 to 255.</exception>
    public static IReadOnlyList<OwnerTrustEntry> Parse(string text, GnuPGLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        limits ??= GnuPGLimits.Default;
        var list = new List<OwnerTrustEntry>();
        int lineNo = 0;
        foreach (string raw in text.Split('\n'))
        {
            lineNo++;
            if (lineNo > limits.MaxTextLines)
            {
                throw new GnuPGFormatException(GnuPGError.LimitExceeded, lineNo, "lines");
            }

            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            string[] parts = line.Split(':');
            if (parts.Length < 2 || (parts[0].Length is not (40 or 64)) || !byte.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out byte level))
            {
                throw new GnuPGFormatException(GnuPGError.BadSyntax, lineNo, "owner-trust line");
            }

            byte[] fpr;
            try
            {
                fpr = Convert.FromHexString(parts[0]);
            }
            catch (FormatException)
            {
                throw new GnuPGFormatException(GnuPGError.BadSyntax, lineNo, "fingerprint");
            }

            list.Add(new OwnerTrustEntry(fpr, level, 0, 0, 0, 0));
        }

        return list;
    }

    /// <summary>Writes entries in the export format, without the timestamped comment lines GnuPG adds.</summary>
    /// <param name="entries">The entries.</param>
    public static string Format(IEnumerable<OwnerTrustEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var sb = new StringBuilder();
        foreach (OwnerTrustEntry e in entries)
        {
            sb.Append(e.FingerprintHex).Append(':').Append(e.Value.ToString(CultureInfo.InvariantCulture)).Append(":\n");
        }

        return sb.ToString();
    }
}
