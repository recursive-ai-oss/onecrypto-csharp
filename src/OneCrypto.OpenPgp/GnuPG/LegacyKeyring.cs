using System.Buffers.Binary;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.GnuPG;

/// <summary>The kind of data a GnuPG ring-trust packet carries.</summary>
public enum RingTrustKind
{
    /// <summary>A signature cache entry on a signature packet: a trust value and a cached verification result.</summary>
    Signature = 0,

    /// <summary>Where the key came from, on a primary key.</summary>
    KeySource = 1,

    /// <summary>Where the key came from, on a user ID.</summary>
    UserIdSource = 2,
}

/// <summary>
/// The contents of a trust packet (tag 12) in a legacy GnuPG keyring, which RFC 9580 §5.10 leaves implementation-defined. The packet itself is
/// always preserved as read; this is a view of it, decoded from GnuPG's documentation of the format.
/// </summary>
public sealed class RingTrust
{
    private RingTrust(RingTrustKind kind, byte trustValue, byte signatureCache, byte keySource, uint updateTime, string? sourceUrl)
    {
        Kind = kind;
        TrustValue = trustValue;
        SignatureCache = signatureCache;
        KeySource = keySource;
        UpdateTimeSeconds = updateTime;
        SourceUrl = sourceUrl;
    }

    /// <summary>What the packet describes.</summary>
    public RingTrustKind Kind { get; }

    /// <summary>The trust value (signature entries only; 0 otherwise).</summary>
    public byte TrustValue { get; }

    /// <summary>The cached signature-check result (signature entries only; 0 otherwise).</summary>
    public byte SignatureCache { get; }

    /// <summary>
    /// The origin of the key: 0 unknown, 1 public keyserver, 2 preferred keyserver, 3 OpenPGP DANE, 4 Web Key Directory, 5 trusted URL,
    /// 6 trusted file, 7 self-generated (key and user-ID entries only; 0 otherwise).
    /// </summary>
    public byte KeySource { get; }

    /// <summary>Time of the last update, seconds since the epoch (key and user-ID entries only).</summary>
    public uint UpdateTimeSeconds { get; }

    /// <summary>The URL of the source, or null when none was recorded.</summary>
    public string? SourceUrl { get; }

    /// <summary>Decodes a trust packet.</summary>
    /// <param name="packet">The packet.</param>
    /// <param name="trust">The decoded view, or null.</param>
    /// <returns>True when the body is one of the forms GnuPG writes: two octets (a signature entry), or trust value, cache, <c>gpg</c>, a subtype and for the key and user-ID subtypes a source, a time and a length-prefixed URL.</returns>
    public static bool TryDecode(TrustPacket packet, out RingTrust? trust)
    {
        ArgumentNullException.ThrowIfNull(packet);
        ReadOnlySpan<byte> b = packet.Body.Span;
        trust = null;
        if (b.Length == 2)
        {
            trust = new RingTrust(RingTrustKind.Signature, b[0], b[1], 0, 0, null);
            return true;
        }

        if (b.Length < 6 || b[2] != (byte)'g' || b[3] != (byte)'p' || b[4] != (byte)'g')
        {
            return false;
        }

        switch (b[5])
        {
            case 0:
                trust = new RingTrust(RingTrustKind.Signature, b[0], b[1], 0, 0, null);
                return true;
            case 1 or 2:
            {
                if (b.Length < 12)
                {
                    return false;
                }

                int urlLength = b[11];
                if (b.Length != 12 + urlLength)
                {
                    return false;
                }

                trust = new RingTrust(
                    b[5] == 1 ? RingTrustKind.KeySource : RingTrustKind.UserIdSource,
                    0,
                    0,
                    b[6],
                    BinaryPrimitives.ReadUInt32BigEndian(b[7..]),
                    urlLength == 0 ? null : System.Text.Encoding.UTF8.GetString(b.Slice(12, urlLength)));
                return true;
            }

            default:
                return false;
        }
    }
}

/// <summary>
/// GnuPG's legacy keyrings (<c>pubring.gpg</c>, <c>secring.gpg</c>): binary OpenPGP packets, transferable keys one after another, with GnuPG's
/// trust packets in between. Every packet keeps its bytes, so <see cref="Write"/> reproduces the input.
/// </summary>
public static class LegacyKeyring
{
    /// <summary>Reads a keyring into transferable keys. Ring-trust packets stay in each key's <c>OtherPackets</c> lists, in place.</summary>
    /// <param name="data">The file contents (binary, not armored).</param>
    /// <param name="limits">Limits for the packet reader; null for <see cref="OpenPgpLimits.Default"/>.</param>
    /// <returns>The keys in file order; empty for an empty file.</returns>
    /// <exception cref="OpenPgpParseException">The data is not a well-formed packet stream, or the packets do not group into transferable keys.</exception>
    public static IReadOnlyList<TransferableKey> Read(ReadOnlyMemory<byte> data, OpenPgpLimits? limits = null) =>
        TransferableKey.ParseAll(PacketParser.ParseAll(data, limits));

    /// <summary>Reads a keyring from a stream.</summary>
    /// <param name="input">The stream, read to its end.</param>
    /// <param name="limits">Limits for the packet reader; null for <see cref="OpenPgpLimits.Default"/>.</param>
    /// <exception cref="OpenPgpParseException">As for <see cref="Read(ReadOnlyMemory{byte}, OpenPgpLimits?)"/>.</exception>
    public static IReadOnlyList<TransferableKey> Read(Stream input, OpenPgpLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        return TransferableKey.ParseAll(PacketParser.ParseAll(input, limits));
    }

    /// <summary>Reads a keyring without throwing for malformed input.</summary>
    /// <param name="data">The file contents.</param>
    /// <param name="keys">The keys, or null.</param>
    /// <param name="failure">The reason when this returns false.</param>
    /// <param name="limits">Limits for the packet reader; null for <see cref="OpenPgpLimits.Default"/>.</param>
    /// <returns>True when the data was read.</returns>
    public static bool TryRead(ReadOnlyMemory<byte> data, out IReadOnlyList<TransferableKey>? keys, out OpenPgpFailure failure, OpenPgpLimits? limits = null)
    {
        try
        {
            keys = Read(data, limits);
            failure = default;
            return true;
        }
        catch (OpenPgpParseException e)
        {
            keys = null;
            failure = e.Failure;
            return false;
        }
    }

    /// <summary>Writes keys one after another, each with the packets it was read with (trust packets included).</summary>
    /// <param name="keys">The keys.</param>
    /// <param name="destination">Where to write.</param>
    public static void Write(IEnumerable<TransferableKey> keys, Stream destination)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(destination);
        foreach (TransferableKey k in keys)
        {
            k.WriteTo(destination);
        }
    }
}
