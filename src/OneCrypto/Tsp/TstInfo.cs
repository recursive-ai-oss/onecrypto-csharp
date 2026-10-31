using System.Linq;
using System.Globalization;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Tsp;

/// <summary>The accuracy of a time-stamp (RFC 3161 §2.4.2): how far genTime may be from the true time. Absent parts are zero.</summary>
/// <param name="Seconds">Whole seconds, or null when absent.</param>
/// <param name="Milliseconds">Milliseconds 1 to 999, or null when absent.</param>
/// <param name="Microseconds">Microseconds 1 to 999, or null when absent.</param>
public sealed record TimeStampAccuracy(int? Seconds = null, int? Milliseconds = null, int? Microseconds = null)
{
    /// <summary>The accuracy as a time span.</summary>
    public TimeSpan Total => TimeSpan.FromSeconds(Seconds ?? 0) + TimeSpan.FromMilliseconds(Milliseconds ?? 0) + TimeSpan.FromTicks((Microseconds ?? 0) * 10L);

    internal byte[] Encode()
    {
        var parts = new List<byte[]>();
        if (Seconds is int s)
        {
            parts.Add(DerWriter.SignedInteger(s));
        }

        if (Milliseconds is int ms)
        {
            parts.Add(DerWriter.Tlv(0x80, DerWriter.SignedInteger(ms).AsSpan(2).ToArray()));
        }

        if (Microseconds is int us)
        {
            parts.Add(DerWriter.Tlv(0x81, DerWriter.SignedInteger(us).AsSpan(2).ToArray()));
        }

        return DerWriter.Sequence([.. parts]);
    }
}

/// <summary>
/// The <c>TSTInfo</c> a time-stamp token signs (RFC 3161 §2.4.2). Immutable and lossless: <see cref="Encoded"/> is the structure as received, which is
/// the octets the token's signature covers.
/// </summary>
public sealed class TstInfo
{
    private readonly ReadOnlyMemory<byte> _extensions;
    private readonly TimeStampLimits _limits;
    private ExtensionCollection? _extensionList;

    private TstInfo(ReadOnlyMemory<byte> encoded, TimeStampLimits limits)
    {
        Encoded = encoded;
        _limits = limits;
        try
        {
            var outer = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader r = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            Version = r.ReadInt32();
            Policy = r.ReadObjectIdentifier();
            (HashAlgorithm, MessageImprint) = TspRead.ReadImprint(ref r, encoded, limits, "TSTInfo");
            SerialNumber = X509Read.Slice(encoded, r.ReadIntegerBytes());
            GenTime = r.ReadGeneralizedTime();
            if (r.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Sequence)
            {
                Accuracy = ReadAccuracy(ref r);
            }

            if (r.TryPeekTag(out t) && t == new Asn1Tag(Asn1Tags.Boolean))
            {
                Ordering = r.ReadBoolean();
            }

            if (r.TryPeekTag(out t) && t == new Asn1Tag(Asn1Tags.IntegerType))
            {
                Nonce = TspRead.ReadNonce(ref r, encoded, limits, "TSTInfo");
                HasNonce = true;
            }

            if (r.TryPeekTag(out t) && t == Asn1Tag.Context(0))
            {
                Asn1Reader w = r.ReadSequence(Asn1Tag.Context(0, true));
                Tsa = GeneralName.Parse(X509Read.Slice(encoded, w.ReadEncodedValue()));
                w.ThrowIfNotEmpty();
            }

            _extensions = TspRead.ReadExtensions(ref r, limits, 1, "TSTInfo");
            r.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException e)
        {
            throw new TimeStampParseException("TSTInfo", e);
        }
        catch (X509ParseException e)
        {
            throw new TimeStampParseException("TSTInfo", e.Message);
        }

        if (Version != 1)
        {
            throw new TimeStampParseException("TSTInfo", $"version {Version} is not understood (RFC 3161 §2.4.2 defines 1)");
        }

        if (SerialNumber.Length == 0 || (SerialNumber.Span[0] & 0x80) != 0)
        {
            // RFC 3161 §2.4.2: the serial number is a positive integer.
            throw new TimeStampParseException("TSTInfo", "the serial number is not a positive integer");
        }
    }

    private static TimeStampAccuracy ReadAccuracy(ref Asn1Reader parent)
    {
        Asn1Reader a = parent.ReadSequence();
        int? seconds = null, millis = null, micros = null;
        if (a.TryPeekTag(out Asn1Tag t) && t == new Asn1Tag(Asn1Tags.IntegerType))
        {
            seconds = a.ReadInt32();
        }

        if (a.TryPeekTag(out t) && t == Asn1Tag.Context(0))
        {
            millis = a.ReadInt32(Asn1Tag.Context(0));
        }

        if (a.TryPeekTag(out t) && t == Asn1Tag.Context(1))
        {
            micros = a.ReadInt32(Asn1Tag.Context(1));
        }

        a.ThrowIfNotEmpty();
        return new TimeStampAccuracy(seconds, millis, micros);
    }

    /// <summary>The structure exactly as received or built: what the token's signature covers.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The version: always 1.</summary>
    public int Version { get; }

    /// <summary>The policy under which the token was issued (an OID).</summary>
    public string Policy { get; } = string.Empty;

    /// <summary>The imprint's hash algorithm.</summary>
    public AlgorithmIdentifier HashAlgorithm { get; } = null!;

    /// <summary>The stamped digest.</summary>
    public ReadOnlyMemory<byte> MessageImprint { get; }

    /// <summary>The serial number's content octets (positive, unique per authority).</summary>
    public ReadOnlyMemory<byte> SerialNumber { get; }

    /// <summary>The time the authority says it stamped, UTC (fractions of a second kept).</summary>
    public DateTimeOffset GenTime { get; }

    /// <summary>The accuracy, or null when the token does not state one.</summary>
    public TimeStampAccuracy? Accuracy { get; }

    /// <summary>True when the authority promises that tokens are ordered by genTime (default false).</summary>
    public bool Ordering { get; }

    /// <summary>True when the token carries a nonce.</summary>
    public bool HasNonce { get; }

    /// <summary>The nonce INTEGER's content octets; empty when there is none.</summary>
    public ReadOnlyMemory<byte> Nonce { get; }

    /// <summary>The authority's name as it appears in the token, or null. When present it must identify the signer's certificate (RFC 3161 §2.4.2).</summary>
    public GeneralName? Tsa { get; }

    /// <summary>The token's extensions, possibly empty.</summary>
    public ExtensionCollection Extensions => _extensionList ??= _extensions.IsEmpty ? ExtensionCollection.Empty : ExtensionCollection.Decode(_extensions, _limits.X509, "TSTInfo");

    /// <summary>Reads a TSTInfo with the default limits.</summary>
    /// <exception cref="TimeStampParseException">The octets are not a version-1 TSTInfo.</exception>
    public static TstInfo Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, TimeStampLimits.Default);

    /// <summary>Reads a TSTInfo.</summary>
    /// <exception cref="TimeStampParseException">The octets are not a version-1 TSTInfo, or a limit is exceeded.</exception>
    public static TstInfo Parse(ReadOnlyMemory<byte> encoded, TimeStampLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxResponseSize)
        {
            throw new TimeStampParseException("TSTInfo", "larger than the limit");
        }

        return new TstInfo(encoded, limits);
    }

    /// <summary>Reads a TSTInfo, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out TstInfo? info)
    {
        try
        {
            info = Parse(encoded);
            return true;
        }
        catch (TimeStampParseException)
        {
            info = null;
            return false;
        }
    }

    /// <summary>Reads the TSTInfo a token holds.</summary>
    /// <exception cref="TimeStampParseException">The token's content is not a TSTInfo.</exception>
    public static TstInfo FromSignedData(SignedData token)
    {
        ArgumentNullException.ThrowIfNull(token);
        if (token.EncapsulatedContentType != CmsOids.TstInfo || !token.HasEncapsulatedContent)
        {
            throw new TimeStampParseException("TimeStampToken", "the token does not hold a TSTInfo (RFC 3161 §2.4.2)");
        }

        return Parse(token.EncapsulatedContent);
    }

    /// <summary>GeneralizedTime with at most <paramref name="fractionDigits"/> fractional digits and no trailing zeros (RFC 3161 §2.4.2).</summary>
    internal static byte[] EncodeGenTime(DateTimeOffset t, int fractionDigits)
    {
        DateTime u = t.UtcDateTime;
        string s = u.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        if (fractionDigits > 0)
        {
            string frac = (u.Ticks % TimeSpan.TicksPerSecond).ToString("D7", CultureInfo.InvariantCulture)[..Math.Min(fractionDigits, 7)].TrimEnd('0');
            if (frac.Length > 0)
            {
                s += "." + frac;
            }
        }

        return DerWriter.Tlv(0x18, System.Text.Encoding.ASCII.GetBytes(s + "Z"));
    }

    internal static byte[] Encode(string policy, AlgorithmIdentifier hash, ReadOnlySpan<byte> imprint, ReadOnlySpan<byte> serial, DateTimeOffset genTime, int fractionDigits,
        TimeStampAccuracy? accuracy, bool ordering, ReadOnlySpan<byte> nonceContent, GeneralName? tsa)
    {
        var parts = new List<byte[]>
        {
            DerWriter.SignedInteger(1),
            DerWriter.Oid(policy),
            DerWriter.Sequence(hash.Encoded.ToArray(), DerWriter.OctetString(imprint)),
            DerWriter.UnsignedInteger(serial),
            EncodeGenTime(genTime, fractionDigits),
        };
        if (accuracy is not null)
        {
            parts.Add(accuracy.Encode());
        }

        if (ordering)
        {
            parts.Add(DerWriter.Boolean(true));
        }

        if (!nonceContent.IsEmpty)
        {
            parts.Add(DerWriter.Tlv(0x02, nonceContent.ToArray()));
        }

        if (tsa is not null)
        {
            parts.Add(DerWriter.Context(0, tsa.Encoded.ToArray()));
        }

        return DerWriter.Sequence([.. parts]);
    }
}
