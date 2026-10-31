using System.Linq;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Tsp;

/// <summary>The <c>PKIStatus</c> of a time-stamp response (RFC 3161 §2.4.2).</summary>
public enum TimeStampStatus
{
    /// <summary>granted (0): the token is as requested.</summary>
    Granted = 0,

    /// <summary>grantedWithMods (1): the token is usable but differs from the request in some way the client must check.</summary>
    GrantedWithMods = 1,

    /// <summary>rejection (2): no token.</summary>
    Rejection = 2,

    /// <summary>waiting (3): the request is pending.</summary>
    Waiting = 3,

    /// <summary>revocationWarning (4): a revocation is imminent.</summary>
    RevocationWarning = 4,

    /// <summary>revocationNotification (5): a revocation has occurred.</summary>
    RevocationNotification = 5,
}

/// <summary>The <c>PKIFailureInfo</c> bits a time-stamp authority uses (RFC 3161 §2.4.2). The value of each member is <c>1 &lt;&lt; bit number</c>.</summary>
[Flags]
public enum TimeStampFailure : uint
{
    /// <summary>No bit set.</summary>
    None = 0,

    /// <summary>badAlg (0): unrecognized or unsupported algorithm identifier.</summary>
    BadAlg = 1u << 0,

    /// <summary>badRequest (2): the transaction is not permitted or supported.</summary>
    BadRequest = 1u << 2,

    /// <summary>badDataFormat (5): the data submitted has the wrong format.</summary>
    BadDataFormat = 1u << 5,

    /// <summary>timeNotAvailable (14): the TSA's time source is not available.</summary>
    TimeNotAvailable = 1u << 14,

    /// <summary>unacceptedPolicy (15): the requested policy is not supported.</summary>
    UnacceptedPolicy = 1u << 15,

    /// <summary>unacceptedExtension (16): the requested extension is not supported.</summary>
    UnacceptedExtension = 1u << 16,

    /// <summary>addInfoNotAvailable (17): the additional information requested could not be understood or is not available.</summary>
    AddInfoNotAvailable = 1u << 17,

    /// <summary>systemFailure (25): the request cannot be handled due to system failure.</summary>
    SystemFailure = 1u << 25,
}

/// <summary>
/// A <c>TimeStampResp</c> (RFC 3161 §2.4.2): a status and, when granted, a token. Immutable and lossless; the token's bytes are embedded as received.
/// </summary>
public sealed class TimeStampResponse : IEquatable<TimeStampResponse>
{
    private SignedData? _token;
    private bool _tokenRead;

    private TimeStampResponse(ReadOnlyMemory<byte> encoded, TimeStampLimits limits)
    {
        Encoded = encoded;
        Limits = limits;
        StatusStrings = [];
        try
        {
            var outer = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader r = outer.ReadSequence();
            outer.ThrowIfNotEmpty();

            // PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText OPTIONAL, failInfo PKIFailureInfo OPTIONAL }
            Asn1Reader s = r.ReadSequence();
            int code = s.ReadInt32();
            if (code is < 0 or > 5)
            {
                throw new TimeStampParseException("TimeStampResp", $"PKIStatus {code} is not defined");
            }

            Status = (TimeStampStatus)code;
            if (s.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Sequence)
            {
                Asn1Reader text = s.ReadSequence();
                var list = new List<string>();
                while (text.HasData)
                {
                    if (list.Count >= 16)
                    {
                        throw new TimeStampParseException("TimeStampResp", "too many status strings");
                    }

                    list.Add(text.ReadCharacterString(Asn1Tags.Utf8String));
                }

                StatusStrings = list;
            }

            if (s.TryPeekTag(out t) && t == new Asn1Tag(Asn1Tags.BitString))
            {
                ReadOnlySpan<byte> bits = s.ReadBitString(out int unused);
                uint v = 0;
                for (int bit = 0; bit < bits.Length * 8 - unused && bit < 32; bit++)
                {
                    if ((bits[bit / 8] & (0x80 >> (bit % 8))) != 0)
                    {
                        v |= 1u << bit;
                    }
                }

                FailureInfo = (TimeStampFailure)v;
            }

            s.ThrowIfNotEmpty();
            if (r.HasData)
            {
                TokenEncoded = X509Read.Slice(encoded, r.ReadEncodedValue());
            }

            r.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException e)
        {
            throw new TimeStampParseException("TimeStampResp", e);
        }
    }

    /// <summary>The response exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The limits the response was read with (and its token is read with).</summary>
    public TimeStampLimits Limits { get; }

    /// <summary>The status.</summary>
    public TimeStampStatus Status { get; }

    /// <summary>True for <see cref="TimeStampStatus.Granted"/> and <see cref="TimeStampStatus.GrantedWithMods"/>, the two statuses that must carry a token.</summary>
    public bool IsGranted => Status is TimeStampStatus.Granted or TimeStampStatus.GrantedWithMods;

    /// <summary>Free text the authority gave with the status (human readable, never to be trusted as data).</summary>
    public IReadOnlyList<string> StatusStrings { get; }

    /// <summary>The failure bits of a rejection, or <see cref="TimeStampFailure.None"/>.</summary>
    public TimeStampFailure FailureInfo { get; }

    /// <summary>The token's ContentInfo as received, or empty when the response has none.</summary>
    public ReadOnlyMemory<byte> TokenEncoded { get; }

    /// <summary>The token as a SignedData, or null when there is none or it is not a readable SignedData (the verifier reports which).</summary>
    public SignedData? Token
    {
        get
        {
            if (!_tokenRead)
            {
                _tokenRead = true;
                if (!TokenEncoded.IsEmpty && SignedData.TryParse(TokenEncoded, out SignedData? sd))
                {
                    _token = sd;
                }
            }

            return _token;
        }
    }

    /// <summary>Reads a response with the default limits.</summary>
    /// <exception cref="TimeStampParseException">The octets are not a time-stamp response.</exception>
    public static TimeStampResponse Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, TimeStampLimits.Default);

    /// <summary>Reads a response.</summary>
    /// <exception cref="TimeStampParseException">The octets are not a time-stamp response, or the limit is exceeded.</exception>
    public static TimeStampResponse Parse(ReadOnlyMemory<byte> encoded, TimeStampLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxResponseSize)
        {
            throw new TimeStampParseException("TimeStampResp", $"larger than the limit of {limits.MaxResponseSize} octets");
        }

        return new TimeStampResponse(encoded, limits);
    }

    /// <summary>Reads a response, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out TimeStampResponse? response)
    {
        try
        {
            response = Parse(encoded);
            return true;
        }
        catch (TimeStampParseException)
        {
            response = null;
            return false;
        }
    }

    internal static byte[] EncodeStatus(TimeStampStatus status, TimeStampFailure failure, string? text)
    {
        var parts = new List<byte[]> { DerWriter.SignedInteger((int)status) };
        if (!string.IsNullOrEmpty(text))
        {
            parts.Add(DerWriter.Sequence(DerWriter.Utf8String(text)));
        }

        if (failure != TimeStampFailure.None)
        {
            uint v = (uint)failure;
            int highest = 31 - System.Numerics.BitOperations.LeadingZeroCount(v);
            var bits = new byte[highest / 8 + 1];
            for (int bit = 0; bit <= highest; bit++)
            {
                if ((v & (1u << bit)) != 0)
                {
                    bits[bit / 8] |= (byte)(0x80 >> (bit % 8));
                }
            }

            int unused = bits.Length * 8 - (highest + 1);
            parts.Add(DerWriter.Tlv(0x03, [(byte)unused, .. bits]));
        }

        return DerWriter.Sequence([.. parts]);
    }

    /// <inheritdoc/>
    public bool Equals(TimeStampResponse? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as TimeStampResponse);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = default(HashCode);
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }
}
