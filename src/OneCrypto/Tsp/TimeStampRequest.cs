using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Tsp;

/// <summary>Raised when a time-stamp request, response or TSTInfo cannot be read. Every <c>Parse</c> has a <c>TryParse</c> twin that returns false instead.</summary>
public sealed class TimeStampParseException : FormatException
{
    /// <summary>Creates the exception for <paramref name="structure"/> (for example "TimeStampReq").</summary>
    public TimeStampParseException(string structure, string message)
        : base($"{structure}: {message}")
    {
        Structure = structure;
    }

    /// <summary>Creates the exception for <paramref name="structure"/> with the ASN.1 failure behind it.</summary>
    public TimeStampParseException(string structure, Asn1ParseException inner)
        : base($"{structure}: {inner?.Message}", inner)
    {
        Structure = structure;
    }

    /// <summary>Creates an empty exception.</summary>
    public TimeStampParseException()
        : this("Time-stamp message", "malformed")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public TimeStampParseException(string message)
        : this("Time-stamp message", message)
    {
    }

    /// <summary>Creates the exception with a message and a cause.</summary>
    public TimeStampParseException(string message, Exception innerException)
        : base(message, innerException)
    {
        Structure = "Time-stamp message";
    }

    /// <summary>The structure being read.</summary>
    public string Structure { get; } = "Time-stamp message";
}

/// <summary>Resource limits for the time-stamp parsers. The defaults suit a request arriving from the network.</summary>
public sealed class TimeStampLimits
{
    /// <summary>The limits used when none are given.</summary>
    public static TimeStampLimits Default { get; } = new();

    /// <summary>Largest accepted request, response or TSTInfo in octets (default 64 KiB for a request; responses carry certificates, see <see cref="MaxResponseSize"/>).</summary>
    public int MaxRequestSize { get; init; } = 1 << 16;

    /// <summary>Largest accepted response or token in octets (default 1 MiB).</summary>
    public int MaxResponseSize { get; init; } = 1 << 20;

    /// <summary>Longest nonce in octets (default 64; RFC 3161 puts no bound on it, real clients send 8).</summary>
    public int MaxNonceLength { get; init; } = 64;

    /// <summary>Longest message imprint in octets (default 128, past SHA-512).</summary>
    public int MaxImprintLength { get; init; } = 128;

    /// <summary>The ASN.1 limits underneath (nesting depth 16).</summary>
    public Asn1Limits Asn1 { get; init; } = new Asn1Limits { MaxDepth = 16 };

    /// <summary>The PKI limits used for extensions and names inside the messages.</summary>
    public X509Limits X509 { get; init; } = X509Limits.Default;
}

/// <summary>Shared reading helpers of the time-stamp models.</summary>
internal static class TspRead
{
    /// <summary>Hashes a message imprint may use, with the digest length each fixes.</summary>
    public static bool TryImprintHash(string oid, out HashAlgorithmName name, out int length)
    {
        length = 0;
        if (!SignatureAlgorithms.TryHash(oid, out name))
        {
            return false;
        }

        length = name.Name switch
        {
            "SHA1" => 20,
            "SHA224" => 28,
            "SHA256" or "SHA3-256" => 32,
            "SHA384" or "SHA3-384" => 48,
            "SHA512" or "SHA3-512" => 64,
            _ => 0,
        };
        return length != 0;
    }

    /// <summary>Strips redundant leading octets so two encodings of one INTEGER compare equal.</summary>
    public static ReadOnlySpan<byte> NormalizeInteger(ReadOnlySpan<byte> s)
    {
        while (s.Length > 1 && ((s[0] == 0 && s[1] < 0x80) || (s[0] == 0xFF && s[1] >= 0x80)))
        {
            s = s[1..];
        }

        return s;
    }

    /// <summary>MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING } (RFC 3161 §2.4.1).</summary>
    public static (AlgorithmIdentifier Algorithm, ReadOnlyMemory<byte> Digest) ReadImprint(ref Asn1Reader parent, ReadOnlyMemory<byte> root, TimeStampLimits limits, string what)
    {
        Asn1Reader mi = parent.ReadSequence();
        AlgorithmIdentifier alg = AlgorithmIdentifier.Read(ref mi, root);
        ReadOnlySpan<byte> digest = mi.ReadOctetString();
        mi.ThrowIfNotEmpty();
        if (digest.Length == 0 || digest.Length > limits.MaxImprintLength)
        {
            throw new TimeStampParseException(what, "the message imprint has an unreasonable length");
        }

        return (alg, X509Read.Slice(root, digest));
    }

    public static ReadOnlyMemory<byte> ReadNonce(ref Asn1Reader r, ReadOnlyMemory<byte> root, TimeStampLimits limits, string what)
    {
        ReadOnlySpan<byte> n = r.ReadIntegerBytes();
        if (n.Length > limits.MaxNonceLength)
        {
            throw new TimeStampParseException(what, "the nonce is longer than the limit");
        }

        return X509Read.Slice(root, n);
    }

    /// <summary>Opens <c>[tag] IMPLICIT Extensions</c> when it is next, returning a SEQUENCE-tagged copy for the collection decoder.</summary>
    public static ReadOnlyMemory<byte> ReadExtensions(ref Asn1Reader r, TimeStampLimits limits, int contextTag, string what)
    {
        if (!r.TryPeekTag(out Asn1Tag t) || t != Asn1Tag.Context(contextTag))
        {
            return default;
        }

        byte[] copy = r.ReadEncodedValue().ToArray();
        copy[0] = 0x30;
        ExtensionCollection.Validate(copy, limits.X509, what);
        return copy;
    }
}

/// <summary>What goes into a time-stamp request (RFC 3161 §2.4.1).</summary>
public sealed class TimeStampRequestOptions
{
    /// <summary>The hash the imprint was made with: SHA-256, SHA-384, SHA-512 or a SHA-3 hash.</summary>
    public required HashAlgorithmName Hash { get; init; }

    /// <summary>The digest of the data to stamp. Its length must be the hash's.</summary>
    public required ReadOnlyMemory<byte> MessageImprint { get; init; }

    /// <summary>The policy the client asks for (an OID), or null to leave it to the authority.</summary>
    public string? Policy { get; init; }

    /// <summary>The nonce as unsigned big-endian octets, or empty for none. <see cref="TimeStampRequest.NewNonce"/> makes a good one. A nonce ties a response to its request; leaving it out is only right where replay does not matter.</summary>
    public ReadOnlyMemory<byte> Nonce { get; init; }

    /// <summary>True (the default) to ask the authority to include its certificate in the token.</summary>
    public bool CertReq { get; init; } = true;

    /// <summary>Request extensions, written after the standard fields.</summary>
    public IReadOnlyList<Extension> Extensions { get; init; } = [];
}

/// <summary>
/// A <c>TimeStampReq</c> (RFC 3161 §2.4.1). Immutable and lossless: <see cref="Encoded"/> is the request as received or built, and the accessors decode over it.
/// </summary>
public sealed class TimeStampRequest : IEquatable<TimeStampRequest>
{
    private readonly ReadOnlyMemory<byte> _extensions;
    private readonly TimeStampLimits _limits;
    private ExtensionCollection? _extensionList;

    private TimeStampRequest(ReadOnlyMemory<byte> encoded, TimeStampLimits limits)
    {
        Encoded = encoded;
        _limits = limits;
        try
        {
            var outer = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader r = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            Version = r.ReadInt32();
            (HashAlgorithm, MessageImprint) = TspRead.ReadImprint(ref r, encoded, limits, "TimeStampReq");
            if (r.TryPeekTag(out Asn1Tag t) && t == new Asn1Tag(Asn1Tags.ObjectIdentifier))
            {
                Policy = r.ReadObjectIdentifier();
            }

            if (r.TryPeekTag(out t) && t == new Asn1Tag(Asn1Tags.IntegerType))
            {
                Nonce = TspRead.ReadNonce(ref r, encoded, limits, "TimeStampReq");
                HasNonce = true;
            }

            if (r.TryPeekTag(out t) && t == new Asn1Tag(Asn1Tags.Boolean))
            {
                CertReq = r.ReadBoolean();
            }

            _extensions = TspRead.ReadExtensions(ref r, limits, 0, "TimeStampReq");
            r.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException e)
        {
            throw new TimeStampParseException("TimeStampReq", e);
        }
        catch (X509ParseException e)
        {
            throw new TimeStampParseException("TimeStampReq", e.Message);
        }

        if (Version != 1)
        {
            throw new TimeStampParseException("TimeStampReq", $"version {Version} is not understood (RFC 3161 §2.4.1 defines 1)");
        }
    }

    /// <summary>The request exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The version: always 1.</summary>
    public int Version { get; }

    /// <summary>The imprint's hash algorithm.</summary>
    public AlgorithmIdentifier HashAlgorithm { get; }

    /// <summary>The digest to stamp, as received.</summary>
    public ReadOnlyMemory<byte> MessageImprint { get; }

    /// <summary>The requested policy OID, or null.</summary>
    public string? Policy { get; }

    /// <summary>True when the request carries a nonce.</summary>
    public bool HasNonce { get; }

    /// <summary>The nonce INTEGER's content octets (two's complement, as encoded); empty when there is none.</summary>
    public ReadOnlyMemory<byte> Nonce { get; }

    /// <summary>True when the client wants the authority's certificate in the token (<c>certReq</c>, default false when absent).</summary>
    public bool CertReq { get; }

    /// <summary>The request extensions, possibly empty.</summary>
    public ExtensionCollection Extensions => _extensionList ??= _extensions.IsEmpty ? ExtensionCollection.Empty : ExtensionCollection.Decode(_extensions, _limits.X509, "TimeStampReq");

    /// <summary>Fresh nonce octets: 8 random octets from the system generator with the top bit clear, so the INTEGER is positive and short.</summary>
    public static byte[] NewNonce()
    {
        byte[] n = RandomNumberGenerator.GetBytes(8);
        n[0] &= 0x7F;
        n[0] |= 0x40; // a full 64 bits keeps the encoding the same length every time
        return n;
    }

    /// <summary>Builds a request.</summary>
    /// <exception cref="ArgumentException">The hash is not usable, the imprint's length does not fit it, or the policy is not an OID.</exception>
    public static TimeStampRequest Create(TimeStampRequestOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        string? oid = ImprintOid(options.Hash);
        if (oid is null || !TspRead.TryImprintHash(oid, out _, out int len))
        {
            throw new ArgumentException("Use SHA-256, SHA-384, SHA-512 or a SHA-3 hash for the message imprint.", nameof(options));
        }

        if (options.MessageImprint.Length != len)
        {
            throw new ArgumentException($"The message imprint is {options.MessageImprint.Length} octets; {options.Hash.Name} makes {len}.", nameof(options));
        }

        var parts = new List<byte[]>
        {
            DerWriter.SignedInteger(1),
            DerWriter.Sequence(AlgorithmIdentifier.Create(oid).Encoded.ToArray(), DerWriter.OctetString(options.MessageImprint.Span)),
        };
        if (options.Policy is { } policy)
        {
            parts.Add(DerWriter.Oid(policy));
        }

        if (!options.Nonce.IsEmpty)
        {
            parts.Add(DerWriter.UnsignedInteger(options.Nonce.Span));
        }

        if (options.CertReq)
        {
            parts.Add(DerWriter.Boolean(true));
        }

        if (options.Extensions.Count > 0)
        {
            parts.Add(DerWriter.Retag(BuildHelpers.Extensions(options.Extensions), 0xA0));
        }

        return Parse(DerWriter.Sequence([.. parts]));
    }

    /// <summary>Reads a request with the default limits.</summary>
    /// <exception cref="TimeStampParseException">The octets are not a version-1 time-stamp request, or a limit is exceeded.</exception>
    public static TimeStampRequest Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, TimeStampLimits.Default);

    /// <summary>Reads a request.</summary>
    /// <exception cref="TimeStampParseException">The octets are not a version-1 time-stamp request, or a limit is exceeded.</exception>
    public static TimeStampRequest Parse(ReadOnlyMemory<byte> encoded, TimeStampLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxRequestSize)
        {
            throw new TimeStampParseException("TimeStampReq", $"larger than the limit of {limits.MaxRequestSize} octets");
        }

        return new TimeStampRequest(encoded, limits);
    }

    /// <summary>Reads a request, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out TimeStampRequest? request)
    {
        try
        {
            request = Parse(encoded);
            return true;
        }
        catch (Exception e) when (e is TimeStampParseException or X509ParseException)
        {
            request = null;
            return false;
        }
    }

    internal static string? ImprintOid(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA256" => KnownOids.Sha256,
        "SHA384" => KnownOids.Sha384,
        "SHA512" => KnownOids.Sha512,
        "SHA3-256" => KnownOids.Sha3256,
        "SHA3-384" => KnownOids.Sha3384,
        "SHA3-512" => KnownOids.Sha3512,
        _ => null,
    };

    /// <inheritdoc/>
    public bool Equals(TimeStampRequest? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as TimeStampRequest);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = default(HashCode);
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }
}
