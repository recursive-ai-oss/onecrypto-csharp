using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Pem;

namespace RecursiveAI.OneCrypto;

/// <summary>Why a PKI structure (certificate, request, revocation list, OCSP message or extension) could not be read.</summary>
public enum X509Error
{
    /// <summary>The octets are not well-formed ASN.1; <see cref="Exception.InnerException"/> carries the position.</summary>
    Asn1,

    /// <summary>The ASN.1 is well-formed but a required element is missing, extra, or of the wrong type.</summary>
    UnexpectedStructure,

    /// <summary>A version number the library does not read.</summary>
    UnsupportedVersion,

    /// <summary>A value is outside what the structure allows (for example a negative length, an unknown enumeration, bad text).</summary>
    InvalidValue,

    /// <summary>A configured limit (see <see cref="X509Limits"/>) was exceeded.</summary>
    LimitExceeded,
}

/// <summary>Raised when a PKI structure cannot be read. Every <c>Parse</c> has a <c>TryParse</c> twin that returns false instead.</summary>
public sealed class X509ParseException : FormatException
{
    /// <summary>Creates the exception for <paramref name="structure"/> (for example "Certificate").</summary>
    public X509ParseException(string structure, X509Error error, string message)
        : base($"{structure}: {message}")
    {
        Structure = structure;
        Error = error;
    }

    /// <summary>Creates the exception for <paramref name="structure"/> with the ASN.1 failure that caused it.</summary>
    public X509ParseException(string structure, Asn1ParseException inner)
        : base($"{structure}: {inner?.Message}", inner)
    {
        Structure = structure;
        Error = X509Error.Asn1;
    }

    /// <summary>Creates an empty exception.</summary>
    public X509ParseException()
        : this("X.509", X509Error.UnexpectedStructure, "malformed")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public X509ParseException(string message)
        : this("X.509", X509Error.UnexpectedStructure, message)
    {
    }

    /// <summary>Creates the exception with a message and a cause.</summary>
    public X509ParseException(string message, Exception innerException)
        : base(message, innerException)
    {
        Structure = "X.509";
        Error = X509Error.Asn1;
    }

    /// <summary>The kind of structure being read.</summary>
    public string Structure { get; } = "X.509";

    /// <summary>The category of the failure.</summary>
    public X509Error Error { get; }
}

/// <summary>Resource limits applied by the PKI readers. The defaults suit certificates, requests and OCSP messages from untrusted sources.</summary>
public sealed class X509Limits
{
    /// <summary>The limits used when none are given.</summary>
    public static X509Limits Default { get; } = new();

    /// <summary>Largest accepted encoding in octets of a certificate, request, attribute certificate or OCSP message (1 MiB). Revocation lists have their own limit.</summary>
    public int MaxEncodedSize { get; init; } = 1 << 20;

    /// <summary>Largest accepted revocation list in octets (256 MiB).</summary>
    public int MaxCrlSize { get; init; } = 1 << 28;

    /// <summary>Most extensions in one list (128).</summary>
    public int MaxExtensions { get; init; } = 128;

    /// <summary>Most relative distinguished names in one name, and most attributes in one of them (64 each).</summary>
    public int MaxNameElements { get; init; } = 64;

    /// <summary>Longest encoded distinguished name in octets (64 KiB).</summary>
    public int MaxNameLength { get; init; } = 1 << 16;

    /// <summary>Most entries read from any one list inside an extension value, such as general names, policies or distribution points (10,000).</summary>
    public int MaxListEntries { get; init; } = 10_000;

    /// <summary>Most certificates carried inside one OCSP message (64).</summary>
    public int MaxEmbeddedCertificates { get; init; } = 64;

    /// <summary>The ASN.1 limits the readers use underneath (nesting depth 32, other values as <see cref="Asn1Limits.Default"/>).</summary>
    public Asn1Limits Asn1 { get; init; } = new Asn1Limits { MaxDepth = 32 };
}

/// <summary>Reading helpers shared by the PKI models.</summary>
internal static class X509Read
{
    public static X509ParseException Bad(string what, string message) => new(what, X509Error.UnexpectedStructure, message);

    public static X509ParseException Invalid(string what, string message) => new(what, X509Error.InvalidValue, message);

    public static X509ParseException Limit(string what, string message) => new(what, X509Error.LimitExceeded, message);

    /// <summary>The slice of <paramref name="root"/> that <paramref name="sub"/> (a span taken from it) covers.</summary>
    public static ReadOnlyMemory<byte> Slice(ReadOnlyMemory<byte> root, ReadOnlySpan<byte> sub)
    {
        if (sub.Length == 0 || !root.Span.Overlaps(sub, out int offset))
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        return root.Slice(offset, sub.Length);
    }

    /// <summary>Runs <paramref name="parse"/> and turns an ASN.1 failure into the typed exception for <paramref name="what"/>.</summary>
    public static T Run<T>(string what, Func<T> parse)
    {
        try
        {
            return parse();
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException(what, e);
        }
    }

    public static bool Try<T>(Func<T> parse, out T value)
        where T : class
    {
        try
        {
            value = parse();
            return true;
        }
        catch (X509ParseException)
        {
            value = null!;
            return false;
        }
    }

    /// <summary>Checks that <paramref name="alg"/> is an AlgorithmIdentifier and returns its slice of <paramref name="root"/>, so a later read of it cannot fail.</summary>
    public static ReadOnlyMemory<byte> Algorithm(ReadOnlySpan<byte> alg, ReadOnlyMemory<byte> root, X509Limits limits)
    {
        try
        {
            var outer = new Asn1Reader(alg, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader seq = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            seq.ReadObjectIdentifierBytes();
            if (seq.HasData)
            {
                seq.SkipValue();
                seq.ThrowIfNotEmpty();
            }
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("AlgorithmIdentifier", e);
        }

        return Slice(root, alg);
    }

    /// <summary>The blocks of PEM text (lax mode), with a PEM failure reported as the typed error for the structure.</summary>
    public static IReadOnlyList<PemBlock> Pem(string what, string text)
    {
        try
        {
            return PemCodec.ParseAll(text, PemMode.Lax);
        }
        catch (PemFormatException e)
        {
            throw new X509ParseException(what + ": " + e.Message, e);
        }
    }

    /// <summary>Reads a whole-element DER/BER value that must be the only thing in <paramref name="data"/>.</summary>
    public static Asn1Reader Open(ReadOnlyMemory<byte> data, string what, X509Limits limits, int maxSize)
    {
        if (data.Length > maxSize)
        {
            throw Limit(what, $"{data.Length} octets exceed the limit of {maxSize}.");
        }

        return new Asn1Reader(data.Span, Asn1Rules.Ber, limits.Asn1);
    }
}
