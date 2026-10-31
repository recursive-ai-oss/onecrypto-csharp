using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto.Wire.Cms;

/// <summary>Why a CMS structure could not be read or an operation on it could not run.</summary>
public enum CmsError
{
    /// <summary>The octets are not well-formed ASN.1; <see cref="Exception.InnerException"/> carries the position.</summary>
    Asn1,

    /// <summary>The ASN.1 is well-formed but a required element is missing, extra, or of the wrong type.</summary>
    UnexpectedStructure,

    /// <summary>The ContentInfo holds another content type than the one asked for.</summary>
    UnexpectedContentType,

    /// <summary>A version number or algorithm the library does not read.</summary>
    Unsupported,

    /// <summary>A value is outside what the structure allows.</summary>
    InvalidValue,

    /// <summary>A configured limit (see <see cref="CmsLimits"/>) was exceeded.</summary>
    LimitExceeded,

    /// <summary>No recipient info in the message is meant for the key.</summary>
    NoMatchingRecipient,

    /// <summary>Decryption failed. The cause is deliberately not distinguished (RFC 3218 §2.3).</summary>
    DecryptionFailed,
}

/// <summary>Raised when a CMS structure cannot be read, or decryption fails. Every <c>Parse</c> has a <c>TryParse</c> twin that returns false instead.</summary>
public sealed class CmsParseException : FormatException
{
    /// <summary>Creates the exception for <paramref name="structure"/> (for example "SignedData").</summary>
    public CmsParseException(string structure, CmsError error, string message)
        : base($"{structure}: {message}")
    {
        Structure = structure;
        Error = error;
    }

    /// <summary>Creates the exception for <paramref name="structure"/> with the ASN.1 failure that caused it.</summary>
    public CmsParseException(string structure, Asn1ParseException inner)
        : base($"{structure}: {inner?.Message}", inner)
    {
        Structure = structure;
        Error = CmsError.Asn1;
    }

    /// <summary>Creates an empty exception.</summary>
    public CmsParseException()
        : this("CMS", CmsError.UnexpectedStructure, "malformed")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public CmsParseException(string message)
        : this("CMS", CmsError.UnexpectedStructure, message)
    {
    }

    /// <summary>Creates the exception with a message and a cause.</summary>
    public CmsParseException(string message, Exception innerException)
        : base(message, innerException)
    {
        Structure = "CMS";
        Error = CmsError.Asn1;
    }

    /// <summary>The kind of structure being read.</summary>
    public string Structure { get; } = "CMS";

    /// <summary>The category of the failure.</summary>
    public CmsError Error { get; }
}

/// <summary>Limits applied when reading and processing CMS, on by default. Raise them only for input you trust.</summary>
public sealed class CmsLimits
{
    /// <summary>The defaults.</summary>
    public static CmsLimits Default { get; } = new();

    /// <summary>Most SignerInfos in a SignedData (default 64).</summary>
    public int MaxSigners { get; init; } = 64;

    /// <summary>Most certificates or revocation lists in a SignedData, each (default 1024).</summary>
    public int MaxCertificates { get; init; } = 1024;

    /// <summary>Most attributes in one attribute set (default 64).</summary>
    public int MaxAttributes { get; init; } = 64;

    /// <summary>Most values in one attribute (default 16).</summary>
    public int MaxAttributeValues { get; init; } = 16;

    /// <summary>Largest encoding of one attribute value, in octets (default 4 MiB: an embedded time-stamp token or revocation data).</summary>
    public int MaxAttributeBytes { get; init; } = 4 << 20;

    /// <summary>Most recipients of an EnvelopedData, AuthenticatedData or AuthEnvelopedData (default 1024).</summary>
    public int MaxRecipients { get; init; } = 1024;

    /// <summary>Most countersignature levels followed (default 4).</summary>
    public int MaxCountersignatureDepth { get; init; } = 4;

    /// <summary>Largest encapsulated or encrypted content a one-shot call holds in memory (default 1 GiB).</summary>
    public long MaxContentBytes { get; init; } = 1L << 30;

    /// <summary>Largest ratio of decompressed to compressed size accepted for CompressedData (default 1000).</summary>
    public int MaxDecompressionRatio { get; init; } = 1000;

    /// <summary>Largest decompressed size accepted whatever the ratio (default 1 GiB).</summary>
    public long MaxDecompressedBytes { get; init; } = 1L << 30;

    /// <summary>Largest PBKDF2 iteration count accepted from a PasswordRecipientInfo (default 10 million).</summary>
    public int MaxPbkdf2Iterations { get; init; } = 10_000_000;

    /// <summary>Limits of the ASN.1 layer under the CMS parser.</summary>
    public Asn1Limits Asn1 { get; init; } = Asn1Limits.Default;
}
