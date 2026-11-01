using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;

namespace RecursiveAI.OneCrypto.Pdf;

/// <summary>The PAdES baseline levels of ETSI EN 319 142-1 §6.</summary>
public enum PadesLevel
{
    /// <summary>The signature does not reach a baseline level (invalid, or not a CAdES-style signature).</summary>
    None,

    /// <summary>B-B (§6.2.1): a CAdES signature with the content type, message digest and signing-certificate-v2 attributes.</summary>
    Basic,

    /// <summary>B-T (§6.2.2): B-B plus a signature time-stamp over the signature value.</summary>
    Timestamped,

    /// <summary>B-LT (§6.2.3): B-T plus the validation data of the signer's and the time-stamp authority's chains in the document security store (/DSS).</summary>
    LongTerm,

    /// <summary>B-LTA (§6.2.4): B-LT plus a document time-stamp (ISO 32000-2 §12.8.5) that covers the signature and the /DSS.</summary>
    LongTermArchive,
}

/// <summary>
/// Gets an RFC 3161 time-stamp from an authority. The bridge never opens a connection: the caller plugs a transport in here (the
/// <c>.Online</c> package's client, a test authority, a hardware module). Return the DER <c>TimeStampResp</c> or the bare token.
/// </summary>
/// <param name="request">The <c>TimeStampReq</c> to answer. Its message imprint is the hash of the data to be time-stamped, its
/// nonce must be echoed and <c>certReq</c> is set.</param>
/// <param name="cancellationToken">Cancels the call.</param>
/// <returns>The response or token octets.</returns>
public delegate ValueTask<byte[]> PadesTimestampFunction(TimeStampRequest request, CancellationToken cancellationToken);

/// <summary>Why a signing or augmentation call stopped.</summary>
public enum PadesError
{
    /// <summary>An argument or option is not usable.</summary>
    InvalidArgument,

    /// <summary>The key cannot be used through the signing seam (for example an Ed25519 key: the seam signs a digest of RSA or ECDSA keys only).</summary>
    UnsupportedKey,

    /// <summary>The policy refused the signature algorithm.</summary>
    PolicyRejected,

    /// <summary>The level asks for a time-stamp function and none was given.</summary>
    NoTimestampFunction,

    /// <summary>The time-stamp authority's answer was refused (status, imprint, nonce or signature).</summary>
    TimestampRefused,

    /// <summary>No path from the certificate to a trust anchor was found, so no validation data can be collected for it.</summary>
    NoChain,

    /// <summary>The reserved space of a signature cannot hold the addition.</summary>
    NoRoom,

    /// <summary>The file cannot be augmented: it has no signature, or one cannot be read.</summary>
    UnsupportedFile,
}

/// <summary>Raised by the signing and augmentation calls when they cannot do what was asked. Verification never throws for bad input.</summary>
public sealed class PadesException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <param name="reason">Why.</param>
    /// <param name="message">What happened, in plain words.</param>
    public PadesException(PadesError reason, string message)
        : base(message)
    {
        Reason = reason;
    }

    /// <summary>Creates the exception with a cause.</summary>
    /// <param name="reason">Why.</param>
    /// <param name="message">What happened, in plain words.</param>
    /// <param name="innerException">The cause.</param>
    public PadesException(PadesError reason, string message, Exception innerException)
        : base(message, innerException)
    {
        Reason = reason;
    }

    /// <summary>Creates an exception for an unspecified failure.</summary>
    public PadesException()
        : this(PadesError.InvalidArgument, "PAdES operation failed.")
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What happened.</param>
    public PadesException(string message)
        : this(PadesError.InvalidArgument, message)
    {
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What happened.</param>
    /// <param name="innerException">The cause.</param>
    public PadesException(string message, Exception innerException)
        : this(PadesError.InvalidArgument, message, innerException)
    {
    }

    /// <summary>Why the call stopped.</summary>
    public PadesError Reason { get; }
}

/// <summary>
/// What the bridge needs to collect validation data for the document security store: trust anchors, a pool of intermediates,
/// the data the caller already holds, and (optionally) asynchronous sources that look more up. Nothing is fetched unless a source
/// is given, and the sources are the caller's.
/// </summary>
public sealed class PadesValidationData
{
    /// <summary>Trust anchors. Required to collect data: the chain of each certificate is found from these.</summary>
    public IReadOnlyList<TrustAnchor> TrustAnchors { get; init; } = [];

    /// <summary>Untrusted intermediates to build paths with, besides the certificates the PDF carries.</summary>
    public IReadOnlyList<Certificate> Intermediates { get; init; } = [];

    /// <summary>CRLs and OCSP responses the caller holds. Those that apply to a certificate on a collected path are written to the store.</summary>
    public RevocationData? Revocation { get; init; }

    /// <summary>Finds revocation data for a certificate (called with the locations the certificate names). Null means only <see cref="Revocation"/> is used.</summary>
    public IRevocationSource? RevocationSource { get; init; }

    /// <summary>Finds issuers a path lacks. Null means only the PDF's and the caller's certificates are used.</summary>
    public ICertificateSource? CertificateSource { get; init; }

    /// <summary>The instant the paths are validated at, and the time the store entries are dated with. Required: the bridge reads no clock.</summary>
    public required DateTimeOffset ReferenceTime { get; init; }

    /// <summary>The algorithm policy (default <see cref="CryptoPolicy.Standard"/>).</summary>
    public CryptoPolicy Policy { get; init; } = CryptoPolicy.Standard;

    /// <summary>
    /// Include the trust anchor certificates in the store (default true). EN 319 142-1 §6.3 (r) asks for the full set of certificates
    /// used to validate, the trust anchor included when it is available as a certificate.
    /// </summary>
    public bool IncludeAnchors { get; init; } = true;

    /// <summary>
    /// Also write a /VRI entry per signature (default false). EN 319 142-1 §6.3 (v) says the VRI dictionary should not be used: the
    /// store alone is enough, and a document time-stamp after it dates the data.
    /// </summary>
    public bool WriteVri { get; init; }
}

/// <summary>Choices for <see cref="PadesSigner"/>.</summary>
public sealed class PadesSignOptions
{
    /// <summary>The level to reach (default <see cref="PadesLevel.Basic"/>). Above Basic a <see cref="Timestamp"/> function is required, and from LongTerm up <see cref="ValidationData"/> is.</summary>
    public PadesLevel Level { get; init; } = PadesLevel.Basic;

    /// <summary>The field, page, appearance, reason, certification level and the rest, as OnePDF defines them. Its format, hash, RSA padding and time-stamp callback are replaced by the properties here.</summary>
    public OnePdf.PdfSigningOptions? Pdf { get; init; }

    /// <summary>The digest of the signed attributes (default SHA-256). SHA-1 is refused by the default policy.</summary>
    public HashAlgorithmName Hash { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>For RSA keys: RSASSA-PSS instead of PKCS #1 v1.5 (default false, the most widely understood).</summary>
    public bool RsaPss { get; init; }

    /// <summary>The time-stamp authority function for the signature time-stamp and the document time-stamps.</summary>
    public PadesTimestampFunction? Timestamp { get; init; }

    /// <summary>Hash of the document time-stamp's message imprint (default SHA-256).</summary>
    public HashAlgorithmName TimestampHash { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>What to collect for LongTerm and LongTermArchive.</summary>
    public PadesValidationData? ValidationData { get; init; }

    /// <summary>The algorithm policy asked about the new signature (default <see cref="CryptoPolicy.Standard"/>).</summary>
    public CryptoPolicy Policy { get; init; } = CryptoPolicy.Standard;

    /// <summary>The instant the policy is asked at when <see cref="ValidationData"/> is not given.</summary>
    public DateTimeOffset? ReferenceTime { get; init; }
}

/// <summary>Choices for <see cref="PadesAugmenter"/>.</summary>
public sealed class PadesAugmentOptions
{
    /// <summary>The level to reach for every signature in the file (default <see cref="PadesLevel.LongTermArchive"/>).</summary>
    public PadesLevel Level { get; init; } = PadesLevel.LongTermArchive;

    /// <summary>The time-stamp authority function. Required for Timestamped and LongTermArchive.</summary>
    public PadesTimestampFunction? Timestamp { get; init; }

    /// <summary>Hash of the time-stamp message imprints (default SHA-256).</summary>
    public HashAlgorithmName TimestampHash { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>What to collect. Required for LongTerm and LongTermArchive.</summary>
    public PadesValidationData? ValidationData { get; init; }
}

/// <summary>What <see cref="PadesSigner"/> wrote.</summary>
/// <param name="FieldName">The signature field.</param>
/// <param name="Level">The level reached.</param>
/// <param name="Revisions">How many incremental updates the call appended (the signature, then the store, then the document time-stamp).</param>
public sealed record PadesSignResult(string FieldName, PadesLevel Level, int Revisions);
