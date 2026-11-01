using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>How a signature fared (RFC 9580 §5.2.4 checks plus the key and policy rules around them).</summary>
public enum PgpSignatureStatus
{
    /// <summary>The signature verifies, the key was valid when it was made, and the policy accepts the algorithms.</summary>
    Valid,

    /// <summary>The signature value does not match the data.</summary>
    Invalid,

    /// <summary>No supplied certificate carries the issuing key.</summary>
    UnknownKey,

    /// <summary>The key was not bound, was expired, revoked or unable to sign when the signature was made, or the signature itself is expired or from the future.</summary>
    KeyNotValid,

    /// <summary>The crypto policy rejects the hash or key size for this signature date.</summary>
    Rejected,

    /// <summary>The signature uses an algorithm this build or platform cannot verify.</summary>
    Unsupported,
}

/// <summary>The outcome for one signature: who made it, when, with what, and why it was or was not accepted.</summary>
public sealed class PgpSignatureResult
{
    internal PgpSignatureResult(SignaturePacket signature, PgpSignatureStatus status, PgpKey? signer, PolicyDecision? policy, IReadOnlyList<string> reasons)
    {
        Signature = signature;
        Status = status;
        Signer = signer;
        Policy = policy;
        Reasons = reasons;
    }

    /// <summary>The signature packet.</summary>
    public SignaturePacket Signature { get; }

    /// <summary>The verdict.</summary>
    public PgpSignatureStatus Status { get; }

    /// <summary>True when <see cref="Status"/> is <see cref="PgpSignatureStatus.Valid"/>.</summary>
    public bool IsValid => Status == PgpSignatureStatus.Valid;

    /// <summary>The signing key found among the supplied certificates, or null.</summary>
    public PgpKey? Signer { get; }

    /// <summary>The signature creation time, or null when the signature carries none.</summary>
    public DateTimeOffset? CreatedAt => Signature.CreationTime is { } t ? DateTimeOffset.FromUnixTimeSeconds(t) : null;

    /// <summary>The policy's answer about the hash at the signature date, or null when it was not asked.</summary>
    public PolicyDecision? Policy { get; }

    /// <summary>Human-readable reasons, each naming the rule it comes from; empty for a clean valid signature.</summary>
    public IReadOnlyList<string> Reasons { get; }
}

/// <summary>What was found in a message: its literal data description, whether it was encrypted, how, and every signature with its verdict.</summary>
public sealed class PgpReadResult
{
    internal PgpReadResult()
    {
    }

    internal List<PgpSignatureResult> SignatureList { get; } = [];

    /// <summary>The signatures found in the message, in the order they were checked.</summary>
    public IReadOnlyList<PgpSignatureResult> Signatures => SignatureList;

    /// <summary>True when the message had an encryption layer.</summary>
    public bool WasEncrypted { get; internal set; }

    /// <summary>The session key that opened the message, when it was encrypted (for sop's <c>--session-key-out</c>); null otherwise.</summary>
    public byte[]? SessionKey { get; internal set; }

    /// <summary>The symmetric algorithm the session key belongs to.</summary>
    public SymmetricAlgorithm? SessionKeyCipher { get; internal set; }

    /// <summary>The literal data format octet ('b', 't', 'u', 'm'), or 0 when there was no literal packet.</summary>
    public byte LiteralFormat { get; internal set; }

    /// <summary>The file name stored in the literal packet (untrusted; do not use it as a path).</summary>
    public byte[] LiteralFileName { get; internal set; } = [];

    /// <summary>The date stored in the literal packet (seconds since 1970; 0 when unset).</summary>
    public uint LiteralDate { get; internal set; }

    /// <summary>True when the message was in a SEIPD v1 or other layer that was fully checked before any output (rather than chunk by chunk).</summary>
    public bool CheckedBeforeRelease { get; internal set; }

    /// <summary>True when at least one signature is valid.</summary>
    public bool HasValidSignature => SignatureList.Any(s => s.IsValid);
}

/// <summary>What a message must be for <see cref="PgpMessageReader"/> to accept it.</summary>
public enum PgpRequirement
{
    /// <summary>Encrypted or not.</summary>
    Any,

    /// <summary>The message must have an encryption layer.</summary>
    Encrypted,

    /// <summary>The message must not be encrypted.</summary>
    NotEncrypted,
}

/// <summary>Settings for reading, decrypting and verifying messages.</summary>
public sealed class PgpReadOptions
{
    /// <summary>The reference time: signatures from after it, or expired by it, are not valid. Required; there is no default clock.</summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>Certificates whose keys may have made the signatures. Secret certificates work too.</summary>
    public IReadOnlyList<PgpCertificate> Certificates { get; init; } = [];

    /// <summary>Certificates with secret keys used to open public-key encrypted data.</summary>
    public IReadOnlyList<PgpCertificate> SecretKeys { get; init; } = [];

    /// <summary>Passwords (UTF-8 octets) that unlock the secret keys.</summary>
    public IReadOnlyList<byte[]> KeyPasswords { get; init; } = [];

    /// <summary>Passwords (UTF-8 octets) for password-encrypted messages.</summary>
    public IReadOnlyList<byte[]> MessagePasswords { get; init; } = [];

    /// <summary>Session keys to try before any key or password.</summary>
    public IReadOnlyList<byte[]> SessionKeys { get; init; } = [];

    /// <summary>Session keys that come with their symmetric algorithm (needed for SEIPD v1), tried first.</summary>
    public IReadOnlyList<(SymmetricAlgorithm Cipher, byte[] Key)> SessionKeysWithCipher { get; init; } = [];

    /// <summary>The policy for hashes and key sizes. <see cref="CryptoPolicy.Standard"/> when null.</summary>
    public CryptoPolicy? Policy { get; init; }

    /// <summary>Whether the message must or must not be encrypted. Default <see cref="PgpRequirement.Any"/>.</summary>
    public PgpRequirement Require { get; init; }

    /// <summary>True to decrypt old Symmetrically Encrypted Data packets, which have no integrity protection. Default false: they are refused.</summary>
    public bool AllowUnauthenticatedEncryption { get; init; }

    /// <summary>Largest nesting of compression and encryption layers. Default 8.</summary>
    public int MaxNesting { get; init; } = 8;

    /// <summary>Packet limits for the parser. Default <see cref="OpenPgpLimits.Default"/>.</summary>
    public OpenPgpLimits? Limits { get; init; }
}
