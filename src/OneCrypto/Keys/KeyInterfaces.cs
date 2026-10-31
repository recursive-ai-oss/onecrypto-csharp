using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Keys;

/// <summary>What a key can be asked to do.</summary>
[Flags]
public enum KeyCapabilities
{
    /// <summary>Nothing.</summary>
    None = 0,
    /// <summary>Make signatures (<see cref="ISigningKey"/>).</summary>
    Sign = 1,
    /// <summary>Decrypt a key-transport message or decapsulate a KEM ciphertext (<see cref="IDecryptionKey"/>).</summary>
    Decrypt = 2,
    /// <summary>Derive a shared secret with a peer's public key (<see cref="IAgreementKey"/>).</summary>
    Agree = 4,
}

/// <summary>
/// A private key that stays where it lives. Implementations hold a platform handle, a pinned buffer, or a connection to a token or service; the key
/// bytes are never exposed. Disposing releases what the implementation owns (see each factory for who owns the wrapped key).
/// </summary>
public interface IKey : IDisposable
{
    /// <summary>The matching public key.</summary>
    PublicKeyInfo PublicKey { get; }

    /// <summary>The family of the key.</summary>
    KeyAlgorithm Algorithm => PublicKey.KeyAlgorithm;

    /// <summary>The operations the key offers.</summary>
    KeyCapabilities Capabilities { get; }
}

/// <summary>A key that signs. Each method has a sync and an async form; remote and token backends implement the async one natively.</summary>
public interface ISigningKey : IKey
{
    /// <summary>The spec used when the caller does not name one (see <see cref="SignatureSpec.DefaultFor"/>).</summary>
    SignatureSpec DefaultSpec { get; }

    /// <summary>True when the key can sign under <paramref name="spec"/> (the right family for the key; a context only where the algorithm has one).</summary>
    bool Supports(SignatureSpec spec);

    /// <summary>
    /// Signs <paramref name="data"/> and returns the signature in the spec's encoding. RSA and ECDSA hash the data first; EdDSA and ML-DSA sign it as given.
    /// </summary>
    /// <exception cref="NotSupportedException">The key does not support the spec.</exception>
    /// <exception cref="AlgorithmNotSupportedException">The platform lacks the algorithm.</exception>
    byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec);

    /// <summary>Signs a digest the caller computed with the spec's hash. Only for specs where <see cref="SignatureSpec.SignsDigest"/> is true.</summary>
    /// <exception cref="NotSupportedException">The spec signs the message, or the key does not support it.</exception>
    byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec);

    /// <summary>The async form of <see cref="Sign"/>.</summary>
    ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Sign(data.Span, spec));
    }

    /// <summary>The async form of <see cref="SignDigest"/>.</summary>
    ValueTask<byte[]> SignDigestAsync(ReadOnlyMemory<byte> digest, SignatureSpec spec, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(SignDigest(digest.Span, spec));
    }
}

/// <summary>What a decryption key is asked to undo.</summary>
public enum DecryptionKind
{
    /// <summary>RSAES-PKCS1-v1_5 (RFC 8017 §7.2). Vulnerable to padding-oracle misuse; offered for legacy messages.</summary>
    RsaPkcs1 = 1,
    /// <summary>RSAES-OAEP with MGF1 on the same hash (RFC 8017 §7.1).</summary>
    RsaOaep = 2,
    /// <summary>ML-KEM decapsulation (FIPS 203 §7.3): the input is the KEM ciphertext, the output the 32-octet shared secret.</summary>
    MlKem = 3,
}

/// <summary>How a <see cref="IDecryptionKey"/> decrypts: the family and, for OAEP, the hash.</summary>
public sealed class DecryptionSpec : IEquatable<DecryptionSpec>
{
    private DecryptionSpec(DecryptionKind kind, HashAlgorithmName hash)
    {
        Kind = kind;
        Hash = hash;
    }

    /// <summary>The family.</summary>
    public DecryptionKind Kind { get; }

    /// <summary>The OAEP hash (SHA-1, SHA-256, SHA-384 or SHA-512); empty for the other families.</summary>
    public HashAlgorithmName Hash { get; }

    /// <summary>RSAES-PKCS1-v1_5.</summary>
    public static DecryptionSpec RsaPkcs1() => new(DecryptionKind.RsaPkcs1, default);

    /// <summary>RSAES-OAEP with <paramref name="hash"/> for both the label hash and MGF1 (RFC 8017 §7.1; the empty label).</summary>
    public static DecryptionSpec RsaOaep(HashAlgorithmName hash) => new(DecryptionKind.RsaOaep, hash);

    /// <summary>ML-KEM decapsulation.</summary>
    public static DecryptionSpec MlKem() => new(DecryptionKind.MlKem, default);

    /// <inheritdoc/>
    public bool Equals(DecryptionSpec? other) => other is not null && Kind == other.Kind && Hash == other.Hash;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as DecryptionSpec);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Kind, Hash.Name);

    /// <inheritdoc/>
    public override string ToString() => Kind == DecryptionKind.RsaOaep ? $"RSAES-OAEP {Hash.Name}" : Kind == DecryptionKind.RsaPkcs1 ? "RSAES-PKCS1-v1_5" : "ML-KEM";
}

/// <summary>A key that decrypts a wrapped key or decapsulates a KEM ciphertext.</summary>
public interface IDecryptionKey : IKey
{
    /// <summary>True when the key can decrypt under <paramref name="spec"/>.</summary>
    bool Supports(DecryptionSpec spec);

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/>. The caller wipes the result when done. A failed RSAES-PKCS1-v1_5 or OAEP decryption throws
    /// <see cref="CryptographicException"/> without saying why (RFC 8017 §7.1.2 note on error oracles).
    /// </summary>
    /// <exception cref="NotSupportedException">The key does not support the spec.</exception>
    /// <exception cref="CryptographicException">The ciphertext did not decrypt.</exception>
    byte[] Decrypt(ReadOnlySpan<byte> ciphertext, DecryptionSpec spec);

    /// <summary>The async form of <see cref="Decrypt"/>.</summary>
    ValueTask<byte[]> DecryptAsync(ReadOnlyMemory<byte> ciphertext, DecryptionSpec spec, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Decrypt(ciphertext.Span, spec));
    }
}

/// <summary>A key that derives a shared secret with a peer (ECDH, X25519, X448).</summary>
public interface IAgreementKey : IKey
{
    /// <summary>
    /// Derives the raw shared secret with <paramref name="peer"/>: the x-coordinate of the shared point for ECDH (SEC 1 §3.3.1, RFC 6090), the
    /// u-coordinate result of RFC 7748 §5 for X25519 and X448. Callers run it through a KDF; it is not a key.
    /// </summary>
    /// <exception cref="ArgumentException">The peer's key is of another family or curve.</exception>
    /// <exception cref="CryptographicException">The secret is invalid (X25519 and X448 refuse an all-zero result, RFC 7748 §6.1).</exception>
    byte[] Agree(PublicKeyInfo peer);

    /// <summary>The async form of <see cref="Agree"/>.</summary>
    ValueTask<byte[]> AgreeAsync(PublicKeyInfo peer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Agree(peer));
    }
}

/// <summary>An RSA private key: signs (PKCS #1 v1.5 and PSS) and decrypts (PKCS #1 v1.5 and OAEP).</summary>
public interface IRsaKey : ISigningKey, IDecryptionKey
{
}
