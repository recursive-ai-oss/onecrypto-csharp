using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// Ed25519 (RFC 8032 section 5.1) in its three flavours: plain Ed25519, Ed25519ctx (with a context string) and Ed25519ph
/// (over a SHA-512 prehash, with an optional context). Span one-shots live here; <see cref="Ed25519PrivateKey"/> and
/// <see cref="Ed25519PublicKey"/> keep a key between calls.
/// </summary>
/// <remarks>
/// <para><b>What verification accepts.</b> A signature verifies when all of these hold: it is 64 bytes; S (its second half)
/// is below the group order, which removes signature malleability (RFC 8032 section 5.1.7); the public key A and the point R
/// (its first half) are canonical encodings, with y below 2^255 - 19, on the curve, and not "negative zero"; and the
/// cofactorless equation [S]B = R + [k]A holds exactly, with R compared as an encoding. Consequences against the C2SP Ed25519
/// edge-case set: non-canonical A and R are rejected; low-order A and R are accepted when the equation holds; signatures whose
/// low-order components do not cancel (only the cofactored equation [8][S]B = [8]R + [8][k]A would pass them) are rejected.
/// This is the behaviour of the widely deployed reference implementations, except that non-canonical A is also rejected as the
/// RFC requires. Verification is not batchable and does not accept everything ZIP-215 does.</para>
/// <para><b>Constant time.</b> Signing and key derivation never branch on, index by or stop early on secret data (see the
/// remarks on <see cref="Ed25519PrivateKey"/>); verification works on public data only and is variable time.</para>
/// </remarks>
public static class Ed25519
{
    /// <summary>The size of a private seed in bytes.</summary>
    public const int SeedSize = 32;

    /// <summary>The size of a public key in bytes.</summary>
    public const int PublicKeySize = 32;

    /// <summary>The size of a signature in bytes.</summary>
    public const int SignatureSize = 64;

    /// <summary>The size of the SHA-512 prehash that Ed25519ph signs.</summary>
    public const int PrehashSize = 64;

    /// <summary>The longest context RFC 8032 allows, in bytes.</summary>
    public const int MaxContextSize = 255;

    private static ReadOnlySpan<byte> DomPrefix => "SigEd25519 no Ed25519 collisions"u8;

    /// <summary>Computes the public key for a seed (RFC 8032 section 5.1.5).</summary>
    /// <param name="seed">The 32-byte private seed.</param>
    /// <param name="publicKey">Receives the 32-byte public key.</param>
    /// <exception cref="ArgumentException">A span has the wrong length.</exception>
    public static void DerivePublicKey(ReadOnlySpan<byte> seed, Span<byte> publicKey)
    {
        CheckLength(seed, SeedSize, nameof(seed));
        CheckLength(publicKey, PublicKeySize, nameof(publicKey));
        Span<byte> expanded = stackalloc byte[64]; // fixed small buffer
        Expand(seed, expanded);
        Ge25519 a = Ge25519Ops.ScalarMultBase(expanded[..32]);
        Ge25519Ops.Encode(a, publicKey);
        CryptographicOperations.ZeroMemory(expanded);
    }

    /// <summary>Signs <paramref name="message"/> with plain Ed25519.</summary>
    /// <param name="seed">The 32-byte private seed.</param>
    /// <param name="message">The message; any length.</param>
    /// <param name="signature">Receives the 64-byte signature.</param>
    /// <param name="bytesWritten">64 on success, otherwise 0.</param>
    /// <returns>False if <paramref name="signature"/> is shorter than 64 bytes.</returns>
    /// <exception cref="ArgumentException"><paramref name="seed"/> is not 32 bytes.</exception>
    public static bool TrySign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message, Span<byte> signature, out int bytesWritten) =>
        TrySignCore(seed, -1, default, message, signature, out bytesWritten);

    /// <summary>Signs <paramref name="message"/> with Ed25519ctx, binding the signature to <paramref name="context"/>.</summary>
    /// <param name="seed">The 32-byte private seed.</param>
    /// <param name="message">The message; any length.</param>
    /// <param name="context">1 to 255 bytes. RFC 8032 section 8.3 says the context should not be empty for Ed25519ctx; an empty one is refused.</param>
    /// <param name="signature">Receives the 64-byte signature.</param>
    /// <param name="bytesWritten">64 on success, otherwise 0.</param>
    /// <returns>False if <paramref name="signature"/> is shorter than 64 bytes.</returns>
    /// <exception cref="ArgumentException">The seed is not 32 bytes, or the context is empty or longer than 255 bytes.</exception>
    public static bool TrySignWithContext(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten)
    {
        if (context.Length == 0)
        {
            throw new ArgumentException("Ed25519ctx needs a non-empty context.", nameof(context));
        }
        return TrySignCore(seed, 0, context, message, signature, out bytesWritten);
    }

    /// <summary>Signs <paramref name="message"/> with Ed25519ph: the message is hashed with SHA-512 first.</summary>
    /// <param name="seed">The 32-byte private seed.</param>
    /// <param name="message">The message; any length.</param>
    /// <param name="context">0 to 255 bytes; empty by default in RFC 8032.</param>
    /// <param name="signature">Receives the 64-byte signature.</param>
    /// <param name="bytesWritten">64 on success, otherwise 0.</param>
    /// <returns>False if <paramref name="signature"/> is shorter than 64 bytes.</returns>
    /// <exception cref="ArgumentException">The seed is not 32 bytes, or the context is longer than 255 bytes.</exception>
    public static bool TrySignPrehashed(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten)
    {
        Span<byte> prehash = stackalloc byte[PrehashSize]; // fixed small buffer
        SHA512.HashData(message, prehash);
        return TrySignHash(seed, prehash, context, signature, out bytesWritten);
    }

    /// <summary>Signs a SHA-512 digest computed by the caller with Ed25519ph (for messages hashed as a stream).</summary>
    /// <param name="seed">The 32-byte private seed.</param>
    /// <param name="sha512Digest">The 64-byte SHA-512 digest of the message.</param>
    /// <param name="context">0 to 255 bytes.</param>
    /// <param name="signature">Receives the 64-byte signature.</param>
    /// <param name="bytesWritten">64 on success, otherwise 0.</param>
    /// <returns>False if <paramref name="signature"/> is shorter than 64 bytes.</returns>
    /// <exception cref="ArgumentException">The seed or digest has the wrong length, or the context is longer than 255 bytes.</exception>
    public static bool TrySignHash(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> sha512Digest, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten)
    {
        CheckLength(sha512Digest, PrehashSize, nameof(sha512Digest));
        return TrySignCore(seed, 1, context, sha512Digest, signature, out bytesWritten);
    }

    /// <summary>Verifies a plain Ed25519 signature. Returns false for any malformed input; it never throws on data.</summary>
    /// <param name="publicKey">The 32-byte public key.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="signature">The 64-byte signature.</param>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) =>
        VerifyCore(publicKey, -1, default, message, signature);

    /// <summary>Verifies an Ed25519ctx signature. Returns false for any malformed input, including an empty or over-long context.</summary>
    /// <param name="publicKey">The 32-byte public key.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="context">The context the signer used, 1 to 255 bytes.</param>
    /// <param name="signature">The 64-byte signature.</param>
    public static bool VerifyWithContext(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
        context.Length != 0 && VerifyCore(publicKey, 0, context, message, signature);

    /// <summary>Verifies an Ed25519ph signature over <paramref name="message"/>. Returns false for any malformed input.</summary>
    /// <param name="publicKey">The 32-byte public key.</param>
    /// <param name="message">The signed message; it is hashed with SHA-512 here.</param>
    /// <param name="context">The context the signer used, 0 to 255 bytes.</param>
    /// <param name="signature">The 64-byte signature.</param>
    public static bool VerifyPrehashed(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature)
    {
        Span<byte> prehash = stackalloc byte[PrehashSize]; // fixed small buffer
        SHA512.HashData(message, prehash);
        return VerifyHash(publicKey, prehash, context, signature);
    }

    /// <summary>Verifies an Ed25519ph signature over a SHA-512 digest computed by the caller. Returns false for any malformed input.</summary>
    /// <param name="publicKey">The 32-byte public key.</param>
    /// <param name="sha512Digest">The 64-byte SHA-512 digest of the message.</param>
    /// <param name="context">The context the signer used, 0 to 255 bytes.</param>
    /// <param name="signature">The 64-byte signature.</param>
    public static bool VerifyHash(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> sha512Digest, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
        sha512Digest.Length == PrehashSize && VerifyCore(publicKey, 1, context, sha512Digest, signature);

    // --- shared core ---

    internal static void CheckLength(ReadOnlySpan<byte> s, int expected, string name)
    {
        if (s.Length != expected)
        {
            throw new ArgumentException($"Expected {expected} bytes.", name);
        }
    }

    /// <summary>RFC 8032 section 5.1.5: h = SHA-512(seed); the low half, clamped, is the secret scalar, the high half the nonce prefix.</summary>
    internal static void Expand(ReadOnlySpan<byte> seed, Span<byte> expanded)
    {
        EdHash.Sha512(expanded, seed);
        expanded[0] &= 248;
        expanded[31] &= 127;
        expanded[31] |= 64;
    }

    /// <summary>dom2(f, c) of RFC 8032 section 5.1; empty for plain Ed25519 (flag -1). Returns the number of bytes written.</summary>
    private static int Dom2(Span<byte> to, int flag, ReadOnlySpan<byte> context)
    {
        if (flag < 0)
        {
            return 0;
        }
        DomPrefix.CopyTo(to);
        to[32] = (byte)flag;
        to[33] = (byte)context.Length;
        context.CopyTo(to[34..]);
        return 34 + context.Length;
    }

    private static bool TrySignCore(ReadOnlySpan<byte> seed, int flag, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, Span<byte> signature, out int bytesWritten)
    {
        CheckLength(seed, SeedSize, nameof(seed));
        if (context.Length > MaxContextSize)
        {
            throw new ArgumentException("A context is at most 255 bytes.", nameof(context));
        }
        bytesWritten = 0;
        if (signature.Length < SignatureSize)
        {
            return false;
        }
        Span<byte> expanded = stackalloc byte[64]; // fixed small buffer
        Expand(seed, expanded);
        Span<byte> publicKey = stackalloc byte[PublicKeySize];
        Ge25519Ops.Encode(Ge25519Ops.ScalarMultBase(expanded[..32]), publicKey);
        SignExpanded(expanded[..32], expanded[32..], publicKey, flag, context, message, signature);
        CryptographicOperations.ZeroMemory(expanded);
        bytesWritten = SignatureSize;
        return true;
    }

    /// <summary>RFC 8032 section 5.1.6 from the expanded secret: scalar <paramref name="a"/> and nonce <paramref name="prefix"/>.</summary>
    internal static void SignExpanded(ReadOnlySpan<byte> a, ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> publicKey, int flag, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, Span<byte> signature)
    {
        ScalarField sc = Ed25519Scalar.Field;
        Span<byte> dom = stackalloc byte[34 + MaxContextSize]; // fixed small buffer
        ReadOnlySpan<byte> domain = dom[..Dom2(dom, flag, context)];
        Span<byte> hash = stackalloc byte[64];
        Span<ulong> r = stackalloc ulong[4];
        Span<ulong> k = stackalloc ulong[4];
        Span<ulong> aL = stackalloc ulong[4];
        Span<ulong> s = stackalloc ulong[4];
        Span<byte> rBytes = stackalloc byte[32];

        // r = SHA-512(dom2 || prefix || M) mod L is the secret nonce; R = [r]B.
        EdHash.Sha512(hash, domain, prefix, message);
        sc.ReduceWide(hash, r);
        ScalarField.Store(r, rBytes);
        Ge25519Ops.Encode(Ge25519Ops.ScalarMultBase(rBytes), signature[..32]);

        // k = SHA-512(dom2 || R || A || M) mod L; S = (r + k a) mod L.
        EdHash.Sha512(hash, domain, signature[..32], publicKey, message);
        sc.ReduceWide(hash, k);
        ScalarField.Load(a, aL);
        sc.MulAdd(aL, k, r, s);
        ScalarField.Store(s, signature.Slice(32, 32));

        CryptographicOperations.ZeroMemory(hash);
        CryptographicOperations.ZeroMemory(rBytes);
        r.Clear();
        aL.Clear();
        s.Clear();
    }

    private static bool VerifyCore(ReadOnlySpan<byte> publicKey, int flag, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != PublicKeySize || signature.Length != SignatureSize || context.Length > MaxContextSize)
        {
            return false;
        }
        ReadOnlySpan<byte> rBytes = signature[..32];
        ReadOnlySpan<byte> sBytes = signature[32..];
        ScalarField sc = Ed25519Scalar.Field;
        // RFC 8032 section 5.1.7: S must be below L (rules out S + L malleability).
        if (!sc.IsBelowModulus(sBytes) || !Ge25519Ops.TryDecode(publicKey, out Ge25519 a))
        {
            return false;
        }
        Span<byte> dom = stackalloc byte[34 + MaxContextSize]; // fixed small buffer
        ReadOnlySpan<byte> domain = dom[..Dom2(dom, flag, context)];
        Span<byte> hash = stackalloc byte[64];
        EdHash.Sha512(hash, domain, rBytes, publicKey, message);
        Span<ulong> kl = stackalloc ulong[4];
        sc.ReduceWide(hash, kl);
        Span<byte> k = stackalloc byte[32];
        ScalarField.Store(kl, k);

        // R' = [S]B - [k]A, compared with R as an encoding. A non-canonical R can never equal a canonical re-encoding.
        Span<byte> check = stackalloc byte[32];
        Ge25519Ops.Encode(Ge25519Ops.DoubleScalarMulBaseVartime(sBytes, k, Ge25519Ops.Negate(a)), check);
        return check.SequenceEqual(rBytes);
    }
}

/// <summary>
/// An Ed25519 public key. Immutable and cheap to keep; verification does the point decoding on each call and rejects
/// invalid keys by returning false.
/// </summary>
public sealed class Ed25519PublicKey
{
    private readonly byte[] _bytes;

    private Ed25519PublicKey(byte[] bytes) => _bytes = bytes;

    /// <summary>Wraps 32 public-key bytes. The bytes are not checked to be a valid point; verification with an invalid key fails.</summary>
    /// <exception cref="ArgumentException">The input is not 32 bytes.</exception>
    public static Ed25519PublicKey FromBytes(ReadOnlySpan<byte> publicKey)
    {
        Ed25519.CheckLength(publicKey, Ed25519.PublicKeySize, nameof(publicKey));
        return new Ed25519PublicKey(publicKey.ToArray());
    }

    /// <summary>Wraps 32 public-key bytes; false if the length is wrong.</summary>
    public static bool TryFromBytes(ReadOnlySpan<byte> publicKey, out Ed25519PublicKey? key)
    {
        key = publicKey.Length == Ed25519.PublicKeySize ? new Ed25519PublicKey(publicKey.ToArray()) : null;
        return key is not null;
    }

    /// <summary>Copies the 32-byte public key into <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException">The destination is shorter than 32 bytes.</exception>
    public void Export(Span<byte> destination)
    {
        if (destination.Length < Ed25519.PublicKeySize)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }
        _bytes.CopyTo(destination);
    }

    /// <summary>The 32-byte public key as a new array.</summary>
    public byte[] ToArray() => (byte[])_bytes.Clone();

    /// <inheritdoc cref="Ed25519.Verify"/>
    public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) => Ed25519.Verify(_bytes, message, signature);

    /// <inheritdoc cref="Ed25519.VerifyWithContext"/>
    public bool VerifyWithContext(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
        Ed25519.VerifyWithContext(_bytes, message, context, signature);

    /// <inheritdoc cref="Ed25519.VerifyPrehashed"/>
    public bool VerifyPrehashed(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
        Ed25519.VerifyPrehashed(_bytes, message, context, signature);

    /// <inheritdoc cref="Ed25519.VerifyHash"/>
    public bool VerifyHash(ReadOnlySpan<byte> sha512Digest, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
        Ed25519.VerifyHash(_bytes, sha512Digest, context, signature);
}

/// <summary>
/// An Ed25519 private key. The seed and its expansion live in a pinned buffer that is zeroed on <see cref="Dispose"/>. The
/// runtime cannot promise that no other copy of a secret exists; this narrows the window, it does not close it.
/// </summary>
/// <remarks>
/// <b>Constant time.</b> The secret scalar and the nonce only ever meet fixed-width limb arithmetic with masks. [scalar]B
/// recodes the scalar into signed 4-bit digits and, for each digit, reads every entry of the table row and keeps one with a
/// mask, so neither the memory addresses nor the sequence of group operations depend on the scalar. The group law is
/// complete, so no case is special. Hashing uses the platform's SHA-512.
/// </remarks>
public sealed class Ed25519PrivateKey : IDisposable
{
    // seed (32) || clamped scalar (32) || nonce prefix (32)
    private readonly PinnedSecret _secret;
    private readonly Ed25519PublicKey _publicKey;

    private Ed25519PrivateKey(PinnedSecret secret, Ed25519PublicKey publicKey)
    {
        _secret = secret;
        _publicKey = publicKey;
    }

    /// <summary>Generates a key from the platform's random number generator.</summary>
    public static Ed25519PrivateKey Generate()
    {
        Span<byte> seed = stackalloc byte[Ed25519.SeedSize]; // fixed small buffer
        RandomNumberGenerator.Fill(seed);
        try
        {
            return FromSeed(seed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>Creates a key from its 32-byte seed (the RFC 8032 "private key").</summary>
    /// <exception cref="ArgumentException">The seed is not 32 bytes.</exception>
    public static Ed25519PrivateKey FromSeed(ReadOnlySpan<byte> seed)
    {
        Ed25519.CheckLength(seed, Ed25519.SeedSize, nameof(seed));
        var secret = new PinnedSecret(96);
        seed.CopyTo(secret.Span);
        Ed25519.Expand(seed, secret.Span.Slice(32, 64));
        Span<byte> pub = stackalloc byte[Ed25519.PublicKeySize];
        Ge25519Ops.Encode(Ge25519Ops.ScalarMultBase(secret.Span.Slice(32, 32)), pub);
        return new Ed25519PrivateKey(secret, Ed25519PublicKey.FromBytes(pub));
    }

    /// <summary>The matching public key.</summary>
    public Ed25519PublicKey PublicKey => _publicKey;

    /// <summary>Copies the 32-byte seed into <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException">The destination is shorter than 32 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public void ExportSeed(Span<byte> destination)
    {
        if (destination.Length < Ed25519.SeedSize)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }
        _secret.ReadOnlySpan[..Ed25519.SeedSize].CopyTo(destination);
    }

    /// <summary>Signs with plain Ed25519; see <see cref="Ed25519.TrySign"/>.</summary>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public bool TrySign(ReadOnlySpan<byte> message, Span<byte> signature, out int bytesWritten) =>
        TrySignCore(-1, default, message, signature, out bytesWritten);

    /// <summary>Signs with Ed25519ctx; see <see cref="Ed25519.TrySignWithContext"/>.</summary>
    /// <exception cref="ArgumentException">The context is empty or longer than 255 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public bool TrySignWithContext(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten)
    {
        if (context.Length == 0)
        {
            throw new ArgumentException("Ed25519ctx needs a non-empty context.", nameof(context));
        }
        return TrySignCore(0, context, message, signature, out bytesWritten);
    }

    /// <summary>Signs with Ed25519ph, hashing the message with SHA-512; see <see cref="Ed25519.TrySignPrehashed"/>.</summary>
    /// <exception cref="ArgumentException">The context is longer than 255 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public bool TrySignPrehashed(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten)
    {
        Span<byte> prehash = stackalloc byte[Ed25519.PrehashSize]; // fixed small buffer
        SHA512.HashData(message, prehash);
        return TrySignHash(prehash, context, signature, out bytesWritten);
    }

    /// <summary>Signs a caller-computed SHA-512 digest with Ed25519ph; see <see cref="Ed25519.TrySignHash"/>.</summary>
    /// <exception cref="ArgumentException">The digest is not 64 bytes, or the context is longer than 255 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public bool TrySignHash(ReadOnlySpan<byte> sha512Digest, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten)
    {
        Ed25519.CheckLength(sha512Digest, Ed25519.PrehashSize, nameof(sha512Digest));
        return TrySignCore(1, context, sha512Digest, signature, out bytesWritten);
    }

    private bool TrySignCore(int flag, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, Span<byte> signature, out int bytesWritten)
    {
        ReadOnlySpan<byte> secret = _secret.ReadOnlySpan;
        if (context.Length > Ed25519.MaxContextSize)
        {
            throw new ArgumentException("A context is at most 255 bytes.", nameof(context));
        }
        bytesWritten = 0;
        if (signature.Length < Ed25519.SignatureSize)
        {
            return false;
        }
        Span<byte> pub = stackalloc byte[Ed25519.PublicKeySize]; // fixed small buffer
        _publicKey.Export(pub);
        Ed25519.SignExpanded(secret.Slice(32, 32), secret.Slice(64, 32), pub, flag, context, message, signature);
        bytesWritten = Ed25519.SignatureSize;
        return true;
    }

    /// <summary>Zeroes the key material.</summary>
    public void Dispose() => _secret.Dispose();
}
