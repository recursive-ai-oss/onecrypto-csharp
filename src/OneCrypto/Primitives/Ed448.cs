using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// Ed448 and Ed448ph (RFC 8032 section 5.2). Unlike Ed25519, every Ed448 signature carries a domain-separation prefix that
/// includes a context string (empty by default), so there is one pure flavour with an optional context and one prehashed flavour.
/// Span one-shots live here; <see cref="Ed448PrivateKey"/> and <see cref="Ed448PublicKey"/> keep a key between calls.
/// </summary>
/// <remarks>
/// <para><b>What verification accepts.</b> A signature verifies when all of these hold: it is 114 bytes; S (its second half)
/// is below the group order and its padding byte is zero; the public key A and the point R (its first half) are canonical
/// encodings (y below p, on the curve, the unused bits of the last byte zero, not "negative zero"); and the cofactorless equation
/// [S]B = R + [k]A holds, with R compared as an encoding. RFC 8032 section 5.2.7 allows this form as well as the cofactored one.</para>
/// <para><b>Hashing.</b> Ed448 needs SHAKE256. The platform's is used where it exists; otherwise (macOS, for one) a managed
/// Keccak that is constant time by construction gives identical output, so Ed448 runs on every platform.</para>
/// </remarks>
public static class Ed448
{
    /// <summary>The size of a private seed in bytes.</summary>
    public const int SeedSize = 57;

    /// <summary>The size of a public key in bytes.</summary>
    public const int PublicKeySize = 57;

    /// <summary>The size of a signature in bytes.</summary>
    public const int SignatureSize = 114;

    /// <summary>The size of the SHAKE256 prehash that Ed448ph signs.</summary>
    public const int PrehashSize = 64;

    /// <summary>The longest context RFC 8032 allows, in bytes.</summary>
    public const int MaxContextSize = 255;

    private static ReadOnlySpan<byte> DomPrefix => "SigEd448"u8;

    /// <summary>Computes the public key for a seed (RFC 8032 section 5.2.5).</summary>
    /// <param name="seed">The 57-byte private seed.</param>
    /// <param name="publicKey">Receives the 57-byte public key.</param>
    /// <exception cref="ArgumentException">A span has the wrong length.</exception>
    public static void DerivePublicKey(ReadOnlySpan<byte> seed, Span<byte> publicKey)
    {
        CheckLength(seed, SeedSize, nameof(seed));
        CheckLength(publicKey, PublicKeySize, nameof(publicKey));
        Span<byte> expanded = stackalloc byte[114]; // fixed small buffer
        Span<byte> scalar = stackalloc byte[56];
        Expand(seed, expanded, scalar);
        Ge448Ops.Encode(Ge448Ops.ScalarMultBase(scalar), publicKey);
        CryptographicOperations.ZeroMemory(expanded);
        CryptographicOperations.ZeroMemory(scalar);
    }

    /// <summary>Signs <paramref name="message"/> with Ed448.</summary>
    /// <param name="seed">The 57-byte private seed.</param>
    /// <param name="message">The message; any length.</param>
    /// <param name="context">0 to 255 bytes; empty for the usual case.</param>
    /// <param name="signature">Receives the 114-byte signature.</param>
    /// <param name="bytesWritten">114 on success, otherwise 0.</param>
    /// <returns>False if <paramref name="signature"/> is shorter than 114 bytes.</returns>
    /// <exception cref="ArgumentException">The seed is not 57 bytes, or the context is longer than 255 bytes.</exception>
    public static bool TrySign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten) =>
        TrySignCore(seed, 0, context, message, signature, out bytesWritten);

    /// <summary>Signs <paramref name="message"/> with Ed448ph: the message is hashed with SHAKE256 (64 bytes) first.</summary>
    /// <param name="seed">The 57-byte private seed.</param>
    /// <param name="message">The message; any length.</param>
    /// <param name="context">0 to 255 bytes.</param>
    /// <param name="signature">Receives the 114-byte signature.</param>
    /// <param name="bytesWritten">114 on success, otherwise 0.</param>
    /// <returns>False if <paramref name="signature"/> is shorter than 114 bytes.</returns>
    /// <exception cref="ArgumentException">The seed is not 57 bytes, or the context is longer than 255 bytes.</exception>
    public static bool TrySignPrehashed(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten)
    {
        Span<byte> prehash = stackalloc byte[PrehashSize]; // fixed small buffer
        EdHash.Shake256(prehash, message);
        return TrySignHash(seed, prehash, context, signature, out bytesWritten);
    }

    /// <summary>Signs a SHAKE256 digest (64 bytes of output) computed by the caller with Ed448ph.</summary>
    /// <param name="seed">The 57-byte private seed.</param>
    /// <param name="shake256Digest">The 64-byte SHAKE256 output over the message.</param>
    /// <param name="context">0 to 255 bytes.</param>
    /// <param name="signature">Receives the 114-byte signature.</param>
    /// <param name="bytesWritten">114 on success, otherwise 0.</param>
    /// <returns>False if <paramref name="signature"/> is shorter than 114 bytes.</returns>
    /// <exception cref="ArgumentException">The seed or digest has the wrong length, or the context is longer than 255 bytes.</exception>
    public static bool TrySignHash(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> shake256Digest, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten)
    {
        CheckLength(shake256Digest, PrehashSize, nameof(shake256Digest));
        return TrySignCore(seed, 1, context, shake256Digest, signature, out bytesWritten);
    }

    /// <summary>Verifies an Ed448 signature. Returns false for any malformed input; it never throws on data.</summary>
    /// <param name="publicKey">The 57-byte public key.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="context">The context the signer used, 0 to 255 bytes.</param>
    /// <param name="signature">The 114-byte signature.</param>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
        VerifyCore(publicKey, 0, context, message, signature);

    /// <summary>Verifies an Ed448ph signature over <paramref name="message"/>. Returns false for any malformed input.</summary>
    /// <param name="publicKey">The 57-byte public key.</param>
    /// <param name="message">The signed message; it is hashed with SHAKE256 here.</param>
    /// <param name="context">The context the signer used, 0 to 255 bytes.</param>
    /// <param name="signature">The 114-byte signature.</param>
    public static bool VerifyPrehashed(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature)
    {
        Span<byte> prehash = stackalloc byte[PrehashSize]; // fixed small buffer
        EdHash.Shake256(prehash, message);
        return VerifyHash(publicKey, prehash, context, signature);
    }

    /// <summary>Verifies an Ed448ph signature over a SHAKE256 digest computed by the caller. Returns false for any malformed input.</summary>
    /// <param name="publicKey">The 57-byte public key.</param>
    /// <param name="shake256Digest">The 64-byte SHAKE256 output over the message.</param>
    /// <param name="context">The context the signer used, 0 to 255 bytes.</param>
    /// <param name="signature">The 114-byte signature.</param>
    public static bool VerifyHash(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> shake256Digest, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
        shake256Digest.Length == PrehashSize && VerifyCore(publicKey, 1, context, shake256Digest, signature);

    // --- shared core ---

    internal static void CheckLength(ReadOnlySpan<byte> s, int expected, string name)
    {
        if (s.Length != expected)
        {
            throw new ArgumentException($"Expected {expected} bytes.", name);
        }
    }

    /// <summary>
    /// RFC 8032 section 5.2.5: h = SHAKE256(seed, 114); the low 57 bytes, clamped, are the secret scalar and the high 57 the nonce
    /// prefix. <paramref name="reducedScalar"/> receives that scalar reduced modulo the group order (56 bytes): B has exactly
    /// that order, so [s]B = [s mod L]B, and the reduced form keeps the fixed-base recoding inside its table.
    /// </summary>
    internal static void Expand(ReadOnlySpan<byte> seed, Span<byte> expanded, Span<byte> reducedScalar)
    {
        EdHash.Shake256(expanded, seed);
        expanded[0] &= 252;
        expanded[55] |= 128;
        expanded[56] = 0;
        Span<ulong> r = stackalloc ulong[7]; // fixed small buffer
        Ed448Scalar.Field.ReduceWide(expanded[..56], r);
        ScalarField.Store(r, reducedScalar);
        r.Clear();
    }

    /// <summary>dom4(f, c) of RFC 8032 section 5.2; the prefix is present in every Ed448 signature. Returns the number of bytes written.</summary>
    private static int Dom4(Span<byte> to, int flag, ReadOnlySpan<byte> context)
    {
        DomPrefix.CopyTo(to);
        to[8] = (byte)flag;
        to[9] = (byte)context.Length;
        context.CopyTo(to[10..]);
        return 10 + context.Length;
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
        Span<byte> expanded = stackalloc byte[114]; // fixed small buffer
        Span<byte> scalar = stackalloc byte[56];
        Expand(seed, expanded, scalar);
        Span<byte> publicKey = stackalloc byte[PublicKeySize];
        Ge448Ops.Encode(Ge448Ops.ScalarMultBase(scalar), publicKey);
        SignExpanded(scalar, expanded[57..], publicKey, flag, context, message, signature);
        CryptographicOperations.ZeroMemory(expanded);
        CryptographicOperations.ZeroMemory(scalar);
        bytesWritten = SignatureSize;
        return true;
    }

    /// <summary>RFC 8032 section 5.2.6 from the expanded secret: reduced scalar <paramref name="scalar"/> (56 bytes) and nonce <paramref name="prefix"/>.</summary>
    internal static void SignExpanded(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> publicKey, int flag, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, Span<byte> signature)
    {
        ScalarField sc = Ed448Scalar.Field;
        Span<byte> dom = stackalloc byte[10 + MaxContextSize]; // fixed small buffer
        ReadOnlySpan<byte> domain = dom[..Dom4(dom, flag, context)];
        Span<byte> hash = stackalloc byte[114];
        Span<ulong> r = stackalloc ulong[7];
        Span<ulong> k = stackalloc ulong[7];
        Span<ulong> a = stackalloc ulong[7];
        Span<ulong> s = stackalloc ulong[7];
        Span<byte> rBytes = stackalloc byte[56];

        // r = SHAKE256(dom4 || prefix || M, 114) mod L is the secret nonce; R = [r]B.
        EdHash.Shake256(hash, domain, prefix, message);
        sc.ReduceWide(hash, r);
        ScalarField.Store(r, rBytes);
        Ge448Ops.Encode(Ge448Ops.ScalarMultBase(rBytes), signature[..57]);

        // k = SHAKE256(dom4 || R || A || M, 114) mod L; S = (r + k s) mod L.
        EdHash.Shake256(hash, domain, signature[..57], publicKey, message);
        sc.ReduceWide(hash, k);
        ScalarField.Load(scalar, a);
        sc.MulAdd(a, k, r, s);
        signature[114 - 1] = 0;
        ScalarField.Store(s, signature.Slice(57, 56));

        CryptographicOperations.ZeroMemory(hash);
        CryptographicOperations.ZeroMemory(rBytes);
        r.Clear();
        a.Clear();
        s.Clear();
    }

    private static bool VerifyCore(ReadOnlySpan<byte> publicKey, int flag, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != PublicKeySize || signature.Length != SignatureSize || context.Length > MaxContextSize)
        {
            return false;
        }
        ReadOnlySpan<byte> rBytes = signature[..57];
        ReadOnlySpan<byte> sBytes = signature[57..];
        ScalarField sc = Ed448Scalar.Field;
        // RFC 8032 section 5.2.7: S must be below L; its 57th byte is padding and must be zero (IsBelowModulus checks it).
        if (!sc.IsBelowModulus(sBytes) || !Ge448Ops.TryDecode(publicKey, out Ge448 a))
        {
            return false;
        }
        Span<byte> dom = stackalloc byte[10 + MaxContextSize]; // fixed small buffer
        ReadOnlySpan<byte> domain = dom[..Dom4(dom, flag, context)];
        Span<byte> hash = stackalloc byte[114];
        EdHash.Shake256(hash, domain, rBytes, publicKey, message);
        Span<ulong> kl = stackalloc ulong[7];
        sc.ReduceWide(hash, kl);
        Span<byte> k = stackalloc byte[56];
        ScalarField.Store(kl, k);

        // R' = [S]B - [k]A, compared with R as an encoding.
        Span<byte> check = stackalloc byte[57];
        Ge448Ops.Encode(Ge448Ops.DoubleScalarMulBaseVartime(sBytes[..56], k, Ge448Ops.Negate(a)), check);
        return check.SequenceEqual(rBytes);
    }
}

/// <summary>An Ed448 public key. Immutable; verification with an invalid key returns false.</summary>
public sealed class Ed448PublicKey
{
    private readonly byte[] _bytes;

    private Ed448PublicKey(byte[] bytes) => _bytes = bytes;

    /// <summary>Wraps 57 public-key bytes. The bytes are not checked to be a valid point; verification with an invalid key fails.</summary>
    /// <exception cref="ArgumentException">The input is not 57 bytes.</exception>
    public static Ed448PublicKey FromBytes(ReadOnlySpan<byte> publicKey)
    {
        Ed448.CheckLength(publicKey, Ed448.PublicKeySize, nameof(publicKey));
        return new Ed448PublicKey(publicKey.ToArray());
    }

    /// <summary>Wraps 57 public-key bytes; false if the length is wrong.</summary>
    public static bool TryFromBytes(ReadOnlySpan<byte> publicKey, out Ed448PublicKey? key)
    {
        key = publicKey.Length == Ed448.PublicKeySize ? new Ed448PublicKey(publicKey.ToArray()) : null;
        return key is not null;
    }

    /// <summary>Copies the 57-byte public key into <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException">The destination is shorter than 57 bytes.</exception>
    public void Export(Span<byte> destination)
    {
        if (destination.Length < Ed448.PublicKeySize)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }
        _bytes.CopyTo(destination);
    }

    /// <summary>The 57-byte public key as a new array.</summary>
    public byte[] ToArray() => (byte[])_bytes.Clone();

    /// <inheritdoc cref="Ed448.Verify"/>
    public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
        Ed448.Verify(_bytes, message, context, signature);

    /// <inheritdoc cref="Ed448.VerifyPrehashed"/>
    public bool VerifyPrehashed(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
        Ed448.VerifyPrehashed(_bytes, message, context, signature);

    /// <inheritdoc cref="Ed448.VerifyHash"/>
    public bool VerifyHash(ReadOnlySpan<byte> shake256Digest, ReadOnlySpan<byte> context, ReadOnlySpan<byte> signature) =>
        Ed448.VerifyHash(_bytes, shake256Digest, context, signature);
}

/// <summary>
/// An Ed448 private key. The seed and its expansion live in a pinned buffer that is zeroed on <see cref="Dispose"/>. The
/// runtime cannot promise that no other copy of a secret exists; this narrows the window, it does not close it.
/// </summary>
/// <remarks>
/// <b>Constant time.</b> The secret scalar and the nonce only ever meet fixed-width limb arithmetic with masks. [scalar]B
/// recodes the scalar into signed 4-bit digits and, for each digit, reads every entry of the table row and keeps one with a
/// mask, so neither the memory addresses nor the sequence of group operations depend on the scalar. The group law is complete.
/// </remarks>
public sealed class Ed448PrivateKey : IDisposable
{
    // seed (57) || reduced scalar (56) || nonce prefix (57)
    private readonly PinnedSecret _secret;
    private readonly Ed448PublicKey _publicKey;

    private Ed448PrivateKey(PinnedSecret secret, Ed448PublicKey publicKey)
    {
        _secret = secret;
        _publicKey = publicKey;
    }

    /// <summary>Generates a key from the platform's random number generator.</summary>
    public static Ed448PrivateKey Generate()
    {
        Span<byte> seed = stackalloc byte[Ed448.SeedSize]; // fixed small buffer
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

    /// <summary>Creates a key from its 57-byte seed (the RFC 8032 "private key").</summary>
    /// <exception cref="ArgumentException">The seed is not 57 bytes.</exception>
    public static Ed448PrivateKey FromSeed(ReadOnlySpan<byte> seed)
    {
        Ed448.CheckLength(seed, Ed448.SeedSize, nameof(seed));
        var secret = new PinnedSecret(57 + 56 + 57);
        Span<byte> expanded = stackalloc byte[114]; // fixed small buffer
        Span<byte> scalar = stackalloc byte[56];
        try
        {
            Ed448.Expand(seed, expanded, scalar);
            seed.CopyTo(secret.Span);
            scalar.CopyTo(secret.Span[57..]);
            expanded[57..].CopyTo(secret.Span[(57 + 56)..]);
            Span<byte> pub = stackalloc byte[Ed448.PublicKeySize];
            Ge448Ops.Encode(Ge448Ops.ScalarMultBase(scalar), pub);
            return new Ed448PrivateKey(secret, Ed448PublicKey.FromBytes(pub));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expanded);
            CryptographicOperations.ZeroMemory(scalar);
        }
    }

    /// <summary>The matching public key.</summary>
    public Ed448PublicKey PublicKey => _publicKey;

    /// <summary>Copies the 57-byte seed into <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException">The destination is shorter than 57 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public void ExportSeed(Span<byte> destination)
    {
        if (destination.Length < Ed448.SeedSize)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }
        _secret.ReadOnlySpan[..Ed448.SeedSize].CopyTo(destination);
    }

    /// <summary>Signs with Ed448; see <see cref="Ed448.TrySign"/>.</summary>
    /// <exception cref="ArgumentException">The context is longer than 255 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public bool TrySign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten) =>
        TrySignCore(0, context, message, signature, out bytesWritten);

    /// <summary>Signs with Ed448ph, hashing the message with SHAKE256; see <see cref="Ed448.TrySignPrehashed"/>.</summary>
    /// <exception cref="ArgumentException">The context is longer than 255 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public bool TrySignPrehashed(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten)
    {
        Span<byte> prehash = stackalloc byte[Ed448.PrehashSize]; // fixed small buffer
        EdHash.Shake256(prehash, message);
        return TrySignHash(prehash, context, signature, out bytesWritten);
    }

    /// <summary>Signs a caller-computed SHAKE256 digest with Ed448ph; see <see cref="Ed448.TrySignHash"/>.</summary>
    /// <exception cref="ArgumentException">The digest is not 64 bytes, or the context is longer than 255 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public bool TrySignHash(ReadOnlySpan<byte> shake256Digest, ReadOnlySpan<byte> context, Span<byte> signature, out int bytesWritten)
    {
        Ed448.CheckLength(shake256Digest, Ed448.PrehashSize, nameof(shake256Digest));
        return TrySignCore(1, context, shake256Digest, signature, out bytesWritten);
    }

    private bool TrySignCore(int flag, ReadOnlySpan<byte> context, ReadOnlySpan<byte> message, Span<byte> signature, out int bytesWritten)
    {
        ReadOnlySpan<byte> secret = _secret.ReadOnlySpan;
        if (context.Length > Ed448.MaxContextSize)
        {
            throw new ArgumentException("A context is at most 255 bytes.", nameof(context));
        }
        bytesWritten = 0;
        if (signature.Length < Ed448.SignatureSize)
        {
            return false;
        }
        Span<byte> pub = stackalloc byte[Ed448.PublicKeySize]; // fixed small buffer
        _publicKey.Export(pub);
        Ed448.SignExpanded(secret.Slice(57, 56), secret.Slice(57 + 56, 57), pub, flag, context, message, signature);
        bytesWritten = Ed448.SignatureSize;
        return true;
    }

    /// <summary>Zeroes the key material.</summary>
    public void Dispose() => _secret.Dispose();
}
