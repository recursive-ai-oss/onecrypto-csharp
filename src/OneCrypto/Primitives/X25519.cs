using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// X25519 Diffie-Hellman on Curve25519 (RFC 7748 sections 5 and 6.1). The scalar is clamped as the RFC says and the
/// u-coordinate of the peer's key has its top bit ignored.
/// </summary>
/// <remarks>
/// <b>Constant time.</b> The Montgomery ladder performs the same 255 steps for every scalar and swaps its two working points
/// with a mask taken from the scalar bit, never a branch or an index. The field arithmetic is straight-line code on fixed-width
/// limbs, and the final inversion is a fixed exponentiation chain.
/// </remarks>
public static class X25519
{
    /// <summary>The size of a private key, a public key and a shared secret in bytes.</summary>
    public const int KeySize = 32;

    private static ReadOnlySpan<byte> BasePoint => [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // (A - 2) / 4 = 121665 for the curve y^2 = x^3 + 486662 x^2 + x (RFC 7748 section 5).
    private static readonly Fe25519 A24 = new() { V0 = 121665 };

    /// <summary>
    /// The X25519 function of RFC 7748 section 5: multiplies the point with u-coordinate <paramref name="u"/> by the clamped
    /// <paramref name="scalar"/>. The result is not checked for the all-zero value; <see cref="TryDeriveSharedSecret"/> does that.
    /// </summary>
    /// <param name="scalar">32 bytes; clamping is applied here.</param>
    /// <param name="u">32 bytes; bit 255 is ignored and values of p or more are read modulo p.</param>
    /// <param name="result">Receives 32 bytes.</param>
    /// <exception cref="ArgumentException">A span has the wrong length.</exception>
    public static void ScalarMult(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> u, Span<byte> result)
    {
        Ed25519.CheckLength(scalar, KeySize, nameof(scalar));
        Ed25519.CheckLength(u, KeySize, nameof(u));
        Ed25519.CheckLength(result, KeySize, nameof(result));
        Span<byte> k = stackalloc byte[32]; // fixed small buffer
        scalar.CopyTo(k);
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;

        Fe25519 x1 = Fe25519.FromBytes(u);
        Fe25519 x2 = Fe25519.One, z2 = Fe25519.Zero, x3 = x1, z3 = Fe25519.One;
        ulong swap = 0;
        for (int t = 254; t >= 0; t--)
        {
            ulong bit = (ulong)((k[t >> 3] >> (t & 7)) & 1);
            swap ^= bit;
            ulong mask = 0 - swap;
            Fe25519.CSwap(ref x2, ref x3, mask);
            Fe25519.CSwap(ref z2, ref z3, mask);
            swap = bit;

            Fe25519 a = Fe25519.Add(x2, z2);
            Fe25519 aa = Fe25519.Square(a);
            Fe25519 b = Fe25519.Sub(x2, z2);
            Fe25519 bb = Fe25519.Square(b);
            Fe25519 e = Fe25519.Sub(aa, bb);
            Fe25519 c = Fe25519.Add(x3, z3);
            Fe25519 d = Fe25519.Sub(x3, z3);
            Fe25519 da = Fe25519.Mul(d, a);
            Fe25519 cb = Fe25519.Mul(c, b);
            x3 = Fe25519.Square(Fe25519.Add(da, cb));
            z3 = Fe25519.Mul(x1, Fe25519.Square(Fe25519.Sub(da, cb)));
            x2 = Fe25519.Mul(aa, bb);
            z2 = Fe25519.Mul(e, Fe25519.Add(aa, Fe25519.Mul(A24, e)));
        }
        ulong last = 0 - swap;
        Fe25519.CSwap(ref x2, ref x3, last);
        Fe25519.CSwap(ref z2, ref z3, last);
        Fe25519.Mul(x2, Fe25519.Invert(z2)).ToBytes(result);
        CryptographicOperations.ZeroMemory(k);
    }

    /// <summary>Computes the public key for a private key: <see cref="ScalarMult"/> with the base point u = 9.</summary>
    /// <param name="privateKey">32 bytes.</param>
    /// <param name="publicKey">Receives 32 bytes.</param>
    /// <exception cref="ArgumentException">A span has the wrong length.</exception>
    public static void DerivePublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey)
    {
        Ed25519.CheckLength(privateKey, KeySize, nameof(privateKey));
        Ed25519.CheckLength(publicKey, KeySize, nameof(publicKey));
        // Same result as ScalarMult with u = 9, but through the constant-time fixed-base table: Curve25519's base point is the
        // image of the Ed25519 base point under u = (1 + y) / (1 - y) (RFC 7748 section 4.1), so [k]B on the Edwards curve
        // maps to the u-coordinate of the public key. A clamped scalar is never a multiple of the group order (it has bit 254
        // set, is divisible by 8 and is below 8 times the order), so the result is never the identity and 1 - y is invertible.
        Span<byte> k = stackalloc byte[32]; // fixed small buffer
        privateKey.CopyTo(k);
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        Ge25519 p = Ge25519Ops.ScalarMultBase(k);
        Fe25519.Mul(Fe25519.Add(p.Z, p.Y), Fe25519.Invert(Fe25519.Sub(p.Z, p.Y))).ToBytes(publicKey);
        CryptographicOperations.ZeroMemory(k);
    }

    /// <summary>The same computation by the ladder with u = 9; used to cross-check <see cref="DerivePublicKey"/>.</summary>
    internal static void DerivePublicKeyByLadder(ReadOnlySpan<byte> privateKey, Span<byte> publicKey) =>
        ScalarMult(privateKey, BasePoint, publicKey);

    /// <summary>
    /// Computes the shared secret and applies the check of RFC 7748 section 6.1: if the peer's key is a low-order point the
    /// result is all zeros, and the exchange must be abandoned.
    /// </summary>
    /// <param name="privateKey">Our 32-byte private key.</param>
    /// <param name="peerPublicKey">The peer's 32-byte public key.</param>
    /// <param name="sharedSecret">Receives 32 bytes (all zeros when the method returns false).</param>
    /// <returns>False if the shared secret is all zeros. The check itself does not depend on any secret except that outcome.</returns>
    /// <exception cref="ArgumentException">A span has the wrong length.</exception>
    public static bool TryDeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
    {
        ScalarMult(privateKey, peerPublicKey, sharedSecret);
        Span<byte> zero = stackalloc byte[KeySize]; // fixed small buffer
        return !CryptographicOperations.FixedTimeEquals(sharedSecret, zero);
    }
}

/// <summary>An X25519 public key (the u-coordinate, 32 bytes).</summary>
public sealed class X25519PublicKey
{
    private readonly byte[] _bytes;

    private X25519PublicKey(byte[] bytes) => _bytes = bytes;

    /// <summary>Wraps 32 public-key bytes. Any 32 bytes are a valid u-coordinate; low-order keys are caught when deriving the secret.</summary>
    /// <exception cref="ArgumentException">The input is not 32 bytes.</exception>
    public static X25519PublicKey FromBytes(ReadOnlySpan<byte> publicKey)
    {
        Ed25519.CheckLength(publicKey, X25519.KeySize, nameof(publicKey));
        return new X25519PublicKey(publicKey.ToArray());
    }

    /// <summary>Copies the 32-byte public key into <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException">The destination is shorter than 32 bytes.</exception>
    public void Export(Span<byte> destination)
    {
        if (destination.Length < X25519.KeySize)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }
        _bytes.CopyTo(destination);
    }

    /// <summary>The 32-byte public key as a new array.</summary>
    public byte[] ToArray() => (byte[])_bytes.Clone();
}

/// <summary>An X25519 private key held in a pinned buffer that is zeroed on <see cref="Dispose"/>.</summary>
public sealed class X25519PrivateKey : IDisposable
{
    private readonly PinnedSecret _secret;
    private readonly X25519PublicKey _publicKey;

    private X25519PrivateKey(PinnedSecret secret, X25519PublicKey publicKey)
    {
        _secret = secret;
        _publicKey = publicKey;
    }

    /// <summary>Generates a key from the platform's random number generator.</summary>
    public static X25519PrivateKey Generate()
    {
        Span<byte> k = stackalloc byte[X25519.KeySize]; // fixed small buffer
        RandomNumberGenerator.Fill(k);
        try
        {
            return FromBytes(k);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(k);
        }
    }

    /// <summary>Creates a key from its 32 private bytes (clamping happens when the key is used).</summary>
    /// <exception cref="ArgumentException">The input is not 32 bytes.</exception>
    public static X25519PrivateKey FromBytes(ReadOnlySpan<byte> privateKey)
    {
        Ed25519.CheckLength(privateKey, X25519.KeySize, nameof(privateKey));
        var secret = new PinnedSecret(privateKey);
        Span<byte> pub = stackalloc byte[X25519.KeySize]; // fixed small buffer
        X25519.DerivePublicKey(privateKey, pub);
        return new X25519PrivateKey(secret, X25519PublicKey.FromBytes(pub));
    }

    /// <summary>The matching public key.</summary>
    public X25519PublicKey PublicKey => _publicKey;

    /// <summary>Copies the 32 private bytes into <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException">The destination is shorter than 32 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public void Export(Span<byte> destination)
    {
        if (destination.Length < X25519.KeySize)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }
        _secret.ReadOnlySpan.CopyTo(destination);
    }

    /// <summary>Computes the shared secret with a peer; see <see cref="X25519.TryDeriveSharedSecret"/>.</summary>
    /// <param name="peer">The peer's public key.</param>
    /// <param name="sharedSecret">Receives 32 bytes.</param>
    /// <returns>False if the shared secret is all zeros (a low-order peer key); the exchange must then be abandoned.</returns>
    /// <exception cref="ArgumentException">The destination is shorter than 32 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public bool TryDeriveSharedSecret(X25519PublicKey peer, Span<byte> sharedSecret)
    {
        ArgumentNullException.ThrowIfNull(peer);
        Span<byte> pub = stackalloc byte[X25519.KeySize]; // fixed small buffer
        peer.Export(pub);
        return X25519.TryDeriveSharedSecret(_secret.ReadOnlySpan, pub, sharedSecret);
    }

    /// <summary>Zeroes the key material.</summary>
    public void Dispose() => _secret.Dispose();
}
