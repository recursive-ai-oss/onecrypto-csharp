using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// X448 Diffie-Hellman on Curve448 (RFC 7748 sections 5 and 6.2). The scalar is clamped as the RFC says.
/// </summary>
/// <remarks>
/// <b>Constant time.</b> The Montgomery ladder performs the same 448 steps for every scalar and swaps its two working points
/// with a mask taken from the scalar bit, never a branch or an index. The field arithmetic is straight-line code on fixed-width
/// limbs, and the final inversion is a fixed exponentiation chain.
/// </remarks>
public static class X448
{
    /// <summary>The size of a private key, a public key and a shared secret in bytes.</summary>
    public const int KeySize = 56;

    private static ReadOnlySpan<byte> BasePoint => [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // (A - 2) / 4 = 39081 for the curve y^2 = x^3 + 156326 x^2 + x (RFC 7748 section 5).
    private static readonly Fe448 A24 = new() { V0 = 39081 };

    /// <summary>
    /// The X448 function of RFC 7748 section 5: multiplies the point with u-coordinate <paramref name="u"/> by the clamped
    /// <paramref name="scalar"/>. The result is not checked for the all-zero value; <see cref="TryDeriveSharedSecret"/> does that.
    /// </summary>
    /// <param name="scalar">56 bytes; clamping is applied here.</param>
    /// <param name="u">56 bytes; all 448 bits are used and values of p or more are read modulo p.</param>
    /// <param name="result">Receives 56 bytes.</param>
    /// <exception cref="ArgumentException">A span has the wrong length.</exception>
    public static void ScalarMult(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> u, Span<byte> result)
    {
        Ed448.CheckLength(scalar, KeySize, nameof(scalar));
        Ed448.CheckLength(u, KeySize, nameof(u));
        Ed448.CheckLength(result, KeySize, nameof(result));
        Span<byte> k = stackalloc byte[56]; // fixed small buffer
        scalar.CopyTo(k);
        k[0] &= 252;
        k[55] |= 128;

        Fe448 x1 = Fe448.FromBytes(u);
        Fe448 x2 = Fe448.One, z2 = Fe448.Zero, x3 = x1, z3 = Fe448.One;
        ulong swap = 0;
        for (int t = 447; t >= 0; t--)
        {
            ulong bit = (ulong)((k[t >> 3] >> (t & 7)) & 1);
            swap ^= bit;
            ulong mask = 0 - swap;
            Fe448.CSwap(ref x2, ref x3, mask);
            Fe448.CSwap(ref z2, ref z3, mask);
            swap = bit;

            Fe448 a = Fe448.Add(x2, z2);
            Fe448 aa = Fe448.Square(a);
            Fe448 b = Fe448.Sub(x2, z2);
            Fe448 bb = Fe448.Square(b);
            Fe448 e = Fe448.Sub(aa, bb);
            Fe448 c = Fe448.Add(x3, z3);
            Fe448 d = Fe448.Sub(x3, z3);
            Fe448 da = Fe448.Mul(d, a);
            Fe448 cb = Fe448.Mul(c, b);
            x3 = Fe448.Square(Fe448.Add(da, cb));
            z3 = Fe448.Mul(x1, Fe448.Square(Fe448.Sub(da, cb)));
            x2 = Fe448.Mul(aa, bb);
            z2 = Fe448.Mul(e, Fe448.Add(aa, Fe448.Mul(A24, e)));
        }
        ulong last = 0 - swap;
        Fe448.CSwap(ref x2, ref x3, last);
        Fe448.CSwap(ref z2, ref z3, last);
        Fe448.Mul(x2, Fe448.Invert(z2)).ToBytes(result);
        CryptographicOperations.ZeroMemory(k);
    }

    /// <summary>Computes the public key for a private key: <see cref="ScalarMult"/> with the base point u = 5.</summary>
    /// <param name="privateKey">56 bytes.</param>
    /// <param name="publicKey">Receives 56 bytes.</param>
    /// <exception cref="ArgumentException">A span has the wrong length.</exception>
    public static void DerivePublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey)
    {
        Ed448.CheckLength(privateKey, KeySize, nameof(privateKey));
        Ed448.CheckLength(publicKey, KeySize, nameof(publicKey));
        // Same result as ScalarMult with u = 5, but through the constant-time fixed-base table of Ed448. RFC 7748 section 4.2
        // gives the 4-isogeny from edwards448 to Curve448, (x, y) to u = y^2 / x^2; it maps the Ed448 base point to the Curve448
        // base point (up to sign, which u ignores), and being a group homomorphism it maps [k]B to [k]P. B has order L, so the
        // scalar can be reduced modulo L first, which also keeps it inside the table's recoding range.
        Span<byte> k = stackalloc byte[56]; // fixed small buffers
        privateKey.CopyTo(k);
        k[0] &= 252;
        k[55] |= 128;
        Span<ulong> r = stackalloc ulong[7];
        Ed448Scalar.Field.ReduceWide(k, r);
        ScalarField.Store(r, k);
        Ge448 p = Ge448Ops.ScalarMultBase(k);
        // X is zero only if k is a multiple of L (the single clamped value 4L); inversion of zero gives zero, as the ladder does.
        Fe448.Mul(Fe448.Square(p.Y), Fe448.Invert(Fe448.Square(p.X))).ToBytes(publicKey);
        CryptographicOperations.ZeroMemory(k);
        r.Clear();
    }

    /// <summary>The same computation by the ladder with u = 5; used to cross-check <see cref="DerivePublicKey"/>.</summary>
    internal static void DerivePublicKeyByLadder(ReadOnlySpan<byte> privateKey, Span<byte> publicKey) =>
        ScalarMult(privateKey, BasePoint, publicKey);

    /// <summary>
    /// Computes the shared secret and applies the check of RFC 7748 section 6.1: if the peer's key is a low-order point the
    /// result is all zeros, and the exchange must be abandoned.
    /// </summary>
    /// <param name="privateKey">Our 56-byte private key.</param>
    /// <param name="peerPublicKey">The peer's 56-byte public key.</param>
    /// <param name="sharedSecret">Receives 56 bytes (all zeros when the method returns false).</param>
    /// <returns>False if the shared secret is all zeros. The check itself does not depend on any secret except that outcome.</returns>
    /// <exception cref="ArgumentException">A span has the wrong length.</exception>
    public static bool TryDeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
    {
        ScalarMult(privateKey, peerPublicKey, sharedSecret);
        Span<byte> zero = stackalloc byte[KeySize]; // fixed small buffer
        return !CryptographicOperations.FixedTimeEquals(sharedSecret, zero);
    }
}

/// <summary>An X448 public key (the u-coordinate, 56 bytes).</summary>
public sealed class X448PublicKey
{
    private readonly byte[] _bytes;

    private X448PublicKey(byte[] bytes) => _bytes = bytes;

    /// <summary>Wraps 56 public-key bytes. Any 56 bytes are a valid u-coordinate; low-order keys are caught when deriving the secret.</summary>
    /// <exception cref="ArgumentException">The input is not 56 bytes.</exception>
    public static X448PublicKey FromBytes(ReadOnlySpan<byte> publicKey)
    {
        Ed448.CheckLength(publicKey, X448.KeySize, nameof(publicKey));
        return new X448PublicKey(publicKey.ToArray());
    }

    /// <summary>Copies the 56-byte public key into <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException">The destination is shorter than 56 bytes.</exception>
    public void Export(Span<byte> destination)
    {
        if (destination.Length < X448.KeySize)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }
        _bytes.CopyTo(destination);
    }

    /// <summary>The 56-byte public key as a new array.</summary>
    public byte[] ToArray() => (byte[])_bytes.Clone();
}

/// <summary>An X448 private key held in a pinned buffer that is zeroed on <see cref="Dispose"/>.</summary>
public sealed class X448PrivateKey : IDisposable
{
    private readonly PinnedSecret _secret;
    private readonly X448PublicKey _publicKey;

    private X448PrivateKey(PinnedSecret secret, X448PublicKey publicKey)
    {
        _secret = secret;
        _publicKey = publicKey;
    }

    /// <summary>Generates a key from the platform's random number generator.</summary>
    public static X448PrivateKey Generate()
    {
        Span<byte> k = stackalloc byte[X448.KeySize]; // fixed small buffer
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

    /// <summary>Creates a key from its 56 private bytes (clamping happens when the key is used).</summary>
    /// <exception cref="ArgumentException">The input is not 56 bytes.</exception>
    public static X448PrivateKey FromBytes(ReadOnlySpan<byte> privateKey)
    {
        Ed448.CheckLength(privateKey, X448.KeySize, nameof(privateKey));
        var secret = new PinnedSecret(privateKey);
        Span<byte> pub = stackalloc byte[X448.KeySize]; // fixed small buffer
        X448.DerivePublicKey(privateKey, pub);
        return new X448PrivateKey(secret, X448PublicKey.FromBytes(pub));
    }

    /// <summary>The matching public key.</summary>
    public X448PublicKey PublicKey => _publicKey;

    /// <summary>Copies the 56 private bytes into <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException">The destination is shorter than 56 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public void Export(Span<byte> destination)
    {
        if (destination.Length < X448.KeySize)
        {
            throw new ArgumentException("The destination is too short.", nameof(destination));
        }
        _secret.ReadOnlySpan.CopyTo(destination);
    }

    /// <summary>Computes the shared secret with a peer; see <see cref="X448.TryDeriveSharedSecret"/>.</summary>
    /// <param name="peer">The peer's public key.</param>
    /// <param name="sharedSecret">Receives 56 bytes.</param>
    /// <returns>False if the shared secret is all zeros (a low-order peer key); the exchange must then be abandoned.</returns>
    /// <exception cref="ArgumentException">The destination is shorter than 56 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key has been disposed.</exception>
    public bool TryDeriveSharedSecret(X448PublicKey peer, Span<byte> sharedSecret)
    {
        ArgumentNullException.ThrowIfNull(peer);
        Span<byte> pub = stackalloc byte[X448.KeySize]; // fixed small buffer
        peer.Export(pub);
        return X448.TryDeriveSharedSecret(_secret.ReadOnlySpan, pub, sharedSecret);
    }

    /// <summary>Zeroes the key material.</summary>
    public void Dispose() => _secret.Dispose();
}
