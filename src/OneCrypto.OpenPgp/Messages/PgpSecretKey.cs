using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// Unlocked secret key material for one key packet. It lives in a pinned buffer that is zeroed on <see cref="Dispose"/>; signing goes
/// through <see cref="ISigningKey"/> (so the RSA and ECDSA private operations stay inside the platform) and decryption stays in this class.
/// </summary>
public sealed class PgpSecretKey : IDisposable
{
    private readonly byte[] _plain;
    private readonly int _length;
    private ISigningKey? _signer;

    private PgpSecretKey(PgpKey key, byte[] plain, int length)
    {
        Key = key;
        _plain = plain;
        _length = length;
    }

    /// <summary>The public side: the key packet and its certificate.</summary>
    public PgpKey Key { get; }

    /// <summary>
    /// Unlocks a secret key packet. Tries each password in turn when the packet is protected (RFC 9580 §5.5.3); an unprotected packet needs none.
    /// </summary>
    /// <param name="key">A key of a certificate that carries secret material.</param>
    /// <param name="passwords">Candidate passwords (UTF-8 octets); may be empty for unprotected keys.</param>
    /// <param name="limits">Cost limits for Argon2 parameters read from the key; <see cref="KdfLimits.Default"/> when null.</param>
    /// <exception cref="PgpException">The key has no secret part, is protected and no password fits (<see cref="PgpFailure.KeyIsProtected"/>), or uses an unsupported algorithm.</exception>
    public static PgpSecretKey Unlock(PgpKey key, IReadOnlyList<byte[]>? passwords = null, KdfLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Packet is not SecretKeyPacket sp)
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "The key has no secret part.");
        }

        limits ??= KdfLimits.Default;
        SecretKeyProtection prot = sp.Protection;
        if (!prot.IsProtected)
        {
            return Finish(key, sp, sp.SecretData.Span, true);
        }

        foreach (byte[] pw in passwords ?? [])
        {
            byte[]? plain = TryDecrypt(sp, pw, limits);
            if (plain is not null)
            {
                try
                {
                    return Finish(key, sp, plain, false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                }
            }
        }

        throw new PgpException(PgpFailure.KeyIsProtected, "The secret key is protected and none of the passwords unlocks it.");
    }

    /// <summary>Tries to unlock; returns false (and does not throw) when the key is protected and no password fits.</summary>
    public static bool TryUnlock(PgpKey key, IReadOnlyList<byte[]>? passwords, out PgpSecretKey? unlocked, KdfLimits? limits = null)
    {
        try
        {
            unlocked = Unlock(key, passwords, limits);
            return true;
        }
        catch (PgpException e) when (e.Failure is PgpFailure.KeyIsProtected or PgpFailure.KeyCannotPerform)
        {
            unlocked = null;
            return false;
        }
    }

    private static byte[]? TryDecrypt(SecretKeyPacket sp, byte[] password, KdfLimits limits)
    {
        SecretKeyProtection p = sp.Protection;
        if (p.S2k is null)
        {
            throw new PgpException(PgpFailure.Unsupported, "Secret key protection without a string-to-key specifier is not supported.");
        }

        int keySize = PgpAlgorithms.KeySize(p.Cipher);
        byte[] kdf = PgpAlgorithms.S2k(p.S2k, password, keySize, limits);
        try
        {
            ReadOnlySpan<byte> data = sp.SecretData.Span;
            if (p.Usage == 253)
            {
                // RFC 9580 §5.5.3: the KEK is HKDF-SHA256 of the S2K output with the packet tag, version, cipher and AEAD as info; the public part is the AD.
                AeadAlgorithm aead = p.Aead ?? throw new PgpException(PgpFailure.MalformedMessage, "AEAD-protected key without an AEAD algorithm.");
                byte tag = (byte)(0xC0 | sp.TagId);
                byte[] info = [tag, sp.Version, (byte)p.Cipher, (byte)aead];
                byte[] kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, kdf, keySize, [], info);
                byte[] ad = new byte[1 + sp.PublicBody.Length];
                ad[0] = tag;
                sp.PublicBody.Span.CopyTo(ad.AsSpan(1));
                if (data.Length < 16)
                {
                    return null;
                }

                byte[] plain = new byte[data.Length - 16];
                using var a = new PgpAlgorithms.Aead(aead, kek);
                bool ok = a.TryDecrypt(p.Iv.Span, data[..^16], data[^16..], plain, ad);
                CryptographicOperations.ZeroMemory(kek);
                if (!ok)
                {
                    CryptographicOperations.ZeroMemory(plain);
                    return null;
                }

                return plain;
            }

            if (p.Usage is 254 or 255)
            {
                byte[] buf = data.ToArray();
                byte[] iv = p.Iv.ToArray();
                PgpAlgorithms.CfbDecrypt(kdf, iv, buf);
                if (p.Usage == 254)
                {
                    if (buf.Length < 20)
                    {
                        return null;
                    }

                    byte[] expect = PgpAlgorithms.Sha1(buf.AsSpan(0, buf.Length - 20));
                    if (!CryptographicOperations.FixedTimeEquals(expect, buf.AsSpan(buf.Length - 20)))
                    {
                        CryptographicOperations.ZeroMemory(buf);
                        return null;
                    }

                    return buf.AsSpan(0, buf.Length - 20).ToArray();
                }

                if (buf.Length < 2 || BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(buf.Length - 2)) != PgpAlgorithms.Checksum(buf.AsSpan(0, buf.Length - 2)))
                {
                    CryptographicOperations.ZeroMemory(buf);
                    return null;
                }

                return buf.AsSpan(0, buf.Length - 2).ToArray();
            }

            throw new PgpException(PgpFailure.Unsupported, "This secret key protection method is not supported.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kdf);
        }
    }

    private static PgpSecretKey Finish(PgpKey key, SecretKeyPacket sp, ReadOnlySpan<byte> plain, bool unprotected)
    {
        if (unprotected && sp.Version <= 4)
        {
            // RFC 9580 §5.5.3: an unprotected v3/v4 packet ends with the two-octet sum of the material.
            if (plain.Length < 2 || BinaryPrimitives.ReadUInt16BigEndian(plain[^2..]) != PgpAlgorithms.Checksum(plain[..^2]))
            {
                throw new PgpException(PgpFailure.MalformedMessage, "The secret key checksum is wrong.");
            }

            plain = plain[..^2];
        }

        byte[] pinned = GC.AllocateUninitializedArray<byte>(plain.Length, pinned: true);
        plain.CopyTo(pinned);
        return new PgpSecretKey(key, pinned, plain.Length);
    }

    // Splits the algorithm-specific secret octets into their values (RFC 9580 §5.5.5): MPIs for the classic algorithms, fixed-size octet strings for the native ones.
    private List<byte[]> Parts()
    {
        var parts = new List<byte[]>();
        ReadOnlySpan<byte> m = _plain.AsSpan(0, _length);
        PublicKeyAlgorithm alg = Key.Algorithm;
        switch (alg)
        {
            case PublicKeyAlgorithm.Ed25519:
            case PublicKeyAlgorithm.X25519:
                parts.Add(Take(ref m, 32));
                break;
            case PublicKeyAlgorithm.X448:
                parts.Add(Take(ref m, 56));
                break;
            case PublicKeyAlgorithm.Ed448:
                parts.Add(Take(ref m, 57));
                break;
            case PublicKeyAlgorithm.Rsa:
            case PublicKeyAlgorithm.RsaEncryptOnly:
            case PublicKeyAlgorithm.RsaSignOnly:
                for (int i = 0; i < 4; i++)
                {
                    parts.Add(ReadMpi(ref m));
                }

                break;
            case PublicKeyAlgorithm.Ecdsa:
            case PublicKeyAlgorithm.EdDsaLegacy:
            case PublicKeyAlgorithm.Ecdh:
                parts.Add(ReadMpi(ref m));
                break;
            default:
                throw new PgpException(PgpFailure.Unsupported, $"The key algorithm {(byte)alg} ({alg}) is not supported for private operations.");
        }

        if (!m.IsEmpty)
        {
            // RFC 9580 §5.5.3: octets beyond the algorithm's values make the key unusable.
            throw new PgpException(PgpFailure.MalformedMessage, "The secret key material has trailing data.");
        }

        return parts;
    }

    private static byte[] Take(ref ReadOnlySpan<byte> m, int n)
    {
        if (m.Length < n)
        {
            throw new PgpException(PgpFailure.MalformedMessage, "The secret key material is truncated.");
        }

        byte[] r = m[..n].ToArray();
        m = m[n..];
        return r;
    }

    private static byte[] ReadMpi(ref ReadOnlySpan<byte> m)
    {
        if (m.Length < 2)
        {
            throw new PgpException(PgpFailure.MalformedMessage, "The secret key material is truncated.");
        }

        int bits = BinaryPrimitives.ReadUInt16BigEndian(m);
        int n = (bits + 7) / 8;
        m = m[2..];
        return Take(ref m, n);
    }

    /// <summary>
    /// Creates a signing key over the platform's (or the library's) primitives. The result is owned by this object and disposed with it.
    /// </summary>
    /// <exception cref="PgpException">The algorithm cannot sign here.</exception>
    public ISigningKey SigningKey => _signer ??= CreateSigner();

    private ISigningKey CreateSigner()
    {
        List<byte[]> p = Parts();
        PublicKeyMaterial pub = Key.Packet.Material;
        try
        {
            switch (Key.Algorithm)
            {
                case PublicKeyAlgorithm.Ed25519:
                    return PrivateKey.FromEd25519(Ed25519PrivateKey.FromSeed(p[0]), true);
                case PublicKeyAlgorithm.EdDsaLegacy:
                    return PrivateKey.FromEd25519(Ed25519PrivateKey.FromSeed(SignatureEngine.LeftPad(p[0], 32)), true);
                case PublicKeyAlgorithm.Ed448:
                    return PrivateKey.FromEd448(Ed448PrivateKey.FromSeed(p[0]), true);
                case PublicKeyAlgorithm.Rsa:
                case PublicKeyAlgorithm.RsaSignOnly:
                    return PrivateKey.FromRsa(ImportRsa(pub, p), true);
                case PublicKeyAlgorithm.Ecdsa:
                    {
                        ECCurve curve = SignatureEngine.Curves.Find(pub.CurveOid.Span, out int size);
                        ReadOnlySpan<byte> q = pub.Values[0].Span;
                        var ec = ECDsa.Create(new ECParameters
                        {
                            Curve = curve,
                            D = SignatureEngine.LeftPad(p[0], size),
                            Q = new ECPoint { X = q.Slice(1, size).ToArray(), Y = q.Slice(1 + size, size).ToArray() },
                        });
                        return PrivateKey.FromECDsa(ec, true);
                    }

                default:
                    throw new PgpException(PgpFailure.KeyCannotPerform, $"The key algorithm {(byte)Key.Algorithm} cannot sign.");
            }
        }
        finally
        {
            foreach (byte[] b in p)
            {
                CryptographicOperations.ZeroMemory(b);
            }
        }
    }

    private static RSA ImportRsa(PublicKeyMaterial pub, List<byte[]> p)
    {
        // RFC 9580 §5.5.5.1 stores d, p, q and u = p^-1 mod q with p < q. The platform wants InverseQ = q^-1 mod p, so the roles of p and q
        // are swapped: the stored q plays "P", the stored p plays "Q", and u is the inverse of the new "Q" modulo the new "P".
        byte[] n = pub.Values[0].ToArray();
        byte[] d = p[0];
        byte[] pp = p[2];
        byte[] qq = p[1];
        int half = (n.Length + 1) / 2;
        byte[] pm1 = Decrement(pp);
        byte[] qm1 = Decrement(qq);
        byte[] dp = new byte[pp.Length];
        byte[] dq = new byte[qq.Length];
        RecursiveAI.OneCrypto.Internal.SecretMod.Reduce(d, pm1, dp);
        RecursiveAI.OneCrypto.Internal.SecretMod.Reduce(d, qm1, dq);
        var prm = new RSAParameters
        {
            Modulus = n,
            Exponent = pub.Values[1].ToArray(),
            D = RecursiveAI.OneCrypto.Internal.SecretMod.Fixed(d, n.Length),
            P = RecursiveAI.OneCrypto.Internal.SecretMod.Fixed(pp, half),
            Q = RecursiveAI.OneCrypto.Internal.SecretMod.Fixed(qq, half),
            DP = RecursiveAI.OneCrypto.Internal.SecretMod.Fixed(dp, half),
            DQ = RecursiveAI.OneCrypto.Internal.SecretMod.Fixed(dq, half),
            InverseQ = RecursiveAI.OneCrypto.Internal.SecretMod.Fixed(p[3], half),
        };
        var rsa = RSA.Create();
        rsa.ImportParameters(prm);
        return rsa;
    }

    private static byte[] Decrement(byte[] bigEndian)
    {
        // p and q are odd primes, so the low octet is never zero and the borrow stops at the first octet whatever the key.
        byte[] r = (byte[])bigEndian.Clone();
        for (int i = r.Length - 1; i >= 0; i--)
        {
            if (r[i]-- != 0)
            {
                break;
            }
        }

        return r;
    }

    /// <summary>Releases the key and zeroes the secret material.</summary>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_plain);
        _signer?.Dispose();
        _signer = null;
    }

    // Decryption of the session key lives in SessionKeys.cs and reads the parts through this method.
    internal List<byte[]> SecretParts() => Parts();
}
