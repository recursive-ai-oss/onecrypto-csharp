using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Primitives.Fallback;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// LibrePGP's ML-KEM (Kyber) composite session-key encryption (draft-koch-librepgp §5.1, §5.6.7, §14.1): an elliptic-curve key encapsulation and an
/// ML-KEM encapsulation whose two shares are combined with KMAC256 into the key that wraps the session key. This is the format GnuPG writes for
/// public-key algorithm 8, and it differs from the RFC 9980 composites (different combiner, fixed-info and curves).
/// </summary>
internal static class LibrePgpKyber
{
    private static readonly byte[] DomSeparation = Encoding.UTF8.GetBytes("OpenPGPCompositeKeyDerivationFunction");
    private static readonly byte[] X25519Oid = [0x2B, 0x65, 0x6E];
    private static readonly byte[] X448Oid = [0x2B, 0x65, 0x6F];

    private enum Kind
    {
        X25519,
        X448,
    }

    private static (Kind Kind, int Size, int ShareBits) Curve(ReadOnlySpan<byte> oid)
    {
        if (oid.SequenceEqual(X25519Oid))
        {
            return (Kind.X25519, 32, 256);
        }

        if (oid.SequenceEqual(X448Oid))
        {
            return (Kind.X448, 56, 512);
        }

        // The NIST and Brainpool pairings of the draft's table 17 are not accepted: messages GnuPG 2.5.24 wrote for them did not open with the construction
        // the draft describes, and encrypting to them would write what its readers might not open. They are reported as unsupported.
        throw new PgpException(PgpFailure.Unsupported, "Kyber composites over this curve are not supported; only X25519 and X448 are.");
    }

    private static MLKemAlgorithm KemFor(int publicKeyLength) => publicKeyLength switch
    {
        1184 => MLKemAlgorithm.MLKem768,
        1568 => MLKemAlgorithm.MLKem1024,
        _ => throw new PgpException(PgpFailure.Unsupported, "The ML-KEM public key has an unexpected length."),
    };

    /// <summary>The curve point as the key packet stores it (a native key carries the 0x40 prefix of the legacy encoding); the bare encoding is returned.</summary>
    private static byte[] BarePoint(int size, ReadOnlySpan<byte> stored)
    {
        if (stored.Length == size + 1 && stored[0] == 0x40)
        {
            return stored[1..].ToArray();
        }

        return stored.ToArray();
    }

    /// <summary>draft-koch-librepgp §14.1.4: multiKeyCombine with one counter block, KMAC256 keyed by the domain string and customised with "KDF".</summary>
    internal static byte[] Combine(byte[] eccShare, byte[] eccCipherText, byte[] mlkemShare, byte[] mlkemCipherText, byte cipher, ReadOnlySpan<byte> fingerprint)
    {
        byte[] data = [0, 0, 0, 1, .. eccShare, .. eccCipherText, .. mlkemShare, .. mlkemCipherText, cipher, .. fingerprint];
        byte[] kek = new byte[32];
        KyberKmac.Compute(DomSeparation, data, kek, "KDF"u8);
        CryptographicOperations.ZeroMemory(data);
        return kek;
    }

    private static byte[] Share(int bits, ReadOnlySpan<byte> x, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> publicKey)
    {
        byte[] input = [.. x, .. ciphertext, .. publicKey];
        byte[] share = new byte[bits / 8];
        PlatformHash.Sha3(bits, input, share);
        CryptographicOperations.ZeroMemory(input);
        return share;
    }

    /// <summary>Null on any failure, as for the other algorithms (RFC 9580 §13).</summary>
    internal static SessionKeys.Recovered? Decrypt(PgpSecretKey key, PublicKeyEncryptedSessionKeyPacket p)
    {
        Platform.RequireMlKem();
        PublicKeyMaterial pm = key.Key.Packet.Material;
        (Kind kind, int size, int shareBits) = Curve(pm.CurveOid.Span);
        if (key.Key.Packet.Version != 5 || p.Values.Count != 4 || p.Values[2].Length != 1)
        {
            return null;
        }

        List<byte[]> sec = key.SecretParts();
        byte[] eccPublic = BarePoint(size, pm.Values[0].Span);
        byte[] eccCt = BarePoint(size, p.Values[0].Span);
        byte[] mlCt = p.Values[1].ToArray();
        byte[] wrapped = p.Values[3].ToArray();
        byte cipher = p.Values[2].Span[0];
        if (cipher is < 7 or > 9 || wrapped.Length is < 24 or > 72 || wrapped.Length % 8 != 0)
        {
            return null;
        }

        if (eccCt.Length != size)
        {
            return null;
        }

        // GnuPG stores the Curve25519 scalar big-endian, as the legacy Curve25519 key does; X448 has no legacy form and is little-endian.
        byte[] scalar = kind == Kind.X25519 ? sec[0].Reverse().ToArray() : sec[0];
        byte[] x = new byte[size];
        bool ok = kind == Kind.X25519 ? X25519.TryDeriveSharedSecret(scalar, eccCt, x) : X448.TryDeriveSharedSecret(scalar, eccCt, x);
        CryptographicOperations.ZeroMemory(scalar);
        if (!ok)
        {
            return null;
        }

        byte[] eccShare = Share(shareBits, x, eccCt, eccPublic);
        CryptographicOperations.ZeroMemory(x);

        using MLKem kem = MLKem.ImportDecapsulationKey(KemFor(pm.Values[1].Length), sec[1]);
        byte[] mlShare = new byte[32];
        kem.Decapsulate(mlCt, mlShare);
        byte[] kek = Combine(eccShare, eccCt, mlShare, mlCt, cipher, key.Key.Packet.GetFingerprint());
        CryptographicOperations.ZeroMemory(eccShare);
        CryptographicOperations.ZeroMemory(mlShare);
        byte[] sk = new byte[wrapped.Length - 8];
        using var kw = new AesKeyWrap(kek);
        CryptographicOperations.ZeroMemory(kek);
        return kw.TryUnwrap(wrapped, sk) ? new SessionKeys.Recovered((SymmetricAlgorithm)cipher, sk) : null;
    }

    /// <summary>The algorithm-specific part of a version 3 PKESK (draft-koch-librepgp §5.1): point, ML-KEM ciphertext, session-key algorithm, wrapped key.</summary>
    internal static byte[] Encrypt(PgpKey recipient, byte[] sessionKey, SymmetricAlgorithm cipher)
    {
        Platform.RequireMlKem();
        PublicKeyMaterial pm = recipient.Packet.Material;
        (Kind kind, int size, int shareBits) = Curve(pm.CurveOid.Span);
        if (recipient.Packet.Version != 5)
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "A Kyber key must be a version 5 key.");
        }

        if (cipher is not (SymmetricAlgorithm.Aes128 or SymmetricAlgorithm.Aes192 or SymmetricAlgorithm.Aes256))
        {
            throw new PgpException(PgpFailure.Unsupported, "A Kyber recipient needs an AES session key.");
        }

        byte[] eccPublic = BarePoint(size, pm.Values[0].Span);
        byte[] eSec = RandomNumberGenerator.GetBytes(size);
        byte[] eccCt = new byte[size];
        byte[] x = new byte[size];
        bool done;
        if (kind == Kind.X25519)
        {
            X25519.DerivePublicKey(eSec, eccCt);
            done = X25519.TryDeriveSharedSecret(eSec, eccPublic, x);
        }
        else
        {
            X448.DerivePublicKey(eSec, eccCt);
            done = X448.TryDeriveSharedSecret(eSec, eccPublic, x);
        }

        CryptographicOperations.ZeroMemory(eSec);
        if (!done)
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "The recipient's key is a low-order point.");
        }

        byte[] eccShare = Share(shareBits, x, eccCt, eccPublic);
        CryptographicOperations.ZeroMemory(x);

        using MLKem kem = MLKem.ImportEncapsulationKey(KemFor(pm.Values[1].Length), pm.Values[1].Span);
        byte[] mlCt = new byte[kem.Algorithm.CiphertextSizeInBytes];
        byte[] mlShare = new byte[32];
        kem.Encapsulate(mlCt, mlShare);
        byte[] kek = Combine(eccShare, eccCt, mlShare, mlCt, (byte)cipher, recipient.Packet.GetFingerprint());
        CryptographicOperations.ZeroMemory(eccShare);
        CryptographicOperations.ZeroMemory(mlShare);
        byte[] wrapped = new byte[sessionKey.Length + 8];
        using (var kw = new AesKeyWrap(kek))
        {
            kw.Wrap(sessionKey, wrapped);
        }

        CryptographicOperations.ZeroMemory(kek);

        // The point is an opaque string (its bit count is the full octet count); the ML-KEM ciphertext has a four-octet count.
        int bits = eccCt.Length * 8;
        return
        [
            (byte)(bits >> 8), (byte)bits, .. eccCt,
            (byte)(mlCt.Length >> 24), (byte)(mlCt.Length >> 16), (byte)(mlCt.Length >> 8), (byte)mlCt.Length, .. mlCt,
            (byte)cipher,
            (byte)wrapped.Length, .. wrapped,
        ];
    }
}

/// <summary>KMAC256 (NIST SP 800-185 §4) over cSHAKE256, for the Kyber key combiner.</summary>
internal static class KyberKmac
{
    private const int Rate = Keccak.RateShake256;

    // cSHAKE appends the two bits 00 to the message before the padding (SP 800-185 §3.3), which is the byte 0x04 in the sponge's bit order.
    private const byte CShakeSuffix = 0x04;

    internal static void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> output, ReadOnlySpan<byte> customization)
    {
        byte[] prefix = BytePad([.. EncodeString("KMAC"u8), .. EncodeString(customization)]);
        byte[] keyBlock = BytePad(EncodeString(key));
        byte[] tail = RightEncode((ulong)output.Length * 8);
        Keccak.Hash(Rate, CShakeSuffix, output, prefix, keyBlock, data, tail);
    }

    private static byte[] LeftEncode(ulong value)
    {
        int n = 1;
        for (ulong v = value >> 8; v != 0; v >>= 8)
        {
            n++;
        }

        byte[] r = new byte[n + 1];
        r[0] = (byte)n;
        for (int i = 0; i < n; i++)
        {
            r[n - i] = (byte)(value >> (8 * i));
        }

        return r;
    }

    private static byte[] RightEncode(ulong value)
    {
        byte[] left = LeftEncode(value);
        return [.. left[1..], left[0]];
    }

    private static byte[] EncodeString(ReadOnlySpan<byte> s) => [.. LeftEncode((ulong)s.Length * 8), .. s];

    private static byte[] BytePad(byte[] x)
    {
        byte[] z = [.. LeftEncode(Rate), .. x];
        int padded = (z.Length + Rate - 1) / Rate * Rate;
        Array.Resize(ref z, padded);
        return z;
    }
}
