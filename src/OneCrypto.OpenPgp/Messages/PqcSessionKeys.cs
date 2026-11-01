using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>ML-KEM + X25519 / X448 composite session-key encryption (RFC 9980 §4).</summary>
internal static class PqcSessionKeys
{
    private static readonly byte[] DomSep = "OpenPGPCompositeKDFv1"u8.ToArray();

    /// <summary>RFC 9980 §4.2.1: KEK = SHA3-256(mlkemShare || ecdhShare || ecdhCiphertext || ecdhPublicKey || algId || domSep || len(domSep)).</summary>
    private static byte[] Combine(byte[] mlkemShare, byte[] ecdhShare, byte[] ecdhCiphertext, byte[] ecdhPublic, PublicKeyAlgorithm algorithm)
    {
        byte[] input = [.. mlkemShare, .. ecdhShare, .. ecdhCiphertext, .. ecdhPublic, (byte)algorithm, .. DomSep, (byte)DomSep.Length];
        byte[] kek = new byte[32];
        PlatformHash.Sha3(256, input, kek);
        CryptographicOperations.ZeroMemory(input);
        return kek;
    }

    private static (MLKemAlgorithm Kem, int EcdhSize) Params(PublicKeyAlgorithm algorithm) => algorithm == PublicKeyAlgorithm.MlKem768X25519
        ? (MLKemAlgorithm.MLKem768, 32)
        : (MLKemAlgorithm.MLKem1024, 56);

    private static bool EcdhShare(int size, byte[] secret, byte[] peer, byte[] shared) => size == 32 ? X25519.TryDeriveSharedSecret(secret, peer, shared) : X448.TryDeriveSharedSecret(secret, peer, shared);

    /// <summary>RFC 9980 §4.2.4. Null on any failure, as for the other algorithms.</summary>
    internal static SessionKeys.Recovered? Decrypt(PgpSecretKey key, PublicKeyEncryptedSessionKeyPacket p)
    {
        Platform.RequireMlKem();
        (MLKemAlgorithm kemAlg, int size) = Params(p.Algorithm);
        List<byte[]> sec = key.SecretParts();
        byte[] ecdhCt = p.Values[0].ToArray();
        byte[] mlCt = p.Values[1].ToArray();
        byte[] ecdhPub = key.Key.Packet.Material.Values[0].ToArray();
        byte[] shared = new byte[size];
        if (!EcdhShare(size, sec[0], ecdhCt, shared))
        {
            return null;
        }

        using MLKem kem = MLKem.ImportPrivateSeed(kemAlg, sec[1]);
        byte[] mlShare = new byte[32];
        kem.Decapsulate(mlCt, mlShare);
        byte[] kek = Combine(mlShare, shared, ecdhCt, ecdhPub, p.Algorithm);
        CryptographicOperations.ZeroMemory(mlShare);
        CryptographicOperations.ZeroMemory(shared);
        ReadOnlySpan<byte> wrapped = p.Values[2].Span;
        SymmetricAlgorithm? cipher = null;
        if (p.Version == 3)
        {
            // RFC 9980 §4.3.1: the symmetric algorithm travels in the clear before the wrapped key and must be an AES.
            if (wrapped.Length < 1 || wrapped[0] is < 7 or > 9)
            {
                return null;
            }

            cipher = (SymmetricAlgorithm)wrapped[0];
            wrapped = wrapped[1..];
        }

        if (wrapped.Length < 24 || wrapped.Length > 8 + 64 || wrapped.Length % 8 != 0)
        {
            return null;
        }

        byte[] sk = new byte[wrapped.Length - 8];
        using var kw = new AesKeyWrap(kek);
        CryptographicOperations.ZeroMemory(kek);
        return kw.TryUnwrap(wrapped, sk) ? new SessionKeys.Recovered(cipher, sk) : null;
    }

    /// <summary>RFC 9980 §4.2.3: the algorithm-specific part of the PKESK.</summary>
    internal static byte[] Encrypt(PublicKeyAlgorithm algorithm, PublicKeyMaterial pm, byte[] sessionKey, SymmetricAlgorithm cipher, bool v3)
    {
        Platform.RequireMlKem();
        (MLKemAlgorithm kemAlg, int size) = Params(algorithm);
        byte[] ecdhPub = pm.Values[0].ToArray();
        byte[] eSec = RandomNumberGenerator.GetBytes(size);
        byte[] ecdhCt = new byte[size];
        byte[] shared = new byte[size];
        if (size == 32)
        {
            X25519.DerivePublicKey(eSec, ecdhCt);
        }
        else
        {
            X448.DerivePublicKey(eSec, ecdhCt);
        }

        bool ok = EcdhShare(size, eSec, ecdhPub, shared);
        CryptographicOperations.ZeroMemory(eSec);
        if (!ok)
        {
            throw new PgpException(PgpFailure.KeyCannotPerform, "The recipient's key is a low-order point.");
        }

        using MLKem kem = MLKem.ImportEncapsulationKey(kemAlg, pm.Values[1].Span);
        byte[] mlCt = new byte[kem.Algorithm.CiphertextSizeInBytes];
        byte[] mlShare = new byte[32];
        kem.Encapsulate(mlCt, mlShare);
        byte[] kek = Combine(mlShare, shared, ecdhCt, ecdhPub, algorithm);
        CryptographicOperations.ZeroMemory(mlShare);
        CryptographicOperations.ZeroMemory(shared);
        byte[] wrapped = new byte[sessionKey.Length + 8];
        using (var kw = new AesKeyWrap(kek))
        {
            kw.Wrap(sessionKey, wrapped);
        }

        CryptographicOperations.ZeroMemory(kek);
        return [.. ecdhCt, .. mlCt, (byte)(wrapped.Length + (v3 ? 1 : 0)), .. (v3 ? new[] { (byte)cipher } : []), .. wrapped];
    }
}
