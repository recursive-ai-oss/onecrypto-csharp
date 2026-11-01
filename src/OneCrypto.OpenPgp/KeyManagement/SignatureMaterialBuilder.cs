using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// The algorithm-specific part of a signature packet (RFC 9580 §5.2.3 "Algorithm-Specific Fields"): which scheme signs the digest, and how the signer's
/// raw output becomes MPIs or fixed-size octet strings. Shared by message signing, key signatures and two-phase signing.
/// </summary>
internal static class SignatureMaterialBuilder
{
    /// <summary>The scheme that signs the digest for a key (never a composite).</summary>
    internal static SignatureSpec SpecFor(KeyPacket key, PgpHashAlgorithm hash)
    {
        HashAlgorithmName hn = PgpAlgorithms.HashName(hash);
        return key.Algorithm switch
        {
            PublicKeyAlgorithm.Ed25519 or PublicKeyAlgorithm.EdDsaLegacy => SignatureSpec.Ed25519(),
            PublicKeyAlgorithm.Ed448 => SignatureSpec.Ed448(),
            PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaSignOnly => SignatureSpec.RsaPkcs1(hn),
            PublicKeyAlgorithm.Ecdsa => SignatureSpec.Ecdsa(hn, EcdsaSignatureFormat.Rfc4754),
            _ => throw new PgpException(PgpFailure.KeyCannotPerform, $"The key algorithm {(byte)key.Algorithm} cannot sign."),
        };
    }

    /// <summary>Turns the signer's raw output into the signature packet's algorithm-specific fields.</summary>
    internal static byte[] Encode(PublicKeyAlgorithm algorithm, ReadOnlySpan<byte> raw)
    {
        switch (algorithm)
        {
            case PublicKeyAlgorithm.Ed25519:
            case PublicKeyAlgorithm.Ed448:
                return raw.ToArray();
            case PublicKeyAlgorithm.EdDsaLegacy:
                return [.. SignatureEngine.Mpi(raw[..32]), .. SignatureEngine.Mpi(raw.Slice(32, 32))];
            case PublicKeyAlgorithm.Rsa:
            case PublicKeyAlgorithm.RsaSignOnly:
                return SignatureEngine.Mpi(raw);
            case PublicKeyAlgorithm.Ecdsa:
                {
                    int half = raw.Length / 2;
                    return [.. SignatureEngine.Mpi(raw[..half]), .. SignatureEngine.Mpi(raw[half..])];
                }

            default:
                throw new PgpException(PgpFailure.KeyCannotPerform, $"The key algorithm {(byte)algorithm} cannot sign.");
        }
    }

    /// <summary>Signs the digest with an unlocked key and returns the algorithm-specific fields.</summary>
    internal static byte[] Sign(PgpSecretKey key, PgpHashAlgorithm hash, byte version, byte[] digest)
    {
        KeyPacket kp = key.Key.Packet;
        if (kp.Algorithm is PublicKeyAlgorithm.MlDsa65Ed25519 or PublicKeyAlgorithm.MlDsa87Ed448)
        {
            // RFC 9980 §5.3.1: composite ML-DSA signatures need version 6 and a hash of at least 256 bits; they hold two component keys and sign through their own path.
            if (version != 6 || PgpAlgorithms.HashSize(hash) < 32)
            {
                throw new PgpException(PgpFailure.KeyCannotPerform, "ML-DSA composite signatures need version 6 and a hash of at least 256 bits (RFC 9980 §5.3.1).");
            }

            return key.SignComposite(digest);
        }

        SignatureSpec spec = SpecFor(kp, hash);
        ISigningKey signer = key.SigningKey;
        byte[] raw = spec.SignsDigest ? signer.SignDigest(digest, spec) : signer.Sign(digest, spec);
        return Encode(kp.Algorithm, raw);
    }
}
