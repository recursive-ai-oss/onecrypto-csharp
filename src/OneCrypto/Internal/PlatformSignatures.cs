using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives.Fallback;

namespace RecursiveAI.OneCrypto.Internal;

/// <summary>
/// RSA and ECDSA signature verification through the platform dispatch: the platform's where it can do the job, the verify-only managed
/// verifier elsewhere. Signing and decryption are never done here. All inputs are public.
/// </summary>
internal static class PlatformSignatures
{
    /// <summary>Verifies an RSASSA-PKCS1-v1_5 signature over a digest.</summary>
    /// <param name="modulus">The modulus, big-endian.</param>
    /// <param name="exponent">The public exponent, big-endian.</param>
    /// <param name="hash">The digest algorithm.</param>
    /// <param name="digest">The message digest.</param>
    /// <param name="signature">The signature.</param>
    /// <returns>True when valid.</returns>
    /// <exception cref="ArgumentException">The key is not a usable RSA public key.</exception>
    public static bool RsaVerifyPkcs1(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent, HashAlgorithmName hash, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        if (Platform.RsaVerify == Provider.Bcl && IsPlatformHash(hash))
        {
            return PlatformVerify(modulus, exponent, hash, RSASignaturePadding.Pkcs1, digest, signature);
        }

        return RsaVerifier.VerifyPkcs1(modulus, exponent, hash, digest, signature);
    }

    /// <summary>Verifies an RSASSA-PSS signature over a digest.</summary>
    /// <param name="modulus">The modulus, big-endian.</param>
    /// <param name="exponent">The public exponent, big-endian.</param>
    /// <param name="hash">The message digest algorithm.</param>
    /// <param name="mgfHash">The hash MGF1 runs on.</param>
    /// <param name="saltLength">The salt length in bytes.</param>
    /// <param name="digest">The message digest.</param>
    /// <param name="signature">The signature.</param>
    /// <returns>True when valid.</returns>
    /// <exception cref="ArgumentException">The key is not a usable RSA public key.</exception>
    public static bool RsaVerifyPss(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent, HashAlgorithmName hash, HashAlgorithmName mgfHash, int saltLength, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        // The platform's PSS fixes the salt length at the digest size and MGF1 on the same hash; other parameter sets go to the verifier.
        if (Platform.RsaVerify == Provider.Bcl && IsPlatformHash(hash) && hash == mgfHash && saltLength == digest.Length)
        {
            return PlatformVerify(modulus, exponent, hash, RSASignaturePadding.Pss, digest, signature);
        }

        return RsaVerifier.VerifyPss(modulus, exponent, hash, mgfHash, saltLength, digest, signature);
    }

    private static bool IsPlatformHash(HashAlgorithmName hash) =>
        hash == HashAlgorithmName.SHA1 || hash == HashAlgorithmName.SHA256 || hash == HashAlgorithmName.SHA384 || hash == HashAlgorithmName.SHA512;

    private static bool PlatformVerify(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent, HashAlgorithmName hash, RSASignaturePadding padding, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        if (digest.Length != PlatformHash.DigestSize(hash))
        {
            return false;
        }

        // RFC 8017 section 8.2.2 step 1: the signature is exactly as long as the modulus and below it. Some platforms reduce an
        // unreduced signature modulo n and accept it; the library does not.
        ReadOnlySpan<byte> n = Trim(modulus);
        if (signature.Length != n.Length || signature.SequenceCompareTo(n) >= 0)
        {
            return false;
        }

        using RSA rsa = RSA.Create();
        try
        {
            rsa.ImportParameters(new RSAParameters { Modulus = Trim(modulus), Exponent = Trim(exponent) });
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("The RSA public key is not usable.", ex);
        }

        try
        {
            return rsa.VerifyHash(digest, signature, hash, padding);
        }
        catch (CryptographicException)
        {
            return false; // a malformed signature the platform refuses outright
        }
    }

    private static byte[] Trim(ReadOnlySpan<byte> value)
    {
        int i = 0;
        while (i < value.Length - 1 && value[i] == 0)
        {
            i++;
        }

        return value[i..].ToArray();
    }

    /// <summary>Verifies an ECDSA signature over a digest.</summary>
    /// <param name="curve">The curve.</param>
    /// <param name="publicKey">The public point, uncompressed: 0x04, x, y.</param>
    /// <param name="digest">The message digest.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="format">DER or fixed-width <c>r || s</c>.</param>
    /// <returns>True when valid; false for a bad or malformed signature.</returns>
    /// <exception cref="ArgumentException">The public key is not a valid point on the curve.</exception>
    public static bool EcdsaVerifyHash(EcCurve curve, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature, DSASignatureFormat format)
    {
        if (Platform.EcdsaVerify(curve) != Provider.Bcl)
        {
            return EcdsaVerifier.VerifyHash(curve, publicKey, digest, signature, format);
        }

        int size = curve switch
        {
            EcCurve.NistP256 or EcCurve.BrainpoolP256r1 => 32,
            EcCurve.NistP384 or EcCurve.BrainpoolP384r1 => 48,
            _ => curve == EcCurve.NistP521 ? 66 : 64,
        };
        if (publicKey.Length != 1 + (2 * size) || publicKey[0] != 4)
        {
            throw new ArgumentException("The public key must be an uncompressed point.", nameof(publicKey));
        }

        ECCurve named = curve switch
        {
            EcCurve.NistP256 => ECCurve.NamedCurves.nistP256,
            EcCurve.NistP384 => ECCurve.NamedCurves.nistP384,
            EcCurve.NistP521 => ECCurve.NamedCurves.nistP521,
            EcCurve.BrainpoolP256r1 => ECCurve.NamedCurves.brainpoolP256r1,
            EcCurve.BrainpoolP384r1 => ECCurve.NamedCurves.brainpoolP384r1,
            _ => ECCurve.NamedCurves.brainpoolP512r1,
        };
        using ECDsa ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportParameters(new ECParameters
            {
                Curve = named,
                Q = new ECPoint { X = publicKey.Slice(1, size).ToArray(), Y = publicKey.Slice(1 + size, size).ToArray() },
            });
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("The public key is not a point on the curve.", nameof(publicKey), ex);
        }

        // Platform verifiers differ in how much BER they forgive in a DER signature; the library accepts DER only.
        if (format == DSASignatureFormat.Rfc3279DerSequence && !EcdsaVerifier.TryParseDer(signature, out _, out _))
        {
            return false;
        }

        try
        {
            return ecdsa.VerifyHash(digest, signature, format);
        }
        catch (CryptographicException)
        {
            return false; // a malformed signature the platform refuses outright
        }
    }
}
