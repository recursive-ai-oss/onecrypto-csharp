using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Primitives.Fallback;

namespace OneCrypto.Fuzz;

/// <summary>
/// The verify-only RSA and ECDSA code. The first byte picks the case: a fuzzed signature (DER or fixed-width) against a fixed good
/// key, on a NIST and on a Brainpool curve; a fuzzed RSA signature against a fixed modulus, PKCS#1 v1.5 and PSS with a fuzzed salt
/// length; and fuzzed public keys. A bad signature is a false result, a bad key an <see cref="ArgumentException"/>; nothing else may
/// come out.
/// </summary>
internal static class VerifyTarget
{
    // The generator point as the public key: a valid point on both curves, so the arithmetic runs.
    private static readonly byte[] P256Key = Convert.FromHexString("046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    private static readonly byte[] Brainpool256Key = Convert.FromHexString("048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997");

    // An odd 2048-bit number is enough for the verification arithmetic; this is not a real key.
    private static readonly byte[] Modulus = BuildModulus();
    private static readonly byte[] Exponent = [1, 0, 1];

    private static byte[] BuildModulus()
    {
        byte[] n = new byte[256];
        for (int i = 0; i < n.Length; i++)
        {
            n[i] = (byte)(i * 37 + 11);
        }

        n[0] |= 0x80;
        n[^1] |= 1;
        return n;
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        byte mode = data[0];
        ReadOnlySpan<byte> rest = data[1..];
        byte[] digest = SHA256.HashData(rest[..Math.Min(rest.Length, 8)]);
        try
        {
            switch (mode % 7)
            {
                case 0:
                    _ = EcdsaVerifier.VerifyHash(EcCurve.NistP256, P256Key, digest, rest, DSASignatureFormat.Rfc3279DerSequence);
                    break;
                case 1:
                    _ = EcdsaVerifier.VerifyHash(EcCurve.NistP256, P256Key, digest, rest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    break;
                case 2:
                    _ = EcdsaVerifier.VerifyHash(EcCurve.BrainpoolP256r1, Brainpool256Key, digest, rest, DSASignatureFormat.Rfc3279DerSequence);
                    break;
                case 3:
                    _ = RsaVerifier.VerifyPkcs1(Modulus, Exponent, HashAlgorithmName.SHA256, digest, rest);
                    break;
                case 4:
                    _ = RsaVerifier.VerifyPss(Modulus, Exponent, HashAlgorithmName.SHA256, HashAlgorithmName.SHA256, mode >> 3, digest, rest);
                    break;
                case 5:
                    // Public keys from the input: any point, any curve.
                    _ = EcdsaVerifier.VerifyHash((EcCurve)((mode >> 3) % 6), rest, digest, new byte[64], DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    break;
                default:
                    // An RSA modulus and exponent from the input, split at a fuzzed point.
                    int cut = rest[0] * rest.Length / 256;
                    _ = RsaVerifier.VerifyPkcs1(rest[..cut], rest[cut..], HashAlgorithmName.SHA256, digest, rest);
                    break;
            }
        }
        catch (ArgumentException)
        {
            // A key the verifier refuses.
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        byte[] der = Convert.FromHexString("3045022100b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a02200177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2");
        yield return [0, .. der];
        yield return [1, .. new byte[64]];
        yield return [2, .. der];
        yield return [3, .. new byte[256]];
        yield return [4, .. new byte[256]];
        yield return [5, .. P256Key];
        yield return [6, 40, .. Modulus, .. Exponent];
    }
}
