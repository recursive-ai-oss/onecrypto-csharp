using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace OneCrypto.Smoke;

/// <summary>
/// Exercises the platform-gap code in an app that has to be trimmed, AOT-compiled or run in the browser: SHA-3 and SHAKE,
/// ChaCha20-Poly1305, and ECDSA verification (which brings in the managed big-number path), each through the dispatch, and prints
/// this platform's availability section so a script can compare it with the committed table.
/// </summary>
internal static class FallbackSmoke
{
    public static bool Run()
    {
        bool ok = true;

        // FIPS 202 known answers for "abc".
        byte[] abc = "abc"u8.ToArray();
        byte[] d256 = new byte[32];
        PlatformHash.Sha3(256, abc, d256);
        ok &= Check(1, Convert.ToHexStringLower(d256) == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        byte[] d224 = new byte[28];
        PlatformHash.Sha3(224, abc, d224);
        ok &= Check(2, Convert.ToHexStringLower(d224) == "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
        byte[] shake = new byte[32];
        PlatformHash.Shake(128, abc, shake);
        ok &= Check(3, Convert.ToHexStringLower(shake) == "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");

        // ChaCha20-Poly1305: round trip, and a flipped tag is refused.
        byte[] key = new byte[32], nonce = new byte[12], ct = new byte[abc.Length], tag = new byte[16], back = new byte[abc.Length];
        key[0] = 1;
        PlatformAead.ChaCha20Poly1305Encrypt(key, nonce, abc, ct, tag, default);
        ok &= Check(4, PlatformAead.ChaCha20Poly1305TryDecrypt(key, nonce, ct, tag, back, default) && back.AsSpan().SequenceEqual(abc));
        tag[0] ^= 1;
        ok &= Check(5, !PlatformAead.ChaCha20Poly1305TryDecrypt(key, nonce, ct, tag, back, default));

        // ECDSA P-256 verify of a published vector (Wycheproof ecdsa_secp256r1_sha256, tcId 1: the empty message).
        byte[] q = Convert.FromHexString("0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d");
        byte[] sig = Convert.FromHexString("3045022100b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a02200177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2");
        byte[] digest = SHA256.HashData([]);
        ok &= Check(6, PlatformSignatures.EcdsaVerifyHash(EcCurve.NistP256, q, digest, sig, DSASignatureFormat.Rfc3279DerSequence));
        digest[0] ^= 1;
        ok &= Check(7, !PlatformSignatures.EcdsaVerifyHash(EcCurve.NistP256, q, digest, sig, DSASignatureFormat.Rfc3279DerSequence));

        // The table's claims about what the platform has, checked against the platform itself: making each object either works or
        // throws PlatformNotSupportedException (or CryptographicException for a curve), and dispatch must have said so.
        // CA1416 is silenced for these probes only: the point is to call APIs the platform is annotated as lacking, and see that
        // the table says the same as the platform does.
#pragma warning disable CA1416
        ok &= Check(8, Matches(UseAes, Platform.HasAes));
        ok &= Check(9, Matches(() => RSA.Create().Dispose(), Platform.RsaVerify == Provider.Bcl));
        ok &= Check(10, Matches(() => ECDsa.Create(ECCurve.NamedCurves.nistP256).Dispose(), Platform.EcdsaVerify(EcCurve.NistP256) == Provider.Bcl));
        ok &= Check(11, Matches(() => ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1).Dispose(), Platform.EcdsaVerify(EcCurve.BrainpoolP256r1) == Provider.Bcl));
        ok &= Check(12, ChaCha20Poly1305.IsSupported == (Platform.ChaCha20Poly1305Support == Provider.Bcl));
        ok &= Check(13, SHA3_256.IsSupported == (Platform.Sha3(256) == Provider.Bcl));
#pragma warning restore CA1416

        Console.WriteLine("AVAILABILITY-BEGIN");
        Console.Write(Platform.AvailabilitySection());
        Console.WriteLine("AVAILABILITY-END");
        return ok;
    }

    // Making an Aes object may succeed where the cipher itself is missing, so the probe runs one block through it.
    private static void UseAes()
    {
#pragma warning disable CA1416
        using Aes aes = Aes.Create();
        aes.Key = new byte[16];
        _ = aes.EncryptEcb(new byte[16], PaddingMode.None);
#pragma warning restore CA1416
    }

    private static bool Check(int step, bool passed)
    {
        if (!passed)
        {
            Console.Error.WriteLine($"platform-gap check {step} failed");
        }

        return passed;
    }

    private static bool Matches(Action make, bool expectedToWork)
    {
        try
        {
            make();
            return expectedToWork;
        }
        catch (PlatformNotSupportedException)
        {
            return !expectedToWork;
        }
        catch (CryptographicException)
        {
            return !expectedToWork;
        }
    }
}
