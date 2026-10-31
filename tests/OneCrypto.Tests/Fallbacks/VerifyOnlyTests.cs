using System.Security.Cryptography;
using System.Text.Json;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Primitives.Fallback;

namespace OneCrypto.Tests.Fallbacks;

/// <summary>
/// The verify-only RSA and ECDSA code against Wycheproof (testvectors_v1): every file whose hash the library knows, with the managed
/// verifier forced on, and the same files through the dispatch with the platform's own verifier. A test whose hash the library does
/// not offer (SHA-224, SHA-512/224, SHA-512/256, SHAKE) is counted as skipped. "acceptable" results may go either way.
/// </summary>
public class VerifyOnlyTests(ITestOutputHelper output)
{
    private static HashAlgorithmName? Hash(string? name) => name switch
    {
        "SHA-1" => HashAlgorithmName.SHA1,
        "SHA-256" => HashAlgorithmName.SHA256,
        "SHA-384" => HashAlgorithmName.SHA384,
        "SHA-512" => HashAlgorithmName.SHA512,
        "SHA3-224" => PlatformHash.Sha3_224Name,
        "SHA3-256" => HashAlgorithmName.SHA3_256,
        "SHA3-384" => HashAlgorithmName.SHA3_384,
        "SHA3-512" => HashAlgorithmName.SHA3_512,
        _ => null,
    };

    private static EcCurve? Curve(string name) => name switch
    {
        "secp256r1" => EcCurve.NistP256,
        "secp384r1" => EcCurve.NistP384,
        "secp521r1" => EcCurve.NistP521,
        "brainpoolP256r1" => EcCurve.BrainpoolP256r1,
        "brainpoolP384r1" => EcCurve.BrainpoolP384r1,
        "brainpoolP512r1" => EcCurve.BrainpoolP512r1,
        _ => null,
    };

    public static TheoryData<string> EcdsaFiles()
    {
        var d = new TheoryData<string>();
        string dir = Path.Combine(TestFiles.Vectors, "wycheproof", "testvectors_v1");
        if (Directory.Exists(dir))
        {
            foreach (string f in Directory.GetFiles(dir, "ecdsa_*_test.json").Select(Path.GetFileName).OfType<string>().Order(StringComparer.Ordinal))
            {
                string curve = f.Split('_')[1];
                if (Curve(curve) is not null && !f.Contains("bitcoin", StringComparison.Ordinal))
                {
                    d.Add(f);
                }
            }
        }
        else
        {
            d.Add("ecdsa_secp256r1_sha256_test.json");
        }

        return d;
    }

    public static TheoryData<string> RsaFiles()
    {
        var d = new TheoryData<string>();
        string dir = Path.Combine(TestFiles.Vectors, "wycheproof", "testvectors_v1");
        if (Directory.Exists(dir))
        {
            foreach (string f in Directory.GetFiles(dir, "rsa_*_test.json").Select(Path.GetFileName).OfType<string>().Order(StringComparer.Ordinal))
            {
                if (f.StartsWith("rsa_signature_", StringComparison.Ordinal) || f.StartsWith("rsa_pss_", StringComparison.Ordinal))
                {
                    d.Add(f);
                }
            }
        }
        else
        {
            d.Add("rsa_signature_2048_sha256_test.json");
        }

        return d;
    }

    [Theory]
    [MemberData(nameof(EcdsaFiles))]
    public void EcdsaFallback(string file) => RunEcdsa(file, forceFallback: true);

    [Theory]
    [MemberData(nameof(EcdsaFiles))]
    public void EcdsaDispatch(string file) => RunEcdsa(file, forceFallback: false);

    [Theory]
    [MemberData(nameof(RsaFiles))]
    public void RsaFallback(string file) => RunRsa(file, forceFallback: true);

    [Theory]
    [MemberData(nameof(RsaFiles))]
    public void RsaDispatch(string file) => RunRsa(file, forceFallback: false);

    private void RunEcdsa(string file, bool forceFallback)
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(TestFiles.Wycheproof(file)));
        using IDisposable? forced = forceFallback ? Platform.ForceFallbacks() : null;
        bool p1363 = file.Contains("p1363", StringComparison.Ordinal);
        int run = 0, passed = 0, skipped = 0, failed = 0;
        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            JsonElement key = group.GetProperty("publicKey");
            EcCurve? curve = Curve(key.GetProperty("curve").GetString()!);
            HashAlgorithmName? hash = Hash(group.GetProperty("sha").GetString());
            byte[] q = Hex.Decode(key.GetProperty("uncompressed").GetString()!);
            foreach (JsonElement t in group.GetProperty("tests").EnumerateArray())
            {
                run++;
                if (curve is null || hash is null)
                {
                    skipped++;
                    continue;
                }

                byte[] digest = PlatformHash.Digest(hash.Value, Hex.Decode(t.GetProperty("msg").GetString()!))!;
                byte[] sig = Hex.Decode(t.GetProperty("sig").GetString()!);
                string result = t.GetProperty("result").GetString()!;
                bool accepted = PlatformSignatures.EcdsaVerifyHash(curve.Value, q, digest, sig, p1363 ? DSASignatureFormat.IeeeP1363FixedFieldConcatenation : DSASignatureFormat.Rfc3279DerSequence);
                if (result == "acceptable" || accepted == (result == "valid"))
                {
                    passed++;
                }
                else
                {
                    failed++;
                    output.WriteLine($"{file} tcId {t.GetProperty("tcId").GetInt32()} ({result}) got {accepted}");
                }
            }
        }

        output.WriteLine($"{file} ({(forceFallback ? "managed verifier" : "dispatch: " + Platform.EcdsaVerify(EcCurve.NistP256))}): run {run}, passed {passed}, failed {failed}, skipped {skipped}");
        Assert.Equal(0, failed);
    }

    private void RunRsa(string file, bool forceFallback)
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(TestFiles.Wycheproof(file)));
        using IDisposable? forced = forceFallback ? Platform.ForceFallbacks() : null;
        bool pss = file.StartsWith("rsa_pss_", StringComparison.Ordinal);
        int run = 0, passed = 0, skipped = 0, failed = 0;
        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            JsonElement key = group.GetProperty("publicKey");
            byte[] n = Hex.Decode(key.GetProperty("modulus").GetString()!);
            byte[] e = Hex.Decode(key.GetProperty("publicExponent").GetString()!);
            HashAlgorithmName? hash = Hash(group.GetProperty("sha").GetString());
            HashAlgorithmName? mgfHash = pss ? Hash(group.GetProperty("mgfSha").GetString()) : hash;
            int saltLength = pss ? group.GetProperty("sLen").GetInt32() : 0;
            foreach (JsonElement t in group.GetProperty("tests").EnumerateArray())
            {
                run++;
                if (hash is null || mgfHash is null || (pss && group.GetProperty("mgf").GetString() != "MGF1"))
                {
                    skipped++;
                    continue;
                }

                byte[] digest = PlatformHash.Digest(hash.Value, Hex.Decode(t.GetProperty("msg").GetString()!))!;
                byte[] sig = Hex.Decode(t.GetProperty("sig").GetString()!);
                string result = t.GetProperty("result").GetString()!;
                bool accepted = pss
                    ? PlatformSignatures.RsaVerifyPss(n, e, hash.Value, mgfHash.Value, saltLength, digest, sig)
                    : PlatformSignatures.RsaVerifyPkcs1(n, e, hash.Value, digest, sig);
                if (result == "acceptable" || accepted == (result == "valid"))
                {
                    passed++;
                }
                else
                {
                    failed++;
                    output.WriteLine($"{file} tcId {t.GetProperty("tcId").GetInt32()} ({result}) got {accepted}");
                }
            }
        }

        output.WriteLine($"{file} ({(forceFallback ? "managed verifier" : "dispatch: " + Platform.RsaVerify)}): run {run}, passed {passed}, failed {failed}, skipped {skipped}");
        Assert.Equal(0, failed);
    }

    [Fact]
    public void TheCurveParametersDescribeGroupsOfTheStatedOrder()
    {
        // A signature made by the platform's ECDSA verifies in the managed verifier, on every curve the platform can sign with.
        foreach ((ECCurve named, EcCurve curve, HashAlgorithmName hash) in new[]
        {
            (ECCurve.NamedCurves.nistP256, EcCurve.NistP256, HashAlgorithmName.SHA256),
            (ECCurve.NamedCurves.nistP384, EcCurve.NistP384, HashAlgorithmName.SHA384),
            (ECCurve.NamedCurves.nistP521, EcCurve.NistP521, HashAlgorithmName.SHA512),
        })
        {
            using ECDsa key = ECDsa.Create(named);
            ECParameters p = key.ExportParameters(false);
            byte[] q = [4, .. p.Q.X!, .. p.Q.Y!];
            for (int i = 0; i < 5; i++)
            {
                byte[] message = RandomNumberGenerator.GetBytes(40 + i);
                byte[] sig = key.SignData(message, hash);
                byte[] digest = PlatformHash.Digest(hash, message)!;
                Assert.True(EcdsaVerifier.VerifyHash(curve, q, digest, sig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
                sig[^1] ^= 1;
                Assert.False(EcdsaVerifier.VerifyHash(curve, q, digest, sig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            }
        }
    }

    [Fact]
    public void AKeyOffTheCurveIsRefused()
    {
        byte[] q = new byte[65];
        q[0] = 4;
        q[32] = 1;
        q[64] = 1;
        Assert.Throws<ArgumentException>(() => EcdsaVerifier.VerifyHash(EcCurve.NistP256, q, new byte[32], new byte[64], DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Fact]
    public void RsaKeysOutsideTheBoundsAreRefused()
    {
        byte[] e = [1, 0, 1];
        Assert.Throws<ArgumentException>(() => RsaVerifier.VerifyPkcs1(new byte[256], e, HashAlgorithmName.SHA256, new byte[32], new byte[256]));
        byte[] even = new byte[256];
        even[0] = 0x80;
        Assert.Throws<ArgumentException>(() => RsaVerifier.VerifyPkcs1(even, e, HashAlgorithmName.SHA256, new byte[32], new byte[256]));
        byte[] odd = (byte[])even.Clone();
        odd[^1] = 1;
        Assert.Throws<ArgumentException>(() => RsaVerifier.VerifyPkcs1(odd, [2], HashAlgorithmName.SHA256, new byte[32], new byte[256]));
        byte[] huge = new byte[2100];
        huge[0] = 0x80;
        huge[^1] = 1;
        Assert.Throws<ArgumentException>(() => RsaVerifier.VerifyPkcs1(huge, e, HashAlgorithmName.SHA256, new byte[32], new byte[2100]));
    }
}
