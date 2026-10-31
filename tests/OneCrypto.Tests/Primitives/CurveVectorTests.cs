using System.Text.Json;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

/// <summary>
/// Published vectors for Ed25519, Ed448, X25519 and X448: RFC 8032 section 7 and RFC 7748 (committed, small), plus the Wycheproof
/// and C2SP CCTV files, which are fetched by tools/fetch-curve-vectors.sh into $ONECRYPTO_VECTORS (default ~/onecrypto/vectors)
/// and never committed. A test whose suite is not present is skipped, and says so.
/// </summary>
public class CurveVectorTests
{
    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private static string? VectorFile(string relative)
    {
        string root = Environment.GetEnvironmentVariable("ONECRYPTO_VECTORS")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "onecrypto", "vectors");
        string path = Path.Combine(root, relative);
        return File.Exists(path) ? path : null;
    }

    private static JsonElement Load(string path) => JsonDocument.Parse(File.ReadAllText(path)).RootElement;

    // ---- RFC 8032 section 7 ----

    [Fact]
    public void Rfc8032AllVectorsSignAndVerify()
    {
        JsonElement vectors = Load(Path.Combine(AppContext.BaseDirectory, "Primitives", "Data", "rfc8032.json"));
        int n = 0;
        foreach (JsonElement v in vectors.EnumerateArray())
        {
            string alg = v.GetProperty("algorithm").GetString()!;
            byte[] seed = H(v.GetProperty("secret").GetString()!);
            byte[] pub = H(v.GetProperty("public").GetString()!);
            byte[] msg = H(v.GetProperty("message").GetString()!);
            byte[] sig = H(v.GetProperty("signature").GetString()!);
            byte[]? ctx = v.GetProperty("context").ValueKind == JsonValueKind.Null ? null : H(v.GetProperty("context").GetString()!);
            byte[] got = new byte[sig.Length];
            byte[] gotPub = new byte[pub.Length];
            string name = alg + " " + v.GetProperty("name").GetString();
            switch (alg)
            {
                case "Ed25519":
                    Ed25519.DerivePublicKey(seed, gotPub);
                    Assert.True(Ed25519.TrySign(seed, msg, got, out _), name);
                    Assert.True(Ed25519.Verify(pub, msg, sig), name);
                    break;
                case "Ed25519ctx":
                    Ed25519.DerivePublicKey(seed, gotPub);
                    Assert.True(Ed25519.TrySignWithContext(seed, msg, ctx!, got, out _), name);
                    Assert.True(Ed25519.VerifyWithContext(pub, msg, ctx!, sig), name);
                    Assert.False(Ed25519.Verify(pub, msg, sig), name + " must not verify as plain Ed25519");
                    break;
                case "Ed25519ph":
                    Ed25519.DerivePublicKey(seed, gotPub);
                    Assert.True(Ed25519.TrySignPrehashed(seed, msg, ctx ?? [], got, out _), name);
                    Assert.True(Ed25519.VerifyPrehashed(pub, msg, ctx ?? [], sig), name);
                    break;
                case "Ed448":
                    Ed448.DerivePublicKey(seed, gotPub);
                    Assert.True(Ed448.TrySign(seed, msg, ctx ?? [], got, out _), name);
                    Assert.True(Ed448.Verify(pub, msg, ctx ?? [], sig), name);
                    break;
                case "Ed448ph":
                    Ed448.DerivePublicKey(seed, gotPub);
                    Assert.True(Ed448.TrySignPrehashed(seed, msg, ctx ?? [], got, out _), name);
                    Assert.True(Ed448.VerifyPrehashed(pub, msg, ctx ?? [], sig), name);
                    break;
                default:
                    throw new InvalidOperationException(alg);
            }
            Assert.Equal(Convert.ToHexString(pub), Convert.ToHexString(gotPub));
            Assert.Equal(Convert.ToHexString(sig), Convert.ToHexString(got));
            // Flipping a message bit or a signature bit must break it.
            byte[] bad = (byte[])sig.Clone();
            bad[3] ^= 1;
            bool tamperedOk = alg.StartsWith("Ed448", StringComparison.Ordinal) ? Ed448.Verify(pub, msg, ctx ?? [], bad) : Ed25519.Verify(pub, msg, bad);
            Assert.False(tamperedOk, name + " tampered");
            n++;
        }
        Assert.Equal(21, n);
    }

    [Fact]
    public void KeyObjectsMatchOneShots()
    {
        byte[] seed = H("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        using var key = Ed25519PrivateKey.FromSeed(seed);
        byte[] sig = new byte[64];
        Assert.True(key.TrySign("abc"u8, sig, out int n));
        Assert.Equal(64, n);
        Assert.True(key.PublicKey.Verify("abc"u8, sig));
        Assert.False(key.PublicKey.Verify("abd"u8, sig));
        Assert.False(key.TrySign("abc"u8, new byte[63], out n));
        Assert.Equal(0, n);

        using var k448 = Ed448PrivateKey.Generate();
        byte[] s448 = new byte[114];
        Assert.True(k448.TrySign("abc"u8, "ctx"u8, s448, out _));
        Assert.True(k448.PublicKey.Verify("abc"u8, "ctx"u8, s448));
        Assert.False(k448.PublicKey.Verify("abc"u8, "ctz"u8, s448));
    }

    // ---- RFC 7748 ----

    [Fact]
    public void Rfc7748X25519FunctionVectors()
    {
        byte[] r = new byte[32];
        X25519.ScalarMult(H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"), H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"), r);
        Assert.Equal("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", Convert.ToHexStringLower(r));
        X25519.ScalarMult(H("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"), H("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"), r);
        Assert.Equal("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", Convert.ToHexStringLower(r));
    }

    [Fact]
    public void Rfc7748X448FunctionVectors()
    {
        byte[] r = new byte[56];
        X448.ScalarMult(H("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"),
            H("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"), r);
        Assert.Equal("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f", Convert.ToHexStringLower(r));
        X448.ScalarMult(H("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"),
            H("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"), r);
        Assert.Equal("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d", Convert.ToHexStringLower(r));
    }

    private static string Iterate25519(int iterations)
    {
        byte[] k = new byte[32], u = new byte[32], r = new byte[32];
        k[0] = 9;
        u[0] = 9;
        for (int i = 0; i < iterations; i++)
        {
            X25519.ScalarMult(k, u, r);
            k.CopyTo(u, 0);
            r.CopyTo(k, 0);
        }
        return Convert.ToHexStringLower(k);
    }

    private static string Iterate448(int iterations)
    {
        byte[] k = new byte[56], u = new byte[56], r = new byte[56];
        k[0] = 5;
        u[0] = 5;
        for (int i = 0; i < iterations; i++)
        {
            X448.ScalarMult(k, u, r);
            k.CopyTo(u, 0);
            r.CopyTo(k, 0);
        }
        return Convert.ToHexStringLower(k);
    }

    [Fact]
    public void Rfc7748Iterations1And1000()
    {
        Assert.Equal("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", Iterate25519(1));
        Assert.Equal("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", Iterate25519(1000));
        Assert.Equal("3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113", Iterate448(1));
        Assert.Equal("aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38", Iterate448(1000));
    }

    /// <summary>The 1,000,000-iteration loops; set ONECRYPTO_LONG=1 (they take a minute or more).</summary>
    [Fact]
    public void Rfc7748Iterations1000000()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("ONECRYPTO_LONG") == "1", "set ONECRYPTO_LONG=1 to run the million-iteration loops");
        Assert.Equal("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424", Iterate25519(1_000_000));
        Assert.Equal("077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37", Iterate448(1_000_000));
    }

    [Fact]
    public void Rfc7748DiffieHellmanExamples()
    {
        // Section 6.1
        byte[] a = H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] b = H("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] pa = new byte[32], pb = new byte[32], k1 = new byte[32], k2 = new byte[32];
        X25519.DerivePublicKey(a, pa);
        X25519.DerivePublicKey(b, pb);
        Assert.Equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Convert.ToHexStringLower(pa));
        Assert.Equal("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", Convert.ToHexStringLower(pb));
        Assert.True(X25519.TryDeriveSharedSecret(a, pb, k1));
        Assert.True(X25519.TryDeriveSharedSecret(b, pa, k2));
        Assert.Equal("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", Convert.ToHexStringLower(k1));
        Assert.Equal(Convert.ToHexStringLower(k1), Convert.ToHexStringLower(k2));

        // Section 6.2
        byte[] a4 = H("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
        byte[] b4 = H("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
        byte[] pa4 = new byte[56], pb4 = new byte[56], s1 = new byte[56], s2 = new byte[56];
        X448.DerivePublicKey(a4, pa4);
        X448.DerivePublicKey(b4, pb4);
        Assert.Equal("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0", Convert.ToHexStringLower(pa4));
        Assert.Equal("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609", Convert.ToHexStringLower(pb4));
        Assert.True(X448.TryDeriveSharedSecret(a4, pb4, s1));
        Assert.True(X448.TryDeriveSharedSecret(b4, pa4, s2));
        Assert.Equal("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d", Convert.ToHexStringLower(s1));
        Assert.Equal(Convert.ToHexStringLower(s1), Convert.ToHexStringLower(s2));
    }

    [Fact]
    public void LowOrderPeerKeyIsReportedAsZeroSharedSecret()
    {
        byte[] priv = H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] zeroU = new byte[32];
        byte[] shared = new byte[32];
        Assert.False(X25519.TryDeriveSharedSecret(priv, zeroU, shared));
        Assert.All(shared, x => Assert.Equal(0, x));
        using var key = X448PrivateKey.Generate();
        Assert.False(key.TryDeriveSharedSecret(X448PublicKey.FromBytes(new byte[56]), new byte[56]));
    }

    // ---- Wycheproof ----

    private sealed record Counts(int Run, int Passed, int Failed, int Accepted, int Rejected);

    [Theory]
    [InlineData("ed25519_test.json", 25519)]
    [InlineData("ed448_test.json", 448)]
    public void WycheproofEdDsa(string file, int curve)
    {
        string? path = VectorFile("wycheproof/testvectors_v1/" + file);
        Assert.SkipWhen(path is null, "Wycheproof vectors not fetched (tools/fetch-curve-vectors.sh)");
        JsonElement root = Load(path!);
        int run = 0, accepted = 0, rejected = 0;
        var failures = new List<string>();
        foreach (JsonElement g in root.GetProperty("testGroups").EnumerateArray())
        {
            byte[] pk = H(g.GetProperty("publicKey").GetProperty("pk").GetString()!);
            foreach (JsonElement t in g.GetProperty("tests").EnumerateArray())
            {
                byte[] msg = H(t.GetProperty("msg").GetString()!);
                byte[] sig = H(t.GetProperty("sig").GetString()!);
                string result = t.GetProperty("result").GetString()!;
                bool ok = curve == 25519 ? Ed25519.Verify(pk, msg, sig) : Ed448.Verify(pk, msg, [], sig);
                run++;
                if (ok) { accepted++; } else { rejected++; }
                // "acceptable" cases (small-order and mixed-order keys) may go either way by design; they are counted, not failed.
                if ((result == "valid" && !ok) || (result == "invalid" && ok))
                {
                    failures.Add($"tcId {t.GetProperty("tcId").GetInt32()} {t.GetProperty("comment").GetString()} expected {result}, got {(ok ? "accept" : "reject")}");
                }
            }
        }
        Console.WriteLine($"{file}: run {run}, failed {failures.Count}, accepted {accepted}, rejected {rejected}");
        Assert.True(failures.Count == 0, string.Join("; ", failures.Take(10)));
        Assert.Equal(root.GetProperty("numberOfTests").GetInt32(), run);
    }

    [Theory]
    [InlineData("x25519_test.json", 32)]
    [InlineData("x448_test.json", 56)]
    public void WycheproofXdh(string file, int size)
    {
        string? path = VectorFile("wycheproof/testvectors_v1/" + file);
        Assert.SkipWhen(path is null, "Wycheproof vectors not fetched (tools/fetch-curve-vectors.sh)");
        JsonElement root = Load(path!);
        int run = 0, agreed = 0, refused = 0;
        var failures = new List<string>();
        foreach (JsonElement g in root.GetProperty("testGroups").EnumerateArray())
        {
            foreach (JsonElement t in g.GetProperty("tests").EnumerateArray())
            {
                byte[] pub = H(t.GetProperty("public").GetString()!);
                byte[] priv = H(t.GetProperty("private").GetString()!);
                string expected = t.GetProperty("shared").GetString()!;
                string result = t.GetProperty("result").GetString()!;
                string outcome;
                if (pub.Length != size || priv.Length != size)
                {
                    outcome = "refused";
                }
                else
                {
                    byte[] shared = new byte[size];
                    bool ok = size == 32 ? X25519.TryDeriveSharedSecret(priv, pub, shared) : X448.TryDeriveSharedSecret(priv, pub, shared);
                    outcome = !ok ? "refused" : Convert.ToHexString(shared).Equals(expected, StringComparison.OrdinalIgnoreCase) ? "agreed" : "wrong";
                }
                run++;
                if (outcome == "agreed") { agreed++; } else if (outcome == "refused") { refused++; }
                // valid: must agree. acceptable: agree with the expected secret or refuse (the zero secret). invalid: must refuse.
                bool bad = outcome == "wrong" || (result == "valid" && outcome != "agreed") || (result == "invalid" && outcome != "refused");
                if (bad)
                {
                    failures.Add($"tcId {t.GetProperty("tcId").GetInt32()} {t.GetProperty("comment").GetString()} expected {result}, got {outcome}");
                }
            }
        }
        Console.WriteLine($"{file}: run {run}, failed {failures.Count}, agreed {agreed}, refused {refused}");
        Assert.True(failures.Count == 0, string.Join("; ", failures.Take(10)));
        Assert.Equal(root.GetProperty("numberOfTests").GetInt32(), run);
    }

    // ---- C2SP CCTV Ed25519 edge cases ----

    [Fact]
    public void CctvEd25519EdgeCasesFollowTheDocumentedPolicy()
    {
        string? path = VectorFile("CCTV/ed25519/ed25519vectors.json");
        Assert.SkipWhen(path is null, "CCTV vectors not fetched (tools/fetch-curve-vectors.sh)");
        JsonElement root = Load(path!);
        int run = 0, accepted = 0, rejected = 0;
        var failures = new List<string>();
        foreach (JsonElement v in root.EnumerateArray())
        {
            // A vector with no edge-case flag has "flags": null.
            JsonElement flagList = v.GetProperty("flags");
            var flags = flagList.ValueKind == JsonValueKind.Array ? flagList.EnumerateArray().Select(f => f.GetString()!).ToHashSet() : [];
            byte[] key = H(v.GetProperty("key").GetString()!);
            byte[] sig = H(v.GetProperty("sig").GetString()!);
            byte[] msg = System.Text.Encoding.UTF8.GetBytes(v.GetProperty("msg").GetString()!);
            bool ok = Ed25519.Verify(key, msg, sig);
            // Policy: reject non-canonical A and R and anything that only the cofactored equation would accept;
            // accept everything else (low-order A and R included) when the cofactorless equation holds.
            bool expected = !(flags.Contains("non_canonical_A") || flags.Contains("non_canonical_R") || flags.Contains("low_order_residue"));
            run++;
            if (ok) { accepted++; } else { rejected++; }
            if (ok != expected)
            {
                failures.Add($"vector {v.GetProperty("number").GetInt32()} [{string.Join(",", flags)}] expected {(expected ? "accept" : "reject")}");
            }
        }
        Console.WriteLine($"ed25519vectors.json: run {run}, failed {failures.Count}, accepted {accepted}, rejected {rejected}");
        Assert.True(failures.Count == 0, string.Join("; ", failures.Take(10)));
    }
}
