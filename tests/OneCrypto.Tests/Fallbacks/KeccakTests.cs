using System.Globalization;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Fallbacks;

/// <summary>
/// SHA-3 and SHAKE through the managed Keccak (forced on, so it is exercised on every host): known answers, the NIST CAVP
/// byte-oriented vectors (short, long, Monte Carlo, variable output), and agreement with the platform where it has the hash.
/// </summary>
public class KeccakTests(ITestOutputHelper output)
{
    public static TheoryData<int, string, string> Known => new()
    {
        { 224, "", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" },
        { 224, "abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" },
        { 256, "", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" },
        { 256, "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
        { 384, "", "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004" },
        { 384, "abc", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25" },
        { 512, "", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" },
        { 512, "abc", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" },
    };

    [Theory]
    [MemberData(nameof(Known))]
    public void Sha3KnownAnswers(int bits, string message, string expected)
    {
        using IDisposable forced = Platform.ForceFallbacks();
        Assert.Equal(Provider.Fallback, Platform.Sha3(bits));
        byte[] digest = new byte[bits / 8];
        PlatformHash.Sha3(bits, System.Text.Encoding.ASCII.GetBytes(message), digest);
        Assert.Equal(expected, Convert.ToHexStringLower(digest));
    }

    [Fact]
    public void ShakeKnownAnswers()
    {
        using IDisposable forced = Platform.ForceFallbacks();
        byte[] a = new byte[32];
        PlatformHash.Shake(128, [], a);
        Assert.Equal("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26", Convert.ToHexStringLower(a));
        PlatformHash.Shake(128, "abc"u8, a);
        Assert.Equal("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8", Convert.ToHexStringLower(a));
        byte[] b = new byte[64];
        PlatformHash.Shake(256, [], b);
        Assert.Equal("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be", Convert.ToHexStringLower(b));
        PlatformHash.Shake(256, "abc"u8, b);
        Assert.Equal("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4", Convert.ToHexStringLower(b));
    }

    // ---- NIST CAVP ----

    public static TheoryData<string, int> ShaFiles()
    {
        var d = new TheoryData<string, int>();
        foreach (int bits in new[] { 224, 256, 384, 512 })
        {
            foreach (string kind in new[] { "ShortMsg", "LongMsg", "Monte" })
            {
                d.Add($"SHA3_{bits}{kind}.rsp", bits);
            }
        }

        return d;
    }

    [Theory]
    [MemberData(nameof(ShaFiles))]
    public void CavpSha3(string file, int bits)
    {
        string path = TestFiles.Cavp(file);
        using IDisposable forced = Platform.ForceFallbacks();
        int run = 0, failed = 0;
        if (file.Contains("Monte", StringComparison.Ordinal))
        {
            // Monte Carlo (CAVP SHA-3 section 6.2.3): each checkpoint is the digest after 1000 chained hashes of the previous digest.
            string[] lines = File.ReadAllLines(path);
            byte[] md = Hex.Decode(lines.First(l => l.StartsWith("Seed = ", StringComparison.Ordinal))[7..]);
            foreach (string expected in lines.Where(l => l.StartsWith("MD = ", StringComparison.Ordinal)).Select(l => l[5..]))
            {
                for (int i = 0; i < 1000; i++)
                {
                    byte[] next = new byte[bits / 8];
                    PlatformHash.Sha3(bits, md, next);
                    md = next;
                }

                run++;
                if (!string.Equals(Convert.ToHexStringLower(md), expected, StringComparison.OrdinalIgnoreCase))
                {
                    failed++;
                }
            }
        }
        else
        {
            foreach (Dictionary<string, string> r in Records(path))
            {
                int len = int.Parse(r["Len"], CultureInfo.InvariantCulture);
                byte[] msg = Hex.Decode(r["Msg"]).AsSpan(0, len / 8).ToArray();
                byte[] md = new byte[bits / 8];
                PlatformHash.Sha3(bits, msg, md);
                run++;
                if (!string.Equals(Convert.ToHexStringLower(md), r["MD"], StringComparison.OrdinalIgnoreCase))
                {
                    failed++;
                }
            }
        }

        output.WriteLine($"{file}: run {run}, passed {run - failed}, failed {failed}, skipped 0");
        Assert.True(run > 0);
        Assert.Equal(0, failed);
    }

    public static TheoryData<string, int> ShakeFiles()
    {
        var d = new TheoryData<string, int>();
        foreach (int bits in new[] { 128, 256 })
        {
            foreach (string kind in new[] { "ShortMsg", "LongMsg", "VariableOut", "Monte" })
            {
                d.Add($"SHAKE{bits}{kind}.rsp", bits);
            }
        }

        return d;
    }

    [Theory]
    [MemberData(nameof(ShakeFiles))]
    public void CavpShake(string file, int bits)
    {
        string path = TestFiles.Cavp(file);
        using IDisposable forced = Platform.ForceFallbacks();
        int run = 0, failed = 0;
        string text = File.ReadAllText(path);
        if (file.Contains("Monte", StringComparison.Ordinal))
        {
            // Monte Carlo (CAVP SHAKE section 6.2.4): the input is the first 128 bits of the previous output, zero padded; the next
            // output length comes from the last 16 bits of the output, in whole bytes between the file's minimum and maximum.
            int min = int.Parse(System.Text.RegularExpressions.Regex.Match(text, @"Minimum Output Length \(bits\) = (\d+)").Groups[1].Value, CultureInfo.InvariantCulture);
            int max = int.Parse(System.Text.RegularExpressions.Regex.Match(text, @"Maximum Output Length \(bits\) = (\d+)").Groups[1].Value, CultureInfo.InvariantCulture);
            byte[] output1 = Hex.Decode(System.Text.RegularExpressions.Regex.Match(text, @"Msg = (\w+)").Groups[1].Value);
            int outLen = max;
            var expectations = System.Text.RegularExpressions.Regex.Matches(text, @"Outputlen = (\d+)\s+Output = (\w+)");
            foreach (System.Text.RegularExpressions.Match m in expectations)
            {
                for (int i = 0; i < 1000; i++)
                {
                    byte[] input = new byte[16];
                    output1.AsSpan(0, Math.Min(16, output1.Length)).CopyTo(input);
                    output1 = new byte[outLen / 8];
                    PlatformHash.Shake(bits, input, output1);
                    int rightmost = (output1[^2] << 8) | output1[^1];
                    outLen = min + (8 * (rightmost % (((max - min) / 8) + 1)));
                }

                run++;
                if (output1.Length * 8 != int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)
                    || !string.Equals(Convert.ToHexStringLower(output1), m.Groups[2].Value, StringComparison.OrdinalIgnoreCase))
                {
                    failed++;
                }
            }
        }
        else
        {
            int fixedOut = 0;
            System.Text.RegularExpressions.Match fixedMatch = System.Text.RegularExpressions.Regex.Match(text, @"\[Outputlen = (\d+)\]");
            if (fixedMatch.Success)
            {
                fixedOut = int.Parse(fixedMatch.Groups[1].Value, CultureInfo.InvariantCulture);
            }

            foreach (Dictionary<string, string> r in Records(path))
            {
                byte[] msg;
                if (r.TryGetValue("Len", out string? lenText))
                {
                    msg = Hex.Decode(r["Msg"]).AsSpan(0, int.Parse(lenText, CultureInfo.InvariantCulture) / 8).ToArray();
                }
                else
                {
                    msg = Hex.Decode(r["Msg"]);
                }

                int outBits = r.TryGetValue("Outputlen", out string? o) ? int.Parse(o, CultureInfo.InvariantCulture) : fixedOut;
                byte[] result = new byte[outBits / 8];
                PlatformHash.Shake(bits, msg, result);
                run++;
                if (!string.Equals(Convert.ToHexStringLower(result), r["Output"], StringComparison.OrdinalIgnoreCase))
                {
                    failed++;
                }
            }
        }

        output.WriteLine($"{file}: run {run}, passed {run - failed}, failed {failed}, skipped 0");
        Assert.True(run > 0);
        Assert.Equal(0, failed);
    }

    // Blank-line separated blocks of `Key = value` lines; comment and bracket lines are ignored.
    private static IEnumerable<Dictionary<string, string>> Records(string path)
    {
        var current = new Dictionary<string, string>();
        foreach (string raw in File.ReadLines(path))
        {
            string line = raw.Trim();
            if (line.Length == 0)
            {
                if (current.Count > 0 && (current.ContainsKey("Msg")))
                {
                    yield return current;
                }

                current = [];
                continue;
            }

            int eq = line.IndexOf(" = ", StringComparison.Ordinal);
            if (line[0] is '#' or '[' || eq < 0)
            {
                continue;
            }

            current[line[..eq]] = line[(eq + 3)..];
        }

        if (current.ContainsKey("Msg"))
        {
            yield return current;
        }
    }

    // ---- agreement with the platform ----

    [Fact]
    public void FallbackAgreesWithThePlatformWhereItHasTheHash()
    {
        var rng = new Random(20260101);
        foreach (int len in new[] { 0, 1, 7, 71, 72, 73, 103, 104, 105, 135, 136, 137, 143, 144, 145, 167, 168, 169, 335, 336, 337, 1000, 5000 })
        {
            byte[] msg = new byte[len];
            rng.NextBytes(msg);
            foreach (int bits in new[] { 256, 384, 512 })
            {
                if (!Platform.Sha3(bits).Equals(Provider.Bcl))
                {
                    continue;
                }

                byte[] expected = new byte[bits / 8];
                PlatformHash.Sha3(bits, msg, expected);
                byte[] got = new byte[bits / 8];
                using (Platform.ForceFallbacks())
                {
                    PlatformHash.Sha3(bits, msg, got);
                }

                Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(got));
            }

            foreach (int bits in new[] { 128, 256 })
            {
                if (Platform.Shake(bits) != Provider.Bcl)
                {
                    continue;
                }

                foreach (int outLen in new[] { 1, 32, 114, 168, 169, 400 })
                {
                    byte[] expected = new byte[outLen];
                    PlatformHash.Shake(bits, msg, expected);
                    byte[] got = new byte[outLen];
                    using (Platform.ForceFallbacks())
                    {
                        PlatformHash.Shake(bits, msg, got);
                    }

                    Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(got));
                }
            }
        }
    }

    [Fact]
    public void EdHashShake256IsTheSameThroughTheFallbackAndThePlatform()
    {
        foreach (int len in new[] { 0, 1, 135, 136, 137, 271, 272, 273, 1000, 5000 })
        {
            byte[] msg = RandomNumberGenerator.GetBytes(len);
            foreach (int outLen in new[] { 1, 64, 114, 136, 137, 300 })
            {
                byte[] expected = new byte[outLen];
                PlatformHash.Shake(256, msg, expected);
                byte[] got = new byte[outLen];
                // Split the input over the pieces the signing code uses.
                int cut = len / 3;
                using (Platform.ForceFallbacks())
                {
                    EdHash.Shake256(got, msg.AsSpan(0, cut), msg.AsSpan(cut, cut), msg.AsSpan(2 * cut));
                }

                Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(got));
            }
        }
    }
}
