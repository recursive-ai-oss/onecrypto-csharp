using System.Diagnostics;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Primitives.Internal;

namespace OneCrypto.Tests.Primitives;

/// <summary>
/// Live two-way checks against OpenSSL as a black box, and the long CAST5 maintenance test. Set <c>ONECRYPTO_OPENSSL_HOME</c> to an
/// OpenSSL install prefix (with <c>bin/openssl</c> and <c>lib/ossl-modules/legacy.so</c>); the OpenSSL tests skip when it is not set.
/// The maintenance test runs when <c>ONECRYPTO_LONG_VECTORS</c> is set.
/// </summary>
public class LegacyCipherInteropTests(ITestOutputHelper output)
{
    private static string Home()
    {
        string? home = Environment.GetEnvironmentVariable("ONECRYPTO_OPENSSL_HOME");
        if (string.IsNullOrEmpty(home))
        {
            Assert.Skip("ONECRYPTO_OPENSSL_HOME is not set");
        }

        return home;
    }

    // Runs `openssl enc` on the input with the legacy provider loaded and returns the output.
    private static byte[] OpenSslEnc(string home, byte[] input, params string[] args)
    {
        string dir = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-legacy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string inFile = Path.Combine(dir, "in");
            string outFile = Path.Combine(dir, "out");
            File.WriteAllBytes(inFile, input);
            var psi = new ProcessStartInfo(Path.Combine(home, "bin", "openssl")) { RedirectStandardOutput = true, RedirectStandardError = true };
            psi.Environment["LD_LIBRARY_PATH"] = Path.Combine(home, "lib");
            psi.Environment["DYLD_LIBRARY_PATH"] = Path.Combine(home, "lib");
            psi.Environment["OPENSSL_MODULES"] = Path.Combine(home, "lib", "ossl-modules");
            string[] fixedArgs = ["enc", "-provider", "legacy", "-provider", "default"];
            foreach (string a in fixedArgs.Concat(args).Concat(["-in", inFile, "-out", outFile]))
            {
                psi.ArgumentList.Add(a);
            }

            using Process p = Process.Start(psi)!;
            Task<string> stderr = p.StandardError.ReadToEndAsync();
            p.WaitForExit();
            Assert.True(p.ExitCode == 0, "openssl failed: " + stderr.Result);
            return File.ReadAllBytes(outFile);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("camellia-128", 16)]
    [InlineData("camellia-192", 24)]
    [InlineData("camellia-256", 32)]
    [InlineData("cast5", 16)]
    [InlineData("idea", 16)]
    [InlineData("bf", 16)]
    public void CbcAndCfbBothWays(string algorithm, int keyLength)
    {
        string home = Home();
        int block = algorithm.StartsWith("camellia", StringComparison.Ordinal) ? 16 : 8;
        int cases = 0;
        foreach (int length in new[] { 0, 1, block - 1, block, block + 1, 3 * block, 100, 1000 })
        {
            byte[] key = RandomNumberGenerator.GetBytes(keyLength);
            byte[] iv = RandomNumberGenerator.GetBytes(block);
            byte[] data = RandomNumberGenerator.GetBytes(length);
            string k = Convert.ToHexString(key);
            string v = Convert.ToHexString(iv);

            // CBC with padding. Camellia can also encrypt, so it goes both ways; the decrypt-only ciphers are read from OpenSSL's output.
            byte[] cbc = OpenSslEnc(home, data, $"-{algorithm}-cbc", "-K", k, "-iv", v);
            byte[] cfb = OpenSslEnc(home, data, $"-{algorithm}-cfb", "-K", k, "-iv", v);
            byte[] back = new byte[cbc.Length];
            byte[] backCfb = new byte[cfb.Length];
            int n;
            if (block == 16)
            {
                using var c = new Camellia(key);
                n = c.DecryptCbc(cbc, iv, back);
                c.DecryptCfb(cfb, iv, backCfb);
                byte[] ours = new byte[length + 16];
                int m = c.EncryptCbc(data, iv, ours);
                Assert.Equal(Convert.ToHexString(OpenSslEnc(home, ours.AsSpan(0, m).ToArray(), $"-{algorithm}-cbc", "-d", "-K", k, "-iv", v)), Convert.ToHexString(data));
                byte[] oursCfb = new byte[length];
                c.EncryptCfb(data, iv, oursCfb);
                Assert.Equal(Convert.ToHexString(data), Convert.ToHexString(OpenSslEnc(home, oursCfb, $"-{algorithm}-cfb", "-d", "-K", k, "-iv", v)));
            }
            else
            {
                using BlockEngine e = algorithm switch
                {
                    "cast5" => new Cast5Engine(key),
                    "idea" => new IdeaEngine(key),
                    _ => new BlowfishEngine(key),
                };
                n = BlockModes.CbcDecrypt(e, cbc, iv, back, PaddingMode.PKCS7);
                BlockModes.Cfb(e, true, cfb, iv, backCfb);
            }

            Assert.Equal(Convert.ToHexString(data), Convert.ToHexString(back.AsSpan(0, n)));
            Assert.Equal(Convert.ToHexString(data), Convert.ToHexString(backCfb));
            cases++;
        }

        output.WriteLine($"{algorithm}: {cases} message lengths, CBC and CFB, agreed with OpenSSL");
    }

    // RFC 2144 Appendix B.2: one million rounds of four encryptions, each keyed by the other 128-bit value.
    [Fact]
    public void Cast5MaintenanceTest()
    {
        if (Environment.GetEnvironmentVariable("ONECRYPTO_LONG_VECTORS") is null)
        {
            Assert.Skip("ONECRYPTO_LONG_VECTORS is not set");
        }

        byte[] a = Hex.Decode("0123456712345678234567893456789A");
        byte[] b = (byte[])a.Clone();
        for (int i = 0; i < 1_000_000; i++)
        {
            using (var ea = new Cast5Engine(b))
            {
                ea.EncryptBlock(a.AsSpan(0, 8), a.AsSpan(0, 8));
                ea.EncryptBlock(a.AsSpan(8, 8), a.AsSpan(8, 8));
            }

            using var eb = new Cast5Engine(a);
            eb.EncryptBlock(b.AsSpan(0, 8), b.AsSpan(0, 8));
            eb.EncryptBlock(b.AsSpan(8, 8), b.AsSpan(8, 8));
        }

        Assert.Equal("EEA9D0A249FD3BA6B3436FB89D6DCA92", Hex.Encode(a));
        Assert.Equal("B2C95EB00C31AD7180AC05B8E83D696E", Hex.Encode(b));
    }
}
