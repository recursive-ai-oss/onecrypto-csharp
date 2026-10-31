using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

/// <summary>
/// Two-way checks against OpenSSL, used as a black box. Set <c>ONECRYPTO_OPENSSL_HOME</c> to an OpenSSL install prefix (with
/// <c>bin/openssl</c> and <c>lib/libcrypto.*</c>); the tests skip when it is not set. OCB runs through <c>tools/openssl_aead.py</c>
/// because the command line has no AEAD modes; key wrap uses <c>openssl enc -id-aes*-wrap</c>.
/// </summary>
public class OpenSslAesModesInteropTests(ITestOutputHelper output)
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

    private static string LibCrypto(string home)
    {
        foreach (string dir in new[] { "lib", "lib64" })
        {
            string d = Path.Combine(home, dir);
            if (Directory.Exists(d))
            {
                string? found = Directory.GetFiles(d, "libcrypto.so.3").Concat(Directory.GetFiles(d, "libcrypto.3.dylib")).FirstOrDefault();
                if (found is not null)
                {
                    return found;
                }
            }
        }

        throw new FileNotFoundException("libcrypto not found under " + home);
    }

    private static ProcessStartInfo OpenSsl(string home, params string[] args)
    {
        var psi = new ProcessStartInfo(Path.Combine(home, "bin", "openssl")) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        psi.Environment["LD_LIBRARY_PATH"] = Path.Combine(home, "lib");
        psi.Environment["DYLD_LIBRARY_PATH"] = Path.Combine(home, "lib");
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        return psi;
    }

    // Runs openssl with the input and output as files: the key-wrap ciphers cannot stream through a pipe.
    private static byte[] RunOpenSsl(string home, byte[] input, out int exitCode, params string[] args)
    {
        string dir = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-aesmodes-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string inFile = Path.Combine(dir, "in");
            string outFile = Path.Combine(dir, "out");
            File.WriteAllBytes(inFile, input);
            string[] all = args.Length > 0 && args[0] == "enc" ? [.. args, "-in", inFile, "-out", outFile] : args;
            using Process p = Process.Start(OpenSsl(home, all))!;
            p.StandardInput.Close();
            Task<string> stdout = p.StandardOutput.ReadToEndAsync();
            Task<string> stderr = p.StandardError.ReadToEndAsync();
            p.WaitForExit();
            exitCode = p.ExitCode;
            if (args.Length > 0 && args[0] == "enc")
            {
                return File.Exists(outFile) ? File.ReadAllBytes(outFile) : [];
            }

            return Encoding.UTF8.GetBytes(stdout.Result + stderr.Result);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void OcbBothWays()
    {
        string home = Home();
        var psi = new ProcessStartInfo("python3") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add(Path.Combine(TestFiles.Tools, "openssl_aead.py"));
        psi.Environment["OPENSSL_LIBCRYPTO"] = LibCrypto(home);
        psi.Environment["LD_LIBRARY_PATH"] = Path.Combine(home, "lib");

        using Process py = Process.Start(psi)!;
        Task<string> stderr = py.StandardError.ReadToEndAsync();

        string Ask(object request)
        {
            py.StandardInput.WriteLine(JsonSerializer.Serialize(request));
            py.StandardInput.Flush();
            return py.StandardOutput.ReadLine() ?? throw new InvalidOperationException("oracle closed: " + stderr.Result);
        }

        int cases = 0;
        int[] dataLengths = [0, 1, 15, 16, 17, 100, 2047, 2048, 2049, 5000];
        int[] aadLengths = [0, 1, 16, 2049];
        foreach (int keySize in new[] { 16, 24, 32 })
        {
            string cipher = $"AES-{keySize * 8}-OCB";
            foreach (int nonceSize in new[] { 1, 7, 12, 15 })
            {
                foreach (int tagSize in new[] { 8, 12, 16 })
                {
                    byte[] key = RandomNumberGenerator.GetBytes(keySize);
                    using var ocb = new AesOcb(key, tagSize);
                    foreach (int dataLength in dataLengths)
                    {
                        foreach (int aadLength in aadLengths)
                        {
                            byte[] nonce = RandomNumberGenerator.GetBytes(nonceSize);
                            byte[] aad = RandomNumberGenerator.GetBytes(aadLength);
                            byte[] plaintext = RandomNumberGenerator.GetBytes(dataLength);
                            string label = $"{cipher} nonce {nonceSize} tag {tagSize} data {dataLength} aad {aadLength}";

                            // ours -> OpenSSL
                            byte[] ct = new byte[dataLength];
                            byte[] tag = new byte[tagSize];
                            ocb.Encrypt(nonce, plaintext, ct, tag, aad);
                            using (JsonDocument r = JsonDocument.Parse(Ask(new { op = "dec", cipher, key = Hex.Encode(key), iv = Hex.Encode(nonce), aad = Hex.Encode(aad), taglen = tagSize, data = Hex.Encode(ct), tag = Hex.Encode(tag) })))
                            {
                                Assert.True(r.RootElement.GetProperty("ok").GetBoolean(), "OpenSSL rejected ours: " + label);
                                Assert.Equal(Hex.Encode(plaintext), r.RootElement.GetProperty("data").GetString()!.ToUpperInvariant());
                            }

                            // a flipped tag bit must be rejected by OpenSSL too
                            byte[] bad = (byte[])tag.Clone();
                            bad[0] ^= 1;
                            using (JsonDocument r = JsonDocument.Parse(Ask(new { op = "dec", cipher, key = Hex.Encode(key), iv = Hex.Encode(nonce), aad = Hex.Encode(aad), taglen = tagSize, data = Hex.Encode(ct), tag = Hex.Encode(bad) })))
                            {
                                Assert.False(r.RootElement.GetProperty("ok").GetBoolean(), "OpenSSL accepted a bad tag: " + label);
                            }

                            // OpenSSL -> ours
                            using (JsonDocument r = JsonDocument.Parse(Ask(new { op = "enc", cipher, key = Hex.Encode(key), iv = Hex.Encode(nonce), aad = Hex.Encode(aad), taglen = tagSize, data = Hex.Encode(plaintext) })))
                            {
                                Assert.True(r.RootElement.GetProperty("ok").GetBoolean(), "OpenSSL failed to encrypt: " + label);
                                byte[] theirCt = Hex.Decode(r.RootElement.GetProperty("data").GetString()!);
                                byte[] theirTag = Hex.Decode(r.RootElement.GetProperty("tag").GetString()!);
                                Assert.Equal(Hex.Encode(ct), Hex.Encode(theirCt));
                                Assert.Equal(Hex.Encode(tag), Hex.Encode(theirTag));
                                byte[] back = new byte[dataLength];
                                ocb.Decrypt(nonce, theirCt, theirTag, back, aad);
                                Assert.Equal(plaintext, back);
                            }

                            cases++;
                        }
                    }
                }
            }
        }

        py.StandardInput.Close();
        py.WaitForExit();
        output.WriteLine($"OCB vs OpenSSL ({Version(home)}): {cases} cases x (ours->OpenSSL, bad tag, OpenSSL->ours), 0 failures");
    }

    private static string Version(string home)
    {
        byte[] v = RunOpenSsl(home, [], out _, "version");
        return Encoding.ASCII.GetString(v).Trim();
    }

    [Fact]
    public void KeyWrapBothWays()
    {
        string home = Home();
        int cases = 0;
        foreach (int keySize in new[] { 16, 24, 32 })
        {
            string cipher = $"-id-aes{keySize * 8}-wrap";
            foreach (int dataLength in new[] { 16, 24, 32, 40, 64, 128, 1024 })
            {
                byte[] kek = RandomNumberGenerator.GetBytes(keySize);
                byte[] data = RandomNumberGenerator.GetBytes(dataLength);
                using var kw = new AesKeyWrap(kek);
                byte[] wrapped = new byte[dataLength + 8];
                kw.Wrap(data, wrapped);

                byte[] theirs = RunOpenSsl(home, data, out int code, "enc", cipher, "-K", Hex.Encode(kek), "-iv", "A6A6A6A6A6A6A6A6");
                Assert.Equal(0, code);
                Assert.Equal(Hex.Encode(wrapped), Hex.Encode(theirs));

                byte[] unwrapped = RunOpenSsl(home, wrapped, out code, "enc", "-d", cipher, "-K", Hex.Encode(kek), "-iv", "A6A6A6A6A6A6A6A6");
                Assert.Equal(0, code);
                Assert.Equal(Hex.Encode(data), Hex.Encode(unwrapped));

                byte[] bad = (byte[])wrapped.Clone();
                bad[3] ^= 1;
                RunOpenSsl(home, bad, out code, "enc", "-d", cipher, "-K", Hex.Encode(kek), "-iv", "A6A6A6A6A6A6A6A6");
                Assert.NotEqual(0, code);
                Assert.False(kw.TryUnwrap(bad, new byte[dataLength]));
                cases++;
            }
        }

        output.WriteLine($"AES-KW vs OpenSSL ({Version(home)}): {cases} cases x (ours->OpenSSL, OpenSSL->ours, tampered), 0 failures");
    }
}
