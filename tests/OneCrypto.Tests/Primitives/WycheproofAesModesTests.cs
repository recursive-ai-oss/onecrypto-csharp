using System.Security.Cryptography;
using System.Text.Json;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Primitives;
using Xunit.Sdk;

namespace OneCrypto.Tests.Primitives;

/// <summary>
/// Wycheproof vectors (testvectors_v1) for the AES modes in this folder, plus AES-KWP against the platform's implementation. The
/// set has no OCB file. Each test class reports its run, passed, skipped and failed counts through the test output.
/// </summary>
public class WycheproofAesModesTests(ITestOutputHelper output)
{
    [Fact]
    public void AesEax()
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(TestFiles.Wycheproof("aes_eax_test.json")));
        int run = 0, passed = 0, skipped = 0, failed = 0;
        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            int tagSize = group.GetProperty("tagSize").GetInt32() / 8;
            foreach (JsonElement t in group.GetProperty("tests").EnumerateArray())
            {
                run++;
                byte[] key = Hex.Decode(t.GetProperty("key").GetString()!);
                byte[] nonce = Hex.Decode(t.GetProperty("iv").GetString()!);
                byte[] aad = Hex.Decode(t.GetProperty("aad").GetString()!);
                byte[] msg = Hex.Decode(t.GetProperty("msg").GetString()!);
                byte[] ct = Hex.Decode(t.GetProperty("ct").GetString()!);
                byte[] tag = Hex.Decode(t.GetProperty("tag").GetString()!);
                string result = t.GetProperty("result").GetString()!;
                using var eax = new AesEax(key, tagSize);
                bool ok;
                byte[] output1 = new byte[ct.Length];
                bool accepted = eax.TryDecrypt(nonce, ct, tag, output1, aad);
                if (result == "valid")
                {
                    byte[] ct2 = new byte[msg.Length];
                    byte[] tag2 = new byte[tagSize];
                    eax.Encrypt(nonce, msg, ct2, tag2, aad);
                    ok = accepted && output1.AsSpan().SequenceEqual(msg) && ct2.AsSpan().SequenceEqual(ct) && tag2.AsSpan().SequenceEqual(tag);
                }
                else
                {
                    ok = !accepted && output1.All(b => b == 0);
                }

                if (ok)
                {
                    passed++;
                }
                else
                {
                    failed++;
                    output.WriteLine($"aes_eax_test tcId {t.GetProperty("tcId").GetInt32()} ({result}) failed");
                }
            }
        }

        output.WriteLine($"aes_eax_test.json: run {run}, passed {passed}, failed {failed}, skipped {skipped}");
        Assert.Equal(0, failed);
        Assert.Equal(240, run);
    }

    [Fact]
    public void AesKeyWrap()
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(TestFiles.Wycheproof("aes_wrap_test.json")));
        int run = 0, passed = 0, failed = 0, acceptableRejected = 0, acceptableAccepted = 0;
        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            foreach (JsonElement t in group.GetProperty("tests").EnumerateArray())
            {
                run++;
                byte[] key = Hex.Decode(t.GetProperty("key").GetString()!);
                byte[] msg = Hex.Decode(t.GetProperty("msg").GetString()!);
                byte[] ct = Hex.Decode(t.GetProperty("ct").GetString()!);
                string result = t.GetProperty("result").GetString()!;
                using var kw = new AesKeyWrap(key);

                // Sizes our API refuses are a rejection, like a failed integrity check.
                bool unwrapped;
                byte[] recovered = new byte[Math.Max(0, ct.Length - 8)];
                try
                {
                    unwrapped = kw.TryUnwrap(ct, recovered);
                }
                catch (ArgumentException)
                {
                    unwrapped = false;
                }

                bool ok;
                if (result == "valid")
                {
                    byte[] wrapped = new byte[msg.Length + 8];
                    kw.Wrap(msg, wrapped);
                    ok = unwrapped && recovered.AsSpan().SequenceEqual(msg) && wrapped.AsSpan().SequenceEqual(ct);
                }
                else if (result == "invalid")
                {
                    ok = !unwrapped;
                }
                else
                {
                    ok = true; // acceptable: either outcome is allowed
                    if (unwrapped)
                    {
                        acceptableAccepted++;
                    }
                    else
                    {
                        acceptableRejected++;
                    }
                }

                if (ok)
                {
                    passed++;
                }
                else
                {
                    failed++;
                    output.WriteLine($"aes_wrap_test tcId {t.GetProperty("tcId").GetInt32()} ({result}) failed");
                }
            }
        }

        output.WriteLine($"aes_wrap_test.json: run {run}, passed {passed}, failed {failed}, skipped 0 (acceptable cases: {acceptableAccepted} accepted, {acceptableRejected} rejected)");
        Assert.Equal(0, failed);
        Assert.Equal(165, run);
    }

    // AES-KWP is the platform's; this checks that the platform path agrees with the published vectors on this machine.
    [Fact]
    public void AesKeyWrapPaddedAgainstThePlatform()
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(TestFiles.Wycheproof("aes_kwp_test.json")));
        int run = 0, passed = 0, failed = 0;
        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            foreach (JsonElement t in group.GetProperty("tests").EnumerateArray())
            {
                run++;
                byte[] key = Hex.Decode(t.GetProperty("key").GetString()!);
                byte[] msg = Hex.Decode(t.GetProperty("msg").GetString()!);
                byte[] ct = Hex.Decode(t.GetProperty("ct").GetString()!);
                string result = t.GetProperty("result").GetString()!;
                using Aes aes = Aes.Create();
                aes.SetKey(key);
                bool ok;
                if (result == "valid")
                {
                    byte[] wrapped = aes.EncryptKeyWrapPadded(msg);
                    byte[] unwrapped = aes.DecryptKeyWrapPadded(ct);
                    ok = wrapped.AsSpan().SequenceEqual(ct) && unwrapped.AsSpan().SequenceEqual(msg);
                }
                else
                {
                    ok = Rejects(() => aes.DecryptKeyWrapPadded(ct));
                }

                if (ok)
                {
                    passed++;
                }
                else
                {
                    failed++;
                    output.WriteLine($"aes_kwp_test tcId {t.GetProperty("tcId").GetInt32()} ({result}) failed");
                }
            }
        }

        output.WriteLine($"aes_kwp_test.json (platform AES-KWP): run {run}, passed {passed}, failed {failed}, skipped 0");
        Assert.Equal(0, failed);
    }

    private static bool Rejects(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }
}
