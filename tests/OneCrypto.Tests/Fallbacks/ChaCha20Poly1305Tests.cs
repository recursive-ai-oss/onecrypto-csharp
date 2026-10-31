using System.Security.Cryptography;
using System.Text.Json;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Primitives.Fallback;

namespace OneCrypto.Tests.Fallbacks;

/// <summary>
/// The managed ChaCha20-Poly1305: RFC 8439 (block function, Poly1305 edge cases, the AEAD example and the decryption example),
/// Wycheproof, and agreement with the platform where it has the cipher. Always runs the managed code, whatever the host offers.
/// </summary>
public class ChaCha20Poly1305Tests(ITestOutputHelper output)
{
    private static IEnumerable<string[]> Lines(string kind) =>
        File.ReadLines(Path.Combine(TestFiles.TestData, "vectors", "rfc8439.txt"))
            .Select(l => l.Split(' '))
            .Where(f => f[0] == kind);

    [Fact]
    public void BlockFunctionMatchesRfc8439AppendixA1()
    {
        int n = 0;
        foreach (string[] f in Lines("block"))
        {
            byte[] stream = new byte[64];
            ChaCha20Poly1305Managed.Block(Hex.Decode(f[1]), Convert.ToUInt32(f[2], 16), Hex.Decode(f[3]), stream);
            Assert.Equal(f[4], Convert.ToHexStringLower(stream));
            n++;
        }

        Assert.Equal(5, n);
    }

    [Fact]
    public void Poly1305MatchesRfc8439AppendixA3()
    {
        // Eleven vectors, including the carry and reduction edge cases (r = 0, s overflow, h just under and over 2^130 - 5).
        int n = 0;
        foreach (string[] f in Lines("poly1305"))
        {
            byte[] key = Hex.Decode(f[1]);
            byte[] message = Hex.Decode(f[2]);
            byte[] tag = ChaCha20Poly1305Managed.Poly1305Mac(key, message);
            Assert.Equal(f[3], Convert.ToHexStringLower(tag));
            n++;
        }

        Assert.Equal(11, n);
    }

    [Fact]
    public void AeadExampleMatchesRfc8439Section282()
    {
        string[] f = Lines("aead").Single();
        byte[] key = Hex.Decode(f[1]), nonce = Hex.Decode(f[2]), aad = Hex.Decode(f[3]), pt = Hex.Decode(f[4]);
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        ChaCha20Poly1305Managed.Encrypt(key, nonce, pt, ct, tag, aad);
        Assert.Equal(f[5], Convert.ToHexStringLower(ct));
        Assert.Equal(f[6], Convert.ToHexStringLower(tag));
        byte[] back = new byte[ct.Length];
        Assert.True(ChaCha20Poly1305Managed.TryDecrypt(key, nonce, ct, tag, back, aad));
        Assert.Equal(pt, back);
    }

    [Fact]
    public void DecryptionExampleMatchesRfc8439AppendixA5()
    {
        string[] f = Lines("decrypt").Single();
        byte[] key = Hex.Decode(f[1]), nonce = Hex.Decode(f[2]), aad = Hex.Decode(f[3]), ct = Hex.Decode(f[4]), tag = Hex.Decode(f[5]);
        byte[] pt = new byte[ct.Length];
        Assert.True(ChaCha20Poly1305Managed.TryDecrypt(key, nonce, ct, tag, pt, aad));
        Assert.StartsWith("Internet-Drafts are draft documents valid for a maximum of six months", System.Text.Encoding.ASCII.GetString(pt), StringComparison.Ordinal);
        // And the other way: encrypting that plaintext gives back the received ciphertext and tag.
        byte[] ct2 = new byte[pt.Length];
        byte[] tag2 = new byte[16];
        ChaCha20Poly1305Managed.Encrypt(key, nonce, pt, ct2, tag2, aad);
        Assert.Equal(ct, ct2);
        Assert.Equal(tag, tag2);
    }

    [Fact]
    public void AWrongTagReleasesNoPlaintext()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32), nonce = RandomNumberGenerator.GetBytes(12);
        byte[] pt = RandomNumberGenerator.GetBytes(200);
        byte[] ct = new byte[200];
        byte[] tag = new byte[16];
        ChaCha20Poly1305Managed.Encrypt(key, nonce, pt, ct, tag, default);
        byte[] outBuf = new byte[200];
        Array.Fill(outBuf, (byte)0xAA);
        tag[5] ^= 1;
        Assert.False(ChaCha20Poly1305Managed.TryDecrypt(key, nonce, ct, tag, outBuf, default));
        Assert.All(outBuf, b => Assert.Equal(0, b));
        tag[5] ^= 1;
        ct[3] ^= 1;
        Assert.False(ChaCha20Poly1305Managed.TryDecrypt(key, nonce, ct, tag, outBuf, default));
        Assert.False(ChaCha20Poly1305Managed.TryDecrypt(key, nonce, ct, tag, outBuf, [1]));
    }

    [Fact]
    public void WycheproofChaCha20Poly1305()
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(TestFiles.Wycheproof("chacha20_poly1305_test.json")));
        int run = 0, passed = 0, skipped = 0, failed = 0;
        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            int ivSize = group.GetProperty("ivSize").GetInt32();
            foreach (JsonElement t in group.GetProperty("tests").EnumerateArray())
            {
                run++;
                if (ivSize != 96)
                {
                    skipped++; // RFC 8439 fixes the nonce at 96 bits
                    continue;
                }

                byte[] key = Hex.Decode(t.GetProperty("key").GetString()!);
                byte[] nonce = Hex.Decode(t.GetProperty("iv").GetString()!);
                byte[] aad = Hex.Decode(t.GetProperty("aad").GetString()!);
                byte[] msg = Hex.Decode(t.GetProperty("msg").GetString()!);
                byte[] ct = Hex.Decode(t.GetProperty("ct").GetString()!);
                byte[] tag = Hex.Decode(t.GetProperty("tag").GetString()!);
                string result = t.GetProperty("result").GetString()!;
                bool ok;
                if (tag.Length != 16)
                {
                    skipped++; // truncated tags are not part of RFC 8439
                    continue;
                }

                byte[] plain = new byte[ct.Length];
                bool accepted = ChaCha20Poly1305Managed.TryDecrypt(key, nonce, ct, tag, plain, aad);
                if (result == "valid")
                {
                    byte[] ct2 = new byte[msg.Length];
                    byte[] tag2 = new byte[16];
                    ChaCha20Poly1305Managed.Encrypt(key, nonce, msg, ct2, tag2, aad);
                    ok = accepted && plain.AsSpan().SequenceEqual(msg) && ct2.AsSpan().SequenceEqual(ct) && tag2.AsSpan().SequenceEqual(tag);
                }
                else
                {
                    ok = !accepted && plain.All(b => b == 0);
                }

                if (ok)
                {
                    passed++;
                }
                else
                {
                    failed++;
                    output.WriteLine($"chacha20_poly1305_test tcId {t.GetProperty("tcId").GetInt32()} ({result}) failed");
                }
            }
        }

        output.WriteLine($"chacha20_poly1305_test.json: run {run}, passed {passed}, failed {failed}, skipped {skipped}");
        Assert.Equal(0, failed);
        Assert.True(passed > 300);
    }

    [Fact]
    public void AgreesWithThePlatformOnRandomInputs()
    {
        Assert.SkipUnless(ChaCha20Poly1305.IsSupported, "the platform has no ChaCha20-Poly1305 to compare with");
        var rng = new Random(8439);
        foreach (int len in new[] { 0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1000, 4096, 10000 })
        {
            foreach (int aadLen in new[] { 0, 1, 16, 33 })
            {
                byte[] key = new byte[32], nonce = new byte[12], pt = new byte[len], aad = new byte[aadLen];
                rng.NextBytes(key);
                rng.NextBytes(nonce);
                rng.NextBytes(pt);
                rng.NextBytes(aad);
                byte[] ct1 = new byte[len], tag1 = new byte[16];
                using (var platform = new ChaCha20Poly1305(key))
                {
                    platform.Encrypt(nonce, pt, ct1, tag1, aad);
                }

                byte[] ct2 = new byte[len], tag2 = new byte[16];
                ChaCha20Poly1305Managed.Encrypt(key, nonce, pt, ct2, tag2, aad);
                Assert.Equal(Convert.ToHexString(ct1), Convert.ToHexString(ct2));
                Assert.Equal(Convert.ToHexString(tag1), Convert.ToHexString(tag2));
            }
        }
    }

    [Fact]
    public void TheDispatchTakesTheManagedPathWhenForcedAndRoundTrips()
    {
        using IDisposable forced = Platform.ForceFallbacks();
        Assert.Equal(Provider.Fallback, Platform.ChaCha20Poly1305Support);
        byte[] key = RandomNumberGenerator.GetBytes(32), nonce = RandomNumberGenerator.GetBytes(12);
        byte[] pt = RandomNumberGenerator.GetBytes(77);
        byte[] ct = new byte[77], tag = new byte[16], back = new byte[77];
        PlatformAead.ChaCha20Poly1305Encrypt(key, nonce, pt, ct, tag, [9, 9]);
        Assert.True(PlatformAead.ChaCha20Poly1305TryDecrypt(key, nonce, ct, tag, back, [9, 9]));
        Assert.Equal(pt, back);
    }
}
