using System.Security.Cryptography;
using System.Text.Json;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Primitives.Internal;

namespace OneCrypto.Tests.Primitives;

/// <summary>Known answers and round trips for Camellia, CAST5, IDEA, Blowfish and Twofish.</summary>
public class LegacyCipherTests(ITestOutputHelper output)
{
    private static BlockEngine Engine(string cipher, byte[] key) => cipher switch
    {
        "camellia128" or "camellia192" or "camellia256" => new CamelliaEngine(key),
        "cast5" => new Cast5Engine(key),
        "idea" => new IdeaEngine(key),
        "blowfish" => new BlowfishEngine(key),
        "twofish" => new TwofishEngine(key),
        _ => throw new ArgumentException(cipher),
    };

    private static byte[] Block(BlockEngine e, byte[] input, bool decrypt)
    {
        byte[] o = new byte[input.Length];
        for (int i = 0; i < input.Length; i += e.BlockSize)
        {
            if (decrypt)
            {
                e.DecryptBlock(input.AsSpan(i, e.BlockSize), o.AsSpan(i, e.BlockSize));
            }
            else
            {
                e.EncryptBlock(input.AsSpan(i, e.BlockSize), o.AsSpan(i, e.BlockSize));
            }
        }

        return o;
    }

    // RFC 3713 Appendix A; RFC 2144 Appendix B.1; the IDEA, Blowfish and Twofish rows are the published known answers
    // (Blowfish: the variable-key test set; Twofish: the submission's known-answer tests).
    public static IEnumerable<object[]> Known() =>
    [
        ["camellia128", "0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"],
        ["camellia192", "0123456789abcdeffedcba98765432100011223344556677", "0123456789abcdeffedcba9876543210", "b4993401b3e996f84ee5cee7d79b09b9"],
        ["camellia256", "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff", "0123456789abcdeffedcba9876543210", "9acc237dff16d76c20ef7c919e3a7509"],
        ["cast5", "0123456712345678234567893456789a", "0123456789abcdef", "238b4fe5847e44b2"],
        ["cast5", "01234567123456782345", "0123456789abcdef", "eb6a711a2c02271b"],
        ["cast5", "0123456712", "0123456789abcdef", "7ac816d16e9b302e"],
        ["idea", "00010002000300040005000600070008", "0000000100020003", "11fbed2b01986de5"],
        ["blowfish", "0000000000000000", "0000000000000000", "4ef997456198dd78"],
        ["blowfish", "ffffffffffffffff", "ffffffffffffffff", "51866fd5b85ecb8a"],
        ["blowfish", "3000000000000000", "1000000000000001", "7d856f9a613063f2"],
        ["blowfish", "0123456789abcdef", "1111111111111111", "61f9c3802281b096"],
        ["twofish", "00000000000000000000000000000000", "00000000000000000000000000000000", "9f589f5cf6122c32b6bfec2f2ae8c35a"],
        ["twofish", "0123456789abcdeffedcba98765432100011223344556677", "00000000000000000000000000000000", "cfd1d2e5a9be9cdf501f13b892bd2248"],
        ["twofish", "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff", "00000000000000000000000000000000", "37527be0052334b89f0cfccae87cfa20"],
    ];

    [Theory]
    [MemberData(nameof(Known))]
    public void KnownAnswer(string cipher, string key, string plaintext, string ciphertext)
    {
        using BlockEngine e = Engine(cipher, Hex.Decode(key));
        Assert.Equal(ciphertext.ToUpperInvariant(), Hex.Encode(Block(e, Hex.Decode(plaintext), false)));
        Assert.Equal(plaintext.ToUpperInvariant(), Hex.Encode(Block(e, Hex.Decode(ciphertext), true)));
    }

    public static IEnumerable<object[]> OpenSslVectors() =>
        File.ReadLines(Path.Combine(TestFiles.TestData, "vectors", "legacy-ciphers-openssl.txt"))
            .Where(l => !l.StartsWith('#'))
            .Select(l => new object[] { l });

    // Ciphertexts written by OpenSSL (see tools/gen_legacy_vectors.py): our public decryption must read them, and the internal
    // encryption must write the same bytes.
    [Theory]
    [MemberData(nameof(OpenSslVectors))]
    public void OpenSslVector(string line)
    {
        string[] f = line.Split(' ');
        string cipher = f[0];
        string mode = f[1];
        byte[] key = Hex.Decode(f[2]);
        byte[] iv = Hex.Decode(f[3]);
        byte[] pt = Hex.Decode(f[4]);
        byte[] ct = Hex.Decode(f[5]);
        using BlockEngine e = Engine(cipher, key);
        byte[] decrypted = new byte[ct.Length];
        byte[] encrypted = new byte[pt.Length + e.BlockSize];
        int n;
        switch (mode)
        {
            case "ecb":
                BlockModes.Ecb(e, false, pt, encrypted);
                n = pt.Length;
                BlockModes.Ecb(e, true, ct, decrypted);
                break;
            case "cbc":
                n = BlockModes.CbcEncrypt(e, pt, iv, encrypted, PaddingMode.PKCS7);
                int m = BlockModes.CbcDecrypt(e, ct, iv, decrypted, PaddingMode.PKCS7);
                decrypted = decrypted[..m];
                break;
            default:
                BlockModes.Cfb(e, false, pt, iv, encrypted);
                n = pt.Length;
                BlockModes.Cfb(e, true, ct, iv, decrypted);
                break;
        }

        Assert.Equal(Hex.Encode(ct), Hex.Encode(encrypted.AsSpan(0, n)));
        Assert.Equal(Hex.Encode(pt), Hex.Encode(decrypted));
    }

    [Fact]
    public void PublicCamelliaMatchesEngine()
    {
        byte[] key = Hex.Decode("0123456789abcdeffedcba98765432100011223344556677");
        byte[] iv = Hex.Decode("000102030405060708090a0b0c0d0e0f");
        byte[] pt = new byte[53];
        new Random(5).NextBytes(pt);
        using var c = new Camellia(key);
        byte[] ct = new byte[64];
        Assert.Equal(64, c.EncryptCbc(pt, iv, ct));
        byte[] back = new byte[64];
        Assert.Equal(53, c.DecryptCbc(ct, iv, back));
        Assert.Equal(pt, back[..53]);
        byte[] cfb = new byte[53];
        c.EncryptCfb(pt, iv, cfb);
        c.DecryptCfb(cfb, iv, cfb); // in place
        Assert.Equal(pt, cfb);
    }

    [Fact]
    public void CbcDecryptRejectsBadPaddingAndReleasesNothing()
    {
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        using var c = new Camellia(key);
        byte[] ct = new byte[32];
        c.EncryptEcb(new byte[32], ct); // plaintext of zeros: last byte 0 is not valid padding
        byte[] dest = new byte[32];
        Array.Fill(dest, (byte)0xAA);
        Assert.Throws<CryptographicException>(() => c.DecryptCbc(ct, iv, dest));
        Assert.All(dest, b => Assert.Equal(0, b));
    }

    [Fact]
    public void WycheproofCamelliaCbc()
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(TestFiles.Wycheproof("camellia_cbc_pkcs5_test.json")));
        int run = 0, passed = 0, failed = 0;
        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            foreach (JsonElement t in group.GetProperty("tests").EnumerateArray())
            {
                run++;
                byte[] key = Hex.Decode(t.GetProperty("key").GetString()!);
                byte[] iv = Hex.Decode(t.GetProperty("iv").GetString()!);
                byte[] msg = Hex.Decode(t.GetProperty("msg").GetString()!);
                byte[] ct = Hex.Decode(t.GetProperty("ct").GetString()!);
                string result = t.GetProperty("result").GetString()!;
                using var c = new Camellia(key);
                bool ok;
                byte[] dest = new byte[ct.Length];
                try
                {
                    int n = c.DecryptCbc(ct, iv, dest);
                    bool same = dest.AsSpan(0, n).SequenceEqual(msg);
                    byte[] again = new byte[msg.Length + 16];
                    int m = c.EncryptCbc(msg, iv, again);
                    ok = result == "valid" && same && again.AsSpan(0, m).SequenceEqual(ct);
                }
                catch (Exception e) when (e is CryptographicException or ArgumentException)
                {
                    ok = result == "invalid";
                }

                if (ok)
                {
                    passed++;
                }
                else
                {
                    failed++;
                    output.WriteLine($"camellia_cbc_pkcs5_test tcId {t.GetProperty("tcId").GetInt32()} ({result}) failed");
                }
            }
        }

        output.WriteLine($"camellia_cbc_pkcs5_test.json: run {run}, passed {passed}, failed {failed}, skipped 0");
        Assert.Equal(0, failed);
    }

    [Theory]
    [InlineData("camellia128", 16)]
    [InlineData("camellia256", 32)]
    [InlineData("cast5", 16)]
    [InlineData("cast5", 7)]
    [InlineData("idea", 16)]
    [InlineData("blowfish", 16)]
    [InlineData("blowfish", 56)]
    [InlineData("blowfish", 4)]
    [InlineData("twofish", 16)]
    [InlineData("twofish", 24)]
    [InlineData("twofish", 32)]
    public void RoundTrip(string cipher, int keyLength)
    {
        var rng = new Random(keyLength * 31);
        for (int i = 0; i < 20; i++)
        {
            byte[] key = new byte[keyLength];
            rng.NextBytes(key);
            using BlockEngine e = Engine(cipher, key);
            byte[] data = new byte[e.BlockSize * 4];
            rng.NextBytes(data);
            byte[] ct = Block(e, data, false);
            Assert.NotEqual(data, ct);
            Assert.Equal(data, Block(e, ct, true));
        }
    }

    public static IEnumerable<object[]> GnuPgVectors() =>
        File.ReadLines(Path.Combine(TestFiles.TestData, "vectors", "gnupg-openpgp-cfb.txt"))
            .Where(l => !l.StartsWith('#'))
            .Select(l => new object[] { l });

    // OpenPGP symmetric-key encrypted data written by GnuPG (see tools/gen_gnupg_cfb_fixtures.py): the older unprotected packet
    // with the resynchronised register, and the protected packet with its modification detection trailer (RFC 9580 section 5.14): packet header D3 14 then 20 hash bytes.
    [Theory]
    [MemberData(nameof(GnuPgVectors))]
    public void GnuPgOpenPgpCfb(string line)
    {
        string[] f = line.Split(' ');
        int id = int.Parse(f[0]);
        byte[] key = Hex.Decode(f[1]);
        bool resync = f[2] == "1";
        byte[] ct = Hex.Decode(f[3]);
        byte[] message = Hex.Decode(f[4]);
        byte[] plain = new byte[ct.Length];
        int bs;
        switch (id)
        {
            case 1:
                using (var c = new Idea(key)) { c.DecryptOpenPgpCfb(ct, plain, resync); }
                bs = 8;
                break;
            case 3:
                using (var c = new Cast5(key)) { c.DecryptOpenPgpCfb(ct, plain, resync); }
                bs = 8;
                break;
            case 4:
                using (var c = new Blowfish(key)) { c.DecryptOpenPgpCfb(ct, plain, resync); }
                bs = 8;
                break;
            case 10:
                using (var c = new Twofish(key)) { c.DecryptOpenPgpCfb(ct, plain, resync); }
                bs = 16;
                break;
            default:
                using (var c = new Camellia(key)) { c.DecryptOpenPgpCfb(ct, plain, resync); }
                bs = 16;
                break;
        }

        // The last two prefix bytes repeat the two before them (the quick check of RFC 9580 section 13.9).
        Assert.Equal(plain[bs - 2], plain[bs]);
        Assert.Equal(plain[bs - 1], plain[bs + 1]);
        Assert.True(plain.AsSpan(bs + 2).IndexOf(message) >= 0, "the message is in the literal data packet");
        if (!resync)
        {
            ReadOnlySpan<byte> body = plain.AsSpan(0, plain.Length - 20); // the trailer hash is not checked here: SHA-1 is not used in tests
            Assert.Equal(0xD3, body[^2]);
            Assert.Equal(0x14, body[^1]);
        }
    }

    [Fact]
    public void OpenPgpCfbResync()
    {
        // Build resynchronised data by hand (RFC 4880 section 13.9) and read it back through the public method.
        byte[] key = Hex.Decode("00112233445566778899aabbccddeeff");
        using var c = new Camellia(key);
        byte[] plain = new byte[16 + 2 + 40];
        new Random(9).NextBytes(plain);
        plain[16] = plain[14];
        plain[17] = plain[15];
        byte[] ct = new byte[plain.Length];
        c.EncryptCfb(plain.AsSpan(0, 18), new byte[16], ct.AsSpan(0, 18));
        c.EncryptCfb(plain.AsSpan(18), ct.AsSpan(2, 16), ct.AsSpan(18));
        byte[] back = new byte[ct.Length];
        c.DecryptOpenPgpCfb(ct, back, resync: true);
        Assert.Equal(plain, back);
        c.DecryptOpenPgpCfb(ct, ct, resync: true); // in place
        Assert.Equal(plain, ct);
    }
}
