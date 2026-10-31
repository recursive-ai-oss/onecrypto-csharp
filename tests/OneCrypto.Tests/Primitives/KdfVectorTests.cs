using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

/// <summary>Known-answer tests for BLAKE2b, Argon2 and scrypt from their RFCs.</summary>
public class KdfVectorTests
{
    // The 2 GiB and 1 GiB vectors need a lot of memory and seconds of CPU: they run when ONECRYPTO_BIG_VECTORS=1.
    private static bool Big => Environment.GetEnvironmentVariable("ONECRYPTO_BIG_VECTORS") == "1";

    private static byte[] Hex(string s) => Convert.FromHexString(s.Replace(" ", string.Empty));

    private static byte[] Repeat(byte b, int n) => Enumerable.Repeat(b, n).ToArray();

    [Fact]
    public void Blake2bRFC7693AppendixAabc()
    {
        byte[] digest = new byte[64];
        Blake2b.Hash("abc"u8, digest);
        Assert.Equal(
            Hex("BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923"),
            digest);
    }

    [Fact]
    public void Blake2bShortOutputsAndBlockBoundariesAgreeWithOneShot()
    {
        // Streaming in odd pieces must equal one call, across the 128-byte block boundary that holds the last block back.
        foreach (int length in new[] { 0, 1, 127, 128, 129, 255, 256, 257, 1000 })
        {
            byte[] data = RandomNumberGenerator.GetBytes(length);
            byte[] whole = new byte[48];
            Blake2b.Hash(data, whole);
            var h = new Blake2b(48);
            for (int i = 0; i < data.Length; i += 37)
            {
                h.Update(data.AsSpan(i, Math.Min(37, data.Length - i)));
            }

            byte[] pieces = new byte[48];
            h.Finish(pieces);
            Assert.Equal(whole, pieces);
        }
    }

    [Theory]
    [InlineData(Argon2Type.Argon2d, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")]
    [InlineData(Argon2Type.Argon2i, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")]
    [InlineData(Argon2Type.Argon2id, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")]
    public void Argon2RFC9106Section5(Argon2Type type, string tag)
    {
        byte[] derived = Argon2.DeriveKey(
            type, Repeat(1, 32), Repeat(2, 16), memoryKiB: 32, passes: 3, parallelism: 4, tagLength: 32,
            secret: Repeat(3, 8), associatedData: Repeat(4, 12));
        Assert.Equal(Hex(tag), derived);
    }

    [Fact]
    public void Argon2VerifyAcceptsRightTagAndRejectsWrongOne()
    {
        byte[] tag = Hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
        Assert.True(Argon2.Verify(Argon2Type.Argon2id, Repeat(1, 32), Repeat(2, 16), 32, 3, 4, tag, Repeat(3, 8), Repeat(4, 12)));
        tag[31] ^= 1;
        Assert.False(Argon2.Verify(Argon2Type.Argon2id, Repeat(1, 32), Repeat(2, 16), 32, 3, 4, tag, Repeat(3, 8), Repeat(4, 12)));
    }

    // RFC 9580 Appendix A.12: Argon2id (t = 1, p = 4, m = 2^21 KiB), passphrase "password". The v4 SKESK holds
    // algorithm || session key under AES-CFB with a zero IV; deriving the key and decrypting must give the session key
    // printed in the appendix.
    [Theory]
    [InlineData("9c52f83c27f95e50d535440ecdff3136", "9e52fcad22cf3f956542cba794ef840b11", "01FE16BBACFD1E7B78EF3B865187374F", 16)]
    [InlineData("e14cac4715345918a962dca347e143f8", "8732c9daf6b7146f3fa66a483ddfc7fe6768552e5504b2f017", "27006DAE68E509022CE45A14E569E91001C2955AF8DFE194", 24)]
    [InlineData("b8789520206ff799c6882c4245a6627c", "9d9f65ecab5a81d0a59bd51a43f67a33fe6ba249521a91aeeb6dd899a5decc68fc", "BBEDA55B9AAE63DAC45D4F49D89DACF4AF37FEFC13BAB2F1F8E18FB74580D8B0", 32)]
    public void Argon2idRFC9580AppendixA12SessionKey(string salt, string encryptedSessionKey, string sessionKey, int keySize)
    {
        Assert.SkipUnless(Big, "needs 2 GiB; set ONECRYPTO_BIG_VECTORS=1");
        byte[] key = Argon2.DeriveKey(
            Argon2Type.Argon2id, "password"u8, Hex(salt), memoryKiB: 1 << 21, passes: 1, parallelism: 4, tagLength: keySize,
            limits: new KdfLimits { MaxMemoryBytes = 4L << 30 });
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] clear = CfbDecrypt(aes, Hex(encryptedSessionKey));
        Assert.Equal(Hex(sessionKey), clear[1..]);
        Assert.Equal(keySize, clear.Length - 1);
    }

    // OpenPGP CFB with a zero IV (RFC 9580 section 5.3.1): each keystream block is the block cipher applied to the previous
    // ciphertext block, and the last block may be short, which the platform's CFB does not accept.
    private static byte[] CfbDecrypt(Aes aes, byte[] data)
    {
        byte[] clear = new byte[data.Length];
        byte[] previous = new byte[16];
        byte[] stream = new byte[16];
        for (int i = 0; i < data.Length; i += 16)
        {
            aes.EncryptEcb(previous, stream, PaddingMode.None);
            int n = Math.Min(16, data.Length - i);
            for (int j = 0; j < n; j++)
            {
                clear[i + j] = (byte)(data[i + j] ^ stream[j]);
            }

            if (n == 16)
            {
                Array.Copy(data, i, previous, 0, 16);
            }
        }

        return clear;
    }

    [Fact]
    public void Argon2ParallelLanesGiveTheSameTagAsTheirDefinition()
    {
        // A segment of 512 blocks takes the multi-threaded path; the tag must still be deterministic.
        byte[] a = Argon2.DeriveKey(Argon2Type.Argon2id, "pw"u8, Repeat(7, 16), 8192, 2, 4, 32);
        byte[] b = Argon2.DeriveKey(Argon2Type.Argon2id, "pw"u8, Repeat(7, 16), 8192, 2, 4, 32);
        Assert.Equal(a, b);
    }

    [Fact]
    public void Argon2ParametersOutsideTheLimitsRaiseTypedErrorsBeforeAllocating()
    {
        var e = Assert.Throws<KdfLimitExceededException>(() =>
            Argon2.DeriveKey(Argon2Type.Argon2id, "p"u8, Repeat(1, 16), memoryKiB: int.MaxValue, passes: 1, parallelism: 1, tagLength: 32));
        Assert.Equal("memory (bytes)", e.Parameter);
        Assert.Throws<KdfLimitExceededException>(() =>
            Argon2.DeriveKey(Argon2Type.Argon2id, "p"u8, Repeat(1, 16), 64, passes: 1000, parallelism: 1, tagLength: 32));
        Assert.Throws<KdfLimitExceededException>(() =>
            Argon2.DeriveKey(Argon2Type.Argon2id, "p"u8, Repeat(1, 16), 100000, passes: 1, parallelism: 100, tagLength: 32));
        Assert.Throws<ArgumentException>(() => Argon2.DeriveKey(Argon2Type.Argon2id, "p"u8, Repeat(1, 7), 64, 1, 1, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2.DeriveKey(Argon2Type.Argon2id, "p"u8, Repeat(1, 16), 7, 1, 1, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2.DeriveKey(Argon2Type.Argon2id, "p"u8, Repeat(1, 16), 64, 1, 1, 3));
    }

    [Fact]
    public void ScryptRFC7914Section12Small()
    {
        Assert.Equal(
            Hex("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
            Scrypt.DeriveKey(""u8, ""u8, 16, 1, 1, 64));
        Assert.Equal(
            Hex("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
            Scrypt.DeriveKey("password"u8, "NaCl"u8, 1024, 8, 16, 64));
        Assert.Equal(
            Hex("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"),
            Scrypt.DeriveKey("pleaseletmein"u8, "SodiumChloride"u8, 16384, 8, 1, 64));
    }

    [Fact]
    public void ScryptRFC7914Section12OneMillionAndSection13()
    {
        Assert.SkipUnless(Big, "needs 1 GiB; set ONECRYPTO_BIG_VECTORS=1");
        var limits = new KdfLimits { MaxMemoryBytes = 4L << 30 };
        Assert.Equal(
            Hex("2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4"),
            Scrypt.DeriveKey("pleaseletmein"u8, "SodiumChloride"u8, 1 << 20, 8, 1, 64, limits));

        // Section 13: the derived key of the PKCS#8 example.
        Assert.Equal(
            Hex("E277EA2CACB23EDAFC039D229B79DC13ECEDB601D99B182A9FEDBA1E2BFB4F58"),
            Scrypt.DeriveKey("Rabbit"u8, "Mouse"u8, 1 << 20, 8, 1, 32, limits));
    }

    [Fact]
    public void ScryptVectorSalsaMatchesTheScalarReference()
    {
        for (int i = 0; i < 2000; i++)
        {
            uint[] block = new uint[16];
            RandomNumberGenerator.Fill(System.Runtime.InteropServices.MemoryMarshal.AsBytes(block.AsSpan()));
            uint[] scalar = (uint[])block.Clone();
            Scrypt.Salsa208(scalar);
            Scrypt.Salsa208Vector(block);
            Assert.Equal(scalar, block);
        }
    }

    [Fact]
    public void ScryptParametersOutsideTheLimitsRaiseTypedErrors()
    {
        // 2^21 x 8 needs 2 GiB plus, over the default limit.
        var e = Assert.Throws<KdfLimitExceededException>(() => Scrypt.DeriveKey("p"u8, "s"u8, 1 << 21, 8, 1, 32));
        Assert.Equal("scrypt", e.Algorithm);
        Assert.Throws<KdfLimitExceededException>(() => Scrypt.DeriveKey("p"u8, "s"u8, 1 << 14, 8, 1000, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => Scrypt.DeriveKey("p"u8, "s"u8, 15, 8, 1, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => Scrypt.DeriveKey("p"u8, "s"u8, 1 << 16, 1, 1, 32));
    }
}
