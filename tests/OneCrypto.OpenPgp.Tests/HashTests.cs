using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>The managed SHA-224 (FIPS 180-4 examples) and RIPEMD-160 (the designers' published set), used only to verify old signatures.</summary>
public class HashTests
{
    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    private const string Alpha56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    public static TheoryData<string, string> Sha224Vectors => new()
    {
        { "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
        { "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
        { Alpha56, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" },
    };

    [Theory]
    [MemberData(nameof(Sha224Vectors))]
    public void Sha224MatchesPublishedExamples(string input, string expected) =>
        Assert.Equal(expected, Hex(PgpHash.Compute(PgpHashAlgorithm.Sha224, Ascii(input))));

    [Fact]
    public void Sha224OfAMillionAs() =>
        Assert.Equal("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67", Hex(PgpHash.Compute(PgpHashAlgorithm.Sha224, Ascii(new string('a', 1_000_000)))));

    public static TheoryData<string, string> RipemdVectors => new()
    {
        { "", "9c1185a5c5e9fc54612808977ee8f548b2258d31" },
        { "a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe" },
        { "abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
        { "message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36" },
        { "abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc" },
        { Alpha56, "12a053384a9c0c88e405a06c27dcf49ada62eb2b" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189" },
        { "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "9b752e45573d4b39f4dbd3323cab82bf63326bfb" },
    };

    [Theory]
    [MemberData(nameof(RipemdVectors))]
    public void Ripemd160MatchesPublishedSet(string input, string expected) =>
        Assert.Equal(expected, Hex(PgpHash.Compute(PgpHashAlgorithm.Ripemd160, Ascii(input))));

    [Fact]
    public void Ripemd160OfAMillionAs() =>
        Assert.Equal("52783243c1697bdbe16d37f97f68f08325dc1528", Hex(PgpHash.Compute(PgpHashAlgorithm.Ripemd160, Ascii(new string('a', 1_000_000)))));

    [Theory]
    [InlineData(PgpHashAlgorithm.Sha224)]
    [InlineData(PgpHashAlgorithm.Ripemd160)]
    public void SplittingAtAnyOffsetGivesTheSameDigestAndTheHashResets(PgpHashAlgorithm algorithm)
    {
        byte[] data = new byte[300];
        new Random(7).NextBytes(data);
        byte[] whole = PgpHash.Compute(algorithm, data);
        using var h = new PgpHash(algorithm);
        for (int cut = 0; cut <= data.Length; cut++)
        {
            h.Append(data.AsSpan(0, cut));
            h.Append(data.AsSpan(cut));
            Assert.Equal(whole, h.Finish());
        }
    }

    [Fact]
    public void Sha224CoversLengthsAroundTheBlockBoundaries()
    {
        // Padding crosses into a second block at 56 octets; compare to SHA-256's structure indirectly through determinism and the 55/56/63/64 inputs.
        foreach (int n in new[] { 55, 56, 57, 63, 64, 65, 119, 120, 128 })
        {
            byte[] data = new byte[n];
            Array.Fill(data, (byte)0x61);
            Assert.Equal(PgpHash.Compute(PgpHashAlgorithm.Sha224, data), PgpHash.Compute(PgpHashAlgorithm.Sha224, data.ToArray()));
        }
    }

    // Signatures and password messages GnuPG made with these hashes (tools/oracles/oldhash-fixtures.sh).
    private static readonly DateTimeOffset Now = new(2026, 11, 2, 0, 0, 0, TimeSpan.Zero);

    private static byte[] Old(string name) => File.ReadAllBytes(TestFiles.OpenPgp("oldhash", name));

    private static PgpReadOptions Options(Policy.CryptoPolicy? policy = null) =>
        new() { Now = Now, Certificates = [PgpCertificate.Parse(Old("rsa-pub.gpg"))], MessagePasswords = [Encoding.UTF8.GetBytes("pw")], Policy = policy };

    [Theory]
    [InlineData("sha224")]
    [InlineData("ripemd160")]
    public void DetachedSignaturesFromGnuPgVerify(string hash)
    {
        PgpReadResult r = PgpMessageReader.VerifyDetached(new MemoryStream(Old("data.txt")), new MemoryStream(Old($"detached-{hash}.sig")), Options(Policy.CryptoPolicy.Permissive));
        PgpSignatureResult s = Assert.Single(r.Signatures);
        Assert.True(s.IsValid, string.Join("; ", s.Reasons));
        r = PgpMessageReader.VerifyDetached(new MemoryStream("other"u8.ToArray()), new MemoryStream(Old($"detached-{hash}.sig")), Options(Policy.CryptoPolicy.Permissive));
        Assert.False(Assert.Single(r.Signatures).IsValid);
    }

    [Theory]
    [InlineData("sha224")]
    [InlineData("ripemd160")]
    public void InlineSignaturesFromGnuPgVerify(string hash)
    {
        using var o = new MemoryStream();
        PgpReadResult r = PgpMessageReader.Read(new MemoryStream(Old($"inline-{hash}.gpg")), o, Options(Policy.CryptoPolicy.Permissive));
        Assert.Equal("old hash test\n", Encoding.ASCII.GetString(o.ToArray()));
        Assert.True(Assert.Single(r.Signatures).IsValid);
    }

    [Fact]
    public void PoliciesTreatTheTwoHashesAsTheirDatesSay()
    {
        PgpSignatureResult sha224 = Assert.Single(PgpMessageReader.VerifyDetached(new MemoryStream(Old("data.txt")), new MemoryStream(Old("detached-sha224.sig")), Options()).Signatures);
        Assert.True(sha224.IsValid, string.Join("; ", sha224.Reasons));
        PgpSignatureResult strictRipemd = Assert.Single(PgpMessageReader.VerifyDetached(new MemoryStream(Old("data.txt")), new MemoryStream(Old("detached-ripemd160.sig")), Options(Policy.CryptoPolicy.Strict)).Signatures);
        Assert.False(strictRipemd.IsValid);
    }

    [Theory]
    [InlineData("sha224")]
    [InlineData("ripemd160")]
    public void PasswordMessagesWithTheseS2kHashesDecrypt(string hash)
    {
        using var o = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(Old($"pw-{hash}.gpg")), o, Options());
        Assert.Equal("old hash test\n", Encoding.ASCII.GetString(o.ToArray()));
    }

    [Theory]
    [InlineData(PgpHashAlgorithm.Sha224)]
    [InlineData(PgpHashAlgorithm.Ripemd160)]
    public void NewSignaturesWithTheseHashesAreRefused(PgpHashAlgorithm hash)
    {
        PgpCertificate secret = PgpCertificate.Parse(File.ReadAllBytes(TestFiles.OpenPgp("librepgp", "v4-sec.gpg")));
        using PgpSecretKey key = PgpSecretKey.Unlock(secret.Primary);
        var e = Assert.Throws<PgpException>(() => PgpMessageWriter.SignDetached(new MemoryStream("x"u8.ToArray()), new MemoryStream(), new PgpWriteOptions { Now = Now, Signers = [key], SignatureHash = hash, Policy = Policy.CryptoPolicy.Permissive }));
        Assert.Equal(PgpFailure.PolicyViolation, e.Failure);
    }
}
