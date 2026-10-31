using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

public class AesOcbTests
{
    private static IEnumerable<string[]> VectorLines(string prefix) =>
        File.ReadLines(Path.Combine(TestFiles.TestData, "vectors", "rfc7253-ocb.txt"))
            .Where(l => l.StartsWith(prefix, StringComparison.Ordinal))
            .Select(l => l.Split(' '));

    public static IEnumerable<object[]> SampleResults() => VectorLines("rfc7253-").Select(f => new object[] { f[0] });

    // RFC 7253 Appendix A: the 16 sample tuples (128-bit tag) and the 96-bit-tag tuple.
    [Theory]
    [MemberData(nameof(SampleResults))]
    public void RfcSampleResult(string name)
    {
        string[] f = VectorLines(name + " ").Single();
        byte[] key = Hex.Decode(f[1]);
        int tagSize = int.Parse(f[2]) / 8;
        byte[] nonce = Hex.Decode(f[3]);
        byte[] aad = Hex.Decode(f[4]);
        byte[] plaintext = Hex.Decode(f[5]);
        byte[] expected = Hex.Decode(f[6]);

        using var ocb = new AesOcb(key, tagSize);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[tagSize];
        ocb.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        Assert.Equal(Hex.Encode(expected), Hex.Encode([.. ciphertext, .. tag]));

        byte[] decrypted = new byte[plaintext.Length];
        ocb.Decrypt(nonce, ciphertext, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }

    public static IEnumerable<object[]> IteratedResults() => VectorLines("iter ").Select(f => new object[] { int.Parse(f[1]), int.Parse(f[2]), f[3] });

    // RFC 7253 Appendix A: the iterated test over many lengths, for each key size and tag length given.
    [Theory]
    [MemberData(nameof(IteratedResults))]
    public void RfcIteratedTest(int keyBits, int tagBits, string expected)
    {
        byte[] key = new byte[keyBits / 8];
        key[^1] = (byte)tagBits;
        int tagSize = tagBits / 8;
        using var ocb = new AesOcb(key, tagSize);
        var c = new List<byte>();

        static byte[] Nonce(int n)
        {
            byte[] nonce = new byte[12];
            nonce[11] = (byte)n;
            nonce[10] = (byte)(n >> 8);
            return nonce;
        }

        void Add(int n, byte[] aad, byte[] plaintext)
        {
            byte[] ct = new byte[plaintext.Length];
            byte[] tag = new byte[tagSize];
            ocb.Encrypt(Nonce(n), plaintext, ct, tag, aad);
            c.AddRange(ct);
            c.AddRange(tag);
        }

        for (int i = 0; i < 128; i++)
        {
            byte[] s = new byte[i];
            Add((3 * i) + 1, s, s);
            Add((3 * i) + 2, [], s);
            Add((3 * i) + 3, s, []);
        }

        byte[] finalTag = new byte[tagSize];
        ocb.Encrypt(Nonce(385), [], [], finalTag, c.ToArray());
        Assert.Equal(expected, Hex.Encode(finalTag));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void RoundTripsEveryLengthAcrossTheBatchBoundary(int keySize)
    {
        byte[] key = RandomNumberGenerator.GetBytes(keySize);
        using var ocb = new AesOcb(key);
        byte[] nonce = RandomNumberGenerator.GetBytes(15);
        int[] lengths = [0, 1, 15, 16, 17, 31, 32, 33, 2031, 2032, 2033, 2047, 2048, 2049, 2064, 4095, 4096, 4097, 6000];
        foreach (int dataLength in lengths)
        {
            foreach (int aadLength in new[] { 0, 1, 16, 2047, 2048, 2049, 4100 })
            {
                byte[] plaintext = RandomNumberGenerator.GetBytes(dataLength);
                byte[] aad = RandomNumberGenerator.GetBytes(aadLength);
                byte[] ct = new byte[dataLength];
                byte[] tag = new byte[16];
                ocb.Encrypt(nonce, plaintext, ct, tag, aad);

                byte[] pt = new byte[dataLength];
                ocb.Decrypt(nonce, ct, tag, pt, aad);
                Assert.Equal(plaintext, pt);

                byte[] inPlace = (byte[])plaintext.Clone();
                byte[] tag2 = new byte[16];
                ocb.Encrypt(nonce, inPlace, inPlace, tag2, aad);
                Assert.Equal(ct, inPlace);
                Assert.Equal(tag, tag2);
                ocb.Decrypt(nonce, inPlace, tag2, inPlace, aad);
                Assert.Equal(plaintext, inPlace);
            }
        }
    }

    [Fact]
    public void NonceAndTagLengthsAreBoundIntoTheResult()
    {
        byte[] key = new byte[16];
        byte[] plaintext = new byte[40];
        var seen = new HashSet<string>();
        for (int nonceSize = 1; nonceSize <= 15; nonceSize++)
        {
            for (int tagSize = 8; tagSize <= 16; tagSize++)
            {
                using var ocb = new AesOcb(key, tagSize);
                byte[] nonce = new byte[nonceSize];
                byte[] ct = new byte[40];
                byte[] tag = new byte[tagSize];
                ocb.Encrypt(nonce, plaintext, ct, tag);
                Assert.True(seen.Add(Hex.Encode(ct) + Hex.Encode(tag)), "each (nonce size, tag size) pair gives a distinct result");
                byte[] pt = new byte[40];
                ocb.Decrypt(nonce, ct, tag, pt);
                Assert.Equal(plaintext, pt);
            }
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(17)]
    [InlineData(33)]
    public void AnyTamperingFailsAndReleasesNoPlaintext(int dataLength)
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        using var ocb = new AesOcb(key);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] aad = RandomNumberGenerator.GetBytes(20);
        byte[] plaintext = RandomNumberGenerator.GetBytes(dataLength);
        byte[] ct = new byte[dataLength];
        byte[] tag = new byte[16];
        ocb.Encrypt(nonce, plaintext, ct, tag, aad);

        void Expect(byte[] n, byte[] c, byte[] t, byte[] a)
        {
            byte[] output = Enumerable.Repeat((byte)0xEE, dataLength).ToArray();
            Assert.Throws<AuthenticationTagMismatchException>(() => ocb.Decrypt(n, c, t, output, a));
            Assert.All(output, b => Assert.Equal(0, b));
            Assert.False(ocb.TryDecrypt(n, c, t, output, a));
        }

        for (int i = 0; i < 16; i++)
        {
            byte[] t = (byte[])tag.Clone();
            t[i] ^= 0x01;
            Expect(nonce, ct, t, aad);
        }

        for (int i = 0; i < dataLength; i++)
        {
            byte[] c = (byte[])ct.Clone();
            c[i] ^= 0x80;
            Expect(nonce, c, tag, aad);
        }

        for (int i = 0; i < aad.Length; i++)
        {
            byte[] a = (byte[])aad.Clone();
            a[i] ^= 0x04;
            Expect(nonce, ct, tag, a);
        }

        Expect(nonce, ct, tag, aad[..^1]);
        Expect(nonce, ct, tag, [.. aad, 0]);
        byte[] n2 = (byte[])nonce.Clone();
        n2[^1] ^= 1;
        Expect(n2, ct, tag, aad);
        Expect(nonce[..^1], ct, tag, aad);
    }

    [Fact]
    public void ArgumentsAreChecked()
    {
        Assert.Throws<ArgumentException>(() => new AesOcb(new byte[15]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AesOcb(new byte[16], 7));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AesOcb(new byte[16], 17));
        var ocb = new AesOcb(new byte[16]);
        byte[] tag = new byte[16];
        Assert.Throws<ArgumentException>(() => ocb.Encrypt(Array.Empty<byte>(), new byte[3], new byte[3], tag));
        Assert.Throws<ArgumentException>(() => ocb.Encrypt(new byte[16], new byte[3], new byte[3], tag));
        Assert.Throws<ArgumentException>(() => ocb.Encrypt(new byte[12], new byte[3], new byte[4], tag));
        Assert.Throws<ArgumentException>(() => ocb.Encrypt(new byte[12], new byte[3], new byte[3], new byte[15]));
        byte[] buffer = new byte[64];
        Assert.Throws<ArgumentException>(() => ocb.Encrypt(new byte[12], buffer.AsSpan(0, 40), buffer.AsSpan(8, 40), tag));
        ocb.Dispose();
        ocb.Dispose();
        Assert.Throws<ObjectDisposedException>(() => ocb.Encrypt(new byte[12], new byte[3], new byte[3], tag));
    }
}
