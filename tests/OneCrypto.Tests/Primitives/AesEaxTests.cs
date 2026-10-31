using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

public class AesEaxTests
{
    public static IEnumerable<object[]> PaperVectors() =>
        File.ReadLines(Path.Combine(TestFiles.TestData, "vectors", "eax-bellare-rogaway-wagner.txt"))
            .Where(l => !l.StartsWith('#'))
            .Select(l => new object[] { l });

    // Appendix G of the EAX paper.
    [Theory]
    [MemberData(nameof(PaperVectors))]
    public void PaperVector(string line)
    {
        string[] f = line.Split(' ');
        byte[] plaintext = Hex.Decode(f[0]);
        byte[] expected = Hex.Decode(f[4]);
        using var eax = new AesEax(Hex.Decode(f[1]));
        byte[] nonce = Hex.Decode(f[2]);
        byte[] header = Hex.Decode(f[3]);
        byte[] ct = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        eax.Encrypt(nonce, plaintext, ct, tag, header);
        Assert.Equal(Hex.Encode(expected), Hex.Encode([.. ct, .. tag]));
        byte[] back = new byte[plaintext.Length];
        eax.Decrypt(nonce, ct, tag, back, header);
        Assert.Equal(plaintext, back);
    }

    // An independent, block-at-a-time EAX built straight from the paper's Figure 1 and Figure 2, used to check the batched code across
    // every boundary of its internal buffers.
    private static byte[] ReferenceEax(byte[] key, byte[] nonce, byte[] header, byte[] message, int tagSize, out byte[] tag)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;

        byte[] E(byte[] block) => aes.EncryptEcb(block, PaddingMode.None);

        static byte[] Dbl(byte[] x)
        {
            byte[] r = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                r[i] = (byte)((x[i] << 1) | (i < 15 ? x[i + 1] >> 7 : 0));
            }

            if ((x[0] & 0x80) != 0)
            {
                r[15] ^= 0x87;
            }

            return r;
        }

        byte[] l = E(new byte[16]);
        byte[] b = Dbl(l);
        byte[] p = Dbl(b);

        byte[] Omac(byte t, byte[] m)
        {
            byte[] input = [.. new byte[15], t, .. m];
            int blocks = Math.Max(1, (input.Length + 15) / 16);
            byte[] state = new byte[16];
            for (int i = 0; i < blocks; i++)
            {
                byte[] block = new byte[16];
                int start = i * 16;
                int len = Math.Min(16, input.Length - start);
                Array.Copy(input, start, block, 0, len);
                if (i == blocks - 1)
                {
                    if (len == 16)
                    {
                        for (int k = 0; k < 16; k++) { block[k] ^= b[k]; }
                    }
                    else
                    {
                        block[len] = 0x80;
                        for (int k = 0; k < 16; k++) { block[k] ^= p[k]; }
                    }
                }

                for (int k = 0; k < 16; k++) { block[k] ^= state[k]; }
                state = E(block);
            }

            return state;
        }

        byte[] n = Omac(0, nonce);
        byte[] h = Omac(1, header);
        byte[] counter = (byte[])n.Clone();
        byte[] c = new byte[message.Length];
        for (int i = 0; i < message.Length; i += 16)
        {
            byte[] ks = E(counter);
            for (int k = 0; k < 16 && i + k < message.Length; k++)
            {
                c[i + k] = (byte)(message[i + k] ^ ks[k]);
            }

            for (int k = 15; k >= 0; k--)
            {
                if (++counter[k] != 0)
                {
                    break;
                }
            }
        }

        byte[] cm = Omac(2, c);
        tag = new byte[tagSize];
        for (int k = 0; k < tagSize; k++)
        {
            tag[k] = (byte)(n[k] ^ h[k] ^ cm[k]);
        }

        return c;
    }

    [Theory]
    [InlineData(16, 16)]
    [InlineData(24, 12)]
    [InlineData(32, 8)]
    public void MatchesTheReferenceAcrossBufferBoundaries(int keySize, int tagSize)
    {
        byte[] key = RandomNumberGenerator.GetBytes(keySize);
        using var eax = new AesEax(key, tagSize);
        int[] lengths = [0, 1, 15, 16, 17, 31, 32, 2015, 2016, 2017, 2031, 2032, 2033, 2047, 2048, 2049, 4095, 4096, 4097, 5000];
        foreach (int nonceLength in new[] { 0, 1, 12, 16, 2031, 2032, 2033 })
        {
            foreach (int dataLength in lengths)
            {
                byte[] nonce = RandomNumberGenerator.GetBytes(nonceLength);
                byte[] header = RandomNumberGenerator.GetBytes(lengths[(dataLength + nonceLength) % lengths.Length]);
                byte[] message = RandomNumberGenerator.GetBytes(dataLength);
                byte[] expectedCt = ReferenceEax(key, nonce, header, message, tagSize, out byte[] expectedTag);

                byte[] ct = new byte[dataLength];
                byte[] tag = new byte[tagSize];
                eax.Encrypt(nonce, message, ct, tag, header);
                Assert.Equal(expectedCt, ct);
                Assert.Equal(expectedTag, tag);

                byte[] inPlace = (byte[])message.Clone();
                eax.Encrypt(nonce, inPlace, inPlace, tag, header);
                Assert.Equal(expectedCt, inPlace);
                eax.Decrypt(nonce, inPlace, expectedTag, inPlace, header);
                Assert.Equal(message, inPlace);
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
        using var eax = new AesEax(key);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] aad = RandomNumberGenerator.GetBytes(20);
        byte[] plaintext = RandomNumberGenerator.GetBytes(dataLength);
        byte[] ct = new byte[dataLength];
        byte[] tag = new byte[16];
        eax.Encrypt(nonce, plaintext, ct, tag, aad);

        void Expect(byte[] n, byte[] c, byte[] t, byte[] a)
        {
            byte[] output = Enumerable.Repeat((byte)0xEE, dataLength).ToArray();
            Assert.Throws<AuthenticationTagMismatchException>(() => eax.Decrypt(n, c, t, output, a));
            Assert.All(output, b => Assert.Equal(0, b));
            Assert.False(eax.TryDecrypt(n, c, t, output, a));
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
        Expect(nonce[..^1], ct, tag, aad);
    }

    [Fact]
    public void ArgumentsAreChecked()
    {
        Assert.Throws<ArgumentException>(() => new AesEax(new byte[17]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AesEax(new byte[16], 7));
        var eax = new AesEax(new byte[16]);
        byte[] tag = new byte[16];
        Assert.Throws<ArgumentException>(() => eax.Encrypt(new byte[12], new byte[3], new byte[4], tag));
        Assert.Throws<ArgumentException>(() => eax.Encrypt(new byte[12], new byte[3], new byte[3], new byte[15]));
        byte[] buffer = new byte[64];
        Assert.Throws<ArgumentException>(() => eax.Encrypt(new byte[12], buffer.AsSpan(0, 40), buffer.AsSpan(8, 40), tag));
        eax.Dispose();
        Assert.Throws<ObjectDisposedException>(() => eax.Encrypt(new byte[12], new byte[3], new byte[3], tag));
    }
}
