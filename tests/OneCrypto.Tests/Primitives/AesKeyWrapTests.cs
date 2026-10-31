using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Primitives;

public class AesKeyWrapTests
{
    // RFC 3394 §4.1 to §4.6.
    public static IEnumerable<object[]> Rfc3394() =>
    [
        ["000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"],
        ["000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"],
        ["000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"],
        ["000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607", "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"],
        ["000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607", "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"],
        ["000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"],
    ];

    [Theory]
    [MemberData(nameof(Rfc3394))]
    public void Rfc3394Vector(string kek, string keyData, string expected)
    {
        using var kw = new AesKeyWrap(Hex.Decode(kek));
        byte[] data = Hex.Decode(keyData);
        byte[] wrapped = new byte[data.Length + 8];
        kw.Wrap(data, wrapped);
        Assert.Equal(expected, Hex.Encode(wrapped));
        byte[] back = new byte[data.Length];
        kw.Unwrap(wrapped, back);
        Assert.Equal(data, back);
    }

    [Fact]
    public void TamperingFailsAndReleasesNothing()
    {
        using var kw = new AesKeyWrap(RandomNumberGenerator.GetBytes(32));
        byte[] data = RandomNumberGenerator.GetBytes(32);
        byte[] wrapped = new byte[40];
        kw.Wrap(data, wrapped);
        for (int i = 0; i < wrapped.Length; i++)
        {
            byte[] bad = (byte[])wrapped.Clone();
            bad[i] ^= 0x10;
            byte[] output = Enumerable.Repeat((byte)0xEE, 32).ToArray();
            Assert.Throws<AuthenticationTagMismatchException>(() => kw.Unwrap(bad, output));
            Assert.All(output, b => Assert.Equal(0, b));
        }
    }

    [Fact]
    public void ArgumentsAreChecked()
    {
        using var kw = new AesKeyWrap(new byte[16]);
        Assert.Throws<ArgumentException>(() => new AesKeyWrap(new byte[20]));
        Assert.Throws<ArgumentException>(() => kw.Wrap(new byte[8], new byte[16]));
        Assert.Throws<ArgumentException>(() => kw.Wrap(new byte[20], new byte[28]));
        Assert.Throws<ArgumentException>(() => kw.Wrap(new byte[16], new byte[16]));
        Assert.Throws<ArgumentException>(() => kw.TryUnwrap(new byte[16], new byte[8]));
        Assert.Throws<ArgumentException>(() => kw.TryUnwrap(new byte[28], new byte[20]));
        byte[] buffer = new byte[40];
        Assert.Throws<ArgumentException>(() => kw.Wrap(buffer.AsSpan(0, 16), buffer.AsSpan(8, 24)));
    }
}
