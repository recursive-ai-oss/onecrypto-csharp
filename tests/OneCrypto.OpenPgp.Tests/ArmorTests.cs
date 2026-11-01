using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

public class ArmorTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(47)]
    [InlineData(48)]
    [InlineData(1000)]
    public void EncodeThenDecodeRoundTrips(int length)
    {
        byte[] data = Enumerable.Range(0, length).Select(i => (byte)(i * 7 + 3)).ToArray();
        foreach (bool checksum in new[] { false, true })
        {
            string text = Armor.Encode(ArmorKind.PublicKey, data, new ArmorWriteOptions { Checksum = checksum });
            ArmorBlock block = Armor.Decode(Encoding.ASCII.GetBytes(text));
            Assert.Equal(data, block.Data);
            Assert.Equal(ArmorKind.PublicKey, block.Kind);
            Assert.Equal(checksum, block.HasChecksum);
            Assert.All(text.Split('\n'), l => Assert.True(l.Length <= 64 || l.StartsWith("-----", StringComparison.Ordinal)));
        }
    }

    [Fact]
    public void HeadersAreKeptInOrder()
    {
        var headers = new[] { new KeyValuePair<string, string>("Comment", "one"), new KeyValuePair<string, string>("Comment", "two"), new KeyValuePair<string, string>("Version", "x y") };
        string text = Armor.Encode("PGP MESSAGE", [1, 2, 3], new ArmorWriteOptions { Headers = headers });
        ArmorBlock block = Armor.Decode(Encoding.ASCII.GetBytes(text));
        Assert.Equal(headers, block.Headers);
    }

    [Fact]
    public void TheChecksumIsTheCrc24OfTheData()
    {
        // CRC-24 of "123456789" under the OpenPGP parameters is 0x21CF02.
        Assert.Equal(0x21CF02u, Armor.Crc24(Armor.Crc24Init, "123456789"u8));
    }

    [Fact]
    public void AWrongChecksumIsRejectedAndAMissingOneIsFine()
    {
        string good = Armor.Encode(ArmorKind.Message, "hello world"u8, new ArmorWriteOptions { Checksum = true });
        string[] lines = good.TrimEnd('\n').Split('\n');
        int crc = Array.FindIndex(lines, l => l.StartsWith('=') && !l.StartsWith("-----", StringComparison.Ordinal));
        lines[crc] = "=AAAA";
        var e = Assert.Throws<OpenPgpParseException>(() => Armor.Decode(Encoding.ASCII.GetBytes(string.Join('\n', lines) + "\n")));
        Assert.Equal(OpenPgpError.BadArmorChecksum, e.Error);
        string noCrc = string.Join('\n', lines.Where((_, i) => i != crc)) + "\n";
        Assert.Equal("hello world"u8.ToArray(), Armor.Decode(Encoding.ASCII.GetBytes(noCrc)).Data);
    }

    [Theory]
    [InlineData("no armor at all\n")]
    [InlineData("-----BEGIN PGP MESSAGE-----\n\nAAAA\n")]
    [InlineData("-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n")]
    [InlineData("-----BEGIN PGP MESSAGE-----\n\nAA*A\n-----END PGP MESSAGE-----\n")]
    [InlineData("-----BEGIN PGP MESSAGE-----\n\nA\n-----END PGP MESSAGE-----\n")]
    [InlineData("-----BEGIN PGP MESSAGE-----\nnot a header\n\nAAAA\n-----END PGP MESSAGE-----\n")]
    [InlineData("-----BEGIN PGP SIGNED MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----\n")]
    public void MalformedArmorRaisesATypedError(string text)
    {
        Assert.Throws<OpenPgpParseException>(() => Armor.Decode(Encoding.ASCII.GetBytes(text)));
        Assert.False(Armor.TryDecode(Encoding.ASCII.GetBytes(text), out ArmorBlock? block, out _));
        Assert.Null(block);
    }

    [Fact]
    public void StrictReadingRejectsLeadingTextLongLinesAndTrailingData()
    {
        string good = Armor.Encode(ArmorKind.Message, new byte[100]);
        byte[] Bytes(string s) => Encoding.ASCII.GetBytes(s);
        Assert.NotNull(Armor.Decode(Bytes(good), ArmorReadOptions.Strict));
        Assert.NotNull(Armor.Decode(Bytes(good + "  \n\n"), ArmorReadOptions.Strict));
        Assert.Throws<OpenPgpParseException>(() => Armor.Decode(Bytes("text\n" + good), ArmorReadOptions.Strict));
        Assert.Throws<OpenPgpParseException>(() => Armor.Decode(Bytes(good + "more\n"), ArmorReadOptions.Strict));
        Assert.NotNull(Armor.Decode(Bytes("text\n" + good + "more\n")));
        string wide = Armor.Encode("PGP MESSAGE", new byte[100], new ArmorWriteOptions { LineLength = 76 }).Replace("\n", string.Empty, StringComparison.Ordinal);
        _ = wide;
        string longLine = "-----BEGIN PGP MESSAGE-----\n\n" + new string('A', 80) + "\n-----END PGP MESSAGE-----\n";
        Assert.Throws<OpenPgpParseException>(() => Armor.Decode(Bytes(longLine), ArmorReadOptions.Strict));
        Assert.Equal(60, Armor.Decode(Bytes(longLine)).Data.Length);
    }

    [Fact]
    public void CrlfLineEndsAndOddWrappingAreRead()
    {
        string text = Armor.Encode(ArmorKind.Message, Enumerable.Range(0, 200).Select(i => (byte)i).ToArray());
        string crlf = text.Replace("\n", "\r\n", StringComparison.Ordinal);
        Assert.Equal(200, Armor.Decode(Encoding.ASCII.GetBytes(crlf)).Data.Length);
        string[] lines = text.Split('\n');
        string rewrapped = string.Join('\n', lines[..3]) + "\n" + string.Join(string.Empty, lines[3..^3]).Insert(10, "\n") + "\n" + string.Join('\n', lines[^3..]);
        Assert.Equal(200, Armor.Decode(Encoding.ASCII.GetBytes(rewrapped)).Data.Length);
    }

    [Fact]
    public void StreamingDecodeAndEncodeWorkInSmallPieces()
    {
        byte[] data = Enumerable.Range(0, 100_000).Select(i => (byte)(i ^ (i >> 8))).ToArray();
        using var ms = new MemoryStream();
        using (var w = new ArmorWriteStream(ms, "PGP MESSAGE", new ArmorWriteOptions { Checksum = true }))
        {
            for (int i = 0; i < data.Length; i += 777)
            {
                w.Write(data, i, Math.Min(777, data.Length - i));
            }
        }

        ms.Position = 0;
        using var r = new ArmorReadStream(ms);
        using var outMs = new MemoryStream();
        r.CopyTo(outMs);
        Assert.Equal(data, outMs.ToArray());
        Assert.True(r.HasChecksum);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(48)]
    [InlineData(300)]
    public void DefaultArmorHasTheCrcEvenWhenTheLengthIsAMultipleOfThree(int length)
    {
        // GnuPG 2.4/2.5 reject armor with neither padding nor a CRC line, which is what a length divisible by 3 gives.
        byte[] data = Enumerable.Range(0, length).Select(i => (byte)(i * 11 + 1)).ToArray();
        string text = Armor.Encode(ArmorKind.Message, data);
        Assert.DoesNotContain("=\n", text.Replace("\r", ""), StringComparison.Ordinal);
        string[] lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Matches("^=[A-Za-z0-9+/]{4}$", lines[^2]);
        Assert.True(Armor.Decode(Encoding.ASCII.GetBytes(text)).HasChecksum);
    }
}
