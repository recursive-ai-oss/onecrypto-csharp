using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Cms;
using RecursiveAI.OneCrypto.Tsp;

namespace OneCrypto.Tests.Asn1;

public class DerWriterTests
{
    [Theory]
    [InlineData("1.2.840.113549.1.9.16.2.47")]
    [InlineData("2.5.29.14")]
    [InlineData("1.3.6.1.5.5.7.3.8")]
    [InlineData("2.100.3")]
    [InlineData("1.2.840.113583.1.1.8")]
    public void ObjectIdentifiersRoundTripThroughTheReader(string oid)
    {
        Assert.True(Asn1Element.TryRead(DerWriter.Oid(oid), out Asn1Element e, out _, out _));
        Assert.Equal(oid, Asn1Values.TryOid(e));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(65535)]
    [InlineData(65536)]
    [InlineData(1 << 24)]
    public void LengthsOfEveryWidthAreReadBack(int size)
    {
        byte[] encoded = DerWriter.OctetString(new byte[size]);
        Assert.True(Asn1Element.TryRead(encoded, out Asn1Element e, out int used, out _));
        Assert.Equal(encoded.Length, used);
        Assert.Equal(size, e.Content.Length);
        int expectedHeader = size < 128 ? 2 : size < 256 ? 3 : size < 65536 ? 4 : size < (1 << 24) ? 5 : 6;
        Assert.Equal(expectedHeader, encoded.Length - size);
    }

    [Fact]
    public void IntegersAreMinimalTwosComplement()
    {
        Assert.Equal([0x02, 0x01, 0x00], DerWriter.SignedInteger(0));
        Assert.Equal([0x02, 0x01, 0x7F], DerWriter.SignedInteger(127));
        Assert.Equal([0x02, 0x02, 0x00, 0x80], DerWriter.SignedInteger(128));
        Assert.Equal([0x02, 0x01, 0xFF], DerWriter.SignedInteger(-1));
        Assert.Equal([0x02, 0x03, 0x00, 0x80, 0x01], DerWriter.UnsignedInteger([0x00, 0x00, 0x80, 0x01]));
        Assert.Equal([0x02, 0x01, 0x05], DerWriter.UnsignedInteger([0x05]));
        Assert.Equal([0x02, 0x01, 0x00], DerWriter.UnsignedInteger([]));
    }

    [Fact]
    public void SetOfSortsMembersByEncoding()
    {
        byte[] set = DerWriter.SetOf([DerWriter.SignedInteger(300), DerWriter.SignedInteger(2), DerWriter.SignedInteger(1)]);
        Assert.True(Asn1Element.TryRead(set, out Asn1Element e, out _, out _));
        var kids = new List<Asn1Element>();
        Assert.True(Asn1Element.TryChildren(e, 10, kids, out _));
        Assert.Equal([1, 2], kids.Take(2).Select(static k => Asn1Values.TrySmallInt(k)).ToArray());
        Assert.Equal(300, Asn1Values.TrySmallInt(kids[2]));
    }

    [Fact]
    public void BadObjectIdentifiersAreRefused()
    {
        Assert.Throws<ArgumentException>(() => DerWriter.Oid("1"));
        Assert.Throws<ArgumentException>(() => DerWriter.Oid("3.1"));
        Assert.Throws<ArgumentException>(() => DerWriter.Oid("1.40"));
    }

    [Fact]
    public void HostileTimestampResponsesAreRefusedNotThrown()
    {
        byte[] imprint = new byte[32];
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[][] hostile =
        [
            [],
            [0x30],
            [0x30, 0x80],
            [0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            [0x30, 0x03, 0x02, 0x01, 0x00],
            DerWriter.Sequence(DerWriter.Sequence(DerWriter.SignedInteger(0))),
            DerWriter.Sequence(DerWriter.Sequence(DerWriter.SignedInteger(0)), DerWriter.Sequence(DerWriter.Oid(Oids.SignedData), DerWriter.Context(0))),
            DerWriter.Sequence(DerWriter.Oid(Oids.SignedData)),
            new byte[2 << 20],
        ];
        foreach (byte[] data in hostile)
        {
            Assert.False(Rfc3161.TryExtractToken(data, System.Security.Cryptography.HashAlgorithmName.SHA256, imprint, nonce, out _, out string error));
            Assert.NotEmpty(error);
        }
    }
}
