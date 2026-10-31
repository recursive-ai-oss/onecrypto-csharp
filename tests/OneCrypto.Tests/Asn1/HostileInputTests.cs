using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Cms;

namespace OneCrypto.Tests.Asn1;

/// <summary>Hostile ASN.1 and CMS input: deep nesting, huge lengths, indefinite-length bombs. Typed results, never exceptions.</summary>
public class HostileInputTests
{
    [Fact]
    public void DeeplyNestedIndefiniteLengthsAreRefused()
    {
        byte[] data = new byte[200_000];
        for (int i = 0; i < data.Length; i += 2)
        {
            data[i] = 0x30;
            data[i + 1] = 0x80;
        }

        Assert.False(Asn1Element.TryRead(data, out _, out _, out string? error));
        Assert.NotNull(error);
        Assert.False(CmsSignedData.TryParse(data, out _, out _));
    }

    [Theory]
    [InlineData(new byte[] { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF })]
    [InlineData(new byte[] { 0x30, 0x85, 1, 0, 0, 0, 0 })]
    [InlineData(new byte[] { 0x04, 0x82, 0x7F, 0xFF, 1 })]
    [InlineData(new byte[] { 0x30, 0x80, 0x04, 0x01, 0x00 })]
    [InlineData(new byte[] { 0x04, 0x80, 0, 0 })]
    [InlineData(new byte[] { 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00 })]
    [InlineData(new byte[] { 0x30 })]
    [InlineData(new byte[] { })]
    public void MalformedElementsFailWithoutAllocatingOrThrowing(byte[] data)
    {
        Assert.False(Asn1Element.TryRead(data, out _, out _, out _));
        Assert.False(CmsSignedData.TryParse(data, out _, out _));
    }

    [Fact]
    public void ManyShallowSiblingsInsideAnIndefiniteElementStayLinear()
    {
        var data = new List<byte> { 0x30, 0x80 };
        for (int i = 0; i < 300_000; i++)
        {
            data.AddRange([0x05, 0x00]);
        }

        data.AddRange([0, 0]);
        Assert.True(Asn1Element.TryRead(data.ToArray(), out Asn1Element e, out int used, out _));
        Assert.Equal(data.Count, used);
        Assert.False(Asn1Element.TryChildren(e, 1000, [], out _));
    }

    [Fact]
    public void ObjectIdentifiersAndTimesAreValidated()
    {
        Assert.True(Asn1Element.TryRead(new byte[] { 6, 3, 0x2A, 0x03, 0x04 }, out Asn1Element oid, out _, out _));
        Assert.Equal("1.2.3.4", Asn1Values.TryOid(oid));
        Assert.True(Asn1Element.TryRead(new byte[] { 6, 11, 0x2A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F }, out Asn1Element big, out _, out _));
        Assert.Null(Asn1Values.TryOid(big));
        Assert.True(Asn1Element.TryRead(System.Text.Encoding.ASCII.GetBytes("\u0018\u000f20260102030405Z"), out Asn1Element t, out _, out _));
        Assert.True(Asn1Values.TryTime(t, out DateTimeOffset when));
        Assert.Equal(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero), when);
        Assert.True(Asn1Element.TryRead(System.Text.Encoding.ASCII.GetBytes("\u0018\u000f20261302030405Z"), out Asn1Element badMonth, out _, out _));
        Assert.False(Asn1Values.TryTime(badMonth, out _));
    }
}
