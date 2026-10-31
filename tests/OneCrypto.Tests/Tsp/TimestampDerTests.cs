using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Cms;

namespace OneCrypto.Tests.Tsp;

public class TimestampDerTests
{
    // Writes the first <levels> nested constructed levels of a DER encoding with indefinite lengths, as some authorities do.
    private static byte[] Indefinite(byte[] der, int levels)
    {
        Assert.True(Asn1Element.TryRead(der, out Asn1Element e, out _, out _));
        if (levels == 0 || !e.Constructed)
        {
            return der;
        }

        var kids = new List<Asn1Element>();
        Assert.True(Asn1Element.TryChildren(e, 1000, kids, out _));
        var body = new List<byte> { der[0], 0x80 };
        for (int i = 0; i < kids.Count; i++)
        {
            // Only the content-carrying first-child chain is made indefinite; siblings are copied as they were.
            body.AddRange(i == kids.Count - 1 ? Indefinite(kids[i].Encoded.ToArray(), levels - 1) : kids[i].Encoded.ToArray());
        }

        body.Add(0);
        body.Add(0);
        return body.ToArray();
    }

    [Fact]
    public void ConstructedOctetStringsAndIndefiniteLengthsBecomeDefinite()
    {
        byte[] piece1 = [0x04, 0x02, 1, 2];
        byte[] piece2 = [0x04, 0x01, 3];
        // SEQUENCE (indefinite) { OCTET STRING (indefinite) { piece1, piece2 }, SET { 05 00, 02 01 07 } (definite, deliberately not sorted) }
        byte[] set = [0x31, 0x05, 0x05, 0x00, 0x02, 0x01, 0x07];
        byte[] ber = [0x30, 0x80, 0x24, 0x80, .. piece1, .. piece2, 0, 0, .. set, 0, 0];
        Assert.True(BerToDer.TryConvert(ber, out byte[] der));
        byte[] expected = [0x30, 0x0C, 0x04, 0x03, 1, 2, 3, .. set];
        Assert.Equal(expected, der);
    }

    [Fact]
    public void DefiniteInputIsReturnedUnchanged()
    {
        byte[] input = Der.Seq(Der.Int(5), Der.Oct([1, 2, 3]));
        Assert.True(BerToDer.TryConvert(input, out byte[] same));
        Assert.Equal(input, same);
    }

    [Fact]
    public void TruncatedAndTrailingInputIsRefused()
    {
        Assert.False(BerToDer.TryConvert(new byte[] { 0x30, 0x80, 0x02, 0x01, 0x05 }, out _));
        Assert.False(BerToDer.TryConvert(new byte[] { 0x02, 0x01, 0x05, 0x00 }, out _));
        Assert.False(BerToDer.TryConvert(new byte[] { 0x30, 0x05, 0x02 }, out _));
    }

    [Fact]
    public void TokenWithIndefiniteLengthsIsEmbeddedAsDerAndTheSignatureStaysValid()
    {
        var tsa = new CmsFixture.TestTsa { BareToken = true };
        byte[] seen = [];
        byte[] Callback(CmsTimestampRequest r)
        {
            byte[] der = tsa.Answer(r);
            seen = der;
            return Indefinite(der, 3);
        }

        var signer = CmsSigner.Create(CmsFixture.Credential(TestPki.Shared.RsaSigner), HashAlgorithmName.SHA256, CmsRsaPadding.Pkcs1, cades: true);
        byte[] digest = CryptographicOperations.HashData(HashAlgorithmName.SHA256, CmsFixture.Content);
        byte[] cms = signer.Build(digest, DateTimeOffset.UtcNow, Callback, CancellationToken.None);
        Assert.NotEqual(seen, Indefinite(seen, 3));
        CmsSignerResult v = CmsFixture.VerifyOne(cms);
        Assert.True(v.IsValid, CmsFixture.WarningsOf(v));
        Assert.NotNull(v.Timestamp);

        // The embedded SignedData holds the token as definite-length DER: the stamped bytes are found verbatim.
        Assert.Contains(Convert.ToHexString(seen), Convert.ToHexString(cms), StringComparison.OrdinalIgnoreCase);
    }
}
