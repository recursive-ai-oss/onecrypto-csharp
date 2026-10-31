using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Tsp;

namespace OneCrypto.Fuzz;

/// <summary>
/// CMS and ASN.1 surface. The first byte picks the mode: bit 1 set with bit 0 clear checks the rest as a time-stamp response against
/// a fixed imprint and nonce; anything else parses the rest as CMS SignedData and verifies every signer over a fixed content
/// (attached, then detached). Nothing may escape: malformed input is reported, not thrown.
/// </summary>
internal static class CmsTarget
{
    private static readonly RecursiveAI.OneCrypto.Wire.Cms.CmsLimits CmsLimits = new() { MaxContentBytes = 1 << 20 };

    private static readonly byte[] FixedImprint = new byte[32];

    private static readonly byte[] FixedNonce = [0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22];

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        if ((data[0] & 3) == 2)
        {
            // A time-stamp authority's answer, as the signing code receives it from its callback.
            _ = Rfc3161.TryExtractToken(rest, HashAlgorithmName.SHA256, FixedImprint, FixedNonce, out _, out _);
            return;
        }

        if (BerToDer.TryConvert(rest, out byte[] der))
        {
            _ = der.Length;
        }

        // Streaming decompression of whatever CompressedData the input happens to be: bounded output, typed errors only.
        var small = new RecursiveAI.OneCrypto.Wire.Cms.CmsLimits { MaxDecompressedBytes = 1 << 20 };
        bool compressedSync = false, compressedAsync = false;
        try
        {
            CompressedData.DecompressStream(new MemoryStream(rest), Stream.Null, small);
            compressedSync = true;
        }
        catch (RecursiveAI.OneCrypto.Wire.Cms.CmsParseException)
        {
        }

        try
        {
            CompressedData.DecompressStreamAsync(new MemoryStream(rest), Stream.Null, small).GetAwaiter().GetResult();
            compressedAsync = true;
        }
        catch (RecursiveAI.OneCrypto.Wire.Cms.CmsParseException)
        {
        }

        if (compressedSync != compressedAsync)
        {
            throw new InvalidOperationException("DecompressStream and DecompressStreamAsync disagree");
        }

        if (SignedData.TryParse(rest, out SignedData? sd, allowTrailingZeros: (data[0] & 4) != 0) && sd is not null)
        {
            _ = sd.Certificates.Count + sd.Crls.Count;
            _ = sd.Verify().IsValid;
            _ = sd.Verify(CmsFixture.Content).IsValid;
            bool? sync = null;
            try
            {
                sync = SignedData.VerifyStream(new MemoryStream(rest), null, null, CmsLimits).IsValid;
            }
            catch (RecursiveAI.OneCrypto.Wire.Cms.CmsParseException)
            {
            }

            // The asynchronous twin must reach the same verdict (the harness may block; the library does not).
            bool? async = null;
            try
            {
                async = SignedData.VerifyStreamAsync(new MemoryStream(rest), null, null, CmsLimits).GetAwaiter().GetResult().IsValid;
            }
            catch (RecursiveAI.OneCrypto.Wire.Cms.CmsParseException)
            {
            }

            if (sync != async)
            {
                throw new InvalidOperationException("VerifyStream and VerifyStreamAsync disagree");
            }

            foreach (SignerInfo s in sd.Signers)
            {
                _ = s.Countersignatures.Count;
                _ = s.SignedAttributesToVerify();
            }
        }
    }

    /// <summary>Starting inputs: signed CMS (several schemes, ours and the test kit's), a time-stamp response and a bare token.</summary>
    public static IEnumerable<byte[]> Seeds()
    {
        TestPki pki = TestPki.Shared;
        yield return [0, .. CmsFixture.KitSign(pki.RsaSigner, new CmsSpec { Cades = true })];
        yield return [0, .. CmsFixture.KitSign(pki.EcSigner, new CmsSpec { Scheme = SigScheme.Ecdsa })];
        yield return [0, .. CmsFixture.KitSign(pki.RsaSigner, new CmsSpec { Scheme = SigScheme.RsaPss, Hash = HashAlgorithmName.SHA384 })];
        yield return [0, .. SignedData.Create(CmsFixture.Content, [CmsKeys.Get(SigKind.P256).Spec(), CmsKeys.Get(SigKind.Ed25519).Spec()]).Encoded.ToArray()];
        SignedData one = SignedData.Create(CmsFixture.Content, [CmsKeys.Get(SigKind.Rsa).Spec()]);
        yield return [0, .. one.WithUnsignedAttribute(0, SignedData.CreateCountersignature(one.Signers[0], CmsKeys.Get(SigKind.P256).Spec())).Encoded.ToArray()];
        byte[] token = CmsKit.Timestamp(FixedImprint, HashAlgorithmName.SHA256, DateTimeOffset.UtcNow, null, FixedNonce);
        yield return [2, .. Der.Seq(Der.Seq(Der.Int(0)), token)];
        yield return [2, .. token];
        yield return [0, .. CompressedData.Create(CmsFixture.Content).Encoded.ToArray()];
    }
}
