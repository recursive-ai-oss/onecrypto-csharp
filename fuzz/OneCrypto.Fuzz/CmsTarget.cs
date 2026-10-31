using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Cms;
using RecursiveAI.OneCrypto.Tsp;

namespace OneCrypto.Fuzz;

/// <summary>
/// CMS and ASN.1 surface. The first byte picks the mode: bit 1 set with bit 0 clear checks the rest as a time-stamp response against
/// a fixed imprint and nonce; anything else parses the rest as a CMS SignedData and verifies its first signer over a fixed content,
/// chain building included. Nothing may escape: malformed input is reported, not thrown.
/// </summary>
internal static class CmsTarget
{
    private static readonly byte[] FixedImprint = new byte[32];

    private static readonly byte[] FixedNonce = [0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22];

    private static readonly Lazy<CmsVerifyOptions> Options = new(static () => TestPki.Shared.Trusting());

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

        if (CmsSignedData.TryParse(rest, out CmsSignedData? sd, out _) && sd is not null)
        {
            _ = sd.Signers.Count + sd.Certificates.Count;
        }

        CmsSignerResult r = CmsSignerVerifier.Verify(rest, CmsFixture.DigestOf(CmsFixture.Content), Options.Value, CancellationToken.None);
        _ = r.IsValid;
    }

    /// <summary>Starting inputs: a signed CMS (several schemes), a time-stamped one, a time-stamp response and a bare token.</summary>
    public static IEnumerable<byte[]> Seeds()
    {
        TestPki pki = TestPki.Shared;
        yield return [0, .. CmsFixture.KitSign(pki.RsaSigner, new CmsSpec { Cades = true, Timestamp = true })];
        yield return [0, .. CmsFixture.KitSign(pki.EcSigner, new CmsSpec { Scheme = SigScheme.Ecdsa })];
        yield return [0, .. CmsFixture.KitSign(pki.RsaSigner, new CmsSpec { Scheme = SigScheme.RsaPss, Hash = HashAlgorithmName.SHA384 })];
        byte[] token = CmsKit.Timestamp(FixedImprint, HashAlgorithmName.SHA256, DateTimeOffset.UtcNow, null, FixedNonce);
        yield return [2, .. Der.Seq(Der.Seq(Der.Int(0)), token)];
        yield return [2, .. token];
    }
}
