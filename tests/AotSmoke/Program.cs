using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Cms;
using RecursiveAI.OneCrypto.Tsp;

// Exercises the library from a NativeAOT-published app; grows as the library does.
TestPki pki = TestPki.Shared;
byte[] cms = CmsFixture.KitSign(pki.RsaSigner, new CmsSpec { Cades = true, Timestamp = true });

if (!CmsSignedData.TryParse(cms, out CmsSignedData? sd, out string? error) || sd is null || sd.Signers.Count != 1)
{
    Console.Error.WriteLine("CMS did not parse: " + error);
    return 1;
}

CmsSignerResult verdict = CmsFixture.VerifyOne(cms);
if (!verdict.IsValid)
{
    Console.Error.WriteLine("CMS did not verify: " + CmsFixture.WarningsOf(verdict));
    return 1;
}

// The library's own signer, with a time-stamp from the in-process authority.
var tsa = new CmsFixture.TestTsa();
var signer = CmsSigner.Create(CmsFixture.Credential(pki.EcSigner), HashAlgorithmName.SHA256, CmsRsaPadding.Pkcs1, cades: true);
byte[] own = signer.Build(SHA256.HashData(CmsFixture.Content), DateTimeOffset.UtcNow, tsa.Callback, CancellationToken.None);
if (!CmsFixture.VerifyOne(own).IsValid || tsa.Calls != 1)
{
    Console.Error.WriteLine("own signature did not verify");
    return 1;
}

// Hostile input is refused, not thrown.
if (Asn1Reader.TryRead(new byte[] { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, out _, out _, out _)
    || Rfc3161.TryExtractToken([0x30, 0x80], HashAlgorithmName.SHA256, new byte[32], new byte[8], out _, out _))
{
    Console.Error.WriteLine("hostile input accepted");
    return 1;
}

Console.WriteLine("OneCrypto AOT smoke: ok");
return 0;
