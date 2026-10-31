using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Cms;
using RecursiveAI.OneCrypto.Primitives;
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

// The AES modes, against one published vector each (RFC 7253 A, the EAX paper G, RFC 3394 4.1).
byte[] ocbKey = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
byte[] ocbPlain = Convert.FromHexString("0001020304050607");
byte[] ocbCipher = new byte[8];
byte[] ocbTag = new byte[16];
using (var ocb = new AesOcb(ocbKey))
{
    ocb.Encrypt(Convert.FromHexString("BBAA99887766554433221101"), ocbPlain, ocbCipher, ocbTag, ocbPlain);
}

byte[] eaxTag = new byte[16];
using (var eax = new AesEax(Convert.FromHexString("233952DEE4D5ED5F9B9C6D6FF80FF478")))
{
    eax.Encrypt(Convert.FromHexString("62EC67F9C3A4A407FCB2A8C49031A8B3"), [], [], eaxTag, Convert.FromHexString("6BFB914FD07EAE6B"));
}

byte[] wrapped = new byte[24];
using (var kw = new AesKeyWrap(ocbKey))
{
    kw.Wrap(Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), wrapped);
}

if (Convert.ToHexString(ocbCipher) + Convert.ToHexString(ocbTag) != "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009"
    || Convert.ToHexString(eaxTag) != "E037830E8389F27B025A2D6527E79D01"
    || Convert.ToHexString(wrapped) != "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
{
    Console.Error.WriteLine("AES modes gave a wrong result");
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
