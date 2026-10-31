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

// Hostile input is refused, not thrown.
if (Asn1Reader.TryRead(new byte[] { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, out _, out _, out _)
    || Rfc3161.TryExtractToken([0x30, 0x80], HashAlgorithmName.SHA256, new byte[32], new byte[8], out _, out _))
{
    Console.Error.WriteLine("hostile input accepted");
    return 1;
}

// Password-based key derivation: RFC 9106 Argon2id and RFC 7914 scrypt vectors, and a bcrypt-pbkdf run.
byte[] argon = Argon2.DeriveKey(
    Argon2Type.Argon2id, Enumerable.Repeat((byte)1, 32).ToArray(), Enumerable.Repeat((byte)2, 16).ToArray(), 32, 3, 4, 32,
    Enumerable.Repeat((byte)3, 8).ToArray(), Enumerable.Repeat((byte)4, 12).ToArray());
byte[] scrypt = Scrypt.DeriveKey("password"u8, "NaCl"u8, 1024, 8, 16, 64);
if (Convert.ToHexString(argon) != "0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659"
    || !Convert.ToHexString(scrypt).StartsWith("FDBABE1C9D347200", StringComparison.Ordinal)
    || BcryptPbkdf.DeriveKey("pw"u8, "salt"u8, 2, 48).Length != 48)
{
    Console.Error.WriteLine("key derivation gave the wrong answer");
    return 1;
}

Console.WriteLine("OneCrypto AOT smoke: ok");
return 0;
