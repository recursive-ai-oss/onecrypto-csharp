using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.Tsp;

// A detached SignedData with one signer and no certificates, written with the DER writer: enough to exercise parsing, which needs
// no public-key operations. Signature verification needs RSA or ECDSA, which the browser runtime does not offer.
byte[] sha256 = DerWriter.Sequence(DerWriter.Oid(KnownOids.Sha256));
byte[] signerInfo = DerWriter.Sequence(
    DerWriter.SignedInteger(1),
    DerWriter.Sequence(DerWriter.Sequence(DerWriter.Set(DerWriter.Sequence(DerWriter.Oid("2.5.4.3"), DerWriter.Tlv(0x0C, "smoke"u8.ToArray())))), DerWriter.SignedInteger(7)),
    sha256,
    DerWriter.Sequence(DerWriter.Oid(KnownOids.Sha256WithRsa), DerWriter.Null()),
    DerWriter.OctetString(new byte[256]));
byte[] signedData = DerWriter.Sequence(
    DerWriter.SignedInteger(1),
    DerWriter.Set(sha256),
    DerWriter.Sequence(DerWriter.Oid(CmsOids.Data)),
    DerWriter.Set(signerInfo));
byte[] cms = DerWriter.Sequence(DerWriter.Oid(CmsOids.SignedData), DerWriter.Context(0, signedData));

if (!SignedData.TryParse(cms, out SignedData? sd) || sd is null || sd.Signers.Count != 1)
{
    Console.Error.WriteLine("CMS did not parse");
    return 1;
}

if (sd.Signers[0].DigestAlgorithm.Oid != KnownOids.Sha256)
{
    Console.Error.WriteLine("digest algorithm not recognised");
    return 1;
}

// Hashing is available in the browser runtime.
byte[] digest = SHA256.HashData(cms);
byte[] request = Rfc3161.BuildRequest(HashAlgorithmName.SHA256, digest, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
if (!BerToDer.TryConvert(request, out byte[] der) || der.Length != request.Length)
{
    Console.Error.WriteLine("time-stamp request did not round-trip");
    return 1;
}

// The curves the platform lacks: sign and verify with each, and agree a secret both ways.
using (var ed = RecursiveAI.OneCrypto.Primitives.Ed25519PrivateKey.Generate())
using (var ed4 = RecursiveAI.OneCrypto.Primitives.Ed448PrivateKey.Generate())
using (var xa = RecursiveAI.OneCrypto.Primitives.X25519PrivateKey.Generate())
using (var xb = RecursiveAI.OneCrypto.Primitives.X25519PrivateKey.Generate())
using (var xa4 = RecursiveAI.OneCrypto.Primitives.X448PrivateKey.Generate())
using (var xb4 = RecursiveAI.OneCrypto.Primitives.X448PrivateKey.Generate())
{
    byte[] sig = new byte[64], sig4 = new byte[114], s1 = new byte[32], s2 = new byte[32], t1 = new byte[56], t2 = new byte[56];
    bool ok = ed.TrySign("smoke"u8, sig, out _) && ed.PublicKey.Verify("smoke"u8, sig) && !ed.PublicKey.Verify("smokf"u8, sig)
        && ed4.TrySign("smoke"u8, [], sig4, out _) && ed4.PublicKey.Verify("smoke"u8, [], sig4)
        && xa.TryDeriveSharedSecret(xb.PublicKey, s1) && xb.TryDeriveSharedSecret(xa.PublicKey, s2) && s1.AsSpan().SequenceEqual(s2)
        && xa4.TryDeriveSharedSecret(xb4.PublicKey, t1) && xb4.TryDeriveSharedSecret(xa4.PublicKey, t2) && t1.AsSpan().SequenceEqual(t2);
    if (!ok)
    {
        Console.Error.WriteLine("curve primitives failed");
        return 1;
    }
}

// Camellia (RFC 3713 Appendix A) and the decrypt-only legacy ciphers (RFC 2144 B.1 for CAST5, the published Twofish known answer).
using (var cam = new RecursiveAI.OneCrypto.Primitives.Camellia(Convert.FromHexString("0123456789abcdeffedcba9876543210")))
using (var cast = new RecursiveAI.OneCrypto.Primitives.Cast5(Convert.FromHexString("0123456712345678234567893456789A")))
using (var two = new RecursiveAI.OneCrypto.Primitives.Twofish(new byte[16]))
{
    byte[] camPlain = Convert.FromHexString("0123456789abcdeffedcba9876543210");
    byte[] camOut = new byte[16], castOut = new byte[8], twoOut = new byte[16];
    cam.EncryptEcb(camPlain, camOut);
    cast.DecryptEcb(Convert.FromHexString("238B4FE5847E44B2"), castOut);
    two.DecryptEcb(Convert.FromHexString("9F589F5CF6122C32B6BFEC2F2AE8C35A"), twoOut);
    if (Convert.ToHexString(camOut) != "67673138549669730857065648EABE43" || Convert.ToHexString(castOut) != "0123456789ABCDEF" || twoOut.AsSpan().ContainsAnyExcept((byte)0))
    {
        Console.Error.WriteLine("block ciphers gave a wrong result");
        return 1;
    }
}

// The asynchronous ASN.1 reader walks the same tokens as the synchronous one, and streaming decompression runs through its async twin.
var syncReader = new Asn1StreamReader(new MemoryStream(cms));
var asyncReader = new Asn1StreamReader(new MemoryStream(cms));
int tokens = 0;
while (syncReader.TryReadToken(out Asn1Token t1))
{
    (bool more, Asn1Token t2) = await asyncReader.TryReadTokenAsync();
    if (!more || t1.Kind != t2.Kind || t1.Offset != t2.Offset || t1.Length != t2.Length)
    {
        Console.Error.WriteLine("the async reader diverged from the sync reader");
        return 1;
    }

    tokens++;
}

var inflated = new MemoryStream();
await CompressedData.DecompressStreamAsync(new MemoryStream(CompressedData.Create(cms).Encoded.ToArray()), inflated);
if (tokens < 10 || !inflated.ToArray().AsSpan().SequenceEqual(cms) || PreparedSignedData.TryDecode(cms, out _, out _)
    || RecursiveAI.OneCrypto.Policy.CryptoPolicy.Strict.CheckContentCipher("AES-256-CBC", RecursiveAI.OneCrypto.Policy.CryptoUse.Decrypt).IsAllowed)
{
    Console.Error.WriteLine("async streaming or the policy gave a wrong result");
    return 1;
}

if (!OneCrypto.Smoke.FallbackSmoke.Run())
{
    Console.Error.WriteLine("platform-gap code failed");
    return 1;
}

Console.WriteLine("OneCrypto WASM smoke: ok");
return 0;
