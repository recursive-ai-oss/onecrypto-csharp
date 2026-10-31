using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Cms;
using RecursiveAI.OneCrypto.Tsp;

// A detached SignedData with one signer and no certificates, written with the DER writer: enough to exercise parsing, which needs
// no public-key operations. Signature verification needs RSA or ECDSA, which the browser runtime does not offer.
byte[] sha256 = DerWriter.Sequence(DerWriter.Oid(Oids.Sha256));
byte[] signerInfo = DerWriter.Sequence(
    DerWriter.SignedInteger(1),
    DerWriter.Sequence(DerWriter.Sequence(DerWriter.Set(DerWriter.Sequence(DerWriter.Oid("2.5.4.3"), DerWriter.Tlv(0x0C, "smoke"u8.ToArray())))), DerWriter.SignedInteger(7)),
    sha256,
    DerWriter.Sequence(DerWriter.Oid(Oids.Sha256WithRsa), DerWriter.Null()),
    DerWriter.OctetString(new byte[256]));
byte[] signedData = DerWriter.Sequence(
    DerWriter.SignedInteger(1),
    DerWriter.Set(sha256),
    DerWriter.Sequence(DerWriter.Oid(Oids.Data)),
    DerWriter.Set(signerInfo));
byte[] cms = DerWriter.Sequence(DerWriter.Oid(Oids.SignedData), DerWriter.Context(0, signedData));

if (!CmsSignedData.TryParse(cms, out CmsSignedData? sd, out string? error) || sd is null || sd.Signers.Count != 1)
{
    Console.Error.WriteLine("CMS did not parse: " + error);
    return 1;
}

if (Oids.HashFor(sd.Signers[0].DigestAlgorithm.Oid) != HashAlgorithmName.SHA256)
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

Console.WriteLine("OneCrypto WASM smoke: ok");
return 0;
