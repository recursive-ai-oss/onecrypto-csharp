using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Cms;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.X509;

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

// The wire layer: write DER, read it back with the span reader and the stream reader, and go through PEM.
var writer = new Asn1Writer();
writer.PushSequence();
writer.WriteInteger(300);
writer.WriteObjectIdentifier("1.2.840.113549.1.1.11");
writer.PushSetOf();
writer.WriteOctetString([2]);
writer.WriteOctetString([1]);
writer.Pop();
writer.Pop();
byte[] der = writer.Encode();
var reader = new Asn1Reader(der, Asn1Rules.Der);
Asn1Reader body = reader.ReadSequence();
if (body.ReadInt32() != 300 || body.ReadObjectIdentifier() != "1.2.840.113549.1.1.11" || body.ReadSetOf().ReadOctetString()[0] != 1)
{
    Console.Error.WriteLine("ASN.1 round trip failed");
    return 1;
}

var tokens = new Asn1StreamReader(new MemoryStream(der), Asn1Rules.Der);
int count = 0;
while (tokens.TryReadToken(out _))
{
    count++;
}

PemBlock pem = PemCodec.Parse(PemCodec.Write("TEST", der), PemMode.Strict);
if (count != 8 || !pem.Data.AsSpan().SequenceEqual(der))
{
    Console.Error.WriteLine("stream or PEM round trip failed");
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
if (Asn1Element.TryRead(new byte[] { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, out _, out _, out _)
    || Rfc3161.TryExtractToken([0x30, 0x80], HashAlgorithmName.SHA256, new byte[32], new byte[8], out _, out _))
{
    Console.Error.WriteLine("hostile input accepted");
    return 1;
}

// PKI models: build a chain, a request, a CRL and an OCSP exchange, read them back and check every signature.
using (var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
using (var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
{
    DateTimeOffset now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
    X509Signer rootSigner = X509Signer.FromECDsa(rootKey);
    Certificate root = CertificateBuilder.CreateSelfSigned(
        new CertificateOptions { Subject = DistinguishedName.FromString("CN=Smoke Root,O=Smoke"), NotBefore = now, NotAfter = now.AddYears(5), Extensions = [Extension.Create(new BasicConstraints(true, 0), true)] },
        rootSigner);
    Certificate leaf = CertificateBuilder.Create(
        new CertificateOptions
        {
            Subject = DistinguishedName.FromString("CN=smoke.example.test"),
            PublicKey = X509Signer.FromECDsa(leafKey).PublicKey,
            NotBefore = now,
            NotAfter = now.AddYears(1),
            Extensions = [Extension.Create(new SubjectAlternativeName([GeneralName.Dns("smoke.example.test")]), false)],
        },
        root,
        rootSigner);
    CertificateSigningRequest csr = CertificateSigningRequestBuilder.Create(new CertificateSigningRequestOptions { Subject = leaf.Subject }, X509Signer.FromECDsa(leafKey));
    CertificateRevocationList crl = RevocationListBuilder.Create(
        new RevocationListOptions { ThisUpdate = now, Number = 1, Revoked = [new RevokedCertificateInfo(7, now, RevocationReason.Superseded)] }, rootSigner, root);
    OcspCertId id = OcspCertId.Create(leaf, root);
    OcspResponse response = OcspResponseBuilder.CreateSuccessful(
        new OcspResponseOptions { Responder = new OcspResponderId(root.Subject), ProducedAt = now, Responses = [new OcspSingleResponseInfo(id, OcspCertStatus.Good, now)] }, rootSigner);
    OcspRequest request = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [id], Nonce = new byte[] { 1, 2, 3 } });
    if (!leaf.VerifySignature(root).IsValid || !root.IsSelfSigned || !csr.VerifySignature().IsValid || !crl.VerifySignature(root).IsValid
        || !response.BasicResponse!.VerifySignature(root.PublicKey).IsValid || leaf.SubjectAlternativeName!.Names[0].Value != "smoke.example.test"
        || crl.Find(new byte[] { 7 }) is null || request.Nonce is null || !id.Matches(leaf, root)
        || !Certificate.FromPem(leaf.ToPem()).Equals(leaf) || leaf.Subject.ToString() != "CN=smoke.example.test")
    {
        Console.Error.WriteLine("PKI models did not round trip");
        return 1;
    }

    if (Certificate.TryParse(new byte[] { 0x30, 0x80 }, out _) || !leaf.TryToX509Certificate2(out System.Security.Cryptography.X509Certificates.X509Certificate2? platform) || platform is null)
    {
        Console.Error.WriteLine("PKI hostile input or platform conversion failed");
        return 1;
    }

    platform.Dispose();
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

if (!OneCrypto.Smoke.FallbackSmoke.Run())
{
    Console.Error.WriteLine("platform-gap code failed");
    return 1;
}

if (!OneCrypto.Smoke.ValidationSmoke.Run())
{
    Console.Error.WriteLine("path validation gave the wrong answer");
    return 1;
}

Console.WriteLine("OneCrypto AOT smoke: ok");
return 0;
