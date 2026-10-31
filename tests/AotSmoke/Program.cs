using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.X509;

// Exercises the library from a NativeAOT-published app; grows as the library does.
byte[] cms = CmsFixture.KitSign(TestPki.Shared.RsaSigner, new CmsSpec { Cades = true });

if (!SignedData.TryParse(cms, out SignedData? sd) || sd is null || sd.Signers.Count != 1 || !sd.Verify(CmsFixture.Content).IsValid)
{
    Console.Error.WriteLine("hand-built CMS did not parse and verify");
    return 1;
}

// The library's own signer: attached, two signers (RSA and ECDSA), a countersignature, then read back.
SignerKit rsa = CmsKeys.Get(SigKind.Rsa);
SignerKit ec = CmsKeys.Get(SigKind.P256);
SignedData own = SignedData.Create(CmsFixture.Content, [rsa.Spec(), ec.Spec()]);
own = own.WithUnsignedAttribute(0, SignedData.CreateCountersignature(own.Signers[0], ec.Spec()));
SignedDataReport report = SignedData.Parse(own.Encoded).Verify();
if (!report.IsValid || report.Signers.Count != 2 || report.Signers[0].Countersignatures.Count != 1)
{
    Console.Error.WriteLine("own signature did not verify");
    return 1;
}

// Encrypted CMS: key transport, key agreement (P-256 and X25519), a shared key and a password, then authenticated, streamed and compressed forms.
byte[] secret = CmsFixture.Content;
byte[] kek = new byte[32];
RecipientKit rsaRecipient = RecipientKit.Get(RecipKind.Rsa);
RecipientKit ecRecipient = RecipientKit.Get(RecipKind.P256);
RecipientKit xRecipient = RecipientKit.Get(RecipKind.X25519);
EnvelopedData env = EnvelopedData.Parse(EnvelopedData.Create(secret,
    [CmsRecipient.KeyTransport(rsaRecipient.Certificate), CmsRecipient.KeyAgreement(ecRecipient.Certificate), CmsRecipient.KeyAgreement(xRecipient.Certificate),
     CmsRecipient.KeyEncryptionKey(kek, "k"u8, padded: true), CmsRecipient.Password("pw", 1000)]).Encoded);
foreach (CmsDecryptionKey key in new[] { rsaRecipient.Key(), ecRecipient.Key(), xRecipient.Key(), CmsDecryptionKey.FromKeyEncryptionKey(kek, "k"u8), CmsDecryptionKey.FromPassword("pw") })
{
    using (key)
    {
        if (!env.Decrypt(key).AsSpan().SequenceEqual(secret))
        {
            Console.Error.WriteLine("enveloped data did not decrypt");
            return 1;
        }
    }
}

using (CmsDecryptionKey key = rsaRecipient.Key())
{
    if (!AuthEnvelopedData.Parse(AuthEnvelopedData.Create(secret, [CmsRecipient.KeyTransport(rsaRecipient.Certificate)]).Encoded).Decrypt(key).AsSpan().SequenceEqual(secret))
    {
        Console.Error.WriteLine("authenticated enveloped data did not decrypt");
        return 1;
    }

    var streamed = new MemoryStream();
    EnvelopedData.EncryptStream(new MemoryStream(secret), streamed, [CmsRecipient.KeyTransport(rsaRecipient.Certificate)]);
    var back = new MemoryStream();
    EnvelopedData.DecryptStream(new MemoryStream(streamed.ToArray()), back, key);
    if (!back.ToArray().AsSpan().SequenceEqual(secret))
    {
        Console.Error.WriteLine("streamed enveloped data did not decrypt");
        return 1;
    }
}

var signedStream = new MemoryStream();
SignedData.SignStream(new MemoryStream(secret), signedStream, [ec.Spec()]);
if (!SignedData.VerifyStream(new MemoryStream(signedStream.ToArray())).IsValid)
{
    Console.Error.WriteLine("streamed signature did not verify");
    return 1;
}

if (!CompressedData.Parse(CompressedData.Create(secret).Encoded).Decompress().AsSpan().SequenceEqual(secret)
    || !AuthenticatedData.Parse(AuthenticatedData.Create(secret, [CmsRecipient.KeyEncryptionKey(kek, "k"u8)]).Encoded).Verify(CmsDecryptionKey.FromKeyEncryptionKey(kek, "k"u8)).IsValid
    || !DigestedData.Parse(DigestedData.Create(secret).Encoded).Verify().IsValid
    || !EncryptedData.Parse(EncryptedData.Create(secret, kek).Encoded).Decrypt(kek).AsSpan().SequenceEqual(secret))
{
    Console.Error.WriteLine("a simple content type failed");
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

Console.WriteLine("OneCrypto AOT smoke: ok");
return 0;
