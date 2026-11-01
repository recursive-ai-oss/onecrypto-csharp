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

// The asynchronous streaming twins, two-phase CMS signing, signing through a key interface, and the policy at the decision points.
var asyncSigned = new MemoryStream();
await SignedData.SignStreamAsync(new MemoryStream(secret), asyncSigned, [ec.Spec()]);
var asyncSeen = new MemoryStream();
using (CmsDecryptionKey asyncKey = rsaRecipient.Key())
{
    var asyncEnc = new MemoryStream();
    await EnvelopedData.EncryptStreamAsync(new MemoryStream(secret), asyncEnc, [CmsRecipient.KeyTransport(rsaRecipient.Certificate)]);
    var asyncPlain = new MemoryStream();
    await EnvelopedData.DecryptStreamAsync(new MemoryStream(asyncEnc.ToArray()), asyncPlain, asyncKey);
    var asyncAuth = new MemoryStream();
    await AuthEnvelopedData.EncryptStreamAsync(new MemoryStream(secret), asyncAuth, [CmsRecipient.KeyTransport(rsaRecipient.Certificate)]);
    var asyncAuthPlain = new MemoryStream();
    await AuthEnvelopedData.DecryptStreamAsync(new MemoryStream(asyncAuth.ToArray()), asyncAuthPlain, asyncKey);
    if (!(await SignedData.VerifyStreamAsync(new MemoryStream(asyncSigned.ToArray()), asyncSeen)).IsValid || !asyncSeen.ToArray().AsSpan().SequenceEqual(secret)
        || !asyncPlain.ToArray().AsSpan().SequenceEqual(secret) || !asyncAuthPlain.ToArray().AsSpan().SequenceEqual(secret))
    {
        Console.Error.WriteLine("an async streaming twin failed");
        return 1;
    }
}

var asyncCompressed = new MemoryStream();
await CompressedData.DecompressStreamAsync(new MemoryStream(CompressedData.Create(secret).Encoded.ToArray()), asyncCompressed);
if (!asyncCompressed.ToArray().AsSpan().SequenceEqual(secret))
{
    Console.Error.WriteLine("streaming decompression failed");
    return 1;
}

PreparedSignedData cmsPrepared = SignedData.Prepare(secret, [new CmsSignerSpec { Certificate = ec.Certificate, SignatureSpec = ec.Signer.Spec }], CmsKeys.SigningTime);
PreparedSignedData restoredState = PreparedSignedData.Decode(cmsPrepared.Encode());
byte[] twoPhaseSignature = restoredState.Signatures[0].SignWith(ec.Signer.Key!);
if (!restoredState.Complete(twoPhaseSignature).Verify().IsValid)
{
    Console.Error.WriteLine("two-phase CMS signing failed");
    return 1;
}

bool refusedSha1 = false;
try
{
    _ = SignedData.Create(secret, [new CmsSignerSpec { Certificate = rsa.Certificate, Key = rsa.Signer.Key, SignatureSpec = RecursiveAI.OneCrypto.Keys.SignatureSpec.RsaPkcs1(System.Security.Cryptography.HashAlgorithmName.SHA1) }]);
}
catch (RecursiveAI.OneCrypto.Policy.PolicyViolationException)
{
    refusedSha1 = true;
}

var verifyAt = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
SignedDataReport policed = SignedData.Create(secret, [rsa.Spec()]).Verify(new SignedDataVerifyOptions { Policy = RecursiveAI.OneCrypto.Policy.CryptoPolicy.Standard, ReferenceTime = verifyAt });
if (!refusedSha1 || !policed.IsValid || policed.Signers[0].Policy is null)
{
    Console.Error.WriteLine("the policy did not decide as expected");
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

// Policy decisions and a two-phase signature, in process: prepare, serialise, sign elsewhere, restore, complete.
using (var pk = ECDsa.Create(ECCurve.NamedCurves.nistP256))
using (var pkey = RecursiveAI.OneCrypto.Keys.PrivateKey.FromECDsa(pk))
{
    DateTimeOffset at = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
    var policy = RecursiveAI.OneCrypto.Policy.CryptoPolicy.Standard;
    var sha1 = policy.CheckHash(HashAlgorithmName.SHA1, RecursiveAI.OneCrypto.Policy.CryptoUse.Verify, at);
    var spec = RecursiveAI.OneCrypto.Keys.SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
    var prepared = RecursiveAI.OneCrypto.Keys.PreparedSignature.Prepare(pkey.PublicKey, spec, "smoke"u8, policy, at);
    var restored = RecursiveAI.OneCrypto.Keys.PreparedSignature.Decode(prepared.Encode());
    byte[] sig = pkey.SignDigest(restored.ToSign.Span, restored.Spec);
    var tbs = RecursiveAI.OneCrypto.CertificateBuilder.PrepareSelfSigned(
        new CertificateOptions { Subject = DistinguishedName.FromString("CN=Two Phase"), NotBefore = at, NotAfter = at.AddYears(1) }, pkey.PublicKey, spec, policy, at);
    Certificate twoPhase = CertificateBuilder.Complete(tbs, tbs.SignWith(pkey));
    if (sha1.Verdict != RecursiveAI.OneCrypto.Policy.PolicyVerdict.Flagged || restored.Complete(sig).Length == 0 || !twoPhase.IsSelfSigned
        || policy.CheckHash(HashAlgorithmName.SHA1, RecursiveAI.OneCrypto.Policy.CryptoUse.Sign, at).IsAllowed)
    {
        Console.Error.WriteLine("policy or two-phase signing failed");
        return 1;
    }
}

// The issuer side: a CA issues a time-stamping certificate and a leaf, the authority stamps and the client verifies, the responder answers and a CRL is issued.
using (var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
using (var tsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
using (var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
{
    DateTimeOffset at = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    var ca = RecursiveAI.OneCrypto.Issuance.CertificateAuthority.CreateRoot(DistinguishedName.FromString("CN=Smoke CA"), X509Signer.FromECDsa(caKey), at.AddDays(-1), TimeSpan.FromDays(365));
    Certificate tsaCert = ca.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(tsaKey), DistinguishedName.FromString("CN=Smoke TSA"),
        new RecursiveAI.OneCrypto.Issuance.CertificateIssueOptions { Profile = RecursiveAI.OneCrypto.Issuance.CertificateProfile.TimeStamping, NotBefore = at });
    Certificate leafCert = ca.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(leafKey), DistinguishedName.FromString("CN=Smoke Leaf"),
        new RecursiveAI.OneCrypto.Issuance.CertificateIssueOptions { Profile = RecursiveAI.OneCrypto.Issuance.CertificateProfile.CodeSigning, NotBefore = at });
    var tsa = new TimeStampAuthority(new TimeStampAuthorityOptions { Certificate = tsaCert, Signer = X509Signer.FromECDsa(tsaKey), DefaultPolicy = "1.2.3.4.1" }, new CounterTimeStampSerialSource());
    TimeStampRequest tsReq = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData("smoke"u8), Nonce = TimeStampRequest.NewNonce() });
    TimeStampResponse tsResp = tsa.Handle(tsReq.Encoded, at);
    TimeStampReport tsReport = TimeStampVerifier.Verify(tsReq, tsResp.Encoded);
    var source = new RecursiveAI.OneCrypto.Issuance.InMemoryRevocationSource(TimeSpan.FromHours(1));
    source.SetRevoked(leafCert.SerialNumber.Span, at, RevocationReason.KeyCompromise);
    var responder = new RecursiveAI.OneCrypto.Issuance.OcspResponder(new RecursiveAI.OneCrypto.Issuance.OcspResponderOptions { Issuer = ca.Certificate, ResponderCertificate = ca.Certificate, Signer = X509Signer.FromECDsa(caKey), Source = source });
    OcspRequest oReq = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [OcspCertId.Create(leafCert, ca.Certificate)], Nonce = new byte[] { 9, 8, 7, 6 } });
    OcspResponse oResp = responder.Handle(oReq.Encoded, at);
    CertificateRevocationList issuedCrl = ca.IssueCrl(new RecursiveAI.OneCrypto.Issuance.CrlIssueOptions { ThisUpdate = at, NextUpdate = at.AddDays(1), Number = 1, Revoked = [new RevokedCertificateInfo(leafCert.SerialNumberValue, at)] });
    if (!tsReport.IsValid || tsResp.Token is null || !leafCert.VerifySignature(ca.Certificate).IsValid || !issuedCrl.VerifySignature(ca.Certificate).IsValid
        || oResp.Status != OcspResponseStatus.Successful || oResp.BasicResponse!.Responses[0].Status != OcspCertStatus.Revoked
        || !oResp.BasicResponse.VerifySignature(ca.Certificate.PublicKey).IsValid
        || tsa.Handle(new byte[] { 0x30, 0x80 }, at).FailureInfo != TimeStampFailure.BadDataFormat
        || responder.Handle(new byte[] { 0x30, 0x80 }, at).Status != OcspResponseStatus.MalformedRequest)
    {
        Console.Error.WriteLine("issuer side failed");
        return 1;
    }
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

// Key containers: PKCS#8 (plain and PBES2-encrypted), a PKCS#12 file with both MAC kinds, and OpenSSH keys, all without the platform's certificate classes.
using (var ed = RecursiveAI.OneCrypto.Primitives.Ed25519PrivateKey.Generate())
using (RecursiveAI.OneCrypto.Pkcs.PrivateKeyInfo pk = RecursiveAI.OneCrypto.Pkcs.PrivateKeyInfo.FromEd25519(ed))
{
    var fast = new RecursiveAI.OneCrypto.Pkcs.Pbes2Options { Iterations = 100 };
    using var back = RecursiveAI.OneCrypto.Pkcs.EncryptedPrivateKeyInfo.Parse(pk.Encrypt("pw", fast).Encoded.Span).Decrypt("pw");
    bool wrong = RecursiveAI.OneCrypto.Pkcs.EncryptedPrivateKeyInfo.Parse(pk.Encrypt("pw", fast).Encoded.Span).TryDecrypt("no", out _) == RecursiveAI.OneCrypto.Pkcs.PkcsStatus.WrongPasswordOrCorrupt;

    var bag = RecursiveAI.OneCrypto.Pkcs.Pkcs12Bag.ForPrivateKey(pk, "k");
    var p12 = RecursiveAI.OneCrypto.Pkcs.Pkcs12File.Create([bag], "pw", new RecursiveAI.OneCrypto.Pkcs.Pkcs12WriteOptions { Encryption = fast, MacIterations = 100 });
    var p12b = RecursiveAI.OneCrypto.Pkcs.Pkcs12File.Create([bag], "pw", new RecursiveAI.OneCrypto.Pkcs.Pkcs12WriteOptions { Encryption = fast, MacIterations = 100, Mac = RecursiveAI.OneCrypto.Pkcs.Pkcs12MacKind.Pbmac1 });
    using var opened = RecursiveAI.OneCrypto.Pkcs.Pkcs12File.Parse(p12.Encoded.Span).Open("pw");
    using var openedB = RecursiveAI.OneCrypto.Pkcs.Pkcs12File.Parse(p12b.Encoded.Span).Open("pw");

    var ssh = RecursiveAI.OneCrypto.Wire.Ssh.SshPrivateKey.FromPem(RecursiveAI.OneCrypto.Wire.Ssh.SshPrivateKey.Create(pk, "c", "pw", new RecursiveAI.OneCrypto.Wire.Ssh.SshKeyWriteOptions { Rounds = 2 }).ToPem());
    using var sshOpen = ssh.Open("pw");
    var pub = RecursiveAI.OneCrypto.Wire.Ssh.SshPublicKey.ParseAuthorizedKey(ssh.PublicKey.ToAuthorizedKey("c"));
    if (!back.Encoded.SequenceEqual(pk.Encoded) || !wrong || opened.PrivateKeys.Count != 1 || openedB.PrivateKeys.Count != 1
        || !sshOpen.PrivateKey!.Encoded.SequenceEqual(pk.Encoded) || !pub.Equals(ssh.PublicKey))
    {
        Console.Error.WriteLine("key containers did not round trip");
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

if (!OneCrypto.Smoke.LoadSmoke.Run(true))
{
    Console.Error.WriteLine("Crypto.Load gave a wrong result");
    return 1;
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

if (!await OneCrypto.Smoke.OnlineSmoke.Run())
{
    Console.Error.WriteLine("replayed fetch gave the wrong answer");
    return 1;
}

Console.WriteLine("OneCrypto AOT smoke: ok");
return 0;
