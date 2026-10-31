using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Cms;
using RecursiveAI.OneCrypto.Pem;
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

Console.WriteLine("OneCrypto AOT smoke: ok");
return 0;
