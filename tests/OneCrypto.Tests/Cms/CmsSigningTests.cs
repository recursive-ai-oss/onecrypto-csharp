using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Cms;
using static OneCrypto.Tests.Support.CmsFixture;

namespace OneCrypto.Tests.Cms;

/// <summary>The signer: its output must verify with our verifier, carry the right attributes, and fail with typed reasons.</summary>
public class CmsSigningTests
{
    private static (X509Certificate2 Cert, CmsRsaPadding Padding) Key(string id)
    {
        TestPki pki = TestPki.Shared;
        return id switch
        {
            "rsa-pkcs1" => (pki.RsaSigner, CmsRsaPadding.Pkcs1),
            "rsa-pss" => (pki.RsaSigner, CmsRsaPadding.Pss),
            "ec256" => (pki.EcSigner, CmsRsaPadding.Pkcs1),
            "ec384" => (pki.Ec384Signer, CmsRsaPadding.Pkcs1),
            _ => throw new ArgumentOutOfRangeException(nameof(id)),
        };
    }

    private static byte[] Sign(CmsSigner signer, CmsTimestampCallback? timestamp = null, DateTimeOffset? at = null) =>
        signer.Build(CryptographicOperations.HashData(signer.Hash, Content), at ?? DateTimeOffset.UtcNow, timestamp, CancellationToken.None);

    public static IEnumerable<object[]> Matrix()
    {
        foreach (string key in new[] { "rsa-pkcs1", "rsa-pss", "ec256", "ec384" })
        {
            foreach (string hash in new[] { "SHA256", "SHA384" })
            {
                foreach (bool cades in new[] { true, false })
                {
                    foreach (bool stamped in new[] { false, true })
                    {
                        yield return [key, hash, cades, stamped];
                    }
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public void OurVerifierValidatesOurOutput(string key, string hash, bool cades, bool stamped)
    {
        (X509Certificate2 cert, CmsRsaPadding padding) = Key(key);
        var tsa = new TestTsa();
        var signer = CmsSigner.Create(Credential(cert), new HashAlgorithmName(hash), padding, cades);
        byte[] cms = Sign(signer, stamped ? tsa.Callback : null);
        CmsSignerResult v = VerifyOne(cms);
        Assert.True(v.IsValid, WarningsOf(v));
        Assert.Equal(stamped, v.Timestamp is not null);
        Assert.Equal(stamped ? 1 : 0, tsa.Calls);
        Assert.True(signer.EstimateBytes(stamped) >= cms.Length, "the size estimate leaves room for the real thing");
    }

    [Fact]
    public void CadesProfileMatchesBaselineRequirements()
    {
        byte[] cms = Sign(CmsSigner.Create(Credential(TestPki.Shared.RsaSigner), HashAlgorithmName.SHA256, CmsRsaPadding.Pkcs1, cades: true), new TestTsa().Callback);
        Assert.True(CmsSignedData.TryParse(cms, out CmsSignedData? sd, out string? error), error);
        CmsSignerInfo si = Assert.Single(sd!.Signers);
        Assert.NotNull(si.FindSigned(Oids.ContentType));
        Assert.NotNull(si.FindSigned(Oids.MessageDigest));
        Assert.NotNull(si.FindSigned(Oids.SigningCertificateV2));
        Assert.Null(si.FindSigned(Oids.SigningTime));
        Assert.Null(si.FindSigned(Oids.SigningCertificate));
        Assert.NotNull(si.FindUnsigned(Oids.SignatureTimeStampToken));
        Assert.Null(sd.Content);
        Assert.True(sd.Certificates.Count >= 2, "signer and intermediate are embedded");

        byte[] pkcs7 = Sign(CmsSigner.Create(Credential(TestPki.Shared.RsaSigner), HashAlgorithmName.SHA256, CmsRsaPadding.Pkcs1, cades: false));
        Assert.True(CmsSignedData.TryParse(pkcs7, out CmsSignedData? sd2, out _));
        Assert.NotNull(sd2!.Signers[0].FindSigned(Oids.SigningTime));
        Assert.Null(sd2.Signers[0].FindUnsigned(Oids.SignatureTimeStampToken));
    }

    [Theory]
    [InlineData("rsa-pkcs1", false)]
    [InlineData("rsa-pss", false)]
    [InlineData("ec256", false)]
    [InlineData("ec256", true)]
    [InlineData("ec384", true)]
    public void ExternalSignerPathIsValid(string key, bool p1363)
    {
        (X509Certificate2 cert, CmsRsaPadding padding) = Key(key);
        X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(cert.RawData);
        var seen = new List<CmsSignRequest>();
        CmsExternalSigner external = request =>
        {
            seen.Add(request);
            if (request.KeyType == CmsKeyType.Rsa)
            {
                using RSA rsa = cert.GetRSAPrivateKey()!;
                return rsa.SignHash(request.Hash.ToArray(), request.HashAlgorithm, request.RsaPadding == CmsRsaPadding.Pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
            }

            using ECDsa ec = cert.GetECDsaPrivateKey()!;
            return ec.SignHash(request.Hash.ToArray(), p1363 ? DSASignatureFormat.IeeeP1363FixedFieldConcatenation : DSASignatureFormat.Rfc3279DerSequence);
        };

        var signer = CmsSigner.Create(CmsSigningCredential.FromExternalSigner(publicOnly, external, [TestPki.Shared.Intermediate]), HashAlgorithmName.SHA384, padding, cades: true);
        CmsSignerResult v = VerifyOne(Sign(signer));
        Assert.True(v.IsValid, WarningsOf(v));
        CmsSignRequest r = Assert.Single(seen);
        Assert.Equal(48, r.Hash.Length);
        Assert.Equal(HashAlgorithmName.SHA384, r.HashAlgorithm);
    }

    [Fact]
    public void ErrorsAreTyped()
    {
        TestPki pki = TestPki.Shared;
        X509Certificate2 publicOnly = X509CertificateLoader.LoadCertificate(pki.RsaSigner.RawData);

        CmsSigningException noKey = Assert.Throws<CmsSigningException>(() => CmsSigner.Create(CmsSigningCredential.FromCertificate(publicOnly), HashAlgorithmName.SHA256, CmsRsaPadding.Pkcs1, true));
        Assert.Equal(CmsSigningError.NoPrivateKey, noKey.Reason);

        CmsSigningException weak = Assert.Throws<CmsSigningException>(() => CmsSigner.Create(Credential(pki.RsaSigner), HashAlgorithmName.SHA1, CmsRsaPadding.Pkcs1, true));
        Assert.Equal(CmsSigningError.UnsupportedAlgorithm, weak.Reason);

        CmsSigningException garbage = Assert.Throws<CmsSigningException>(() => Sign(CmsSigner.Create(
            CmsSigningCredential.FromExternalSigner(publicOnly, static _ => [1, 2, 3, 4]), HashAlgorithmName.SHA256, CmsRsaPadding.Pkcs1, true)));
        Assert.Equal(CmsSigningError.SignerFailed, garbage.Reason);

        CmsSigningException wrongKey = Assert.Throws<CmsSigningException>(() => Sign(CmsSigner.Create(
            CmsSigningCredential.FromExternalSigner(publicOnly, request =>
            {
                using RSA other = RSA.Create(2048);
                return other.SignHash(request.Hash.ToArray(), request.HashAlgorithm, RSASignaturePadding.Pkcs1);
            }), HashAlgorithmName.SHA256, CmsRsaPadding.Pkcs1, true)));
        Assert.Equal(CmsSigningError.SignerFailed, wrongKey.Reason);

        var signer = CmsSigner.Create(Credential(pki.RsaSigner), HashAlgorithmName.SHA256, CmsRsaPadding.Pkcs1, true);
        foreach (TestTsa bad in new[]
        {
            new TestTsa { WrongImprint = true },
            new TestTsa { WrongNonce = true },
            new TestTsa { DropNonce = true },
            new TestTsa { Refuse = true },
        })
        {
            CmsSigningException ts = Assert.Throws<CmsSigningException>(() => Sign(signer, bad.Callback));
            Assert.Equal(CmsSigningError.TimestampRejected, ts.Reason);
        }

        CmsSigningException garbageToken = Assert.Throws<CmsSigningException>(() => Sign(signer, static _ => [0x30, 0x03, 0x02, 0x01, 0x05]));
        Assert.Equal(CmsSigningError.TimestampRejected, garbageToken.Reason);
        CmsSigningException nullToken = Assert.Throws<CmsSigningException>(() => Sign(signer, static _ => null!));
        Assert.Equal(CmsSigningError.TimestampRejected, nullToken.Reason);
    }
}
