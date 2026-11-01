using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Cms;

/// <summary>A detached CMS signature built from a digest the caller computed (the signing half of PDF-style external-digest flows).</summary>
public class DigestSigningTests
{
    private static readonly byte[] Doc = "the bytes a PDF signature covers"u8.ToArray();
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    public static TheoryData<string> Kinds => ["rsa", "rsa-pss", "ecdsa", "ed25519", "ed448"];

    private static (ISigningKey Key, Certificate Certificate, IDisposable Owner) Make(string kind)
    {
        switch (kind)
        {
            case "rsa" or "rsa-pss":
                var rsa = RSA.Create(2048);
                ISigningKey rk = PrivateKey.FromRsa(rsa);
                return (rk, CmsKeys.SelfSigned("digest " + kind, X509Signer.FromKey(rk, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256))), rsa);
            case "ecdsa":
                var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                ISigningKey ek = PrivateKey.FromECDsa(ec);
                return (ek, CmsKeys.SelfSigned("digest ecdsa", X509Signer.FromKey(ek, SignatureSpec.Ecdsa(HashAlgorithmName.SHA256))), ec);
            case "ed25519":
                var ed = Ed25519PrivateKey.Generate();
                ISigningKey dk = PrivateKey.FromEd25519(ed);
                return (dk, CmsKeys.SelfSigned("digest ed25519", X509Signer.FromKey(dk)), ed);
            default:
                var e4 = Ed448PrivateKey.Generate();
                ISigningKey fk = PrivateKey.FromEd448(e4);
                return (fk, CmsKeys.SelfSigned("digest ed448", X509Signer.FromKey(fk)), e4);
        }
    }

    private static CmsSignerSpec Spec(string kind, ISigningKey key, Certificate cert) => new()
    {
        Certificate = cert,
        Key = key,
        SignatureSpec = kind == "rsa-pss" ? SignatureSpec.RsaPss(HashAlgorithmName.SHA256) : kind == "rsa" ? SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256) : kind == "ecdsa" ? SignatureSpec.Ecdsa(HashAlgorithmName.SHA256) : null,
    };

    [Theory]
    [MemberData(nameof(Kinds))]
    public void ADetachedMessageFromADigestVerifiesAgainstTheContentAndCarriesTheBaselineAttributes(string kind)
    {
        (ISigningKey key, Certificate cert, IDisposable owner) = Make(kind);
        using (owner)
        {
            CmsSignerSpec spec = Spec(kind, key, cert);
            string oid = SignedData.DigestAlgorithmFor(spec);
            byte[] digest = SignedData.HashContent(oid, new MemoryStream(Doc));
            SignedData cms = SignedData.CreateDetachedFromDigest(digest, oid, [spec]);

            Assert.False(cms.HasEncapsulatedContent);
            SignerInfo signer = cms.Signers[0];
            Assert.NotNull(signer.FindSigned(CmsOids.ContentType));
            Assert.NotNull(signer.FindSigned(CmsOids.MessageDigest));
            Assert.NotNull(signer.FindSigned(CmsOids.SigningCertificateV2));
            Assert.Null(signer.FindSigned(CmsOids.SigningTime));
            Assert.True(cms.Verify(new MemoryStream(Doc)).IsValid);
            Assert.False(cms.Verify(new MemoryStream("another"u8.ToArray())).IsValid);

            if (kind == "ed448")
            {
                Assert.Equal(CmsOids.Shake256, oid);
            }

            // OpenSSL before 3.5 refuses EdDSA SignerInfos with signed attributes ("invalid digest"), so EdDSA is checked
            // against 3.5 or newer only.
            if (OpenSslTool.Available && (kind is not ("ed448" or "ed25519") || OpenSslTool.AtLeast(3, 5)))
            {
                string dir = Path.Combine(OpenSslTool.TempDir("cms-digest"), kind);
                Directory.CreateDirectory(dir);
                File.WriteAllBytes(Path.Combine(dir, "m.der"), cms.Encoded.ToArray());
                File.WriteAllBytes(Path.Combine(dir, "c.bin"), Doc);
                (int code, string output) = OpenSslTool.RunIn(dir, "cms", "-verify", "-inform", "DER", "-in", "m.der", "-content", "c.bin", "-noverify", "-binary", "-out", "o.bin");
                Assert.True(code == 0, "openssl cms -verify: " + output);
            }
        }
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public void TheTwoStepFormSurvivesSerialisationAndCompletes(string kind)
    {
        (ISigningKey key, Certificate cert, IDisposable owner) = Make(kind);
        using (owner)
        {
            CmsSignerSpec keyless = new() { Certificate = cert, SignatureSpec = Spec(kind, key, cert).SignatureSpec ?? SignatureSpec.DefaultFor(cert.PublicKey) };
            string oid = SignedData.DigestAlgorithmFor(keyless);
            byte[] digest = SignedData.HashContent(oid, new MemoryStream(Doc));
            byte[] state = SignedData.PrepareDetachedFromDigest(digest, oid, [keyless], Now).Encode();

            PreparedSignedData restored = PreparedSignedData.Decode(state);
            Assert.False(restored.IsAttached);
            SignedData cms = restored.Complete(restored.Signatures[0].SignWith(key));
            Assert.True(cms.Verify(new MemoryStream(Doc)).IsValid);
        }
    }

    [Fact]
    public void ADigestOfTheWrongSizeOrAlgorithmIsRefused()
    {
        (ISigningKey key, Certificate cert, IDisposable owner) = Make("ecdsa");
        using (owner)
        {
            CmsSignerSpec spec = Spec("ecdsa", key, cert);
            string sha256 = SignedData.DigestAlgorithmFor(spec);
            Assert.Throws<ArgumentException>(() => SignedData.CreateDetachedFromDigest(new byte[20], sha256, [spec]));
            Assert.Throws<ArgumentException>(() => SignedData.CreateDetachedFromDigest(new byte[64], KnownOids.Sha512, [spec]));
            Assert.Throws<NotSupportedException>(() => SignedData.CreateDetachedFromDigest(new byte[32], sha256, [new CmsSignerSpec { Certificate = cert, Key = key, SignatureSpec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256), SignedAttributes = false }]));
        }
    }
}
