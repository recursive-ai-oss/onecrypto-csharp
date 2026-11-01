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
            DigestMismatchException wrongSize = Assert.Throws<DigestMismatchException>(() => SignedData.CreateDetachedFromDigest(new byte[20], sha256, [spec]));
            Assert.Contains("SHA-256", wrongSize.Message, StringComparison.Ordinal);
            Assert.Contains("20 bytes", wrongSize.Message, StringComparison.Ordinal);
            DigestMismatchException wrongAlgorithm = Assert.Throws<DigestMismatchException>(() => SignedData.CreateDetachedFromDigest(new byte[64], KnownOids.Sha512, [spec]));
            Assert.Contains("SHA-256", wrongAlgorithm.Message, StringComparison.Ordinal);
            Assert.Contains("SHA-512", wrongAlgorithm.Message, StringComparison.Ordinal);
            Assert.Equal("SHA-256", wrongAlgorithm.Expected);
            Assert.Equal("SHA-512", wrongAlgorithm.Actual);
            Assert.Throws<NotSupportedException>(() => SignedData.CreateDetachedFromDigest(new byte[32], sha256, [new CmsSignerSpec { Certificate = cert, Key = key, SignatureSpec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256), SignedAttributes = false }]));
        }
    }

    [Fact]
    public void HashNamesMapToDigestOidsAndBack()
    {
        foreach ((HashAlgorithmName name, string oid) in new[] { (HashAlgorithmName.SHA1, KnownOids.Sha1), (HashAlgorithmName.SHA256, KnownOids.Sha256), (HashAlgorithmName.SHA384, KnownOids.Sha384), (HashAlgorithmName.SHA512, KnownOids.Sha512), (HashAlgorithmName.SHA3_256, KnownOids.Sha3256), (HashAlgorithmName.SHA3_512, KnownOids.Sha3512), (DigestNames.Shake256, CmsOids.Shake256) })
        {
            Assert.Equal(oid, DigestNames.GetOid(name));
            Assert.Equal(name, DigestNames.GetHashAlgorithmName(oid));
        }

        Assert.False(DigestNames.TryGetOid(HashAlgorithmName.MD5, out _));
        Assert.False(DigestNames.TryGetHashAlgorithmName("1.2.3.4", out _));
        Assert.Throws<NotSupportedException>(() => DigestNames.GetOid(HashAlgorithmName.MD5));
        Assert.True(DigestNames.TryGetDigestLength(KnownOids.Sha384, out int len));
        Assert.Equal(48, len);
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public void ADigestCanBeNamedByHashAlgorithmName(string kind)
    {
        (ISigningKey key, Certificate cert, IDisposable owner) = Make(kind);
        using (owner)
        {
            CmsSignerSpec spec = Spec(kind, key, cert);
            HashAlgorithmName hash = SignedData.HashAlgorithmFor(spec);
            Assert.Equal(SignedData.DigestAlgorithmFor(spec), DigestNames.GetOid(hash));
            byte[] digest = SignedData.HashContent(DigestNames.GetOid(hash), new MemoryStream(Doc));
            SignedData cms = SignedData.CreateDetachedFromDigest(digest, hash, [spec]);
            Assert.True(cms.Verify(new MemoryStream(Doc)).IsValid);

            CmsSignerSpec keyless = new() { Certificate = cert, SignatureSpec = Spec(kind, key, cert).SignatureSpec ?? SignatureSpec.DefaultFor(cert.PublicKey) };
            PreparedSignedData prepared = SignedData.PrepareDetachedFromDigest(digest, hash, [keyless], Now);
            Assert.True(prepared.Complete(prepared.Signatures[0].SignWith(key)).Verify(new MemoryStream(Doc)).IsValid);
        }
    }

    [Fact]
    public void AHashNamedWrongSaysSoInPlainWords()
    {
        (ISigningKey key, Certificate cert, IDisposable owner) = Make("ecdsa");
        using (owner)
        {
            CmsSignerSpec spec = Spec("ecdsa", key, cert); // signs with SHA-256
            DigestMismatchException e = Assert.Throws<DigestMismatchException>(() => SignedData.CreateDetachedFromDigest(SHA512.HashData(Doc), HashAlgorithmName.SHA512, [spec]));
            Assert.Contains("SHA-256", e.Message, StringComparison.Ordinal);
            Assert.Contains("SHA-512", e.Message, StringComparison.Ordinal);
            Assert.Throws<DigestMismatchException>(() => SignedData.CreateDetachedFromDigest(SHA384.HashData(Doc), HashAlgorithmName.SHA256, [spec]));
            Assert.Throws<NotSupportedException>(() => SignedData.CreateDetachedFromDigest(new byte[16], HashAlgorithmName.MD5, [spec]));
        }
    }

    [Fact]
    public void ASignerWithoutAKeyPointsAtThePrepareCall()
    {
        (ISigningKey key, Certificate cert, IDisposable owner) = Make("ecdsa");
        using (owner)
        {
            var keyless = new CmsSignerSpec { Certificate = cert, SignatureSpec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256) };
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => SignedData.CreateDetachedFromDigest(SHA256.HashData(Doc), HashAlgorithmName.SHA256, [keyless]));
            Assert.Contains("PrepareDetachedFromDigest", e.Message, StringComparison.Ordinal);
            Assert.Contains("PrepareDetachedFromDigest", Assert.Throws<InvalidOperationException>(() => SignedData.CreateDetachedFromDigest(SHA256.HashData(Doc), KnownOids.Sha256, [keyless])).Message, StringComparison.Ordinal);
        }
    }
}
