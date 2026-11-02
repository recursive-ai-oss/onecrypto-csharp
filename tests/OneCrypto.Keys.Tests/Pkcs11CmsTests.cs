using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Pkcs11;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Keys.Tests;

/// <summary>CMS with keys on the token, in both directions against OpenSSL.</summary>
public class Pkcs11CmsTests
{
    private static readonly byte[] Doc = RandomNumberGenerator.GetBytes(3000);

    private static string Dir(string name)
    {
        string d = Path.Combine(SoftHsm.Work, "cms", name);
        Directory.CreateDirectory(d);
        return d;
    }

    public static TheoryData<string> Kinds => ["rsa-pkcs1", "rsa-pss", "p256", "p384", "ed25519"];

    private static (Pkcs11Key Key, SignatureSpec Spec, KeyUsages Usages) Make(Pkcs11Session s, string kind)
    {
        (string label, byte[] id) = SoftHsm.Fresh("cms-" + kind);
        switch (kind)
        {
            case "rsa-pkcs1":
                return (s.GenerateKeyPair(Pkcs11KeyPairSpec.Rsa(2048), label, id), SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256), KeyUsages.DigitalSignature | KeyUsages.KeyEncipherment);
            case "rsa-pss":
                return (s.GenerateKeyPair(Pkcs11KeyPairSpec.Rsa(2048), label, id), SignatureSpec.RsaPss(HashAlgorithmName.SHA256), KeyUsages.DigitalSignature | KeyUsages.KeyEncipherment);
            case "p256":
                return (s.GenerateKeyPair(Pkcs11KeyPairSpec.P256(), label, id), SignatureSpec.Ecdsa(HashAlgorithmName.SHA256), KeyUsages.DigitalSignature | KeyUsages.KeyAgreement);
            case "p384":
                return (s.GenerateKeyPair(Pkcs11KeyPairSpec.P384(), label, id), SignatureSpec.Ecdsa(HashAlgorithmName.SHA384), KeyUsages.DigitalSignature | KeyUsages.KeyAgreement);
            default:
                Assert.SkipUnless(s.Slot.GetMechanisms().Contains(0x1055), "the token has no EdDSA");
                return (s.GenerateKeyPair(Pkcs11KeyPairSpec.Ed25519(), label, id), SignatureSpec.Ed25519(), KeyUsages.DigitalSignature);
        }
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public void SignedDataSignedByTheTokenVerifiesHereAndInOpenSsl(string kind)
    {
        Tools.RequireOpenSsl();
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (Pkcs11Key key, SignatureSpec spec, KeyUsages usages) = Make(session, kind);
            Certificate cert = TokenCertificates.SelfSigned("token signer " + kind, (ISigningKey)key, usages & ~(KeyUsages.KeyEncipherment | KeyUsages.KeyAgreement), spec);
            foreach (bool detached in new[] { true, false })
            {
                SignedData sd = SignedData.Create(Doc, [new CmsSignerSpec { Certificate = cert, Key = (ISigningKey)key, SignatureSpec = spec }], new SignedDataOptions { Detached = detached });
                Assert.True((detached ? sd.Verify(Doc) : sd.Verify()).IsValid, $"{kind} detached={detached}: ours");

                string dir = Dir($"sign-{kind}-{detached}");
                File.WriteAllBytes(Path.Combine(dir, "msg.der"), sd.Encoded.ToArray());
                File.WriteAllBytes(Path.Combine(dir, "content.bin"), Doc);
                string[] args = ["cms", "-verify", "-inform", "DER", "-in", Path.Combine(dir, "msg.der"), "-noverify", "-binary", "-out", Path.Combine(dir, "out.bin")];
                if (detached)
                {
                    args = [.. args, "-content", Path.Combine(dir, "content.bin")];
                }

                if (kind == "ed25519" && !Tools.OpenSslAtLeast(3, 5))
                {
                    continue; // OpenSSL before 3.5 refuses EdDSA without signed attributes
                }

                var r = Tools.Run(Tools.OpenSsl!, null, args);
                Assert.True(r.Code == 0, $"{kind} detached={detached}: openssl cms -verify: {r.Error}");
                Assert.Equal(Doc, File.ReadAllBytes(Path.Combine(dir, "out.bin")));
            }
        }
    }

    [Theory]
    [InlineData("rsa-pkcs1", KeyTransportScheme.Pkcs1V15)]
    [InlineData("rsa-pkcs1", KeyTransportScheme.OaepSha1)]
    [InlineData("rsa-pkcs1", KeyTransportScheme.OaepSha256)]
    [InlineData("p256", KeyTransportScheme.OaepSha1)]
    [InlineData("p384", KeyTransportScheme.OaepSha1)]
    public void EnvelopedDataForATokenKeyIsOpenedByTheToken(string kind, KeyTransportScheme scheme)
    {
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (Pkcs11Key key, SignatureSpec spec, KeyUsages usages) = Make(session, kind);
            bool rsa = kind.StartsWith("rsa", StringComparison.Ordinal);
            Certificate cert = TokenCertificates.SelfSigned("token recipient " + kind, (ISigningKey)key, usages, spec);
            CmsRecipient recipient = rsa ? CmsRecipient.KeyTransport(cert, scheme) : CmsRecipient.KeyAgreement(cert);
            EnvelopedData ed = EnvelopedData.Create(Doc, [recipient], new CmsEncryptOptions { AllowLegacy = scheme == KeyTransportScheme.Pkcs1V15 });
            using CmsDecryptionKey dk = CmsDecryptionKey.FromKey(key, cert);
            try
            {
                Assert.Equal(Doc, ed.Decrypt(dk));
            }
            catch (CmsParseException) when (scheme is KeyTransportScheme.OaepSha256)
            {
                // SoftHSM2 does OAEP with SHA-1 only: a token that refuses the hash cannot open a SHA-256 message, and says so as a decryption failure here.
                Assert.True(session.Slot.Module.Info.Manufacturer.Contains("SoftHSM", StringComparison.Ordinal));
            }
        }
    }

    [Theory]
    [InlineData("rsa-pkcs1", "rsa")]
    [InlineData("rsa-pkcs1", "oaep")]
    [InlineData("p256", "ec")]
    public void AnOpenSslEnvelopedMessageIsOpenedByTheToken(string kind, string how)
    {
        Tools.RequireOpenSsl();
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open();
        using (module)
        using (session)
        {
            (Pkcs11Key key, SignatureSpec spec, KeyUsages usages) = Make(session, kind);
            Certificate cert = TokenCertificates.SelfSigned("token recipient " + kind, (ISigningKey)key, usages, spec);
            string dir = Dir($"env-{kind}-{how}");
            File.WriteAllText(Path.Combine(dir, "cert.pem"), Tools.Pem("CERTIFICATE", cert.Encoded.ToArray()));
            File.WriteAllBytes(Path.Combine(dir, "content.bin"), Doc);
            string[] args = ["cms", "-encrypt", "-aes-256-cbc", "-binary", "-outform", "DER", "-in", Path.Combine(dir, "content.bin"), "-out", Path.Combine(dir, "msg.der")];
            args = how == "oaep" ? [.. args, "-recip", Path.Combine(dir, "cert.pem"), "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha1", "-keyopt", "rsa_mgf1_md:sha1"] : [.. args, Path.Combine(dir, "cert.pem")];
            var r = Tools.Run(Tools.OpenSsl!, null, args);
            Assert.True(r.Code == 0, "openssl cms -encrypt: " + r.Error);
            EnvelopedData ed = EnvelopedData.Parse(File.ReadAllBytes(Path.Combine(dir, "msg.der")));
            using CmsDecryptionKey dk = CmsDecryptionKey.FromKey(key, cert);
            Assert.Equal(Doc, ed.Decrypt(dk, new CmsDecryptOptions()));
        }
    }
}
