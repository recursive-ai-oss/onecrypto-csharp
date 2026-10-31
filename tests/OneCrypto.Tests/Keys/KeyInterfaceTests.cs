using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Keys;

public class KeyInterfaceTests
{
    private static readonly byte[] Message = "the message to sign"u8.ToArray();

    private static void RoundTrip(ISigningKey key, SignatureSpec spec)
    {
        Assert.True(key.Supports(spec));
        byte[] sig = key.Sign(Message, spec);
        Assert.True(spec.Verify(key.PublicKey, Message, sig).IsValid, spec.ToString());
        byte[] bad = (byte[])Message.Clone();
        bad[0] ^= 1;
        Assert.False(spec.Verify(key.PublicKey, bad, sig).IsValid);
        if (spec.SignsDigest)
        {
            byte[] viaDigest = key.SignDigest(CryptographicOperations.HashData(spec.Hash, Message), spec);
            Assert.True(spec.Verify(key.PublicKey, Message, viaDigest).IsValid);
        }
    }

    [Theory]
    [InlineData(false, "SHA256")]
    [InlineData(false, "SHA384")]
    [InlineData(false, "SHA512")]
    [InlineData(true, "SHA256")]
    [InlineData(true, "SHA384")]
    public async Task RsaSignsAndDecrypts(bool pss, string hash)
    {
        using RSA rsa = RSA.Create(2048);
        using IRsaKey key = PrivateKey.FromRsa(rsa);
        var h = new HashAlgorithmName(hash);
        SignatureSpec spec = pss ? SignatureSpec.RsaPss(h) : SignatureSpec.RsaPkcs1(h);
        RoundTrip(key, spec);
        byte[] async = await key.SignAsync(Message, spec);
        Assert.True(spec.Verify(key.PublicKey, Message, async).IsValid);

        byte[] secret = RandomNumberGenerator.GetBytes(32);
        byte[] oaep = rsa.Encrypt(secret, RSAEncryptionPadding.OaepSHA256);
        Assert.Equal(secret, key.Decrypt(oaep, DecryptionSpec.RsaOaep(HashAlgorithmName.SHA256)));
        byte[] v15 = rsa.Encrypt(secret, RSAEncryptionPadding.Pkcs1);
        Assert.Equal(secret, await key.DecryptAsync(v15, DecryptionSpec.RsaPkcs1()));
        Assert.ThrowsAny<CryptographicException>(() => key.Decrypt(oaep, DecryptionSpec.RsaOaep(HashAlgorithmName.SHA384)));
    }

    [Theory]
    [InlineData("nistP256", "SHA256", false)]
    [InlineData("nistP256", "SHA256", true)]
    [InlineData("nistP384", "SHA384", false)]
    [InlineData("nistP384", "SHA384", true)]
    [InlineData("nistP521", "SHA512", false)]
    [InlineData("nistP521", "SHA512", true)]
    public void EcdsaSignsDerAndP1363(string curve, string hash, bool p1363)
    {
        using ECDsa ec = ECDsa.Create(ECCurve.CreateFromFriendlyName(curve));
        using ISigningKey key = PrivateKey.FromECDsa(ec);
        var spec = SignatureSpec.Ecdsa(new HashAlgorithmName(hash), p1363 ? EcdsaSignatureFormat.Rfc4754 : EcdsaSignatureFormat.Der);
        RoundTrip(key, spec);
        byte[] sig = key.Sign(Message, spec);
        int size = (key.PublicKey.KeySizeBits + 7) / 8;
        Assert.Equal(p1363, sig.Length == 2 * size);
    }

    [Fact]
    public void EdDsaSignsWithTheLibrarysKeys()
    {
        using Ed25519PrivateKey e = Ed25519PrivateKey.Generate();
        using ISigningKey k = PrivateKey.FromEd25519(e);
        RoundTrip(k, SignatureSpec.Ed25519());
        Assert.False(k.Supports(SignatureSpec.Ed448()));
        Assert.Throws<NotSupportedException>(() => k.SignDigest(new byte[64], SignatureSpec.Ed25519()));

        using Ed448PrivateKey e4 = Ed448PrivateKey.Generate();
        using ISigningKey k4 = PrivateKey.FromEd448(e4);
        RoundTrip(k4, SignatureSpec.Ed448());
        SignatureSpec withContext = SignatureSpec.Ed448("ctx"u8);
        RoundTrip(k4, withContext);
        Assert.False(SignatureSpec.Ed448().Verify(k4.PublicKey, Message, k4.Sign(Message, withContext)).IsValid);
    }

    [Fact]
    public void MlDsaSignsWithAndWithoutContext()
    {
        Assert.SkipUnless(MLDsa.IsSupported, "ML-DSA is not available on this platform");
        using MLDsa m = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using ISigningKey k = PrivateKey.FromMLDsa(m);
        RoundTrip(k, SignatureSpec.MlDsa());
        RoundTrip(k, SignatureSpec.MlDsa("c"u8));
        Assert.False(SignatureSpec.MlDsa().Verify(k.PublicKey, Message, k.Sign(Message, SignatureSpec.MlDsa("c"u8))).IsValid);
    }

    [Fact]
    public void AgreementWorksForEcdhX25519AndX448()
    {
        using ECDiffieHellman a = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using ECDiffieHellman b = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using IAgreementKey ka = PrivateKey.FromECDiffieHellman(a);
        using IAgreementKey kb = PrivateKey.FromECDiffieHellman(b);
        Assert.Equal(ka.Agree(kb.PublicKey), kb.Agree(ka.PublicKey));
        Assert.Equal(ka.Agree(kb.PublicKey), a.DeriveRawSecretAgreement(b.PublicKey));

        using X25519PrivateKey xa = X25519PrivateKey.Generate();
        using X25519PrivateKey xb = X25519PrivateKey.Generate();
        using IAgreementKey x1 = PrivateKey.FromX25519(xa);
        using IAgreementKey x2 = PrivateKey.FromX25519(xb);
        Assert.Equal(x1.Agree(x2.PublicKey), x2.Agree(x1.PublicKey));
        Assert.Throws<ArgumentException>(() => x1.Agree(ka.PublicKey));

        using X448PrivateKey ya = X448PrivateKey.Generate();
        using X448PrivateKey yb = X448PrivateKey.Generate();
        using IAgreementKey y1 = PrivateKey.FromX448(ya);
        using IAgreementKey y2 = PrivateKey.FromX448(yb);
        Assert.Equal(y1.Agree(y2.PublicKey), y2.Agree(y1.PublicKey));
        Assert.Throws<ArgumentException>(() => ka.Agree(x2.PublicKey));
    }

    [Fact]
    public async Task MlKemDecapsulates()
    {
        Assert.SkipUnless(MLKem.IsSupported, "ML-KEM is not available on this platform");
        using MLKem kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        using IDecryptionKey key = PrivateKey.FromMLKem(kem);
        Assert.Equal(KeyAlgorithm.MlKem, key.PublicKey.KeyAlgorithm);
        kem.Encapsulate(out byte[] ciphertext, out byte[] secret);
        Assert.Equal(secret, await key.DecryptAsync(ciphertext, DecryptionSpec.MlKem()));
    }

    [Fact]
    public void OwnershipAndDisposal()
    {
        using RSA rsa = RSA.Create(2048);
        IRsaKey borrowed = PrivateKey.FromRsa(rsa);
        borrowed.Dispose();
        _ = rsa.SignData(Message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // still usable: the caller owns it
        IRsaKey owned = PrivateKey.FromRsa(RSA.Create(2048), ownsKey: true);
        owned.Dispose();
        Assert.Throws<ObjectDisposedException>(() => owned.Sign(Message, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)));
    }

    [Fact]
    public void UnsupportedSpecsAreRefusedByName()
    {
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ISigningKey k = PrivateKey.FromECDsa(ec);
        Assert.False(k.Supports(SignatureSpec.RsaPss(HashAlgorithmName.SHA256)));
        Assert.Throws<NotSupportedException>(() => k.Sign(Message, SignatureSpec.Ed25519()));
        Assert.Throws<ArgumentException>(() => SignatureSpec.RsaPkcs1(HashAlgorithmName.MD5));
        Assert.Throws<ArgumentException>(() => SignatureSpec.Ed448(new byte[256]));
    }

    [Fact]
    public void P1363SignatureOfTheWrongLengthIsRefusedWithAReason()
    {
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ISigningKey k = PrivateKey.FromECDsa(ec);
        SignatureVerification v = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256, EcdsaSignatureFormat.Rfc4754).Verify(k.PublicKey, Message, new byte[63]);
        Assert.Equal(SignatureStatus.Invalid, v.Status);
        Assert.NotEmpty(v.Reason);
    }

    // ---- verified by openssl ----

    private static string Pem(string label, byte[] der) => PemCodec.Write(label, der);

    [Fact]
    public void OpenSslVerifiesRsaAndEcdsaSignatures()
    {
        OpenSslTool.RequireOrSkip();
        string dir = OpenSslTool.TempDir("keys-rsa-ec");
        File.WriteAllBytes(Path.Combine(dir, "msg"), Message);
        using RSA rsa = RSA.Create(2048);
        using ISigningKey rk = PrivateKey.FromRsa(rsa);
        File.WriteAllText(Path.Combine(dir, "rsa.pub"), Pem("PUBLIC KEY", rk.PublicKey.Encoded.ToArray()));
        File.WriteAllBytes(Path.Combine(dir, "rsa1.sig"), rk.Sign(Message, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)));
        File.WriteAllBytes(Path.Combine(dir, "rsa2.sig"), rk.Sign(Message, SignatureSpec.RsaPss(HashAlgorithmName.SHA384)));
        (int c1, string o1) = OpenSslTool.RunIn(dir, "dgst", "-sha256", "-verify", "rsa.pub", "-signature", "rsa1.sig", "msg");
        Assert.True(c1 == 0, o1);
        (int c2, string o2) = OpenSslTool.RunIn(dir, "dgst", "-sha384", "-verify", "rsa.pub", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:-1", "-signature", "rsa2.sig", "msg");
        Assert.True(c2 == 0, o2);

        foreach ((string curve, string hash) in new[] { ("nistP256", "sha256"), ("nistP384", "sha384"), ("nistP521", "sha512") })
        {
            using ECDsa ec = ECDsa.Create(ECCurve.CreateFromFriendlyName(curve));
            using ISigningKey ek = PrivateKey.FromECDsa(ec);
            File.WriteAllText(Path.Combine(dir, "ec.pub"), Pem("PUBLIC KEY", ek.PublicKey.Encoded.ToArray()));
            File.WriteAllBytes(Path.Combine(dir, "ec.sig"), ek.Sign(Message, SignatureSpec.Ecdsa(new HashAlgorithmName(hash.ToUpperInvariant()))));
            (int c, string o) = OpenSslTool.RunIn(dir, "dgst", "-" + hash, "-verify", "ec.pub", "-signature", "ec.sig", "msg");
            Assert.True(c == 0, curve + ": " + o);
        }
    }

    [Fact]
    public void OpenSslVerifiesEdDsaAndMlDsaSignatures()
    {
        OpenSslTool.RequireOrSkip();
        string dir = OpenSslTool.TempDir("keys-ed");
        File.WriteAllBytes(Path.Combine(dir, "msg"), Message);
        using Ed25519PrivateKey e = Ed25519PrivateKey.Generate();
        using ISigningKey k25 = PrivateKey.FromEd25519(e);
        using Ed448PrivateKey e4 = Ed448PrivateKey.Generate();
        using ISigningKey k448 = PrivateKey.FromEd448(e4);
        var cases = new List<(string Name, ISigningKey Key, SignatureSpec Spec)> { ("ed25519", k25, SignatureSpec.Ed25519()), ("ed448", k448, SignatureSpec.Ed448()) };
        MLDsa? ml = null;
        ISigningKey? mlKey = null;
        if (MLDsa.IsSupported && OpenSslTool.Has("ML-DSA-65"))
        {
            ml = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
            mlKey = PrivateKey.FromMLDsa(ml);
            cases.Add(("mldsa65", mlKey, SignatureSpec.MlDsa()));
        }

        try
        {
            foreach ((string name, ISigningKey key, SignatureSpec spec) in cases)
            {
                File.WriteAllText(Path.Combine(dir, name + ".pub"), Pem("PUBLIC KEY", key.PublicKey.Encoded.ToArray()));
                File.WriteAllBytes(Path.Combine(dir, name + ".sig"), key.Sign(Message, spec));
                (int c, string o) = OpenSslTool.RunIn(dir, "pkeyutl", "-verify", "-pubin", "-inkey", name + ".pub", "-rawin", "-in", "msg", "-sigfile", name + ".sig");
                Assert.True(c == 0, name + ": " + o);
            }
        }
        finally
        {
            mlKey?.Dispose();
            ml?.Dispose();
        }
    }
}
