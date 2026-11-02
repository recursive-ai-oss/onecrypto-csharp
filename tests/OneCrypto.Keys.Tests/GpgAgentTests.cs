using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Agents;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Keys.Tests;

/// <summary>The gpg-agent backend against a real gpg-agent in a throwaway home: socket discovery, listing, signing, decrypting, agreement and the failure modes.</summary>
public class GpgAgentTests : IClassFixture<GpgAgentFixture>
{
    private readonly GpgAgentFixture _f;

    public GpgAgentTests(GpgAgentFixture fixture)
    {
        _f = fixture;
        fixture.RequireGpg();
    }

    private GpgAgentClient Client(GpgAgentOptions? o = null) => new(o ?? new GpgAgentOptions { HomeDirectory = _f.Home });

    private static PublicKeyInfo X25519Spki(byte[] u) => PublicKeyInfo.Parse(DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(KnownOids.X25519)), DerWriter.Tlv(0x03, [0, .. u])));

    [Fact]
    public void TheSocketIsFoundTheWayGpgconfNamesIt()
    {
        Assert.Equal(_f.ExpectedSocket, GpgAgent.LocateSocket(_f.Home));
        Assert.Equal(_f.ExpectedSocket, Client().SocketPath);
        // The z-base-32 hash of the home path is what names the directory.
        Assert.Contains("d." + GpgAgent.HomeHash(_f.Home), _f.ExpectedSocket, StringComparison.Ordinal);
    }

    [Fact]
    public void ListingReturnsEverySecretKeyWithItsProtection()
    {
        IReadOnlyList<GpgAgentKeyInfo> keys = Client().ListKeys();
        string[] expected = [.. _f.Keys.SelectMany(k => new[] { k.SignGrip, k.EncryptGrip })];
        Assert.Equal(expected.Order(StringComparer.Ordinal), keys.Select(k => k.Keygrip).Order(StringComparer.Ordinal));
        Assert.All(keys.Where(k => k.Keygrip != _f.Key("locked").SignGrip && k.Keygrip != _f.Key("locked").EncryptGrip), k => Assert.Equal(GpgAgentKeyProtection.None, k.Protection));
        Assert.Equal(GpgAgentKeyProtection.Passphrase, keys.Single(k => k.Keygrip == _f.Key("locked").SignGrip).Protection);
        Assert.All(keys, k => Assert.False(k.IsOnToken));
    }

    [Fact]
    public void KeysOpenAsTheTypeThatMatchesTheirAlgorithm()
    {
        GpgAgentClient c = Client();
        using GpgAgentKey rsa = c.GetKey(_f.Key("rsa").SignGrip);
        using GpgAgentKey ec = c.GetKey(_f.Key("p256").SignGrip);
        using GpgAgentKey ed = c.GetKey(_f.Key("ed25519").SignGrip);
        using GpgAgentKey cv = c.GetKey(_f.Key("ed25519").EncryptGrip);
        Assert.IsType<GpgAgentRsaKey>(rsa);
        Assert.IsType<GpgAgentEcKey>(ec);
        Assert.IsType<GpgAgentEdKey>(ed);
        Assert.IsType<GpgAgentMontgomeryKey>(cv);
        Assert.Equal(KeyAlgorithm.Rsa, rsa.PublicKey.KeyAlgorithm);
        Assert.Equal(3072, rsa.PublicKey.KeySizeBits);
        Assert.Equal(KnownOids.P256, ec.PublicKey.CurveOid);
        Assert.Equal(KeyAlgorithm.Ed25519, ed.PublicKey.KeyAlgorithm);
        Assert.Equal(KeyAlgorithm.X25519, cv.PublicKey.KeyAlgorithm);
        Assert.Equal(KeyCapabilities.Sign | KeyCapabilities.Decrypt, rsa.Capabilities);
        // FindKey matches by public key.
        using GpgAgentKey? found = c.FindKey(ec.PublicKey);
        Assert.Equal(ec.Keygrip, found?.Keygrip);
    }

    [Theory]
    [InlineData("SHA1")]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void AnRSAKeySignsPKCS1AndTheBCLVerifies(string hash)
    {
        using var key = (GpgAgentRsaKey)Client().GetKey(_f.Key("rsa").SignGrip);
        var h = new HashAlgorithmName(hash);
        byte[] data = "signed through gpg-agent"u8.ToArray();
        byte[] sig = key.Sign(data, SignatureSpec.RsaPkcs1(h));
        Assert.Equal(384, sig.Length);
        using RSA rsa = key.PublicKey.ToRsa();
#pragma warning disable CA5350 // SHA-1 is one of the digests the agent is asked to sign with.
        Assert.True(rsa.VerifyData(data, sig, h, RSASignaturePadding.Pkcs1));
#pragma warning restore CA5350
        // The digest form gives the same bytes: PKCS #1 v1.5 is deterministic.
        Assert.Equal(sig, key.SignDigest(CryptographicOperations.HashData(h, data), SignatureSpec.RsaPkcs1(h)));
    }

    [Fact]
    public void RSAPSSIsNotOffered()
    {
        using var key = (GpgAgentRsaKey)Client().GetKey(_f.Key("rsa").SignGrip);
        Assert.False(key.Supports(SignatureSpec.RsaPss(HashAlgorithmName.SHA256)));
        Assert.Throws<NotSupportedException>(() => key.Sign([1], SignatureSpec.RsaPss(HashAlgorithmName.SHA256)));
    }

    [Theory]
    [InlineData(EcdsaSignatureFormat.Der)]
    [InlineData(EcdsaSignatureFormat.Rfc4754)]
    public void AP256KeySignsECDSAInEitherEncoding(EcdsaSignatureFormat format)
    {
        using var key = (GpgAgentEcKey)Client().GetKey(_f.Key("p256").SignGrip);
        byte[] data = "ecdsa through the agent"u8.ToArray();
        foreach (string h in new[] { "SHA256", "SHA384", "SHA512" })
        {
            var hash = new HashAlgorithmName(h);
            byte[] sig = key.Sign(data, SignatureSpec.Ecdsa(hash, format));
            using ECDsa ec = key.PublicKey.ToECDsa();
            Assert.True(ec.VerifyData(data, sig, hash, format == EcdsaSignatureFormat.Der ? DSASignatureFormat.Rfc3279DerSequence : DSASignatureFormat.IeeeP1363FixedFieldConcatenation), h);
        }
    }

    [Fact]
    public void AnEd25519KeySignsTheMessageAndOurEd25519Verifies()
    {
        using var key = (GpgAgentEdKey)Client().GetKey(_f.Key("ed25519").SignGrip);
        byte[] pub = key.PublicKey.KeyBits.ToArray();
        foreach (int n in new[] { 0, 1, 64, 2048 })
        {
            byte[] data = RandomNumberGenerator.GetBytes(n);
            byte[] sig = key.Sign(data, SignatureSpec.Ed25519());
            Assert.Equal(64, sig.Length);
            Assert.True(Ed25519.Verify(pub, data, sig), $"{n} octets");
        }

        Assert.Throws<NotSupportedException>(() => key.SignDigest(new byte[32], SignatureSpec.Ed25519()));
    }

    [Fact]
    public void AMessageOverTheInquiryLimitIsATypedLimitError()
    {
        using var key = (GpgAgentEdKey)Client().GetKey(_f.Key("ed25519").SignGrip);
        Assert.Throws<AgentLimitException>(() => key.Sign(new byte[100_000], SignatureSpec.Ed25519()));
        // The agent is still usable afterwards: each operation has its own connection.
        Assert.Equal(64, key.Sign([1, 2, 3], SignatureSpec.Ed25519()).Length);
    }

    [Theory]
    [InlineData("pkcs1", "")]
    [InlineData("oaep", "SHA1")]
    [InlineData("oaep", "SHA256")]
    [InlineData("oaep", "SHA384")]
    [InlineData("oaep", "SHA512")]
    public void AnRSAKeyDecryptsWhatTheBCLEncrypted(string scheme, string hash)
    {
        using var key = (GpgAgentRsaKey)Client().GetKey(_f.Key("rsa").EncryptGrip);
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        using RSA rsa = key.PublicKey.ToRsa();
        DecryptionSpec spec = scheme == "pkcs1" ? DecryptionSpec.RsaPkcs1() : DecryptionSpec.RsaOaep(new HashAlgorithmName(hash));
        byte[] ct = scheme == "pkcs1" ? rsa.Encrypt(secret, RSAEncryptionPadding.Pkcs1) : rsa.Encrypt(secret, RSAEncryptionPadding.CreateOaep(new HashAlgorithmName(hash)));
        Assert.Equal(secret, key.Decrypt(ct, spec));
    }

    [Fact]
    public void ACiphertextThatDoesNotDecryptIsAPlainCryptographicException()
    {
        using var key = (GpgAgentRsaKey)Client().GetKey(_f.Key("rsa").EncryptGrip);
        byte[] junk = RandomNumberGenerator.GetBytes(384);
        junk[0] &= 0x7F;
        Assert.Throws<CryptographicException>(() => key.Decrypt(junk, DecryptionSpec.RsaOaep(HashAlgorithmName.SHA256)));
        Assert.Throws<CryptographicException>(() => key.Decrypt(new byte[10], DecryptionSpec.RsaPkcs1()));
    }

    [Fact]
    public void AP256KeyAgreesLikeTheBCL()
    {
        using var key = (GpgAgentEcKey)Client().GetKey(_f.Key("p256").EncryptGrip);
        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        PublicKeyInfo peerKey = PublicKeyInfo.Parse(peer.ExportSubjectPublicKeyInfo());
        byte[] fromAgent = key.Agree(peerKey);
        using ECDiffieHellman mine = ECDiffieHellman.Create();
        mine.ImportSubjectPublicKeyInfo(key.PublicKey.Encoded.Span, out _);
        Assert.Equal(peer.DeriveRawSecretAgreement(mine.PublicKey), fromAgent);
    }

    [Fact]
    public void ACv25519KeyAgreesLikeOurX25519()
    {
        using var key = (GpgAgentMontgomeryKey)Client().GetKey(_f.Key("ed25519").EncryptGrip);
        byte[] scalar = RandomNumberGenerator.GetBytes(32);
        byte[] u = new byte[32];
        X25519.DerivePublicKey(scalar, u);
        byte[] expected = new byte[32];
        X25519.ScalarMult(scalar, key.PublicKey.KeyBits.Span, expected);
        Assert.Equal(expected, key.Agree(X25519Spki(u)));
        // RFC 7748 §6.1: a low-order peer point gives an all-zero secret, which is refused.
        Assert.Throws<CryptographicException>(() => key.Agree(X25519Spki(new byte[32])));
    }

    [Fact]
    public void AKeyTheAgentDoesNotHaveIsATypedNotFound()
    {
        Assert.Throws<AgentKeyNotFoundException>(() => Client().GetKey(new string('0', 40)));
        Assert.Throws<ArgumentException>(() => Client().GetKey("not a keygrip"));
    }

    [Fact]
    public void AKeyDeletedAfterItWasOpenedIsATypedNotFoundOnUse()
    {
        string name = "gone" + Guid.NewGuid().ToString("N")[..6];
        Assert.Equal(0, _f.GpgRun(null, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", name + "@onecrypto.invalid", "ed25519", "sign", "never").Code);
        (int _, byte[] listing, string _) = _f.GpgRun(null, "--list-secret-keys", "--with-colons", "--with-keygrip", name);
        string grip = Tools.Text(listing).Split('\n').First(l => l.StartsWith("grp:", StringComparison.Ordinal)).Split(':')[9];
        GpgAgentClient c = Client();
        using var key = (GpgAgentEdKey)c.GetKey(grip);
        Assert.Equal(64, key.Sign([1], SignatureSpec.Ed25519()).Length);
        Assert.Equal(0, _f.ConnectAgent("DELETE_KEY --force " + grip).Code);
        Assert.Throws<AgentKeyNotFoundException>(() => key.Sign([1], SignatureSpec.Ed25519()));
    }

    [Fact]
    public void NoAgentOnTheSocketIsATypedUnavailableErrorNamingTheSocket()
    {
        string dir = Tools.ShortTemp("none");
        string sock = Path.Combine(dir, "S.nothing");
        var e = Assert.Throws<AgentUnavailableException>(() => new GpgAgentClient(new GpgAgentOptions { SocketPath = sock }).ListKeys());
        Assert.Equal(sock, e.SocketPath);
        // No socket anywhere for a home nobody runs an agent in.
        Assert.Null(GpgAgent.LocateSocket(Path.Combine(dir, "nohome")));
        Assert.Throws<AgentUnavailableException>(() => new GpgAgentClient(new GpgAgentOptions { HomeDirectory = Path.Combine(dir, "nohome") }).ListKeys());
        Directory.Delete(dir, true);
    }

    [Fact]
    public void APassphraseProtectedKeyGoesThroughTheAgentsOwnPrompt()
    {
        string grip = _f.Key("locked").SignGrip;
        var client = Client();
        using var key = (GpgAgentRsaKey)client.GetKey(grip, "Sign a test document");
        byte[] data = [1, 2, 3];
        try
        {
            // The user cancels the prompt: a typed refusal that says so.
            _f.SetPinentry("cancel");
            var cancelled = Assert.Throws<AgentRefusedException>(() => key.Sign(data, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)));
            Assert.True(cancelled.IsCancelled, cancelled.Message);

            // A wrong passphrase.
            _f.SetPinentry("not the passphrase");
            var wrong = Assert.Throws<AgentRefusedException>(() => key.Sign(data, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)));
            Assert.True(wrong.IsBadPassphrase, wrong.Message);

            // The right one: the signature verifies, and the agent caches the passphrase so the next call needs no prompt.
            _f.SetPinentry("onecrypto-test");
            byte[] sig = key.Sign(data, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256));
            using RSA rsa = key.PublicKey.ToRsa();
            Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            _f.SetPinentry("cancel");
            Assert.Equal(sig, key.Sign(data, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)));
        }
        finally
        {
            _f.Gpgconf("--reload", "gpg-agent");
            _f.SetPinentry("onecrypto-test");
        }
    }

    [Fact]
    public void CancellingTheTokenWhileTheAgentWaitsForTheUserEndsTheCall()
    {
        using var key = (GpgAgentRsaKey)Client().GetKey(_f.Key("locked").SignGrip);
        try
        {
            _f.Gpgconf("--reload", "gpg-agent");
            _f.SetPinentry("hang");
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            Assert.ThrowsAny<OperationCanceledException>(() => key.SignAsync(new byte[] { 1 }, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256), cts.Token).AsTask().GetAwaiter().GetResult());
        }
        finally
        {
            _f.SetPinentry("onecrypto-test");
            _f.Gpgconf("--reload", "gpg-agent");
        }
    }

    [Fact]
    public void TheOperationTimeoutAppliesWhenThePromptNeverReturns()
    {
        var client = Client(new GpgAgentOptions { HomeDirectory = _f.Home, OperationTimeout = TimeSpan.FromSeconds(1) });
        using var key = (GpgAgentRsaKey)client.GetKey(_f.Key("locked").SignGrip);
        try
        {
            _f.Gpgconf("--reload", "gpg-agent");
            _f.SetPinentry("hang");
            Assert.Throws<AgentUnavailableException>(() => key.Sign([1], SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)));
        }
        finally
        {
            _f.SetPinentry("onecrypto-test");
            _f.Gpgconf("--reload", "gpg-agent");
        }
    }
}
