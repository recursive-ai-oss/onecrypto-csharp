using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Pkcs11;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Keys.Tests;

/// <summary>Regression tests for the key-backend glue review (docs/key-backend-review.md): what happens with answers that backends should never give.</summary>
public class KeyBackendGlueTests
{
    private sealed class FixedAgreement(PublicKeyInfo pub, byte[] answer) : IAgreementKey
    {
        public PublicKeyInfo PublicKey => pub;

        public KeyCapabilities Capabilities => KeyCapabilities.Agree;

        public byte[] Agree(PublicKeyInfo peer) => (byte[])answer.Clone();

        public void Dispose()
        {
        }
    }

    private sealed class ScriptedDecryptor(PublicKeyInfo pub, Func<byte[]> answer) : IDecryptionKey
    {
        public PublicKeyInfo PublicKey => pub;

        public KeyCapabilities Capabilities => KeyCapabilities.Decrypt;

        public bool Supports(DecryptionSpec spec) => true;

        public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, DecryptionSpec spec) => answer();

        public void Dispose()
        {
        }
    }

    private static PublicKeyInfo RsaPublicOf(PgpKey key)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = key.Packet.Material.Values[0].ToArray(), Exponent = key.Packet.Material.Values[1].ToArray() });
        return PublicKeyInfo.Parse(rsa.ExportSubjectPublicKeyInfo());
    }

    private sealed class LockedTokenException() : CryptographicException("the token is locked");

    private static (PgpCertificate Cert, byte[] Message) RsaMessage()
    {
        var now = new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
        PgpCertificate secret = PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = now, UserIds = ["R <r@example.org>"], Profile = PgpKeyProfile.Rfc4880Rsa });
        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream("hello"u8.ToArray()), enc, new PgpWriteOptions { Now = now, Recipients = [secret.ToPublicCertificate()] });
        return (secret, enc.ToArray());
    }

    private static PgpException ReadFails(PgpCertificate cert, byte[] message, Func<byte[]> answer)
    {
        PgpCertificate pub = cert.ToPublicCertificate();
        using PgpSecretKey ext = PgpSecretKey.FromExternalKey(pub.Keys[1], new ScriptedDecryptor(RsaPublicOf(pub.Keys[1]), answer));
        var options = new PgpReadOptions { Now = new DateTimeOffset(2026, 6, 1, 12, 1, 0, TimeSpan.Zero), ExternalKeys = [ext] };
        return Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(message), new MemoryStream(), options));
    }

    // ---- K2: a key elsewhere that cannot use the ciphertext gives the one failure; its own trouble is not blamed on the message ----

    [Fact]
    public void EveryWayAnExternalRsaKeyRefusesACiphertextIsTheSameFailureAsABadBody()
    {
        (PgpCertificate cert, byte[] message) = RsaMessage();
        byte[] tampered = (byte[])message.Clone();
        tampered[^1] ^= 1;
        PgpException body = ReadFails(cert, tampered, () => throw new CryptographicException("x"));
        Assert.Equal(PgpFailure.CannotDecrypt, body.Failure);

        // A refusal, a plaintext of the wrong shape, an empty one, a short one, a long one: all the same failure and the same words.
        Func<byte[]>[] answers =
        [
            () => throw new CryptographicException("padding"),
            () => throw new ArgumentException("length"),
            () => [],
            () => [1, 2, 3],
            () => RandomNumberGenerator.GetBytes(24),
            () => RandomNumberGenerator.GetBytes(300),
        ];
        foreach (Func<byte[]> a in answers)
        {
            PgpException e = ReadFails(cert, message, a);
            Assert.Equal(PgpFailure.CannotDecrypt, e.Failure);
            Assert.Equal(body.Message, e.Message);
        }
    }

    [Fact]
    public void ALockedTokenIsNotReportedAsAnUndecryptableMessage()
    {
        (PgpCertificate cert, byte[] message) = RsaMessage();
        PgpCertificate pub = cert.ToPublicCertificate();
        using PgpSecretKey ext = PgpSecretKey.FromExternalKey(pub.Keys[1], new ScriptedDecryptor(RsaPublicOf(pub.Keys[1]), () => throw new LockedTokenException()));
        var options = new PgpReadOptions { Now = new DateTimeOffset(2026, 6, 1, 12, 1, 0, TimeSpan.Zero), ExternalKeys = [ext] };
        Assert.Throws<LockedTokenException>(() => PgpMessageReader.Read(new MemoryStream(message), new MemoryStream(), options));
    }

    // ---- K1: a token's signature is checked before it is released ----

    [Fact]
    public void ATokenSignatureThatDoesNotVerifyIsNeverReleased()
    {
        using ISigningKey ed = PrivateKey.FromEd25519(Ed25519PrivateKey.FromSeed(RandomNumberGenerator.GetBytes(32)), ownsKey: true);
        var key = new Pkcs11EdKey(null!, 0, "k", [], ed.PublicKey, true, false);
        SignatureSpec spec = SignatureSpec.Ed25519();
        byte[] data = RandomNumberGenerator.GetBytes(100);
        byte[] good = ed.Sign(data, spec);
        Assert.Equal(good, key.Checked(spec, data, false, good));

        byte[] bad = (byte[])good.Clone();
        bad[10] ^= 1;
        Assert.Throws<Pkcs11Exception>(() => key.Checked(spec, data, false, bad));
        Assert.Throws<Pkcs11Exception>(() => key.Checked(spec, data, false, good[..63]));
        Assert.Throws<Pkcs11Exception>(() => key.Checked(spec, RandomNumberGenerator.GetBytes(100), false, good));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ATokenEcdsaSignatureIsCheckedInBothEncodings(bool der)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ISigningKey signer = PrivateKey.FromECDsa(ec, ownsKey: false);
        var key = new Pkcs11EcKey(null!, 0, "k", [], signer.PublicKey, true, false, false);
        SignatureSpec spec = der ? SignatureSpec.Ecdsa(HashAlgorithmName.SHA256) : SignatureSpec.Ecdsa(HashAlgorithmName.SHA256, EcdsaSignatureFormat.Rfc4754);
        byte[] digest = SHA256.HashData([1, 2, 3]);
        byte[] sig = signer.SignDigest(digest, spec);
        Assert.Equal(sig, key.Checked(spec, digest, true, sig));
        byte[] bad = (byte[])sig.Clone();
        bad[^1] ^= 0x80;
        Assert.Throws<Pkcs11Exception>(() => key.Checked(spec, digest, true, bad));
    }

    // ---- K3: an all-zero agreement result from a key elsewhere is refused (RFC 7748 §6.1) ----

    [Fact]
    public void AnAllZeroX25519ResultFromAnExternalKeyIsRefused()
    {
        using X25519PrivateKey x = X25519PrivateKey.Generate();
        using IAgreementKey real = PrivateKey.FromX25519(x, ownsKey: false);
        var zero = new FixedAgreement(real.PublicKey, new byte[32]);
        Assert.Throws<CryptographicException>(() => SessionKeys.ExternalAgree(zero, new byte[32]));

        var fine = new FixedAgreement(real.PublicKey, RandomNumberGenerator.GetBytes(32));
        Assert.Equal(32, SessionKeys.ExternalAgree(fine, new byte[32]).Length);
    }

    [Fact]
    public void AnAllZeroX448ResultFromAnExternalKeyIsRefused()
    {
        using X448PrivateKey x = X448PrivateKey.Generate();
        using IAgreementKey real = PrivateKey.FromX448(x, ownsKey: false);
        var zero = new FixedAgreement(real.PublicKey, new byte[56]);
        Assert.Throws<CryptographicException>(() => SessionKeys.ExternalAgree(zero, new byte[56]));
    }
}
