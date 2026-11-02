using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Pkcs11;
using RecursiveAI.OneCrypto.OpenPgp;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace OneCrypto.Keys.Tests;

/// <summary>An external key must be the private half of the key packet it is attached to; a mismatch is refused when the wrapper is made.</summary>
public class ExternalKeyPairingTests
{
    private sealed class PublicOnly(PublicKeyInfo pub) : IKey
    {
        public PublicKeyInfo PublicKey => pub;

        public KeyCapabilities Capabilities => KeyCapabilities.None;

        public void Dispose()
        {
        }
    }

    private static PgpCertificate Cert(PgpKeyProfile profile) =>
        PgpKeyGenerator.Generate(new PgpKeyGenerationOptions { Now = new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero), UserIds = ["P <p@example.org>"], Profile = profile });

    private static PublicKeyInfo Raw(string oid, byte[] key) =>
        PublicKeyInfo.Parse(DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(oid)), DerWriter.Tlv(0x03, [0, .. key])));

    private static PublicKeyInfo Rsa(PgpKey key)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = key.Packet.Material.Values[0].ToArray(), Exponent = key.Packet.Material.Values[1].ToArray() });
        return PublicKeyInfo.Parse(rsa.ExportSubjectPublicKeyInfo());
    }

    private static PublicKeyInfo Ec(PgpKey key)
    {
        ReadOnlySpan<byte> q = key.Packet.Material.Values[0].Span;
        int size = (q.Length - 1) / 2;
        ECCurve curve = size switch { 32 => ECCurve.NamedCurves.nistP256, 48 => ECCurve.NamedCurves.nistP384, _ => ECCurve.NamedCurves.nistP521 };
        using var ec = ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = q.Slice(1, size).ToArray(), Y = q.Slice(1 + size, size).ToArray() } });
        return PublicKeyInfo.FromAsymmetricAlgorithm(ec);
    }

    private static void Mismatch(PgpKey key, PublicKeyInfo other) =>
        Assert.Equal(PgpFailure.KeyMismatch, Assert.Throws<PgpException>(() => PgpSecretKey.FromExternalKey(key, new PublicOnly(other))).Failure);

    [Fact]
    public void RsaKeysPairByModulusAndExponent()
    {
        PgpCertificate c = Cert(PgpKeyProfile.Rfc4880Rsa);
        PgpKey key = c.Keys[0];
        PgpSecretKey.FromExternalKey(key, new PublicOnly(Rsa(key))).Dispose();
        using var other = RSA.Create(3072);
        Mismatch(key, PublicKeyInfo.Parse(other.ExportSubjectPublicKeyInfo()));
        // Another key's modulus, or the same modulus with another exponent, is no match either.
        using var sameN = RSA.Create();
        sameN.ImportParameters(new RSAParameters { Modulus = key.Packet.Material.Values[0].ToArray(), Exponent = [3] });
        Mismatch(key, PublicKeyInfo.Parse(sameN.ExportSubjectPublicKeyInfo()));
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Mismatch(key, PublicKeyInfo.FromAsymmetricAlgorithm(ec));
    }

    [Fact]
    public void EcdsaAndEcdhKeysPairByCurveAndPoint()
    {
        PgpCertificate c = Cert(PgpKeyProfile.NistP256);
        foreach (PgpKey key in new[] { c.Keys[0], c.Keys[1] })
        {
            PgpSecretKey.FromExternalKey(key, new PublicOnly(Ec(key))).Dispose();
            using var otherPoint = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Mismatch(key, PublicKeyInfo.FromAsymmetricAlgorithm(otherPoint));
            using var otherCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            Mismatch(key, PublicKeyInfo.FromAsymmetricAlgorithm(otherCurve));
            Mismatch(key, Raw("1.3.101.112", RandomNumberGenerator.GetBytes(32)));
        }
    }

    [Fact]
    public void Ed25519AndX25519KeysPairByKey()
    {
        PgpCertificate c = Cert(PgpKeyProfile.Rfc9580);
        PgpKey ed = c.Keys[0], x = c.Keys[1];
        PgpSecretKey.FromExternalKey(ed, new PublicOnly(Raw("1.3.101.112", ed.Packet.Material.Values[0].ToArray()))).Dispose();
        PgpSecretKey.FromExternalKey(x, new PublicOnly(Raw("1.3.101.110", x.Packet.Material.Values[0].ToArray()))).Dispose();
        Mismatch(ed, Raw("1.3.101.112", RandomNumberGenerator.GetBytes(32)));
        Mismatch(x, Raw("1.3.101.110", RandomNumberGenerator.GetBytes(32)));
        // The right bytes under the wrong algorithm.
        Mismatch(ed, Raw("1.3.101.110", ed.Packet.Material.Values[0].ToArray()));
        Mismatch(x, Raw("1.3.101.112", x.Packet.Material.Values[0].ToArray()));
    }

    [Fact]
    public void TheLegacyCurve25519FormsPairWithoutTheirPrefix()
    {
        PgpCertificate c = Cert(PgpKeyProfile.Rfc4880Curve25519);
        PgpKey ed = c.Keys[0], x = c.Keys[1];
        PgpSecretKey.FromExternalKey(ed, new PublicOnly(Raw("1.3.101.112", ed.Packet.Material.Values[0].ToArray()[1..]))).Dispose();
        PgpSecretKey.FromExternalKey(x, new PublicOnly(Raw("1.3.101.110", x.Packet.Material.Values[0].ToArray()[1..]))).Dispose();
        Mismatch(ed, Raw("1.3.101.112", RandomNumberGenerator.GetBytes(32)));
        Mismatch(x, Raw("1.3.101.110", RandomNumberGenerator.GetBytes(32)));
    }

    [Fact]
    public void ATokenKeyOfAnotherCertificateIsRefused()
    {
        Pkcs11PgpTests.Imported mine = Pkcs11PgpTests.Import(PgpKeyProfile.NistP256, out string run);
        Pkcs11PgpTests.Imported other = Pkcs11PgpTests.Import(PgpKeyProfile.NistP256, out string otherRun);
        (Pkcs11Module module, Pkcs11Session session) = SoftHsm.Open("u-import");
        using (module)
        using (session)
        {
            Pkcs11Key token = Pkcs11PgpTests.Open(session, mine, run, 0);
            PgpSecretKey.FromExternalKey(mine.Public.Primary, token).Dispose();
            Mismatch(other.Public.Primary, token.PublicKey);

            // F2 on the token backend: a scheme the platform cannot verify is refused unless the session opts out.
            session.SimulateVerificationGap = true;
            byte[] digest = SHA256.HashData([1, 2, 3]);
            SignatureSpec spec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
            var signer = (ISigningKey)token;
            Assert.Throws<AlgorithmNotSupportedException>(() => signer.SignDigest(digest, spec));
            session.AllowUncheckedSignatures = true;
            byte[] sig = signer.SignDigest(digest, spec);
            Assert.True(spec.VerifyDigest(token.PublicKey, digest, sig).IsValid);
        }
    }
}
