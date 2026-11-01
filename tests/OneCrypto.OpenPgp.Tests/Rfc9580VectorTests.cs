using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>The sample objects of RFC 9580 Appendix A, extracted by tools/extract-rfc9580-vectors.py.</summary>
public class Rfc9580VectorTests
{
    public static TheoryData<string> Files() => new(Directory.GetFiles(TestFiles.OpenPgp("rfc9580"), "*.asc").Select(Path.GetFileName).OfType<string>().Where(f => !f.Contains("cleartext", StringComparison.Ordinal)).Order());

    [Theory]
    [MemberData(nameof(Files))]
    public void EverySampleParsesAndWritesBackIdentically(string file)
    {
        byte[] binary = TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", file));
        IReadOnlyList<Packet> packets = PacketParser.ParseAll(binary);
        Assert.NotEmpty(packets);
        using var ms = new MemoryStream();
        PacketParser.Write(packets, ms);
        Assert.Equal(binary, ms.ToArray());
        Assert.DoesNotContain(packets, p => p is UnrecognizedPacket);
    }

    [Fact]
    public void TheV4Ed25519LegacyKeyHasThePublishedFingerprint()
    {
        byte[] binary = TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_1.asc"));
        var key = Assert.IsType<PublicKeyPacket>(PacketParser.ParseAll(binary).Single());
        Assert.Equal(4, key.Version);
        Assert.Equal(PublicKeyAlgorithm.EdDsaLegacy, key.Algorithm);
        Assert.Equal("C959BDBAFA32A2F89A153B678CFDE12197965A9A", key.FingerprintHex);
        Assert.Equal("8CFDE12197965A9A", key.KeyIdHex);
        Assert.Equal(Convert.FromHexString("2b06010401da470f01"), key.Material.CurveOid.ToArray());
    }

    [Fact]
    public void TheV6CertificateHasThePublishedFingerprintsAndStructure()
    {
        byte[] binary = TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_3.asc"));
        TransferableKey key = TransferableKey.Parse(PacketParser.ParseAll(binary));
        Assert.False(key.IsSecret);
        Assert.Equal(6, key.Primary.Version);
        Assert.Equal(PublicKeyAlgorithm.Ed25519, key.Primary.Algorithm);
        Assert.Equal("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9", key.Primary.FingerprintHex);
        Assert.Equal("CB186C4F0609A697", key.Primary.KeyIdHex);
        SubkeyComponent sub = Assert.Single(key.Subkeys);
        Assert.Equal("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885", sub.Key.FingerprintHex);
        Assert.Equal(PublicKeyAlgorithm.X25519, sub.Key.Algorithm);
        SignaturePacket direct = Assert.Single(key.DirectSignatures);
        Assert.Equal(6, direct.Version);
        Assert.Equal(SignatureType.DirectKey, direct.Type);
        Assert.Equal(32, direct.IssuerFingerprint!.Value.Length - 1);
        Assert.Equal(SignatureType.SubkeyBinding, Assert.Single(sub.Signatures).Type);
        Assert.NotNull(direct.KeyFlags);
        Assert.Empty(key.Users);
    }

    [Fact]
    public void ASecretKeyGivesTheSameCertificateWhenMadePublic()
    {
        TransferableKey secret = TransferableKey.Parse(PacketParser.ParseAll(TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_4.asc"))));
        Assert.True(secret.IsSecret);
        var sk = Assert.IsType<SecretKeyPacket>(secret.Primary);
        Assert.False(sk.Protection.IsProtected);
        TransferableKey pub = secret.ToPublic();
        TransferableKey cert = TransferableKey.Parse(PacketParser.ParseAll(TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_3.asc"))));
        using var a = new MemoryStream();
        using var b = new MemoryStream();
        pub.WriteTo(a, canonical: true);
        cert.WriteTo(b, canonical: true);
        Assert.Equal(b.ToArray(), a.ToArray());
    }

    [Fact]
    public void ALockedV6KeyDescribesItsProtection()
    {
        TransferableKey key = TransferableKey.Parse(PacketParser.ParseAll(TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_5.asc"))));
        var sk = Assert.IsType<SecretKeyPacket>(key.Primary);
        Assert.True(sk.Protection.IsProtected);
        Assert.Equal(253, sk.Protection.Usage);
        Assert.Equal(AeadAlgorithm.Ocb, sk.Protection.Aead);
        Assert.Equal(S2kType.Argon2, sk.Protection.S2k!.Type);
        Assert.Equal(15, sk.Protection.Iv.Length);
    }

    [Fact]
    public void TheV6EncryptedMessagesExposeTheirSessionKeyPackets()
    {
        var a8 = PacketParser.ParseAll(TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_8_5.asc")));
        var pkesk = Assert.IsType<PublicKeyEncryptedSessionKeyPacket>(a8[0]);
        Assert.Equal(6, pkesk.Version);
        Assert.Equal(PublicKeyAlgorithm.X25519, pkesk.Algorithm);
        Assert.Equal(32, pkesk.RecipientFingerprint.Length);
        var seipd = Assert.IsType<SymmetricallyEncryptedIntegrityProtectedDataPacket>(a8[1]);
        Assert.Equal(2, seipd.Fields.Version);
        Assert.Equal(AeadAlgorithm.Ocb, seipd.Fields.Aead);
        Assert.Equal(32, seipd.Fields.Salt.Length);
        var skesk = Assert.IsType<SymmetricKeyEncryptedSessionKeyPacket>(PacketParser.ParseAll(TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_10_5.asc")))[0]);
        Assert.Equal(6, skesk.Version);
        Assert.Equal(AeadAlgorithm.Ocb, skesk.Aead);
        var argon = Assert.IsType<SymmetricKeyEncryptedSessionKeyPacket>(PacketParser.ParseAll(TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_12_1.asc")))[0]);
        Assert.Equal(4, argon.Version);
        Assert.Equal(S2kType.Argon2, argon.S2k.Type);
    }

    [Fact]
    public void TheInlineSignedSampleHasOnePassSignatureLiteralAndSignature()
    {
        var packets = PacketParser.ParseAll(TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_7.asc")));
        Assert.Equal([PacketTag.OnePassSignature, PacketTag.LiteralData, PacketTag.Signature], packets.Select(p => p.Tag));
        var ops = (OnePassSignaturePacket)packets[0];
        Assert.Equal(6, ops.Version);
        Assert.Equal(32, ops.Fingerprint.Length);
    }
}
