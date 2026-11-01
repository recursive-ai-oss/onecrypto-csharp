using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>Messages: the RFC 9580 Appendix A samples and round trips with the sample keys.</summary>
public class MessageTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static byte[] Sample(string name) => File.ReadAllBytes(TestFiles.OpenPgp("rfc9580", name));

    private static PgpCertificate Cert(string name) => PgpCertificate.Parse(Sample(name));

    private static byte[] Pw(string s) => Encoding.UTF8.GetBytes(s);

    [Theory]
    [InlineData("A_9_5.asc")]
    [InlineData("A_10_5.asc")]
    [InlineData("A_11_5.asc")]
    public void PasswordSamplesDecrypt(string file)
    {
        using var output = new MemoryStream();
        PgpReadResult r = PgpMessageReader.Read(new MemoryStream(Sample(file)), output, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("password")] });
        Assert.True(r.WasEncrypted);
        Assert.Equal("Hello, world!", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Theory]
    [InlineData("A_12_1.asc")]
    [InlineData("A_12_2.asc")]
    [InlineData("A_12_3.asc")]
    public void Argon2V4SkeskSamplesDecrypt(string file)
    {
        using var output = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(Sample(file)), output, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("password")] });
        Assert.Equal("Hello, world!", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public void X25519SampleDecryptsWithTheSampleSecretKey()
    {
        using var output = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(Sample("A_8_5.asc")), output, new PgpReadOptions { Now = Now, SecretKeys = [Cert("A_4.asc")] });
        Assert.Equal("Hello, world!", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public void LockedSecretKeyNeedsItsPassword()
    {
        PgpCertificate locked = Cert("A_5.asc");
        var o = new PgpReadOptions { Now = Now, SecretKeys = [locked] };
        PgpException e = Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(Sample("A_8_5.asc")), null, o));
        Assert.Equal(PgpFailure.NoDecryptionKey, e.Failure);
        using var output = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(Sample("A_8_5.asc")), output, new PgpReadOptions { Now = Now, SecretKeys = [locked], KeyPasswords = [Pw("correct horse battery staple")] });
        Assert.Equal("Hello, world!", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public void InlineSignedSampleVerifies()
    {
        using var output = new MemoryStream();
        PgpReadResult r = PgpMessageReader.Read(new MemoryStream(Sample("A_7.asc")), output, new PgpReadOptions { Now = Now, Certificates = [Cert("A_3.asc")] });
        Assert.Single(r.Signatures);
        Assert.True(r.Signatures[0].IsValid, string.Join("; ", r.Signatures[0].Reasons));
        Assert.StartsWith("What we need from the grocery store:", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public void CleartextSampleVerifies()
    {
        PgpReadResult r = PgpMessageReader.VerifyCleartext(new MemoryStream(Sample("A_6_cleartext.asc")), null, new PgpReadOptions { Now = Now, Certificates = [Cert("A_3.asc")] });
        Assert.Single(r.Signatures);
        Assert.True(r.Signatures[0].IsValid, string.Join("; ", r.Signatures[0].Reasons));
    }

    [Fact]
    public void LegacyEd25519DetachedSampleVerifiesAndRejectsOtherData()
    {
        // The sample key is a bare key packet with no self-signature, so only the signature check itself is exercised.
        PgpCertificate c = Cert("A_1.asc");
        SignaturePacket sig = (SignaturePacket)PacketParser.ParseAll(Sample("A_2.asc").Length > 0 ? TestFiles.ReadArmored(TestFiles.OpenPgp("rfc9580", "A_2.asc")) : []).Single();
        byte[] good = SignatureEngine.Digest(sig, "OpenPGP"u8.ToArray());
        Assert.True(SignatureEngine.VerifyDigest(c.Primary.Packet, sig, good));
        Assert.False(SignatureEngine.VerifyDigest(c.Primary.Packet, sig, SignatureEngine.Digest(sig, "OpenPGq"u8.ToArray())));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SignEncryptRoundTrip(bool v1)
    {
        PgpCertificate secret = Cert("A_4.asc");
        PgpCertificate pub = PgpCertificate.Parse(secret.ExportPublic());
        using PgpSecretKey signer = PgpSecretKey.Unlock(secret.Primary);
        byte[] data = new byte[300_000];
        new Random(1).NextBytes(data);
        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream(data), enc, new PgpWriteOptions { Now = Now, Recipients = [pub], Signers = [signer], ForceSeipd1 = v1, FileName = "f.bin"u8.ToArray() });
        using var dec = new MemoryStream();
        PgpReadResult r = PgpMessageReader.Read(new MemoryStream(enc.ToArray()), dec, new PgpReadOptions { Now = Now, SecretKeys = [secret], Certificates = [pub] });
        Assert.Equal(data, dec.ToArray());
        Assert.True(r.Signatures.Single().IsValid, string.Join("; ", r.Signatures[0].Reasons));
        Assert.Equal(v1, r.CheckedBeforeRelease);
    }

    [Fact]
    public void PasswordRoundTripBothVersions()
    {
        foreach (bool v1 in new[] { false, true })
        {
            using var enc = new MemoryStream();
            PgpMessageWriter.Write(new MemoryStream("hello"u8.ToArray()), enc, new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], ForceSeipd1 = v1, Armor = true });
            Assert.StartsWith("-----BEGIN PGP MESSAGE-----", Encoding.ASCII.GetString(enc.ToArray()), StringComparison.Ordinal);
            using var dec = new MemoryStream();
            PgpMessageReader.Read(new MemoryStream(enc.ToArray()), dec, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
            Assert.Equal("hello", Encoding.UTF8.GetString(dec.ToArray()));
            Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(enc.ToArray()), null, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("other")] }));
        }
    }

    [Fact]
    public void DetachedAndCleartextRoundTrip()
    {
        PgpCertificate secret = Cert("A_4.asc");
        PgpCertificate pub = PgpCertificate.Parse(secret.ExportPublic());
        using PgpSecretKey signer = PgpSecretKey.Unlock(secret.Primary);
        var w = new PgpWriteOptions { Now = Now, Signers = [signer], Armor = true };
        using var sig = new MemoryStream();
        PgpMessageWriter.SignDetached(new MemoryStream("abc"u8.ToArray()), sig, w);
        var ro = new PgpReadOptions { Now = Now, Certificates = [pub] };
        Assert.True(PgpMessageReader.VerifyDetached(new MemoryStream("abc"u8.ToArray()), new MemoryStream(sig.ToArray()), ro).Signatures[0].IsValid);

        using var clear = new MemoryStream();
        PgpMessageWriter.SignCleartext(new MemoryStream("- dashed  \nline two\n\nlast"u8.ToArray()), clear, w);
        using var text = new MemoryStream();
        PgpReadResult r = PgpMessageReader.VerifyCleartext(new MemoryStream(clear.ToArray()), text, ro);
        Assert.True(r.Signatures[0].IsValid, string.Join("; ", r.Signatures[0].Reasons));
        Assert.Equal("- dashed  \nline two\n\nlast", Encoding.UTF8.GetString(text.ToArray()));
    }

    [Fact]
    public void TamperedAeadMessagesFailClosed()
    {
        PgpCertificate secret = Cert("A_4.asc");
        PgpCertificate pub = PgpCertificate.Parse(secret.ExportPublic());
        byte[] data = new byte[700_000];
        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream(data), enc, new PgpWriteOptions { Now = Now, Recipients = [pub] });
        byte[] good = enc.ToArray();
        for (int at = good.Length - 1; at > good.Length - 400_000; at -= 99_991)
        {
            byte[] bad = (byte[])good.Clone();
            bad[at] ^= 1;
            using var sink = new MemoryStream();
            Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(bad), sink, new PgpReadOptions { Now = Now, SecretKeys = [secret] }));
            Assert.True(sink.Length < data.Length);
        }

        // truncation, including the loss of just the final tag
        byte[] cut = good.AsSpan(0, good.Length - 17).ToArray();
        Assert.ThrowsAny<Exception>(() => PgpMessageReader.Read(new MemoryStream(cut), new MemoryStream(), new PgpReadOptions { Now = Now, SecretKeys = [secret] }));
    }

    [Fact]
    public void TamperedSeipd1ReleasesNothing()
    {
        PgpCertificate secret = Cert("A_4.asc");
        PgpCertificate pub = PgpCertificate.Parse(secret.ExportPublic());
        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream(new byte[100_000]), enc, new PgpWriteOptions { Now = Now, Recipients = [pub], ForceSeipd1 = true });
        byte[] bad = enc.ToArray();
        bad[^30] ^= 1;
        using var sink = new MemoryStream();
        Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(bad), sink, new PgpReadOptions { Now = Now, SecretKeys = [secret] }));
        Assert.Equal(0, sink.Length);
    }
}
