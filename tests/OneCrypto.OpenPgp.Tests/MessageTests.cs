using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>Messages: the RFC 9580 Appendix A samples and round trips with the sample keys.</summary>
[Collection("ProcessMemory")]
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
    [InlineData("CAST5")]
    [InlineData("3DES")]
    [InlineData("BLOWFISH")]
    [InlineData("IDEA")]
    [InlineData("TWOFISH")]
    [InlineData("CAMELLIA128")]
    [InlineData("CAMELLIA256")]
    public void LegacyCipherMessagesDecrypt(string name)
    {
        // SEIPD v1 messages written by GnuPG (tools/oracles/legacy-ciphers-fixtures.sh): legacy ciphers are decrypt-only.
        using var output = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(File.ReadAllBytes(TestFiles.OpenPgp("legacy", "msg-" + name + ".gpg"))), output, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
        Assert.Equal("legacy cipher test " + name + "\n", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Theory]
    [InlineData("sed-aes.gpg", "sed test\n")]
    [InlineData("sed-cast5.gpg", "sed test cast\n")]
    public void OldUnprotectedEncryptionNeedsAnExplicitOptIn(string file, string expected)
    {
        byte[] data = File.ReadAllBytes(TestFiles.OpenPgp("legacy", file));
        using var none = new MemoryStream();
        var e = Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(data), none, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] }));
        Assert.Equal(PgpFailure.UnauthenticatedEncryption, e.Failure);
        Assert.Equal(0, none.Length);

        using var output = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(data), output, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")], AllowUnauthenticatedEncryption = true });
        Assert.Equal(expected, Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public void LibrePgpOcbEncryptedDataDecryptsAndFailsClosedWhenTampered()
    {
        byte[] data = File.ReadAllBytes(TestFiles.OpenPgp("legacy", "ocbed-librepgp.gpg"));
        using var output = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(data), output, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
        Assert.Equal("ocbed test\n", Encoding.UTF8.GetString(output.ToArray()));

        byte[] bad = (byte[])data.Clone();
        bad[^20] ^= 1;
        using var sink = new MemoryStream();
        Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(bad), sink, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] }));
        Assert.Equal(0, sink.Length);
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
        Assert.Equal(PgpFailure.KeyIsProtected, e.Failure);
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

    [Fact]
    public void Seipd1MdcAndTruncationFailClosed()
    {
        PgpCertificate secret = Cert("A_4.asc");
        PgpCertificate pub = PgpCertificate.Parse(secret.ExportPublic());
        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream(new byte[5_000]), enc, new PgpWriteOptions { Now = Now, Recipients = [pub], ForceSeipd1 = true });
        byte[] good = enc.ToArray();
        var ro = new PgpReadOptions { Now = Now, SecretKeys = [secret] };
        foreach (int back in new[] { 1, 10, 22, 23 })
        {
            byte[] bad = (byte[])good.Clone();
            bad[^back] ^= 0x80;
            using var sink = new MemoryStream();
            Assert.ThrowsAny<PgpException>(() => PgpMessageReader.Read(new MemoryStream(bad), sink, ro));
            Assert.Equal(0, sink.Length);
        }

        foreach (int cut in new[] { 1, 21, 22, 40, 2000 })
        {
            using var sink = new MemoryStream();
            Assert.ThrowsAny<Exception>(() => PgpMessageReader.Read(new MemoryStream(good.AsSpan(0, good.Length - cut).ToArray()), sink, ro));
            Assert.Equal(0, sink.Length);
        }
    }

    [Fact]
    public void DeeplyNestedCompressionIsRefused()
    {
        // A literal packet wrapped in 40 compressed-data layers: the reader stops at its nesting limit instead of recursing.
        byte[] packet = [0xCB, 7, (byte)'b', 0, 0, 0, 0, 0, (byte)'x'];
        for (int i = 0; i < 40; i++)
        {
            using var raw = new MemoryStream();
            using (var z = new System.IO.Compression.DeflateStream(raw, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
            {
                z.Write(packet);
            }

            byte[] body = [1, .. raw.ToArray()];
            int len = body.Length;
            packet = [0xC8, 0xFF, (byte)(len >> 24), (byte)(len >> 16), (byte)(len >> 8), (byte)len, .. body];
        }

        var e = Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(packet), new MemoryStream(), new PgpReadOptions { Now = Now }));
        Assert.Equal(PgpFailure.LimitExceeded, e.Failure);
    }

    [Theory]
    [InlineData(CompressionAlgorithm.Zip)]
    [InlineData(CompressionAlgorithm.Zlib)]
    public void CompressedMessagesRoundTrip(CompressionAlgorithm algorithm)
    {
        byte[] data = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("compressible ", 5000)));
        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream(data), enc, new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], Compression = algorithm });
        using var dec = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(enc.ToArray()), dec, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
        Assert.Equal(data, dec.ToArray());
    }

    private static byte[] Pqc(string name) => File.ReadAllBytes(TestFiles.OpenPgp("rfc9980", name));

    [Theory]
    [InlineData("A_1", "A_1_msg.asc")]
    [InlineData("A_2", "A_2_msg_seipd1.asc")]
    [InlineData("A_2", "A_2_msg_seipd2.asc")]
    [InlineData("A_3", "A_3_msg.asc")]
    [InlineData("A_4", "A_4_msg.asc")]
    public void Rfc9980MessagesDecryptAndVerify(string key, string message)
    {
        Assert.SkipUnless(System.Security.Cryptography.MLKem.IsSupported && System.Security.Cryptography.MLDsa.IsSupported, "ML-KEM/ML-DSA are not available on this platform");
        PgpCertificate secret = PgpCertificate.Parse(Pqc(key + "_sec.asc"));
        PgpCertificate pub = PgpCertificate.Parse(Pqc(key + "_pub.asc"));
        using var output = new MemoryStream();
        PgpReadResult r = PgpMessageReader.Read(new MemoryStream(Pqc(message)), output, new PgpReadOptions { Now = Now, SecretKeys = [secret], Certificates = [pub] });
        Assert.Equal("Testing\n", Encoding.UTF8.GetString(output.ToArray()));
        Assert.True(r.Signatures.Single().IsValid, string.Join("; ", r.Signatures[0].Reasons));
    }

    [Theory]
    [InlineData("A_3", "A_3_sig.asc")]
    [InlineData("A_4", "A_4_sig.asc")]
    public void Rfc9980DetachedSignaturesVerify(string key, string sig)
    {
        Assert.SkipUnless(System.Security.Cryptography.MLKem.IsSupported && System.Security.Cryptography.MLDsa.IsSupported, "ML-KEM/ML-DSA are not available on this platform");
        PgpCertificate pub = PgpCertificate.Parse(Pqc(key + "_pub.asc"));
        PgpReadResult r = PgpMessageReader.VerifyDetached(new MemoryStream("Testing\n"u8.ToArray()), new MemoryStream(Pqc(sig)), new PgpReadOptions { Now = Now, Certificates = [pub] });
        Assert.True(r.Signatures.Single().IsValid, string.Join("; ", r.Signatures[0].Reasons));
        Assert.False(PgpMessageReader.VerifyDetached(new MemoryStream("Testing!\n"u8.ToArray()), new MemoryStream(Pqc(sig)), new PgpReadOptions { Now = Now, Certificates = [pub] }).Signatures.Single().IsValid);
    }

    [Theory]
    [InlineData("A_1")]
    [InlineData("A_3")]
    [InlineData("A_4")]
    public void PostQuantumSignEncryptRoundTrip(string key)
    {
        Assert.SkipUnless(System.Security.Cryptography.MLKem.IsSupported && System.Security.Cryptography.MLDsa.IsSupported, "ML-KEM/ML-DSA are not available on this platform");
        PgpCertificate secret = PgpCertificate.Parse(Pqc(key + "_sec.asc"));
        PgpCertificate pub = PgpCertificate.Parse(Pqc(key + "_pub.asc"));
        using PgpSecretKey signer = PgpSecretKey.Unlock(secret.Primary);
        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream("round trip"u8.ToArray()), enc, new PgpWriteOptions { Now = Now, Recipients = [pub], Signers = [signer] });
        using var dec = new MemoryStream();
        PgpReadResult r = PgpMessageReader.Read(new MemoryStream(enc.ToArray()), dec, new PgpReadOptions { Now = Now, SecretKeys = [secret], Certificates = [pub] });
        Assert.Equal("round trip", Encoding.UTF8.GetString(dec.ToArray()));
        Assert.True(r.Signatures.Single().IsValid, string.Join("; ", r.Signatures[0].Reasons));
    }
}
