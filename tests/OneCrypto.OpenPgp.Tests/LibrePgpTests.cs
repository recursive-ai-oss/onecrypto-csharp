using System.Security.Cryptography;
using System.Text;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>LibrePGP: GnuPG 2.5 Kyber keys and messages, the KMAC256 combiner, and the encryption format chosen for each kind of recipient.</summary>
public class LibrePgpTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 2, 0, 0, 0, TimeSpan.Zero);

    private static byte[] Fixture(string name) => File.ReadAllBytes(TestFiles.OpenPgp("librepgp", name));

    private static PgpCertificate Cert(string name) => PgpCertificate.Parse(Fixture(name));

    private static byte[] Pw(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public void Kmac256MatchesTheNistSample()
    {
        // NIST SP 800-185 KMAC sample #4: key 40..5F, data 00 01 02 03, 512 bits, customization "My Tagged Application".
        byte[] key = Enumerable.Range(0x40, 32).Select(i => (byte)i).ToArray();
        byte[] output = new byte[64];
        KyberKmac.Compute(key, [0, 1, 2, 3], output, "My Tagged Application"u8);
        Assert.Equal("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD", Convert.ToHexString(output));
    }

    [Fact]
    public void Kmac256AgreesWithThePlatformWhenItHasOne()
    {
        if (!System.Security.Cryptography.Kmac256.IsSupported)
        {
            return;
        }

        var rng = new Random(7);
        for (int i = 0; i < 20; i++)
        {
            byte[] key = new byte[rng.Next(1, 80)];
            byte[] data = new byte[rng.Next(0, 400)];
            byte[] custom = new byte[rng.Next(0, 10)];
            rng.NextBytes(key);
            rng.NextBytes(data);
            rng.NextBytes(custom);
            byte[] ours = new byte[32];
            KyberKmac.Compute(key, data, ours, custom);
            Assert.Equal(System.Security.Cryptography.Kmac256.HashData(key, data, 32, custom), ours);
        }
    }

    [Theory]
    [InlineData("ky768_cv25519")]
    [InlineData("ky1024_cv448")]
    public void GnuPg25KyberMessagesDecrypt(string kind)
    {
        Assert.SkipUnless(System.Security.Cryptography.MLKem.IsSupported, "ML-KEM is not available on this platform");
        PgpCertificate secret = Cert($"sec-kyber-{kind}.gpg");
        using var output = new MemoryStream();
        PgpReadResult r = PgpMessageReader.Read(new MemoryStream(Fixture($"msg-kyber-{kind}.gpg")), output, new PgpReadOptions { Now = Now, SecretKeys = [secret] });
        Assert.True(r.WasEncrypted);
        Assert.Equal($"plain {kind}\n", Encoding.ASCII.GetString(output.ToArray()));
    }

    [Theory]
    [InlineData("ky768_nistp256")]
    [InlineData("ky768_bp256")]
    public void KyberOverWeierstrassCurvesIsReportedUnsupported(string kind)
    {
        PgpCertificate secret = Cert($"sec-kyber-{kind}.gpg");
        using var output = new MemoryStream();
        var e = Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(Fixture($"msg-kyber-{kind}.gpg")), output, new PgpReadOptions { Now = Now, SecretKeys = [secret] }));
        Assert.Equal(PgpFailure.Unsupported, e.Failure);
        Assert.Equal(0, output.Length);
    }

    private static string Read(byte[] message, PgpReadOptions options)
    {
        using var output = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(message), output, options);
        return Encoding.UTF8.GetString(output.ToArray());
    }

    [Theory]
    [InlineData("v5")]
    [InlineData("v4o")]
    public void GnuPgOcbEncryptedDataToLibrePgpKeysDecrypts(string key)
    {
        string text = Read(Fixture($"msg-{key}-ocbed.gpg"), new PgpReadOptions { Now = Now, SecretKeys = [Cert($"{key}-sec.gpg")] });
        Assert.Equal("librepgp test\n", text);
    }

    [Theory]
    [InlineData("msg-pw-ocbed.gpg")]
    [InlineData("msg-bzip2.gpg")]
    public void GnuPgPasswordMessagesDecrypt(string file)
    {
        Assert.Equal("librepgp test\n", Read(Fixture(file), new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] }));
    }

    private static PgpWriteResult Write(Stream plain, Stream output, PgpWriteOptions o) => PgpMessageWriter.Write(plain, output, o);

    [Theory]
    [InlineData("v5-pub.gpg", PgpEncryptionFormat.LibrePgpOcb)]
    [InlineData("v4o-pub.gpg", PgpEncryptionFormat.LibrePgpOcb)]
    [InlineData("v4-pub.gpg", PgpEncryptionFormat.Seipd1)]
    public void TheFormatFollowsTheRecipientsKey(string pub, PgpEncryptionFormat expected)
    {
        using var enc = new MemoryStream();
        PgpWriteResult r = Write(new MemoryStream("x"u8.ToArray()), enc, new PgpWriteOptions { Now = Now, Recipients = [Cert(pub)] });
        Assert.Equal(expected, r.Format);
        Assert.False(string.IsNullOrEmpty(r.Reason));
        Assert.Contains(expected == PgpEncryptionFormat.LibrePgpOcb ? (byte)20 : (byte)18, FindTags(enc.ToArray()));
    }

    private static List<byte> FindTags(byte[] message)
    {
        var tags = new List<byte>();
        foreach (Packets.Packet p in Packets.PacketParser.ParseAll(message))
        {
            tags.Add(p.TagId);
        }

        return tags;
    }

    [Fact]
    public void ARfc9580KeyKeepsSeipd2AndAMixKeepsSeipd1()
    {
        PgpCertificate v6 = PgpCertificate.Parse(File.ReadAllBytes(TestFiles.OpenPgp("rfc9580", "A_4.asc")));
        using var a = new MemoryStream();
        Assert.Equal(PgpEncryptionFormat.Seipd2, Write(new MemoryStream("x"u8.ToArray()), a, new PgpWriteOptions { Now = Now, Recipients = [PgpCertificate.Parse(v6.ExportPublic())] }).Format);

        using var b = new MemoryStream();
        PgpWriteResult mixed = Write(new MemoryStream("x"u8.ToArray()), b, new PgpWriteOptions { Now = Now, Recipients = [PgpCertificate.Parse(v6.ExportPublic()), Cert("v5-pub.gpg")] });
        Assert.Equal(PgpEncryptionFormat.Seipd1, mixed.Format);
        Assert.Contains("share", mixed.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("v5", 10)]
    [InlineData("v4o", 700_000)]
    public void OurOcbEncryptedDataOpensWithTheKeyAndWithGnuPgsKey(string key, int size)
    {
        byte[] data = new byte[size];
        new Random(size).NextBytes(data);
        using var enc = new MemoryStream();
        Write(new MemoryStream(data), enc, new PgpWriteOptions { Now = Now, Recipients = [Cert($"{key}-pub.gpg")] });
        using var dec = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(enc.ToArray()), dec, new PgpReadOptions { Now = Now, SecretKeys = [Cert($"{key}-sec.gpg")] });
        Assert.Equal(data, dec.ToArray());
    }

    [Fact]
    public void APasswordCanBeAddedToAnOcbEncryptedDataMessage()
    {
        using var enc = new MemoryStream();
        Write(new MemoryStream("both"u8.ToArray()), enc, new PgpWriteOptions { Now = Now, Recipients = [Cert("v5-pub.gpg")], Passwords = [Pw("pw")], S2kIterationCode = 0x60 });
        Assert.Equal("both", Read(enc.ToArray(), new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] }));
        Assert.Equal("both", Read(enc.ToArray(), new PgpReadOptions { Now = Now, SecretKeys = [Cert("v5-sec.gpg")] }));

        using var pwOnly = new MemoryStream();
        PgpWriteResult r = Write(new MemoryStream("pw"u8.ToArray()), pwOnly, new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], ForceLibrePgp = true, S2kIterationCode = 0x60 });
        Assert.Equal(PgpEncryptionFormat.LibrePgpOcb, r.Format);
        Assert.Equal("pw", Read(pwOnly.ToArray(), new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] }));
    }

    [Fact]
    public void ATamperedLibrePgpMessageReleasesNothing()
    {
        // Every single-bit change of a password message (SKESK version 5 and OCB Encrypted Data) either fails or, for the packet framing only, still yields the true text.
        using var enc = new MemoryStream();
        Write(new MemoryStream("secret plaintext"u8.ToArray()), enc, new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], ForceLibrePgp = true, S2kIterationCode = 0x60 });
        byte[] good = enc.ToArray();
        for (int i = 0; i < good.Length; i++)
        {
            byte[] bad = (byte[])good.Clone();
            bad[i] ^= 0x01;
            using var output = new MemoryStream();
            try
            {
                PgpMessageReader.Read(new MemoryStream(bad), output, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
            }
            catch (PgpException)
            {
            }
            catch (Packets.OpenPgpParseException)
            {
            }

            Assert.True(output.Length == 0 || Encoding.ASCII.GetString(output.ToArray()) == "secret plaintext" && IsHarmlessFlip(good, i), $"byte {i} released {output.Length} octets");
        }
    }

    // A flip in the packet framing that leaves the encrypted payload intact may still decrypt (for example a length header): it releases the true plaintext only.
    private static bool IsHarmlessFlip(byte[] good, int i) => i < 2;

    // GnuPG 2.5 makes its version 5 ECDH keys with the OID 1.3.101.110 instead of the legacy Curve25519 one (v5x-*.gpg, throwaway keys from 2.5.24).
    // tools/oracles/librepgp-interop.sh checks both directions against gpg with such a key; this keeps the round trip in the suite.
    [Fact]
    public void AnEcdhKeyNamedByTheNativeX25519OidEncryptsAndDecrypts()
    {
        PgpCertificate pub = Cert("v5x-pub.gpg");
        PgpCertificate secret = Cert("v5x-sec.gpg");
        using var enc = new MemoryStream();
        Write(new MemoryStream("native oid"u8.ToArray()), enc, new PgpWriteOptions { Now = Now, Recipients = [pub] });
        Assert.Equal("native oid", Read(enc.ToArray(), new PgpReadOptions { Now = Now, SecretKeys = [secret] }));
    }

    [Fact]
    public void AVersion5KeySignsVersion5SignaturesAndTheyVerify()
    {
        PgpCertificate secret = Cert("v5-sec.gpg");
        PgpCertificate pub = Cert("v5-pub.gpg");
        using PgpSecretKey signer = PgpSecretKey.Unlock(secret.Primary);
        using var enc = new MemoryStream();
        Write(new MemoryStream("signed by a v5 key"u8.ToArray()), enc, new PgpWriteOptions { Now = Now, Recipients = [pub], Signers = [signer] });
        using var dec = new MemoryStream();
        PgpReadResult r = PgpMessageReader.Read(new MemoryStream(enc.ToArray()), dec, new PgpReadOptions { Now = Now, SecretKeys = [secret], Certificates = [pub] });
        Assert.Equal("signed by a v5 key", Encoding.ASCII.GetString(dec.ToArray()));
        PgpSignatureResult sig = Assert.Single(r.Signatures);
        Assert.True(sig.IsValid, string.Join("; ", sig.Reasons));
        Assert.Equal(5, sig.Signature.Version);
    }

    // The OCB protection of a version 5 secret key (usage 253) is built here from the draft's description: GnuPG 2.4 and 2.5 do not export keys in that form,
    // so there is no oracle for it and this checks the reader against the written rules (S2K output as the OCB key, 15 of the 16 IV octets as nonce, the
    // tag, cipher, mode and public fields as additional data) and its refusal of damage.
    private static PgpCertificate WithOcbProtectedPrimary(string password, out byte[] protectedBody)
    {
        var packets = Packets.PacketParser.ParseAll(Fixture("v5-sec.gpg")).ToList();
        var sp = (Packets.SecretKeyPacket)packets[0];
        byte[] plain = sp.SecretData.Span[..^2].ToArray(); // the two-octet checksum is not part of the OCB form
        byte[] s2k = [3, (byte)Packets.PgpHashAlgorithm.Sha256, 1, 2, 3, 4, 5, 6, 7, 8, 0x60];
        byte[] iv = [.. Enumerable.Range(0, 15).Select(i => (byte)(0x40 + i)), 0];
        byte[] key = PgpAlgorithms.S2k(Packets.S2kSpecifier.Parse(s2k, out _), Pw(password), 32, Primitives.KdfLimits.Default);
        byte[] ad = [0xC5, (byte)Packets.SymmetricAlgorithm.Aes256, (byte)Packets.AeadAlgorithm.Ocb, .. sp.PublicBody.ToArray()];
        byte[] ct = new byte[plain.Length];
        byte[] tag = new byte[16];
        using (var a = new PgpAlgorithms.Aead(Packets.AeadAlgorithm.Ocb, key))
        {
            a.Encrypt(iv.AsSpan(0, 15), plain, ct, tag, ad);
        }

        byte[] fields = [(byte)Packets.SymmetricAlgorithm.Aes256, (byte)Packets.AeadAlgorithm.Ocb, .. s2k, .. iv];
        int n = ct.Length + 16;
        protectedBody = [.. sp.PublicBody.ToArray(), 253, (byte)fields.Length, .. fields, (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n, .. ct, .. tag];
        packets[0] = Packets.Packet.Create(5, protectedBody);
        using var ms = new MemoryStream();
        Packets.PacketParser.Write(packets, ms);
        return PgpCertificate.Parse(ms.ToArray());
    }

    [Fact]
    public void AVersion5KeyProtectedWithOcbUnlocksOnlyWithItsPasswordAndUndamaged()
    {
        PgpCertificate cert = WithOcbProtectedPrimary("pw", out byte[] body);
        using (PgpSecretKey ok = PgpSecretKey.Unlock(cert.Primary, [Pw("pw")]))
        {
            Assert.NotNull(ok);
        }

        Assert.Throws<PgpException>(() => PgpSecretKey.Unlock(cert.Primary, [Pw("wrong")]));
        for (int i = body.Length - 50; i < body.Length; i += 7)
        {
            byte[] bad = (byte[])body.Clone();
            bad[i] ^= 1;
            var packets = Packets.PacketParser.ParseAll(Fixture("v5-sec.gpg")).ToList();
            packets[0] = Packets.Packet.Create(5, bad);
            using var ms = new MemoryStream();
            Packets.PacketParser.Write(packets, ms);
            PgpCertificate damaged = PgpCertificate.Parse(ms.ToArray());
            Assert.Throws<PgpException>(() => PgpSecretKey.Unlock(damaged.Primary, [Pw("pw")]));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void ATamperedKyberSessionKeyIsNotOpened(int part)
    {
        Assert.SkipUnless(System.Security.Cryptography.MLKem.IsSupported, "ML-KEM is not available on this platform");
        // Flip one octet in the ephemeral key (part 0) or in the wrapped session key (part 1) of the PKESK GnuPG wrote.
        byte[] good = Fixture("msg-kyber-ky768_cv25519.gpg");
        var packets = Packets.PacketParser.ParseAll(good).ToList();
        var pkesk = (Packets.PublicKeyEncryptedSessionKeyPacket)packets[0];
        byte[] body = pkesk.Body.ToArray();
        int at = part == 0 ? 10 + 2 + 5 : body.Length - 3;
        body[at] ^= 0x80;
        packets[0] = Packets.Packet.Create(1, body);
        using var ms = new MemoryStream();
        Packets.PacketParser.Write(packets, ms);
        using var output = new MemoryStream();
        Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(ms.ToArray()), output, new PgpReadOptions { Now = Now, SecretKeys = [Cert("sec-kyber-ky768_cv25519.gpg")] }));
        Assert.Equal(0, output.Length);
    }
}
