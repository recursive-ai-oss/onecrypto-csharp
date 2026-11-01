using System.Runtime.Versioning;
using System.Text;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests.Review;

/// <summary>
/// Findings of the decryption-path review for OpenPGP (docs/decryption-review.md). Each finding has a test here; it
/// pins the fix; the other tests pin behaviour the review found correct.
/// </summary>
[Collection("ProcessMemory")]
public class DecryptionReviewTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static PgpCertificate Cert(string name) => PgpCertificate.Parse(File.ReadAllBytes(TestFiles.OpenPgp("rfc9580", name)));

    private static byte[] Pw(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Encrypt(PgpWriteOptions o, byte[] data)
    {
        using var enc = new MemoryStream();
        PgpMessageWriter.Write(new MemoryStream(data), enc, o);
        return enc.ToArray();
    }

    private static PgpException Fail(byte[] message, PgpReadOptions o, Stream? sink = null) =>
        Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream(message), sink ?? Stream.Null, o));

    /// <summary>A version 6 SKESK whose Argon2 cost is far above any limit.</summary>
    private static byte[] CostBombSkesk()
    {
        byte[] s2k = [4, .. new byte[16], 3, 4, 40];
        byte[] body = [6, (byte)(3 + s2k.Length + 15), 9, 2, (byte)s2k.Length, .. s2k, .. new byte[15], .. new byte[32]];
        return [0xC3, (byte)body.Length, .. body];
    }

    // ---- D1: a failed session-key recovery is a different failure class from a failed body ----

    [Fact]
    public void BadSessionKeyAndBadBodyAreTheSameFailure()
    {
        PgpCertificate secret = Cert("A_4.asc");
        PgpCertificate pub = PgpCertificate.Parse(secret.ExportPublic());
        byte[] good = Encrypt(new PgpWriteOptions { Now = Now, Recipients = [pub] }, new byte[2000]);
        var ro = new PgpReadOptions { Now = Now, SecretKeys = [secret] };

        byte[] badKey = (byte[])good.Clone();
        badKey[2 + good[1] - 3] ^= 1; // inside the PKESK's wrapped session key
        byte[] badBody = (byte[])good.Clone();
        badBody[^5] ^= 1;

        PgpException a = Fail(badKey, ro);
        PgpException b = Fail(badBody, ro);
        Assert.Equal(a.Failure, b.Failure);
        Assert.Equal(a.Message, b.Message);
    }

    // ---- D2: an unusable password packet in front of a good one aborts the read ----

    [Fact]
    public void AHostileSkeskDoesNotMaskAGoodOne()
    {
        byte[] good = Encrypt(new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], S2kIterationCode = 0x10 }, "hello"u8.ToArray());
        using var dec = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream([.. CostBombSkesk(), .. good]), dec, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
        Assert.Equal("hello", Encoding.UTF8.GetString(dec.ToArray()));
    }

    // ---- D3: the version pairing of RFC 9580 §10.3.2.1 is not enforced ----

    [Fact]
    public void AV3PkeskMayNotOpenAV2Seipd()
    {
        PgpCertificate secret = Cert("A_4.asc");
        PgpCertificate pub = PgpCertificate.Parse(secret.ExportPublic());
        byte[]? sk = null;
        SymmetricAlgorithm cipher = default;
        byte[] v2 = Encrypt(new PgpWriteOptions { Now = Now, Recipients = [pub], OnSessionKey = (c, k) => { cipher = c; sk = k; } }, "hello"u8.ToArray());
        IReadOnlyList<Packet> packets = PacketParser.ParseAll(v2);
        Assert.Equal(PacketTag.PublicKeyEncryptedSessionKey, packets[0].Tag);
        PgpKey encKey = pub.Keys.First(static k => k.Packet.Algorithm == PublicKeyAlgorithm.X25519);
        byte[] v3 = SessionKeys.Encrypt(encKey, sk!, cipher, 3).ToArray();
        byte[] rest = [.. packets.Skip(1).SelectMany(static p => p.ToArray())];
        var e = Assert.Throws<PgpException>(() => PgpMessageReader.Read(new MemoryStream([.. v3, .. rest]), Stream.Null, new PgpReadOptions { Now = Now, SecretKeys = [secret] }));
        Assert.Equal(PgpFailure.MalformedMessage, e.Failure);
    }

    // ---- D4: nothing bounds how many session-key packets are tried ----

    [Fact]
    public void ManySessionKeyPacketsAreRefused()
    {
        PgpCertificate secret = Cert("A_4.asc");
        PgpCertificate pub = PgpCertificate.Parse(secret.ExportPublic());
        byte[] good = Encrypt(new PgpWriteOptions { Now = Now, Recipients = [pub] }, new byte[100]);
        int pkeskLength = 2 + good[1];
        byte[] pkesk = good[..pkeskLength];
        var all = new List<byte>();
        for (int i = 0; i < 20_000; i++)
        {
            all.AddRange(pkesk);
        }

        all.AddRange(good.AsSpan(pkeskLength).ToArray());
        var e = Fail([.. all], new PgpReadOptions { Now = Now, SecretKeys = [secret] });
        Assert.Equal(PgpFailure.LimitExceeded, e.Failure);
    }

    // ---- D5: SEIPD v1 plaintext waits in a temporary file readable by other users ----

    [Fact]
    [UnsupportedOSPlatform("windows")]
    public void SpooledPlaintextIsNotReadableByOtherUsers()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux() || OperatingSystem.IsMacOS(), "Unix file modes");
        string dir = Path.Combine(Path.GetTempPath(), "onecrypto-review-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string? old = Environment.GetEnvironmentVariable("TMPDIR");
        Environment.SetEnvironmentVariable("TMPDIR", dir);
        try
        {
            byte[] msg = Encrypt(new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], ForceSeipd1 = true, S2kIterationCode = 0x10 }, new byte[6 << 20]);
            var sink = new ModeProbe(dir);
            PgpMessageReader.Read(new MemoryStream(msg), sink, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
            Assert.NotNull(sink.Mode);
            const UnixFileMode others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite;
            Assert.Equal((UnixFileMode)0, sink.Mode!.Value & others);
            Assert.Empty(Directory.GetFiles(dir)); // the spool file is gone once the read has finished
        }
        finally
        {
            Environment.SetEnvironmentVariable("TMPDIR", old);
            Directory.Delete(dir, true);
        }
    }

    /// <summary>Notes the mode of the spool file the first time plaintext reaches it.</summary>
    [UnsupportedOSPlatform("windows")]
    private sealed class ModeProbe(string dir) : Stream
    {
        public UnixFileMode? Mode { get; private set; }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (Mode is null)
            {
                string? f = Directory.GetFiles(dir, "onecrypto-*.tmp").FirstOrDefault();
                if (f is not null)
                {
                    Mode = File.GetUnixFileMode(f);
                }
            }
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }

    // ---- D6: the result does not say how the plaintext was protected ----

    [Fact]
    public void TheResultTellsUnauthenticatedFromAuthenticatedDecryption()
    {
        byte[] sed = File.ReadAllBytes(TestFiles.OpenPgp("legacy", "sed-aes.gpg"));
        PgpReadResult unauth = PgpMessageReader.Read(new MemoryStream(sed), Stream.Null, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")], AllowUnauthenticatedEncryption = true });
        byte[] v2 = Encrypt(new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], S2kIterationCode = 0x10 }, "x"u8.ToArray());
        PgpReadResult auth = PgpMessageReader.Read(new MemoryStream(v2), Stream.Null, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
        Assert.Equal(PgpProtection.None, unauth.Protection);
        Assert.Equal(PgpProtection.Aead, auth.Protection);
        Assert.False(unauth.CheckedBeforeRelease);
        byte[] v1 = Encrypt(new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], ForceSeipd1 = true, S2kIterationCode = 0x10 }, "x"u8.ToArray());
        Assert.Equal(PgpProtection.Mdc, PgpMessageReader.Read(new MemoryStream(v1), Stream.Null, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] }).Protection);
    }

    // ---- D7: a quick-check false positive on a wrong candidate hides the right one ----

    [Fact]
    public void ASeipd1QuickCheckFalsePositiveDoesNotHideTheRightKey()
    {
        SymmetricAlgorithm cipher = default;
        byte[] sk = [];
        byte[] msg = Encrypt(new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], ForceSeipd1 = true, S2kIterationCode = 0x10, OnSessionKey = (c, k) => { cipher = c; sk = k; } }, "hello"u8.ToArray());
        Packet seipd = PacketParser.ParseAll(msg).Single(static p => p.Tag == PacketTag.SymmetricallyEncryptedIntegrityProtectedData);
        byte[] head = seipd.Body.Span.Slice(1, 18).ToArray();
        // About one random key in 65,536 passes the two-octet check: find one.
        byte[] fake = new byte[PgpAlgorithms.KeySize(cipher)];
        var rnd = new Random(7);
        while (true)
        {
            rnd.NextBytes(fake);
            byte[] t = head.AsSpan(0, 18).ToArray();
            PgpAlgorithms.CfbDecrypt(cipher, fake, new byte[16], t);
            if (t[14] == t[16] && t[15] == t[17] && !fake.AsSpan().SequenceEqual(sk))
            {
                break;
            }
        }

        using var dec = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(msg), dec, new PgpReadOptions { Now = Now, SessionKeysWithCipher = [(cipher, fake), (cipher, sk)] });
        Assert.Equal("hello", Encoding.UTF8.GetString(dec.ToArray()));
    }

    // ---- pinned: checked and correct ----

    [Fact]
    public void AeadReleasesVerifiedChunksBeforeALateFailureAndNeverTheBadOne()
    {
        // 256 KiB chunks: damage in the last chunk means the earlier ones were handed over. This is the documented behaviour of the synchronous reader.
        byte[] data = new byte[700_000];
        new Random(2).NextBytes(data);
        byte[] msg = Encrypt(new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], S2kIterationCode = 0x10 }, data);
        byte[] bad = (byte[])msg.Clone();
        bad[^30] ^= 1;
        using var sink = new MemoryStream();
        Fail(bad, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] }, sink);
        Assert.InRange(sink.Length, 1, data.Length - 1);
        Assert.Equal(data.AsSpan(0, (int)sink.Length).ToArray(), sink.ToArray());
    }

    /// <summary>Rewrites the encrypted-data packet body of a message and gives the packet a fresh header, so damage reaches the AEAD layer instead of the packet layer.</summary>
    private static byte[] Edit(byte[] message, Func<byte[], byte[]> edit)
    {
        var all = new List<byte>();
        foreach (Packet p in PacketParser.ParseAll(message))
        {
            all.AddRange(p.Tag == PacketTag.SymmetricallyEncryptedIntegrityProtectedData ? Packet.Create(p.TagId, edit(p.Body.ToArray())).ToArray() : p.ToArray());
        }

        return [.. all];
    }

    private static byte[] AeadMessage(int size) => Encrypt(new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], S2kIterationCode = 0x10 }, new byte[size]);

    [Theory]
    [InlineData(16)]  // the final tag removed
    [InlineData(1)]   // one octet of the final tag removed
    [InlineData(17)]  // the final tag and an octet of the last chunk's tag
    [InlineData(300_000)] // whole chunks removed
    public void AeadTruncationFailsAtEveryBoundary(int cut)
    {
        var o = new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] };
        byte[] msg = AeadMessage(600_000);
        PgpMessageReader.Read(new MemoryStream(Edit(msg, static b => b)), Stream.Null, o); // control: the rebuilt message is good
        Fail(Edit(msg, b => b[..^cut]), o);
    }

    [Fact]
    public void AeadReorderedDuplicatedAndExtendedChunksFail()
    {
        // Chunks are 256 KiB plus a 16-octet tag after the 4-octet header and 32-octet salt.
        const int first = 36;
        const int wire = (1 << 18) + 16;
        var o = new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] };
        byte[] msg = AeadMessage(900_000);
        PgpMessageReader.Read(new MemoryStream(Edit(msg, static b => b)), Stream.Null, o);

        Fail(Edit(msg, b =>
        {
            byte[] c = (byte[])b.Clone();
            b.AsSpan(first, wire).CopyTo(c.AsSpan(first + wire));
            b.AsSpan(first + wire, wire).CopyTo(c.AsSpan(first));
            return c;
        }), o);
        Fail(Edit(msg, b =>
        {
            byte[] c = (byte[])b.Clone();
            b.AsSpan(first, wire).CopyTo(c.AsSpan(first + wire));
            return c;
        }), o);
        Fail(Edit(msg, static b => [.. b, 0]), o);
        Fail(Edit(msg, static b => [.. b[..first], .. b[(first + wire)..]]), o); // first chunk dropped
    }

    [Fact]
    public void ChunkSizeAboveTheSpecificationLimitIsRefusedBeforeAnyAllocation()
    {
        byte[] bad = Edit(AeadMessage(10), static b =>
        {
            byte[] c = (byte[])b.Clone();
            c[3] = 0xFF;
            return c;
        });
        var e = Fail(bad, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
        Assert.Equal(PgpFailure.LimitExceeded, e.Failure);
    }

    [Fact]
    public void ZeroesCompressedToTheDeflateLimitStillPassTheRatioCeiling()
    {
        // 100 MiB of zeros deflate to about 100 KiB (about 1000:1); the ceiling is 1 MiB plus 1032 times the compressed octets, so honest data passes and an inflated claim does not.
        byte[] zeros = new byte[100 << 20];
        byte[] msg = Encrypt(new PgpWriteOptions { Now = Now, Passwords = [Pw("pw")], S2kIterationCode = 0x10, Compression = CompressionAlgorithm.Zip }, zeros);
        using var sink = new MemoryStream();
        PgpMessageReader.Read(new MemoryStream(msg), sink, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
        Assert.Equal(zeros.Length, sink.Length);
    }

    [Fact]
    public void SedNeedsTheOptInAndEveryOtherFailureIsTyped()
    {
        byte[] sed = File.ReadAllBytes(TestFiles.OpenPgp("legacy", "sed-aes.gpg"));
        var e = Fail(sed, new PgpReadOptions { Now = Now, MessagePasswords = [Pw("pw")] });
        Assert.Equal(PgpFailure.UnauthenticatedEncryption, e.Failure);
        // a session key supplied by the caller does not bypass the refusal
        var e2 = Fail(sed, new PgpReadOptions { Now = Now, SessionKeysWithCipher = [(SymmetricAlgorithm.Aes128, new byte[16])] });
        Assert.Equal(PgpFailure.UnauthenticatedEncryption, e2.Failure);
    }
}
