using System.Diagnostics;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace OneCrypto.Tests.Cms;

/// <summary>Streaming sign, verify, encrypt and decrypt with indefinite-length BER.</summary>
public class StreamingTests
{
    private static readonly byte[] Content = RandomNumberGenerator.GetBytes(300_000);

    [Theory]
    [InlineData(SigKind.Rsa)]
    [InlineData(SigKind.P256)]
    [InlineData(SigKind.Ed25519)]
    public void StreamedSignatureVerifiesBothWays(SigKind kind)
    {
        SignerKit k = CmsKeys.Get(kind);
        var ms = new MemoryStream();
        SignedData.SignStream(new MemoryStream(Content), ms, [k.Spec()]);
        byte[] msg = ms.ToArray();
        Assert.Equal(0x30, msg[0]);
        Assert.Equal(0x80, msg[1]); // indefinite length

        // The one-shot reader takes it as received and agrees.
        SignedData sd = SignedData.Parse(msg);
        Assert.True(sd.Verify().IsValid);
        Assert.Equal(Content, sd.EncapsulatedContent.ToArray());

        var copy = new MemoryStream();
        SignedDataReport report = SignedData.VerifyStream(new MemoryStream(msg), copy);
        Assert.True(report.IsValid);
        Assert.Equal(Content, copy.ToArray());

        // A one-shot, definite-length message verifies through the stream path too.
        byte[] der = SignedData.Create(Content, [k.Spec()]).Encoded.ToArray();
        Assert.True(SignedData.VerifyStream(new MemoryStream(der)).IsValid);
    }

    [Fact]
    public void StreamedVerifyCatchesAChangedByte()
    {
        SignerKit k = CmsKeys.Get(SigKind.P256);
        var ms = new MemoryStream();
        SignedData.SignStream(new MemoryStream(Content), ms, [k.Spec()]);
        byte[] msg = ms.ToArray();
        msg[1000] ^= 1;
        SignedDataReport report = SignedData.VerifyStream(new MemoryStream(msg));
        Assert.False(report.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, report.Signers[0].Find("message-digest")!.Status);
    }

    [Fact]
    public void StreamedDetachedSignatureVerifiesWithTheContent()
    {
        SignerKit k = CmsKeys.Get(SigKind.Rsa);
        var ms = new MemoryStream();
        SignedData.SignStream(new MemoryStream(Content), ms, [k.Spec()], new SignedDataOptions { Detached = true });
        SignedData sd = SignedData.Parse(ms.ToArray());
        Assert.False(sd.HasEncapsulatedContent);
        Assert.True(sd.Verify(new MemoryStream(Content)).IsValid);
        Assert.Throws<CmsParseException>(() => SignedData.VerifyStream(new MemoryStream(ms.ToArray())));
    }

    [Fact]
    public void StreamedSigningNeedsSignedAttributes()
    {
        SignerKit k = CmsKeys.Get(SigKind.Rsa);
        Assert.Throws<NotSupportedException>(() => SignedData.SignStream(new MemoryStream(Content), new MemoryStream(), [k.Spec(b => b.SignedAttributes = false)]));
    }

    [Fact]
    public void DamagedStreamsRaiseOnlyTypedErrors()
    {
        // A fuzz run found an algorithm identifier with a bad OID escaping as another exception type; every byte of both messages is now damaged in turn.
        SignerKit k = CmsKeys.Get(SigKind.P256);
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        var sign = new MemoryStream();
        SignedData.SignStream(new MemoryStream(Content.AsSpan(0, 40).ToArray()), sign, [k.Spec()]);
        var enc = new MemoryStream();
        EnvelopedData.EncryptStream(new MemoryStream(Content.AsSpan(0, 40).ToArray()), enc, [CmsRecipient.KeyTransport(kit.Certificate)]);
        using CmsDecryptionKey key = kit.Key();
        foreach (byte value in new byte[] { 0xFF, 0x80, 0x00, 0x31 })
        {
            foreach (byte[] msg in new[] { sign.ToArray(), enc.ToArray() })
            {
                for (int i = 0; i < msg.Length; i++)
                {
                    byte[] bad = (byte[])msg.Clone();
                    bad[i] = value;
                    try
                    {
                        _ = SignedData.VerifyStream(new MemoryStream(bad)).IsValid;
                    }
                    catch (CmsParseException)
                    {
                    }

                    try
                    {
                        EnvelopedData.DecryptStream(new MemoryStream(bad), Stream.Null, key);
                    }
                    catch (CmsParseException)
                    {
                    }
                }
            }
        }
    }

    [Fact]
    public void TruncatedStreamsAreTypedErrors()
    {
        SignerKit k = CmsKeys.Get(SigKind.P256);
        var ms = new MemoryStream();
        SignedData.SignStream(new MemoryStream(Content), ms, [k.Spec()]);
        byte[] msg = ms.ToArray();
        foreach (int cut in new[] { 0, 5, 40, 5000, msg.Length - 3, msg.Length - 100 })
        {
            Assert.Throws<CmsParseException>(() => SignedData.VerifyStream(new MemoryStream(msg, 0, cut)));
        }
    }

    [Theory]
    [InlineData(RecipKind.Rsa)]
    [InlineData(RecipKind.X25519)]
    [InlineData(RecipKind.P256)]
    public void StreamedEncryptionRoundTripsBothWays(RecipKind kind)
    {
        RecipientKit kit = RecipientKit.Get(kind);
        CmsRecipient r = kind == RecipKind.Rsa ? CmsRecipient.KeyTransport(kit.Certificate) : CmsRecipient.KeyAgreement(kit.Certificate);
        var ms = new MemoryStream();
        EnvelopedData.EncryptStream(new MemoryStream(Content), ms, [r]);
        byte[] msg = ms.ToArray();
        Assert.Equal(0x80, msg[1]);
        using CmsDecryptionKey key = kit.Key();
        Assert.Equal(Content, EnvelopedData.Parse(msg).Decrypt(key));
        var plain = new MemoryStream();
        EnvelopedData.DecryptStream(new MemoryStream(msg), plain, key);
        Assert.Equal(Content, plain.ToArray());

        // A definite-length one-shot message also opens through the stream path.
        var plain2 = new MemoryStream();
        EnvelopedData.DecryptStream(new MemoryStream(EnvelopedData.Create(Content, [r]).Encoded.ToArray()), plain2, key);
        Assert.Equal(Content, plain2.ToArray());
    }

    [Fact]
    public void StreamedDecryptionFailsTheSameWayWhateverWentWrong()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        var ms = new MemoryStream();
        EnvelopedData.EncryptStream(new MemoryStream(Content), ms, [CmsRecipient.KeyTransport(kit.Certificate)]);
        byte[] msg = ms.ToArray();
        using CmsDecryptionKey key = kit.Key();
        using CmsDecryptionKey wrong = CmsDecryptionKey.FromRsa(RSA.Create(2048));
        Assert.Equal(CmsError.DecryptionFailed, Assert.Throws<CmsParseException>(() => EnvelopedData.DecryptStream(new MemoryStream(msg), new MemoryStream(), wrong)).Error);

        // Damage to the last block makes the padding wrong (almost always): the same error, and the final block was never written out.
        byte[] damaged = (byte[])msg.Clone();
        damaged[^20] ^= 0x55;
        var sink = new MemoryStream();
        try
        {
            EnvelopedData.DecryptStream(new MemoryStream(damaged), sink, key);
        }
        catch (CmsParseException e)
        {
            Assert.Equal(CmsError.DecryptionFailed, e.Error);
            Assert.True(sink.Length <= Content.Length - 1 || sink.Length < Content.Length + 16);
        }
    }

    [Fact]
    public void AuthEnvelopedStreamsAreBufferedAndAuthenticated()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.P384);
        var ms = new MemoryStream();
        AuthEnvelopedData.EncryptStream(new MemoryStream(Content), ms, [CmsRecipient.KeyAgreement(kit.Certificate)]);
        using CmsDecryptionKey key = kit.Key();
        var plain = new MemoryStream();
        AuthEnvelopedData.DecryptStream(new MemoryStream(ms.ToArray()), plain, key);
        Assert.Equal(Content, plain.ToArray());
        byte[] bad = ms.ToArray();
        bad[bad.Length / 2] ^= 1;
        var sink = new MemoryStream();
        Assert.Throws<CmsParseException>(() => AuthEnvelopedData.DecryptStream(new MemoryStream(bad), sink, key));
        Assert.Equal(0, sink.Length);
        Assert.Throws<CmsParseException>(() => AuthEnvelopedData.DecryptStream(new MemoryStream(ms.ToArray()), new MemoryStream(), key, new CmsDecryptOptions { Limits = new CmsLimits { MaxContentBytes = 1000 } }));
    }

    /// <summary>A stream of pseudo-random bytes that never exists in memory.</summary>
    private sealed class Endless(long length) : Stream
    {
        private long _left = length;
        private ulong _state = 0x9E3779B97F4A7C15;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = (int)Math.Min(count, _left);
            for (int i = 0; i < n; i++)
            {
                _state = (_state * 6364136223846793005UL) + 1442695040888963407UL;
                buffer[offset + i] = (byte)(_state >> 56);
            }

            _left -= n;
            return n;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>Counts bytes and keeps a SHA-256 of them.</summary>
    private sealed class HashSink : Stream
    {
        private readonly IncrementalHash _h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        public long Count { get; private set; }

        public byte[] Hash() => _h.GetHashAndReset();

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

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            _h.AppendData(buffer);
            Count += buffer.Length;
        }
    }

    /// <summary>A write-only file stream that is read back later: the message of a large run lives on disk, not in memory.</summary>
    private static string BigFile(string name) => Path.Combine(OpenSslSignedDataTests.Dir("big"), name);

    [Fact]
    public void OneGibSignsVerifiesEncryptsAndDecryptsInConstantMemory()
    {
        string? gib = Environment.GetEnvironmentVariable("ONECRYPTO_STREAM_BYTES");
        Assert.SkipUnless(gib is not null, "set ONECRYPTO_STREAM_BYTES (for example 1073741824) to run the large streaming check");
        long size = long.Parse(gib!, System.Globalization.CultureInfo.InvariantCulture);
        long start = Process.GetCurrentProcess().WorkingSet64;
        long peak = start;
        using var timer = new Timer(_ => peak = Math.Max(peak, Process.GetCurrentProcess().WorkingSet64), null, 0, 50);

        // The expected hash of the content.
        var expected = new HashSink();
        new Endless(size).CopyTo(expected, 1 << 16);
        byte[] contentHash = expected.Hash();

        SignerKit k = CmsKeys.Get(SigKind.P256);
        string signedPath = BigFile("signed.der");
        using (FileStream fs = File.Create(signedPath))
        {
            SignedData.SignStream(new Endless(size), fs, [k.Spec()]);
        }

        var seen = new HashSink();
        using (FileStream fs = File.OpenRead(signedPath))
        {
            Assert.True(SignedData.VerifyStream(fs, seen).IsValid);
        }

        Assert.Equal(size, seen.Count);
        Assert.Equal(contentHash, seen.Hash());
        File.Delete(signedPath);

        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        string encPath = BigFile("enveloped.der");
        using (FileStream fs = File.Create(encPath))
        {
            EnvelopedData.EncryptStream(new Endless(size), fs, [CmsRecipient.KeyTransport(kit.Certificate)]);
        }

        var plain = new HashSink();
        using (CmsDecryptionKey key = kit.Key())
        using (FileStream fs = File.OpenRead(encPath))
        {
            EnvelopedData.DecryptStream(fs, plain, key);
        }

        Assert.Equal(size, plain.Count);
        Assert.Equal(contentHash, plain.Hash());
        File.Delete(encPath);
        peak = Math.Max(peak, Process.GetCurrentProcess().WorkingSet64);
        File.AppendAllText(BigFile("result.txt"), $"stream-check size={size} start-ws={start >> 20}MiB peak-ws={peak >> 20}MiB gc-heap-after={GC.GetTotalMemory(true) >> 20}MiB{Environment.NewLine}");
        Assert.True(peak - start < 200L << 20, $"working set grew by {(peak - start) >> 20} MiB");
    }

    /// <summary>A fuzz finding: a deflate block the inflater rejects as an unsupported method used to leak InvalidDataException from the one-shot decompressor.</summary>
    [Fact]
    public async Task DamagedDeflateDataIsACmsParseErrorOnEveryDecompressPath()
    {
        byte[] file = File.ReadAllBytes(Path.Combine(TestFiles.TestData, "fuzz", "compresseddata-unsupported-deflate-method.bin"));
        byte[] message = file[1..]; // the first byte only selected the fuzz target
        CompressedData cd = CompressedData.Parse(message);
        Assert.Throws<CmsParseException>(() => cd.Decompress());
        Assert.Throws<CmsParseException>(() => CompressedData.DecompressStream(new MemoryStream(message), Stream.Null));
        await Assert.ThrowsAsync<CmsParseException>(() => CompressedData.DecompressStreamAsync(new MemoryStream(message), Stream.Null));
    }
}
