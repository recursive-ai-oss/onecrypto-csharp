using System.Diagnostics;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace OneCrypto.Tests.Cms;

/// <summary>The asynchronous twins of the streaming CMS operations, the async ASN.1 reader and writer under them, and streaming CompressedData.</summary>
public class AsyncStreamingTests
{
    private static readonly byte[] Content = Enumerable.Range(0, 300_000).Select(static i => (byte)((i * 31) ^ (i >> 7))).ToArray();

    // ---- ASN.1 ----

    /// <summary>Hands out one octet per read, so every header and every content run crosses a buffer boundary.</summary>
    private sealed class Dribble(byte[] data) : Stream
    {
        private int _at;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("the async reader must not read synchronously");

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_at >= data.Length || buffer.IsEmpty)
            {
                return ValueTask.FromResult(0);
            }

            buffer.Span[0] = data[_at++];
            return ValueTask.FromResult(1);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task TheAsyncReaderSeesTheSameTokensAsTheSynchronousOne()
    {
        SignerKit k = CmsKeys.Get(SigKind.P256);
        var ms = new MemoryStream();
        SignedData.SignStream(new MemoryStream(Content[..5000]), ms, [k.Spec()]);
        byte[] msg = ms.ToArray();

        var sync = new List<string>();
        var rs = new Asn1StreamReader(new MemoryStream(msg));
        while (rs.TryReadToken(out Asn1Token t))
        {
            sync.Add(Describe(t, t.Kind == Asn1TokenKind.Primitive && t.Length <= 4096 ? rs.ReadContent() : []));
        }

        var async = new List<string>();
        var ra = new Asn1StreamReader(new Dribble(msg));
        while (true)
        {
            (bool ok, Asn1Token t) = await ra.TryReadTokenAsync();
            if (!ok)
            {
                break;
            }

            async.Add(Describe(t, t.Kind == Asn1TokenKind.Primitive && t.Length <= 4096 ? await ra.ReadContentAsync() : []));
        }

        Assert.Equal(sync, async);
        Assert.True(sync.Count > 20);

        // A stream that ends inside an element fails the same way.
        var cut = new Asn1StreamReader(new Dribble(msg[..200]));
        await Assert.ThrowsAsync<Asn1ParseException>(async () =>
        {
            while (true)
            {
                Asn1Token t = await cut.ReadTokenAsync();
                if (t.Kind == Asn1TokenKind.Primitive)
                {
                    await cut.ReadContentAsync();
                }
            }
        });
    }

    private static string Describe(Asn1Token t, byte[] content) => $"{t.Kind}/{t.Tag.TagClass}/{t.Tag.TagNumber}/{t.Length}/{t.Offset}/{Convert.ToHexString(content)}";

    [Fact]
    public async Task TheAsyncWriterWritesTheBytesOfTheSynchronousOne()
    {
        var a = new MemoryStream();
        var wa = new BerStreamWriter(a);
        wa.BeginIndefinite(Asn1Tag.Sequence);
        wa.WriteEncodedValue(DerWriter.Oid("1.2.840.113549.1.7.1"));
        wa.WriteOctetStringFrom(new MemoryStream(Content), 1000, Asn1Tag.Context(0, true));
        wa.WriteDefinite(new Asn1Tag(Asn1Tags.OctetString), Content.AsSpan(0, 10));
        wa.End();

        var b = new MemoryStream();
        var wb = new BerStreamWriter(b);
        await wb.BeginIndefiniteAsync(Asn1Tag.Sequence);
        await wb.WriteEncodedValueAsync(DerWriter.Oid("1.2.840.113549.1.7.1"));
        await wb.WriteOctetStringFromAsync(new MemoryStream(Content), 1000, Asn1Tag.Context(0, true));
        await wb.WriteDefiniteAsync(new Asn1Tag(Asn1Tags.OctetString), Content.AsMemory(0, 10));
        await wb.EndAsync();

        Assert.Equal(a.ToArray(), b.ToArray());
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await wb.EndAsync());
    }

    // ---- CMS round trips, both directions with the synchronous forms ----

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignedDataStreamsAsyncAndSyncInterchange(bool detached)
    {
        SignerKit k = CmsKeys.Get(SigKind.Rsa);
        var options = new SignedDataOptions { Detached = detached };

        var asyncMsg = new MemoryStream();
        await SignedData.SignStreamAsync(new Dribble(Content), asyncMsg, [k.Spec()], options);
        var syncMsg = new MemoryStream();
        SignedData.SignStream(new MemoryStream(Content), syncMsg, [k.Spec()], options);

        if (detached)
        {
            Assert.True(SignedData.Parse(asyncMsg.ToArray()).Verify(Content).IsValid);
            Assert.True(SignedData.Parse(syncMsg.ToArray()).Verify(new MemoryStream(Content)).IsValid);
            return;
        }

        var seen = new MemoryStream();
        Assert.True((await SignedData.VerifyStreamAsync(new Dribble(asyncMsg.ToArray()), seen)).IsValid);
        Assert.Equal(Content, seen.ToArray());
        var seen2 = new MemoryStream();
        Assert.True((await SignedData.VerifyStreamAsync(new MemoryStream(syncMsg.ToArray()), seen2)).IsValid);
        Assert.Equal(Content, seen2.ToArray());
        Assert.True(SignedData.VerifyStream(new MemoryStream(asyncMsg.ToArray())).IsValid);

        byte[] tampered = syncMsg.ToArray();
        tampered[1000] ^= 1;
        Assert.False((await SignedData.VerifyStreamAsync(new MemoryStream(tampered))).IsValid);
    }

    [Fact]
    public async Task EnvelopedDataStreamsAsyncAndSyncInterchange()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        CmsRecipient[] recipients = [CmsRecipient.KeyTransport(kit.Certificate)];
        using CmsDecryptionKey key = kit.Key();

        var asyncMsg = new MemoryStream();
        await EnvelopedData.EncryptStreamAsync(new Dribble(Content), asyncMsg, recipients);
        var plain = new MemoryStream();
        EnvelopedData.DecryptStream(new MemoryStream(asyncMsg.ToArray()), plain, key);
        Assert.Equal(Content, plain.ToArray());

        var syncMsg = new MemoryStream();
        EnvelopedData.EncryptStream(new MemoryStream(Content), syncMsg, recipients);
        var plain2 = new MemoryStream();
        await EnvelopedData.DecryptStreamAsync(new Dribble(syncMsg.ToArray()), plain2, key);
        Assert.Equal(Content, plain2.ToArray());

        // Its own output opens one-shot as well.
        Assert.Equal(Content, EnvelopedData.Parse(asyncMsg.ToArray()).Decrypt(key));

        // Uniform failure with a wrong key, after the whole content was read.
        using RSA other = RSA.Create(2048);
        using CmsDecryptionKey wrong = CmsDecryptionKey.FromRsa(other);
        CmsParseException e = await Assert.ThrowsAsync<CmsParseException>(async () => await EnvelopedData.DecryptStreamAsync(new MemoryStream(asyncMsg.ToArray()), new MemoryStream(), wrong));
        Assert.Contains(e.Error, new[] { CmsError.DecryptionFailed, CmsError.NoMatchingRecipient });
    }

    [Fact]
    public async Task AuthEnvelopedDataStreamsAsyncAndSyncInterchange()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        CmsRecipient[] recipients = [CmsRecipient.KeyTransport(kit.Certificate)];
        using CmsDecryptionKey key = kit.Key();

        var asyncMsg = new MemoryStream();
        await AuthEnvelopedData.EncryptStreamAsync(new Dribble(Content), asyncMsg, recipients);
        var plain = new MemoryStream();
        AuthEnvelopedData.DecryptStream(new MemoryStream(asyncMsg.ToArray()), plain, key);
        Assert.Equal(Content, plain.ToArray());

        var syncMsg = new MemoryStream();
        AuthEnvelopedData.EncryptStream(new MemoryStream(Content), syncMsg, recipients);
        var plain2 = new MemoryStream();
        await AuthEnvelopedData.DecryptStreamAsync(new Dribble(syncMsg.ToArray()), plain2, key);
        Assert.Equal(Content, plain2.ToArray());

        // A damaged tag releases nothing.
        byte[] damaged = asyncMsg.ToArray();
        damaged[^3] ^= 1;
        var sink = new MemoryStream();
        await Assert.ThrowsAsync<CmsParseException>(async () => await AuthEnvelopedData.DecryptStreamAsync(new MemoryStream(damaged), sink, key));
        Assert.Equal(0, sink.Length);
    }

    // ---- cancellation ----

    /// <summary>Cancels the token once <paramref name="after"/> octets were read, then keeps serving data.</summary>
    private sealed class CancelAfter(byte[] data, long after, CancellationTokenSource cts) : Stream
    {
        private int _at;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("the async path must not read synchronously");

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int n = Math.Min(Math.Min(buffer.Length, 8192), data.Length - _at);
            data.AsSpan(_at, n).CopyTo(buffer.Span);
            _at += n;
            if (_at >= after)
            {
                cts.Cancel();
            }

            return ValueTask.FromResult(n);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task CancellingSigningOrEncryptingStopsAndTheOutputIsPartial()
    {
        SignerKit k = CmsKeys.Get(SigKind.P256);
        using var cts = new CancellationTokenSource();
        var output = new MemoryStream();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await SignedData.SignStreamAsync(new CancelAfter(Content, 50_000, cts), output, [k.Spec()], null, cts.Token));
        Assert.True(output.Length < Content.Length, "the message was not finished");

        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        using var cts2 = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await EnvelopedData.EncryptStreamAsync(new CancelAfter(Content, 50_000, cts2), new MemoryStream(), [CmsRecipient.KeyTransport(kit.Certificate)], null, cts2.Token));
    }

    [Fact]
    public async Task CancellingADecryptionReleasesNoPlaintextAfterTheCancelAndNeverTheFinalBlock()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        using CmsDecryptionKey key = kit.Key();

        // CBC: plaintext flows as it is read (documented); a cancellation stops it, and the final block, which carries the padding, is never released.
        var enc = new MemoryStream();
        EnvelopedData.EncryptStream(new MemoryStream(Content), enc, [CmsRecipient.KeyTransport(kit.Certificate)]);
        using var cts = new CancellationTokenSource();
        var sink = new MemoryStream();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await EnvelopedData.DecryptStreamAsync(new CancelAfter(enc.ToArray(), 100_000, cts), sink, key, null, cts.Token));
        Assert.True(sink.Length < Content.Length - 16, $"{sink.Length} octets were released of {Content.Length}");
        Assert.Equal(Content.AsSpan(0, (int)sink.Length).ToArray(), sink.ToArray());

        // AuthEnveloped: nothing is released before the tag is checked, so a cancellation leaves the sink empty.
        var authEnc = new MemoryStream();
        AuthEnvelopedData.EncryptStream(new MemoryStream(Content), authEnc, [CmsRecipient.KeyTransport(kit.Certificate)]);
        using var cts2 = new CancellationTokenSource();
        var sink2 = new MemoryStream();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await AuthEnvelopedData.DecryptStreamAsync(new CancelAfter(authEnc.ToArray(), 100_000, cts2), sink2, key, null, cts2.Token));
        Assert.Equal(0, sink2.Length);

        // An already-cancelled token stops before any work.
        using var done = new CancellationTokenSource();
        done.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await AuthEnvelopedData.DecryptStreamAsync(new MemoryStream(authEnc.ToArray()), new MemoryStream(), key, null, done.Token));
    }

    // ---- CompressedData ----

    private static byte[] IndefiniteCompressed(byte[] zlib)
    {
        var ms = new MemoryStream();
        var w = new BerStreamWriter(ms);
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.Oid(CmsOids.CompressedData));
        w.BeginIndefinite(Asn1Tag.Context(0, true));
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.SignedInteger(0));
        w.WriteEncodedValue(DerWriter.Sequence(DerWriter.Oid(CmsOids.ZlibCompress)));
        w.BeginIndefinite(Asn1Tag.Sequence);
        w.WriteEncodedValue(DerWriter.Oid(CmsOids.Data));
        w.BeginIndefinite(Asn1Tag.Context(0, true));
        w.WriteOctetStringFrom(new MemoryStream(zlib), 777);
        w.End();
        w.End();
        w.End();
        w.End();
        w.End();
        return ms.ToArray();
    }

    [Fact]
    public async Task CompressedDataDecompressesAsAStreamWithABoundedOutput()
    {
        byte[] definite = CompressedData.Create(Content).Encoded.ToArray();
        var a = new MemoryStream();
        CompressedData.DecompressStream(new MemoryStream(definite), a);
        Assert.Equal(Content, a.ToArray());

        byte[] zlib = CompressedData.Parse(definite).CompressedContent.ToArray();
        byte[] indefinite = IndefiniteCompressed(zlib);
        var b = new MemoryStream();
        CompressedData.DecompressStream(new MemoryStream(indefinite), b);
        Assert.Equal(Content, b.ToArray());
        var c = new MemoryStream();
        await CompressedData.DecompressStreamAsync(new Dribble(indefinite), c);
        Assert.Equal(Content, c.ToArray());

        // A compression bomb stops at the ratio limit with a small output, in both forms.
        byte[] zeros = new byte[64 << 20];
        byte[] bomb = CompressedData.Create(zeros).Encoded.ToArray();
        var limits = new CmsLimits { MaxDecompressionRatio = 100 };
        var sink = new MemoryStream();
        CmsParseException e = Assert.Throws<CmsParseException>(() => CompressedData.DecompressStream(new MemoryStream(bomb), sink, limits));
        Assert.Equal(CmsError.LimitExceeded, e.Error);
        Assert.True(sink.Length < 16 << 20, $"{sink.Length} octets were written before the stop");
        var sink2 = new MemoryStream();
        e = await Assert.ThrowsAsync<CmsParseException>(async () => await CompressedData.DecompressStreamAsync(new MemoryStream(bomb), sink2, limits));
        Assert.Equal(CmsError.LimitExceeded, e.Error);
        var capped = new MemoryStream();
        e = Assert.Throws<CmsParseException>(() => CompressedData.DecompressStream(new MemoryStream(definite), capped, new CmsLimits { MaxDecompressedBytes = 1000 }));
        Assert.Equal(CmsError.LimitExceeded, e.Error);

        // Damaged data and the wrong content type are typed errors.
        byte[] damaged = (byte[])definite.Clone();
        damaged[damaged.Length / 2] ^= 0x55;
        Assert.ThrowsAny<CmsParseException>(() => CompressedData.DecompressStream(new MemoryStream(damaged), new MemoryStream()));
        Assert.Throws<CmsParseException>(() => CompressedData.DecompressStream(new MemoryStream(EnvelopedData.Create(Content, [CmsRecipient.KeyEncryptionKey(new byte[16], [1])]).Encoded.ToArray()), new MemoryStream()));
    }

    // ---- 1 GiB, run on request ----

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

        public override int Read(byte[] buffer, int offset, int count) => Fill(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => ValueTask.FromResult(Fill(buffer.Span));

        private int Fill(Span<byte> buffer)
        {
            int n = (int)Math.Min(buffer.Length, _left);
            for (int i = 0; i < n; i++)
            {
                _state = (_state * 6364136223846793005UL) + 1442695040888963407UL;
                buffer[i] = (byte)(_state >> 56);
            }

            _left -= n;
            return n;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

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

    private static string BigFile(string name) => Path.Combine(OpenSslSignedDataTests.Dir("big-async"), name);

    [Fact]
    public async Task OneGibRoundTripsThroughEachAsyncTwinInConstantMemory()
    {
        string? gib = Environment.GetEnvironmentVariable("ONECRYPTO_STREAM_BYTES");
        Assert.SkipUnless(gib is not null, "set ONECRYPTO_STREAM_BYTES (for example 1073741824) to run the large async streaming check");
        long size = long.Parse(gib!, System.Globalization.CultureInfo.InvariantCulture);
        long authSize = long.Parse(Environment.GetEnvironmentVariable("ONECRYPTO_AUTH_STREAM_BYTES") ?? "134217728", System.Globalization.CultureInfo.InvariantCulture);
        long start = Process.GetCurrentProcess().WorkingSet64;
        long peak = start;
        using var timer = new Timer(_ => peak = Math.Max(peak, Process.GetCurrentProcess().WorkingSet64), null, 0, 50);
        async Task<byte[]> ExpectedHash(long n)
        {
            var expected = new HashSink();
            await new Endless(n).CopyToAsync(expected, 1 << 16);
            return expected.Hash();
        }

        byte[] contentHash = await ExpectedHash(size);
        var report = new System.Text.StringBuilder();

        // SignStreamAsync and VerifyStreamAsync.
        SignerKit k = CmsKeys.Get(SigKind.P256);
        string signedPath = BigFile("signed.der");
        await using (FileStream fs = new(signedPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, useAsync: true))
        {
            await SignedData.SignStreamAsync(new Endless(size), fs, [k.Spec()]);
        }

        var seen = new HashSink();
        await using (FileStream fs = new(signedPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, useAsync: true))
        {
            Assert.True((await SignedData.VerifyStreamAsync(fs, seen)).IsValid);
        }

        Assert.Equal(size, seen.Count);
        Assert.Equal(contentHash, seen.Hash());
        File.Delete(signedPath);
        report.Append($"sign+verify peak-ws={peak >> 20}MiB; ");

        // EncryptStreamAsync and DecryptStreamAsync (AES-CBC).
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        string encPath = BigFile("enveloped.der");
        await using (FileStream fs = new(encPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, useAsync: true))
        {
            await EnvelopedData.EncryptStreamAsync(new Endless(size), fs, [CmsRecipient.KeyTransport(kit.Certificate)]);
        }

        var plain = new HashSink();
        using (CmsDecryptionKey key = kit.Key())
        await using (FileStream fs = new(encPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, useAsync: true))
        {
            await EnvelopedData.DecryptStreamAsync(fs, plain, key);
        }

        Assert.Equal(size, plain.Count);
        Assert.Equal(contentHash, plain.Hash());
        File.Delete(encPath);
        report.Append($"encrypt+decrypt peak-ws={peak >> 20}MiB; ");
        long constantPeak = peak;

        // AuthEnvelopedData: the platform's AEAD is one-shot, so the content is held in memory (as in the synchronous form). Run at a smaller size.
        byte[] authHash = await ExpectedHash(authSize);
        string authPath = BigFile("auth.der");
        await using (FileStream fs = new(authPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, useAsync: true))
        {
            await AuthEnvelopedData.EncryptStreamAsync(new Endless(authSize), fs, [CmsRecipient.KeyTransport(kit.Certificate)], null, new CmsLimits { MaxContentBytes = authSize + (1 << 20) });
        }

        var authPlain = new HashSink();
        using (CmsDecryptionKey key = kit.Key())
        await using (FileStream fs = new(authPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, useAsync: true))
        {
            await AuthEnvelopedData.DecryptStreamAsync(fs, authPlain, key, new CmsDecryptOptions { Limits = new CmsLimits { MaxContentBytes = authSize + (1 << 20) } });
        }

        Assert.Equal(authSize, authPlain.Count);
        Assert.Equal(authHash, authPlain.Hash());
        File.Delete(authPath);
        peak = Math.Max(peak, Process.GetCurrentProcess().WorkingSet64);
        report.Append($"auth({authSize >> 20}MiB) peak-ws={peak >> 20}MiB");
        File.AppendAllText(BigFile("result.txt"), $"async-stream-check size={size} start-ws={start >> 20}MiB constant-ops-peak-ws={constantPeak >> 20}MiB {report}{Environment.NewLine}");
        Assert.True(constantPeak - start < 200L << 20, $"working set grew by {(constantPeak - start) >> 20} MiB");
    }

    /// <summary>A CompressedData whose algorithm OID is damaged raises the typed CMS error on both twins (a fuzz finding: it escaped as an X.509 parse error).</summary>
    [Fact]
    public async Task DamagedCompressionAlgorithmIsATypedError()
    {
        byte[] msg = Convert.FromHexString("301B060B2A864886F70D0109100109A00C300A020100300506 03FFFFFF".Replace(" ", ""));
        Assert.Throws<CmsParseException>(() => CompressedData.DecompressStream(new MemoryStream(msg), Stream.Null));
        await Assert.ThrowsAsync<CmsParseException>(() => CompressedData.DecompressStreamAsync(new MemoryStream(msg), Stream.Null));
    }
}
