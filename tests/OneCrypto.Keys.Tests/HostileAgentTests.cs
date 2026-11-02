using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Keys.Agents;
using RecursiveAI.OneCrypto.Wire.Ssh;

namespace OneCrypto.Keys.Tests;

/// <summary>A scripted agent on a Unix socket, for replies no real agent would send.</summary>
internal sealed class FakeAgent : IDisposable
{
    private readonly Socket _listener;
    private readonly string _dir;
    private readonly Task _loop;
    private long _sent;

    public FakeAgent(Func<Stream, Func<long>, Task> script)
    {
        _dir = Tools.ShortTemp("fake");
        Path = System.IO.Path.Combine(_dir, "s");
        _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _listener.Bind(new UnixDomainSocketEndPoint(Path));
        _listener.Listen(8);
        _loop = Task.Run(async () =>
        {
            while (true)
            {
                Socket s;
                try
                {
                    s = await _listener.AcceptAsync();
                }
                catch (Exception e) when (e is ObjectDisposedException or SocketException)
                {
                    return;
                }

                _ = Task.Run(async () =>
                {
                    using var ns = new NetworkStream(s, ownsSocket: true);
                    try
                    {
                        await script(new CountingStream(ns, n => Interlocked.Add(ref _sent, n)), () => Interlocked.Read(ref _sent));
                    }
                    catch (Exception e) when (e is IOException or ObjectDisposedException or SocketException or InvalidOperationException)
                    {
                        // the client hung up, which is what the bounded readers are meant to do
                    }
                });
            }
        });
    }

    public string Path { get; }

    public long BytesSent => Interlocked.Read(ref _sent);

    public void Dispose()
    {
        _listener.Dispose();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // best effort
        }
    }
}

/// <summary>Counts what the fake agent writes.</summary>
internal sealed class CountingStream(NetworkStream inner, Action<long> counted) : Stream
{
    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Flush() => inner.Flush();

    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => await inner.ReadAsync(buffer, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        inner.Write(buffer, offset, count);
        counted(count);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await inner.WriteAsync(buffer, cancellationToken);
        counted(buffer.Length);
    }
}

/// <summary>Hostile and broken agents: every reply that breaks the protocol or the limits gives a typed error, and the client never reads or allocates without bound.</summary>
public class HostileAgentTests
{
    private const string Pleased = "OK Pleased to meet you\n";

    private static async Task<string> Line(Stream s)
    {
        var sb = new StringBuilder();
        var one = new byte[1];
        while (await s.ReadAsync(one) == 1)
        {
            if (one[0] == '\n')
            {
                break;
            }

            sb.Append((char)one[0]);
        }

        return sb.ToString();
    }

    private static Task Send(Stream s, string text) => s.WriteAsync(Encoding.Latin1.GetBytes(text)).AsTask();

    private static GpgAgentClient Gpg(FakeAgent a, int maxReply = 64 * 1024, bool verify = true) =>
        new(new GpgAgentOptions { SocketPath = a.Path, ForwardEnvironment = false, MaxReplyBytes = maxReply, OperationTimeout = TimeSpan.FromSeconds(20), VerifySignatures = verify });

    private static SshAgentClient Ssh(FakeAgent a) => new(new SshAgentOptions { SocketPath = a.Path, OperationTimeout = TimeSpan.FromSeconds(20) });

    private static readonly string Grip = new('A', 40);

    // ---- gpg-agent: framing and limits ----

    [Fact]
    public void AGreetingThatIsNotOkIsAProtocolError()
    {
        using var a = new FakeAgent(async (s, _) => await Send(s, "hello there\n"));
        Assert.Throws<AgentProtocolException>(() => Gpg(a).ListKeys());
    }

    [Fact]
    public void AnErrGreetingIsATypedRefusal()
    {
        using var a = new FakeAgent(async (s, _) => await Send(s, "ERR 67109210 Forbidden <GPG Agent>\n"));
        var e = Assert.Throws<AgentRefusedException>(() => Gpg(a).ListKeys());
        Assert.Equal(4, e.ErrorSource);
        Assert.Contains("Forbidden", e.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void ARepliesThatEndsEarlyIsAProtocolError()
    {
        using var a = new FakeAgent(async (s, _) =>
        {
            await Send(s, Pleased);
            await Line(s);
            await Send(s, "S KEYINFO " + Grip + " D - - - C - - -\n");
        });
        Assert.Throws<AgentProtocolException>(() => Gpg(a).ListKeys());
    }

    [Fact]
    public void AnEndlessStreamOfDataLinesIsCutOffAtTheReplyLimit()
    {
        using var a = new FakeAgent(async (s, _) =>
        {
            await Send(s, Pleased);
            await Line(s);
            string line = "D " + new string('A', 900) + "\n";
            while (true)
            {
                await Send(s, line);
            }
        });
        long before = GC.GetTotalAllocatedBytes(true);
        var e = Assert.Throws<AgentProtocolException>(() => Gpg(a, maxReply: 64 * 1024).GetKey(Grip));
        Assert.Contains("limit", e.Message, StringComparison.Ordinal);
        Assert.True(GC.GetTotalAllocatedBytes(true) - before < 16_000_000, "allocation stays bounded");
        Assert.True(a.BytesSent < 4_000_000, $"the agent managed to send {a.BytesSent} octets");
    }

    [Fact]
    public void AnEndlessStreamOfCommentsIsCutOffToo()
    {
        using var a = new FakeAgent(async (s, _) =>
        {
            await Send(s, Pleased);
            await Line(s);
            while (true)
            {
                await Send(s, "# nothing to see here, keep going\n");
            }
        });
        Assert.Throws<AgentProtocolException>(() => Gpg(a, maxReply: 32 * 1024).ListKeys());
        Assert.True(a.BytesSent < 4_000_000);
    }

    [Fact]
    public void AnOverlongLineWithoutALineEndingIsAProtocolError()
    {
        using var a = new FakeAgent(async (s, _) =>
        {
            await Send(s, Pleased);
            await Line(s);
            string chunk = new('x', 4096);
            while (true)
            {
                await Send(s, chunk);
            }
        });
        var e = Assert.Throws<AgentProtocolException>(() => Gpg(a).ListKeys());
        Assert.Contains("longer", e.Message, StringComparison.Ordinal);
        Assert.True(a.BytesSent < 4_000_000);
    }

    [Theory]
    [InlineData("D %ZZ\nOK\n")]
    [InlineData("D %4\nOK\n")]
    [InlineData("WHAT is this\nOK\n")]
    [InlineData("ERR notanumber oops\n")]
    public void MalformedLinesAreProtocolErrors(string reply)
    {
        using var a = new FakeAgent(async (s, _) =>
        {
            await Send(s, Pleased);
            await Line(s);
            await Send(s, reply);
        });
        Assert.Throws<AgentProtocolException>(() => Gpg(a).GetKey(Grip));
    }

    [Fact]
    public void AnInquiryWeCannotAnswerIsCancelledAndTheAgentsErrorSurfaces()
    {
        string? received = null;
        using var a = new FakeAgent(async (s, _) =>
        {
            await Send(s, Pleased);
            await Line(s);
            await Send(s, "INQUIRE NEEDPIN\n");
            received = await Line(s);
            await Send(s, "ERR 83886179 Operation cancelled <Pinentry>\n");
        });
        var e = Assert.Throws<AgentRefusedException>(() => Gpg(a).ListKeys());
        Assert.True(e.IsCancelled);
        Assert.Equal("CAN", received);
    }

    // ---- gpg-agent: bad key and signature data ----

    private static byte[] RsaPublicKeySExp(RSA rsa)
    {
        RSAParameters p = rsa.ExportParameters(false);
        static byte[] Atom(byte[] v) => [.. Encoding.ASCII.GetBytes(v.Length + ":"), .. v];
        byte[] n = [0, .. p.Modulus!];
        return [.. "(10:public-key(3:rsa(1:n"u8.ToArray(), .. Atom(n), .. ")(1:e"u8.ToArray(), .. Atom(p.Exponent!), .. ")))"u8.ToArray()];
    }

    private static string Escaped(byte[] raw)
    {
        var sb = new StringBuilder();
        foreach (byte b in raw)
        {
            sb.Append(b is (byte)'%' or (byte)'\r' or (byte)'\n' ? "%" + b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture) : ((char)b).ToString());
        }

        return sb.ToString();
    }

    [Theory]
    [InlineData("not an s-expression")]
    [InlineData("(10:public-key(3:rsa(1:n99999999:abc)))")]
    [InlineData("((((((((((((((((((((a))))))))))))))))))))")]
    [InlineData("(10:public-key(3:rsa))")]
    [InlineData("(10:public-key(3:dsa(1:p1:a)))")]
    [InlineData("(10:public-key(3:ecc(5:curve5:Bogus1)(1:q1:a)))")]
    public void ABadPublicKeyIsATypedError(string sexp)
    {
        using var a = new FakeAgent(async (s, _) =>
        {
            await Send(s, Pleased);
            await Line(s);
            await Send(s, "D " + sexp + "\nOK\n");
        });
        Exception e = Assert.ThrowsAny<Exception>(() => Gpg(a).GetKey(Grip));
        Assert.True(e is AgentProtocolException or AlgorithmNotSupportedException, e.GetType().Name);
    }

    [Fact]
    public void ASignatureThatDoesNotVerifyIsRefusedUnlessCheckingIsSwitchedOff()
    {
        using var rsa = RSA.Create(2048);
        byte[] pubExp = RsaPublicKeySExp(rsa);
        byte[] junk = RandomNumberGenerator.GetBytes(256);
        junk[0] &= 0x7F;
        byte[] sigVal = [.. "(7:sig-val(3:rsa(1:s256:"u8.ToArray(), .. junk, .. ")))"u8.ToArray()];
        using var a = new FakeAgent(async (s, _) =>
        {
            await Send(s, Pleased);
            while (true)
            {
                string cmd = await Line(s);
                if (cmd.StartsWith("READKEY", StringComparison.Ordinal))
                {
                    await Send(s, "D " + Escaped(pubExp) + "\nOK\n");
                }
                else if (cmd.StartsWith("PKSIGN", StringComparison.Ordinal))
                {
                    await Send(s, "D " + Escaped(sigVal) + "\nOK\n");
                }
                else if (cmd.Length == 0)
                {
                    return;
                }
                else
                {
                    await Send(s, "OK\n");
                }
            }
        });
        using var key = (GpgAgentRsaKey)Gpg(a).GetKey(Grip);
        var e = Assert.Throws<AgentProtocolException>(() => key.Sign([1], SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)));
        Assert.Contains("does not verify", e.Message, StringComparison.Ordinal);
        using var unchecked_ = (GpgAgentRsaKey)Gpg(a, verify: false).GetKey(Grip);
        Assert.Equal(junk.Length, unchecked_.Sign([1], SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)).Length);
    }

    [Fact]
    public void ASignatureOfAnotherAlgorithmThanTheKeysIsAProtocolError()
    {
        using var rsa = RSA.Create(2048);
        byte[] pubExp = RsaPublicKeySExp(rsa);
        byte[] sigVal = "(7:sig-val(5:ecdsa(1:r1:a)(1:s1:b)))"u8.ToArray();
        using var a = new FakeAgent(async (s, _) =>
        {
            await Send(s, Pleased);
            while (true)
            {
                string cmd = await Line(s);
                if (cmd.StartsWith("READKEY", StringComparison.Ordinal))
                {
                    await Send(s, "D " + Escaped(pubExp) + "\nOK\n");
                }
                else if (cmd.StartsWith("PKSIGN", StringComparison.Ordinal))
                {
                    await Send(s, "D " + Escaped(sigVal) + "\nOK\n");
                }
                else if (cmd.Length == 0)
                {
                    return;
                }
                else
                {
                    await Send(s, "OK\n");
                }
            }
        });
        using var key = (GpgAgentRsaKey)Gpg(a).GetKey(Grip);
        Assert.Throws<AgentProtocolException>(() => key.Sign([1], SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ASchemeThePlatformCannotVerifyIsRefusedUnlessTheCallerOptsOut(bool gap, bool allow)
    {
        using var rsa = RSA.Create(2048);
        byte[] pubExp = RsaPublicKeySExp(rsa);
        using var a = new FakeAgent(async (s, _) =>
        {
            await Send(s, Pleased);
            while (true)
            {
                string cmd = await Line(s);
                if (cmd.StartsWith("READKEY", StringComparison.Ordinal))
                {
                    await Send(s, "D " + Escaped(pubExp) + "\nOK\n");
                }
                else if (cmd.Length == 0)
                {
                    return;
                }
                else
                {
                    await Send(s, "OK\n");
                }
            }
        });
        var client = new GpgAgentClient(new GpgAgentOptions { SocketPath = a.Path, ForwardEnvironment = false, SimulateVerificationGap = gap, AllowUncheckedSignatures = allow });
        using var key = (GpgAgentRsaKey)client.GetKey(Grip);
        SignatureSpec spec = SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256);
        byte[] data = [1, 2, 3];
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (gap && !allow)
        {
            Assert.Throws<AlgorithmNotSupportedException>(() => key.CheckSignature(spec, sig, data, false));
        }
        else
        {
            Assert.Equal(sig, key.CheckSignature(spec, sig, data, false));
        }
    }

    // ---- ssh-agent ----

    private static byte[] Frame(byte[] body) => [(byte)(body.Length >> 24), (byte)(body.Length >> 16), (byte)(body.Length >> 8), (byte)body.Length, .. body];

    private static async Task ReadRequest(Stream s)
    {
        var h = new byte[4];
        await s.ReadExactlyAsync(h);
        int n = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3];
        await s.ReadExactlyAsync(new byte[n]);
    }

    [Theory]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF })]
    [InlineData(new byte[] { 0, 0, 0, 0 })]
    [InlineData(new byte[] { 0, 4, 0, 1 })]
    [InlineData(new byte[] { 0, 0, 0, 2, 6, 0 })]
    [InlineData(new byte[] { 0, 0, 0, 100, 12, 0, 0 })]
    public void BrokenSshAgentRepliesAreProtocolErrors(byte[] reply)
    {
        using var a = new FakeAgent(async (s, _) =>
        {
            await ReadRequest(s);
            await s.WriteAsync(reply);
        });
        long before = GC.GetTotalAllocatedBytes(true);
        Assert.Throws<AgentProtocolException>(() => Ssh(a).ListIdentities());
        // Process-wide count, so tests running in parallel add to it; the bound only has to catch allocating an announced length of up to 4 GiB.
        Assert.True(GC.GetTotalAllocatedBytes(true) - before < 64_000_000, "a huge announced length allocates nothing");
    }

    [Fact]
    public void AKeyCountThatTheReplyCannotHoldIsAProtocolError()
    {
        using var a = new FakeAgent(async (s, _) =>
        {
            await ReadRequest(s);
            await s.WriteAsync(Frame([12, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]));
        });
        Assert.Throws<AgentProtocolException>(() => Ssh(a).ListIdentities());
    }

    [Fact]
    public void AFailureReplyToASignRequestIsATypedRefusal()
    {
        using var a = new FakeAgent(async (s, _) =>
        {
            await ReadRequest(s);
            await s.WriteAsync(Frame([5]));
        });
        Assert.Throws<AgentRefusedException>(() => Ssh(a).SignRawAsync(new byte[] { 1 }, new byte[] { 2 }, 0).AsTask().GetAwaiter().GetResult());
    }

    private static byte[] SshStr(byte[] b) => [(byte)(b.Length >> 24), (byte)(b.Length >> 16), (byte)(b.Length >> 8), (byte)b.Length, .. b];

    private static byte[] SshStr(string s) => SshStr(Encoding.ASCII.GetBytes(s));

    private static byte[] Mpint(byte[] magnitude)
    {
        byte[] m = magnitude.SkipWhile(x => x == 0).ToArray();
        return SshStr(m.Length > 0 && (m[0] & 0x80) != 0 ? [0, .. m] : m);
    }

    [Theory]
    [InlineData("downgrade")]
    [InlineData("wrongkey")]
    public void ASignatureThatIsNotWhatWasAskedForIsAProtocolError(string mode)
    {
        using var rsa = RSA.Create(2048);
        using var other = RSA.Create(2048);
        RSAParameters p = rsa.ExportParameters(false);
        byte[] blob = [.. SshStr("ssh-rsa"), .. Mpint(p.Exponent!), .. Mpint(p.Modulus!)];
        using var a = new FakeAgent(async (s, _) =>
        {
            while (true)
            {
                var h = new byte[4];
                if (await s.ReadAsync(h) < 4)
                {
                    return;
                }

                int n = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3];
                var req = new byte[n];
                await s.ReadExactlyAsync(req);
                if (req[0] == 11)
                {
                    await s.WriteAsync(Frame([12, 0, 0, 0, 1, .. SshStr(blob), .. SshStr("comment")]));
                    continue;
                }

                // The data to sign follows the key blob in the request.
                var r = new SshReader(req.AsSpan(1), "request");
                r.ReadString();
                byte[] data = r.ReadString().ToArray();
                byte[] sigBytes;
                string name;
                if (mode == "downgrade")
                {
                    // A valid SHA-1 signature under the old name, to a request for rsa-sha2-256.
#pragma warning disable CA5350
                    sigBytes = rsa.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
#pragma warning restore CA5350
                    name = "ssh-rsa";
                }
                else
                {
                    sigBytes = other.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    name = "rsa-sha2-256";
                }

                await s.WriteAsync(Frame([14, .. SshStr([.. SshStr(name), .. SshStr(sigBytes)])]));
            }
        });
        using SshAgentKey key = Ssh(a).GetKey(SshPublicKey.Parse(blob));
        var e = Assert.Throws<AgentProtocolException>(() => key.Sign([1, 2, 3], SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256)));
        Assert.Contains(mode == "downgrade" ? "ssh-rsa" : "does not verify", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAgentThatNeverAnswersIsCutOffByTheOperationTimeout()
    {
        using var a = new FakeAgent(async (s, _) =>
        {
            await ReadRequest(s);
            await Task.Delay(TimeSpan.FromSeconds(30));
        });
        var client = new SshAgentClient(new SshAgentOptions { SocketPath = a.Path, OperationTimeout = TimeSpan.FromMilliseconds(500) });
        Assert.Throws<AgentUnavailableException>(() => client.ListIdentities());
    }

    [Fact]
    public void ASocketPathThatIsTooLongIsAnUnavailableError()
    {
        var client = new SshAgentClient(new SshAgentOptions { SocketPath = "/tmp/" + new string('a', 300) });
        Assert.Throws<AgentUnavailableException>(() => client.ListIdentities());
    }
}
