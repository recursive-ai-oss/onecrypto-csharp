using System.Net;
using System.Net.Sockets;
using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Online.Tests;

/// <summary>
/// A server that behaves like a responder which closes its connection after each answer, but advertises keep-alive: it answers the first request on a connection,
/// then reads the next request on that same connection and drops it without a word. The client's pool offers that dead connection to the next request, so the
/// failure is the same every run, not a matter of timing.
/// </summary>
internal sealed class ClosingPeer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly Func<byte[], byte[]> _answer;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;
    private int _dropped;
    private int _served;

    public ClosingPeer(Func<byte[], byte[]> answer, string contentType)
    {
        _answer = answer;
        ContentType = contentType;
        _listener.Start();
        _loop = Task.Run(AcceptLoop);
    }

    public string ContentType { get; }

    public Uri Uri => new($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/");

    public int Dropped => Volatile.Read(ref _dropped);

    public int Served => Volatile.Read(ref _served);

    private async Task AcceptLoop()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient c = await _listener.AcceptTcpClientAsync(_stop.Token);
                _ = Task.Run(() => Connection(c));
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private async Task Connection(TcpClient client)
    {
        using (client)
        {
            try
            {
                NetworkStream s = client.GetStream();
                bool first = true;
                while (true)
                {
                    byte[]? body = await ReadRequest(s);
                    if (body is null)
                    {
                        return;
                    }

                    if (!first)
                    {
                        Interlocked.Increment(ref _dropped);
                        client.Client.LingerState = new LingerOption(true, 0); // reset, as a peer that has already closed would
                        return;
                    }

                    first = false;
                    byte[] reply = _answer(body);
                    Interlocked.Increment(ref _served);
                    string head = $"HTTP/1.1 200 OK\r\nContent-Type: {ContentType}\r\nContent-Length: {reply.Length}\r\nConnection: keep-alive\r\n\r\n";
                    await s.WriteAsync(Encoding.ASCII.GetBytes(head));
                    await s.WriteAsync(reply);
                }
            }
            catch (IOException)
            {
            }
            catch (SocketException)
            {
            }
        }
    }

    private static async Task<byte[]?> ReadRequest(NetworkStream s)
    {
        var head = new List<byte>();
        var one = new byte[1];
        while (true)
        {
            if (await s.ReadAsync(one) == 0)
            {
                return null;
            }

            head.Add(one[0]);
            int n = head.Count;
            if (n >= 4 && head[n - 4] == '\r' && head[n - 3] == '\n' && head[n - 2] == '\r' && head[n - 1] == '\n')
            {
                break;
            }
        }

        string text = Encoding.ASCII.GetString([.. head]);
        int length = 0;
        foreach (string line in text.Split("\r\n"))
        {
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
            {
                length = int.Parse(line["Content-Length:".Length..].Trim(), System.Globalization.CultureInfo.InvariantCulture);
            }
        }

        var body = new byte[length];
        int got = 0;
        while (got < length)
        {
            int r = await s.ReadAsync(body.AsMemory(got));
            if (r == 0)
            {
                return null;
            }

            got += r;
        }

        return body;
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        try
        {
            _loop.Wait(1000);
        }
        catch (AggregateException)
        {
        }
    }
}

public class ClosingPeerTests
{
    private static World W => World.Get();

    private static byte[] OcspAnswer(byte[] request) => W.Responder.Handle(request, World.Now).Encoded.ToArray();

    [Fact]
    public async Task AnOcspPostSurvivesAPeerThatClosesAfterEachAnswer()
    {
        using var peer = new ClosingPeer(OcspAnswer, "application/ocsp-response");
        using var transport = new HttpTransport();
        var client = new OcspClient(new Fetcher(transport, new FetchOptions { Cache = null }));
        var options = new OcspQueryOptions { ResponderUri = peer.Uri, Method = OcspHttpMethod.Post, UseNonce = true, RequireNonce = false, ReferenceTime = World.Now };

        for (int i = 0; i < 3; i++)
        {
            OcspQueryResult r = await client.QueryAsync(W.Good, W.Intermediate.Certificate, options);
            Assert.True(r.Outcome == OcspOutcome.Answered, $"query {i}: {r.Outcome}: {r.Reason}");
            Assert.Equal(OcspCertStatus.Good, r.Answer!.Status);
        }

        Assert.True(peer.Dropped >= 1, "the peer never saw a request on a reused connection, so the test proved nothing");
    }

    [Fact]
    public async Task APostThatIsNotMarkedRepeatableIsNotSentAgainAndSaysWhy()
    {
        using var peer = new ClosingPeer(_ => [1], "application/octet-stream");
        using var transport = new HttpTransport();
        var fetcher = new Fetcher(transport, new FetchOptions { Cache = null });
        FetchRequest Post() => new() { Uri = peer.Uri, Method = "POST", Body = new byte[] { 1, 2, 3 } };

        Assert.True((await fetcher.FetchAsync(Post())).IsSuccess);
        FetchResult second = await fetcher.FetchAsync(Post());
        Assert.Equal(FetchOutcome.NetworkError, second.Outcome);
        Assert.NotEmpty(second.Reason);
        Assert.Equal(1, peer.Dropped);

        // The failed attempt left no pooled connection; one request opens a fresh one, and a repeatable request that meets the dead pooled connection recovers.
        Assert.True((await fetcher.FetchAsync(Post())).IsSuccess);
        FetchResult again = await fetcher.FetchAsync(new FetchRequest { Uri = peer.Uri, Method = "POST", Body = new byte[] { 1 }, Idempotent = true });
        Assert.True(again.IsSuccess, again.Reason);
    }
}
