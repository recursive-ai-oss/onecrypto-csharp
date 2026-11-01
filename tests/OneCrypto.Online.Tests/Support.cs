using System.Net;
using System.Net.Sockets;
using System.Text;
using RecursiveAI.OneCrypto.Online;

namespace OneCrypto.Online.Tests;

/// <summary>A response for <see cref="FakeNetwork"/>.</summary>
internal sealed record Reply(int Status, byte[] Body, params (string Name, string Value)[] Headers)
{
    public static Reply Ok(byte[] body, string contentType, params (string, string)[] more) =>
        new(200, body, [("Content-Type", contentType), .. more]);

    public static Reply Redirect(string location, int status = 302) => new(status, [], ("Location", location));

    public static Reply Code(int status) => new(status, []);
}

/// <summary>A transport that answers from a function and remembers what it was asked. Nothing leaves the process.</summary>
internal sealed class FakeNetwork : ITransport
{
    private readonly Func<TransportRequest, Reply> _handler;
    private readonly object _gate = new();

    public FakeNetwork(Func<TransportRequest, Reply> handler) => _handler = handler;

    public List<TransportRequest> Requests { get; } = [];

    public int Count(string startsWith)
    {
        lock (_gate)
        {
            return Requests.Count(r => r.Uri.AbsoluteUri.StartsWith(startsWith, StringComparison.Ordinal));
        }
    }

    public ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            Requests.Add(request);
        }

        Reply r = _handler(request);
        return ValueTask.FromResult(new TransportResponse(r.Status, [.. r.Headers.Select(h => new KeyValuePair<string, string>(h.Name, h.Value))], new MemoryStream(r.Body, writable: false)));
    }
}

/// <summary>A transport whose answer the test builds, including streams that stall or fail.</summary>
internal sealed class StreamNetwork : ITransport
{
    private readonly Func<TransportRequest, CancellationToken, TransportResponse> _make;

    public StreamNetwork(Func<TransportRequest, CancellationToken, TransportResponse> make) => _make = make;

    public ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken) => ValueTask.FromResult(_make(request, cancellationToken));
}

/// <summary>A stream that delivers some bytes, then fails or waits for ever.</summary>
internal sealed class StallingStream : Stream
{
    private readonly byte[] _head;
    private readonly bool _fail;
    private int _pos;

    public StallingStream(byte[] head, bool fail)
    {
        _head = head;
        _fail = fail;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_pos < _head.Length)
        {
            int n = Math.Min(buffer.Length, _head.Length - _pos);
            _head.AsMemory(_pos, n).CopyTo(buffer);
            _pos += n;
            return n;
        }

        if (_fail)
        {
            throw new IOException("connection reset");
        }

        await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
        return 0;
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>Answers names from a table, and counts the questions.</summary>
internal sealed class TestResolver : IAddressResolver
{
    private readonly Func<string, int, IPAddress[]> _answer;
    private int _calls;

    public TestResolver(Func<string, int, IPAddress[]> answer) => _answer = answer;

    public TestResolver(params (string Host, string Address)[] table)
        : this((h, _) => table.Where(t => t.Host == h).Select(t => IPAddress.Parse(t.Address)).ToArray())
    {
    }

    public int Calls => Volatile.Read(ref _calls);

    public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) =>
        ValueTask.FromResult<IReadOnlyList<IPAddress>>(_answer(host, Interlocked.Increment(ref _calls)));
}

/// <summary>
/// A small HTTP/1.1 server on the loopback interface for tests of the real transport. The handler gets the request line, headers and body and returns raw
/// response bytes (so a test can lie about Content-Length), or null to close without answering.
/// </summary>
internal sealed class TestServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;
    private int _accepted;

    public TestServer(Func<string, Dictionary<string, string>, byte[], byte[]?> handler)
    {
        _listener.Start();
        _loop = Task.Run(() => Accept(handler));
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public int Accepted => Volatile.Read(ref _accepted);

    public List<string> RequestLines { get; } = [];

    public static byte[] Response(int status, string reason, byte[] body, params string[] headers) =>
        Encoding.Latin1.GetBytes($"HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: {body.Length}\r\n{string.Concat(headers.Select(h => h + "\r\n"))}\r\n").Concat(body).ToArray();

    private async Task Accept(Func<string, Dictionary<string, string>, byte[], byte[]?> handler)
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient c;
            try
            {
                c = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            Interlocked.Increment(ref _accepted);
            _ = Task.Run(() => Serve(c, handler));
        }
    }

    private async Task Serve(TcpClient client, Func<string, Dictionary<string, string>, byte[], byte[]?> handler)
    {
        using (client)
        {
            try
            {
                NetworkStream s = client.GetStream();
                var head = new List<byte>();
                var one = new byte[1];
                while (!(head.Count >= 4 && head[^4] == '\r' && head[^3] == '\n' && head[^2] == '\r' && head[^1] == '\n'))
                {
                    if (await s.ReadAsync(one, _stop.Token) == 0)
                    {
                        return;
                    }

                    head.Add(one[0]);
                }

                string[] lines = Encoding.Latin1.GetString([.. head]).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (string l in lines.Skip(1))
                {
                    int i = l.IndexOf(':', StringComparison.Ordinal);
                    headers[l[..i]] = l[(i + 1)..].Trim();
                }

                byte[] body = [];
                if (headers.TryGetValue("Content-Length", out string? cl))
                {
                    body = new byte[int.Parse(cl)];
                    await s.ReadExactlyAsync(body, _stop.Token);
                }

                lock (RequestLines)
                {
                    RequestLines.Add(lines[0]);
                }

                byte[]? reply = handler(lines[0], headers, body);
                if (reply is not null)
                {
                    await s.WriteAsync(reply, _stop.Token);
                    await s.FlushAsync(_stop.Token);
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException or ObjectDisposedException)
            {
                // The client went away or the test ended.
            }
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        try
        {
            _loop.Wait(2000);
        }
        catch (AggregateException)
        {
        }

        _stop.Dispose();
    }
}
