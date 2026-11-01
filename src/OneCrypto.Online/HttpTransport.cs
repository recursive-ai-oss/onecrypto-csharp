using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>Choices for <see cref="HttpTransport"/>.</summary>
public sealed class HttpTransportOptions
{
    /// <summary>Resolves host names for guarded requests (default: the system resolver).</summary>
    public IAddressResolver Resolver { get; init; } = new SystemAddressResolver();

    /// <summary>How long a connection attempt to one address may take (default 10 seconds).</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>The <c>User-Agent</c> sent unless the request names one (default: the library name).</summary>
    public string UserAgent { get; init; } = "RecursiveAI.OneCrypto.Online";
}

/// <summary>
/// The default transport, over <see cref="HttpClient"/>. It never follows redirects (the <see cref="Fetcher"/> does, applying every guard to each hop), uses no
/// proxy, and sends no <c>Accept-Encoding</c>.
/// </summary>
/// <remarks>
/// For a request that carries a <see cref="NetworkGuard"/>, the connection is made by this class: it resolves the host name once, checks every address it got,
/// refuses the whole connection if any of them is blocked, and then connects to one of those same addresses. The address that was checked is the address that is
/// used, so an answer that changes between lookups cannot redirect the connection afterwards. TLS still validates the certificate against the original host name.
/// Requests are pooled per guard, so a connection opened under a permissive guard is never reused under a stricter one.
/// In a browser the runtime's fetch makes the connection and the address cannot be inspected: only the literal checks of <see cref="Fetcher"/> apply, and the
/// browser's own network rules (CORS, private-network access) do the rest.
/// </remarks>
public sealed class HttpTransport : ITransport, IDisposable
{
    private static readonly HttpRequestOptionsKey<NetworkGuard> GuardKey = new("OneCrypto.Guard");

    private readonly HttpTransportOptions _options;
    private readonly ConcurrentDictionary<NetworkGuard, HttpClient> _guarded = new();
    private readonly Lazy<HttpClient> _open;
    private int _disposed;

    /// <summary>Creates a transport.</summary>
    /// <param name="options">The options; null for the defaults.</param>
    public HttpTransport(HttpTransportOptions? options = null)
    {
        _options = options ?? new HttpTransportOptions();
        _open = new Lazy<HttpClient>(() => CreateClient(guarded: false));
    }

    /// <inheritdoc />
    public async ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        HttpClient client = request.Guard is { } g && !OperatingSystem.IsBrowser() ? _guarded.GetOrAdd(g, _ => CreateClient(guarded: true)) : _open.Value;
        using var message = new HttpRequestMessage(new HttpMethod(request.Method), request.Uri);
        if (request.Guard is { } guard)
        {
            message.Options.Set(GuardKey, guard);
        }

        if (request.Method == "POST")
        {
            message.Content = new ByteArrayContent(request.Body.ToArray());
        }

        bool userAgentSet = false;
        foreach (KeyValuePair<string, string> h in request.Headers)
        {
            if (h.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase) && message.Content is not null)
            {
                message.Content.Headers.TryAddWithoutValidation("Content-Type", h.Value);
            }
            else
            {
                userAgentSet |= h.Key.Equals("User-Agent", StringComparison.OrdinalIgnoreCase);
                message.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }
        }

        if (!userAgentSet)
        {
            message.Headers.TryAddWithoutValidation("User-Agent", _options.UserAgent);
        }

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw Translate(ex);
        }

        try
        {
            var headers = new List<KeyValuePair<string, string>>();
            foreach (KeyValuePair<string, IEnumerable<string>> h in response.Headers)
            {
                foreach (string v in h.Value)
                {
                    headers.Add(new KeyValuePair<string, string>(h.Key, v));
                }
            }

            foreach (KeyValuePair<string, IEnumerable<string>> h in response.Content.Headers)
            {
                foreach (string v in h.Value)
                {
                    headers.Add(new KeyValuePair<string, string>(h.Key, v));
                }
            }

            Stream body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            return new TransportResponse((int)response.StatusCode, headers, body, response);
        }
        catch (HttpRequestException ex)
        {
            response.Dispose();
            throw Translate(ex);
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (_open.IsValueCreated)
        {
            _open.Value.Dispose();
        }

        foreach (HttpClient c in _guarded.Values)
        {
            c.Dispose();
        }
    }

    private static TransportException Translate(HttpRequestException ex)
    {
        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            if (e is TransportException te)
            {
                return te;
            }
        }

        TransportFailure kind = ex.InnerException switch
        {
            AuthenticationException => TransportFailure.Tls,
            SocketException { SocketErrorCode: SocketError.HostNotFound or SocketError.TryAgain or SocketError.NoData } => TransportFailure.NameResolution,
            SocketException => TransportFailure.Connect,
            _ => ex.HttpRequestError switch
            {
                HttpRequestError.NameResolutionError => TransportFailure.NameResolution,
                HttpRequestError.SecureConnectionError => TransportFailure.Tls,
                HttpRequestError.ConnectionError => TransportFailure.Connect,
                _ => TransportFailure.Network,
            },
        };
        return new TransportException(kind, ex.Message, ex);
    }

    private HttpClient CreateClient(bool guarded)
    {
        if (OperatingSystem.IsBrowser())
        {
            return new HttpClient();
        }

        return CreateNativeClient(guarded);
    }

    [UnsupportedOSPlatform("browser")]
    private HttpClient CreateNativeClient(bool guarded)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectTimeout = _options.ConnectTimeout,
            SslOptions = new SslClientAuthenticationOptions { EnabledSslProtocols = SslProtocols.None },
        };
        if (guarded)
        {
            handler.ConnectCallback = ConnectGuardedAsync;
        }

        return new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    [UnsupportedOSPlatform("browser")]
    private async ValueTask<Stream> ConnectGuardedAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        NetworkGuard guard = context.InitialRequestMessage is { } m && m.Options.TryGetValue(GuardKey, out NetworkGuard? g) ? g : NetworkGuard.Default;
        string host = context.DnsEndPoint.Host;
        IReadOnlyList<IPAddress> addresses;
        if (IPAddress.TryParse(host, out IPAddress? literal))
        {
            addresses = [literal];
        }
        else
        {
            addresses = await _options.Resolver.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
            if (addresses.Count == 0)
            {
                throw new TransportException(TransportFailure.NameResolution, $"the name {host} did not resolve");
            }
        }

        // One lookup, every answer checked, then a connection to one of the very addresses that were checked.
        foreach (IPAddress a in addresses)
        {
            if (guard.Check(a) is { } why)
            {
                throw new TransportException(TransportFailure.AddressBlocked, $"{host} resolves to {a}, which is {why}");
            }
        }

        Exception? last = null;
        foreach (IPAddress a in addresses)
        {
            var socket = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(a, context.DnsEndPoint.Port), cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                last = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw new TransportException(TransportFailure.Connect, $"could not connect to {host}", last);
    }
}
