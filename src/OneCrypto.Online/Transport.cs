using System.Net;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>
/// One HTTP exchange, without redirects, caching or guards: those are <see cref="Fetcher"/>'s. The default is <see cref="HttpTransport"/>; the same seam carries
/// <see cref="RecordingTransport"/> and <see cref="ReplayTransport"/>, which is how the library's own tests run without a network.
/// </summary>
public interface ITransport
{
    /// <summary>Sends one request and returns the response with its body still unread.</summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">Cancels the exchange, including the read of the body.</param>
    /// <returns>The response. The caller disposes it.</returns>
    /// <exception cref="TransportException">The exchange failed. Implementations report every failure of their own through this type, so callers never meet a transport's private exceptions.</exception>
    ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken);
}

/// <summary>A request as a transport sees it.</summary>
public sealed class TransportRequest
{
    /// <summary>The HTTP method: <c>GET</c> or <c>POST</c>.</summary>
    public required string Method { get; init; }

    /// <summary>The absolute <c>http</c> or <c>https</c> URI.</summary>
    public required Uri Uri { get; init; }

    /// <summary>Request header fields in order.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; } = [];

    /// <summary>The request body; empty for GET.</summary>
    public ReadOnlyMemory<byte> Body { get; init; }

    /// <summary>
    /// When set, the transport must refuse to connect to any address this guard blocks, judged on the address it connects to (<see cref="HttpTransport"/> does).
    /// Null means the caller vouched for the URL and the transport applies no address rule.
    /// </summary>
    public NetworkGuard? Guard { get; init; }
}

/// <summary>A response whose body is read from <see cref="Body"/> and released with <see cref="Dispose"/>.</summary>
public sealed class TransportResponse : IDisposable
{
    private readonly IDisposable? _owner;

    /// <summary>Creates a response.</summary>
    /// <param name="statusCode">The HTTP status code.</param>
    /// <param name="headers">Header fields (names compare case-insensitively).</param>
    /// <param name="body">The body.</param>
    /// <param name="owner">Disposed with the response, for example the HTTP message that owns the body stream.</param>
    public TransportResponse(int statusCode, IReadOnlyList<KeyValuePair<string, string>> headers, Stream body, IDisposable? owner = null)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(body);
        StatusCode = statusCode;
        Headers = headers;
        Body = body;
        _owner = owner;
    }

    /// <summary>The HTTP status code.</summary>
    public int StatusCode { get; }

    /// <summary>Header fields as received, one entry per field line.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; }

    /// <summary>The body stream.</summary>
    public Stream Body { get; }

    /// <summary>The first value of a header field, or null.</summary>
    public string? Header(string name) => HeaderLookup.First(Headers, name);

    /// <inheritdoc />
    public void Dispose()
    {
        Body.Dispose();
        _owner?.Dispose();
    }
}

/// <summary>Why a transport could not complete an exchange.</summary>
public enum TransportFailure
{
    /// <summary>Any other network or protocol failure.</summary>
    Network = 0,

    /// <summary>The name did not resolve.</summary>
    NameResolution = 1,

    /// <summary>The connection could not be made.</summary>
    Connect = 2,

    /// <summary>The TLS handshake or certificate check failed.</summary>
    Tls = 3,

    /// <summary>An address the <see cref="NetworkGuard"/> blocks.</summary>
    AddressBlocked = 4,

    /// <summary>A replay transport has no recording for the request.</summary>
    NoRecording = 5,

    /// <summary>The platform cannot do what was asked (for example a browser cannot pin the connected address).</summary>
    Unsupported = 6,
}

/// <summary>A transport failure with its kind.</summary>
public sealed class TransportException : IOException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="failure">What failed.</param>
    /// <param name="message">A description.</param>
    /// <param name="inner">The underlying exception, if any.</param>
    public TransportException(TransportFailure failure, string message, Exception? inner = null)
        : base(message, inner)
    {
        Failure = failure;
    }

    /// <summary>Creates the exception.</summary>
    public TransportException()
        : this(TransportFailure.Network, "transport failure")
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">A description.</param>
    public TransportException(string message)
        : this(TransportFailure.Network, message)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">A description.</param>
    /// <param name="inner">The underlying exception.</param>
    public TransportException(string message, Exception inner)
        : this(TransportFailure.Network, message, inner)
    {
    }

    /// <summary>What failed.</summary>
    public TransportFailure Failure { get; }
}

/// <summary>Turns a host name into addresses. The default asks the system resolver; tests substitute their own (including one that answers differently each time).</summary>
public interface IAddressResolver
{
    /// <summary>Resolves <paramref name="host"/>.</summary>
    /// <param name="host">A DNS name.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    /// <returns>The addresses in connection order; empty when the name does not exist.</returns>
    ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken);
}

/// <summary>The system resolver.</summary>
public sealed class SystemAddressResolver : IAddressResolver
{
    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        try
        {
            return await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        }
        catch (System.Net.Sockets.SocketException)
        {
            return [];
        }
    }
}

internal static class HeaderLookup
{
    internal static string? First(IReadOnlyList<KeyValuePair<string, string>> headers, string name)
    {
        foreach (KeyValuePair<string, string> h in headers)
        {
            if (h.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return h.Value;
            }
        }

        return null;
    }

    /// <summary>All values of a field joined with commas (RFC 9110 §5.3).</summary>
    internal static string? Joined(IReadOnlyList<KeyValuePair<string, string>> headers, string name)
    {
        string? joined = null;
        foreach (KeyValuePair<string, string> h in headers)
        {
            if (h.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                joined = joined is null ? h.Value : joined + ", " + h.Value;
            }
        }

        return joined;
    }
}
