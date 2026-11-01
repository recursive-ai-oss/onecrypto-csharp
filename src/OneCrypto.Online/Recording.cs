using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RecursiveAI.OneCrypto.Online;

/// <summary>One recorded request and its response.</summary>
public sealed class RecordedExchange
{
    /// <summary>The HTTP method.</summary>
    public string Method { get; set; } = "GET";

    /// <summary>The absolute URI.</summary>
    public string Uri { get; set; } = string.Empty;

    /// <summary>The SHA-256 of the request body in hexadecimal, empty for none.</summary>
    public string RequestBodySha256 { get; set; } = string.Empty;

    /// <summary>The status code.</summary>
    public int Status { get; set; }

    /// <summary>The response header fields in order, as <c>name</c>/<c>value</c> pairs.</summary>
    public List<RecordedHeader> Headers { get; set; } = [];

    /// <summary>The response body (Base64 in the file).</summary>
    public byte[] Body { get; set; } = [];

    /// <summary>When the exchange was recorded, for the reader of the fixture; replays do not use it.</summary>
    public DateTimeOffset? RecordedAt { get; set; }
}

/// <summary>A header field of a recorded response.</summary>
public sealed class RecordedHeader
{
    /// <summary>The field name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The field value.</summary>
    public string Value { get; set; } = string.Empty;
}

/// <summary>The fixture file: a list of recorded exchanges, stored as JSON so a reviewer can read it and a diff means something.</summary>
public sealed class ExchangeLog
{
    /// <summary>The file format version (1).</summary>
    public int Version { get; set; } = 1;

    /// <summary>The exchanges in the order they were recorded.</summary>
    public List<RecordedExchange> Exchanges { get; set; } = [];

    /// <summary>Writes the log as indented JSON.</summary>
    public byte[] ToJson() => JsonSerializer.SerializeToUtf8Bytes(this, OnlineJsonContext.Default.ExchangeLog);

    /// <summary>Reads a log.</summary>
    /// <param name="json">The JSON text of a file written by <see cref="ToJson"/>.</param>
    /// <exception cref="FormatException">The text is not a valid log.</exception>
    public static ExchangeLog Parse(ReadOnlySpan<byte> json)
    {
        try
        {
            ExchangeLog? log = JsonSerializer.Deserialize(json, OnlineJsonContext.Default.ExchangeLog);
            return log is { Version: 1 } ? log : throw new FormatException("not an exchange log of version 1");
        }
        catch (JsonException ex)
        {
            throw new FormatException("the exchange log is not valid JSON: " + ex.Message, ex);
        }
    }

    internal static string BodyHash(ReadOnlySpan<byte> body) => body.IsEmpty ? string.Empty : Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
}

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault)]
[JsonSerializable(typeof(ExchangeLog))]
internal sealed partial class OnlineJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Passes requests to another transport and keeps what came back, so a run against real endpoints can be saved as a fixture and replayed later without a
/// network. Request headers are not recorded (they may carry credentials); response bodies are.
/// </summary>
public sealed class RecordingTransport : ITransport
{
    private readonly ITransport _inner;
    private readonly object _gate = new();

    /// <summary>Creates a recorder.</summary>
    /// <param name="inner">The transport that does the real work.</param>
    /// <param name="time">The clock for <see cref="RecordedExchange.RecordedAt"/>.</param>
    public RecordingTransport(ITransport inner, TimeProvider? time = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        Time = time ?? TimeProvider.System;
    }

    /// <summary>What has been recorded so far.</summary>
    public ExchangeLog Log { get; } = new();

    private TimeProvider Time { get; }

    /// <inheritdoc />
    public async ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        TransportResponse live = await _inner.SendAsync(request, cancellationToken).ConfigureAwait(false);
        try
        {
            using var ms = new MemoryStream();
            await live.Body.CopyToAsync(ms, 81920, cancellationToken).ConfigureAwait(false);
            byte[] body = ms.ToArray();
            var rec = new RecordedExchange
            {
                Method = request.Method,
                Uri = request.Uri.AbsoluteUri,
                RequestBodySha256 = ExchangeLog.BodyHash(request.Body.Span),
                Status = live.StatusCode,
                Headers = [.. live.Headers.Select(h => new RecordedHeader { Name = h.Key, Value = h.Value })],
                Body = body,
                RecordedAt = Time.GetUtcNow(),
            };
            lock (_gate)
            {
                Log.Exchanges.RemoveAll(e => Same(e, rec));
                Log.Exchanges.Add(rec);
            }

            return new TransportResponse(live.StatusCode, live.Headers, new MemoryStream(body, writable: false));
        }
        finally
        {
            live.Dispose();
        }
    }

    private static bool Same(RecordedExchange a, RecordedExchange b) => a.Method == b.Method && a.Uri == b.Uri && a.RequestBodySha256 == b.RequestBodySha256;
}

/// <summary>How a <see cref="ReplayTransport"/> matches requests.</summary>
public sealed class ReplayOptions
{
    /// <summary>When true (default) a POST matches only a recording made with the same body; when false the body is ignored, for requests that carry a fresh nonce.</summary>
    public bool MatchBody { get; init; } = true;
}

/// <summary>
/// Serves recorded exchanges and nothing else: a request with no recording fails with <see cref="TransportFailure.NoRecording"/>. It uses no operating-system
/// API, so the same fixtures run in a native test, an AOT app and a browser.
/// </summary>
public sealed class ReplayTransport : ITransport
{
    private readonly ExchangeLog _log;
    private readonly ReplayOptions _options;
    private readonly List<string> _requests = [];

    /// <summary>Creates a replayer.</summary>
    /// <param name="log">The recordings.</param>
    /// <param name="options">The matching rules; null for the defaults.</param>
    public ReplayTransport(ExchangeLog log, ReplayOptions? options = null)
    {
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _options = options ?? new ReplayOptions();
    }

    /// <summary>The method and URI of every request served or refused, in order, for tests that assert what was (not) fetched.</summary>
    public IReadOnlyList<string> Requests
    {
        get
        {
            lock (_requests)
            {
                return [.. _requests];
            }
        }
    }

    /// <inheritdoc />
    public ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        lock (_requests)
        {
            _requests.Add(request.Method + " " + request.Uri.AbsoluteUri);
        }

        string hash = ExchangeLog.BodyHash(request.Body.Span);
        foreach (RecordedExchange e in _log.Exchanges)
        {
            if (e.Method == request.Method && e.Uri == request.Uri.AbsoluteUri && (!_options.MatchBody || e.RequestBodySha256 == hash))
            {
                return ValueTask.FromResult(new TransportResponse(e.Status, [.. e.Headers.Select(h => new KeyValuePair<string, string>(h.Name, h.Value))], new MemoryStream(e.Body, writable: false)));
            }
        }

        throw new TransportException(TransportFailure.NoRecording, $"no recorded exchange for {request.Method} {request.Uri.AbsoluteUri}");
    }
}
