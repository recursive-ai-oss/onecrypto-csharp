using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace RecursiveAI.OneCrypto.Keys.Agents;

/// <summary>What a command returned: the data lines joined, the status lines, and the text after <c>OK</c>.</summary>
internal sealed class AssuanReply
{
    public byte[] Data { get; init; } = [];

    public List<(string Keyword, string Text)> Status { get; } = [];

    public string OkText { get; set; } = string.Empty;
}

/// <summary>Answers an <c>INQUIRE</c>: gets the keyword, its parameters and the largest size the server announced (or -1); returns the data to send, or null to cancel the command.</summary>
internal delegate byte[]? InquiryHandler(string keyword, string parameters, int maxLength);

/// <summary>
/// One client conversation with an Assuan server (the protocol gpg-agent speaks): a line-based exchange of commands and
/// <c>OK</c>/<c>ERR</c>/<c>S</c>/<c>D</c>/<c>INQUIRE</c>/<c>#</c> lines, with percent-escaping in data lines. Every read is bounded: a line is at most
/// <see cref="MaxLineBytes"/> octets, one reply at most <see cref="MaxReplyBytes"/> octets in total (comments and status lines included), so an agent that
/// never stops talking costs a fixed amount of memory.
/// </summary>
internal sealed class AssuanSession : IDisposable
{
    /// <summary>The longest line accepted. The protocol allows 1000 octets including the line ending; a little more is tolerated.</summary>
    public const int MaxLineBytes = 1100;

    // The most that goes into one D line we send: the protocol's 1000 octets less "D " and the line ending.
    private const int SendLineBudget = 996;

    private readonly Stream _stream;
    private readonly byte[] _buffer = new byte[2048];
    private readonly byte[] _lineBuffer = new byte[MaxLineBytes + 1];
    private int _start, _end;
    private long _budget;

    /// <summary>Wraps an open stream to the server.</summary>
    /// <param name="stream">A duplex stream; disposed with the session.</param>
    /// <param name="maxReplyBytes">The most octets one reply may take.</param>
    public AssuanSession(Stream stream, int maxReplyBytes)
    {
        _stream = stream;
        MaxReplyBytes = maxReplyBytes;
    }

    /// <summary>The most octets one reply may take, counted over every line.</summary>
    public int MaxReplyBytes { get; }

    /// <summary>Connects to a Unix-domain socket and reads the server's greeting.</summary>
    public static async Task<AssuanSession> ConnectAsync(string socketPath, TimeSpan connectTimeout, int maxReplyBytes, CancellationToken cancellationToken)
    {
        Stream stream = await ConnectSocketAsync(socketPath, connectTimeout, cancellationToken).ConfigureAwait(false);
        var session = new AssuanSession(stream, maxReplyBytes);
        try
        {
            await session.ReadGreetingAsync(cancellationToken).ConfigureAwait(false);
            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    internal static async Task<Stream> ConnectSocketAsync(string socketPath, TimeSpan connectTimeout, CancellationToken cancellationToken)
    {
        Socket? socket = null;
        try
        {
            socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (connectTimeout != Timeout.InfiniteTimeSpan)
            {
                timeout.CancelAfter(connectTimeout);
            }

            await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), timeout.Token).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            socket?.Dispose();
            throw new AgentUnavailableException(socketPath, "Connecting to the agent socket timed out.");
        }
        catch (Exception e) when (e is SocketException or IOException or PlatformNotSupportedException or ArgumentException or NotSupportedException or UnauthorizedAccessException)
        {
            socket?.Dispose();
            throw new AgentUnavailableException(socketPath, $"Could not connect to the agent socket {socketPath}: {e.Message}", e);
        }
        catch
        {
            socket?.Dispose();
            throw;
        }
    }

    /// <summary>Reads the server's first line: <c>OK ...</c> means it is ready, <c>ERR</c> means it refuses this client.</summary>
    internal async Task ReadGreetingAsync(CancellationToken cancellationToken)
    {
        _budget = MaxReplyBytes;
        while (true)
        {
            byte[] line = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            if (IsKeyword(line, "OK"))
            {
                return;
            }

            if (IsKeyword(line, "ERR"))
            {
                throw ParseErr(line);
            }

            throw new AgentProtocolException("The agent did not greet with OK.");
        }
    }

    /// <summary>Sends a command line (the caller guarantees it holds no CR or LF) and returns the reply, answering inquiries with <paramref name="inquiry"/>.</summary>
    /// <exception cref="AgentRefusedException">The server answered <c>ERR</c>.</exception>
    /// <exception cref="AgentProtocolException">The reply broke the protocol or the limits.</exception>
    public async Task<AssuanReply> CommandAsync(string command, InquiryHandler? inquiry, CancellationToken cancellationToken)
    {
        if (command.AsSpan().IndexOfAny('\r', '\n') >= 0)
        {
            throw new ArgumentException("A command is one line.", nameof(command));
        }

        byte[] line = Encoding.UTF8.GetBytes(command + "\n");
        if (line.Length > 1000)
        {
            throw new AgentLimitException("An Assuan command line is at most 1000 octets.");
        }

        await WriteAsync(line, cancellationToken).ConfigureAwait(false);
        return await ReadReplyAsync(inquiry, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<AssuanReply> ReadReplyAsync(InquiryHandler? inquiry, CancellationToken cancellationToken)
    {
        _budget = MaxReplyBytes;
        using var data = new ByteSink(MaxReplyBytes);
        var status = new List<(string, string)>();
        int maxLen = -1;
        while (true)
        {
            byte[] line = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            if (IsKeyword(line, "OK"))
            {
                var reply = new AssuanReply { Data = data.Detach(), OkText = Tail(line, 2) };
                reply.Status.AddRange(status);
                return reply;
            }

            if (IsKeyword(line, "ERR"))
            {
                throw ParseErr(line);
            }

            if (line.Length >= 2 && line[0] == 'D' && line[1] == ' ')
            {
                bool ok = data.TryAppendUnescaped(line.AsSpan(2));
                CryptographicOperations.ZeroMemory(line);
                if (!ok)
                {
                    throw new AgentProtocolException("A data line is malformed or the reply is too big.");
                }

                continue;
            }

            if (IsKeyword(line, "S"))
            {
                string text = Tail(line, 1);
                int sp = text.IndexOf(' ', StringComparison.Ordinal);
                string kw = sp < 0 ? text : text[..sp], rest = sp < 0 ? string.Empty : text[(sp + 1)..];
                if (kw == "INQUIRE_MAXLEN" && int.TryParse(rest, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int m))
                {
                    maxLen = m;
                }

                status.Add((kw, rest));
                continue;
            }

            if (IsKeyword(line, "INQUIRE"))
            {
                string text = Tail(line, 7);
                int sp = text.IndexOf(' ', StringComparison.Ordinal);
                string kw = sp < 0 ? text : text[..sp], rest = sp < 0 ? string.Empty : text[(sp + 1)..];
                byte[]? answer = inquiry?.Invoke(kw, rest, maxLen);
                if (answer is null)
                {
                    await WriteAsync("CAN\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await SendDataAsync(answer, cancellationToken).ConfigureAwait(false);
                }

                continue;
            }

            if (IsKeyword(line, "END"))
            {
                continue;
            }

            throw new AgentProtocolException("The agent sent a line the protocol does not define.");
        }
    }

    private async Task SendDataAsync(byte[] answer, CancellationToken cancellationToken)
    {
        var o = new MemoryStream();
        int i = 0;
        while (i < answer.Length)
        {
            // One D line holds at most SendLineBudget escaped octets; % CR and LF cost three each.
            o.Write("D "u8);
            int used = 0;
            while (i < answer.Length)
            {
                byte b = answer[i];
                int cost = b is (byte)'%' or (byte)'\r' or (byte)'\n' ? 3 : 1;
                if (used + cost > SendLineBudget)
                {
                    break;
                }

                if (cost == 3)
                {
                    o.WriteByte((byte)'%');
                    o.WriteByte((byte)"0123456789ABCDEF"[b >> 4]);
                    o.WriteByte((byte)"0123456789ABCDEF"[b & 15]);
                }
                else
                {
                    o.WriteByte(b);
                }

                used += cost;
                i++;
            }

            o.WriteByte((byte)'\n');
        }

        o.Write("END\n"u8);
        await WriteAsync(o.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private async Task WriteAsync(byte[] bytes, CancellationToken cancellationToken)
    {
        try
        {
            await _stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (IOException e)
        {
            throw new AgentProtocolException("The connection to the agent broke while sending: " + e.Message, e);
        }
        catch (ObjectDisposedException e)
        {
            throw new AgentProtocolException("The connection to the agent was closed.", e);
        }
    }

    /// <summary>Reads one line without its line ending (CR LF or LF). Bounded by <see cref="MaxLineBytes"/> and the reply budget.</summary>
    private async Task<byte[]> ReadLineAsync(CancellationToken cancellationToken)
    {
        int count = 0;
        while (true)
        {
            if (_start == _end)
            {
                int n;
                try
                {
                    n = await _stream.ReadAsync(_buffer, cancellationToken).ConfigureAwait(false);
                }
                catch (IOException e)
                {
                    throw new AgentProtocolException("The connection to the agent broke while reading: " + e.Message, e);
                }
                catch (ObjectDisposedException e)
                {
                    throw new AgentProtocolException("The connection to the agent was closed.", e);
                }

                if (n == 0)
                {
                    throw new AgentProtocolException("The agent closed the connection before it finished its reply.");
                }

                _start = 0;
                _end = n;
            }

            byte b = _buffer[_start++];
            if (--_budget < 0)
            {
                throw new AgentProtocolException($"The agent's reply is longer than the limit of {MaxReplyBytes} octets.");
            }

            if (b == '\n')
            {
                if (count > 0 && _lineBuffer[count - 1] == '\r')
                {
                    count--;
                }

                byte[] result = _lineBuffer.AsSpan(0, count).ToArray();
                CryptographicOperations.ZeroMemory(_lineBuffer.AsSpan(0, count));
                return result;
            }

            if (count >= MaxLineBytes)
            {
                throw new AgentProtocolException($"The agent sent a line longer than {MaxLineBytes} octets.");
            }

            _lineBuffer[count++] = b;
        }
    }

    private static bool IsKeyword(byte[] line, string keyword)
    {
        if (line.Length < keyword.Length || (line.Length > keyword.Length && line[keyword.Length] != ' '))
        {
            return false;
        }

        for (int i = 0; i < keyword.Length; i++)
        {
            if (line[i] != keyword[i])
            {
                return false;
            }
        }

        return true;
    }

    private static string Tail(byte[] line, int keywordLength) =>
        line.Length <= keywordLength + 1 ? string.Empty : Encoding.UTF8.GetString(line, keywordLength + 1, line.Length - keywordLength - 1);

    internal static AgentException ParseErr(byte[] line)
    {
        string text = Tail(line, 3);
        int sp = text.IndexOf(' ', StringComparison.Ordinal);
        string number = sp < 0 ? text : text[..sp];
        if (!uint.TryParse(number, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out uint code))
        {
            return new AgentProtocolException("An ERR line has no error number.");
        }

        string description = sp < 0 ? string.Empty : text[(sp + 1)..];
        return new AgentRefusedException(code, description);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_buffer);
        CryptographicOperations.ZeroMemory(_lineBuffer);
        _stream.Dispose();
    }
}

/// <summary>
/// A growing buffer for the data lines of one reply, with a hard size limit. The data may be a decrypted session key, so growth zeroes the old array and
/// <see cref="Dispose"/> zeroes what is left; a garbage-collected runtime still cannot promise no other copy exists.
/// </summary>
internal sealed class ByteSink : IDisposable
{
    private readonly int _limit;
    private byte[] _buffer = new byte[256];
    private int _length;

    public ByteSink(int limit) => _limit = limit;

    /// <summary>Appends the percent-decoded octets of a D line; false on a bad escape or when the total would pass the limit.</summary>
    public bool TryAppendUnescaped(ReadOnlySpan<byte> text)
    {
        for (int i = 0; i < text.Length; i++)
        {
            byte b = text[i];
            if (b == '%')
            {
                if (i + 2 >= text.Length)
                {
                    return false;
                }

                int hi = Hex(text[i + 1]), lo = Hex(text[i + 2]);
                if (hi < 0 || lo < 0)
                {
                    return false;
                }

                b = (byte)((hi << 4) | lo);
                i += 2;
            }

            if (_length >= _limit)
            {
                return false;
            }

            if (_length == _buffer.Length)
            {
                byte[] bigger = new byte[Math.Min(_buffer.Length * 2, _limit)];
                _buffer.AsSpan(0, _length).CopyTo(bigger);
                CryptographicOperations.ZeroMemory(_buffer);
                _buffer = bigger;
            }

            _buffer[_length++] = b;
        }

        return true;
    }

    /// <summary>Returns the octets in an array of exactly their length and clears the buffer.</summary>
    public byte[] Detach()
    {
        byte[] o = _buffer.AsSpan(0, _length).ToArray();
        CryptographicOperations.ZeroMemory(_buffer);
        _length = 0;
        return o;
    }

    private static int Hex(byte c) => c switch
    {
        >= (byte)'0' and <= (byte)'9' => c - '0',
        >= (byte)'A' and <= (byte)'F' => c - 'A' + 10,
        >= (byte)'a' and <= (byte)'f' => c - 'a' + 10,
        _ => -1,
    };

    /// <inheritdoc/>
    public void Dispose() => CryptographicOperations.ZeroMemory(_buffer);
}
