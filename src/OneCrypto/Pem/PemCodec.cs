using System.Text;

namespace RecursiveAI.OneCrypto.Pem;

/// <summary>Why PEM text was rejected.</summary>
public enum PemError
{
    /// <summary>No error.</summary>
    None = 0,

    /// <summary>No <c>-----BEGIN …-----</c> line was found.</summary>
    NoBlock,

    /// <summary>A block has no matching <c>-----END …-----</c> line.</summary>
    MissingEnd,

    /// <summary>The label on the END line differs from the one on the BEGIN line.</summary>
    LabelMismatch,

    /// <summary>The label has characters RFC 7468 clause 3 does not allow.</summary>
    InvalidLabel,

    /// <summary>The body is not valid base64.</summary>
    InvalidBase64,

    /// <summary>Strict mode: a line has the wrong length, extra whitespace or a stray character (RFC 7468 clause 3).</summary>
    InvalidLayout,

    /// <summary>Strict mode: encapsulation headers are present, which RFC 7468 does not have.</summary>
    HeadersNotAllowed,

    /// <summary>A header line is not <c>Name: value</c>.</summary>
    InvalidHeader,

    /// <summary>The input is not valid UTF-8 or has a NUL or control character inside a block.</summary>
    InvalidText,

    /// <summary>A block is larger than the limit.</summary>
    TooLarge,
}

/// <summary>The PEM text is malformed. Carries the reason and the character offset.</summary>
public sealed class PemFormatException : FormatException
{
    /// <summary>Creates the exception for a reason at an offset.</summary>
    public PemFormatException(PemError error, int offset)
        : base($"PEM: {error} (offset {offset}).")
    {
        Error = error;
        Offset = offset;
    }

    /// <summary>Creates an exception with a message.</summary>
    public PemFormatException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an inner exception.</summary>
    public PemFormatException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates an exception with no details.</summary>
    public PemFormatException()
        : this(PemError.InvalidLayout, 0)
    {
    }

    /// <summary>The reason.</summary>
    public PemError Error { get; }

    /// <summary>Character offset in the input where the problem was found.</summary>
    public int Offset { get; }
}

/// <summary>How tolerant the parser is.</summary>
public enum PemMode
{
    /// <summary>
    /// RFC 7468 clause 3 "strict": 64-character base64 lines (the last may be shorter), no whitespace inside a line, CRLF or LF line
    /// ends, no encapsulation headers. Text outside blocks is skipped.
    /// </summary>
    Strict = 0,

    /// <summary>
    /// RFC 7468 clause 2 "lax": any whitespace and line length in the body, a missing final newline, and legacy
    /// <c>Name: value</c> encapsulation headers (RFC 1421 style, as written by OpenSSL for encrypted keys).
    /// </summary>
    Lax = 1,
}

/// <summary>One PEM block: the label, the headers (legacy form) and the decoded octets.</summary>
public sealed class PemBlock
{
    /// <summary>Creates a block.</summary>
    public PemBlock(string label, byte[] data, IReadOnlyList<KeyValuePair<string, string>>? headers = null)
    {
        ArgumentNullException.ThrowIfNull(label);
        ArgumentNullException.ThrowIfNull(data);
        Label = label;
        Data = data;
        Headers = headers ?? [];
    }

    /// <summary>The text between <c>BEGIN </c> and the closing hyphens, for example <c>CERTIFICATE</c> or <c>PRIVATE KEY</c>.</summary>
    public string Label { get; }

    /// <summary>The decoded body.</summary>
    public byte[] Data { get; }

    /// <summary>Encapsulation headers in order; empty for RFC 7468 text. Names are as written.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; }

    /// <summary>The value of the first header with this name (case-insensitive), or null.</summary>
    public string? GetHeader(string name)
    {
        foreach (KeyValuePair<string, string> h in Headers)
        {
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return h.Value;
            }
        }

        return null;
    }

    /// <summary>True for the legacy OpenSSL form <c>Proc-Type: 4,ENCRYPTED</c>: the body is encrypted per <see cref="DekInfo"/>.</summary>
    public bool IsLegacyEncrypted => GetHeader("Proc-Type") is { } p && p.Contains("ENCRYPTED", StringComparison.Ordinal);

    /// <summary>The <c>DEK-Info</c> header (cipher name, comma, hex IV) of a legacy encrypted block, or null. Decrypting is the caller's job.</summary>
    public string? DekInfo => GetHeader("DEK-Info");

    /// <summary>Writes this block as RFC 7468 text (or with its headers, if it has any).</summary>
    public override string ToString() => PemCodec.Write(Label, Data, Headers);
}

/// <summary>Parsing and writing of PEM text (RFC 7468).</summary>
public static class PemCodec
{
    /// <summary>Largest decoded block accepted: 64 MiB. Larger bodies raise <see cref="PemError.TooLarge"/>.</summary>
    public const int MaxBlockBytes = 64 * 1024 * 1024;

    private const string Begin = "-----BEGIN ";
    private const string End = "-----END ";
    private const string Dashes = "-----";

    /// <summary>Parses every block in <paramref name="text"/>, skipping explanatory text between them. Throws <see cref="PemFormatException"/>.</summary>
    public static IReadOnlyList<PemBlock> ParseAll(ReadOnlySpan<char> text, PemMode mode = PemMode.Strict)
    {
        List<PemBlock> list = [];
        int pos = 0;
        while (true)
        {
            Step s = Next(text, ref pos, mode, out PemBlock? block, out Err err);
            if (s == Step.Block)
            {
                list.Add(block!);
            }
            else if (s == Step.Done)
            {
                return list;
            }
            else
            {
                throw new PemFormatException(err.Error, err.At);
            }
        }
    }

    /// <summary>Parses every block in <paramref name="text"/>; false (with <paramref name="error"/>) if any block is malformed.</summary>
    public static bool TryParseAll(ReadOnlySpan<char> text, PemMode mode, out IReadOnlyList<PemBlock> blocks, out PemError error)
    {
        List<PemBlock> list = [];
        blocks = list;
        error = PemError.None;
        int pos = 0;
        while (true)
        {
            Step s = Next(text, ref pos, mode, out PemBlock? block, out Err err);
            if (s == Step.Block)
            {
                list.Add(block!);
            }
            else if (s == Step.Done)
            {
                return true;
            }
            else
            {
                error = err.Error;
                blocks = [];
                return false;
            }
        }
    }

    /// <summary>Parses the first block. Throws <see cref="PemFormatException"/> (reason <see cref="PemError.NoBlock"/> if there is none).</summary>
    public static PemBlock Parse(ReadOnlySpan<char> text, PemMode mode = PemMode.Strict)
    {
        int pos = 0;
        Step s = Next(text, ref pos, mode, out PemBlock? block, out Err err);
        return s == Step.Block ? block! : throw new PemFormatException(s == Step.Done ? PemError.NoBlock : err.Error, err.At);
    }

    /// <summary>Parses the first block; false with the reason otherwise.</summary>
    public static bool TryParse(ReadOnlySpan<char> text, PemMode mode, out PemBlock? block, out PemError error)
    {
        int pos = 0;
        Step s = Next(text, ref pos, mode, out block, out Err err);
        error = s == Step.Block ? PemError.None : s == Step.Done ? PemError.NoBlock : err.Error;
        return s == Step.Block;
    }

    /// <summary>Parses the first block of UTF-8 (or ASCII) text.</summary>
    public static bool TryParse(ReadOnlySpan<byte> utf8, PemMode mode, out PemBlock? block, out PemError error)
    {
        block = null;
        if (!System.Text.Unicode.Utf8.IsValid(utf8))
        {
            error = PemError.InvalidText;
            return false;
        }

        return TryParse(Encoding.UTF8.GetString(utf8), mode, out block, out error);
    }

    /// <summary>Parses every block of UTF-8 (or ASCII) text.</summary>
    public static bool TryParseAll(ReadOnlySpan<byte> utf8, PemMode mode, out IReadOnlyList<PemBlock> blocks, out PemError error)
    {
        blocks = [];
        if (!System.Text.Unicode.Utf8.IsValid(utf8))
        {
            error = PemError.InvalidText;
            return false;
        }

        return TryParseAll(Encoding.UTF8.GetString(utf8), mode, out blocks, out error);
    }

    /// <summary>Writes one block: the BEGIN line, base64 in 64-character lines, the END line, each ending in LF, with a trailing LF.</summary>
    public static string Write(string label, ReadOnlySpan<byte> data) => Write(label, data, null);

    /// <summary>Writes one block with legacy encapsulation headers (followed by a blank line) when <paramref name="headers"/> is non-empty.</summary>
    public static string Write(string label, ReadOnlySpan<byte> data, IReadOnlyList<KeyValuePair<string, string>>? headers)
    {
        ArgumentNullException.ThrowIfNull(label);
        if (!LabelOk(label.AsSpan()))
        {
            throw new ArgumentException("The label has characters PEM does not allow.", nameof(label));
        }

        string b64 = Convert.ToBase64String(data);
        var sb = new StringBuilder(b64.Length + (b64.Length / 64) + (2 * label.Length) + 48);
        sb.Append(Begin).Append(label).Append(Dashes).Append('\n');
        if (headers is { Count: > 0 })
        {
            foreach (KeyValuePair<string, string> h in headers)
            {
                if (h.Key.Length == 0 || h.Key.Contains(':', StringComparison.Ordinal) || h.Key.AsSpan().ContainsAny('\r', '\n') || h.Value.AsSpan().ContainsAny('\r', '\n'))
                {
                    throw new ArgumentException("A header name or value is not valid.", nameof(headers));
                }

                sb.Append(h.Key).Append(": ").Append(h.Value).Append('\n');
            }

            sb.Append('\n');
        }

        for (int i = 0; i < b64.Length; i += 64)
        {
            sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
        }

        sb.Append(End).Append(label).Append(Dashes).Append('\n');
        return sb.ToString();
    }

    // ---- parser ------------------------------------------------------------------------------------------------------------

    private enum Step
    {
        Block,
        Done,
        Error,
    }

    private readonly record struct Err(PemError Error, int At);

    private static Step Fail(PemError e, int at, out Err err)
    {
        err = new Err(e, at);
        return Step.Error;
    }

    // RFC 7468 clause 3: label = [ labelchar *( ["-" / SP] labelchar ) ], labelchar = %x21-2C / %x2E-7E.
    private static bool LabelOk(ReadOnlySpan<char> l)
    {
        if (l.IsEmpty)
        {
            return true;
        }

        bool prevSep = true;
        foreach (char c in l)
        {
            bool labelChar = (c >= 0x21 && c <= 0x2C) || (c >= 0x2E && c <= 0x7E);
            if (labelChar)
            {
                prevSep = false;
            }
            else if ((c == '-' || c == ' ') && !prevSep)
            {
                prevSep = true;
            }
            else
            {
                return false;
            }
        }

        return !prevSep;
    }

    private static ReadOnlySpan<char> Line(ReadOnlySpan<char> text, int pos, out int next, out int contentEnd)
    {
        int i = pos;
        while (i < text.Length && text[i] is not ('\n' or '\r'))
        {
            i++;
        }

        contentEnd = i;
        if (i < text.Length)
        {
            i += text[i] == '\r' && i + 1 < text.Length && text[i + 1] == '\n' ? 2 : 1;
        }

        next = i;
        return text[pos..contentEnd];
    }

    private static Step Next(ReadOnlySpan<char> text, ref int pos, PemMode mode, out PemBlock? block, out Err err)
    {
        block = null;
        err = default;
        bool strict = mode == PemMode.Strict;

        // Find a BEGIN line at the start of a line.
        string? label = null;
        int beginAt = 0;
        while (pos < text.Length)
        {
            int lineStart = pos;
            ReadOnlySpan<char> line = Line(text, pos, out int next, out _);
            pos = next;
            if (!strict)
            {
                line = line.Trim(' ');
            }

            if (line.StartsWith(Begin, StringComparison.Ordinal) && line.EndsWith(Dashes, StringComparison.Ordinal) && line.Length >= Begin.Length + Dashes.Length)
            {
                ReadOnlySpan<char> l = line[Begin.Length..^Dashes.Length];
                if (!LabelOk(l))
                {
                    return Fail(PemError.InvalidLabel, lineStart, out err);
                }

                label = l.ToString();
                beginAt = lineStart;
                break;
            }
        }

        if (label is null)
        {
            return Step.Done;
        }

        // Headers (lax only): "Name: value" lines up to a blank line.
        List<KeyValuePair<string, string>>? headers = null;
        if (pos < text.Length)
        {
            int save = pos;
            ReadOnlySpan<char> first = Line(text, pos, out _, out _);
            if (first.Contains(':') && !first.StartsWith(End, StringComparison.Ordinal))
            {
                if (strict)
                {
                    return Fail(PemError.HeadersNotAllowed, pos, out err);
                }

                headers = [];
                while (true)
                {
                    if (pos >= text.Length)
                    {
                        return Fail(PemError.MissingEnd, beginAt, out err);
                    }

                    int ls = pos;
                    ReadOnlySpan<char> h = Line(text, pos, out int hn, out _);
                    if (h.Trim().IsEmpty)
                    {
                        pos = hn;
                        break;
                    }

                    // Folded continuation lines start with whitespace (RFC 1421 clause 4.4).
                    if (h[0] is ' ' or '\t' && headers.Count > 0)
                    {
                        KeyValuePair<string, string> last = headers[^1];
                        headers[^1] = new(last.Key, last.Value + " " + h.Trim().ToString());
                        pos = hn;
                        continue;
                    }

                    int colon = h.IndexOf(':');
                    if (colon <= 0 || h[..colon].Trim().IsEmpty)
                    {
                        return Fail(PemError.InvalidHeader, ls, out err);
                    }

                    headers.Add(new(h[..colon].Trim().ToString(), h[(colon + 1)..].Trim().ToString()));
                    pos = hn;
                }
            }
            else
            {
                pos = save;
            }
        }

        // Body up to the END line.
        var b64 = new StringBuilder();
        bool ended = false;
        bool shortSeen = false;
        while (pos < text.Length)
        {
            int ls = pos;
            ReadOnlySpan<char> line = Line(text, pos, out int next, out _);
            pos = next;
            ReadOnlySpan<char> t = strict ? line : line.Trim();
            if (t.StartsWith(End, StringComparison.Ordinal))
            {
                if (!t.EndsWith(Dashes, StringComparison.Ordinal) || t.Length < End.Length + Dashes.Length)
                {
                    return Fail(PemError.MissingEnd, ls, out err);
                }

                if (!t[End.Length..^Dashes.Length].SequenceEqual(label))
                {
                    return Fail(PemError.LabelMismatch, ls, out err);
                }

                ended = true;
                break;
            }

            if (strict)
            {
                // RFC 7468 clause 3: every line but the last holds 64 characters; the last holds 1 to 64.
                if (shortSeen || line.Length is 0 or > 64)
                {
                    return Fail(PemError.InvalidLayout, ls, out err);
                }

                if (line.Length < 64)
                {
                    shortSeen = true;
                }

                foreach (char c in line)
                {
                    if (!IsBase64Char(c))
                    {
                        return Fail(PemError.InvalidLayout, ls, out err);
                    }
                }

                b64.Append(line);
            }
            else
            {
                foreach (char c in line)
                {
                    if (c is ' ' or '\t' or '\v' or '\f')
                    {
                        continue;
                    }

                    if (!IsBase64Char(c))
                    {
                        return Fail(c < 0x20 ? PemError.InvalidText : PemError.InvalidBase64, ls, out err);
                    }

                    b64.Append(c);
                }
            }

            if (b64.Length > (MaxBlockBytes / 3 * 4) + 8)
            {
                return Fail(PemError.TooLarge, ls, out err);
            }
        }

        if (!ended)
        {
            return Fail(PemError.MissingEnd, beginAt, out err);
        }

        byte[] data;
        if (b64.Length == 0)
        {
            data = [];
        }
        else
        {
            string s = b64.ToString();
            data = new byte[s.Length / 4 * 3 + 3];
            // Convert.TryFromBase64String also demands correct padding; RFC 7468 clause 3 does too.
            if (s.Length % 4 != 0 || !Convert.TryFromBase64String(s, data, out int n))
            {
                return Fail(PemError.InvalidBase64, beginAt, out err);
            }

            data = data.AsSpan(0, n).ToArray();
        }

        block = new PemBlock(label, data, headers is null ? null : headers);
        return Step.Block;
    }

    private static bool IsBase64Char(char c) => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '+' or '/' or '=';
}
