using System.Text;

namespace RecursiveAI.OneCrypto.OpenPgp.GnuPG;

/// <summary>A node of an S-expression: an atom (octets) or a list. Internal: the key-file API exposes typed results instead.</summary>
internal abstract class SexpNode
{
}

internal sealed class SexpAtom : SexpNode
{
    public SexpAtom(byte[] value)
    {
        Value = value;
    }

    public byte[] Value { get; }

    /// <summary>The atom as text (Latin-1, as tokens and names are ASCII).</summary>
    public string Text => Encoding.Latin1.GetString(Value);
}

internal sealed class SexpList : SexpNode
{
    public List<SexpNode> Items { get; } = [];

    /// <summary>The first item as a token, or null when the list starts with a list or is empty.</summary>
    public string? Name => Items.Count > 0 && Items[0] is SexpAtom a ? a.Text : null;

    /// <summary>The first child list whose name is <paramref name="name"/> (compared ignoring ASCII case), or null.</summary>
    public SexpList? Find(string name)
    {
        for (int i = 0; i < Items.Count; i++)
        {
            if (Items[i] is SexpList l && string.Equals(l.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return l;
            }
        }

        return null;
    }

    /// <summary>The octets of the second item of the child list named <paramref name="name"/>, or null.</summary>
    public byte[]? Value(string name)
    {
        SexpList? l = Find(name);
        return l is { Items.Count: >= 2 } && l.Items[1] is SexpAtom a ? a.Value : null;
    }
}

/// <summary>
/// Reads S-expressions in the canonical form (<c>(3:rsa(1:n257:…))</c>) and in the advanced form GnuPG prints for editable files (tokens,
/// quoted strings, <c>#hex#</c>, <c>|base64|</c>, whitespace). The depth, the node count and the input size are bounded by <see cref="GnuPGLimits"/>.
/// </summary>
internal static class SexpReader
{
    public static SexpList Parse(ReadOnlySpan<byte> data, GnuPGLimits limits, out int consumed)
    {
        var p = new Parser(data, limits);
        p.SkipSpace();
        if (p.Done || p.Peek != '(')
        {
            throw p.Fail(GnuPGError.BadSyntax, "expected '('");
        }

        SexpList l = p.ParseList(1);
        consumed = p.Position;
        return l;
    }

    private ref struct Parser
    {
        private readonly ReadOnlySpan<byte> _s;
        private readonly GnuPGLimits _limits;
        private int _nodes;

        public Parser(ReadOnlySpan<byte> s, GnuPGLimits limits)
        {
            _s = s;
            _limits = limits;
            Position = 0;
        }

        public int Position { get; private set; }

        public readonly bool Done => Position >= _s.Length;

        public readonly char Peek => (char)_s[Position];

        public readonly GnuPGFormatException Fail(GnuPGError e, string what) => new(e, Position, what);

        public void SkipSpace()
        {
            while (Position < _s.Length && _s[Position] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
            {
                Position++;
            }
        }

        public SexpList ParseList(int depth)
        {
            if (depth > _limits.MaxSexpDepth)
            {
                throw Fail(GnuPGError.LimitExceeded, "S-expression nesting");
            }

            Count();
            Position++; // '('
            var list = new SexpList();
            while (true)
            {
                SkipSpace();
                if (Done)
                {
                    throw Fail(GnuPGError.Truncated, "unterminated list");
                }

                char c = Peek;
                if (c == ')')
                {
                    Position++;
                    return list;
                }

                if (c == '(')
                {
                    list.Items.Add(ParseList(depth + 1));
                }
                else if (c == '[')
                {
                    SkipHint();
                }
                else
                {
                    Count();
                    list.Items.Add(new SexpAtom(ParseAtom()));
                }
            }
        }

        private void Count()
        {
            if (++_nodes > _limits.MaxSexpNodes)
            {
                throw Fail(GnuPGError.LimitExceeded, "S-expression size");
            }
        }

        // A display hint "[...]" in front of an atom carries no key data; skip it.
        private void SkipHint()
        {
            while (!Done && Peek != ']')
            {
                Position++;
            }

            if (Done)
            {
                throw Fail(GnuPGError.Truncated, "display hint");
            }

            Position++;
        }

        private byte[] ParseAtom()
        {
            char c = Peek;
            switch (c)
            {
                case '#':
                    return ParseHex();
                case '"':
                    return ParseQuoted();
                case '|':
                    return ParseBase64();
                default:
                    if (c is >= '0' and <= '9')
                    {
                        int start = Position;
                        long n = 0;
                        while (!Done && Peek is >= '0' and <= '9')
                        {
                            n = (n * 10) + (Peek - '0');
                            if (n > _limits.MaxKeyFileLength)
                            {
                                throw Fail(GnuPGError.LimitExceeded, "atom length");
                            }

                            Position++;
                        }

                        if (!Done && Peek == ':')
                        {
                            Position++;
                            if (n > _s.Length - Position)
                            {
                                throw Fail(GnuPGError.Truncated, "verbatim atom");
                            }

                            byte[] v = _s.Slice(Position, (int)n).ToArray();
                            Position += (int)n;
                            return v;
                        }

                        Position = start; // a token that starts with digits
                    }

                    return ParseToken();
            }
        }

        private byte[] ParseToken()
        {
            int start = Position;
            while (!Done && !IsDelimiter(Peek))
            {
                Position++;
            }

            if (Position == start)
            {
                throw Fail(GnuPGError.BadSyntax, "unexpected character");
            }

            return _s[start..Position].ToArray();
        }

        private static bool IsDelimiter(char c) => c is ' ' or '\t' or '\r' or '\n' or '(' or ')' or '#' or '"' or '|' or '[' or ']';

        private byte[] ParseHex()
        {
            Position++;
            var outBytes = new List<byte>();
            int hi = -1;
            while (true)
            {
                if (Done)
                {
                    throw Fail(GnuPGError.Truncated, "hex atom");
                }

                char c = Peek;
                Position++;
                if (c == '#')
                {
                    break;
                }

                if (c is ' ' or '\t' or '\r' or '\n')
                {
                    continue;
                }

                int v = c switch
                {
                    >= '0' and <= '9' => c - '0',
                    >= 'a' and <= 'f' => c - 'a' + 10,
                    >= 'A' and <= 'F' => c - 'A' + 10,
                    _ => -1,
                };
                if (v < 0)
                {
                    throw Fail(GnuPGError.BadSyntax, "hex digit");
                }

                if (hi < 0)
                {
                    hi = v;
                }
                else
                {
                    outBytes.Add((byte)((hi << 4) | v));
                    hi = -1;
                }
            }

            if (hi >= 0)
            {
                throw Fail(GnuPGError.BadSyntax, "odd number of hex digits");
            }

            return outBytes.ToArray();
        }

        private byte[] ParseBase64()
        {
            Position++;
            int start = Position;
            while (!Done && Peek != '|')
            {
                Position++;
            }

            if (Done)
            {
                throw Fail(GnuPGError.Truncated, "base64 atom");
            }

            string text = Encoding.ASCII.GetString(_s[start..Position]);
            Position++;
            try
            {
                return Convert.FromBase64String(string.Concat(text.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries)));
            }
            catch (FormatException)
            {
                throw Fail(GnuPGError.BadSyntax, "base64 atom");
            }
        }

        private byte[] ParseQuoted()
        {
            Position++;
            var o = new List<byte>();
            while (true)
            {
                if (Done)
                {
                    throw Fail(GnuPGError.Truncated, "quoted string");
                }

                byte c = _s[Position++];
                if (c == (byte)'"')
                {
                    return o.ToArray();
                }

                if (c != (byte)'\\')
                {
                    o.Add(c);
                    continue;
                }

                if (Done)
                {
                    throw Fail(GnuPGError.Truncated, "escape");
                }

                byte e = _s[Position++];
                switch (e)
                {
                    case (byte)'n':
                        o.Add((byte)'\n');
                        break;
                    case (byte)'r':
                        o.Add((byte)'\r');
                        break;
                    case (byte)'t':
                        o.Add((byte)'\t');
                        break;
                    case (byte)'b':
                        o.Add(8);
                        break;
                    case (byte)'f':
                        o.Add(12);
                        break;
                    case (byte)'v':
                        o.Add(11);
                        break;
                    case (byte)'x':
                    {
                        if (_s.Length - Position < 2 || !Uri.IsHexDigit((char)_s[Position]) || !Uri.IsHexDigit((char)_s[Position + 1]))
                        {
                            throw Fail(GnuPGError.BadSyntax, "\\x escape");
                        }

                        o.Add(Convert.ToByte(Encoding.ASCII.GetString(_s.Slice(Position, 2)), 16));
                        Position += 2;
                        break;
                    }

                    case >= (byte)'0' and <= (byte)'7':
                    {
                        if (_s.Length - Position < 2)
                        {
                            throw Fail(GnuPGError.BadSyntax, "octal escape");
                        }

                        int v = e - '0';
                        for (int i = 0; i < 2; i++)
                        {
                            byte d = _s[Position++];
                            if (d is < (byte)'0' or > (byte)'7')
                            {
                                throw Fail(GnuPGError.BadSyntax, "octal escape");
                            }

                            v = (v << 3) | (d - '0');
                        }

                        o.Add((byte)v);
                        break;
                    }

                    case (byte)'\n':
                    case (byte)'\r':
                        break; // a backslash at the end of a line continues the string
                    default:
                        o.Add(e);
                        break;
                }
            }
        }
    }
}

/// <summary>Writes S-expressions in the canonical form, which is what GnuPG hashes and uses as associated data.</summary>
internal static class SexpWriter
{
    public static byte[] Canonical(SexpNode node)
    {
        using var ms = new MemoryStream();
        Write(node, ms);
        return ms.ToArray();
    }

    public static void Write(SexpNode node, Stream o)
    {
        switch (node)
        {
            case SexpAtom a:
                WriteAscii(o, a.Value.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
                o.WriteByte((byte)':');
                o.Write(a.Value);
                break;
            case SexpList l:
                o.WriteByte((byte)'(');
                foreach (SexpNode n in l.Items)
                {
                    Write(n, o);
                }

                o.WriteByte((byte)')');
                break;
        }
    }

    private static void WriteAscii(Stream o, string s)
    {
        foreach (char ch in s)
        {
            o.WriteByte((byte)ch);
        }
    }
}
