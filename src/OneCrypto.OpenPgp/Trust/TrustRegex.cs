using System.Text;

namespace RecursiveAI.OneCrypto.OpenPgp.Trust;

/// <summary>
/// The regular expressions of Regular Expression signature subpackets (RFC 9580 §5.2.3.22) that scope a trust signature to some User IDs.
/// This is a small extended-regex dialect run as a state-set simulation, so matching takes time proportional to the User ID length times the
/// pattern size no matter what the pattern is; there is no backtracking and no back-reference. Supported: literals, <c>.</c>, bracket
/// expressions (ranges, negation, <c>[:alpha:]</c>-style classes), <c>( )</c>, <c>|</c>, <c>*</c>, <c>+</c>, <c>?</c>, <c>{m}</c>, <c>{m,}</c>,
/// <c>{m,n}</c>, <c>^</c>, <c>$</c> and backslash escapes. A match is a search: the pattern need not cover the whole User ID.
/// </summary>
public sealed class TrustRegex
{
    private const int MaxRepeat = 255;

    private enum Op : byte
    {
        Char,
        Any,
        Class,
        Split,
        Jump,
        Begin,
        End,
        Match,
    }

    private readonly struct Inst
    {
        internal Inst(Op op, int a = 0, int b = 0, ClassSet? set = null)
        {
            Op = op;
            A = a;
            B = b;
            Set = set;
        }

        internal Op Op { get; }

        internal int A { get; }

        internal int B { get; }

        internal ClassSet? Set { get; }
    }

    private sealed class ClassSet
    {
        internal List<(int Lo, int Hi)> Ranges { get; } = [];

        internal List<string> Named { get; } = [];

        internal bool Negated { get; set; }

        internal bool Contains(int cp)
        {
            bool hit = false;
            foreach ((int lo, int hi) in Ranges)
            {
                if (cp >= lo && cp <= hi)
                {
                    hit = true;
                    break;
                }
            }

            if (!hit)
            {
                foreach (string n in Named)
                {
                    if (NamedMatch(n, cp))
                    {
                        hit = true;
                        break;
                    }
                }
            }

            return hit != Negated;
        }

        private static bool NamedMatch(string name, int c) => name switch
        {
            "alpha" => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'),
            "digit" => c >= '0' && c <= '9',
            "alnum" => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'),
            "upper" => c >= 'A' && c <= 'Z',
            "lower" => c >= 'a' && c <= 'z',
            "space" => c is ' ' or '\t' or '\n' or '\r' or '\f' or '\v',
            "blank" => c is ' ' or '\t',
            "punct" => c is > 32 and < 127 && !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')),
            "xdigit" => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'),
            _ => false,
        };
    }

    // The syntax tree. Repetition counts are expanded when compiling, which is where the state limit applies.
    private abstract record Node;

    private sealed record Lit(int Cp) : Node;

    private sealed record AnyNode : Node;

    private sealed record Cls(ClassSet Set) : Node;

    private sealed record Anchor(bool AtEnd) : Node;

    private sealed record Seq(List<Node> Items) : Node;

    private sealed record Alt(List<Node> Choices) : Node;

    private sealed record Rep(Node Inner, int Min, int Max) : Node; // Max -1 = unbounded

    private readonly Inst[] _program;

    private TrustRegex(string pattern, Inst[] program)
    {
        Pattern = pattern;
        _program = program;
    }

    /// <summary>The pattern as given.</summary>
    public string Pattern { get; }

    /// <summary>Compiles a pattern.</summary>
    /// <param name="pattern">The pattern.</param>
    /// <param name="regex">The compiled pattern, or null.</param>
    /// <param name="limits">Limits; null for <see cref="TrustLimits.Default"/>.</param>
    /// <returns>True when the pattern is valid, within the limits, and was compiled. A pattern that is not valid is never a match, so a scope that cannot be read restricts rather than widens.</returns>
    public static bool TryCompile(string pattern, out TrustRegex? regex, TrustLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        limits ??= TrustLimits.Default;
        regex = null;
        if (pattern.Length > limits.MaxRegexLength)
        {
            return false;
        }

        try
        {
            var p = new Parser(pattern);
            Node tree = p.ParseAlt();
            if (!p.AtEnd)
            {
                return false;
            }

            var code = new List<Inst>();
            Emit(tree, code, limits.MaxRegexStates);
            code.Add(new Inst(Op.Match));
            regex = new TrustRegex(pattern, [.. code]);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Compiles a pattern.</summary>
    /// <param name="pattern">The pattern.</param>
    /// <param name="limits">Limits; null for <see cref="TrustLimits.Default"/>.</param>
    /// <exception cref="FormatException">The pattern is not valid or exceeds the limits.</exception>
    public static TrustRegex Compile(string pattern, TrustLimits? limits = null) =>
        TryCompile(pattern, out TrustRegex? r, limits) ? r! : throw new FormatException("The regular expression is not valid or is too large.");

    /// <summary>The pattern GnuPG-style tools build for "any address in this domain": <c>&lt;[^&gt;]+[@.]domain&gt;$</c>, with the domain's dots escaped.</summary>
    /// <param name="domain">A domain such as <c>example.org</c>.</param>
    public static string DomainPattern(string domain)
    {
        ArgumentNullException.ThrowIfNull(domain);
        var sb = new StringBuilder("<[^>]+[@.]");
        foreach (char c in domain)
        {
            if (c is '.' or '\\' or '[' or ']' or '(' or ')' or '*' or '+' or '?' or '{' or '}' or '|' or '^' or '$')
            {
                sb.Append('\\');
            }

            sb.Append(c);
        }

        return sb.Append(">$").ToString();
    }

    /// <summary>True when the pattern matches anywhere in <paramref name="text"/>.</summary>
    /// <param name="text">The User ID text.</param>
    public bool IsMatch(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        int n = _program.Length;
        var current = new List<int>(n);
        var next = new List<int>(n);
        var seen = new int[n];
        int generation = 0;
        int index = 0;
        bool atStart = true;
        while (true)
        {
            bool atEnd = index >= text.Length;
            generation++;
            // A search can begin at every position: add the start state each time before following empty moves.
            AddState(current, 0, seen, generation, atStart, atEnd);
            foreach (int pc in current)
            {
                if (_program[pc].Op == Op.Match)
                {
                    return true;
                }
            }

            if (atEnd)
            {
                return false;
            }

            Rune.TryGetRuneAt(text, index, out Rune rune);
            int len = rune.Utf16SequenceLength;
            int cp = rune.Value;
            generation++;
            bool nextAtEnd = index + len >= text.Length;
            next.Clear();
            foreach (int pc in current)
            {
                Inst inst = _program[pc];
                bool ok = inst.Op switch
                {
                    Op.Char => inst.A == cp,
                    Op.Any => true,
                    Op.Class => inst.Set!.Contains(cp),
                    _ => false,
                };
                if (ok)
                {
                    AddState(next, pc + 1, seen, generation, false, nextAtEnd);
                }
            }

            (current, next) = (next, current);
            index += len;
            atStart = false;
        }
    }

    private void AddState(List<int> list, int pc, int[] seen, int generation, bool atStart, bool atEnd)
    {
        var stack = new Stack<int>();
        stack.Push(pc);
        while (stack.Count > 0)
        {
            int p = stack.Pop();
            if (seen[p] == generation)
            {
                continue;
            }

            seen[p] = generation;
            Inst inst = _program[p];
            switch (inst.Op)
            {
                case Op.Jump:
                    stack.Push(inst.A);
                    break;
                case Op.Split:
                    stack.Push(inst.B);
                    stack.Push(inst.A);
                    break;
                case Op.Begin:
                    if (atStart)
                    {
                        stack.Push(p + 1);
                    }

                    break;
                case Op.End:
                    if (atEnd)
                    {
                        stack.Push(p + 1);
                    }

                    break;
                default:
                    list.Add(p);
                    break;
            }
        }
    }

    private static void Emit(Node node, List<Inst> code, int maxStates)
    {
        if (code.Count > maxStates)
        {
            throw new FormatException("too many states");
        }

        switch (node)
        {
            case Lit l:
                code.Add(new Inst(Op.Char, l.Cp));
                break;
            case AnyNode:
                code.Add(new Inst(Op.Any));
                break;
            case Cls c:
                code.Add(new Inst(Op.Class, set: c.Set));
                break;
            case Anchor a:
                code.Add(new Inst(a.AtEnd ? Op.End : Op.Begin));
                break;
            case Seq s:
                foreach (Node item in s.Items)
                {
                    Emit(item, code, maxStates);
                }

                break;
            case Alt alt:
                {
                    var jumps = new List<int>();
                    for (int i = 0; i < alt.Choices.Count; i++)
                    {
                        if (i < alt.Choices.Count - 1)
                        {
                            int split = code.Count;
                            code.Add(default);
                            Emit(alt.Choices[i], code, maxStates);
                            jumps.Add(code.Count);
                            code.Add(default);
                            code[split] = new Inst(Op.Split, split + 1, code.Count);
                        }
                        else
                        {
                            Emit(alt.Choices[i], code, maxStates);
                        }
                    }

                    foreach (int j in jumps)
                    {
                        code[j] = new Inst(Op.Jump, code.Count);
                    }

                    break;
                }

            case Rep r:
                for (int i = 0; i < r.Min; i++)
                {
                    Emit(r.Inner, code, maxStates);
                }

                if (r.Max < 0)
                {
                    int split = code.Count;
                    code.Add(default);
                    Emit(r.Inner, code, maxStates);
                    code.Add(new Inst(Op.Jump, split));
                    code[split] = new Inst(Op.Split, split + 1, code.Count);
                }
                else
                {
                    var splits = new List<int>();
                    for (int i = r.Min; i < r.Max; i++)
                    {
                        splits.Add(code.Count);
                        code.Add(default);
                        Emit(r.Inner, code, maxStates);
                    }

                    foreach (int s in splits)
                    {
                        code[s] = new Inst(Op.Split, s + 1, code.Count);
                    }
                }

                break;
            default:
                throw new FormatException("unknown node");
        }

        if (code.Count > maxStates)
        {
            throw new FormatException("too many states");
        }
    }

    private sealed class Parser
    {
        private readonly string _s;
        private int _i;
        private int _depth;

        internal Parser(string s)
        {
            _s = s;
        }

        internal bool AtEnd => _i >= _s.Length;

        internal Node ParseAlt()
        {
            if (++_depth > 64)
            {
                throw new FormatException("nesting");
            }

            var choices = new List<Node> { ParseSeq() };
            while (_i < _s.Length && _s[_i] == '|')
            {
                _i++;
                choices.Add(ParseSeq());
            }

            _depth--;
            return choices.Count == 1 ? choices[0] : new Alt(choices);
        }

        private Seq ParseSeq()
        {
            var items = new List<Node>();
            while (_i < _s.Length && _s[_i] is not ('|' or ')'))
            {
                items.Add(ParseRepeat());
            }

            return new Seq(items);
        }

        private Node ParseRepeat()
        {
            Node atom = ParseAtom();
            while (_i < _s.Length)
            {
                char c = _s[_i];
                if (c == '*')
                {
                    _i++;
                    atom = new Rep(atom, 0, -1);
                }
                else if (c == '+')
                {
                    _i++;
                    atom = new Rep(atom, 1, -1);
                }
                else if (c == '?')
                {
                    _i++;
                    atom = new Rep(atom, 0, 1);
                }
                else if (c == '{')
                {
                    _i++;
                    int min = ReadNumber();
                    int max = min;
                    if (_i < _s.Length && _s[_i] == ',')
                    {
                        _i++;
                        max = _i < _s.Length && _s[_i] == '}' ? -1 : ReadNumber();
                    }

                    if (_i >= _s.Length || _s[_i] != '}' || min > MaxRepeat || max > MaxRepeat || (max >= 0 && max < min))
                    {
                        throw new FormatException("interval");
                    }

                    _i++;
                    atom = new Rep(atom, min, max);
                }
                else
                {
                    break;
                }
            }

            return atom;
        }

        private int ReadNumber()
        {
            int start = _i;
            int v = 0;
            while (_i < _s.Length && _s[_i] is >= '0' and <= '9')
            {
                v = checked((v * 10) + (_s[_i] - '0'));
                if (v > 100_000)
                {
                    throw new FormatException("number");
                }

                _i++;
            }

            return _i == start ? throw new FormatException("number") : v;
        }

        private Node ParseAtom()
        {
            char c = _s[_i];
            switch (c)
            {
                case '(':
                    {
                        _i++;
                        Node inner = ParseAlt();
                        if (_i >= _s.Length || _s[_i] != ')')
                        {
                            throw new FormatException("group");
                        }

                        _i++;
                        return inner;
                    }

                case '.':
                    _i++;
                    return new AnyNode();
                case '^':
                    _i++;
                    return new Anchor(false);
                case '$':
                    _i++;
                    return new Anchor(true);
                case '[':
                    return ParseBracket();
                case '\\':
                    {
                        _i++;
                        if (_i >= _s.Length)
                        {
                            throw new FormatException("escape");
                        }

                        Rune.TryGetRuneAt(_s, _i, out Rune r);
                        _i += r.Utf16SequenceLength;
                        return new Lit(r.Value);
                    }

                case '*' or '+' or '?':
                    throw new FormatException("nothing to repeat");
                default:
                    {
                        Rune.TryGetRuneAt(_s, _i, out Rune r);
                        _i += r.Utf16SequenceLength;
                        return new Lit(r.Value);
                    }
            }
        }

        private Cls ParseBracket()
        {
            _i++; // [
            var set = new ClassSet();
            if (_i < _s.Length && _s[_i] == '^')
            {
                set.Negated = true;
                _i++;
            }

            bool first = true;
            while (true)
            {
                if (_i >= _s.Length)
                {
                    throw new FormatException("bracket");
                }

                char c = _s[_i];
                if (c == ']' && !first)
                {
                    _i++;
                    return new Cls(set);
                }

                first = false;
                if (c == '[' && _i + 1 < _s.Length && _s[_i + 1] == ':')
                {
                    int end = _s.IndexOf(":]", _i + 2, StringComparison.Ordinal);
                    if (end < 0)
                    {
                        throw new FormatException("class");
                    }

                    set.Named.Add(_s[(_i + 2)..end]);
                    _i = end + 2;
                    continue;
                }

                Rune.TryGetRuneAt(_s, _i, out Rune lo);
                _i += lo.Utf16SequenceLength;
                int hi = lo.Value;
                if (_i + 1 < _s.Length && _s[_i] == '-' && _s[_i + 1] != ']')
                {
                    _i++;
                    Rune.TryGetRuneAt(_s, _i, out Rune h);
                    _i += h.Utf16SequenceLength;
                    hi = h.Value;
                    if (hi < lo.Value)
                    {
                        throw new FormatException("range");
                    }
                }

                set.Ranges.Add((lo.Value, hi));
            }
        }
    }
}
