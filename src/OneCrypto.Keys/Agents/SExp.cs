using System.Text;

namespace RecursiveAI.OneCrypto.Keys.Agents;

/// <summary>
/// A canonical S-expression as gpg-agent speaks it (Libgcrypt's "canonical" form: <c>(3:rsa(1:n257:...))</c>): atoms are length-prefixed octet strings, lists are
/// parenthesised. Reading is bounded in depth, node count and atom length, so a hostile agent cannot make a parse expensive.
/// </summary>
internal sealed class SExp
{
    internal const int MaxDepth = 8;
    internal const int MaxNodes = 256;

    private SExp(byte[]? atom, List<SExp>? items)
    {
        Atom = atom;
        Items = items;
    }

    /// <summary>The octets when this is an atom, else null.</summary>
    public byte[]? Atom { get; }

    /// <summary>The members when this is a list, else null.</summary>
    public List<SExp>? Items { get; }

    /// <summary>The atom as ASCII text, or null when this is a list or the octets are not printable ASCII.</summary>
    public string? Text
    {
        get
        {
            if (Atom is null)
            {
                return null;
            }

            foreach (byte b in Atom)
            {
                if (b is < 0x20 or > 0x7E)
                {
                    return null;
                }
            }

            return Encoding.ASCII.GetString(Atom);
        }
    }

    /// <summary>Reads one S-expression that fills <paramref name="data"/>.</summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out SExp? result, out string? error)
    {
        result = null;
        int pos = 0, nodes = 0;
        if (!TryReadNode(data, ref pos, 0, ref nodes, out SExp? node, out error))
        {
            return false;
        }

        if (pos != data.Length)
        {
            error = "Data follows the S-expression.";
            return false;
        }

        result = node;
        return true;
    }

    private static bool TryReadNode(ReadOnlySpan<byte> d, ref int pos, int depth, ref int nodes, out SExp? node, out string? error)
    {
        node = null;
        error = null;
        if (++nodes > MaxNodes)
        {
            error = "The S-expression has too many elements.";
            return false;
        }

        if (pos >= d.Length)
        {
            error = "The S-expression ends early.";
            return false;
        }

        if (d[pos] == '(')
        {
            if (depth >= MaxDepth)
            {
                error = "The S-expression nests too deeply.";
                return false;
            }

            pos++;
            var items = new List<SExp>();
            while (true)
            {
                if (pos >= d.Length)
                {
                    error = "The S-expression ends inside a list.";
                    return false;
                }

                if (d[pos] == ')')
                {
                    pos++;
                    node = new SExp(null, items);
                    return true;
                }

                if (!TryReadNode(d, ref pos, depth + 1, ref nodes, out SExp? child, out error))
                {
                    return false;
                }

                items.Add(child!);
            }
        }

        // An atom: decimal length, a colon, then that many octets (no leading zeros, at most 7 digits).
        int start = pos, len = 0;
        while (pos < d.Length && d[pos] is >= (byte)'0' and <= (byte)'9')
        {
            if (pos - start >= 7)
            {
                error = "An atom length has too many digits.";
                return false;
            }

            len = (len * 10) + (d[pos] - '0');
            pos++;
        }

        if (pos == start || pos >= d.Length || d[pos] != ':' || (d[start] == '0' && pos - start > 1))
        {
            error = "The S-expression has a malformed atom.";
            return false;
        }

        pos++;
        if (len > d.Length - pos)
        {
            error = "An atom is longer than the data.";
            return false;
        }

        node = new SExp(d.Slice(pos, len).ToArray(), null);
        pos += len;
        return true;
    }

    /// <summary>The first member list whose first atom is <paramref name="name"/>, or null.</summary>
    public SExp? Find(string name)
    {
        if (Items is null)
        {
            return null;
        }

        foreach (SExp item in Items)
        {
            if (item.Items is { Count: > 0 } && item.Items[0].Text == name)
            {
                return item;
            }
        }

        return null;
    }

    /// <summary>The octets of the second element of the member list called <paramref name="name"/>, or null.</summary>
    public byte[]? ValueOf(string name)
    {
        SExp? member = Find(name);
        return member?.Items is { Count: 2 } && member.Items[1].Atom is { } a ? a : null;
    }

    /// <summary>Zeroes every atom in the tree; used when the expression carried a secret.</summary>
    public void Wipe()
    {
        if (Atom is not null)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(Atom);
        }

        if (Items is not null)
        {
            foreach (SExp item in Items)
            {
                item.Wipe();
            }
        }
    }

    /// <summary>The name of a list (its first atom), or null.</summary>
    public string? Name => Items is { Count: > 0 } ? Items[0].Text : null;
}

/// <summary>Builds the canonical S-expressions gpg-agent takes as input.</summary>
internal static class SExpWriter
{
    public static byte[] Atom(ReadOnlySpan<byte> value)
    {
        byte[] prefix = Encoding.ASCII.GetBytes(value.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":");
        var o = new byte[prefix.Length + value.Length];
        prefix.CopyTo(o, 0);
        value.CopyTo(o.AsSpan(prefix.Length));
        return o;
    }

    public static byte[] Atom(string value) => Atom(Encoding.ASCII.GetBytes(value));

    public static byte[] List(params ReadOnlySpan<byte[]> parts)
    {
        int n = 2;
        foreach (byte[] p in parts)
        {
            n += p.Length;
        }

        var o = new byte[n];
        o[0] = (byte)'(';
        int at = 1;
        foreach (byte[] p in parts)
        {
            p.CopyTo(o, at);
            at += p.Length;
        }

        o[at] = (byte)')';
        return o;
    }
}
