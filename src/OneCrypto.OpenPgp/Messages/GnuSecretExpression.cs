namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// Reads the canonical S-expression in which GnuPG 2.5 stores a composite (curve plus ML-KEM) secret key when it exports it (the format of its key files,
/// described in the GnuPG key-format notes): <c>(composite-key (private-key (ecc (curve ..)(q ..)(d ..))) (private-key (kyber768 (p ..)(s ..)(seed ..))))</c>.
/// Atoms are length-prefixed byte strings, so no input is ever interpreted as text.
/// </summary>
internal static class GnuSecretExpression
{
    private const int MaxDepth = 8;

    private sealed class Node
    {
        public byte[]? Atom;
        public List<Node>? List;
    }

    /// <summary>The curve scalar <c>d</c> and the ML-KEM decapsulation key <c>s</c>.</summary>
    internal static List<byte[]> CompositeParts(ReadOnlySpan<byte> s)
    {
        int i = 0;
        Node root = Parse(s, ref i, 0);
        if (i != s.Length || root.List is null || !Is(root.List, 0, "composite-key"))
        {
            throw Bad();
        }

        byte[]? d = null;
        byte[]? kem = null;
        foreach (Node n in root.List.Skip(1))
        {
            if (n.List is not { Count: 2 } pk || !Is(pk, 0, "private-key") || pk[1].List is not { Count: > 1 } algo || algo[0].Atom is null)
            {
                throw Bad();
            }

            string name = System.Text.Encoding.ASCII.GetString(algo[0].Atom!);
            foreach (Node item in algo.Skip(1))
            {
                if (item.List is not { Count: 2 } kv || kv[0].Atom is null || kv[1].Atom is null)
                {
                    continue;
                }

                string key = System.Text.Encoding.ASCII.GetString(kv[0].Atom!);
                if (name == "ecc" && key == "d")
                {
                    d = kv[1].Atom;
                }
                else if (name.StartsWith("kyber", StringComparison.Ordinal) && key == "s")
                {
                    kem = kv[1].Atom;
                }
            }
        }

        if (d is null || kem is null)
        {
            throw Bad();
        }

        return [d, kem];
    }

    private static bool Is(List<Node> list, int index, string text) => list.Count > index && list[index].Atom is { } a && System.Text.Encoding.ASCII.GetString(a) == text;

    private static PgpException Bad() => new(PgpFailure.MalformedMessage, "The composite secret key is not in the expected form.");

    private static Node Parse(ReadOnlySpan<byte> s, ref int i, int depth)
    {
        if (depth > MaxDepth || i >= s.Length)
        {
            throw Bad();
        }

        if (s[i] == (byte)'(')
        {
            i++;
            var list = new List<Node>();
            while (true)
            {
                if (i >= s.Length)
                {
                    throw Bad();
                }

                if (s[i] == (byte)')')
                {
                    i++;
                    return new Node { List = list };
                }

                list.Add(Parse(s, ref i, depth + 1));
                if (list.Count > 64)
                {
                    throw Bad();
                }
            }
        }

        // An atom: decimal length, a colon, the octets.
        int length = 0;
        int digits = 0;
        while (i < s.Length && s[i] is >= (byte)'0' and <= (byte)'9')
        {
            length = (length * 10) + (s[i] - '0');
            if (++digits > 6 || length > s.Length)
            {
                throw Bad();
            }

            i++;
        }

        if (digits == 0 || i >= s.Length || s[i] != (byte)':' || i + 1 + length > s.Length)
        {
            throw Bad();
        }

        byte[] atom = s.Slice(i + 1, length).ToArray();
        i += 1 + length;
        return new Node { Atom = atom };
    }
}
