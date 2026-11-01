using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace RecursiveAI.OneCrypto.OpenPgp.GnuPG;

/// <summary>How a key file protects its secret parameters.</summary>
public enum GnuPGKeyProtection
{
    /// <summary>The secret parameters are stored in the clear (<c>private-key</c>).</summary>
    None = 0,

    /// <summary>AES-128 in OCB mode under a passphrase key (<c>openpgp-s2k3-ocb-aes</c>), the mode GnuPG 2.2 and later write.</summary>
    OcbAes,

    /// <summary>AES-128 in CBC mode with a SHA-1 integrity value (<c>openpgp-s2k3-sha1-aes-cbc</c>), the mode older GnuPG versions write.</summary>
    Sha1AesCbc,

    /// <summary>The OpenPGP secret-key transport form (<c>openpgp-native</c>). Recognised but not opened.</summary>
    OpenPgpNative,

    /// <summary>The secret key is on a token (<c>shadowed-private-key</c>); the file holds only a reference.</summary>
    Shadowed,

    /// <summary>A protection mode this reader does not know.</summary>
    Unknown,
}

/// <summary>
/// A key file of GnuPG's <c>private-keys-v1.d</c>: either a naked S-expression (canonical or advanced form) or the extended format of
/// name/value lines whose <c>Key</c> line holds the S-expression. Parsing reads the public parameters and the protection parameters;
/// <see cref="Unlock"/> decrypts the secret parameters.
/// </summary>
public sealed class GnuPGKeyFile
{
    private readonly SexpList _algorithmList;
    private readonly SexpList _root;
    private readonly byte[] _publicCanonicalAd;

    private GnuPGKeyFile(
        ReadOnlyMemory<byte> raw,
        List<KeyValuePair<string, string>> headers,
        SexpList root,
        SexpList algorithmList,
        GnuPGKeyProtection protection)
    {
        Raw = raw;
        Headers = headers;
        _root = root;
        _algorithmList = algorithmList;
        Protection = protection;
        Algorithm = algorithmList.Name!.ToLowerInvariant();
        Curve = algorithmList.Find("curve") is { Items.Count: >= 2 } c && c.Items[1] is SexpAtom ca ? ca.Text : null;
        _publicCanonicalAd = BuildAssociatedData(algorithmList);
    }

    /// <summary>The file as read.</summary>
    public ReadOnlyMemory<byte> Raw { get; }

    /// <summary>The header lines of an extended-format file in order (names as written); empty for a naked S-expression.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; }

    /// <summary>The protection mode.</summary>
    public GnuPGKeyProtection Protection { get; }

    /// <summary>True when the secret parameters are encrypted (every mode but <see cref="GnuPGKeyProtection.None"/>).</summary>
    public bool IsProtected => Protection != GnuPGKeyProtection.None;

    /// <summary>The algorithm name as the key expression gives it, lower case: <c>rsa</c>, <c>ecc</c>, <c>dsa</c>, <c>elg</c>, <c>kyber</c>…</summary>
    public string Algorithm { get; }

    /// <summary>The curve name of an <c>ecc</c> key as written (for example <c>Ed25519</c>, <c>NIST P-256</c>, <c>brainpoolP256r1</c>), or null.</summary>
    public string? Curve { get; }

    /// <summary>The first header named <paramref name="name"/> (compared ignoring case), or null.</summary>
    /// <param name="name">The header name without the colon.</param>
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

    /// <summary>The creation time from the <c>Created</c> header, or the <c>created-at</c> element of the key, or null when neither is present.</summary>
    public DateTimeOffset? Created
    {
        get
        {
            string? text = GetHeader("Created");
            if (text is not null && TryIsoTime(text, out DateTimeOffset t))
            {
                return t;
            }

            byte[]? v = _root.Value("created-at");
            if (v is not null)
            {
                string s = Encoding.Latin1.GetString(v);
                if (TryIsoTime(s, out t))
                {
                    return t;
                }

                if (long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out long secs) && secs is >= 0 and <= 253402300799)
                {
                    return DateTimeOffset.FromUnixTimeSeconds(secs);
                }
            }

            return null;
        }
    }

    /// <summary>The free-text description (the <c>Description</c> header), or null.</summary>
    public string? Description => GetHeader("Description");

    /// <summary>The comment element of the key, or null.</summary>
    public string? Comment => _root.Value("comment") is { } v ? Encoding.UTF8.GetString(v) : null;

    /// <summary>The time the key was protected (<c>protected-at</c>), or null.</summary>
    public DateTimeOffset? ProtectedAt => _algorithmList.Value("protected-at") is { } v && TryIsoTime(Encoding.Latin1.GetString(v), out DateTimeOffset t) ? t : null;

    /// <summary>For a shadowed key, the serial number and key reference of the token as written in the <c>Token</c> header, or null.</summary>
    public string? Token => GetHeader("Token");

    /// <summary>
    /// The octets of a public parameter (<c>n</c> and <c>e</c> of RSA, <c>q</c> of an elliptic-curve key, <c>p</c>, <c>q</c>, <c>g</c> and
    /// <c>y</c> of DSA, …) exactly as stored, including a leading zero octet of an unsigned integer. Empty when the key has no such parameter.
    /// </summary>
    /// <param name="name">The parameter name.</param>
    public ReadOnlyMemory<byte> GetPublicParameter(string name) => _algorithmList.Value(name) ?? [];

    /// <summary>Reads a key file.</summary>
    /// <param name="data">The file contents.</param>
    /// <param name="limits">Limits; null for <see cref="GnuPGLimits.Default"/>.</param>
    /// <exception cref="GnuPGFormatException">The file is not a key file, the S-expression is malformed or is not a private, protected or shadowed key, or a limit is exceeded.</exception>
    public static GnuPGKeyFile Parse(ReadOnlyMemory<byte> data, GnuPGLimits? limits = null)
    {
        limits ??= GnuPGLimits.Default;
        if (data.Length > limits.MaxKeyFileLength)
        {
            throw new GnuPGFormatException(GnuPGError.LimitExceeded, 0, "key file length");
        }

        var headers = new List<KeyValuePair<string, string>>();
        SexpList root;
        ReadOnlySpan<byte> s = data.Span;
        if (s.Length > 0 && s[0] == (byte)'(')
        {
            root = SexpReader.Parse(s, limits, out _);
        }
        else
        {
            string? keyText = ReadHeaders(s, headers);
            if (keyText is null)
            {
                throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, "no Key line");
            }

            root = SexpReader.Parse(Encoding.UTF8.GetBytes(keyText), limits, out _);
        }

        string? kind = root.Name;
        bool isPrivate = kind == "private-key";
        bool isProtected = kind == "protected-private-key";
        bool isShadowed = kind == "shadowed-private-key";
        if (!isPrivate && !isProtected && !isShadowed)
        {
            throw new GnuPGFormatException(GnuPGError.BadHeader, 0, "not a private key expression");
        }

        if (root.Items.Count < 2 || root.Items[1] is not SexpList alg || alg.Name is null)
        {
            throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, "key algorithm");
        }

        GnuPGKeyProtection protection = GnuPGKeyProtection.None;
        if (isShadowed)
        {
            protection = GnuPGKeyProtection.Shadowed;
        }
        else if (isProtected)
        {
            SexpList? prot = alg.Find("protected");
            if (prot is null || prot.Items.Count < 3 || prot.Items[1] is not SexpAtom mode)
            {
                throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, "protected element");
            }

            protection = mode.Text switch
            {
                "openpgp-s2k3-ocb-aes" => GnuPGKeyProtection.OcbAes,
                "openpgp-s2k3-sha1-aes-cbc" => GnuPGKeyProtection.Sha1AesCbc,
                "openpgp-native" => GnuPGKeyProtection.OpenPgpNative,
                _ => GnuPGKeyProtection.Unknown,
            };
        }

        return new GnuPGKeyFile(data, headers, root, alg, protection);
    }

    /// <summary>Reads a key file without throwing for malformed input.</summary>
    /// <param name="data">The file contents.</param>
    /// <param name="file">The key file, or null.</param>
    /// <param name="failure">The reason when this returns false.</param>
    /// <param name="limits">Limits; null for <see cref="GnuPGLimits.Default"/>.</param>
    /// <returns>True when the file was read.</returns>
    public static bool TryParse(ReadOnlyMemory<byte> data, out GnuPGKeyFile? file, out GnuPGFailure failure, GnuPGLimits? limits = null)
    {
        try
        {
            file = Parse(data, limits);
            failure = default;
            return true;
        }
        catch (GnuPGFormatException e)
        {
            file = null;
            failure = e.Failure;
            return false;
        }
    }

    /// <summary>
    /// Decrypts the secret parameters. An unprotected key ignores the passphrase. The passphrase is encoded as UTF-8 into a buffer that is zeroed
    /// before this returns; the decrypted parameters live in a pinned buffer owned by the result.
    /// </summary>
    /// <param name="passphrase">The passphrase.</param>
    /// <param name="limits">Limits; null for <see cref="GnuPGLimits.Default"/>.</param>
    /// <exception cref="GnuPGWrongPassphraseException">The passphrase is wrong, or the encrypted part is damaged (the two cannot be told apart).</exception>
    /// <exception cref="RecursiveAI.OneCrypto.Primitives.KdfLimitExceededException">The key file asks for more S2K work than <see cref="GnuPGLimits.MaxS2kCount"/>.</exception>
    /// <exception cref="GnuPGFormatException">The protection parameters or the decrypted data are malformed.</exception>
    /// <exception cref="NotSupportedException">The key is shadowed, uses <c>openpgp-native</c> or an unknown protection mode.</exception>
    public GnuPGSecretKey Unlock(ReadOnlySpan<char> passphrase, GnuPGLimits? limits = null)
    {
        limits ??= GnuPGLimits.Default;
        return Protection switch
        {
            GnuPGKeyProtection.None => GnuPGSecretKey.FromClear(this, _algorithmList, limits),
            GnuPGKeyProtection.OcbAes or GnuPGKeyProtection.Sha1AesCbc => GnuPGSecretKey.FromProtected(this, _algorithmList, _publicCanonicalAd, passphrase, limits),
            GnuPGKeyProtection.Shadowed => throw new NotSupportedException("The secret key is on a token; this key file holds only a reference."),
            GnuPGKeyProtection.OpenPgpNative => throw new NotSupportedException("The openpgp-native protection mode is not supported."),
            _ => throw new NotSupportedException("Unknown key protection mode."),
        };
    }

    /// <summary>The protected element's parameters: S2K salt, iteration count, and the IV or nonce.</summary>
    internal (byte[] Salt, long Count, byte[] IvOrNonce, byte[] Encrypted) ProtectionParameters()
    {
        SexpList prot = _algorithmList.Find("protected")!;
        if (prot.Items[2] is not SexpList parms || parms.Items.Count != 2 || parms.Items[0] is not SexpList s2k || s2k.Items.Count != 3
            || s2k.Items[0] is not SexpAtom hash || hash.Text != "sha1" || s2k.Items[1] is not SexpAtom salt || s2k.Items[2] is not SexpAtom countAtom
            || parms.Items[1] is not SexpAtom iv || prot.Items.Count < 4 || prot.Items[3] is not SexpAtom encrypted)
        {
            throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, "protection parameters");
        }

        if (salt.Value.Length != 8)
        {
            throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, "S2K salt length");
        }

        if (!long.TryParse(countAtom.Text, NumberStyles.None, CultureInfo.InvariantCulture, out long count))
        {
            throw new GnuPGFormatException(GnuPGError.BadSyntax, 0, "S2K count");
        }

        return (salt.Value, count, iv.Value, encrypted.Value);
    }

    internal SexpList AlgorithmList => _algorithmList;

    // The OCB associated data and the CBC integrity hash both cover the key expression without the protected element: the algorithm name,
    // the public parameters in file order, and the protected-at element if present.
    private static byte[] BuildAssociatedData(SexpList alg)
    {
        var list = new SexpList();
        foreach (SexpNode n in alg.Items)
        {
            if (n is SexpList l && string.Equals(l.Name, "protected", StringComparison.Ordinal))
            {
                continue;
            }

            if (n is SexpList pa && string.Equals(pa.Name, "protected-at", StringComparison.Ordinal))
            {
                continue; // appended last
            }

            list.Items.Add(n);
        }

        if (alg.Find("protected-at") is { } at)
        {
            list.Items.Add(at);
        }

        return SexpWriter.Canonical(list);
    }

    private static string? ReadHeaders(ReadOnlySpan<byte> data, List<KeyValuePair<string, string>> headers)
    {
        string text = Encoding.UTF8.GetString(data);
        string[] lines = text.Split('\n');
        string? name = null;
        var value = new StringBuilder();
        string? key = null;
        int lineNo = 0;
        void Flush()
        {
            if (name is null)
            {
                return;
            }

            string v = value.ToString();
            if (string.Equals(name, "Key", StringComparison.OrdinalIgnoreCase))
            {
                if (key is not null)
                {
                    throw new GnuPGFormatException(GnuPGError.BadSyntax, lineNo, "more than one Key line");
                }

                key = v;
            }

            headers.Add(new KeyValuePair<string, string>(name, v));
            name = null;
            value.Clear();
        }

        foreach (string raw in lines)
        {
            lineNo++;
            string line = raw.TrimEnd('\r');
            if (line.Trim().Length == 0 || line.TrimStart().StartsWith('#'))
            {
                continue; // blank lines and comment lines
            }

            if (line[0] is ' ' or '\t')
            {
                if (name is null)
                {
                    throw new GnuPGFormatException(GnuPGError.BadSyntax, lineNo, "continuation without a header");
                }

                value.Append(line.AsSpan(1)); // one leading blank is the continuation marker; the rest is part of the value
                continue;
            }

            Flush();
            int colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0 || !IsHeaderName(line.AsSpan(0, colon)))
            {
                throw new GnuPGFormatException(GnuPGError.BadSyntax, lineNo, "header line");
            }

            name = line[..colon];
            value.Append(line.AsSpan(colon + 1).TrimStart(" \t"));
        }

        Flush();
        return key;
    }

    private static bool IsHeaderName(ReadOnlySpan<char> s)
    {
        if (s.Length == 0 || !char.IsAsciiLetter(s[0]))
        {
            return false;
        }

        foreach (char c in s)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '-')
            {
                return false;
            }
        }

        return true;
    }

    // GnuPG writes times as yyyymmddThhmmss in UTC.
    private static bool TryIsoTime(string s, out DateTimeOffset time)
    {
        if (s.Length == 15 && s[8] == 'T'
            && DateTime.TryParseExact(s, "yyyyMMdd'T'HHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime dt))
        {
            time = new DateTimeOffset(dt, TimeSpan.Zero);
            return true;
        }

        time = default;
        return false;
    }
}

/// <summary>The passphrase did not open the key, or the encrypted part is damaged. The two cannot be told apart, by design.</summary>
public sealed class GnuPGWrongPassphraseException : CryptographicException
{
    /// <summary>Creates the exception.</summary>
    public GnuPGWrongPassphraseException()
        : base("The passphrase is wrong or the key file is damaged.")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public GnuPGWrongPassphraseException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and a cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The cause.</param>
    public GnuPGWrongPassphraseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
