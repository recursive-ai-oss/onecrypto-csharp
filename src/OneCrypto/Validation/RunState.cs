using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

/// <summary>
/// What every engine of one validation shares: the work budget, the certificate pool with its indexes, the parsed views and the verified signatures.
/// A CRL signer is validated by a nested engine; sharing this state makes the limits cover the whole validation, not each nested engine separately,
/// and means the pool is indexed once.
/// </summary>
internal sealed class RunState
{
    private sealed class RefComparer : IEqualityComparer<(object A, object B)>
    {
        public bool Equals((object A, object B) x, (object A, object B) y) => ReferenceEquals(x.A, y.A) && ReferenceEquals(x.B, y.B);

        public int GetHashCode((object A, object B) k) => HashCode.Combine(RuntimeHelpers.GetHashCode(k.A), RuntimeHelpers.GetHashCode(k.B));
    }

    private readonly HashSet<Certificate> _poolSet = [];
    private readonly Dictionary<string, List<Certificate>> _bySubject = new(StringComparer.Ordinal);
    private Dictionary<string, List<Certificate>>? _byKeyHash;

    /// <summary>Search steps taken by all engines.</summary>
    public int Steps;

    /// <summary>Signature verifications done by all engines.</summary>
    public int SigChecks;

    /// <summary>Paths fully validated by all engines.</summary>
    public int Validated;

    /// <summary>CRL-signer validations started (not answered from the cache) by all engines.</summary>
    public int SignerValidations;

    public Dictionary<Certificate, CertView> Views { get; } = new(ReferenceEqualityComparer.Instance);

    public Dictionary<(object, object), SignatureVerification> SigCache { get; } = new(new RefComparer());

    /// <summary>
    /// The verdict on a CRL signer certificate, by signer, anchor and nesting depth (the depth decides how much revocation checking the nested
    /// validation does). Null: acceptable.
    /// </summary>
    public Dictionary<(Certificate, TrustAnchor, int), string?> SignerCache { get; } = new();

    /// <summary>The pool without duplicates, in the order supplied.</summary>
    public List<Certificate> Pool { get; } = [];

    public void AddToPool(Certificate? c)
    {
        if (c is null || !_poolSet.Add(c))
        {
            return;
        }

        Pool.Add(c);
        string key = NameKey(c.Subject);
        if (!_bySubject.TryGetValue(key, out List<Certificate>? list))
        {
            _bySubject[key] = list = [];
        }

        list.Add(c);
        _byKeyHash = null;
    }

    /// <summary>Pool certificates whose subject is the same name as <paramref name="name"/> under RFC 5280 §7.1, in pool order.</summary>
    public IReadOnlyList<Certificate> PoolBySubject(DistinguishedName name) =>
        _bySubject.TryGetValue(NameKey(name), out List<Certificate>? list) ? list : [];

    /// <summary>Pool certificates whose key bits have this SHA-1 (an OCSP responder's <c>byKey</c>, RFC 6960 §4.2.2.3), in pool order.</summary>
    public IReadOnlyList<Certificate> PoolByKeyHash(ReadOnlySpan<byte> sha1)
    {
        if (_byKeyHash is null)
        {
            _byKeyHash = new(StringComparer.Ordinal);
            foreach (Certificate c in Pool)
            {
                string h = Convert.ToHexString(CryptographicOperations.HashData(HashAlgorithmName.SHA1, c.PublicKey.KeyBits.Span));
                if (!_byKeyHash.TryGetValue(h, out List<Certificate>? l))
                {
                    _byKeyHash[h] = l = [];
                }

                l.Add(c);
            }
        }

        return _byKeyHash.TryGetValue(Convert.ToHexString(sha1), out List<Certificate>? list) ? list : [];
    }

    // Names that DistinguishedName.Matches calls equal have the same key: relative names in order, attributes within one relative name unordered, text
    // values compared after the same case folding and white-space collapsing. A name that cannot be decoded matches only identical bytes, so it keys on them.
    // Keep this in step with the folding in DistinguishedName.Matches. Different keys never match; the same key is only a candidate, and callers still verify.
    internal static string NameKey(DistinguishedName name)
    {
        IReadOnlyList<RelativeDistinguishedName> rdns;
        try
        {
            rdns = name.Rdns;
        }
        catch (X509ParseException)
        {
            return "#" + Convert.ToHexString(name.Encoded.Span);
        }

        var sb = new StringBuilder();
        foreach (RelativeDistinguishedName rdn in rdns)
        {
            var parts = new List<string>(rdn.Attributes.Count);
            foreach (AttributeTypeAndValue a in rdn.Attributes)
            {
                string? text = a.Text;
                parts.Add(a.Type + "=" + (text is null ? "#" + Convert.ToHexString(a.Value.Span) : Fold(text)));
            }

            parts.Sort(StringComparer.Ordinal);
            sb.Append(string.Join('+', parts.Select(Escape))).Append('\n');
        }

        return sb.ToString();
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("+", "\\+", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);

    private static string Fold(string s)
    {
        var sb = new StringBuilder(s.Length);
        bool space = true;
        foreach (char c in s)
        {
            if (c == ' ' || c == '\t')
            {
                if (!space)
                {
                    sb.Append(' ');
                }

                space = true;
            }
            else
            {
                sb.Append(char.ToUpperInvariant(c));
                space = false;
            }
        }

        return sb.ToString().TrimEnd(' ');
    }
}
