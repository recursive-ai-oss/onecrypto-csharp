using System.Globalization;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp.Trust;

/// <summary>How valid a certificate or one of its User IDs is under the classic model, as GnuPG's colon listing reports it.</summary>
public enum ClassicValidity
{
    /// <summary>Nothing vouches for it (GnuPG prints <c>-</c>, or <c>o</c> before the trust database is checked).</summary>
    Unknown = 0,

    /// <summary>Certified, but only by keys that carry no usable trust (<c>q</c>).</summary>
    Undefined,

    /// <summary>Marginally valid (<c>m</c>): some trusted certification, fewer than the full-validity rule asks for.</summary>
    Marginal,

    /// <summary>Fully valid (<c>f</c>).</summary>
    Full,

    /// <summary>The key is ultimately trusted (<c>u</c>): the user's own.</summary>
    Ultimate,

    /// <summary>The key has expired (<c>e</c>), or for a User ID, expired.</summary>
    Expired,

    /// <summary>The key (or the User ID) is revoked (<c>r</c>).</summary>
    Revoked,
}

/// <summary>The settings of the classic model. The defaults are GnuPG's.</summary>
public sealed class ClassicTrustOptions
{
    /// <summary>How many marginally trusted certifications make a User ID fully valid. Default 3.</summary>
    public int MarginalsNeeded { get; init; } = 3;

    /// <summary>How many fully trusted certifications make a User ID fully valid. Default 1.</summary>
    public int CompletesNeeded { get; init; } = 1;

    /// <summary>The longest chain of certifications from an ultimately trusted key that still validates a key. Default 5, at most 255.</summary>
    public int MaxCertDepth { get; init; } = 5;

    /// <summary>
    /// Certifications of a lower certification level are ignored: persona certifications (0x11) are level 1, casual (0x12) level 2, positive (0x13)
    /// level 3, and a generic certification (0x10) is level 0 which is always accepted. Default 2, like GnuPG.
    /// </summary>
    public int MinCertLevel { get; init; } = 2;
}

/// <summary>What one certifier contributed to a User ID.</summary>
/// <param name="Certifier">The certifying certificate (fingerprint hex).</param>
/// <param name="Counted">How it counted: <see cref="ClassicValidity.Full"/>, <see cref="ClassicValidity.Marginal"/>, or <see cref="ClassicValidity.Unknown"/> for none.</param>
/// <param name="Source">Where its trust comes from: owner trust, a trust signature, or it is ultimately trusted.</param>
public sealed record ClassicContribution(string Certifier, ClassicValidity Counted, string Source);

/// <summary>The validity of one User ID.</summary>
public sealed class UserIdValidity
{
    internal UserIdValidity(string userId, ClassicValidity validity, IReadOnlyList<ClassicContribution> contributions, string reason)
    {
        UserId = userId;
        Validity = validity;
        Contributions = contributions;
        Reason = reason;
    }

    /// <summary>The User ID text.</summary>
    public string UserId { get; }

    /// <summary>Its validity.</summary>
    public ClassicValidity Validity { get; }

    /// <summary>The certifications that were taken into account, with what each counted as.</summary>
    public IReadOnlyList<ClassicContribution> Contributions { get; }

    /// <summary>Why it has this validity, in plain words.</summary>
    public string Reason { get; }
}

/// <summary>The validity of one certificate and its User IDs.</summary>
public sealed class CertificateValidity
{
    internal CertificateValidity(string id, ClassicValidity validity, IReadOnlyList<UserIdValidity> userIds, int depth)
    {
        Id = id;
        Validity = validity;
        UserIds = userIds;
        Depth = depth;
    }

    /// <summary>The certificate (fingerprint hex).</summary>
    public string Id { get; }

    /// <summary>The key's validity: <see cref="ClassicValidity.Revoked"/> or <see cref="ClassicValidity.Expired"/> for such a key, otherwise the best of its User IDs.</summary>
    public ClassicValidity Validity { get; }

    /// <summary>The User IDs that have a valid self-certification at the reference time.</summary>
    public IReadOnlyList<UserIdValidity> UserIds { get; }

    /// <summary>How many certifications away from an ultimately trusted key it became valid (0 for an ultimately trusted key), or -1 if it never did.</summary>
    public int Depth { get; }
}

/// <summary>The result of the classic model for every certificate of a network.</summary>
public sealed class ClassicTrustReport
{
    internal ClassicTrustReport(DateTimeOffset at, ClassicTrustOptions options, IReadOnlyDictionary<string, CertificateValidity> certificates)
    {
        At = at;
        Options = options;
        Certificates = certificates;
    }

    /// <summary>The reference time.</summary>
    public DateTimeOffset At { get; }

    /// <summary>The settings used.</summary>
    public ClassicTrustOptions Options { get; }

    /// <summary>The result per certificate, by fingerprint hex.</summary>
    public IReadOnlyDictionary<string, CertificateValidity> Certificates { get; }

    /// <summary>The validity of one User ID, or <see cref="ClassicValidity.Unknown"/> when the certificate or the User ID is not known.</summary>
    /// <param name="certificate">The certificate (fingerprint hex).</param>
    /// <param name="userId">The User ID text.</param>
    public ClassicValidity ValidityOf(string certificate, string userId)
    {
        if (Certificates.TryGetValue(certificate, out CertificateValidity? c))
        {
            foreach (UserIdValidity u in c.UserIds)
            {
                if (string.Equals(u.UserId, userId, StringComparison.Ordinal))
                {
                    return u.Validity;
                }
            }
        }

        return ClassicValidity.Unknown;
    }
}

/// <summary>
/// The classic web-of-trust model: owner trust (unknown, never, marginal, full, ultimate) combined with certifications. A User ID is fully valid
/// when it is certified by one fully trusted key or three marginally trusted keys (both configurable) that are themselves valid, reached from an
/// ultimately trusted key through no more than <see cref="ClassicTrustOptions.MaxCertDepth"/> certifications. Trust signatures (RFC 9580 §5.2.3.21)
/// lend trust to the certified key, limited by their level and amount, and their regular expressions (§5.2.3.22) scope that trust to User IDs.
/// Every rule is checked against GnuPG's colon listing (docs/openpgp-trust.md).
/// </summary>
public static class ClassicTrust
{
    private const int MaxGrantsPerKey = 256;
    private const int Unlimited = int.MaxValue;

    /// <summary>Turns owner-trust entries (from <see cref="TrustDb"/> or <see cref="OwnerTrustExport"/>) into the lookup the model takes.</summary>
    /// <param name="entries">The entries; later entries for the same key replace earlier ones. Fingerprints longer than 20 octets match v6 keys.</param>
    public static IReadOnlyDictionary<string, OwnerTrustLevel> OwnerTrustFrom(IEnumerable<OwnerTrustEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var map = new Dictionary<string, OwnerTrustLevel>(StringComparer.Ordinal);
        foreach (OwnerTrustEntry e in entries)
        {
            map[e.FingerprintHex] = e.Level;
        }

        return map;
    }

    private sealed record Grant(ClassicValidity Level, int Cap, string Source, List<string> Scopes)
    {
        internal string Key => string.Create(CultureInfo.InvariantCulture, $"{Level}/{Cap}/{string.Join('|', Scopes)}");
    }

    /// <summary>Evaluates validity for every certificate of the network.</summary>
    /// <param name="network">The network at the reference time.</param>
    /// <param name="ownerTrust">Owner trust by fingerprint hex; keys not listed have no owner trust.</param>
    /// <param name="options">Settings; null for GnuPG's defaults.</param>
    /// <param name="limits">Limits; null for the network's own.</param>
    /// <exception cref="TrustLimitExceededException">The computation took more steps than the limits allow.</exception>
    public static ClassicTrustReport Evaluate(TrustNetwork network, IReadOnlyDictionary<string, OwnerTrustLevel> ownerTrust, ClassicTrustOptions? options = null, TrustLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(ownerTrust);
        options ??= new ClassicTrustOptions();
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MarginalsNeeded, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.CompletesNeeded, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MaxCertDepth, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.MaxCertDepth, 255);
        limits ??= network.Limits;
        return new Run(network, ownerTrust, options, limits).Execute();
    }

    private sealed class Run
    {
        private readonly TrustNetwork _net;
        private readonly IReadOnlyDictionary<string, OwnerTrustLevel> _owner;
        private readonly ClassicTrustOptions _opt;
        private readonly TrustLimits _limits;
        private long _work;
        private readonly Dictionary<string, ClassicValidity> _keyState = new(StringComparer.Ordinal);   // Expired / Revoked / Unknown(usable)
        private readonly Dictionary<string, List<Grant>> _grants = new(StringComparer.Ordinal);
        private readonly Dictionary<string, HashSet<string>> _grantKeys = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _depthFound = new(StringComparer.Ordinal);
        private readonly HashSet<string> _inList = new(StringComparer.Ordinal);
        private readonly Dictionary<(string Target, string UserId), List<TrustCertification>> _certs = new();
        private readonly Dictionary<string, List<string>> _uids = new(StringComparer.Ordinal);
        private readonly Dictionary<(string, string), UserIdValidity> _result = new();

        internal Run(TrustNetwork net, IReadOnlyDictionary<string, OwnerTrustLevel> owner, ClassicTrustOptions opt, TrustLimits limits)
        {
            _net = net;
            _owner = owner;
            _opt = opt;
            _limits = limits;
        }

        private void Spend(long n)
        {
            _work += n;
            if (_work > _limits.MaxWork)
            {
                throw new TrustLimitExceededException(TrustLimit.Work, "The trust computation took more steps than the limit allows.");
            }
        }

        private OwnerTrustLevel OwnerOf(string id) => _owner.TryGetValue(id, out OwnerTrustLevel l) ? l : OwnerTrustLevel.Unknown;

        private static int CertLevel(byte type) => type switch
        {
            0x10 => 0,
            0x11 => 1,
            0x12 => 2,
            0x13 => 3,
            _ => 0,
        };

        internal ClassicTrustReport Execute()
        {
            // Key state at the reference time. A key that is revoked or expired is neither valid nor an introducer.
            foreach (TrustNode n in _net.Nodes)
            {
                _keyState[n.Id] = n.IsUsable ? ClassicValidity.Unknown : (n.UnusableReason ?? string.Empty).Contains("revoked", StringComparison.Ordinal) ? ClassicValidity.Revoked
                    : (n.UnusableReason ?? string.Empty).Contains("expired", StringComparison.Ordinal) ? ClassicValidity.Expired : ClassicValidity.Unknown;
            }

            // Group the counting certifications by the User ID they certify. A User ID counts when its own certificate certified it.
            var selfCertified = new HashSet<(string, string)>();
            foreach (TrustCertification c in _net.Certifications)
            {
                Spend(1);
                if (c.UserId is null)
                {
                    continue; // delegations do not decide validity in this model
                }

                if (c.IsSelf)
                {
                    selfCertified.Add((c.Target, c.UserId));
                    continue;
                }

                // A generic certification (level 0, "unknown") is always accepted; the others must reach the minimum level.
                if (CertLevel(c.SignatureType) is var level and > 0 && level < _opt.MinCertLevel)
                {
                    continue;
                }

                var key = (c.Target, c.UserId);
                if (!_certs.TryGetValue(key, out List<TrustCertification>? list))
                {
                    list = [];
                    _certs[key] = list;
                }

                list.Add(c);
            }

            foreach ((string target, string userId) in selfCertified)
            {
                if (!_uids.TryGetValue(target, out List<string>? l))
                {
                    l = [];
                    _uids[target] = l;
                }

                l.Add(userId);
            }

            // Stage 0: ultimately trusted keys are valid and trusted without any certification.
            foreach (TrustNode n in _net.Nodes)
            {
                if (OwnerOf(n.Id) == OwnerTrustLevel.Ultimate && n.IsUsable)
                {
                    _inList.Add(n.Id);
                    _depthFound[n.Id] = 0;
                    AddGrant(n.Id, new Grant(ClassicValidity.Full, Unlimited, "ultimate", []));
                    foreach (string u in _uids.GetValueOrDefault(n.Id) ?? [])
                    {
                        _result[(n.Id, u)] = new UserIdValidity(u, ClassicValidity.Ultimate, [], "The key is ultimately trusted.");
                    }
                }
            }

            // Each round validates the keys one certification further from the ultimately trusted ones (GnuPG's "maximum certification depth").
            for (int round = 1; round <= _opt.MaxCertDepth; round++)
            {
                bool changed = false;
                var snapshotList = new HashSet<string>(_inList, StringComparer.Ordinal);
                var newlyValid = new List<string>();
                foreach (((string target, string userId), List<TrustCertification> edges) in _certs)
                {
                    Spend(edges.Count + 1);
                    if (_keyState[target] != ClassicValidity.Unknown || _net.IsUserIdRevoked(target, userId) || !_uids.TryGetValue(target, out List<string>? mine) || !mine.Contains(userId))
                    {
                        continue;
                    }

                    if (_result.TryGetValue((target, userId), out UserIdValidity? done) && done.Validity == ClassicValidity.Ultimate)
                    {
                        continue;
                    }

                    UserIdValidity v = Count(target, userId, edges, snapshotList);
                    _result.TryGetValue((target, userId), out UserIdValidity? old);
                    if (old is null || v.Validity > old.Validity)
                    {
                        _result[(target, userId)] = v;
                        changed = true;
                        // Only a fully valid key can introduce others: a marginally valid one with full owner trust does not (GnuPG 2.4.4, 2.4.8, 2.5.24).
                        if (v.Validity == ClassicValidity.Full)
                        {
                            newlyValid.Add(target);
                        }
                    }
                }

                foreach (string t in newlyValid)
                {
                    if (_inList.Add(t))
                    {
                        _depthFound[t] = round;
                    }
                }

                // Trust the new keys lend on to others through their owner trust and the trust signatures made on them.
                foreach (string t in _inList)
                {
                    GrantOwnerTrust(t);
                }

                foreach (TrustCertification c in _net.Certifications)
                {
                    Spend(1);
                    if (c.UserId is not null && c.HasTrustSignature && c.Depth > 0 && !c.IsSelf && _inList.Contains(c.Issuer) && _keyState[c.Target] == ClassicValidity.Unknown)
                    {
                        changed |= GrantFromTrustSignature(c);
                    }
                }

                if (!changed && newlyValid.Count == 0)
                {
                    break;
                }
            }

            return Report();
        }

        private void GrantOwnerTrust(string id)
        {
            ClassicValidity level = OwnerOf(id) switch
            {
                OwnerTrustLevel.Full or OwnerTrustLevel.Ultimate => ClassicValidity.Full,
                OwnerTrustLevel.Marginal => ClassicValidity.Marginal,
                _ => ClassicValidity.Unknown,
            };
            if (level != ClassicValidity.Unknown)
            {
                AddGrant(id, new Grant(level, Unlimited, "owner trust", []));
            }
        }

        private bool AddGrant(string id, Grant g)
        {
            if (!_grants.TryGetValue(id, out List<Grant>? list))
            {
                list = [];
                _grants[id] = list;
                _grantKeys[id] = new HashSet<string>(StringComparer.Ordinal);
            }

            if (!_grantKeys[id].Add(g.Key))
            {
                return false;
            }

            if (list.Count >= MaxGrantsPerKey)
            {
                throw new TrustLimitExceededException(TrustLimit.Work, "A key received too many distinct trust signatures.");
            }

            list.Add(g);
            return true;
        }

        // A trust signature (level L, amount A) from a key we trust lends the certified key trust of the strength its amount gives, for chains
        // as long as L allows and no longer than the issuer's own allowance leaves (RFC 9580 §5.2.3.21).
        private bool GrantFromTrustSignature(TrustCertification c)
        {
            bool added = false;
            ClassicValidity byAmount = c.Amount >= 120 ? ClassicValidity.Full : c.Amount >= 60 ? ClassicValidity.Marginal : ClassicValidity.Unknown;
            if (!_grants.TryGetValue(c.Issuer, out List<Grant>? parents))
            {
                return false;
            }

            // GnuPG looks at the first Regular Expression subpacket only (checked with two and three expressions, 2.4.4, 2.4.8, 2.5.24).
            string? mine = c.Regexes.Count > 0 ? c.Regexes[0] : null;

            // A trust signature too weak to count (amount under 60) leaves the certified key's owner trust alone, unless it carries a regular
            // expression: then it still governs the key, which turns every User ID outside its scope into one the key says nothing about
            // (observed with GnuPG 2.4.8 and 2.5.24, scenario c95-random-16).
            if (byAmount == ClassicValidity.Unknown && mine is null)
            {
                return false;
            }

            // Only a trust signature, or ultimate trust, lets a key pass trust on through its own trust signatures. Owner trust alone makes a key an
            // introducer for plain certifications and nothing more (GnuPG 2.4.4, 2.4.8, 2.5.24).
            foreach (Grant p in parents.ToArray())
            {
                if (p.Source == "owner trust")
                {
                    continue;
                }

                int cap = p.Cap == Unlimited ? c.Depth : Math.Min((int)c.Depth, p.Cap - 1);
                if (cap < 1)
                {
                    continue;
                }

                var scopes = new List<string>(p.Scopes);
                if (mine is not null)
                {
                    scopes.Add(mine);
                }

                ClassicValidity level = byAmount < p.Level ? byAmount : p.Level;
                added |= AddGrant(c.Target, new Grant(level, cap, "trust signature", scopes));
            }

            return added;
        }

        private static bool Applies(Grant g, string userId)
        {
            foreach (string pattern in g.Scopes)
            {
                if (!GnuPGRegex.Matches(pattern, userId))
                {
                    return false;
                }
            }

            return true;
        }

        private UserIdValidity Count(string target, string userId, List<TrustCertification> edges, HashSet<string> list)
        {
            int full = 0;
            int marginal = 0;
            bool seen = false;
            bool ultimateSigned = false;
            var contributions = new List<ClassicContribution>();
            foreach (TrustCertification e in edges)
            {
                if (!list.Contains(e.Issuer) || _keyState[e.Issuer] != ClassicValidity.Unknown)
                {
                    continue;
                }

                List<Grant> grants = _grants.TryGetValue(e.Issuer, out List<Grant>? g) ? g : [];

                // A key that holds a trust signature is governed by it: its owner trust no longer applies where the trust signature's scope does
                // not reach (GnuPG 2.4.8, 2.5.24).
                if (grants.Any(x => x.Source == "trust signature"))
                {
                    grants = grants.Where(x => x.Source != "owner trust").ToList();
                }

                ClassicValidity best = ClassicValidity.Unknown;
                string source = "none";
                bool anyApplicable = grants.Count == 0;
                foreach (Grant gr in grants)
                {
                    if (!Applies(gr, userId))
                    {
                        continue;
                    }

                    anyApplicable = true;
                    if (gr.Level > best)
                    {
                        best = gr.Level;
                        source = gr.Source;
                    }
                }

                // A certifier whose only trust is scoped away from this User ID says nothing about it; one with no trust at all still counts as
                // having certified it, which is what makes the result "undefined" rather than "unknown".
                if (!anyApplicable)
                {
                    continue;
                }

                seen = true;
                contributions.Add(new ClassicContribution(e.Issuer, best, source));
                if (source == "ultimate")
                {
                    // A certification by an ultimately trusted key makes the User ID fully valid by itself, whatever the counts asked for.
                    ultimateSigned = true;
                }

                if (best == ClassicValidity.Full)
                {
                    full++;
                }
                else if (best == ClassicValidity.Marginal)
                {
                    marginal++;
                }
            }

            ClassicValidity v;
            string reason;
            if (ultimateSigned || full >= _opt.CompletesNeeded || marginal >= _opt.MarginalsNeeded)
            {
                v = ClassicValidity.Full;
                reason = string.Create(CultureInfo.InvariantCulture, $"{full} fully and {marginal} marginally trusted certification(s) meet the rule of {_opt.CompletesNeeded} full or {_opt.MarginalsNeeded} marginal.");
            }
            else if (full + marginal >= 1)
            {
                v = ClassicValidity.Marginal;
                reason = string.Create(CultureInfo.InvariantCulture, $"{full} fully and {marginal} marginally trusted certification(s) are fewer than the {_opt.CompletesNeeded} full or {_opt.MarginalsNeeded} marginal needed.");
            }
            else if (seen)
            {
                v = ClassicValidity.Undefined;
                reason = "It is certified, but no certifier has owner trust or a trust signature that counts.";
            }
            else
            {
                v = ClassicValidity.Unknown;
                reason = "No certification by a valid, trusted key was found.";
            }

            return new UserIdValidity(userId, v, contributions, reason);
        }

        private ClassicTrustReport Report()
        {
            var certs = new Dictionary<string, CertificateValidity>(StringComparer.Ordinal);
            foreach (TrustNode n in _net.Nodes)
            {
                var uids = new List<UserIdValidity>();
                ClassicValidity best = ClassicValidity.Unknown;
                foreach (string u in _uids.GetValueOrDefault(n.Id) ?? [])
                {
                    UserIdValidity v;
                    if (_net.IsUserIdRevoked(n.Id, u))
                    {
                        v = new UserIdValidity(u, ClassicValidity.Revoked, [], "The User ID is revoked.");
                    }
                    else if (_result.TryGetValue((n.Id, u), out UserIdValidity? r))
                    {
                        v = r;
                    }
                    else
                    {
                        v = new UserIdValidity(u, ClassicValidity.Unknown, [], "No certification by a valid, trusted key was found.");
                    }

                    if (_keyState[n.Id] == ClassicValidity.Revoked)
                    {
                        v = new UserIdValidity(u, ClassicValidity.Revoked, [], "The key is revoked.");
                    }
                    else if (_keyState[n.Id] == ClassicValidity.Expired)
                    {
                        v = new UserIdValidity(u, ClassicValidity.Expired, [], "The key has expired.");
                    }

                    uids.Add(v);
                    if (v.Validity is not (ClassicValidity.Revoked or ClassicValidity.Expired) && v.Validity > best)
                    {
                        best = v.Validity;
                    }
                }

                ClassicValidity keyValidity = _keyState[n.Id] is ClassicValidity.Revoked or ClassicValidity.Expired ? _keyState[n.Id] : best;
                certs[n.Id] = new CertificateValidity(n.Id, keyValidity, uids, _depthFound.TryGetValue(n.Id, out int d) ? d : -1);
            }

            return new ClassicTrustReport(_net.At, _opt, certs);
        }
    }
}

/// <summary>
/// How GnuPG reads the expression of a trust signature, found by trying forty expressions against three GnuPG versions: the form it writes for
/// "this domain" (<c>&lt;[^&gt;]+[@.]example\.org&gt;$</c>) is matched as an expression, and any other expression is plain text that must occur in the
/// User ID, where a dot stands for any character and a backslash makes the next punctuation character literal; an expression with any other
/// special character matches nothing.
/// </summary>
internal static class GnuPGRegex
{
    private const string DomainPrefix = "<[^>]+[@.]";
    private const string DomainSuffix = ">$";

    internal static bool Matches(string pattern, string userId)
    {
        if (pattern.StartsWith(DomainPrefix, StringComparison.Ordinal) && pattern.EndsWith(DomainSuffix, StringComparison.Ordinal))
        {
            return TrustRegex.TryCompile(pattern, out TrustRegex? rx) && rx!.IsMatch(userId);
        }

        // Plain text with "." standing for any one character; "\" makes the next punctuation character literal. A backslash before a letter or
        // digit, and every other special character, makes the expression match nothing.
        var tokens = new List<char?>(pattern.Length);
        for (int i = 0; i < pattern.Length; i++)
        {
            char ch = pattern[i];
            if (ch == '\\')
            {
                if (++i >= pattern.Length || char.IsAsciiLetterOrDigit(pattern[i]))
                {
                    return false;
                }

                tokens.Add(pattern[i]);
            }
            else if ("[]()|*+?{}^$".Contains(ch, StringComparison.Ordinal))
            {
                return false;
            }
            else
            {
                tokens.Add(ch == '.' ? null : ch);
            }
        }

        for (int start = 0; start + tokens.Count <= userId.Length; start++)
        {
            int k = 0;
            while (k < tokens.Count && (tokens[k] is not char t || t == userId[start + k]))
            {
                k++;
            }

            if (k == tokens.Count)
            {
                return true;
            }
        }

        return false;
    }
}
