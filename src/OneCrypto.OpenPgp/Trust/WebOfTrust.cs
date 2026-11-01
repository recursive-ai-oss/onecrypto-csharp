using System.Globalization;

namespace RecursiveAI.OneCrypto.OpenPgp.Trust;

/// <summary>How far a binding is authenticated.</summary>
public enum AuthenticationLevel
{
    /// <summary>No path from a trust root authenticates the binding.</summary>
    NotAuthenticated,

    /// <summary>Paths exist but their trust amount is below the amount asked for.</summary>
    Partial,

    /// <summary>The paths reach the amount asked for (120 by default: full authentication).</summary>
    Authenticated,
}

/// <summary>One path from a trust root to a binding, with the trust amount it carries.</summary>
public sealed class TrustPath
{
    internal TrustPath(IReadOnlyList<TrustCertification> edges, int amount)
    {
        Certifications = edges;
        Amount = amount;
    }

    /// <summary>The certifications from the trust root to the certificate, in order; the last one certifies the User ID.</summary>
    public IReadOnlyList<TrustCertification> Certifications { get; }

    /// <summary>The trust amount this path adds: the smallest remaining capacity along it when it was found.</summary>
    public int Amount { get; }
}

/// <summary>The result of authenticating one binding (a certificate and a User ID) by the flow-based web of trust.</summary>
public sealed class FlowAuthentication
{
    internal FlowAuthentication(string target, string userId, int required, int amount, IReadOnlyList<TrustPath> paths, IReadOnlyList<string> reasons)
    {
        Target = target;
        UserId = userId;
        Required = required;
        Amount = amount;
        Paths = paths;
        Reasons = reasons;
        Level = amount <= 0 ? AuthenticationLevel.NotAuthenticated : amount >= required ? AuthenticationLevel.Authenticated : AuthenticationLevel.Partial;
    }

    /// <summary>The certificate, as fingerprint hex.</summary>
    public string Target { get; }

    /// <summary>The User ID text asked about.</summary>
    public string UserId { get; }

    /// <summary>The trust amount that counts as authenticated.</summary>
    public int Required { get; }

    /// <summary>The total trust amount found: the maximum flow, stopped once <see cref="Required"/> is reached.</summary>
    public int Amount { get; }

    /// <summary>The verdict.</summary>
    public AuthenticationLevel Level { get; }

    /// <summary>True when <see cref="Level"/> is <see cref="AuthenticationLevel.Authenticated"/>.</summary>
    public bool IsAuthenticated => Level == AuthenticationLevel.Authenticated;

    /// <summary>The paths that make up <see cref="Amount"/>, best first.</summary>
    public IReadOnlyList<TrustPath> Paths { get; }

    /// <summary>Why the binding is not fully authenticated (empty when it is), in plain words with the specification section.</summary>
    public IReadOnlyList<string> Reasons { get; }
}

/// <summary>
/// The flow-based web of trust: authentication of a binding as a maximum flow from the caller's trust roots through certifications, where an
/// edge's capacity is its trust amount, trust depth limits how far introducers extend, and regular expressions scope them to User IDs
/// (draft-nhw-web-of-trust, §3 and §4; RFC 9580 §5.2.3.21 and §5.2.3.22). The result depends only on the network, the roots and the question.
/// </summary>
public static class WebOfTrust
{
    /// <summary>The trust amount that means fully authenticated.</summary>
    public const int FullAmount = 120;

    private const int Infinite = int.MaxValue;

    /// <summary>Authenticates a User ID of a certificate.</summary>
    /// <param name="network">The network at the reference time.</param>
    /// <param name="roots">The trust roots, as fingerprint hex. Each is trusted as an introducer with unlimited depth and amount 120; roots not in the network are ignored.</param>
    /// <param name="target">The certificate asked about, as fingerprint hex.</param>
    /// <param name="userId">The User ID text, compared exactly with the certified one.</param>
    /// <param name="requiredAmount">The amount that counts as authenticated, 1 to 1,000,000; default <see cref="FullAmount"/>.</param>
    /// <param name="limits">Limits; null for the network's own.</param>
    /// <param name="stopAtRequired">False (the default) finds the maximum flow, as Sequoia does, so <see cref="FlowAuthentication.Amount"/> is the total trust amount of all paths.
    /// True stops as soon as <paramref name="requiredAmount"/> is reached, which is cheaper on large networks when only the verdict matters.</param>
    /// <exception cref="TrustLimitExceededException">The search took more steps than the limits allow, or there are too many roots.</exception>
    public static FlowAuthentication Authenticate(TrustNetwork network, IEnumerable<string> roots, string target, string userId, int requiredAmount = FullAmount, TrustLimits? limits = null, bool stopAtRequired = false)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(roots);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentOutOfRangeException.ThrowIfLessThan(requiredAmount, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(requiredAmount, 1_000_000);
        limits ??= network.Limits;
        return new Search(network, limits, target, userId, requiredAmount, roots).Run(stopAtRequired);
    }

    /// <summary>Authenticates a User ID of a certificate, naming certificates by object.</summary>
    /// <param name="network">The network at the reference time.</param>
    /// <param name="roots">The trust root certificates.</param>
    /// <param name="target">The certificate asked about.</param>
    /// <param name="userId">The User ID text.</param>
    /// <param name="requiredAmount">The amount that counts as authenticated; default <see cref="FullAmount"/>.</param>
    /// <param name="limits">Limits; null for the network's own.</param>
    /// <param name="stopAtRequired">As for the other overload.</param>
    /// <exception cref="TrustLimitExceededException">A limit was reached.</exception>
    public static FlowAuthentication Authenticate(TrustNetwork network, IEnumerable<PgpCertificate> roots, PgpCertificate target, string userId, int requiredAmount = FullAmount, TrustLimits? limits = null, bool stopAtRequired = false)
    {
        ArgumentNullException.ThrowIfNull(roots);
        ArgumentNullException.ThrowIfNull(target);
        return Authenticate(network, roots.Select(r => Convert.ToHexString(r.Fingerprint)).ToList(), Convert.ToHexString(target.Fingerprint), userId, requiredAmount, limits, stopAtRequired);
    }

    private sealed class Search
    {
        private readonly TrustNetwork _net;
        private readonly TrustLimits _limits;
        private readonly string _target;
        private readonly string _userId;
        private readonly int _required;
        private readonly Dictionary<string, int> _index = new(StringComparer.Ordinal);
        private readonly bool[] _isRoot;
        private readonly int _n;
        private readonly int _sink;
        private readonly List<int>[] _incoming;       // per node: edge indexes whose normal copy ends there
        private readonly List<int> _terminal = [];    // edges that certify the target User ID: their terminal copy ends at the sink
        private readonly int[] _cap;
        private readonly int[] _depth;
        private readonly int[] _src;
        private readonly int[] _dst;
        private long _work;
        private int _skippedRegex;
        private int _skippedZero;

        internal Search(TrustNetwork net, TrustLimits limits, string target, string userId, int required, IEnumerable<string> roots)
        {
            _net = net;
            _limits = limits;
            _target = target;
            _userId = userId;
            _required = required;
            foreach (TrustNode node in net.Nodes)
            {
                _index[node.Id] = _index.Count;
            }

            _n = _index.Count;
            _sink = _n;
            _isRoot = new bool[_n + 1];
            int rootCount = 0;
            foreach (string r in roots)
            {
                if (++rootCount > limits.MaxRoots)
                {
                    throw new TrustLimitExceededException(TrustLimit.Roots, "Too many trust roots.");
                }

                if (_index.TryGetValue(r, out int ri))
                {
                    _isRoot[ri] = true;
                }
            }

            int e = net.Certifications.Count;
            _incoming = new List<int>[_n + 1];
            _cap = new int[e];
            _depth = new int[e];
            _src = new int[e];
            _dst = new int[e];
            var cache = new Dictionary<string, TrustRegex?>(StringComparer.Ordinal);
            var strongest = new Dictionary<long, int>();
            for (int i = 0; i < e; i++)
            {
                TrustCertification c = net.Certifications[i];
                _src[i] = _index[c.Issuer];
                _dst[i] = _index[c.Target];
                _cap[i] = Math.Min((int)c.Amount, FullAmount);
                // Web-of-trust draft §4.1: a self-certification always has depth 0; 255 means no limit.
                _depth[i] = c.IsSelf ? 0 : c.Depth == 255 ? Infinite : c.Depth;
                if (_cap[i] == 0)
                {
                    // A certification with amount 0 overrides earlier ones and carries nothing (draft §3.2).
                    _skippedZero++;
                    continue;
                }

                // A regular expression scopes what the certified certificate may introduce, so it limits the edges that lead on to the target
                // but not the last one, which certifies the User ID itself. The draft's text applies it to every edge; Sequoia 1.5.0 does not
                // apply it to the last one (docs/openpgp-trust.md, deviation W1).
                bool inScope = InScope(c, cache);
                if (!c.IsSelf && inScope)
                {
                    // Certifications of different User IDs of one certificate by one issuer are one edge when passing through: Sequoia 1.5.0
                    // does not add their capacities (docs/openpgp-trust.md, deviation W2). The strongest one stands for them.
                    long pair = ((long)_src[i] * (_n + 1)) + _dst[i];
                    if (!strongest.TryGetValue(pair, out int other) || _cap[i] > _cap[other] || (_cap[i] == _cap[other] && _depth[i] > _depth[other]))
                    {
                        strongest[pair] = i;
                    }
                }

                if (!inScope)
                {
                    _skippedRegex++;
                }

                if (c.UserId is not null && string.Equals(c.UserId, userId, StringComparison.Ordinal) && string.Equals(c.Target, target, StringComparison.Ordinal))
                {
                    _terminal.Add(i);
                }
            }

            foreach (int i in strongest.Values.OrderBy(x => x))
            {
                (_incoming[_dst[i]] ??= []).Add(i);
            }
        }

        // Draft §3.4: when an edge has regular expressions, at least one must match the User ID being authenticated.
        private bool InScope(TrustCertification c, Dictionary<string, TrustRegex?> cache)
        {
            if (c.Regexes.Count == 0)
            {
                return true;
            }

            foreach (string pattern in c.Regexes)
            {
                if (!cache.TryGetValue(pattern, out TrustRegex? rx))
                {
                    if (pattern.Length > _limits.MaxRegexLength)
                    {
                        throw new TrustLimitExceededException(TrustLimit.Regex, "A regular expression is too long.");
                    }

                    rx = TrustRegex.TryCompile(pattern, out TrustRegex? compiled, _limits) ? compiled : null;
                    cache[pattern] = rx;
                }

                // A pattern that cannot be compiled matches nothing: the scope stays narrow.
                if (rx is not null && rx.IsMatch(_userId))
                {
                    return true;
                }
            }

            return false;
        }

        private void Spend(long steps)
        {
            _work += steps;
            if (_work > _limits.MaxWork)
            {
                throw new TrustLimitExceededException(TrustLimit.Work, "The path search took more steps than the limit allows.");
            }
        }

        internal FlowAuthentication Run(bool stopAtRequired)
        {
            var reasons = new List<string>();
            var paths = new List<TrustPath>();
            int total = 0;
            if (!_index.ContainsKey(_target))
            {
                reasons.Add("The certificate is not among the supplied certificates.");
                return new FlowAuthentication(_target, _userId, _required, 0, paths, reasons);
            }

            if (_net.IsUserIdRevoked(_target, _userId))
            {
                reasons.Add("The User ID is revoked at the reference time (draft §4.2).");
                return new FlowAuthentication(_target, _userId, _required, 0, paths, reasons);
            }

            if (_terminal.Count == 0)
            {
                reasons.Add(_net.UserIds(_target).Contains(_userId)
                    ? "No certification of this User ID is in scope for it (trust amount 0 or no matching regular expression)."
                    : "No valid certification of this User ID is among the supplied certificates.");
                AddRejections(reasons);
                return new FlowAuthentication(_target, _userId, _required, 0, paths, reasons);
            }

            if (!_isRoot.AsSpan(0, _n).Contains(true))
            {
                reasons.Add("None of the trust roots is among the supplied certificates.");
                return new FlowAuthentication(_target, _userId, _required, 0, paths, reasons);
            }

            while (!stopAtRequired || total < _required)
            {
                TrustPath? p = FindPath();
                if (p is null)
                {
                    break;
                }

                paths.Add(p);
                total += p.Amount;
            }

            if (total < _required)
            {
                if (total == 0)
                {
                    reasons.Add("No path from a trust root reaches the User ID: certifiers are not introducers deep enough, are out of regular-expression scope, or are not reachable from a root (draft §3.3, §3.4).");
                }
                else
                {
                    reasons.Add(string.Create(CultureInfo.InvariantCulture, $"The paths add up to {total}, below the required {_required} (draft §4.3)."));
                }

                AddRejections(reasons);
            }

            return new FlowAuthentication(_target, _userId, _required, total, paths, reasons);
        }

        private void AddRejections(List<string> reasons)
        {
            if (_skippedRegex > 0)
            {
                reasons.Add(string.Create(CultureInfo.InvariantCulture, $"{_skippedRegex} certification(s) were not followed past because none of their regular expressions matches the User ID (RFC 9580 §5.2.3.22)."));
            }

            int shown = 0;
            foreach (TrustRejection r in _net.Rejections)
            {
                if (string.Equals(r.Target, _target, StringComparison.Ordinal) && (r.UserId is null || string.Equals(r.UserId, _userId, StringComparison.Ordinal)) && shown < 10)
                {
                    reasons.Add((r.Issuer is null ? "A signature" : "A signature by " + r.Issuer) + " does not count: " + r.Reason);
                    shown++;
                }
            }
        }

        // Draft §5: Dijkstra's algorithm run backwards from the target. Preferring the shortest suffix always leaves a node the least constrained,
        // so a valid path is found whenever one exists; ties go to the larger amount. Roots are never expanded: a path does not pass through a root.
        private TrustPath? FindPath()
        {
            int size = _n + 1;
            int[] len = new int[size];
            int[] amount = new int[size];
            int[] next = new int[size];       // the edge that leaves this node towards the sink
            bool[] viaTerminal = new bool[size]; // whether that edge is used as its terminal copy (it ends at the sink)
            bool[] visited = new bool[size];
            Array.Fill(len, -1);
            Array.Fill(next, -1);
            var queue = new PriorityQueue<int, (int Len, int NegAmount, int Seq)>();
            int seq = 0;
            len[_sink] = 0;
            amount[_sink] = Infinite;
            queue.Enqueue(_sink, (0, 0, seq++));
            while (queue.TryDequeue(out int y, out _))
            {
                if (visited[y])
                {
                    continue;
                }

                visited[y] = true;
                if (y != _sink && _isRoot[y])
                {
                    continue;
                }

                List<int> edges;
                if (y == _sink)
                {
                    edges = _terminal;
                }
                else
                {
                    edges = _incoming[y] ?? [];
                }

                Spend(edges.Count + 1);
                foreach (int e in edges)
                {
                    if (_cap[e] <= 0)
                    {
                        continue;
                    }

                    // Draft §3.3: an edge that is followed by s more edges must designate an introducer of depth at least s.
                    if (_depth[e] < len[y])
                    {
                        continue;
                    }

                    int x = _src[e];
                    if (visited[x])
                    {
                        continue;
                    }

                    int cl = len[y] + 1;
                    int ca = Math.Min(amount[y], _cap[e]);
                    if (len[x] < 0 || cl < len[x] || (cl == len[x] && ca > amount[x]))
                    {
                        len[x] = cl;
                        amount[x] = ca;
                        next[x] = e;
                        viaTerminal[x] = y == _sink;
                        queue.Enqueue(x, (cl, -Math.Min(ca, Infinite - 1), seq++));
                    }
                }
            }

            int best = -1;
            for (int r = 0; r < _n; r++)
            {
                if (!_isRoot[r] || len[r] < 0)
                {
                    continue;
                }

                if (best < 0 || len[r] < len[best] || (len[r] == len[best] && amount[r] > amount[best]))
                {
                    best = r;
                }
            }

            Spend(_n);
            if (best < 0)
            {
                return null;
            }

            int flow = amount[best];
            var edgesOnPath = new List<TrustCertification>();
            int at = best;
            while (at != _sink)
            {
                int e = next[at];
                edgesOnPath.Add(_net.Certifications[e]);
                _cap[e] -= flow;
                // Reaching a node through its normal copy continues from that node; the terminal copy ends at the sink.
                at = viaTerminal[at] ? _sink : _dst[e];
            }

            return new TrustPath(edgesOnPath, flow);
        }
    }
}
