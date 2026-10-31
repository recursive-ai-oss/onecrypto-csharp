using System.Linq;
using System.Collections.Immutable;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

/// <summary>
/// The valid_policy_tree of RFC 5280 §6.1.2 (a), kept level by level. The node count is bounded:
/// a chain of certificates that each carry many policies and mappings makes the tree grow exponentially
/// (the published policy-tree denial-of-service), so growth past the limit stops the computation.
/// </summary>
internal sealed class PolicyTree
{
    internal sealed class Node
    {
        public Node(string policy, Node? parent, HashSet<string> expected)
        {
            Policy = policy;
            Parent = parent;
            Expected = expected;
        }

        public string Policy;
        public Node? Parent;
        public HashSet<string> Expected;
        public int Children;
    }

    private readonly int _limit;
    private int _count;

    // levels[d] holds the nodes of depth d. Depth 0 is the root.
    private List<List<Node>>? _levels;

    public PolicyTree(int limit)
    {
        _limit = limit;
        _count = 1;
        var root = new Node(KnownOids.AnyPolicy, null, [KnownOids.AnyPolicy]);
        _levels = [[root]];
    }

    public bool IsNull => _levels is null;

    public bool Overflowed { get; private set; }

    public void SetNull() => _levels = null;

    private Node Add(int depth, string policy, Node parent, HashSet<string> expected)
    {
        if (++_count > _limit)
        {
            Overflowed = true;
        }

        while (_levels!.Count <= depth)
        {
            _levels.Add([]);
        }

        var n = new Node(policy, parent, expected);
        parent.Children++;
        _levels[depth].Add(n);
        return n;
    }

    /// <summary>§6.1.3 (d) and (e): process the certificate policies of the certificate at 1-based position <paramref name="i"/>.</summary>
    public void ProcessCertificatePolicies(int i, CertificatePolicies? policies, bool anyPolicyAllowedByInhibit)
    {
        if (IsNull)
        {
            return;
        }

        if (policies is null)
        {
            SetNull(); // (e)
            return;
        }

        while (_levels!.Count <= i)
        {
            _levels.Add([]);
        }

        List<Node> parents = _levels[i - 1];
        bool hasAny = false;
        bool anyAllowed = anyPolicyAllowedByInhibit;
        foreach (PolicyInformation p in policies.Policies)
        {
            if (p.PolicyId == KnownOids.AnyPolicy)
            {
                hasAny = true;
                continue;
            }

            bool matched = false;
            foreach (Node parent in parents)
            {
                if (parent.Expected.Contains(p.PolicyId))
                {
                    Add(i, p.PolicyId, parent, [p.PolicyId]);
                    matched = true;
                    if (Overflowed)
                    {
                        return;
                    }
                }
            }

            if (!matched)
            {
                // (d)(1)(ii): no node expected this policy; an anyPolicy node above may stand in for it.
                Node? anyNode = parents.Find(n => n.Policy == KnownOids.AnyPolicy);
                if (anyNode is not null)
                {
                    Add(i, p.PolicyId, anyNode, [p.PolicyId]);
                    if (Overflowed)
                    {
                        return;
                    }
                }
            }
        }

        if (hasAny && anyAllowed)
        {
            // (d)(2): anyPolicy in the certificate stands for every policy the previous level expected and this level lacks.
            foreach (Node parent in parents)
            {
                foreach (string member in parent.Expected.Order(StringComparer.Ordinal))
                {
                    if (!HasChildWithPolicy(i, parent, member))
                    {
                        Add(i, member, parent, [member]);
                        if (Overflowed)
                        {
                            return;
                        }
                    }
                }
            }
        }

        Prune(i);
    }

    private bool HasChildWithPolicy(int depth, Node parent, string policy)
    {
        foreach (Node n in _levels![depth])
        {
            if (n.Parent == parent && n.Policy == policy)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>(d)(3): delete the nodes at depth &lt; <paramref name="from"/> (and the level itself) that have no children, from the deepest level up.</summary>
    private void Prune(int from)
    {
        for (int d = from - 1; d >= 0; d--)
        {
            List<Node> level = _levels![d];
            int removed = level.RemoveAll(n => n.Children == 0);
            _count -= removed;
            if (removed > 0 && d > 0)
            {
                // children counts of the parents need recomputing
                RecountChildren(d - 1);
            }
        }

        if (_levels![0].Count == 0)
        {
            SetNull();
        }
    }

    private void RecountChildren(int depth)
    {
        foreach (Node n in _levels![depth])
        {
            n.Children = 0;
        }

        foreach (Node c in _levels[depth + 1])
        {
            if (c.Parent is not null)
            {
                c.Parent.Children++;
            }
        }
    }

    /// <summary>§6.1.4 (a) and (b): apply policyMappings of the certificate at depth <paramref name="i"/> (the nodes at depth i).</summary>
    public void ApplyMappings(int i, PolicyMappings mappings, bool mappingAllowed)
    {
        if (IsNull)
        {
            return;
        }

        List<Node> level = _levels!.Count > i ? _levels[i] : [];
        var byIssuer = mappings.Mappings.GroupBy(m => m.IssuerDomainPolicy, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal);
        foreach (IGrouping<string, PolicyMapping> g in byIssuer)
        {
            string idp = g.Key;
            if (mappingAllowed)
            {
                var expected = new HashSet<string>(g.Select(m => m.SubjectDomainPolicy), StringComparer.Ordinal);
                bool found = false;
                foreach (Node n in level)
                {
                    if (n.Policy == idp)
                    {
                        n.Expected = new HashSet<string>(expected, StringComparer.Ordinal);
                        found = true;
                    }
                }

                if (!found)
                {
                    Node? any = level.Find(n => n.Policy == KnownOids.AnyPolicy);
                    if (any is not null && any.Parent is not null)
                    {
                        Add(i, idp, any.Parent, new HashSet<string>(expected, StringComparer.Ordinal));
                        if (Overflowed)
                        {
                            return;
                        }
                    }
                }
            }
            else
            {
                // (a)(2): mapping is inhibited, so nodes with the issuer domain policy go away.
                int removed = level.RemoveAll(n => n.Policy == idp);
                _count -= removed;
            }
        }

        if (!mappingAllowed)
        {
            RecountChildren(i - 1);
            Prune(i);
        }
    }

    /// <summary>§6.1.5 (g): intersect the tree with the user-initial-policy-set at the end of the path of <paramref name="n"/> certificates.</summary>
    public ImmutableArray<string> Finish(int n, IReadOnlyList<string> userSet)
    {
        if (IsNull)
        {
            return [];
        }

        bool userAny = userSet.Count == 0 || userSet.Contains(KnownOids.AnyPolicy);
        if (!userAny)
        {
            // (g)(iii)(2): nodes whose parent is anyPolicy stand for policies the user must have listed.
            for (int d = 1; d < _levels!.Count; d++)
            {
                foreach (Node node in _levels[d].ToList())
                {
                    if (node.Parent is { } p && p.Policy == KnownOids.AnyPolicy && node.Policy != KnownOids.AnyPolicy && !userSet.Contains(node.Policy))
                    {
                        RemoveSubtree(d, node);
                    }
                }
            }

            // (g)(iii)(3): a leaf anyPolicy node at depth n is replaced by the user's policies that the tree lacks.
            if (_levels.Count > n)
            {
                foreach (Node any in _levels[n].Where(x => x.Policy == KnownOids.AnyPolicy).ToList())
                {
                    Node parent = any.Parent!;
                    _levels[n].Remove(any);
                    parent.Children--;
                    _count--;
                    var validPolicyNodeSet = new HashSet<string>(
                        _levels.Skip(1).SelectMany(l => l).Where(x => x.Parent is { Policy: var pp } && pp == KnownOids.AnyPolicy).Select(x => x.Policy),
                        StringComparer.Ordinal);
                    foreach (string up in userSet.Order(StringComparer.Ordinal))
                    {
                        if (!validPolicyNodeSet.Contains(up) && up != KnownOids.AnyPolicy)
                        {
                            Add(n, up, parent, [up]);
                        }
                    }
                }
            }

            // (g)(iii)(4): nodes above depth n without children go; the nodes at depth n are the leaves.
            Prune(Math.Min(n, _levels.Count));
        }

        if (IsNull)
        {
            return [];
        }

        var set = new SortedSet<string>(StringComparer.Ordinal);
        foreach (List<Node> level in _levels!.Skip(1))
        {
            foreach (Node node in level)
            {
                set.Add(node.Policy);
            }
        }

        return [.. set];
    }

    private void RemoveSubtree(int depth, Node node)
    {
        _levels![depth].Remove(node);
        _count--;
        node.Parent!.Children--;
        for (int d = depth + 1; d < _levels.Count; d++)
        {
            foreach (Node c in _levels[d].Where(x => x.Parent == node).ToList())
            {
                RemoveSubtree(d, c);
            }
        }
    }
}
