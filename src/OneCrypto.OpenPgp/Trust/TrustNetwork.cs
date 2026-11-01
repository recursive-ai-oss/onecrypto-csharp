using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Policy;

namespace RecursiveAI.OneCrypto.OpenPgp.Trust;

/// <summary>
/// One edge of a web-of-trust network: a certification of a User ID, or a delegation (a direct-key signature) that makes the target a trusted
/// introducer, with the trust parameters it carries (RFC 9580 §5.2.3.21, §5.2.3.22).
/// </summary>
public sealed class TrustCertification
{
    /// <summary>Creates an edge. For networks described by hand; <see cref="TrustNetwork.Build"/> creates edges from signatures.</summary>
    /// <param name="issuer">The issuing certificate, as upper-case hexadecimal of its primary-key fingerprint (or any identifier you use for nodes).</param>
    /// <param name="target">The certified certificate, in the same form.</param>
    /// <param name="userId">The certified User ID text, or null for a delegation (a certification of the certificate alone).</param>
    /// <param name="depth">The trust depth: 0 for a plain certification, n for a trusted introducer that may designate level n-1 introducers, 255 for no limit.</param>
    /// <param name="amount">The trust amount, 0 to 255; 120 and above is full trust and is capped at 120.</param>
    /// <param name="regexes">The scope regular expressions; none means no restriction.</param>
    /// <param name="created">When the certification was made.</param>
    /// <param name="expires">When it expires, or null.</param>
    public TrustCertification(string issuer, string target, string? userId, byte depth = 0, byte amount = 120, IReadOnlyList<string>? regexes = null, DateTimeOffset created = default, DateTimeOffset? expires = null)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(target);
        Issuer = issuer;
        Target = target;
        UserId = userId;
        Depth = depth;
        Amount = amount;
        Regexes = regexes ?? [];
        Created = created;
        Expires = expires;
        Exportable = true;
    }

    /// <summary>The issuing certificate (fingerprint hex).</summary>
    public string Issuer { get; }

    /// <summary>The certified certificate (fingerprint hex).</summary>
    public string Target { get; }

    /// <summary>The certified User ID, or null for a delegation.</summary>
    public string? UserId { get; }

    /// <summary>True for a delegation: it certifies a certificate, not a User ID.</summary>
    public bool IsDelegation => UserId is null;

    /// <summary>True when issuer and target are the same certificate (a self-certification).</summary>
    public bool IsSelf => string.Equals(Issuer, Target, StringComparison.Ordinal);

    /// <summary>The trust depth as written. A self-certification always counts as depth 0.</summary>
    public byte Depth { get; }

    /// <summary>The trust amount as written, 0 to 255; a certification without a Trust Signature subpacket has 120.</summary>
    public byte Amount { get; }

    /// <summary>The scope expressions; empty when the certification is not restricted.</summary>
    public IReadOnlyList<string> Regexes { get; }

    /// <summary>When the signature was made.</summary>
    public DateTimeOffset Created { get; }

    /// <summary>When the signature expires, or null.</summary>
    public DateTimeOffset? Expires { get; }

    /// <summary>False when the signature is marked not exportable (a local certification). It still counts for the local user.</summary>
    public bool Exportable { get; init; }

    /// <summary>True when the signature carried a Trust Signature subpacket.</summary>
    public bool HasTrustSignature { get; init; }

    /// <summary>The certification type (0x10 to 0x13) or 0x1F for a delegation; 0 for a hand-described edge.</summary>
    public byte SignatureType { get; init; }

    /// <summary>The signature packet, or null for a hand-described edge.</summary>
    public SignaturePacket? Signature { get; init; }

    /// <summary>Notes made while evaluating it, for example that its hash is flagged by the policy.</summary>
    public IReadOnlyList<string> Notes { get; init; } = [];
}

/// <summary>A signature that was looked at and not turned into an edge, with the reason; kept so reports can say why a binding is not authenticated.</summary>
/// <param name="Issuer">The issuer, or null when it could not be identified or is not among the supplied certificates.</param>
/// <param name="Target">The certified certificate.</param>
/// <param name="UserId">The User ID, or null for a delegation.</param>
/// <param name="Reason">Why the signature does not count, with the specification section.</param>
public sealed record TrustRejection(string? Issuer, string Target, string? UserId, string Reason);

/// <summary>What the network knows about one certificate: the key's state at the reference time.</summary>
public sealed class TrustNode
{
    internal TrustNode(string id, PgpCertificate? certificate, bool usable, string? reason)
    {
        Id = id;
        Certificate = certificate;
        IsUsable = usable;
        UnusableReason = reason;
    }

    /// <summary>The identifier: the primary-key fingerprint as upper-case hexadecimal.</summary>
    public string Id { get; }

    /// <summary>The certificate, or null in a network described by hand.</summary>
    public PgpCertificate? Certificate { get; }

    /// <summary>True when the primary key is bound, created, unexpired and unrevoked at the reference time.</summary>
    public bool IsUsable { get; }

    /// <summary>Why the key is not usable, or null.</summary>
    public string? UnusableReason { get; }
}

/// <summary>
/// The certificates and the certifications between them as they stand at one reference time: the input both trust models work on. Building it
/// checks every third-party signature against its issuer's key and applies expiry, revocation, supersession and the policy's hash rules
/// (RFC 9580 §5.2.3.18, §5.2.3.31; the web-of-trust draft §4.1, §4.2). It does no network I/O. The network is immutable once built.
/// </summary>
public sealed class TrustNetwork
{
    private readonly Dictionary<string, TrustNode> _nodes;
    private readonly Dictionary<string, List<int>> _incoming = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<string>> _userIds = new(StringComparer.Ordinal);
    private readonly HashSet<(string Target, string UserId)> _revokedUserIds = [];

    private TrustNetwork(DateTimeOffset at, Dictionary<string, TrustNode> nodes, List<TrustCertification> edges, List<TrustRejection> rejections, TrustLimits limits)
    {
        At = at;
        _nodes = nodes;
        Certifications = edges;
        Rejections = rejections;
        Limits = limits;
        for (int i = 0; i < edges.Count; i++)
        {
            TrustCertification e = edges[i];
            if (!_incoming.TryGetValue(e.Target, out List<int>? list))
            {
                list = [];
                _incoming[e.Target] = list;
            }

            list.Add(i);
            if (e.UserId is not null)
            {
                if (!_userIds.TryGetValue(e.Target, out HashSet<string>? set))
                {
                    set = new HashSet<string>(StringComparer.Ordinal);
                    _userIds[e.Target] = set;
                }

                set.Add(e.UserId);
            }
        }
    }

    /// <summary>The reference time every validity question was answered at.</summary>
    public DateTimeOffset At { get; }

    /// <summary>The limits the network was built under; the models reuse them for their own work.</summary>
    public TrustLimits Limits { get; }

    /// <summary>The certificates, by fingerprint hex.</summary>
    public IReadOnlyCollection<TrustNode> Nodes => _nodes.Values;

    /// <summary>The edges that count at the reference time: certifications and delegations, self-certifications included.</summary>
    public IReadOnlyList<TrustCertification> Certifications { get; }

    /// <summary>The signatures that were examined and do not count, with reasons (at most a few thousand are kept).</summary>
    public IReadOnlyList<TrustRejection> Rejections { get; }

    /// <summary>The node for an identifier, or null.</summary>
    /// <param name="id">The fingerprint hex.</param>
    public TrustNode? FindNode(string id) => _nodes.TryGetValue(id, out TrustNode? n) ? n : null;

    /// <summary>The indexes into <see cref="Certifications"/> of the edges that certify <paramref name="target"/> (self-certifications included).</summary>
    /// <param name="target">The certified certificate.</param>
    public IReadOnlyList<int> IncomingEdges(string target) => _incoming.TryGetValue(target, out List<int>? l) ? l : [];

    /// <summary>The User IDs of a certificate that carry at least one counting certification (its own included).</summary>
    /// <param name="target">The certificate.</param>
    public IReadOnlyCollection<string> UserIds(string target) => _userIds.TryGetValue(target, out HashSet<string>? s) ? s : [];

    /// <summary>True when the certificate's own valid revocation of this User ID is in force at the reference time.</summary>
    /// <param name="target">The certificate.</param>
    /// <param name="userId">The User ID text.</param>
    public bool IsUserIdRevoked(string target, string userId) => _revokedUserIds.Contains((target, userId));

    /// <summary>Describes a network by hand: nodes and edges, for graphs that do not come from OpenPGP data (and for tests of the models).</summary>
    /// <param name="nodes">The node identifiers. Every node is usable.</param>
    /// <param name="edges">The edges. Issuers and targets not listed in <paramref name="nodes"/> are added.</param>
    /// <param name="at">The reference time recorded in the network.</param>
    /// <param name="limits">Limits; null for <see cref="TrustLimits.Default"/>.</param>
    /// <exception cref="TrustLimitExceededException">There are more nodes or edges than the limits allow.</exception>
    public static TrustNetwork FromEdges(IEnumerable<string> nodes, IEnumerable<TrustCertification> edges, DateTimeOffset at, TrustLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(nodes);
        ArgumentNullException.ThrowIfNull(edges);
        limits ??= TrustLimits.Default;
        var map = new Dictionary<string, TrustNode>(StringComparer.Ordinal);
        foreach (string n in nodes)
        {
            map[n] = new TrustNode(n, null, true, null);
            if (map.Count > limits.MaxCertificates)
            {
                throw new TrustLimitExceededException(TrustLimit.Certificates, "Too many certificates in the network.");
            }
        }

        var list = new List<TrustCertification>();
        foreach (TrustCertification e in edges)
        {
            if (list.Count >= limits.MaxCertifications)
            {
                throw new TrustLimitExceededException(TrustLimit.Certifications, "Too many certifications in the network.");
            }

            foreach (string id in new[] { e.Issuer, e.Target })
            {
                if (!map.ContainsKey(id))
                {
                    map[id] = new TrustNode(id, null, true, null);
                }
            }

            list.Add(e);
        }

        if (map.Count > limits.MaxCertificates)
        {
            throw new TrustLimitExceededException(TrustLimit.Certificates, "Too many certificates in the network.");
        }

        return new TrustNetwork(at, map, list, [], limits);
    }

    /// <summary>
    /// Builds the network from certificates at a reference time. Certificates with the same primary key (for example an old and a refreshed copy) are merged.
    /// </summary>
    /// <param name="certificates">The certificates, from any source.</param>
    /// <param name="at">The reference time.</param>
    /// <param name="policy">The hash and key-size policy for certification signatures; null for <see cref="CryptoPolicy.Standard"/>.</param>
    /// <param name="limits">Limits; null for <see cref="TrustLimits.Default"/>.</param>
    /// <exception cref="TrustLimitExceededException">More certificates or certification signatures than the limits allow.</exception>
    public static TrustNetwork Build(IEnumerable<PgpCertificate> certificates, DateTimeOffset at, CryptoPolicy? policy = null, TrustLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        policy ??= CryptoPolicy.Standard;
        limits ??= TrustLimits.Default;
        var builder = new Builder(at, policy, limits);
        return builder.Run(certificates);
    }

    private sealed class Builder
    {
        private const int MaxRejections = 4096;
        private readonly DateTimeOffset _at;
        private readonly long _now;
        private readonly CryptoPolicy _policy;
        private readonly TrustLimits _limits;
        private readonly Dictionary<string, PgpCertificate> _certs = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _byKeyId = new(StringComparer.Ordinal);
        private readonly List<TrustRejection> _rejections = [];
        private readonly List<TrustCertification> _edges = [];
        private int _examined;

        internal Builder(DateTimeOffset at, CryptoPolicy policy, TrustLimits limits)
        {
            _at = at;
            _now = at.ToUnixTimeSeconds();
            _policy = policy;
            _limits = limits;
        }

        internal TrustNetwork Run(IEnumerable<PgpCertificate> input)
        {
            foreach (PgpCertificate c in input)
            {
                string id = Convert.ToHexString(c.Fingerprint);
                if (_certs.TryGetValue(id, out PgpCertificate? have))
                {
                    TransferableKey merged = TransferableKey.Parse(CombinedPackets(have.Transferable, c.Transferable));
                    _certs[id] = PgpCertificate.FromTransferable(merged);
                    continue;
                }

                if (_certs.Count >= _limits.MaxCertificates)
                {
                    throw new TrustLimitExceededException(TrustLimit.Certificates, "Too many certificates.");
                }

                _certs[id] = c;
            }

            foreach ((string id, PgpCertificate c) in _certs)
            {
                _byKeyId[Convert.ToHexString(c.Primary.KeyId)] = id;
            }

            var nodes = new Dictionary<string, TrustNode>(StringComparer.Ordinal);
            foreach ((string id, PgpCertificate c) in _certs)
            {
                PgpKeyState st = c.Primary.StateAt(_at);
                nodes[id] = new TrustNode(id, c, st.IsValid, st.Reason);
            }

            var revokedIds = new HashSet<(string, string)>();
            foreach ((string id, PgpCertificate c) in _certs)
            {
                Collect(id, c, revokedIds);
            }

            var net = new TrustNetwork(_at, nodes, _edges, _rejections, _limits);
            foreach ((string, string) r in revokedIds)
            {
                net._revokedUserIds.Add(r);
            }

            return net;
        }

        // Two copies of one certificate: the packets of the first, then the components of the second that the first lacks, by merging as the key store does.
        private static IReadOnlyList<Packet> CombinedPackets(TransferableKey a, TransferableKey b)
        {
            TransferableKey merged = CertD.CertMerge.Merge(a, b, out _);
            return merged.Packets;
        }

        private void Reject(string? issuer, string target, string? uid, string reason)
        {
            if (_rejections.Count < MaxRejections)
            {
                _rejections.Add(new TrustRejection(issuer, target, uid, reason));
            }
        }

        private string? Resolve(SignaturePacket s)
        {
            if (s.Version == 3)
            {
                return _byKeyId.TryGetValue(Convert.ToHexString(s.V3IssuerKeyId.Span), out string? v3) ? v3 : null;
            }

            foreach (SubpacketArea area in new[] { s.HashedSubpackets, s.UnhashedSubpackets })
            {
                foreach (SignatureSubpacket sp in area.FindAll(SubpacketType.IssuerFingerprint))
                {
                    if (sp.Data.Length > 1)
                    {
                        string fp = Convert.ToHexString(sp.Data.Span[1..]);
                        if (_certs.ContainsKey(fp))
                        {
                            return fp;
                        }
                    }
                }
            }

            foreach (SubpacketArea area in new[] { s.HashedSubpackets, s.UnhashedSubpackets })
            {
                foreach (SignatureSubpacket sp in area.FindAll(SubpacketType.IssuerKeyId))
                {
                    if (sp.Data.Length == 8 && _byKeyId.TryGetValue(Convert.ToHexString(sp.Data.Span), out string? id))
                    {
                        return id;
                    }
                }
            }

            return null;
        }

        private void Count()
        {
            if (++_examined > _limits.MaxCertifications)
            {
                throw new TrustLimitExceededException(TrustLimit.Certifications, "Too many certification signatures.");
            }
        }

        private bool Verifies(SignaturePacket s, PgpKey issuer, params ReadOnlyMemory<byte>[] parts)
        {
            Count();
            try
            {
                return SignatureEngine.VerifyDigest(issuer.Packet, s, SignatureEngine.Digest(s, parts));
            }
            catch (PgpException)
            {
                return false;
            }
        }

        private static bool Expired(SignaturePacket s, long at) => s.ExpirationSeconds is { } e and > 0 && (long)(s.CreationTime ?? 0) + e <= at;

        // Returns null when the signature may count, else the reason it does not.
        private string? Screen(SignaturePacket s, PgpCertificate issuer, List<string> notes, bool self)
        {
            if (!SignatureChecker.HasNoUnknownCritical(s))
            {
                return "The signature has a critical subpacket that is not understood (RFC 9580 §5.2.3.7).";
            }

            if (s.CreationTime is not { } created)
            {
                return "The signature has no creation time (RFC 9580 §5.2.3.11).";
            }

            if (created > _now)
            {
                return "The signature was made after the reference time.";
            }

            if (Expired(s, _now))
            {
                return "The signature has expired (RFC 9580 §5.2.3.18).";
            }

            try
            {
                PolicyDecision d = _policy.CheckHash(PgpAlgorithms.HashName(s.Hash), CryptoUse.Verify, DateTimeOffset.FromUnixTimeSeconds(created));
                if (d.Verdict == PolicyVerdict.Rejected)
                {
                    return d.Reason + " " + d.Reference;
                }

                if (d.Verdict == PolicyVerdict.Flagged)
                {
                    notes.Add(d.Reason);
                }
            }
            catch (PgpException e)
            {
                return e.Message;
            }

            // Web-of-trust draft §4.2: the issuer must be valid when it certified. A soft revocation made later does not undo the certification.
            // A self-certification is what binds the key in the first place, so it is not judged by the key's own state.
            PgpKeyState st = self ? new PgpKeyState(true, null, PgpKeyUsage.None, null) : issuer.Primary.StateAt(DateTimeOffset.FromUnixTimeSeconds(created));
            if (!st.IsValid)
            {
                return "The issuing certificate was not valid when it certified: " + st.Reason;
            }

            return null;
        }

        private void Collect(string targetId, PgpCertificate target, HashSet<(string, string)> revokedIds)
        {
            byte[] keyInput = SignatureEngine.KeyInput(target.Primary.Packet);
            foreach (UserComponent u in target.Transferable.Users)
            {
                if (u.Identity is not UserIdPacket uidPacket)
                {
                    continue;
                }

                string uid = uidPacket.Text;
                byte[] uidInput = SignatureEngine.UserIdInput(u.Identity);
                var certs = new List<(SignaturePacket Sig, string Issuer, List<string> Notes)>();
                var revocations = new List<(SignaturePacket Sig, string Issuer)>();
                foreach (SignaturePacket s in u.Signatures)
                {
                    bool isCert = s.Type is SignatureType.GenericCertification or SignatureType.PersonaCertification or SignatureType.CasualCertification or SignatureType.PositiveCertification;
                    bool isRev = s.Type == SignatureType.CertificationRevocation;
                    if (!isCert && !isRev)
                    {
                        continue;
                    }

                    string? issuerId = Resolve(s);
                    if (issuerId is null)
                    {
                        Reject(null, targetId, uid, "The issuing certificate is not among the supplied certificates.");
                        continue;
                    }

                    PgpCertificate issuer = _certs[issuerId];
                    if (!Verifies(s, issuer.Primary, keyInput, uidInput))
                    {
                        Reject(issuerId, targetId, uid, "The signature does not verify (RFC 9580 §5.2.4).");
                        continue;
                    }

                    if (isRev)
                    {
                        revocations.Add((s, issuerId));
                        continue;
                    }

                    var notes = new List<string>();
                    string? why = Screen(s, issuer, notes, issuerId == targetId);
                    if (why is not null)
                    {
                        Reject(issuerId, targetId, uid, why);
                        continue;
                    }

                    certs.Add((s, issuerId, notes));
                }

                // The User ID's own revocation (web-of-trust draft §4.2): a valid self-revocation at or before the reference time, unless the
                // owner certified the User ID again afterwards.
                long newestSelf = -1;
                foreach ((SignaturePacket s, string iss, _) in certs)
                {
                    if (iss == targetId)
                    {
                        newestSelf = Math.Max(newestSelf, s.CreationTime ?? 0);
                    }
                }

                foreach ((SignaturePacket r, string iss) in revocations)
                {
                    long v = r.CreationTime ?? 0;
                    if (iss == targetId && v <= _now && !Expired(r, _now) && v >= newestSelf)
                    {
                        revokedIds.Add((targetId, uid));
                    }
                }

                var kept = new List<(SignaturePacket Sig, string Issuer, List<string> Notes)>();
                foreach ((SignaturePacket s, string iss, List<string> notes) in certs)
                {
                    long c = s.CreationTime ?? 0;
                    bool revoked = s.Revocable && iss != targetId && revocations.Any(r => r.Issuer == iss && (r.Sig.CreationTime ?? 0) > c && (r.Sig.CreationTime ?? 0) <= _now && !Expired(r.Sig, _now));
                    if (revoked)
                    {
                        Reject(iss, targetId, uid, "The certification has been revoked (RFC 9580 §5.2.1).");
                        continue;
                    }

                    kept.Add((s, iss, notes));
                }

                AddNewest(targetId, uid, kept);
            }

            // Delegations: direct-key signatures by other certificates (web-of-trust draft §3.1).
            var delegations = new List<(SignaturePacket Sig, string Issuer, List<string> Notes)>();
            foreach (SignaturePacket s in target.Transferable.DirectSignatures)
            {
                if (s.Type != SignatureType.DirectKey)
                {
                    continue;
                }

                string? issuerId = Resolve(s);
                if (issuerId is null || issuerId == targetId)
                {
                    continue;
                }

                PgpCertificate issuer = _certs[issuerId];
                if (!Verifies(s, issuer.Primary, keyInput))
                {
                    Reject(issuerId, targetId, null, "The signature does not verify (RFC 9580 §5.2.4).");
                    continue;
                }

                var notes = new List<string>();
                string? why = Screen(s, issuer, notes, false);
                if (why is not null)
                {
                    Reject(issuerId, targetId, null, why);
                    continue;
                }

                delegations.Add((s, issuerId, notes));
            }

            AddNewest(targetId, null, delegations);
        }

        // Web-of-trust draft §4.1: for one issuer and binding only the newest certification counts; equally new ones all do.
        private void AddNewest(string targetId, string? uid, List<(SignaturePacket Sig, string Issuer, List<string> Notes)> candidates)
        {
            foreach (IGrouping<string, (SignaturePacket Sig, string Issuer, List<string> Notes)> g in candidates.GroupBy(x => x.Issuer, StringComparer.Ordinal))
            {
                long newest = g.Max(x => (long)(x.Sig.CreationTime ?? 0));
                foreach ((SignaturePacket s, string iss, List<string> notes) in g)
                {
                    if ((s.CreationTime ?? 0) != newest)
                    {
                        Reject(iss, targetId, uid, "A newer certification by the same issuer replaces it (web-of-trust draft §4.1).");
                        continue;
                    }

                    if (_edges.Count >= _limits.MaxCertifications)
                    {
                        throw new TrustLimitExceededException(TrustLimit.Certifications, "Too many certifications.");
                    }

                    bool self = iss == targetId;
                    (byte Level, byte Amount)? ts = s.TrustSignature;
                    var regexes = new List<string>();
                    foreach (SignatureSubpacket rx in s.HashedSubpackets.FindAll(SubpacketType.RegularExpression))
                    {
                        // RFC 9580 §5.2.3.22: the text is NUL-terminated.
                        ReadOnlySpan<byte> raw = rx.Data.Span;
                        int nul = raw.IndexOf((byte)0);
                        regexes.Add(System.Text.Encoding.UTF8.GetString(nul >= 0 ? raw[..nul] : raw));
                    }

                    DateTimeOffset created = DateTimeOffset.FromUnixTimeSeconds(s.CreationTime ?? 0);
                    DateTimeOffset? expires = s.ExpirationSeconds is { } e and > 0 ? created.AddSeconds(e) : null;
                    _edges.Add(new TrustCertification(iss, targetId, uid, self || ts is null ? (byte)0 : ts.Value.Level, ts is null ? (byte)120 : ts.Value.Amount, regexes, created, expires)
                    {
                        Exportable = s.Exportable,
                        HasTrustSignature = ts is not null,
                        SignatureType = s.SignatureTypeId,
                        Signature = s,
                        Notes = notes,
                    });
                }
            }
        }
    }
}
