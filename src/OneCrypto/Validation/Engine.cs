using System.Linq;
using System.Collections.Immutable;
using System.Net;
using System.Runtime.CompilerServices;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

/// <summary>One validation run: builds candidate paths and validates each (RFC 5280 §6.1). Instances are single use.</summary>
internal sealed partial class Engine
{
    private sealed class RefComparer : IEqualityComparer<(object A, object B)>
    {
        public bool Equals((object A, object B) x, (object A, object B) y) => ReferenceEquals(x.A, y.A) && ReferenceEquals(x.B, y.B);

        public int GetHashCode((object A, object B) k) => HashCode.Combine(RuntimeHelpers.GetHashCode(k.A), RuntimeHelpers.GetHashCode(k.B));
    }

    private readonly ValidationOptions _o;
    private readonly ValidationLimits _l;
    private readonly Dictionary<Certificate, CertView> _views = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<(object, object), SignatureVerification> _sigCache = new(new RefComparer());
    private readonly List<CertView> _pool = [];
    private readonly List<PathReport> _paths = [];
    private readonly List<RejectedCandidate> _rejected = [];
    private readonly List<IssuerLocation> _locations = [];
    private int _steps;
    private int _sigChecks;
    private int _validated;
    private bool _limit;
    private bool _stop;
    private PathReport? _winner;

    private readonly int _depth;

    public Engine(ValidationOptions options, int depth = 0)
    {
        _depth = depth;
        _o = options;
        _l = options.Limits ?? ValidationLimits.Default;
        foreach (Certificate c in options.Intermediates)
        {
            if (c is null || _pool.Any(p => p.Cert.Equals(c)))
            {
                continue;
            }

            _pool.Add(View(c));
        }
    }

    public DateTimeOffset RefTime => _o.ReferenceTime;

    // Certificate times have whole-second granularity (RFC 5280 §4.1.2.5), so the reference time is compared to them at that granularity.
    private DateTimeOffset RefSecond => new(_o.ReferenceTime.Ticks - (_o.ReferenceTime.Ticks % TimeSpan.TicksPerSecond), _o.ReferenceTime.Offset);

    public DateTimeOffset DataTime => _o.RevocationDataTime ?? _o.ReferenceTime;

    public CertView View(Certificate c)
    {
        if (!_views.TryGetValue(c, out CertView? v))
        {
            v = new CertView(c);
            _views[c] = v;
        }

        return v;
    }

    /// <summary>Verifies a signature once per certificate and key; the count of real verifications is limited.</summary>
    public SignatureVerification VerifyCert(Certificate cert, PublicKeyInfo key)
    {
        if (_sigCache.TryGetValue((cert, key), out SignatureVerification cached))
        {
            return cached;
        }

        if (_sigChecks >= _l.MaxSignatureChecks)
        {
            _limit = true;
            return new(SignatureStatus.Malformed, string.Empty, "signature-check limit reached", "limit");
        }

        _sigChecks++;
        SignatureVerification r = cert.VerifySignature(key);
        _sigCache[(cert, key)] = r;
        return r;
    }

    public SignatureVerification VerifyCrl(CertificateRevocationList crl, PublicKeyInfo key)
    {
        if (_sigCache.TryGetValue((crl, key), out SignatureVerification cached))
        {
            return cached;
        }

        if (_sigChecks >= _l.MaxSignatureChecks)
        {
            _limit = true;
            return new(SignatureStatus.Malformed, string.Empty, "signature-check limit reached", "limit");
        }

        _sigChecks++;
        SignatureVerification r = crl.VerifySignature(key);
        _sigCache[(crl, key)] = r;
        return r;
    }

    public SignatureVerification VerifyOcsp(OcspBasicResponse resp, PublicKeyInfo key)
    {
        if (_sigCache.TryGetValue((resp, key), out SignatureVerification cached))
        {
            return cached;
        }

        if (_sigChecks >= _l.MaxSignatureChecks)
        {
            _limit = true;
            return new(SignatureStatus.Malformed, string.Empty, "signature-check limit reached", "limit");
        }

        _sigChecks++;
        SignatureVerification r = resp.VerifySignature(key);
        _sigCache[(resp, key)] = r;
        return r;
    }

    // ------------------------------------------------------------------ path building

    public ValidationReport Run(Certificate target)
    {
        ImmutableArray<RuleResult> targetResults = [];
        var anchors = _o.TrustAnchors.Where(a => a is not null).ToList();
        if (anchors.Count == 0)
        {
            targetResults = [new RuleResult(ValidationRule.PathBuilding, RuleOutcome.Fail, "no trust anchors were supplied", "RFC 5280 §6.1.1 (d)")];
            return Assemble(target, targetResults);
        }

        // A target that is itself a trusted certificate needs no issuer (RFC 5937 §3: the anchor is the trust).
        TrustAnchor? self = anchors.Find(a => a.Certificate is not null && a.Certificate.Equals(target));
        if (self is not null)
        {
            Complete([target], self);
        }
        else
        {
            Extend([target], anchors);
        }

        if (_paths.Count == 0)
        {
            string detail = "no certification path from the target to a trust anchor was found";
            if (_rejected.Count > 0)
            {
                detail += $"; {_rejected.Count} candidate issuer(s) were refused, the first because {_rejected[0].Reason}";
            }

            RuleOutcome outcome = _limit ? RuleOutcome.Indeterminate : RuleOutcome.Fail;
            if (_limit)
            {
                detail += "; a work limit was reached";
            }

            targetResults = [new RuleResult(_limit ? ValidationRule.Limit : ValidationRule.PathBuilding, outcome, detail, "RFC 4158 §2; RFC 5280 §6.1")];
        }

        return Assemble(target, targetResults);
    }

    private ValidationReport Assemble(Certificate target, ImmutableArray<RuleResult> targetResults)
    {
        PathReport? selected = _winner;
        ValidationVerdict verdict;
        if (_winner is not null)
        {
            verdict = ValidationVerdict.Valid;
        }
        else if (_paths.Any(p => p.Verdict == ValidationVerdict.Indeterminate))
        {
            verdict = ValidationVerdict.Indeterminate;
            selected = _paths.First(p => p.Verdict == ValidationVerdict.Indeterminate);
        }
        else if (_paths.Count > 0)
        {
            verdict = ValidationVerdict.Invalid;
            selected = _paths.OrderByDescending(p => p.DecidingIndex).First();
        }
        else
        {
            verdict = _limit ? ValidationVerdict.Indeterminate : ValidationVerdict.Invalid;
        }

        RevocationStatus summary = RevocationStatus.NotChecked;
        if (selected is not null)
        {
            summary = Summarise(selected);
        }

        // AIA caIssuers locations of the certificate that lacked an issuer are surfaced, never fetched (RFC 5280 §4.2.2.1).
        if (_winner is null)
        {
            foreach (CertView v in _dead)
            {
                foreach (string uri in v.AuthorityInfoAccess?.UrisFor(KnownOids.AdCaIssuers) ?? [])
                {
                    _locations.Add(new IssuerLocation(v.Cert, uri));
                }
            }
        }

        return new ValidationReport(
            verdict,
            selected,
            [.. _paths],
            [.. _rejected],
            [.. _locations],
            [.. _dead.Select(d => d.Cert)],
            targetResults,
            _limit,
            _o.ReferenceTime,
            summary);
    }

    private static RevocationStatus Summarise(PathReport p)
    {
        bool any = false;
        bool unknown = false;
        bool revoked = false;
        foreach (CertificateReport c in p.Certificates)
        {
            switch (c.Revocation.Status)
            {
                case RevocationStatus.Revoked:
                    revoked = true;
                    any = true;
                    break;
                case RevocationStatus.Unknown:
                    unknown = true;
                    any = true;
                    break;
                case RevocationStatus.Good:
                    any = true;
                    break;
            }
        }

        return revoked ? RevocationStatus.Revoked : unknown ? RevocationStatus.Unknown : any ? RevocationStatus.Good : RevocationStatus.NotChecked;
    }

    private readonly List<CertView> _dead = [];

    private int Score(CertView subject, DistinguishedName? _, CertView cand)
    {
        // RFC 4158 §4.2: prefer a candidate whose subjectKeyIdentifier equals the subject's authorityKeyIdentifier,
        // then one valid at the reference time, so the likeliest path is tried first.
        int s = 0;
        ReadOnlyMemory<byte> aki = subject.AuthorityKeyIdentifier?.KeyIdentifier ?? default;
        ReadOnlyMemory<byte>? ski = cand.SubjectKeyIdentifier?.KeyIdentifier;
        if (!aki.IsEmpty && ski is { } k)
        {
            s += k.Span.SequenceEqual(aki.Span) ? 0 : 2;
        }
        else
        {
            s += 1;
        }

        if (cand.Cert.NotBefore > _o.ReferenceTime || cand.Cert.NotAfter < _o.ReferenceTime)
        {
            s += 4;
        }

        return s;
    }

    private List<CertView> Candidates(CertView subject, IEnumerable<CertView> chain)
    {
        var list = new List<(int Score, CertView V)>();
        foreach (CertView p in _pool)
        {
            if (!subject.Cert.Issuer.Matches(p.Cert.Subject))
            {
                continue;
            }

            // Loop detection (RFC 4158 §4.1): a certificate may appear once, and so may a subject and key pair (cross-certificates of one key make cycles).
            if (chain.Any(c => ReferenceEquals(c, p) || c.Cert.Equals(p.Cert)
                || (c.Cert.PublicKey.Equals(p.Cert.PublicKey) && c.Cert.Subject.Matches(p.Cert.Subject))))
            {
                continue;
            }

            list.Add((Score(subject, null, p), p));
        }

        return [.. list.OrderBy(x => x.Score).ThenByDescending(x => x.V.Cert.NotAfter).ThenBy(x => Convert.ToHexString(x.V.Cert.Encoded.Span.Slice(0, Math.Min(32, x.V.Cert.Encoded.Length))), StringComparer.Ordinal).Select(x => x.V)];
    }

    private bool Extend(List<Certificate> chain, List<TrustAnchor> anchors)
    {
        if (_stop)
        {
            return false;
        }

        if (++_steps > _l.MaxSearchSteps)
        {
            _limit = true;
            _stop = true;
            return false;
        }

        CertView cur = View(chain[^1]);
        var matching = anchors.Where(a => cur.Cert.Issuer.Matches(a.Name)).ToList();
        // Try anchors whose key identifier matches first, and verifying signatures before failing ones.
        var ordered = matching
            .Select(a => (A: a, Sig: VerifyCert(cur.Cert, a.PublicKey).IsValid ? 0 : 1, Id: AnchorScore(cur, a)))
            .OrderBy(x => x.Sig).ThenBy(x => x.Id).Select(x => x.A).ToList();
        foreach (TrustAnchor a in ordered)
        {
            if (Complete(chain, a))
            {
                return true;
            }

            if (_stop)
            {
                return false;
            }
        }

        if (chain.Count >= _l.MaxPathLength)
        {
            _limit = true;
            return false;
        }

        List<CertView> cands = Candidates(cur, chain.Select(View));
        int tried = 0;
        bool any = false;
        foreach (CertView cand in cands)
        {
            if (anchors.Any(a => a.Certificate is not null && a.Certificate.Equals(cand.Cert)))
            {
                continue; // reached through the anchor loop
            }

            if (++tried > _l.MaxCandidatesPerCertificate)
            {
                _limit = true;
                break;
            }

            SignatureVerification sv = VerifyCert(cur.Cert, cand.Cert.PublicKey);
            if (!sv.IsValid)
            {
                if (_rejected.Count < 64)
                {
                    _rejected.Add(new RejectedCandidate(cur.Cert, cand.Cert, "its key does not verify the signature: " + (sv.Reason.Length > 0 ? sv.Reason : sv.Status.ToString())));
                }

                continue;
            }

            any = true;
            chain.Add(cand.Cert);
            bool ok = Extend(chain, anchors);
            chain.RemoveAt(chain.Count - 1);
            if (ok)
            {
                return true;
            }

            if (_stop)
            {
                return false;
            }
        }

        if (!any && matching.Count == 0)
        {
            _dead.Add(cur);
        }

        return false;
    }

    private static int AnchorScore(CertView subject, TrustAnchor a)
    {
        ReadOnlyMemory<byte> aki = subject.AuthorityKeyIdentifier?.KeyIdentifier ?? default;
        if (aki.IsEmpty || a.Certificate is null)
        {
            return 1;
        }

        try
        {
            SubjectKeyIdentifier? ski = a.Certificate.Extensions.Get<SubjectKeyIdentifier>();
            if (ski is null)
            {
                return 1;
            }

            return ski.KeyIdentifier.Span.SequenceEqual(aki.Span) ? 0 : 2;
        }
        catch (X509ParseException)
        {
            return 1;
        }
    }

    private bool Complete(List<Certificate> chainFromTarget, TrustAnchor anchor)
    {
        if (_validated >= _l.MaxPathsValidated)
        {
            _limit = true;
            _stop = true;
            return false;
        }

        _validated++;
        PathReport report = ValidatePath(anchor, chainFromTarget);
        if (_paths.Count < _l.MaxReportedPaths)
        {
            _paths.Add(report);
        }

        if (report.Verdict == ValidationVerdict.Valid)
        {
            _winner = report;
            _stop = true;
            return true;
        }

        return false;
    }

    public static bool TryParseIp(string s, out byte[] bytes)
    {
        bytes = [];
        if (s.Length == 0 || !IPAddress.TryParse(s, out IPAddress? ip))
        {
            return false;
        }

        bytes = ip.GetAddressBytes();
        return true;
    }
}
