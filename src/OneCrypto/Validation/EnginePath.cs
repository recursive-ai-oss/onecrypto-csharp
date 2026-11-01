using System.Linq;
using System.Collections.Immutable;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

internal sealed partial class Engine
{
    private sealed class CertResults
    {
        public readonly List<RuleResult> List = [];
        public RevocationReport Revocation = RevocationReport.NotCheckedReport;

        public void Add(ValidationRule rule, RuleOutcome outcome, string reason, string clause, string? policyRule = null) => List.Add(new RuleResult(rule, outcome, reason, clause, policyRule));

        public void Pass(ValidationRule rule, string reason, string clause) => Add(rule, RuleOutcome.Pass, reason, clause);

        public void Fail(ValidationRule rule, string reason, string clause) => Add(rule, RuleOutcome.Fail, reason, clause);
    }

    // RFC 5280 §4.2.1.12: a certificate that carries an extKeyUsage must allow the purpose the caller asked for; none means unrestricted.
    // The check also covers a target that is itself a trust anchor: trusting a certificate does not widen what it says it is for.
    private void CheckRequiredEku(CertView v, CertResults r)
    {
        if (string.IsNullOrEmpty(RequiredEku) || v.ExtendedKeyUsage is not { } eku)
        {
            return;
        }

        if (eku.Allows(RequiredEku))
        {
            r.Pass(ValidationRule.ExtendedKeyUsage, "extKeyUsage allows the required purpose", "RFC 5280 §4.2.1.12");
        }
        else
        {
            r.Fail(ValidationRule.ExtendedKeyUsage, $"extKeyUsage does not allow {RequiredEku}", "RFC 5280 §4.2.1.12");
        }
    }

    // The algorithm policy: the hash named by the certificate's signature algorithm and the issuer's key, judged at the reference time.
    // One result per decision, each with the policy's own rule id, so a report says which cutoff or minimum applied.
    private void AlgorithmPolicy(Certificate cert, PublicKeyInfo issuerKey, CertResults r)
    {
        // PKI signatures (RFC 5280 §4.1.1.2) are asked with their own use, so the policy can refuse SHA-1 in a certificate long before it refuses it in a message.
        // The server-authentication profile needs no second policy: its 2048-bit RSA floor is a profile rule (WebPkiCertificate) and SHA-1 is already refused from 2017.
        bool any = false;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        Policy.PolicyReport pr = _o.Policy.CheckSignature(cert.SignatureAlgorithm, issuerKey, Policy.CryptoUse.VerifyPki, _o.ReferenceTime);
        foreach (Policy.PolicyDecision d in pr.Findings)
        {
            RuleOutcome oc = d.Verdict == Policy.PolicyVerdict.Rejected ? RuleOutcome.Fail : RuleOutcome.Warning;
            if (!seen.Add($"{d.Rule}|{oc}"))
            {
                continue;
            }

            any = true;
            r.Add(ValidationRule.Algorithm, oc, $"{d.Algorithm}: {d.Reason}", d.Reference, d.Rule);
        }

        if (!any)
        {
            r.Add(ValidationRule.Algorithm, RuleOutcome.Pass, $"signature algorithm and issuer key accepted by the {_o.Policy.Name} policy", "CryptoPolicy");
        }
    }

    private PathReport ValidatePath(TrustAnchor anchor, List<Certificate> fromTarget)
    {
        int n = fromTarget.Count;
        var certs = new Certificate[n];
        for (int i = 0; i < n; i++)
        {
            certs[i] = fromTarget[n - 1 - i]; // certs[0] is signed by the anchor; certs[n-1] is the target
        }

        var res = new CertResults[n];
        for (int i = 0; i < n; i++)
        {
            res[i] = new CertResults();
        }

        var pathResults = new List<RuleResult>();
        bool targetIsAnchor = anchor.Certificate is not null && n == 1 && anchor.Certificate.Equals(certs[0]);
        CertView? anchorView = anchor.Certificate is null ? null : View(anchor.Certificate);

        // §6.1.1: initialisation.
        PublicKeyInfo workingKey = anchor.PublicKey;
        DistinguishedName workingIssuer = anchor.Name;
        var nc = new NameConstraintState(_l.MaxNameConstraintComparisons);
        int explicitPolicy = _o.InitialExplicitPolicy ? 0 : n + 1;
        int policyMapping = _o.InitialPolicyMappingInhibit ? 0 : n + 1;
        int inhibitAny = _o.InitialAnyPolicyInhibit ? 0 : n + 1;
        int maxPathLength = n;
        var tree = new PolicyTree(_l.MaxPolicyNodes);

        if (anchorView is not null)
        {
            CheckAnchor(anchorView, pathResults, n, ref maxPathLength, nc, ref explicitPolicy, ref policyMapping, ref inhibitAny, targetIsAnchor);
        }

        if (targetIsAnchor)
        {
            res[0].Pass(ValidationRule.TrustAnchor, "the target is itself a trust anchor", "RFC 5937 §2");
            StructureChecks(View(certs[0]), res[0], true, false);
            WebPkiCertificate(View(certs[0]), res[0], false);
            if (View(certs[0]).UnrecognisedCritical() is { } tc)
            {
                res[0].Fail(ValidationRule.CriticalExtension, $"critical extension {tc} is not recognised", "RFC 5280 §4.2");
            }

            CheckRequiredEku(View(certs[0]), res[0]);
            TargetChecks(View(certs[0]), res[0], true);
            return Build(res, certs, anchor, pathResults, new PolicyReport(false, false, [], true), true);
        }

        if (_o.MaxIntermediates is int mi)
        {
            // Self-issued intermediates (key rollover) do not count as a further level (RFC 5280 §6.1.4 (l)).
            int logical = 0;
            for (int k = 0; k < n - 1; k++)
            {
                if (!View(certs[k]).SelfIssued)
                {
                    logical++;
                }
            }

            if (logical > mi)
            {
                pathResults.Add(new RuleResult(ValidationRule.PathLength, RuleOutcome.Fail, $"the path has {logical} intermediate(s), the limit is {mi}", "RFC 5280 §6.1.4 (l)"));
            }
        }

        PolicyReport policyReport = new(false, false, [], true);
        bool policyOverflow = false;

        for (int i = 1; i <= n; i++)
        {
            Certificate cert = certs[i - 1];
            CertView v = View(cert);
            CertResults r = res[i - 1];
            bool last = i == n;
            PublicKeyInfo issuerKey = workingKey;
            DistinguishedName issuerName = workingIssuer;

            StructureChecks(v, r, last, false);
            WebPkiCertificate(v, r, false);

            // (a)(4)
            if (cert.Issuer.Matches(workingIssuer))
            {
                r.Pass(ValidationRule.IssuerName, "issuer name equals the working issuer name", "RFC 5280 §6.1.3 (a)(4)");
            }
            else
            {
                r.Fail(ValidationRule.IssuerName, "issuer name does not match the name of the issuing certificate", "RFC 5280 §6.1.3 (a)(4)");
            }

            // (a)(1)
            SignatureVerification sv = VerifyCert(cert, workingKey);
            if (sv.IsValid)
            {
                r.Pass(ValidationRule.Signature, "signature verifies over the received tbsCertificate", "RFC 5280 §6.1.3 (a)(1)");
            }
            else
            {
                r.Fail(ValidationRule.Signature, sv.Reason.Length > 0 ? sv.Reason : $"signature check: {sv.Status}", string.IsNullOrEmpty(sv.Reference) ? "RFC 5280 §6.1.3 (a)(1)" : sv.Reference);
            }

            AlgorithmPolicy(cert, workingKey, r);

            // (a)(2)
            if (RefSecond < cert.NotBefore)
            {
                r.Fail(ValidationRule.Validity, $"not yet valid: notBefore is {cert.NotBefore:u}", "RFC 5280 §6.1.3 (a)(2)");
            }
            else if (RefSecond > cert.NotAfter)
            {
                r.Fail(ValidationRule.Validity, $"expired: notAfter is {cert.NotAfter:u}", "RFC 5280 §6.1.3 (a)(2)");
            }
            else
            {
                r.Pass(ValidationRule.Validity, "valid at the reference time", "RFC 5280 §6.1.3 (a)(2)");
            }

            // (b), (c): the constraints of the CAs above apply, except to self-issued certificates that are not the last.
            if (!v.SelfIssued || last)
            {
                string? ncFail = nc.Check(cert);
                if (ncFail is null)
                {
                    r.Add(ValidationRule.NameConstraints, nc.IsEmpty ? RuleOutcome.NotApplicable : RuleOutcome.Pass, nc.IsEmpty ? "no name constraints in force" : "names satisfy the constraints in force", "RFC 5280 §6.1.3 (b), (c)");
                }
                else
                {
                    r.Fail(ValidationRule.NameConstraints, ncFail, "RFC 5280 §6.1.3 (b), (c); §4.2.1.10");
                }
            }
            else
            {
                r.Add(ValidationRule.NameConstraints, RuleOutcome.NotApplicable, "self-issued intermediate certificates are exempt", "RFC 5280 §6.1.3 (b)");
            }

            // (d), (e), (f)
            if (!policyOverflow)
            {
                tree.ProcessCertificatePolicies(i, v.Policies, inhibitAny > 0 || (!last && v.SelfIssued));
                if (tree.Overflowed)
                {
                    policyOverflow = true;
                    r.Fail(ValidationRule.Policy, $"the policy tree grew beyond {_l.MaxPolicyNodes} nodes; processing stopped", "RFC 5280 §6.1.2; bounded against policy-tree explosion");
                }
                else if (explicitPolicy <= 0 && tree.IsNull)
                {
                    r.Fail(ValidationRule.Policy, "an explicit policy is required and no acceptable policy remains", "RFC 5280 §6.1.3 (f)");
                }
                else
                {
                    r.Add(ValidationRule.Policy, RuleOutcome.Pass, tree.IsNull ? "no policy is required" : "policy tree is not empty", "RFC 5280 §6.1.3 (d)–(f)");
                }
            }

            if (!last)
            {
                PrepareForNext(v, r, i, tree, ref policyMapping, ref explicitPolicy, ref inhibitAny, ref maxPathLength, nc, policyOverflow);
            }

            // §6.1.4 (o) / §6.1.5 (f)
            string? crit = v.UnrecognisedCritical();
            if (crit is null)
            {
                r.Pass(ValidationRule.CriticalExtension, "every critical extension is recognised", "RFC 5280 §6.1.4 (o)");
            }
            else
            {
                r.Fail(ValidationRule.CriticalExtension, $"critical extension {crit} is not recognised", "RFC 5280 §4.2; §6.1.4 (o)");
            }

            CheckRequiredEku(v, r);

            if (last)
            {
                TargetChecks(v, r, false);
            }

            // §6.3 / RFC 6960 for this certificate, against its issuer.
            RevocationScope scope = _o.RevocationRequired;
            bool required = scope == RevocationScope.AllCertificates || (scope == RevocationScope.EndEntity && last);
            Certificate? issuerCert = i == 1 ? anchor.Certificate : certs[i - 2];
            bool hasData = _o.Revocation is not null;
            if (required || hasData)
            {
                r.Revocation = CheckRevocation(v, new IssuerInfo(issuerName, issuerKey, issuerCert, i == 1 ? anchorView : View(certs[i - 2])), certs, anchor, i - 1);
                AddRevocationResult(r, r.Revocation, required);
            }

            workingKey = cert.PublicKey;
            workingIssuer = cert.Subject;
        }

        // §6.1.5: wrap-up.
        CertView lastView = View(certs[n - 1]);
        if (explicitPolicy != 0)
        {
            explicitPolicy--;
        }

        if (lastView.PolicyConstraints?.RequireExplicitPolicy == 0)
        {
            explicitPolicy = 0;
        }

        ImmutableArray<string> acps = [];
        if (!policyOverflow)
        {
            acps = tree.Finish(n, _o.InitialPolicySet);
            bool ok = explicitPolicy > 0 || !tree.IsNull;
            policyReport = new PolicyReport(true, explicitPolicy == 0, acps, tree.IsNull);
            if (!ok)
            {
                res[n - 1].Fail(ValidationRule.Policy, "an explicit policy is required and no acceptable policy remains at the end of the path", "RFC 5280 §6.1.5 (g)");
            }
        }

        return Build(res, certs, anchor, pathResults, policyReport, false);
    }

    private void CheckAnchor(CertView a, List<RuleResult> path, int n, ref int maxPathLength, NameConstraintState nc, ref int explicitPolicy, ref int policyMapping, ref int inhibitAny, bool targetIsAnchor)
    {
        if (_o.CheckAnchorValidity)
        {
            if (RefSecond < a.Cert.NotBefore || RefSecond > a.Cert.NotAfter)
            {
                path.Add(new RuleResult(ValidationRule.TrustAnchor, RuleOutcome.Fail, "the trust anchor certificate is not valid at the reference time", "RFC 5937 §3.1; RFC 5280 §6.1.3 (a)(2)"));
            }
            else
            {
                path.Add(new RuleResult(ValidationRule.TrustAnchor, RuleOutcome.Pass, "the trust anchor certificate is valid at the reference time", "RFC 5937 §3.1"));
            }
        }

        if (targetIsAnchor)
        {
            return;
        }

        var tmp = new CertResults();
        StructureChecks(a, tmp, false, true);
        WebPkiCertificate(a, tmp, true);
        string? crit = a.UnrecognisedCritical();
        if (crit is not null && _o.StrictStructure)
        {
            tmp.Fail(ValidationRule.CriticalExtension, $"the trust anchor has critical extension {crit}, which is not recognised", "RFC 5280 §4.2; RFC 5937 §3.1");
        }

        foreach (RuleResult x in tmp.List)
        {
            if (x.Outcome == RuleOutcome.Fail)
            {
                path.Add(x with { Reason = "trust anchor: " + x.Reason });
            }
        }

        if (targetIsAnchor)
        {
            return;
        }

        if (a.KeyUsage is { } ku && (ku.Usages & KeyUsages.KeyCertSign) == 0)
        {
            path.Add(new RuleResult(ValidationRule.KeyUsage, RuleOutcome.Fail, "the trust anchor's keyUsage lacks keyCertSign", "RFC 5280 §4.2.1.3"));
        }

        if (a.BasicConstraints is { IsCA: false })
        {
            path.Add(new RuleResult(ValidationRule.BasicConstraints, RuleOutcome.Fail, "the trust anchor certificate says it is not a CA", "RFC 5280 §4.2.1.9"));
        }

        if (a.BasicConstraints?.PathLengthConstraint is int p && p < maxPathLength)
        {
            maxPathLength = p;
        }

        if (_o.ApplyAnchorNameConstraints && a.NameConstraints is { } anc)
        {
            nc.Add(anc, a.Ext.IsCritical(KnownOids.NameConstraints) == true);
        }

        if (_o.ApplyAnchorPolicyConstraints)
        {
            if (a.PolicyConstraints?.RequireExplicitPolicy is int re && re < explicitPolicy)
            {
                explicitPolicy = re;
            }

            if (a.PolicyConstraints?.InhibitPolicyMapping is int im && im < policyMapping)
            {
                policyMapping = im;
            }

            if (a.InhibitAnyPolicy is { } ia && ia.SkipCerts < inhibitAny)
            {
                inhibitAny = ia.SkipCerts;
            }
        }
    }

    private void PrepareForNext(CertView v, CertResults r, int i, PolicyTree tree, ref int policyMapping, ref int explicitPolicy, ref int inhibitAny, ref int maxPathLength, NameConstraintState nc, bool policyOverflow)
    {
        // 6.1.4 (a), (b)
        if (v.Mappings is { } policyMappings)
        {
            if (policyMappings.Mappings.Any(m => m.IssuerDomainPolicy == KnownOids.AnyPolicy || m.SubjectDomainPolicy == KnownOids.AnyPolicy))
            {
                r.Fail(ValidationRule.Policy, "a policy mapping involves anyPolicy", "RFC 5280 §4.2.1.5");
            }
            else if (!policyOverflow)
            {
                tree.ApplyMappings(i, policyMappings, policyMapping > 0);
                if (tree.Overflowed)
                {
                    r.Fail(ValidationRule.Policy, $"the policy tree grew beyond {_l.MaxPolicyNodes} nodes; processing stopped", "RFC 5280 §6.1.4 (b); bounded against policy-tree explosion");
                }
            }
        }

        // (g)
        if (v.NameConstraints is { } ncv)
        {
            nc.Add(ncv, v.Ext.IsCritical(KnownOids.NameConstraints) == true);
        }

        // (h)
        if (!v.SelfIssued)
        {
            if (explicitPolicy != 0)
            {
                explicitPolicy--;
            }

            if (policyMapping != 0)
            {
                policyMapping--;
            }

            if (inhibitAny != 0)
            {
                inhibitAny--;
            }
        }

        // (i), (j)
        if (v.PolicyConstraints is { } pc)
        {
            if (pc.RequireExplicitPolicy is int re && re < explicitPolicy)
            {
                explicitPolicy = re;
            }

            if (pc.InhibitPolicyMapping is int ip && ip < policyMapping)
            {
                policyMapping = ip;
            }
        }

        if (v.InhibitAnyPolicy is { } ia && ia.SkipCerts < inhibitAny)
        {
            inhibitAny = ia.SkipCerts;
        }

        // (k)
        if (v.BasicConstraints is { IsCA: true })
        {
            r.Pass(ValidationRule.BasicConstraints, "basicConstraints asserts cA", "RFC 5280 §6.1.4 (k)");
        }
        else
        {
            r.Fail(ValidationRule.BasicConstraints, v.BasicConstraints is null ? "an issuing certificate lacks basicConstraints" : "an issuing certificate has cA false", "RFC 5280 §6.1.4 (k); §4.2.1.9");
        }

        // (l), (m)
        if (!v.SelfIssued)
        {
            if (maxPathLength <= 0)
            {
                r.Fail(ValidationRule.PathLengthConstraint, "the path is longer than a pathLenConstraint above allows", "RFC 5280 §6.1.4 (l)");
            }
            else
            {
                maxPathLength--;
            }
        }

        if (v.BasicConstraints?.PathLengthConstraint is int plc)
        {
            if (!v.IsCa)
            {
                r.Fail(ValidationRule.PathLengthConstraint, "pathLenConstraint without cA", "RFC 5280 §4.2.1.9");
            }
            else if (plc < maxPathLength)
            {
                maxPathLength = plc;
            }
        }

        // (n)
        if (v.KeyUsage is { } ku)
        {
            if ((ku.Usages & KeyUsages.KeyCertSign) == 0)
            {
                r.Fail(ValidationRule.KeyUsage, "keyUsage lacks keyCertSign", "RFC 5280 §6.1.4 (n); §4.2.1.3");
            }
            else
            {
                r.Pass(ValidationRule.KeyUsage, "keyUsage includes keyCertSign", "RFC 5280 §6.1.4 (n)");
            }
        }
        else
        {
            r.Add(ValidationRule.KeyUsage, RuleOutcome.NotApplicable, "no keyUsage extension", "RFC 5280 §6.1.4 (n)");
        }
    }

    private void TargetChecks(CertView v, CertResults r, bool isAnchor)
    {
        if (_o.RequiredKeyUsage != KeyUsages.None)
        {
            if (v.KeyUsage is { } ku)
            {
                if ((ku.Usages & _o.RequiredKeyUsage) == _o.RequiredKeyUsage)
                {
                    r.Pass(ValidationRule.KeyUsage, "keyUsage includes the required usage", "RFC 5280 §4.2.1.3");
                }
                else
                {
                    r.Fail(ValidationRule.KeyUsage, $"keyUsage {ku.Usages} lacks the required {_o.RequiredKeyUsage}", "RFC 5280 §4.2.1.3");
                }
            }
        }

        if (_o.WebPki is { } wp)
        {
            WebPkiTarget(v, r, wp);
        }
    }

    private void AddRevocationResult(CertResults r, RevocationReport rep, bool required)
    {
        switch (rep.Status)
        {
            case RevocationStatus.Revoked:
                r.Fail(ValidationRule.Revocation, rep.Reason, rep.Clause);
                break;
            case RevocationStatus.Unknown:
                if (required && _o.UnknownRevocationIsFatal)
                {
                    r.Add(ValidationRule.Revocation, RuleOutcome.Indeterminate, rep.Reason, rep.Clause);
                }
                else
                {
                    r.Add(ValidationRule.Revocation, RuleOutcome.Warning, "revocation status unknown: " + rep.Reason, rep.Clause);
                }

                break;
            case RevocationStatus.Good:
                r.Pass(ValidationRule.Revocation, rep.Reason, rep.Clause);
                break;
        }
    }

    private static PathReport Build(CertResults[] res, Certificate[] certs, TrustAnchor anchor, List<RuleResult> pathResults, PolicyReport policy, bool targetIsAnchor)
    {
        int n = certs.Length;
        var reports = new List<CertificateReport>(n);
        RuleResult? deciding = null;
        int decidingIndex = -1;

        // Path-level failures (anchor rules) decide first.
        foreach (RuleResult p in pathResults)
        {
            if (p.Outcome == RuleOutcome.Fail && deciding is null)
            {
                deciding = p;
            }
        }

        for (int i = 0; i < n; i++)
        {
            reports.Add(new CertificateReport(certs[i], i, targetIsAnchor, [.. res[i].List], res[i].Revocation));
            foreach (RuleResult x in res[i].List)
            {
                if (x.Outcome == RuleOutcome.Fail && (deciding is null || deciding.Outcome != RuleOutcome.Fail))
                {
                    deciding = x;
                    decidingIndex = i;
                }
                else if (x.Outcome == RuleOutcome.Indeterminate)
                {
                    if (deciding is null)
                    {
                        deciding = x;
                        decidingIndex = i;
                    }
                }
            }
        }

        // Path-level failures name no certificate; give them the certificate nearest the anchor.
        if (deciding is not null && deciding.Outcome == RuleOutcome.Fail && decidingIndex < 0)
        {
            decidingIndex = 0;
        }

        ValidationVerdict verdict = deciding is null ? ValidationVerdict.Valid : deciding.Outcome == RuleOutcome.Fail ? ValidationVerdict.Invalid : ValidationVerdict.Indeterminate;
        return new PathReport(
            [.. reports],
            anchor.Certificate,
            anchor.Name.ToString(),
            verdict,
            deciding,
            decidingIndex,
            policy,
            [.. pathResults]);
    }

}
