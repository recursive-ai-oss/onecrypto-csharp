using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto.Validation;

/// <summary>The issuer of a certificate in a path, as far as revocation needs it.</summary>
internal sealed record IssuerInfo(DistinguishedName Name, PublicKeyInfo Key, Certificate? Cert, CertView? View);

internal sealed partial class Engine
{
    private const RevocationReasons AllReasons = (RevocationReasons)0x1FE;

    // The algorithm-policy decisions about revocation data seen while checking one certificate, and the reasons data was not used. Both end up in the
    // certificate's RevocationReport.
    private readonly List<PolicyDecision> _revPolicy = [];
    private readonly List<string> _revNotes = [];

    private sealed record Finding(RevocationStatus Status, string Reason, string Clause, string? Source, DateTimeOffset? Time = null, RevocationReason? RevReason = null);

    private RevocationReport CheckRevocation(CertView v, IssuerInfo issuer, Certificate[] path, TrustAnchor anchor, int index)
    {
        _revPolicy.Clear();
        RevocationData? data = _o.Revocation;
        if (data is null || (data.Crls.Count == 0 && data.OcspResponses.Count == 0))
        {
            return new RevocationReport(RevocationStatus.Unknown, "no revocation data was supplied for this certificate", "RFC 5280 §6.3");
        }

        var notes = _revNotes;
        notes.Clear();
        Finding? crl = CheckCrls(v, issuer, path, anchor, data, notes);
        Finding? ocsp = CheckOcsp(v, issuer, path, anchor, data, notes);
        Finding? pick = crl is { Status: RevocationStatus.Revoked } ? crl
            : ocsp is { Status: RevocationStatus.Revoked } ? ocsp
            : ocsp is { Status: RevocationStatus.Good } ? ocsp
            : crl is { Status: RevocationStatus.Good } ? crl
            : null;
        if (pick is not null)
        {
            return new RevocationReport(pick.Status, pick.Reason, pick.Clause, pick.Time, pick.RevReason, pick.Source) { Notes = [.. notes], PolicyDecisions = [.. _revPolicy] };
        }

        string why = notes.Count == 0 ? "no applicable CRL or OCSP response" : string.Join("; ", notes.Take(4));
        return new RevocationReport(RevocationStatus.Unknown, why, "RFC 5280 §6.3.3; RFC 6960 §3.2") { Notes = [.. notes], PolicyDecisions = [.. _revPolicy] };
    }

    private static readonly HashSet<string> KnownCrlExtensions = new(StringComparer.Ordinal)
    {
        KnownOids.AuthorityKeyIdentifier, KnownOids.IssuerAltName, KnownOids.CrlNumber, KnownOids.DeltaCrlIndicator,
        KnownOids.IssuingDistributionPoint, KnownOids.FreshestCrl, KnownOids.AuthorityInfoAccess,
    };

    private static RevocationReasons BitOf(RevocationReason? r) => r switch
    {
        RevocationReason.KeyCompromise => RevocationReasons.KeyCompromise,
        RevocationReason.CACompromise => RevocationReasons.CACompromise,
        RevocationReason.AffiliationChanged => RevocationReasons.AffiliationChanged,
        RevocationReason.Superseded => RevocationReasons.Superseded,
        RevocationReason.CessationOfOperation => RevocationReasons.CessationOfOperation,
        RevocationReason.CertificateHold => RevocationReasons.CertificateHold,
        RevocationReason.PrivilegeWithdrawn => RevocationReasons.PrivilegeWithdrawn,
        RevocationReason.AACompromise => RevocationReasons.AACompromise,
        _ => RevocationReasons.None,
    };

    // ---------------------------------------------------------------- CRLs (RFC 5280 §6.3)

    private Finding? CheckCrls(CertView v, IssuerInfo issuer, Certificate[] path, TrustAnchor anchor, RevocationData data, List<string> notes)
    {
        RevocationReasons covered = RevocationReasons.None;
        int examined = 0;
        foreach (CertificateRevocationList crl in data.Crls)
        {
            if (crl.IsDelta)
            {
                continue;
            }

            if (++examined > _l.MaxRevocationObjectsPerCertificate)
            {
                _limit = true;
                break;
            }

            RevocationReasons coverage = Applicable(v, issuer, crl, out string? why);
            if (coverage == RevocationReasons.None)
            {
                notes.Add($"a CRL from {crl.Issuer} does not apply: {why}");
                continue;
            }

            if (!UsableCrl(crl, issuer, path, anchor, out PublicKeyInfo? signerKey, out string? bad, out bool stale) || signerKey is null)
            {
                notes.Add($"a CRL from {crl.Issuer} is not usable: {bad}");
                continue;
            }

            if (stale)
            {
                // RFC 5280 §6.3.3 (a) wants a current CRL, so a stale one cannot show a certificate is good. What it can still show is a revocation that
                // nothing undoes: §5.3.1 makes every reason except certificateHold final, so a stale but authentic CRL that lists the certificate
                // for another reason is as good as a current one for that purpose. A hold may have been lifted since, so it is not relied on.
                Finding? old = StatusIn(v, crl, null, coverage);
                if (old is { Status: RevocationStatus.Revoked } && old.RevReason != RevocationReason.CertificateHold)
                {
                    return old with { Reason = old.Reason + $"; the CRL is stale (nextUpdate {crl.NextUpdate:u}) but a revocation for this reason is permanent" };
                }

                notes.Add(old is { Status: RevocationStatus.Revoked }
                    ? $"a stale CRL (nextUpdate {crl.NextUpdate:u}) from {crl.Issuer} lists the certificate on hold; the hold may since have been lifted, so it is not relied on"
                    : $"a CRL from {crl.Issuer} is stale (nextUpdate {crl.NextUpdate:u}) and does not list the certificate");
                continue;
            }

            // Delta CRLs refine a complete CRL (§5.2.4, §6.3.3 (c)–(d)).
            CertificateRevocationList? delta = FindDelta(crl, data, signerKey, notes);
            Finding? f = StatusIn(v, crl, delta, coverage);
            if (f is { Status: RevocationStatus.Revoked })
            {
                return f;
            }

            if (_o.RevocationModel == RevocationModel.PastTime && crl.ThisUpdate < _o.ReferenceTime)
            {
                notes.Add($"a CRL from {crl.Issuer} was issued before the reference time and cannot show the certificate was not revoked then");
                continue;
            }

            covered |= coverage;
            if (f is { Status: RevocationStatus.Good } && (covered & AllReasons) == AllReasons)
            {
                return f with { Reason = "no applicable CRL lists the certificate, and the CRLs together cover every revocation reason" };
            }
        }

        if (covered != RevocationReasons.None && (covered & AllReasons) != AllReasons)
        {
            notes.Add("the usable CRLs do not cover every revocation reason");
        }

        return null;
    }

    private static RevocationReasons Applicable(CertView v, IssuerInfo issuer, CertificateRevocationList crl, out string? why)
    {
        why = null;
        IssuingDistributionPoint? idp;
        try
        {
            idp = crl.IssuingDistributionPoint;
        }
        catch (X509ParseException)
        {
            why = "issuingDistributionPoint is malformed";
            return RevocationReasons.None;
        }

        bool direct = crl.Issuer.Matches(v.Cert.Issuer);
        if (idp?.OnlyContainsAttributeCerts == true)
        {
            why = "it covers attribute certificates only";
            return RevocationReasons.None;
        }

        if (idp?.OnlyContainsUserCerts == true && v.IsCa)
        {
            why = "it covers end-entity certificates only";
            return RevocationReasons.None;
        }

        if (idp?.OnlyContainsCACerts == true && !v.IsCa)
        {
            why = "it covers CA certificates only";
            return RevocationReasons.None;
        }

        if (!direct && idp?.IndirectCrl != true)
        {
            why = "its issuer is not the certificate's issuer and it is not an indirect CRL";
            return RevocationReasons.None;
        }

        IReadOnlyList<DistributionPoint>? dps = v.CrlDistributionPoints?.Points;
        RevocationReasons dpReasons = AllReasons;
        if (dps is null || dps.Count == 0)
        {
            if (!direct)
            {
                why = "the certificate names no CRL issuer other than its own";
                return RevocationReasons.None;
            }

            if (idp?.DistributionPoint is not null)
            {
                why = "the CRL is scoped to a distribution point the certificate does not name";
                return RevocationReasons.None;
            }
        }
        else
        {
            DistributionPoint? match = null;
            foreach (DistributionPoint dp in dps)
            {
                if (DpMatches(v, dp, idp, crl, direct))
                {
                    match = dp;
                    break;
                }
            }

            if (match is null)
            {
                why = "no distribution point of the certificate matches the CRL's issuingDistributionPoint";
                return RevocationReasons.None;
            }

            dpReasons = match.Reasons ?? AllReasons;
        }

        RevocationReasons cov = dpReasons & (idp?.OnlySomeReasons ?? AllReasons) & AllReasons;
        if (cov == RevocationReasons.None)
        {
            why = "its reason scope is disjoint from the certificate's";
        }

        return cov;
    }

    private static bool DpMatches(CertView v, DistributionPoint dp, IssuingDistributionPoint? idp, CertificateRevocationList crl, bool direct)
    {
        if (dp.CrlIssuer is { Count: > 0 } issuers)
        {
            bool named = false;
            foreach (GeneralName g in issuers)
            {
                if (g.Kind == GeneralNameKind.DirectoryName)
                {
                    try
                    {
                        if (g.DirectoryName?.Matches(crl.Issuer) == true)
                        {
                            named = true;
                        }
                    }
                    catch (X509ParseException)
                    {
                    }
                }
            }

            if (!named)
            {
                return false;
            }
        }
        else if (!direct)
        {
            return false;
        }

        if (idp?.DistributionPoint is not { } iname)
        {
            return true;
        }

        if (dp.Name is not { } dname)
        {
            return false;
        }

        return DpNamesIntersect(dname, iname, crl.Issuer, dp.CrlIssuer);
    }

    private static bool DpNamesIntersect(DistributionPointName a, DistributionPointName b, DistinguishedName crlIssuer, IReadOnlyList<GeneralName>? dpCrlIssuer)
    {
        if (a.FullName is not null && b.FullName is not null)
        {
            return a.FullName.Any(x => b.FullName.Any(y => x.Equals(y) || NamesEqual(x, y)));
        }

        if (a.FullName is null && b.FullName is null)
        {
            return a.RelativeName.Span.SequenceEqual(b.RelativeName.Span);
        }

        // One is a name relative to the CRL issuer: complete it with the issuer's name (§4.2.1.13).
        DistributionPointName full = a.FullName is not null ? a : b;
        DistributionPointName rel = a.FullName is null ? a : b;
        foreach (GeneralName g in full.FullName!)
        {
            if (g.Kind != GeneralNameKind.DirectoryName)
            {
                continue;
            }

            try
            {
                DistinguishedName? dn = g.DirectoryName;
                if (dn is null)
                {
                    continue;
                }

                var parts = new List<byte[]>();
                foreach (RelativeDistinguishedName r in crlIssuer.Rdns)
                {
                    parts.Add(r.Encoded.ToArray());
                }

                parts.Add(Asn1.DerWriter.Tlv(0x31, rel.RelativeName.ToArray()));
                DistinguishedName built = DistinguishedName.Parse(Asn1.DerWriter.Sequence([.. parts]));
                if (built.Matches(dn))
                {
                    return true;
                }
            }
            catch (X509ParseException)
            {
            }
        }

        return false;
    }

    private static bool NamesEqual(GeneralName x, GeneralName y)
    {
        if (x.Kind != y.Kind)
        {
            return false;
        }

        if (x.Kind == GeneralNameKind.DirectoryName)
        {
            try
            {
                return x.DirectoryName?.Matches(y.DirectoryName) == true;
            }
            catch (X509ParseException)
            {
                return false;
            }
        }

        return x.Value is not null && string.Equals(x.Value, y.Value, StringComparison.OrdinalIgnoreCase);
    }

    private bool UsableCrl(CertificateRevocationList crl, IssuerInfo issuer, Certificate[] path, TrustAnchor anchor, out PublicKeyInfo? signerKey, out string? why, out bool stale)
    {
        signerKey = null;
        why = null;
        stale = false;
        foreach (Extension e in crl.Extensions)
        {
            if (e.Critical && !KnownCrlExtensions.Contains(e.Oid))
            {
                why = $"critical CRL extension {e.Oid} is not recognised";
                return false;
            }
        }

        if (crl.Extensions.HasDuplicates)
        {
            why = "a CRL extension appears more than once";
            return false;
        }

        if (CriticalEntryExtension(crl) is { } entryExt)
        {
            why = entryExt;
            return false;
        }

        if (_o.StrictStructure)
        {
            // RFC 5280 §5.2.3: cRLNumber is mandatory and never critical. §5.3: a serial number is listed once.
            Extension? number = crl.Extensions.Find(KnownOids.CrlNumber);
            if (number is null || number.Critical)
            {
                why = number is null ? "the CRL has no cRLNumber" : "cRLNumber is marked critical";
                return false;
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (RevokedCertificate e in crl.Entries)
            {
                if (!seen.Add(Convert.ToHexString(e.SerialNumber.Span)) && !crl.IsIndirect)
                {
                    why = "the CRL lists a serial number twice";
                    return false;
                }
            }
        }

        // Freshness at the revocation-data time (§6.3.3 (a)(1)); §5.1.2.5 makes nextUpdate mandatory.
        if (crl.ThisUpdate > DataTime)
        {
            why = $"thisUpdate {crl.ThisUpdate:u} is after the time the data is judged at";
            return false;
        }

        if (crl.NextUpdate is not { } next)
        {
            why = "the CRL has no nextUpdate";
            return false;
        }

        // A stale CRL is still authenticated below (only then may it be read at all); the caller decides what a stale CRL can show.
        stale = next < DataTime;

        // Find the signer.
        bool direct = crl.Issuer.Matches(issuer.Name);
        if (direct)
        {
            // The issuing certificate may be the CRL signer; when its keyUsage rules that out, or its key does not verify the CRL,
            // another certificate of the same name may hold the CRL signing key (RFC 5280 §6.3.3 (f), PKITS 4.4.19).
            if (issuer.View?.KeyUsage is { } ku && (ku.Usages & KeyUsages.CrlSign) == 0)
            {
                why = "the issuing certificate's keyUsage lacks cRLSign";
            }
            else
            {
                SignatureVerification sv = VerifyCrl(crl, issuer.Key);
                if (sv.IsValid)
                {
                    string? refused = PkiSignaturePolicy(crl.SignatureAlgorithm, issuer.Key, "CRL");
                    if (refused is null)
                    {
                        signerKey = issuer.Key;
                        return true;
                    }

                    why = refused;
                }
                else
                {
                    why = "signature does not verify with the issuing certificate's key: " + sv.Reason;
                }
            }
        }

        // An indirect CRL or a separate CRL signer: its certificate must itself be valid (§6.3.3 (f)).
        var candidates = new List<Certificate>(_st.PoolBySubject(crl.Issuer));
        candidates.AddRange(path);
        if (anchor.Certificate is not null)
        {
            candidates.Add(anchor.Certificate);
        }
        foreach (Certificate c in candidates)
        {
            if (!c.Subject.Matches(crl.Issuer))
            {
                continue;
            }

            if (!VerifyCrl(crl, c.PublicKey).IsValid)
            {
                continue;
            }

            CertView cv = View(c);
            if (cv.KeyUsage is { } ku2 && (ku2.Usages & KeyUsages.CrlSign) == 0)
            {
                why = "the CRL signer's keyUsage lacks cRLSign";
                continue;
            }

            if (PkiSignaturePolicy(crl.SignatureAlgorithm, c.PublicKey, "CRL") is { } refusedBySigner)
            {
                why = refusedBySigner;
                continue;
            }

            // RFC 5280 §6.3.3 (f): the signer's certificate must itself be valid, and that includes its validity period. Checking it first spares a nested
            // path search for the expired reissues of a signing key that a pool of old certificates holds.
            if (RefSecond < c.NotBefore || RefSecond > c.NotAfter)
            {
                why = "the CRL signer's certificate is not valid at the reference time";
                continue;
            }

            string? bad = ValidateSigner(c, anchor);
            if (bad is null)
            {
                signerKey = c.PublicKey;
                return true;
            }

            why = "the CRL signer's certificate is not valid: " + bad;
        }

        why ??= "no certificate that verifies the CRL's signature was found";
        return false;
    }

    // RFC 5280 §5.3: a CRL with a critical entry extension the application cannot process must not be used for any certificate, listed or not.
    private static string? CriticalEntryExtension(CertificateRevocationList crl)
    {
        try
        {
            foreach (RevokedCertificate entry in crl.Entries)
            {
                foreach (Extension e in entry.Extensions)
                {
                    if (e.Critical && e.Oid is not (KnownOids.CrlReason or KnownOids.InvalidityDate or KnownOids.CertificateIssuer))
                    {
                        return $"critical CRL entry extension {e.Oid} is not recognised";
                    }
                }
            }
        }
        catch (X509ParseException)
        {
            return "a CRL entry is malformed";
        }

        return null;
    }

    // RFC 5280 §6.3.3 (f): the CRL signer's path must end at the trust anchor of the certificate's own path, so the sub-validation trusts that anchor alone.
    // Otherwise any other trusted root could certify a key for the CA's name and vouch for the CA's certificates.
    private string? ValidateSigner(Certificate signer, TrustAnchor anchor)
    {
        // One answer per signer, anchor and nesting depth for the whole validation: a pool holding many certificates for the signing key would otherwise
        // be validated again from every nested level.
        var key = (signer, anchor, _depth);
        if (_st.SignerCache.TryGetValue(key, out string? cached))
        {
            return cached;
        }

        if (_st.SignerValidations >= _l.MaxSignerValidations)
        {
            _limit = true;
            return $"the limit of {_l.MaxSignerValidations} CRL signer validations was reached";
        }

        _st.SignerValidations++;
        _st.SignerCache[key] = "validation of this signer is in progress";
        var sub = new ValidationOptions
        {
            TrustAnchors = [anchor],
            Intermediates = _o.Intermediates,
            ReferenceTime = _o.ReferenceTime,
            Policy = _o.Policy,
            ApplyAnchorNameConstraints = _o.ApplyAnchorNameConstraints,
            CheckAnchorValidity = _o.CheckAnchorValidity,
            StrictStructure = false,
            Limits = _l,
            // The signer's own status matters (PKITS 4.4.21), but its CRLs are not chased further than a few levels.
            Revocation = _depth < 3 ? _o.Revocation : null,
            RevocationRequired = _depth < 3 ? _o.RevocationRequired : RevocationScope.None,
            UnknownRevocationIsFatal = _depth < 3 && _o.UnknownRevocationIsFatal,
            RevocationModel = _o.RevocationModel,
            RevocationDataTime = _o.RevocationDataTime,
        };
        var engine = new Engine(sub, _depth + 1, _st);
        ValidationReport rep = engine.Run(signer);
        if (engine.LimitReached)
        {
            _limit = true;
        }

        string? result = rep.IsValid ? null : rep.DecidingRule?.Reason ?? "no path to a trust anchor";
        _st.SignerCache[key] = result;
        return result;
    }

    // The algorithm policy for the signature on a CRL or OCSP response: the same question, with the same rule ids, as for a certificate's signature
    // (a PKI signature, so SHA-1 is judged by the PKI cutoff). Findings go to the certificate's RevocationReport; a refusal returns the reason.
    private string? PkiSignaturePolicy(AlgorithmIdentifier algorithm, PublicKeyInfo signerKey, string what)
    {
        Policy.PolicyReport pr = _o.Policy.CheckSignature(algorithm, signerKey, CryptoUse.VerifyPki, DataTime);
        PolicyDecision? refused = null;
        foreach (PolicyDecision d in pr.Findings)
        {
            if (!_revPolicy.Contains(d))
            {
                _revPolicy.Add(d);
            }

            if (d.Verdict == PolicyVerdict.Rejected)
            {
                refused ??= d;
            }
        }

        return refused is { } r ? $"the {what} signature is refused by the {_o.Policy.Name} policy ({r.Rule}): {r.Reason}" : null;
    }

    private CertificateRevocationList? FindDelta(CertificateRevocationList baseCrl, RevocationData data, PublicKeyInfo signerKey, List<string> notes)
    {
        System.Numerics.BigInteger? baseNo = baseCrl.Number;
        CertificateRevocationList? best = null;
        foreach (CertificateRevocationList d in data.Crls)
        {
            if (!d.IsDelta || !d.Issuer.Matches(baseCrl.Issuer))
            {
                continue;
            }

            System.Numerics.BigInteger? dNo = d.Number;
            System.Numerics.BigInteger? dBase = d.BaseNumber;
            if (baseNo is null || dNo is null || dBase is null || dBase > baseNo || dNo <= baseNo)
            {
                continue;
            }

            Extension? i1 = baseCrl.Extensions.Find(KnownOids.IssuingDistributionPoint);
            Extension? i2 = d.Extensions.Find(KnownOids.IssuingDistributionPoint);
            if ((i1 is null) != (i2 is null) || (i1 is not null && !i1.Value.Span.SequenceEqual(i2!.Value.Span)))
            {
                continue;
            }

            if (d.ThisUpdate > DataTime || d.NextUpdate is not { } n || n < DataTime)
            {
                notes.Add("a delta CRL is not current");
                continue;
            }

            if (d.Extensions.Any(e => e.Critical && !KnownCrlExtensions.Contains(e.Oid)) || CriticalEntryExtension(d) is not null || !VerifyCrl(d, signerKey).IsValid
                || PkiSignaturePolicy(d.SignatureAlgorithm, signerKey, "delta CRL") is not null)
            {
                notes.Add("a delta CRL failed its checks");
                continue;
            }

            if (best is null || dNo > best.Number)
            {
                best = d;
            }
        }

        return best;
    }

    private Finding? StatusIn(CertView v, CertificateRevocationList crl, CertificateRevocationList? delta, RevocationReasons coverage)
    {
        RevokedCertificate? entry = FindEntry(v, crl);
        RevokedCertificate? dentry = delta is null ? null : FindEntry(v, delta);
        string src = "CRL";
        if (dentry is not null)
        {
            // §5.3.1: removeFromCRL in a delta CRL takes a certificate off the hold the base CRL put it on.
            // RFC 5280 §5.3.1 defines removeFromCRL only for a certificate that was on hold, so a delta cannot lift any other revocation.
            entry = dentry.Reason == RevocationReason.RemoveFromCrl ? (entry?.Reason == RevocationReason.CertificateHold ? null : entry) : dentry;
        }

        if (entry is null)
        {
            return new Finding(RevocationStatus.Good, "not listed", "RFC 5280 §6.3.3", src);
        }

        // RFC 5280 §6.3.3 (i)-(j): a certificate found on the CRL takes the entry's status whatever its reason. The CRL's reason scope
        // (onlySomeReasons) only decides which reasons the CRL speaks for when it does NOT list the certificate.
        RevocationReason? reason = entry.Reason;
        DateTimeOffset when = entry.RevocationDate;
        if (_o.RevocationModel == RevocationModel.PastTime && when > _o.ReferenceTime && !CompromiseReason(reason))
        {
            return new Finding(RevocationStatus.Good, $"revoked at {when:u}, after the reference time, for a reason that does not reach back (past-time model)", "ETSI EN 319 102-1 §5.6.2.1", src);
        }

        string why = $"listed on a CRL as revoked at {when:u}" + (reason is { } r ? $", reason {r}" : string.Empty);
        return new Finding(RevocationStatus.Revoked, why, "RFC 5280 §6.3.3", src, when, reason);
    }

    private static bool CompromiseReason(RevocationReason? r) =>
        r is null or RevocationReason.Unspecified or RevocationReason.KeyCompromise or RevocationReason.CACompromise or RevocationReason.AACompromise;

    private static RevokedCertificate? FindEntry(CertView v, CertificateRevocationList crl)
    {
        if (!crl.IsIndirect)
        {
            // Serial numbers are integers (a negative one is legal in a CRL), so "FF" and "00FF" are different numbers.
            RevokedCertificate? hit = crl.Find(v.Cert.SerialNumber.Span);
            if (hit is null || hit.SerialNumberValue == v.Cert.SerialNumberValue)
            {
                return hit;
            }

            return crl.Entries.FirstOrDefault(e => e.SerialNumberValue == v.Cert.SerialNumberValue);
        }

        DistinguishedName current = crl.Issuer;
        foreach (RevokedCertificate e in crl.Entries)
        {
            if (e.CertificateIssuer is { } names)
            {
                foreach (GeneralName g in names)
                {
                    if (g.Kind == GeneralNameKind.DirectoryName)
                    {
                        try
                        {
                            current = g.DirectoryName ?? current;
                        }
                        catch (X509ParseException)
                        {
                        }

                        break;
                    }
                }
            }

            if (current.Matches(v.Cert.Issuer) && e.SerialNumberValue == v.Cert.SerialNumberValue)
            {
                return e;
            }
        }

        return null;
    }

    // ---------------------------------------------------------------- OCSP (RFC 6960)

    private Finding? CheckOcsp(CertView v, IssuerInfo issuer, Certificate[] path, TrustAnchor anchor, RevocationData data, List<string> notes)
    {
        Finding? good = null;
        int examined = 0;
        foreach (OcspBasicResponse resp in data.OcspResponses)
        {
            if (++examined > _l.MaxRevocationObjectsPerCertificate)
            {
                _limit = true;
                break;
            }

            foreach (OcspSingleResponse s in resp.Responses)
            {
                if (!CertIdMatches(s.CertId, v.Cert, issuer))
                {
                    continue;
                }

                PublicKeyInfo? key = AuthoriseResponder(resp, issuer, path, anchor, data, out string? why);
                if (key is null)
                {
                    notes.Add("an OCSP response is not usable: " + why);
                    continue;
                }

                SignatureVerification sv = VerifyOcsp(resp, key);
                if (!sv.IsValid)
                {
                    notes.Add("an OCSP response signature does not verify: " + sv.Reason);
                    continue;
                }

                if (PkiSignaturePolicy(resp.SignatureAlgorithm, key, "OCSP response") is { } refused)
                {
                    notes.Add("an OCSP response is not usable: " + refused);
                    continue;
                }

                // RFC 6960 §3.2 (5): thisUpdate must not be in the future; the response is current until nextUpdate.
                if (s.ThisUpdate > DataTime)
                {
                    notes.Add($"an OCSP response is not yet valid (thisUpdate {s.ThisUpdate:u})");
                    continue;
                }

                DateTimeOffset until = s.NextUpdate ?? s.ThisUpdate + _o.OcspMaxAge;
                if (until < DataTime)
                {
                    notes.Add($"an OCSP response is stale (valid until {until:u})");
                    continue;
                }

                switch (s.Status)
                {
                    case OcspCertStatus.Revoked:
                        DateTimeOffset when = s.RevocationTime ?? s.ThisUpdate;
                        if (_o.RevocationModel == RevocationModel.PastTime && when > _o.ReferenceTime && !CompromiseReason(s.RevocationReason))
                        {
                            good ??= new Finding(RevocationStatus.Good, $"revoked at {when:u}, after the reference time, for a reason that does not reach back (past-time model)", "ETSI EN 319 102-1 §5.6.2.1", "OCSP");
                            break;
                        }

                        return new Finding(RevocationStatus.Revoked, $"OCSP says revoked at {when:u}" + (s.RevocationReason is { } rr ? $", reason {rr}" : string.Empty), "RFC 6960 §2.2", "OCSP", when, s.RevocationReason);
                    case OcspCertStatus.Good:
                        if (_o.RevocationModel == RevocationModel.PastTime && s.ThisUpdate < _o.ReferenceTime)
                        {
                            notes.Add("an OCSP response predates the reference time");
                            break;
                        }

                        good ??= new Finding(RevocationStatus.Good, "OCSP says good", "RFC 6960 §2.2", "OCSP");
                        break;
                    default:
                        notes.Add("the OCSP responder does not know the certificate (status unknown)");
                        break;
                }
            }
        }

        return good;
    }

    private static bool CertIdMatches(OcspCertId id, Certificate cert, IssuerInfo issuer)
    {
        if (!SignatureAlgorithms.TryHash(id.HashAlgorithm.Oid, out HashAlgorithmName h))
        {
            return false;
        }

        ReadOnlySpan<byte> a = id.SerialNumber.Span;
        ReadOnlySpan<byte> b = cert.SerialNumber.Span;
        while (a.Length > 1 && a[0] == 0)
        {
            a = a[1..];
        }

        while (b.Length > 1 && b[0] == 0)
        {
            b = b[1..];
        }

        return a.SequenceEqual(b)
            && CryptographicOperations.HashData(h, cert.Issuer.Encoded.Span).AsSpan().SequenceEqual(id.IssuerNameHash.Span)
            && CryptographicOperations.HashData(h, issuer.Key.KeyBits.Span).AsSpan().SequenceEqual(id.IssuerKeyHash.Span);
    }

    private PublicKeyInfo? AuthoriseResponder(OcspBasicResponse resp, IssuerInfo issuer, Certificate[] path, TrustAnchor anchor, RevocationData data, out string? why)
    {
        why = null;
        OcspResponderId rid = resp.ResponderId;
        bool byIssuer = rid.Name is not null
            ? rid.Name.Matches(issuer.Name)
            : CryptographicOperations.HashData(HashAlgorithmName.SHA1, issuer.Key.KeyBits.Span).AsSpan().SequenceEqual(rid.KeyHash.Span);
        if (byIssuer)
        {
            return issuer.Key; // RFC 6960 §4.2.2.2 (1): signed by the CA that issued the certificate
        }

        foreach (Certificate t in _o.TrustedOcspResponders)
        {
            if (rid.Matches(t))
            {
                return t.PublicKey; // §4.2.2.2 (2): a responder the caller trusts directly
            }
        }

        // §4.2.2.2 (3): a delegated responder holds a certificate issued by the CA, with id-kp-OCSPSigning.
        var candidates = new List<Certificate>(resp.Certificates);
        candidates.AddRange(rid.Name is not null ? _st.PoolBySubject(rid.Name) : _st.PoolByKeyHash(rid.KeyHash.Span));
        foreach (Certificate c in candidates)
        {
            if (!rid.Matches(c))
            {
                continue;
            }

            if (!VerifyCert(c, issuer.Key).IsValid)
            {
                why = "the responder certificate was not issued by the certificate's issuer";
                continue;
            }

            if (PkiSignaturePolicy(c.SignatureAlgorithm, issuer.Key, "responder certificate") is { } refusedCert)
            {
                why = refusedCert;
                continue;
            }

            CertView cv = View(c);
            if (cv.ExtendedKeyUsage is null || !cv.ExtendedKeyUsage.Purposes.Contains(KnownOids.OcspSigning))
            {
                why = "the responder certificate lacks id-kp-OCSPSigning";
                continue;
            }

            if (DataTime < c.NotBefore || DataTime > c.NotAfter)
            {
                why = "the responder certificate is not valid at the time the response is judged";
                continue;
            }

            if (cv.KeyUsage is { } ku && (ku.Usages & (KeyUsages.DigitalSignature | KeyUsages.NonRepudiation)) == 0)
            {
                why = "the responder certificate's keyUsage does not allow signatures";
                continue;
            }

            // RFC 6960 §4.2.2.2.1: without id-pkix-ocsp-nocheck the responder certificate's own status matters. Where the supplied CRLs speak to it, they decide;
            // where nothing does, the RFC leaves trusting it to the client, which we do and say so in the report.
            if (cv.Cert.Extensions.Find(KnownOids.OcspNoCheck) is null)
            {
                var own = new List<string>();
                Finding? status = CheckCrls(cv, issuer, path, anchor, data, own);
                if (status is { Status: RevocationStatus.Revoked })
                {
                    why = "the responder certificate is revoked: " + status.Reason;
                    continue;
                }

                if (status is null)
                {
                    _revNotes.Add("the delegated OCSP responder certificate has no id-pkix-ocsp-nocheck and no supplied CRL gives its status; it is trusted as RFC 6960 §4.2.2.2.1 leaves to the client");
                }
            }

            return c.PublicKey;
        }

        why ??= "the response is signed by a responder that is neither the issuer, a trusted responder nor a delegated responder";
        return null;
    }
}
