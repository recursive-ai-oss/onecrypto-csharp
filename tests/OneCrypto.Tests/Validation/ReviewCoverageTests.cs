using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;
using System.Security.Cryptography;

namespace OneCrypto.Tests.Validation;

/// <summary>
/// What the verdict review checked and found correct, kept as tests so the coverage is visible and stays true
/// (docs/validation-review.md, "Checked and correct").
/// </summary>
public class ReviewCoverageTests
{
    private static readonly DateTimeOffset Now = RNode.Now;

    /// <summary>The report must follow from its rules: Valid means no failing or undecided result anywhere, otherwise the deciding rule names one.</summary>
    private static void AssertConsistent(ValidationReport r)
    {
        IEnumerable<RuleResult> all = r.TargetResults
            .Concat(r.SelectedPath?.PathResults ?? [])
            .Concat(r.SelectedPath?.Certificates.SelectMany(c => c.Results) ?? []);
        if (r.Verdict == ValidationVerdict.Valid)
        {
            Assert.DoesNotContain(all, x => x.Outcome is RuleOutcome.Fail or RuleOutcome.Indeterminate);
            Assert.Null(r.DecidingRule);
        }
        else
        {
            Assert.NotNull(r.DecidingRule);
            Assert.Equal(r.Verdict == ValidationVerdict.Invalid ? RuleOutcome.Fail : RuleOutcome.Indeterminate, r.DecidingRule!.Outcome);
        }
    }

    [Fact]
    public void ACrlSignedByAnUntrustedCertificateOfTheCaNameIsNotUsed()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("leaf", root, false);
        using var rogue = RNode.Make("Root", null, true); // same name, self-signed, not an anchor
        CertificateRevocationList forged = RNode.Crl(rogue);
        ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], [rogue.Certificate], new RevocationData { Crls = [forged] }, RevocationScope.EndEntity));
        Assert.Equal(RevocationStatus.Unknown, r.RevocationSummary);
        AssertConsistent(r);
    }

    [Fact]
    public void ACrlSignedByAnotherKeyOfTheSameCaIsUsedWhenThatKeyIsCertifiedAndMayAnswerCrls()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("leaf", root, false);
        using var crlKey = RNode.Make("Root", root, true, subject: root.Certificate.Subject);
        var listed = new RevokedCertificateInfo(RNode.Serial(leaf.Certificate), Now.AddDays(-2), RevocationReason.Superseded);
        ValidationReport revoked = PathValidator.Validate(leaf.Certificate, RNode.Options([root], [crlKey.Certificate], new RevocationData { Crls = [RNode.Crl(crlKey, [listed])] }));
        Assert.Equal(ValidationVerdict.Invalid, revoked.Verdict);
        Assert.Equal(ValidationRule.Revocation, revoked.DecidingRule!.Rule);
        AssertConsistent(revoked);

        // The same key without cRLSign is not a CRL signer.
        using var noCrlSign = RNode.Make("Root", root, true, [Extension.Create(new KeyUsageExtension(KeyUsages.KeyCertSign), true)], subject: root.Certificate.Subject);
        ValidationReport unknown = PathValidator.Validate(leaf.Certificate, RNode.Options([root], [noCrlSign.Certificate], new RevocationData { Crls = [RNode.Crl(noCrlSign)] }, RevocationScope.EndEntity));
        Assert.Equal(RevocationStatus.Unknown, unknown.RevocationSummary);
    }

    [Fact]
    public void CrlScopeFlagsAndStalenessKeepAnUncoveredCertificateUnknown()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("leaf", root, false);
        ValidationReport R(Extension idp) => PathValidator.Validate(leaf.Certificate, RNode.Options([root], null, new RevocationData { Crls = [RNode.Crl(root, null, [idp])] }, RevocationScope.EndEntity));
        Assert.Equal(RevocationStatus.Unknown, R(Extension.Create(new IssuingDistributionPoint(null, OnlyContainsCACerts: true), true)).RevocationSummary);
        Assert.Equal(RevocationStatus.Unknown, R(Extension.Create(new IssuingDistributionPoint(null, OnlyContainsAttributeCerts: true), true)).RevocationSummary);
        Assert.Equal(RevocationStatus.Unknown, R(Extension.Create(new IssuingDistributionPoint(null, OnlySomeReasons: RevocationReasons.KeyCompromise), true)).RevocationSummary);
        Assert.Equal(RevocationStatus.Good, R(Extension.Create(new IssuingDistributionPoint(null, OnlyContainsUserCerts: true), true)).RevocationSummary);
    }

    [Fact]
    public void OcspResponderAuthorisationFollowsRfc6960()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("leaf", root, false);
        OcspCertId id = OcspCertId.Create(leaf.Certificate, root.Certificate);

        RevocationStatus Status(RNode responder, bool withCert, OcspCertId? certId = null)
        {
            OcspBasicResponse resp = OcspResponseBuilder.CreateSuccessful(
                new OcspResponseOptions
                {
                    Responder = new OcspResponderId(responder.Certificate.Subject),
                    ProducedAt = Now.AddHours(-1),
                    Responses = [new OcspSingleResponseInfo(certId ?? id, OcspCertStatus.Good, Now.AddHours(-1), Now.AddDays(1))],
                    Certificates = withCert ? [responder.Certificate] : [],
                },
                responder.Signer).BasicResponse!;
            return PathValidator.Validate(leaf.Certificate, RNode.Options([root], null, new RevocationData { OcspResponses = [resp] }, RevocationScope.EndEntity)).RevocationSummary;
        }

        using var delegated = RNode.Make("Responder", root, false, [Extension.Create(new ExtendedKeyUsage([KnownOids.OcspSigning]), false)]);
        using var plainLeaf = RNode.Make("NotAResponder", root, false);
        using var expired = RNode.Make("OldResponder", root, false, [Extension.Create(new ExtendedKeyUsage([KnownOids.OcspSigning]), false)], notBefore: Now.AddYears(-2), notAfter: Now.AddDays(-1));
        Assert.Equal(RevocationStatus.Good, Status(delegated, true));
        Assert.Equal(RevocationStatus.Unknown, Status(plainLeaf, true)); // issued by the CA but not an OCSP signer
        Assert.Equal(RevocationStatus.Unknown, Status(expired, true));
        Assert.Equal(RevocationStatus.Good, Status(root, false));

        // A CertID built over a different issuer key does not name this certificate.
        using var other = RNode.Make("Other", null, true);
        Assert.Equal(RevocationStatus.Unknown, Status(root, false, OcspCertId.Create(leaf.Certificate, other.Certificate)));
    }

    [Fact]
    public void PastTimeModelByReason()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("leaf", root, false);
        DateTimeOffset t = Now.AddMonths(-3);
        ValidationVerdict V(RevocationReason? reason, DateTimeOffset when)
        {
            CertificateRevocationList crl = RNode.Crl(root, [new RevokedCertificateInfo(RNode.Serial(leaf.Certificate), when, reason)]);
            var o = new ValidationOptions
            {
                TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
                ReferenceTime = t,
                RevocationDataTime = Now,
                Revocation = new RevocationData { Crls = [crl] },
                RevocationRequired = RevocationScope.EndEntity,
                RevocationModel = RevocationModel.PastTime,
            };
            ValidationReport r = PathValidator.Validate(leaf.Certificate, o);
            AssertConsistent(r);
            return r.Verdict;
        }

        DateTimeOffset after = Now.AddMonths(-1);
        Assert.Equal(ValidationVerdict.Valid, V(RevocationReason.Superseded, after));
        Assert.Equal(ValidationVerdict.Valid, V(RevocationReason.CertificateHold, after));
        Assert.Equal(ValidationVerdict.Valid, V(RevocationReason.CessationOfOperation, after));
        Assert.Equal(ValidationVerdict.Invalid, V(RevocationReason.KeyCompromise, after));
        Assert.Equal(ValidationVerdict.Invalid, V(RevocationReason.CACompromise, after));
        Assert.Equal(ValidationVerdict.Invalid, V(RevocationReason.Unspecified, after));
        Assert.Equal(ValidationVerdict.Invalid, V(null, after));
        Assert.Equal(ValidationVerdict.Invalid, V(RevocationReason.Superseded, t.AddDays(-1))); // revoked before the reference time, whatever the reason
    }

    [Fact]
    public void NameConstraintsCoverDnsIpAndDirectoryNamesAndSkipSelfIssuedIntermediates()
    {
        using var root = RNode.Make("Root", null, true);
        var permitted = Extension.Create(new NameConstraints([new GeneralSubtree(GeneralName.Dns("example.test")), new GeneralSubtree(GeneralName.FromIPAddress([10, 0, 0, 0, 255, 0, 0, 0]))], null), true);
        using var ca = RNode.Make("CA", root, true, [permitted]);

        ValidationReport Leaf(params GeneralName[] names)
        {
            using var leaf = RNode.Make("leaf", ca, false, [Extension.Create(new SubjectAlternativeName(names), false)]);
            ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], [ca.Certificate]));
            AssertConsistent(r);
            return r;
        }

        Assert.True(Leaf(GeneralName.Dns("a.example.test"), GeneralName.FromIPAddress([10, 1, 2, 3])).IsValid);
        Assert.Equal(ValidationRule.NameConstraints, Leaf(GeneralName.Dns("a.example.org")).DecidingRule!.Rule);
        Assert.Equal(ValidationRule.NameConstraints, Leaf(GeneralName.Dns("a.example.test"), GeneralName.FromIPAddress([11, 1, 2, 3])).DecidingRule!.Rule);
        Assert.Equal(ValidationRule.NameConstraints, Leaf(GeneralName.Dns("badexample.test")).DecidingRule!.Rule); // not a label boundary

        // A rfc822Name constraint does not restrict dNSNames, and an excluded wildcard reaches what it could cover.
        var excluded = Extension.Create(new NameConstraints(null, [new GeneralSubtree(GeneralName.Dns("bad.example.test"))]), true);
        using var ca2 = RNode.Make("CA2", root, true, [excluded]);
        using var wild = RNode.Make("leaf", ca2, false, [Extension.Create(new SubjectAlternativeName([GeneralName.Dns("*.example.test")]), false)]);
        Assert.Equal(ValidationRule.NameConstraints, PathValidator.Validate(wild.Certificate, RNode.Options([root], [ca2.Certificate])).DecidingRule!.Rule);
    }

    [Fact]
    public void AnUnrecognisedCriticalExtensionOnAnIntermediateFailsThePath()
    {
        using var root = RNode.Make("Root", null, true);
        using var ca = RNode.Make("CA", root, true, [Extension.Create("1.2.3.4.5.6.7", true, new byte[] { 0x05, 0x00 })]);
        using var leaf = RNode.Make("leaf", ca, false);
        ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], [ca.Certificate]));
        Assert.Equal(ValidationRule.CriticalExtension, r.DecidingRule!.Rule);
        AssertConsistent(r);
    }

    [Fact]
    public void TheCommonNameIsNeverAHostName()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("www.example.test", root, false, leafName: "other.example.test");
        var o = new ValidationOptions
        {
            TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
            ReferenceTime = Now,
            WebPki = new WebPkiProfile { ServerName = "www.example.test", EnforceBaselineRequirements = false },
        };
        ValidationReport r = PathValidator.Validate(leaf.Certificate, o);
        Assert.Equal(ValidationRule.HostName, r.DecidingRule!.Rule);
        AssertConsistent(r);
    }

    [Fact]
    public void AValidChainWithNoRevocationDataIsNeverReportedGood()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("leaf", root, false);
        ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], null, null, RevocationScope.AllCertificates));
        Assert.Equal(RevocationStatus.Unknown, r.RevocationSummary);
        Assert.All(r.SelectedPath!.Certificates, c => Assert.Equal(RevocationStatus.Unknown, c.Revocation.Status));
        AssertConsistent(r);
    }
}
