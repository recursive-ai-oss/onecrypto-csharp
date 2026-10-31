using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;
using System.Security.Cryptography;

namespace OneCrypto.Tests.Validation;

/// <summary>
/// One test per finding of the validator verdict review (docs/validation-review.md). Each asserts the behaviour RFC 5280 / RFC 6960 asks for,
/// so it fails today and is skipped; a fix removes its Skip.
/// </summary>
public class ReviewFindingTests
{
    private static readonly DateTimeOffset Now = RNode.Now;

    // R1: an untrusted pool can fill the validated-path budget with paths that fail, so a valid path is never reached and the verdict is Invalid.
    [Fact(Skip = "review finding R1")]
    public void R1DecoyIssuersCannotCrowdOutTheValidPath()
    {
        using var root = RNode.Make("Root", null, true);
        // The genuine CA expires soonest, so the builder tries it last (later notAfter first).
        using var good = RNode.Make("CA", root, true, notAfter: Now.AddDays(30));
        var pool = new List<Certificate> { good.Certificate };
        for (int i = 0; i < 40; i++)
        {
            // Same name and key as the genuine CA, issued by the root, but without keyCertSign: each completes a path that fails.
            pool.Add(RNode.Reissue(good, root, [RNode.CaBasic, Extension.Create(new KeyUsageExtension(KeyUsages.DigitalSignature), true)], Now.AddYears(2).AddDays(i)));
        }

        using var leaf = RNode.Make("leaf", good, false);
        ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], pool));
        Assert.True(r.Verdict != ValidationVerdict.Invalid, $"{r.DecidingRule} limit={r.LimitReached} paths={r.Paths.Length}"); // a valid path exists; at worst the answer is Indeterminate with LimitReached
    }

    // R2: RFC 5280 §6.3.3 (f): the CRL issuer's path must end at the trust anchor of the certificate's own path. A CRL "signed by the CA" with a key that
    // a different trusted root certified for the CA's name is accepted today, so any root can vouch "not revoked" for any CA.
    [Fact(Skip = "review finding R2")]
    public void R2CrlSignerMustChainToTheSameAnchorAsTheCertificate()
    {
        using var rootA = RNode.Make("RootA", null, true);
        using var rootB = RNode.Make("RootB", null, true);
        using var leaf = RNode.Make("leaf", rootA, false);
        using var rogueKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Certificate signer = CertificateBuilder.Create(
            new CertificateOptions
            {
                Subject = rootA.Certificate.Subject,
                PublicKey = PublicKeyInfo.FromAsymmetricAlgorithm(rogueKey),
                NotBefore = Now.AddYears(-1),
                NotAfter = Now.AddYears(1),
                Extensions = [RNode.CaBasic, RNode.CaUsage],
            },
            rootB.Certificate,
            rootB.Signer);
        CertificateRevocationList forged = RevocationListBuilder.Create(
            new RevocationListOptions { ThisUpdate = Now.AddDays(-1), NextUpdate = Now.AddDays(6), Number = 1 },
            X509Signer.FromECDsa(rogueKey),
            signer);

        ValidationOptions o = RNode.Options([rootA, rootB], [signer], new RevocationData { Crls = [forged] }, RevocationScope.EndEntity);
        ValidationReport r = PathValidator.Validate(leaf.Certificate, o);
        Assert.True(r.RevocationSummary != RevocationStatus.Good, r.SelectedPath?.Certificates[^1].Revocation.Reason ?? r.ToString());
    }

    // R3: RFC 5280 §6.3.3 (j): a certificate found on the CRL takes the entry's reason; the CRL's reason scope only decides which reasons the CRL
    // covers, not whether a listed entry counts. Today an entry whose reason is outside onlySomeReasons is read as "good".
    [Fact(Skip = "review finding R3")]
    public void R3ListedEntryOutsideTheCrlReasonScopeIsStillRevoked()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("leaf", root, false);
        RevocationReasons all = (RevocationReasons)0x1FE;
        CertificateRevocationList superseded = RNode.Crl(
            root,
            [new RevokedCertificateInfo(RNode.Serial(leaf.Certificate), Now.AddDays(-2), RevocationReason.KeyCompromise)],
            [Extension.Create(new IssuingDistributionPoint(null, OnlySomeReasons: RevocationReasons.Superseded), true)]);
        CertificateRevocationList rest = RNode.Crl(
            root,
            null,
            [Extension.Create(new IssuingDistributionPoint(null, OnlySomeReasons: all & ~RevocationReasons.Superseded), true)],
            number: 2);

        ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], null, new RevocationData { Crls = [superseded, rest] }, RevocationScope.EndEntity));
        Assert.Equal(ValidationVerdict.Invalid, r.Verdict);
    }

    // R4: RFC 5280 §5.3: a CRL with a critical entry extension the application does not process must not be used for any certificate.
    [Fact(Skip = "review finding R4")]
    public void R4CrlWithAnUnknownCriticalEntryExtensionIsNotUsed()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("leaf", root, false);
        var other = new RevokedCertificateInfo(
            new System.Numerics.BigInteger(424242),
            Now.AddDays(-2),
            RevocationReason.Superseded,
            null,
            [Extension.Create("1.2.3.4.5.6", true, new byte[] { 0x05, 0x00 })]);
        CertificateRevocationList crl = RNode.Crl(root, [other]);

        ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], null, new RevocationData { Crls = [crl] }, RevocationScope.EndEntity));
        Assert.Equal(RevocationStatus.Unknown, r.RevocationSummary);
    }

    // R5: RFC 8398 §6: rfc822Name constraints apply to SmtpUTF8Mailbox subject alternative names.
    [Fact(Skip = "review finding R5")]
    public void R5Rfc822ExclusionAppliesToSmtpUtf8Mailbox()
    {
        using var root = RNode.Make("Root", null, true);
        var nc = Extension.Create(new NameConstraints(null, [new GeneralSubtree(GeneralName.Email("excluded.test"))]), true);
        using var ca = RNode.Make("CA", root, true, [nc]);
        byte[] mailbox = [0x0C, 18, .. "user@excluded.test"u8.ToArray()];
        var san = Extension.Create(new SubjectAlternativeName([GeneralName.Dns("leaf.example.test"), GeneralName.Other("1.3.6.1.5.5.7.8.9", mailbox)]), false);
        using var leaf = RNode.Make("leaf", ca, false, [san]);

        ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], [ca.Certificate]));
        Assert.Equal(ValidationRule.NameConstraints, r.DecidingRule?.Rule);
    }

    // R6: a URI host written as a fully qualified name ("example.test.") is the same host; the exclusion of example.test must cover it.
    [Fact(Skip = "review finding R6")]
    public void R6TrailingDotUriHostIsInsideTheExcludedSubtree()
    {
        using var root = RNode.Make("Root", null, true);
        var nc = Extension.Create(new NameConstraints(null, [new GeneralSubtree(GeneralName.FromUri("example.test"))]), true);
        using var ca = RNode.Make("CA", root, true, [nc]);
        var san = Extension.Create(new SubjectAlternativeName([GeneralName.Dns("leaf.other.test"), GeneralName.FromUri("https://example.test./x")]), false);
        using var leaf = RNode.Make("leaf", ca, false, [san]);

        ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], [ca.Certificate]));
        Assert.Equal(ValidationRule.NameConstraints, r.DecidingRule?.Rule);
    }

    // R7: RequiredExtendedKeyUsage is skipped for a target that is itself a trust anchor.
    [Fact(Skip = "review finding R7")]
    public void R7RequiredPurposeAppliesWhenTheTargetIsAnAnchor()
    {
        using var self = RNode.Make("Self", null, false);
        ValidationOptions o = new()
        {
            TrustAnchors = [TrustAnchor.FromCertificate(self.Certificate)],
            ReferenceTime = Now,
            RequiredExtendedKeyUsage = "1.3.6.1.5.5.7.3.3", // codeSigning; the certificate says serverAuth only
            StrictStructure = false,
        };
        ValidationReport r = PathValidator.Validate(self.Certificate, o);
        Assert.NotEqual(ValidationVerdict.Valid, r.Verdict);
    }

    // R8: RFC 9525 §6.3 forbids a partial wildcard inside an IDN label; a whole-label "*" still matches an A-label host.
    [Fact(Skip = "review finding R8")]
    public void R8WildcardMatchesAnAceLabelHost()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("leaf", root, false, [Extension.Create(new SubjectAlternativeName([GeneralName.Dns("*.example.test")]), false)]);
        ValidationOptions o = RNode.Options([root]);
        o = new ValidationOptions
        {
            TrustAnchors = o.TrustAnchors,
            ReferenceTime = Now,
            WebPki = new WebPkiProfile { ServerName = "xn--bcher-kva.example.test", EnforceBaselineRequirements = false },
        };
        ValidationReport r = PathValidator.Validate(leaf.Certificate, o);
        Assert.True(r.IsValid, r.DecidingRule?.ToString());
    }
}
