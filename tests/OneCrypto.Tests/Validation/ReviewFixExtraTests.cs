using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Validation;

/// <summary>Edges of the review fixes that the one-test-per-finding file does not reach.</summary>
public class ReviewFixExtraTests
{
    private static readonly DateTimeOffset Now = RNode.Now;

    [Theory]
    [InlineData("https://example%2Etest/x")]
    [InlineData("https://EXAMPLE.test./x")]
    [InlineData("https://user@example.test.:8443/x")]
    public void UriHostSpellingsOfAnExcludedHostAreStillExcluded(string uri)
    {
        using var root = RNode.Make("Root", null, true);
        var nc = Extension.Create(new NameConstraints(null, [new GeneralSubtree(GeneralName.FromUri("example.test"))]), true);
        using var ca = RNode.Make("CA", root, true, [nc]);
        var san = Extension.Create(new SubjectAlternativeName([GeneralName.Dns("leaf.other.test"), GeneralName.FromUri(uri)]), false);
        using var leaf = RNode.Make("leaf", ca, false, [san]);
        ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], [ca.Certificate]));
        Assert.Equal(ValidationRule.NameConstraints, r.DecidingRule?.Rule);
    }

    [Fact]
    public void AHostOutsideTheExcludedSubtreeIsNotCaughtByTheNormalisation()
    {
        using var root = RNode.Make("Root", null, true);
        var nc = Extension.Create(new NameConstraints(null, [new GeneralSubtree(GeneralName.FromUri("example.test"))]), true);
        using var ca = RNode.Make("CA", root, true, [nc]);
        var san = Extension.Create(new SubjectAlternativeName([GeneralName.Dns("leaf.other.test"), GeneralName.FromUri("https://notexample.test./x")]), false);
        using var leaf = RNode.Make("leaf", ca, false, [san]);
        ValidationReport r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], [ca.Certificate]));
        Assert.True(r.IsValid, r.ToString());
    }

    [Fact]
    public void SmtpUtf8MailboxInsideAPermittedRfc822SubtreeIsAccepted()
    {
        using var root = RNode.Make("Root", null, true);
        var nc = Extension.Create(new NameConstraints([new GeneralSubtree(GeneralName.Email("allowed.test"))], null), true);
        using var ca = RNode.Make("CA", root, true, [nc]);
        byte[] Mailbox(string m) => [0x0C, (byte)m.Length, .. System.Text.Encoding.UTF8.GetBytes(m)];
        Extension San(string mailbox) => Extension.Create(new SubjectAlternativeName([GeneralName.Dns("leaf.example.test"), GeneralName.Other("1.3.6.1.5.5.7.8.9", Mailbox(mailbox))]), false);
        using var inside = RNode.Make("in", ca, false, [San("user@allowed.test")]);
        using var outside = RNode.Make("out", ca, false, [San("user@elsewhere.test")]);
        // The DNS name is outside any rfc822 constraint, so only the mailbox decides.
        Assert.True(PathValidator.Validate(inside.Certificate, RNode.Options([root], [ca.Certificate])).IsValid);
        Assert.Equal(ValidationRule.NameConstraints, PathValidator.Validate(outside.Certificate, RNode.Options([root], [ca.Certificate])).DecidingRule?.Rule);
    }

    [Fact]
    public void RequiredRevocationWithOnlyAnUnusableCrlIsUndecided()
    {
        using var root = RNode.Make("Root", null, true);
        using var leaf = RNode.Make("leaf", root, false);
        var badEntry = new RevokedCertificateInfo(new System.Numerics.BigInteger(7), Now.AddDays(-2), RevocationReason.Superseded, null, [Extension.Create("1.2.3.4.5.6", true, new byte[] { 0x05, 0x00 })]);
        // A critical entry extension on a listed entry disables the CRL for every certificate, listed or not (RFC 5280 §5.3).
        CertificateRevocationList crl = RNode.Crl(root, [badEntry]);
        // The options leave UnknownRevocationIsFatal at its default: required revocation with no usable data is undecided, not valid.
        var o = new ValidationOptions
        {
            TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
            ReferenceTime = Now,
            Revocation = new RevocationData { Crls = [crl] },
            RevocationRequired = RevocationScope.EndEntity,
        };
        ValidationReport r = PathValidator.Validate(leaf.Certificate, o);
        Assert.Equal(ValidationVerdict.Indeterminate, r.Verdict);
        Assert.Equal(RevocationStatus.Unknown, r.RevocationSummary);

        // The caller can opt out and read the status instead.
        r = PathValidator.Validate(leaf.Certificate, RNode.Options([root], null, new RevocationData { Crls = [crl] }, RevocationScope.EndEntity, fatal: false));
        Assert.Equal(ValidationVerdict.Valid, r.Verdict);
        Assert.Equal(RevocationStatus.Unknown, r.RevocationSummary);
    }
}
