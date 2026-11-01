using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Validation;

/// <summary>The validator asks a <see cref="CryptoPolicy"/> about every certificate signature; Standard and Strict give different verdicts and the report names the rule.</summary>
public class ValidatorPolicyTests
{
    private static readonly DateTimeOffset Born = new(2005, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Dies = new(2045, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static ValidationOptions Options(RNode root, CryptoPolicy policy, DateTimeOffset at, IEnumerable<Certificate>? pool = null) => new()
    {
        TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
        Intermediates = [.. pool ?? []],
        ReferenceTime = at,
        Policy = policy,
    };

    private static Certificate Issue(string cn, PublicKeyInfo key, Certificate issuer, X509Signer signer, bool ca)
    {
        var ext = new List<Extension>();
        if (ca)
        {
            ext.Add(RNode.CaBasic);
            ext.Add(RNode.CaUsage);
        }
        else
        {
            ext.Add(Extension.Create(new BasicConstraints(false), true));
        }

        // The policy is Permissive only to be able to build the old-style certificate; the validator is what is under test.
        return CertificateBuilder.Create(
            new CertificateOptions { Subject = DistinguishedName.FromString("CN=" + cn), PublicKey = key, NotBefore = Born, NotAfter = Dies, Extensions = ext },
            issuer,
            signer,
            CryptoPolicy.Permissive);
    }

    private static RuleResult AlgorithmResult(ValidationReport r, string policyRule) =>
        r.SelectedPath!.Certificates.SelectMany(c => c.Results).First(x => x.Rule == ValidationRule.Algorithm && x.PolicyRule == policyRule);

    [Fact]
    public void Sha1CertificateSignatureFollowsTheCutoffsAndStrictRefusesItAlways()
    {
        using var root = RNode.Make("Root", null, true, notBefore: Born, notAfter: Dies);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // The root signs the leaf with ECDSA-SHA-1.
        Certificate leaf = Issue("leaf", PublicKeyInfo.FromAsymmetricAlgorithm(leafKey), root.Certificate, X509Signer.FromECDsa(RootKey(root), HashAlgorithmName.SHA1), false);

        var y2010 = new DateTimeOffset(2010, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var y2016 = new DateTimeOffset(2016, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var y2020 = new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var y2032 = new DateTimeOffset(2032, 6, 1, 0, 0, 0, TimeSpan.Zero);

        // Before 2011-01-01 Standard has no finding.
        ValidationReport r = PathValidator.Validate(leaf, Options(root, CryptoPolicy.Standard, y2010));
        Assert.True(r.IsValid, r.ToString());
        Assert.DoesNotContain(r.SelectedPath!.Certificates.SelectMany(c => c.Results), x => x.PolicyRule is not null);

        // From 2011 to the end of 2016 it is flagged: a warning, still valid, with the policy's rule id and its reason.
        r = PathValidator.Validate(leaf, Options(root, CryptoPolicy.Standard, y2016));
        Assert.True(r.IsValid, r.ToString());
        RuleResult flagged = AlgorithmResult(r, "hash.sha-1.pki.flagged-from");
        Assert.Equal(RuleOutcome.Warning, flagged.Outcome);
        Assert.Contains("SHA-1", flagged.Reason, StringComparison.Ordinal);

        // From 2017 a SHA-1 certificate signature is rejected (public CAs stopped issuing them in 2016); the same at any later date.
        foreach (DateTimeOffset at in new[] { y2020, y2032 })
        {
            r = PathValidator.Validate(leaf, Options(root, CryptoPolicy.Standard, at));
            Assert.Equal(ValidationVerdict.Invalid, r.Verdict);
            Assert.Equal(ValidationRule.Algorithm, r.DecidingRule!.Rule);
            Assert.Equal("hash.sha-1.pki.rejected-from", r.DecidingRule.PolicyRule);
        }

        // Strict refuses it at every date.
        foreach (DateTimeOffset at in new[] { y2010, y2016, y2020, y2032 })
        {
            r = PathValidator.Validate(leaf, Options(root, CryptoPolicy.Strict, at));
            Assert.Equal(ValidationVerdict.Invalid, r.Verdict);
            Assert.Equal(ValidationRule.Algorithm, r.DecidingRule!.Rule);
        }

        // Permissive accepts it with no finding.
        r = PathValidator.Validate(leaf, Options(root, CryptoPolicy.Permissive, y2032));
        Assert.True(r.IsValid, r.ToString());
    }

    [Fact]
    public void Rsa1024IntermediateIsFlaggedByStandardAndRefusedByStrict()
    {
        using var root = RNode.Make("Root", null, true, notBefore: Born, notAfter: Dies);
        using RSA caKey = RSA.Create(1024);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Certificate ca = Issue("Weak CA", PublicKeyInfo.FromAsymmetricAlgorithm(caKey), root.Certificate, root.Signer, true);
        Certificate leaf = Issue("leaf", PublicKeyInfo.FromAsymmetricAlgorithm(leafKey), ca, X509Signer.FromRsa(caKey, HashAlgorithmName.SHA256), false);

        // Before 2014-01-01, Standard accepts a 1024-bit key; afterwards it flags it.
        ValidationReport r = PathValidator.Validate(leaf, Options(root, CryptoPolicy.Standard, new DateTimeOffset(2012, 1, 1, 0, 0, 0, TimeSpan.Zero), [ca]));
        Assert.True(r.IsValid, r.ToString());
        Assert.DoesNotContain(r.SelectedPath!.Certificates.SelectMany(c => c.Results), x => x.PolicyRule is not null);

        var now = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        r = PathValidator.Validate(leaf, Options(root, CryptoPolicy.Standard, now, [ca]));
        Assert.True(r.IsValid, r.ToString());
        Assert.Equal(RuleOutcome.Warning, AlgorithmResult(r, "key.rsa.weak-from").Outcome);

        // Strict wants 2048 bits to verify.
        r = PathValidator.Validate(leaf, Options(root, CryptoPolicy.Strict, now, [ca]));
        Assert.Equal(ValidationVerdict.Invalid, r.Verdict);
        Assert.Equal("key.rsa.min-verify", r.DecidingRule!.PolicyRule);
        // The key is judged on the signature it made, so the finding sits on the certificate it signed and names the key.
        Assert.Contains("1024", r.DecidingRule!.Reason, StringComparison.Ordinal);

        // A caller-tuned Standard can refuse it too, with the same rule id.
        r = PathValidator.Validate(leaf, Options(root, CryptoPolicy.Standard with { MinRsaBitsVerify = 2048 }, now, [ca]));
        Assert.Equal("key.rsa.min-verify", r.DecidingRule!.PolicyRule);

        // Permissive has no opinion.
        r = PathValidator.Validate(leaf, Options(root, CryptoPolicy.Permissive, now, [ca]));
        Assert.True(r.IsValid, r.ToString());
    }

    [Fact]
    public void ServerAuthenticationProfileLeavesAlgorithmsToThePolicyAndKeepsItsKeySizeFloor()
    {
        using var root = RNode.Make("Root", null, true, notBefore: Born, notAfter: Dies);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Certificate leaf = Issue("leaf", PublicKeyInfo.FromAsymmetricAlgorithm(leafKey), root.Certificate, X509Signer.FromECDsa(RootKey(root), HashAlgorithmName.SHA1), false);
        var y2020 = new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero);

        // Standard already refuses SHA-1 in a certificate from 2017, with or without the profile.
        var profile = new WebPkiProfile { RequireServerAuth = false };
        ValidationReport r = PathValidator.Validate(leaf, new ValidationOptions { TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)], ReferenceTime = y2020, WebPki = profile });
        Assert.False(r.IsValid);
        Assert.Contains(r.SelectedPath!.Certificates.SelectMany(c => c.Results), x => x.Rule == ValidationRule.Algorithm && x.Outcome == RuleOutcome.Fail && x.PolicyRule == "hash.sha-1.pki.rejected-from");

        // The profile adds no algorithm policy of its own: a caller who chose Permissive keeps that choice.
        r = PathValidator.Validate(leaf, new ValidationOptions { TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)], ReferenceTime = y2020, Policy = CryptoPolicy.Permissive, WebPki = profile });
        Assert.DoesNotContain(r.SelectedPath!.Certificates.SelectMany(c => c.Results), x => x.Rule == ValidationRule.Algorithm && x.Outcome == RuleOutcome.Fail);
    }

    private static ECDsa RootKey(RNode root) => root.Key;
}
