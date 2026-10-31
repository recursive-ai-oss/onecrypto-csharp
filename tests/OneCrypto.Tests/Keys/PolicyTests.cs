using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Policy;

namespace OneCrypto.Tests.Keys;

public class PolicyTests
{
    private static readonly DateTimeOffset Y2005 = new(2005, 6, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Y2010 = new(2010, 12, 31, 23, 59, 59, TimeSpan.Zero);
    private static readonly DateTimeOffset Y2011 = new(2011, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Y2026 = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Y2030End = new(2030, 12, 31, 23, 59, 59, TimeSpan.Zero);
    private static readonly DateTimeOffset Y2031 = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Sha1IsNeverUsedForNewSignatures()
    {
        PolicyDecision d = CryptoPolicy.Standard.CheckHash(HashAlgorithmName.SHA1, CryptoUse.Sign, Y2005);
        Assert.Equal(PolicyVerdict.Rejected, d.Verdict);
        Assert.Equal("hash.sha-1.new", d.Rule);
        Assert.Contains("NIST", d.Reference);
        Assert.Equal(PolicyVerdict.Accepted, CryptoPolicy.Standard.CheckHash(HashAlgorithmName.SHA256, CryptoUse.Sign, Y2026).Verdict);
    }

    [Fact]
    public void Sha1OnOldDataIsAcceptedThenFlaggedThenRejectedAtTheCutoffs()
    {
        CryptoPolicy p = CryptoPolicy.Standard;
        Assert.Equal(PolicyVerdict.Accepted, p.CheckHash(HashAlgorithmName.SHA1, CryptoUse.Verify, Y2010).Verdict);
        PolicyDecision flagged = p.CheckHash(HashAlgorithmName.SHA1, CryptoUse.Verify, Y2011);
        Assert.Equal(PolicyVerdict.Flagged, flagged.Verdict);
        Assert.Equal("hash.sha-1.flagged-from", flagged.Rule);
        Assert.Equal(PolicyVerdict.Flagged, p.CheckHash(HashAlgorithmName.SHA1, CryptoUse.Verify, Y2030End).Verdict);
        PolicyDecision rejected = p.CheckHash(HashAlgorithmName.SHA1, CryptoUse.Verify, Y2031);
        Assert.Equal(PolicyVerdict.Rejected, rejected.Verdict);
        Assert.Equal("hash.sha-1.rejected-from", rejected.Rule);
        Assert.Contains("2031-01-01", rejected.Reason);
    }

    [Fact]
    public void Sha1HmacIsNotAffectedByTheCollisionRule() =>
        Assert.Equal(PolicyVerdict.Accepted, CryptoPolicy.Standard.CheckHash(HashAlgorithmName.SHA1, CryptoUse.Mac, Y2026).Verdict);

    [Fact]
    public void Md5IsRejectedFrom2009()
    {
        Assert.Equal(PolicyVerdict.Flagged, CryptoPolicy.Standard.CheckHash(HashAlgorithmName.MD5, CryptoUse.Verify, Y2005).Verdict);
        Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Standard.CheckHash(HashAlgorithmName.MD5, CryptoUse.Verify, Y2010).Verdict);
    }

    [Fact]
    public void StrictRejectsSha1AndMd5AtAnyTime()
    {
        foreach (DateTimeOffset t in new[] { Y2005, Y2010, Y2026 })
        {
            Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Strict.CheckHash(HashAlgorithmName.SHA1, CryptoUse.Verify, t).Verdict);
            Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Strict.CheckHash(HashAlgorithmName.MD5, CryptoUse.Verify, t).Verdict);
        }
    }

    private static RSA NewRsa(int bits)
    {
        try
        {
            return RSA.Create(bits);
        }
        catch (CryptographicException)
        {
            Assert.Skip($"this platform does not generate {bits}-bit RSA keys");
            throw;
        }
    }

    [Theory]
    [InlineData(4096, CryptoUse.Sign, PolicyVerdict.Accepted)]
    [InlineData(2048, CryptoUse.Sign, PolicyVerdict.Accepted)]
    [InlineData(1024, CryptoUse.Sign, PolicyVerdict.Rejected)]
    [InlineData(2048, CryptoUse.Encrypt, PolicyVerdict.Accepted)]
    [InlineData(1024, CryptoUse.Encrypt, PolicyVerdict.Rejected)]
    [InlineData(1024, CryptoUse.Verify, PolicyVerdict.Flagged)]
    [InlineData(1024, CryptoUse.Decrypt, PolicyVerdict.Flagged)]
    [InlineData(2048, CryptoUse.Verify, PolicyVerdict.Accepted)]
    [InlineData(512, CryptoUse.Verify, PolicyVerdict.Rejected)]
    public void StandardRsaSizeRules(int bits, CryptoUse use, PolicyVerdict expected)
    {
        using RSA rsa = NewRsa(bits);
        PolicyDecision d = CryptoPolicy.Standard.CheckKey(PublicKeyInfo.FromAsymmetricAlgorithm(rsa), use, Y2026);
        Assert.Equal(expected, d.Verdict);
        if (expected != PolicyVerdict.Accepted)
        {
            Assert.NotEmpty(d.Rule);
            Assert.NotEmpty(d.Reason);
            Assert.NotEmpty(d.Reference);
        }
    }

    [Fact]
    public void WeakRsaIsAcceptedBeforeItsDeprecationDate()
    {
        using RSA rsa = RSA.Create(1024);
        PublicKeyInfo key = PublicKeyInfo.FromAsymmetricAlgorithm(rsa);
        Assert.Equal(PolicyVerdict.Accepted, CryptoPolicy.Standard.CheckKey(key, CryptoUse.Verify, Y2010).Verdict);
        Assert.Equal(PolicyVerdict.Flagged, CryptoPolicy.Standard.CheckKey(key, CryptoUse.Verify, new DateTimeOffset(2014, 1, 1, 0, 0, 0, TimeSpan.Zero)).Verdict);
    }

    [Theory]
    [InlineData(2048, CryptoUse.Sign, PolicyVerdict.Rejected)]
    [InlineData(3072, CryptoUse.Sign, PolicyVerdict.Accepted)]
    [InlineData(2048, CryptoUse.Verify, PolicyVerdict.Accepted)]
    [InlineData(1024, CryptoUse.Verify, PolicyVerdict.Rejected)]
    public void StrictRsaSizeRules(int bits, CryptoUse use, PolicyVerdict expected)
    {
        using RSA rsa = NewRsa(bits);
        Assert.Equal(expected, CryptoPolicy.Strict.CheckKey(PublicKeyInfo.FromAsymmetricAlgorithm(rsa), use, Y2026).Verdict);
    }

    [Fact]
    public void ADeprecatedFindingBecomesARejectionUnderStrict()
    {
        CryptoPolicy p = CryptoPolicy.Standard with { FlagAsRejected = true };
        Assert.Equal(PolicyVerdict.Rejected, p.CheckHash(HashAlgorithmName.SHA1, CryptoUse.Verify, Y2026).Verdict);
        Assert.Equal(PolicyVerdict.Rejected, p.CheckCipher(CipherAlgorithm.Cast5, true, CryptoUse.Decrypt).Verdict);
    }

    [Fact]
    public void SignatureCheckReportsTheHashAndTheKeyTogether()
    {
        using RSA rsa = RSA.Create(1024);
        PublicKeyInfo key = PublicKeyInfo.FromAsymmetricAlgorithm(rsa);
        PolicyReport r = CryptoPolicy.Standard.CheckSignature(AlgorithmIdentifier.WithNull(KnownOids.Sha1WithRsa), key, CryptoUse.Verify, Y2026);
        Assert.Equal(2, r.Decisions.Count);
        Assert.Equal(PolicyVerdict.Flagged, r.Decisions[0].Verdict);
        Assert.Equal(PolicyVerdict.Flagged, r.Decisions[1].Verdict);
        Assert.Equal(PolicyVerdict.Flagged, r.Verdict);
        Assert.Equal(2, r.Findings.Count());

        PolicyReport later = CryptoPolicy.Standard.CheckSignature(AlgorithmIdentifier.WithNull(KnownOids.Sha1WithRsa), key, CryptoUse.Verify, Y2031);
        Assert.Equal(PolicyVerdict.Rejected, later.Verdict);
        Assert.False(later.IsAllowed);
    }

    [Fact]
    public void LegacyCiphersDecryptButDoNotEncrypt()
    {
        CryptoPolicy p = CryptoPolicy.Standard;
        Assert.Equal(PolicyVerdict.Flagged, p.CheckCipher(CipherAlgorithm.Cast5, true, CryptoUse.Decrypt).Verdict);
        Assert.Equal(PolicyVerdict.Rejected, p.CheckCipher(CipherAlgorithm.Cast5, true, CryptoUse.Encrypt).Verdict);
        Assert.Equal(PolicyVerdict.Flagged, (p with { LegacyCiphers = LegacyCipherMode.EncryptAndDecrypt }).CheckCipher(CipherAlgorithm.Idea, true, CryptoUse.Encrypt).Verdict);
        Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Strict.CheckCipher(CipherAlgorithm.Blowfish, true, CryptoUse.Decrypt).Verdict);
        Assert.Equal(PolicyVerdict.Rejected, p.CheckCipher(CipherAlgorithm.Broken, true, CryptoUse.Decrypt).Verdict);
        Assert.Equal(PolicyVerdict.Accepted, p.CheckCipher(CipherAlgorithm.Aes, true, CryptoUse.Encrypt).Verdict);
    }

    [Fact]
    public void UnauthenticatedEncryptionFailsClosedUnlessOptedIn()
    {
        Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Standard.CheckCipher(CipherAlgorithm.Aes, false, CryptoUse.Decrypt).Verdict);
        Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Standard.CheckCipher(CipherAlgorithm.Aes, false, CryptoUse.Encrypt).Verdict);
        Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Strict.CheckCipher(CipherAlgorithm.Aes, false, CryptoUse.Decrypt).Verdict);
        CryptoPolicy sed = CryptoPolicy.Standard with { AllowUnauthenticatedDecryption = true };
        Assert.Equal(PolicyVerdict.Accepted, sed.CheckCipher(CipherAlgorithm.Aes, false, CryptoUse.Decrypt).Verdict);
        Assert.Equal(PolicyVerdict.Rejected, sed.CheckCipher(CipherAlgorithm.Aes, false, CryptoUse.Encrypt).Verdict);
    }

    [Fact]
    public void KdfCostRules()
    {
        Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Standard.CheckKdf(KdfAlgorithm.Pbkdf2, 500).Verdict);
        Assert.Equal(PolicyVerdict.Flagged, CryptoPolicy.Standard.CheckKdf(KdfAlgorithm.Pbkdf2, 5000).Verdict);
        Assert.Equal(PolicyVerdict.Accepted, CryptoPolicy.Standard.CheckKdf(KdfAlgorithm.Pbkdf2, 600_000).Verdict);
        Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Strict.CheckKdf(KdfAlgorithm.Pbkdf2, 50_000).Verdict);
        Assert.Equal(PolicyVerdict.Flagged, CryptoPolicy.Standard.CheckKdf(KdfAlgorithm.SimpleS2k, 0).Verdict);
        Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Standard.CheckKdf(KdfAlgorithm.Argon2, 1L << 30).Verdict);
        Assert.Equal(PolicyVerdict.Accepted, CryptoPolicy.Standard.CheckKdf(KdfAlgorithm.Argon2, 1L << 21).Verdict);
    }

    [Fact]
    public void PresetsAreImmutableAndDerivable()
    {
        CryptoPolicy custom = CryptoPolicy.Standard with { MinRsaBitsNew = 3072, Name = "Custom" };
        Assert.Equal(2048, CryptoPolicy.Standard.MinRsaBitsNew);
        Assert.Equal(3072, custom.MinRsaBitsNew);
        Assert.Same(CryptoPolicy.Standard.X509Limits, X509Limits.Default);
        Assert.Same(CryptoPolicy.Standard.KdfLimits, RecursiveAI.OneCrypto.Primitives.KdfLimits.Default);
    }

    [Fact]
    public void ViolationExceptionNamesTheRule()
    {
        PolicyReport r = new([CryptoPolicy.Standard.CheckHash(HashAlgorithmName.SHA1, CryptoUse.Sign, Y2026)]);
        var e = new PolicyViolationException(r);
        Assert.Contains("hash.sha-1.new", e.Message);
        Assert.Same(r, e.Report);
    }
}
