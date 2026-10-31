using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto.Cms;
using static OneCrypto.Tests.Support.CmsFixture;

namespace OneCrypto.Tests.Cms;

/// <summary>Signer verification over raw CMS: digests, signature schemes, certificate chains, validation time and time-stamps.</summary>
public class CmsVerifyTests
{
    private static readonly TestPki Pki = TestPki.Shared;

    private static byte[] Signed(SigScheme scheme, HashAlgorithmName hash, bool cades, bool timestamp, X509Certificate2? signer = null, CmsSpec? spec = null)
    {
        signer ??= scheme == SigScheme.Ecdsa ? Pki.EcSigner : Pki.RsaSigner;
        spec ??= new CmsSpec { Hash = hash, Scheme = scheme, Cades = cades, Timestamp = timestamp };
        return KitSign(signer, spec);
    }

    public static IEnumerable<object[]> Matrix()
    {
        foreach (SigScheme scheme in new[] { SigScheme.RsaPkcs1, SigScheme.RsaPss, SigScheme.Ecdsa })
        {
            foreach (string hash in new[] { "SHA256", "SHA384" })
            {
                foreach (bool cades in new[] { false, true })
                {
                    foreach (bool ts in new[] { false, true })
                    {
                        yield return [scheme, hash, cades, ts];
                    }
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public void GeneratedSignaturesVerifyAndChainToTheTestRoot(SigScheme scheme, string hash, bool cades, bool timestamp)
    {
        CmsSignerResult v = VerifyOne(Signed(scheme, new HashAlgorithmName(hash), cades, timestamp));
        Assert.Equal(CmsCheckStatus.Valid, v.Integrity);
        Assert.Equal(CmsCheckStatus.Valid, v.SignatureCheck);
        Assert.Equal(CmsChainStatus.Trusted, v.Chain);
        Assert.Equal(3, v.ChainElements.Count);
        Assert.True(v.IsValid, WarningsOf(v));
        Assert.Equal(CmsRevocationStatus.NotChecked, v.Revocation);
        Assert.Contains(v.Warnings, static w => w.StartsWith("Revocation was not checked", StringComparison.Ordinal));
        Assert.False(v.UsesWeakAlgorithm);
        if (timestamp)
        {
            Assert.NotNull(v.Timestamp);
            Assert.True(v.Timestamp.IsValid, string.Join("; ", v.Timestamp.Warnings));
            Assert.Equal(CmsChainStatus.Trusted, v.Timestamp.Chain);
            Assert.Equal(CmsValidationTimeSource.Timestamp, v.ValidationTimeSource);
        }
        else
        {
            Assert.Null(v.Timestamp);
            Assert.Equal(CmsValidationTimeSource.SigningTime, v.ValidationTimeSource);
        }
    }

    [Fact]
    public void NoAnchorsMeansUntrusted()
    {
        CmsSignerResult v = VerifyOne(Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false), new CmsVerifyOptions());
        Assert.Contains(v.Chain, new[] { CmsChainStatus.UntrustedRoot, CmsChainStatus.Incomplete });
        Assert.Equal(CmsCheckStatus.Valid, v.SignatureCheck);
        Assert.False(v.IsValid);
    }

    [Fact]
    public void ChangedContentBreaksIntegrityButNotTheSignatureValue()
    {
        byte[] cms = Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false);
        byte[] altered = (byte[])Content.Clone();
        altered[0] ^= 1;
        CmsSignerResult v = VerifyOne(cms, content: altered);
        Assert.Equal(CmsCheckStatus.Invalid, v.Integrity);
        Assert.Equal(CmsCheckStatus.Valid, v.SignatureCheck);
        Assert.False(v.IsValid);
        Assert.Contains(v.Warnings, static w => w.Contains("altered", StringComparison.Ordinal));
    }

    [Fact]
    public void ContentThatCannotBeDeterminedIsInvalid()
    {
        byte[] cms = Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false);
        CmsSignerResult v = CmsSignerVerifier.Verify(cms, static _ => null, Trust, CancellationToken.None);
        Assert.Equal(CmsCheckStatus.Invalid, v.Integrity);
        Assert.False(v.IsValid);
    }

    [Fact]
    public void WrongCertificateFailsTheSignatureCheck()
    {
        // The signature names the stranger's certificate as the signer although another key made it.
        var spec = new CmsSpec { ClaimedSigner = Pki.Stranger, Embedded = [Pki.Stranger, Pki.RsaSigner, Pki.Intermediate], Cades = true };
        CmsSignerResult v = VerifyOne(Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, true, false, spec: spec));
        Assert.Equal(CmsCheckStatus.Invalid, v.SignatureCheck);
        Assert.Equal(CmsCheckStatus.Valid, v.Integrity);
        Assert.False(v.IsValid);
    }

    [Fact]
    public void SigningCertificateAttributeMustNameTheSigner()
    {
        // The key is Rita's but the CAdES attribute (and the identifier) name the stranger: nothing verifies.
        var spec = new CmsSpec { ClaimedSigner = Pki.Stranger, Embedded = [Pki.Stranger, Pki.Intermediate], Cades = true };
        CmsSignerResult v = VerifyOne(Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, true, false, spec: spec));
        Assert.NotEqual(CmsCheckStatus.Valid, v.SignatureCheck);
    }

    [Fact]
    public void UntrustedRootIsReportedWithValidSignature()
    {
        var spec = new CmsSpec { Embedded = [Pki.Stranger, Pki.OtherRoot] };
        CmsSignerResult v = VerifyOne(Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false, Pki.Stranger, spec));
        Assert.Equal(CmsCheckStatus.Valid, v.SignatureCheck);
        Assert.Equal(CmsChainStatus.UntrustedRoot, v.Chain);
        Assert.False(v.IsValid);
    }

    [Fact]
    public void MissingIntermediateIsIncompleteUnlessSuppliedAsExtra()
    {
        var spec = new CmsSpec { Embedded = [Pki.RsaSigner] };
        byte[] cms = Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false, spec: spec);
        CmsSignerResult v = VerifyOne(cms);
        Assert.Equal(CmsChainStatus.Incomplete, v.Chain);
        CmsSignerResult fixedUp = VerifyOne(cms, new CmsVerifyOptions { TrustAnchors = [Pki.RootAnchor], ExtraCertificates = [X509CertificateLoader.LoadCertificate(Pki.Intermediate.RawData)] });
        Assert.Equal(CmsChainStatus.Trusted, fixedUp.Chain);
    }

    [Fact]
    public void ExpiredCertificateAtTheValidationTime()
    {
        byte[] cms = Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false, Pki.ExpiredSigner);
        CmsSignerResult now = VerifyOne(cms, new CmsVerifyOptions { TrustAnchors = [Pki.RootAnchor], TimePolicy = CmsValidationTimePolicy.Now });
        Assert.Equal(CmsChainStatus.Expired, now.Chain);
        Assert.Equal(CmsValidationTimeSource.Now, now.ValidationTimeSource);
        Assert.Equal(CmsCheckStatus.Valid, now.SignatureCheck);

        CmsSignerResult then = VerifyOne(cms, new CmsVerifyOptions { TrustAnchors = [Pki.RootAnchor], ValidationTime = DateTimeOffset.UtcNow.AddYears(-3) });
        Assert.Equal(CmsChainStatus.Trusted, then.Chain);
        Assert.Equal(CmsValidationTimeSource.Explicit, then.ValidationTimeSource);
    }

    [Fact]
    public void TheClockInTheOptionsDecidesWhatNowMeans()
    {
        byte[] cms = Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false, Pki.ExpiredSigner);
        var clock = new FixedClock(DateTimeOffset.UtcNow.AddYears(-3));
        CmsSignerResult v = VerifyOne(cms, new CmsVerifyOptions { TrustAnchors = [Pki.RootAnchor], TimePolicy = CmsValidationTimePolicy.Now, Clock = clock });
        Assert.Equal(CmsChainStatus.Trusted, v.Chain);
        Assert.Equal(clock.GetUtcNow(), v.ValidationTime);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    [Fact]
    public void VerifiedTimestampTimeRescuesAnExpiredCertificate()
    {
        var spec = new CmsSpec { Timestamp = true, TimestampTime = DateTimeOffset.UtcNow.AddYears(-3), SigningTime = DateTimeOffset.UtcNow.AddYears(-3) };
        CmsSignerResult v = VerifyOne(Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, true, true, Pki.ExpiredSigner, spec));
        Assert.Equal(CmsValidationTimeSource.Timestamp, v.ValidationTimeSource);
        Assert.Equal(CmsChainStatus.Trusted, v.Chain);
        Assert.True(v.IsValid, WarningsOf(v));
    }

    [Fact]
    public void DigestAlgorithmMismatchIsInvalid()
    {
        var spec = new CmsSpec { Hash = HashAlgorithmName.SHA256, SignatureHashOverride = HashAlgorithmName.SHA384 };
        CmsSignerResult v = VerifyOne(Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false, spec: spec));
        Assert.Equal(CmsCheckStatus.Invalid, v.SignatureCheck);
        Assert.Contains(v.Warnings, static w => w.Contains("digest algorithm", StringComparison.Ordinal));
    }

    [Fact]
    public void SignedAttributeDigestMismatch()
    {
        var spec = new CmsSpec { MessageDigestOverride = RandomNumberGenerator.GetBytes(32) };
        CmsSignerResult v = VerifyOne(Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false, spec: spec));
        Assert.Equal(CmsCheckStatus.Invalid, v.Integrity);
        Assert.Equal(CmsCheckStatus.Valid, v.SignatureCheck);
        Assert.False(v.IsValid);
    }

    [Fact]
    public void KeyUsageIsJudgedByTheSignerCertificate()
    {
        foreach ((X509Certificate2 cert, bool ok) in new[] { (Pki.RsaSigner, true), (Pki.EmailSigner, true), (Pki.KeyEnciphermentSigner, false), (Pki.ServerAuthSigner, false) })
        {
            CmsSignerResult v = VerifyOne(KitSign(cert, new CmsSpec()));
            Assert.Equal(ok ? CmsCheckStatus.Valid : CmsCheckStatus.Invalid, v.KeyUsage);
            Assert.Equal(ok, v.IsValid);

            CmsSignerResult relaxed = VerifyOne(KitSign(cert, new CmsSpec()), new CmsVerifyOptions { TrustAnchors = [Pki.RootAnchor], RequireSigningKeyUsage = false });
            Assert.True(relaxed.IsValid, WarningsOf(relaxed));
        }
    }

    [Fact]
    public void RevocationCallbackIsHonouredAndNothingIsFetched()
    {
        byte[] cms = Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false);
        var calls = new List<string>();
        CmsSignerResult revoked = VerifyOne(cms, new CmsVerifyOptions
        {
            TrustAnchors = [Pki.RootAnchor],
            RevocationCheck = (c, issuer) =>
            {
                calls.Add(c.Subject);
                return c.Subject.Contains("Rita", StringComparison.Ordinal) ? CmsRevocationStatus.Revoked : CmsRevocationStatus.Good;
            },
        });
        Assert.Equal(CmsChainStatus.Revoked, revoked.Chain);
        Assert.Equal(CmsRevocationStatus.Revoked, revoked.Revocation);
        Assert.False(revoked.IsValid);
        Assert.Equal(2, calls.Count);

        CmsSignerResult good = VerifyOne(cms, new CmsVerifyOptions { TrustAnchors = [Pki.RootAnchor], RevocationCheck = static (_, _) => CmsRevocationStatus.Good });
        Assert.Equal(CmsRevocationStatus.Good, good.Revocation);
        Assert.True(good.IsValid);
        Assert.DoesNotContain(good.Warnings, static w => w.StartsWith("Revocation was not checked", StringComparison.Ordinal));
    }

    [Fact]
    public void Sha1IsValidButFlaggedWeak()
    {
        var spec = new CmsSpec { Hash = HashAlgorithmName.SHA1 };
        CmsSignerResult v = VerifyOne(Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA1, false, false, spec: spec));
        Assert.Equal(CmsCheckStatus.Valid, v.SignatureCheck);
        Assert.True(v.UsesWeakAlgorithm);
        Assert.Equal("SHA-1", v.DigestAlgorithm);
    }

    [Fact]
    public void GarbageGivesWarningsNotExceptions()
    {
        foreach (byte[] garbage in new[] { [1, 2, 3], [0x30, 0x82, 0xFF, 0xFF, 1, 2], [], new byte[] { 0x30, 0x80 } })
        {
            CmsSignerResult g = VerifyOne(garbage);
            Assert.Equal(CmsCheckStatus.Invalid, g.SignatureCheck);
            Assert.False(g.IsValid);
            Assert.NotEmpty(g.Warnings);
        }
    }

    [Fact]
    public void BerIndefiniteLengthCmsIsAccepted()
    {
        // Some signing tools write the outer structures with indefinite lengths. Re-wrap the CMS ContentInfo that way.
        byte[] der = KitSign(Pki.RsaSigner, new CmsSpec());
        // ContentInfo ::= SEQUENCE { oid, [0] { SignedData } }: rebuild the SEQUENCE and the [0] with indefinite lengths.
        int start = Skip(der);
        int oidLen = 2 + der[start + 1];
        byte[] oid = der[start..(start + oidLen)];
        int innerStart = start + oidLen;
        int contentStart = innerStart + HeaderLength(der, innerStart);
        byte[] signedData = der[contentStart..];
        byte[] ber = [0x30, 0x80, .. oid, 0xA0, 0x80, .. signedData, 0, 0, 0, 0];
        CmsSignerResult v = VerifyOne(ber);
        Assert.Equal(CmsCheckStatus.Valid, v.SignatureCheck);
        Assert.True(v.IsValid, WarningsOf(v));

        static int Skip(byte[] d) => d[1] < 0x80 ? 2 : 2 + (d[1] & 0x7F);
        static int HeaderLength(byte[] d, int at) => d[at + 1] < 0x80 ? 2 : 2 + (d[at + 1] & 0x7F);
    }

    [Fact]
    public void CancellationIsHonoured()
    {
        byte[] cms = Signed(SigScheme.RsaPkcs1, HashAlgorithmName.SHA256, false, false);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Throws<OperationCanceledException>(() => CmsSignerVerifier.Verify(cms, DigestOf(Content), Trust, cts.Token));
    }
}
