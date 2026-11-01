using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Validation;

/// <summary>
/// The algorithm policy for PKI signatures (certificates, CRLs, OCSP responses) and the revocation observations of the verdict review:
/// stale CRLs that name the certificate, delegated responder revocation, removeFromCRL, and the SHA-1 cutoffs by use.
/// </summary>
public class PkiPolicyTests
{
    private static readonly DateTimeOffset Born = new(2005, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Dies = new(2045, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Y2016 = new(2016, 6, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Y2017 = new(2017, 6, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Y2026 = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Sha1PkiSignaturesAreFlaggedBefore2017AndRejectedFromThenButMessagesKeepTheLaterCutoff()
    {
        using RSA rsa = RSA.Create(2048);
        PublicKeyInfo key = PublicKeyInfo.FromAsymmetricAlgorithm(rsa);
        AlgorithmIdentifier alg = AlgorithmIdentifier.WithNull(KnownOids.Sha1WithRsa);

        RecursiveAI.OneCrypto.Policy.PolicyReport r = CryptoPolicy.Standard.CheckSignature(alg, key, CryptoUse.VerifyPki, Y2016);
        Assert.Equal(PolicyVerdict.Flagged, r.Verdict);
        Assert.Contains(r.Decisions, d => d.Rule == "hash.sha-1.pki.flagged-from");

        foreach (DateTimeOffset at in new[] { Y2017, Y2026 })
        {
            r = CryptoPolicy.Standard.CheckSignature(alg, key, CryptoUse.VerifyPki, at);
            Assert.Equal(PolicyVerdict.Rejected, r.Verdict);
            Assert.Contains(r.Decisions, d => d.Rule == "hash.sha-1.pki.rejected-from" && d.Use == CryptoUse.VerifyPki);
        }

        // A message signature (a CMS SignerInfo) keeps the SP 800-131A dates: flagged in 2026, rejected from 2031.
        r = CryptoPolicy.Standard.CheckSignature(alg, key, CryptoUse.Verify, Y2026);
        Assert.Equal(PolicyVerdict.Flagged, r.Verdict);
        Assert.Contains(r.Decisions, d => d.Rule == "hash.sha-1.flagged-from");
        Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Standard.CheckSignature(alg, key, CryptoUse.Verify, new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero)).Verdict);

        // Strict and Permissive do not change with the use.
        foreach (DateTimeOffset at in new[] { Y2016, Y2017, Y2026 })
        {
            Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Strict.CheckSignature(alg, key, CryptoUse.VerifyPki, at).Verdict);
            Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Strict.CheckSignature(alg, key, CryptoUse.Verify, at).Verdict);
            Assert.Equal(PolicyVerdict.Accepted, CryptoPolicy.Permissive.CheckSignature(alg, key, CryptoUse.VerifyPki, at).Verdict);
            Assert.Equal(PolicyVerdict.Accepted, CryptoPolicy.Permissive.CheckSignature(alg, key, CryptoUse.Verify, at).Verdict);
        }

        // MD5 is rejected from 2009 for both uses.
        Assert.Equal(PolicyVerdict.Rejected, CryptoPolicy.Standard.CheckHash(HashAlgorithmName.MD5, CryptoUse.VerifyPki, new DateTimeOffset(2010, 1, 1, 0, 0, 0, TimeSpan.Zero)).Verdict);
    }

    // A root, a leaf and the data under test at one reference time. The root's SHA-1 signer makes the CRL or response whose algorithm is judged.
    private sealed class Pki : IDisposable
    {
        public Pki(DateTimeOffset at)
        {
            At = at;
            Root = RNode.Make("Root", null, true, notBefore: Born, notAfter: Dies);
            Leaf = RNode.Make("leaf", Root, false, notBefore: Born, notAfter: Dies);
            Sha1 = X509Signer.FromECDsa(Root.Key, HashAlgorithmName.SHA1);
        }

        public DateTimeOffset At { get; }

        public RNode Root { get; }

        public RNode Leaf { get; }

        public X509Signer Sha1 { get; }

        public CertificateRevocationList Crl(X509Signer signer, DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate, IReadOnlyList<RevokedCertificateInfo>? revoked = null, int number = 1) =>
            RevocationListBuilder.Create(
                new RevocationListOptions { ThisUpdate = thisUpdate, NextUpdate = nextUpdate, Number = number, Revoked = revoked ?? [] },
                signer,
                Root.Certificate,
                CryptoPolicy.Permissive);

        public ValidationReport Validate(RevocationData data) =>
            PathValidator.Validate(Leaf.Certificate, new ValidationOptions
            {
                TrustAnchors = [TrustAnchor.FromCertificate(Root.Certificate)],
                ReferenceTime = At,
                Revocation = data,
                RevocationRequired = RevocationScope.EndEntity,
                UnknownRevocationIsFatal = false,
            });

        public static RevocationReport Rev(ValidationReport r) => r.SelectedPath!.Certificates[^1].Revocation;

        public void Dispose()
        {
            Root.Dispose();
            Leaf.Dispose();
        }
    }

    [Theory]
    [InlineData(2016, RevocationStatus.Good, "hash.sha-1.pki.flagged-from", PolicyVerdict.Flagged)]
    [InlineData(2017, RevocationStatus.Unknown, "hash.sha-1.pki.rejected-from", PolicyVerdict.Rejected)]
    [InlineData(2026, RevocationStatus.Unknown, "hash.sha-1.pki.rejected-from", PolicyVerdict.Rejected)]
    public void ASha1CrlSignatureIsJudgedAsAPkiSignature(int year, RevocationStatus expected, string rule, PolicyVerdict verdict)
    {
        DateTimeOffset at = year == 2016 ? Y2016 : year == 2017 ? Y2017 : Y2026;
        using var pki = new Pki(at);
        CertificateRevocationList crl = pki.Crl(pki.Sha1, at.AddDays(-1), at.AddDays(6));
        ValidationReport r = pki.Validate(new RevocationData { Crls = [crl] });
        RevocationReport rev = Pki.Rev(r);
        Assert.Equal(expected, rev.Status);
        PolicyDecision d = Assert.Single(rev.PolicyDecisions, x => x.Rule == rule);
        Assert.Equal(verdict, d.Verdict);
        Assert.Equal(CryptoUse.VerifyPki, d.Use);
        if (verdict == PolicyVerdict.Rejected)
        {
            Assert.Contains(rule, rev.Reason, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ASha1CrlIsUsableUnderPermissiveAndRefusedUnderStrictAtAnyTime()
    {
        using var pki = new Pki(Y2016);
        CertificateRevocationList crl = pki.Crl(pki.Sha1, Y2016.AddDays(-1), Y2016.AddDays(6));
        PathValidatorOptionsCheck(pki, crl, CryptoPolicy.Permissive, RevocationStatus.Good);
        PathValidatorOptionsCheck(pki, crl, CryptoPolicy.Strict, RevocationStatus.Unknown);
        PathValidatorOptionsCheck(pki, crl, CryptoPolicy.Standard, RevocationStatus.Good);
    }

    private static void PathValidatorOptionsCheck(Pki pki, CertificateRevocationList crl, CryptoPolicy policy, RevocationStatus expected)
    {
        ValidationReport r = PathValidator.Validate(pki.Leaf.Certificate, new ValidationOptions
        {
            TrustAnchors = [TrustAnchor.FromCertificate(pki.Root.Certificate)],
            ReferenceTime = pki.At,
            Policy = policy,
            Revocation = new RevocationData { Crls = [crl] },
            RevocationRequired = RevocationScope.EndEntity,
            UnknownRevocationIsFatal = false,
        });
        Assert.Equal(expected, Pki.Rev(r).Status);
    }

    [Theory]
    [InlineData(2016, RevocationStatus.Good, PolicyVerdict.Flagged)]
    [InlineData(2017, RevocationStatus.Unknown, PolicyVerdict.Rejected)]
    [InlineData(2026, RevocationStatus.Unknown, PolicyVerdict.Rejected)]
    public void ASha1OcspResponseSignatureIsJudgedAsAPkiSignature(int year, RevocationStatus expected, PolicyVerdict verdict)
    {
        DateTimeOffset at = year == 2016 ? Y2016 : year == 2017 ? Y2017 : Y2026;
        using var pki = new Pki(at);
        OcspBasicResponse resp = OcspResponseBuilder.CreateSuccessful(
            new OcspResponseOptions
            {
                Responder = new OcspResponderId(pki.Root.Certificate.Subject),
                ProducedAt = at.AddHours(-1),
                Responses = [new OcspSingleResponseInfo(OcspCertId.Create(pki.Leaf.Certificate, pki.Root.Certificate), OcspCertStatus.Good, at.AddHours(-1), at.AddDays(1))],
            },
            pki.Sha1,
            CryptoPolicy.Permissive).BasicResponse!;
        RevocationReport rev = Pki.Rev(pki.Validate(new RevocationData { OcspResponses = [resp] }));
        Assert.Equal(expected, rev.Status);
        PolicyDecision d = Assert.Single(rev.PolicyDecisions, x => x.Rule.StartsWith("hash.sha-1.pki.", StringComparison.Ordinal));
        Assert.Equal(verdict, d.Verdict);
    }

    [Fact]
    public void ADelegatedResponderCertificateSignedWithSha1IsRefusedFrom2017()
    {
        using var pki = new Pki(Y2026);
        using ECDsa responderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Certificate responder = CertificateBuilder.Create(
            new CertificateOptions
            {
                Subject = DistinguishedName.FromString("CN=Responder"),
                PublicKey = PublicKeyInfo.FromAsymmetricAlgorithm(responderKey),
                NotBefore = Born,
                NotAfter = Dies,
                Extensions = [Extension.Create(new ExtendedKeyUsage([KnownOids.OcspSigning]), false)],
            },
            pki.Root.Certificate,
            pki.Sha1,
            CryptoPolicy.Permissive);
        OcspBasicResponse resp = OcspResponseBuilder.CreateSuccessful(
            new OcspResponseOptions
            {
                Responder = new OcspResponderId(responder.Subject),
                ProducedAt = Y2026.AddHours(-1),
                Responses = [new OcspSingleResponseInfo(OcspCertId.Create(pki.Leaf.Certificate, pki.Root.Certificate), OcspCertStatus.Good, Y2026.AddHours(-1), Y2026.AddDays(1))],
                Certificates = [responder],
            },
            X509Signer.FromECDsa(responderKey)).BasicResponse!;
        RevocationReport rev = Pki.Rev(pki.Validate(new RevocationData { OcspResponses = [resp] }));
        Assert.Equal(RevocationStatus.Unknown, rev.Status);
        Assert.Contains(rev.PolicyDecisions, d => d.Rule == "hash.sha-1.pki.rejected-from");
    }

    // O2: a CRL past nextUpdate cannot show that a certificate is not revoked (RFC 5280 §6.3.3 (a)), but a revocation for any reason except
    // certificateHold is final (§5.3.1), so an authentic stale CRL that lists the certificate for such a reason still says "revoked".
    [Theory]
    [InlineData(RevocationReason.KeyCompromise, RevocationStatus.Revoked)]
    [InlineData(RevocationReason.Superseded, RevocationStatus.Revoked)]
    [InlineData(RevocationReason.CertificateHold, RevocationStatus.Unknown)]
    public void AStaleCrlThatNamesTheCertificateIsReported(RevocationReason reason, RevocationStatus expected)
    {
        using var pki = new Pki(Y2026);
        var listed = new[] { new RevokedCertificateInfo(RNode.Serial(pki.Leaf.Certificate), Y2026.AddDays(-40), reason) };
        CertificateRevocationList stale = pki.Crl(pki.Root.Signer, Y2026.AddDays(-30), Y2026.AddDays(-20), listed);
        RevocationReport rev = Pki.Rev(pki.Validate(new RevocationData { Crls = [stale] }));
        Assert.Equal(expected, rev.Status);
        Assert.Contains("stale", expected == RevocationStatus.Revoked ? rev.Reason : string.Join(' ', rev.Notes), StringComparison.Ordinal);
    }

    [Fact]
    public void AStaleCrlThatDoesNotListTheCertificateStaysUnknownAndSaysSo()
    {
        using var pki = new Pki(Y2026);
        CertificateRevocationList stale = pki.Crl(pki.Root.Signer, Y2026.AddDays(-30), Y2026.AddDays(-20));
        RevocationReport rev = Pki.Rev(pki.Validate(new RevocationData { Crls = [stale] }));
        Assert.Equal(RevocationStatus.Unknown, rev.Status);
        Assert.Contains(rev.Notes, n => n.Contains("stale", StringComparison.Ordinal));
    }

    [Fact]
    public void AStaleCrlSignedByAStrangerIsNotTrustedEvenIfItListsTheCertificate()
    {
        using var pki = new Pki(Y2026);
        using var stranger = RNode.Make("Root", null, true);
        var listed = new[] { new RevokedCertificateInfo(RNode.Serial(pki.Leaf.Certificate), Y2026.AddDays(-40), RevocationReason.KeyCompromise) };
        CertificateRevocationList forged = RevocationListBuilder.Create(
            new RevocationListOptions { ThisUpdate = Y2026.AddDays(-30), NextUpdate = Y2026.AddDays(-20), Number = 1, Revoked = listed },
            stranger.Signer,
            pki.Root.Certificate,
            CryptoPolicy.Permissive);
        Assert.Equal(RevocationStatus.Unknown, Pki.Rev(pki.Validate(new RevocationData { Crls = [forged] })).Status);
    }

    // O3: RFC 6960 §4.2.2.2.1: a delegated responder certificate without id-pkix-ocsp-nocheck is subject to revocation checking.
    [Theory]
    [InlineData(false, true, "CRL")]
    [InlineData(false, false, "OCSP")]
    [InlineData(true, true, "OCSP")]
    public void ADelegatedResponderIsCheckedForRevocationUnlessItHasNoCheck(bool noCheck, bool responderRevoked, string answeredBy)
    {
        using var pki = new Pki(Y2026);
        var ext = new List<Extension> { Extension.Create(new ExtendedKeyUsage([KnownOids.OcspSigning]), false) };
        if (noCheck)
        {
            ext.Add(Extension.Create(new OcspNoCheck(), false));
        }

        using var responder = RNode.Make("Responder", pki.Root, false, ext, notBefore: Born, notAfter: Dies);
        OcspBasicResponse resp = OcspResponseBuilder.CreateSuccessful(
            new OcspResponseOptions
            {
                Responder = new OcspResponderId(responder.Certificate.Subject),
                ProducedAt = Y2026.AddHours(-1),
                Responses = [new OcspSingleResponseInfo(OcspCertId.Create(pki.Leaf.Certificate, pki.Root.Certificate), OcspCertStatus.Good, Y2026.AddHours(-1), Y2026.AddDays(1))],
                Certificates = [responder.Certificate],
            },
            responder.Signer).BasicResponse!;
        var listed = responderRevoked ? new[] { new RevokedCertificateInfo(RNode.Serial(responder.Certificate), Y2026.AddDays(-2), RevocationReason.KeyCompromise) } : [];
        // The root's CRL lists the responder (or nothing) and says the leaf is fine. The report prefers OCSP when OCSP is usable, so its source shows which data answered.
        CertificateRevocationList crl = pki.Crl(pki.Root.Signer, Y2026.AddDays(-1), Y2026.AddDays(6), listed);
        RevocationReport rev = Pki.Rev(pki.Validate(new RevocationData { Crls = [crl], OcspResponses = [resp] }));
        Assert.Equal(RevocationStatus.Good, rev.Status);
        Assert.Equal(answeredBy, rev.Source);
        if (answeredBy == "CRL")
        {
            Assert.Contains(rev.Notes, n => n.Contains("responder certificate is revoked", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void ADelegatedResponderWithNoCheckAndNoCrlIsTrustedAndTheReportSaysWhy()
    {
        using var pki = new Pki(Y2026);
        using var responder = RNode.Make("Responder", pki.Root, false, [Extension.Create(new ExtendedKeyUsage([KnownOids.OcspSigning]), false)], notBefore: Born, notAfter: Dies);
        OcspBasicResponse resp = OcspResponseBuilder.CreateSuccessful(
            new OcspResponseOptions
            {
                Responder = new OcspResponderId(responder.Certificate.Subject),
                ProducedAt = Y2026.AddHours(-1),
                Responses = [new OcspSingleResponseInfo(OcspCertId.Create(pki.Leaf.Certificate, pki.Root.Certificate), OcspCertStatus.Good, Y2026.AddHours(-1), Y2026.AddDays(1))],
                Certificates = [responder.Certificate],
            },
            responder.Signer).BasicResponse!;
        RevocationReport rev = Pki.Rev(pki.Validate(new RevocationData { OcspResponses = [resp] }));
        Assert.Equal(RevocationStatus.Good, rev.Status);
        Assert.Contains(rev.Notes, n => n.Contains("id-pkix-ocsp-nocheck", StringComparison.Ordinal));
    }

    // O4: RFC 5280 §5.3.1: removeFromCRL is defined for a certificate on hold, so a delta CRL cannot lift any other revocation.
    [Theory]
    [InlineData(RevocationReason.CertificateHold, RevocationStatus.Good)]
    [InlineData(RevocationReason.KeyCompromise, RevocationStatus.Revoked)]
    [InlineData(RevocationReason.Superseded, RevocationStatus.Revoked)]
    public void RemoveFromCrlLiftsOnlyAHold(RevocationReason baseReason, RevocationStatus expected)
    {
        using var pki = new Pki(Y2026);
        var serial = RNode.Serial(pki.Leaf.Certificate);
        CertificateRevocationList baseCrl = pki.Crl(pki.Root.Signer, Y2026.AddDays(-3), Y2026.AddDays(4), [new RevokedCertificateInfo(serial, Y2026.AddDays(-5), baseReason)], number: 1);
        CertificateRevocationList delta = RevocationListBuilder.Create(
            new RevocationListOptions
            {
                ThisUpdate = Y2026.AddDays(-1),
                NextUpdate = Y2026.AddDays(2),
                Number = 2,
                DeltaBaseNumber = 1,
                Revoked = [new RevokedCertificateInfo(serial, Y2026.AddDays(-1), RevocationReason.RemoveFromCrl)],
            },
            pki.Root.Signer,
            pki.Root.Certificate,
            CryptoPolicy.Permissive);
        Assert.Equal(expected, Pki.Rev(pki.Validate(new RevocationData { Crls = [baseCrl, delta] })).Status);
    }
}
