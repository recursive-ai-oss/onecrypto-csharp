using OneCrypto.Tests.Support;
using OneCrypto.Tests.Validation;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Cms;

/// <summary>
/// Received certificates, CRLs and OCSP responses decode their extensions on first use, so a malformed extension value only shows up deep inside
/// verification. Verification and validation report such data as a finding; they never raise from the middle of a check.
/// </summary>
public class LazyDecodeTests
{
    private static readonly DateTimeOffset Now = RNode.Now;
    private static readonly byte[] Content = "lazy decode"u8.ToArray();

    // An OCTET STRING that claims more content than it holds: well-formed enough to be stored, undecodable as any extension value.
    private static readonly byte[] Broken = [0x04, 0x20, 0x01];

    public static TheoryData<string> BrokenExtensions => new()
    {
        KnownOids.SubjectKeyIdentifier,
        KnownOids.AuthorityKeyIdentifier,
        KnownOids.SubjectAltName,
        KnownOids.KeyUsage,
        KnownOids.BasicConstraints,
        KnownOids.ExtendedKeyUsage,
    };

    private static Extension Bad(string oid) => Extension.Create(oid, false, Broken);

    private static IReadOnlyList<Extension> With(Certificate c, string oid) => [.. c.Extensions.Where(e => e.Oid != oid), Bad(oid)];

    [Fact]
    public void TheRecordedFuzzCrashReplaysAsAReport()
    {
        byte[] file = File.ReadAllBytes(Path.Combine(TestFiles.TestData, "fuzz", "cms-signer-certificate-malformed-ski.bin"));
        byte[] cms = file[1..];
        Assert.True(SignedData.TryParse(cms, out SignedData? sd, allowTrailingZeros: (file[0] & 4) != 0));
        SignedDataReport report = sd!.Verify();
        Assert.False(report.IsValid);
        _ = sd.Verify(Content);

        // The streaming reader is stricter about BER and may refuse the message; a typed parse error is the allowed answer.
        try
        {
            _ = SignedData.VerifyStream(new MemoryStream(cms), null, null, new CmsLimits { MaxContentBytes = 1 << 20 });
        }
        catch (CmsParseException)
        {
        }
    }

    [Theory]
    [MemberData(nameof(BrokenExtensions))]
    public void ASignerCertificateWithABrokenExtensionIsReportedNotThrown(string oid)
    {
        using RNode root = RNode.Make("Root", null, true);
        using RNode good = RNode.Make("signer", root, false);
        Certificate broken = RNode.Reissue(good, root, With(good.Certificate, oid));

        // Embedded as the signer's own certificate, found by issuer and serial number.
        SignedData sd = SignedData.Create(Content, [new CmsSignerSpec { Certificate = broken, Signer = good.Signer }]);
        var chain = new ValidationOptions { TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)], ReferenceTime = Now };
        SignedDataReport plain = SignedData.Parse(sd.Encoded).Verify(new SignedDataVerifyOptions { Chain = chain });
        Assert.NotNull(plain);

        // Embedded beside a good signer and looked up by key identifier: the unreadable certificate matches nobody.
        SignedData byKey = SignedData.Create(
            Content,
            [new CmsSignerSpec { Certificate = good.Certificate, Signer = good.Signer, Identifier = CmsIdentifierKind.SubjectKeyIdentifier }],
            new SignedDataOptions { IncludeSignerCertificates = false, Certificates = [broken] });
        SignedDataReport report = SignedData.Parse(byKey.Encoded).Verify();
        CmsCheck found = report.Signers[0].Checks.Single(c => c.Rule == "signer-certificate");
        if (oid == KnownOids.SubjectKeyIdentifier)
        {
            Assert.False(report.IsValid);
            Assert.Equal(CmsCheckStatus.Failed, found.Status);
            Assert.Contains("cannot be decoded", found.Reason, StringComparison.Ordinal);
        }

        // The signature itself still checks out once the right certificate is supplied.
        Assert.True(SignedData.Parse(byKey.Encoded).Verify(new SignedDataVerifyOptions { ExtraCertificates = [good.Certificate], AnyOfKeyUsages = KeyUsages.None }).Signers[0].Checks
            .Single(c => c.Rule == "signature").Status == CmsCheckStatus.Passed);
    }

    [Theory]
    [MemberData(nameof(BrokenExtensions))]
    public void APoolCertificateWithABrokenExtensionIsJudgedNotThrown(string oid)
    {
        using RNode root = RNode.Make("Root", null, true);
        using RNode ca = RNode.Make("CA", root, true);
        using RNode leaf = RNode.Make("leaf", ca, false);
        Certificate broken = RNode.Reissue(ca, root, With(ca.Certificate, oid));

        ValidationReport r = PathValidator.Validate(leaf.Certificate, ReviewSupportOptions(root, [broken]));
        Assert.NotNull(r);
        if (oid is KnownOids.BasicConstraints or KnownOids.KeyUsage)
        {
            // Undecodable CA constraints are not read as "no constraint".
            Assert.False(r.IsValid);
        }

        // The same certificate as the target and as the trust anchor's issuer chain does not raise either.
        Assert.NotNull(PathValidator.Validate(broken, ReviewSupportOptions(root, [])));
    }

    [Fact]
    public void ACrlEntryWithABrokenExtensionMakesTheCrlUnusableNotFatal()
    {
        using RNode root = RNode.Make("Root", null, true);
        using RNode leaf = RNode.Make("leaf", root, false);
        foreach (string oid in new[] { KnownOids.CrlReason, KnownOids.CertificateIssuer, KnownOids.InvalidityDate })
        {
            CertificateRevocationList crl = RNode.Crl(
                root,
                [new RevokedCertificateInfo(RNode.Serial(leaf.Certificate), Now.AddDays(-1), null, null, [Bad(oid)])]);
            ValidationReport r = PathValidator.Validate(leaf.Certificate, new ValidationOptions
            {
                TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
                ReferenceTime = Now,
                Revocation = new RevocationData { Crls = [crl] },
                RevocationRequired = RevocationScope.EndEntity,
                UnknownRevocationIsFatal = false,
            });
            RevocationReport rev = r.SelectedPath!.Certificates[^1].Revocation;
            Assert.NotEqual(RevocationStatus.Good, rev.Status);
        }
    }

    [Fact]
    public void AnOcspResponseWithABrokenEntryExtensionDoesNotAbortValidation()
    {
        using RNode root = RNode.Make("Root", null, true);
        using RNode leaf = RNode.Make("leaf", root, false);
        OcspBasicResponse basic = OcspResponseBuilder.CreateSuccessful(
            new OcspResponseOptions
            {
                Responder = new OcspResponderId(root.Certificate.Subject),
                ProducedAt = Now.AddHours(-1),
                Responses =
                [
                    new OcspSingleResponseInfo(
                        OcspCertId.Create(leaf.Certificate, root.Certificate),
                        OcspCertStatus.Good,
                        Now.AddHours(-1),
                        Now.AddDays(1),
                        Extensions: [Extension.Create(KnownOids.CrlReason, false, Broken)]),
                ],
            },
            root.Signer).BasicResponse!;
        ValidationReport r = PathValidator.Validate(leaf.Certificate, new ValidationOptions
        {
            TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
            ReferenceTime = Now,
            Revocation = new RevocationData { OcspResponses = [basic] },
            RevocationRequired = RevocationScope.EndEntity,
            UnknownRevocationIsFatal = false,
        });
        Assert.NotNull(r.SelectedPath);
    }

    private static ValidationOptions ReviewSupportOptions(RNode root, IEnumerable<Certificate> pool) => new()
    {
        TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
        Intermediates = [.. pool],
        ReferenceTime = Now,
    };
}
