using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Validation;

/// <summary>
/// RFC 5937 §2: a trust anchor is a name and a key. The anchor certificate's own extensions are not path-validated, so a root that real
/// authorities publish with basicConstraints not marked critical, or with no extensions at all (version 1), still anchors a path.
/// </summary>
public class TrustAnchorTests
{
    private static readonly DateTimeOffset Now = RNode.Now;

    private static ValidationReport Validate(Certificate leaf, Certificate root, bool strictAnchor = false) => PathValidator.Validate(leaf, new ValidationOptions
    {
        TrustAnchors = [TrustAnchor.FromCertificate(root)],
        ReferenceTime = Now,
        StrictAnchorStructure = strictAnchor,
    });

    [Fact]
    public void ARootWithBasicConstraintsNotMarkedCriticalAnchorsAPath()
    {
        using var root = RNode.Make("Root", null, true, [Extension.Create(new BasicConstraints(true), false)]);
        using var leaf = RNode.Make("leaf", root, false);
        ValidationReport r = Validate(leaf.Certificate, root.Certificate);
        Assert.Equal(ValidationVerdict.Valid, r.Verdict);
    }

    [Fact]
    public void TheStrictAnchorOptionRestoresTheCheckOnTheAnchorsOwnExtensions()
    {
        using var root = RNode.Make("Root", null, true, [Extension.Create(new BasicConstraints(true), false)]);
        using var leaf = RNode.Make("leaf", root, false);
        ValidationReport r = Validate(leaf.Certificate, root.Certificate, strictAnchor: true);
        Assert.Equal(ValidationVerdict.Invalid, r.Verdict);
        Assert.Contains("basicConstraints", string.Join(" ", r.SelectedPath?.PathResults.Select(static x => x.Reason) ?? r.Paths.SelectMany(static p => p.PathResults).Select(static x => x.Reason)), StringComparison.Ordinal);
    }

    [Fact]
    // Accepted before this change as well; kept as a guard for the no-extension form.
    public void AVersion1RootWithNoExtensionsAnchorsAPath()
    {
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Signer rootSigner = X509Signer.FromECDsa(rootKey);
        Certificate root = CertificateBuilder.CreateSelfSigned(
            new CertificateOptions
            {
                Subject = DistinguishedName.FromString("CN=Old v1 Root"),
                PublicKey = PublicKeyInfo.FromAsymmetricAlgorithm(rootKey),
                NotBefore = Now.AddYears(-1),
                NotAfter = Now.AddYears(1),
                AddSubjectKeyIdentifier = false,
                AddAuthorityKeyIdentifier = false,
            },
            rootSigner);
        Assert.Equal(1, root.Version);

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Certificate leaf = CertificateBuilder.Create(
            new CertificateOptions
            {
                Subject = DistinguishedName.FromString("CN=leaf"),
                PublicKey = PublicKeyInfo.FromAsymmetricAlgorithm(leafKey),
                NotBefore = Now.AddYears(-1),
                NotAfter = Now.AddMonths(6),
                Extensions =
                [
                    Extension.Create(new BasicConstraints(false), true),
                    Extension.Create(new SubjectAlternativeName([GeneralName.Dns("leaf.example.test")]), false),
                    Extension.Create(new ExtendedKeyUsage([KnownOids.ServerAuth]), false),
                ],
            },
            root,
            rootSigner);
        Assert.Equal(ValidationVerdict.Valid, Validate(leaf, root).Verdict);
    }

    [Fact]
    public void ATimeStampingRootShapedLikeAPublicAuthoritysAnchorsAPath()
    {
        // A self-signed root with basicConstraints (not critical), a key usage and identifiers, issuing a time-stamping certificate whose
        // extended key usage is critical (RFC 3161 §2.3).
        using var root = RNode.Make("Time Authority Root", null, true, [Extension.Create(new BasicConstraints(true), false)]);
        using var tsa = RNode.Make(
            "Time Authority",
            root,
            false,
            [Extension.Create(new ExtendedKeyUsage([KnownOids.TimeStamping]), true), Extension.Create(new BasicConstraints(false), false)]);
        ValidationReport r = PathValidator.Validate(tsa.Certificate, new ValidationOptions
        {
            TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
            ReferenceTime = Now,
            RequiredExtendedKeyUsage = KnownOids.TimeStamping,
        });
        Assert.Equal(ValidationVerdict.Valid, r.Verdict);
        ValidationReport old = PathValidator.Validate(tsa.Certificate, new ValidationOptions
        {
            TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
            ReferenceTime = Now,
            RequiredExtendedKeyUsage = KnownOids.TimeStamping,
            StrictAnchorStructure = true,
        });
        Assert.Equal(ValidationVerdict.Invalid, old.Verdict); // what every earlier build did
    }
}
