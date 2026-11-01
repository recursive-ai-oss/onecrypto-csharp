using System.Diagnostics;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;


namespace OneCrypto.Tests.Validation;

/// <summary>
/// The cost of a large intermediate pool combined with CRL signers that need their own validation. Every copy of the CRL signer's certificate
/// is validated as a CRL signer, and each of those checks revocation again through the same CRL, so without one shared work budget the sub-validations
/// multiply (copies ^ depth). The test builds the case, prints the time, and asserts a loose bound.
/// </summary>
public class PoolScaleTests
{
    private static readonly DateTimeOffset Now = RNode.Now;

    private static (ValidationOptions Options, Certificate Leaf) Build(int decoys, int signerCopies, bool expired)
    {
        using var root = RNode.Make("Root", null, true);
        var ca = RNode.Make("CA", root, true);
        using var stranger = RNode.Make("Stranger", null, true);
        var crlIssuer = new List<GeneralName> { GeneralName.FromDirectoryName(DistinguishedName.FromString("CN=CRL Signer")) };
        Extension viaSigner = Extension.Create(new CrlDistributionPoints([new DistributionPoint(null, null, crlIssuer)]), false);
        var signer = RNode.Make("CRL Signer", root, true, [viaSigner]);
        var pool = new List<Certificate> { ca.Certificate };
        // Copies of the signer's certificate (same name, same key) come first, issued by a CA nobody trusts: each verifies the CRL, so each is validated as a CRL signer and rejected.
        for (int i = 0; i < signerCopies; i++)
        {
            pool.Add(expired
                ? RNode.Reissue(signer, root, [RNode.CaBasic, RNode.CaUsage, viaSigner], Now.AddDays(-1 - i))
                : RNode.Reissue(signer, stranger, [RNode.CaBasic, RNode.CaUsage, viaSigner], Now.AddDays(30 + i)));
        }

        pool.Add(signer.Certificate);
        for (int i = 0; i < decoys; i++)
        {
            pool.Add(RNode.Make("Decoy " + i, root, true).Certificate);
        }

        var leaf = RNode.Make("leaf", ca, false, [viaSigner]);
        CertificateRevocationList crl = RNode.Crl(signer, extensions: [Extension.Create(new IssuingDistributionPoint(null, IndirectCrl: true), true)]);
        ValidationOptions o = RNode.Options([root], pool, new RevocationData { Crls = [crl] }, RevocationScope.AllCertificates);
        return (o, leaf.Certificate);
    }

    [Theory]
    [InlineData(1000, 5, false)]
    [InlineData(1000, 10, false)]
    [InlineData(1000, 200, false)]
    [InlineData(1000, 10, true)]
    [InlineData(1000, 200, true)]
    public void ThousandCertificatePoolWithManyCrlSignerCopiesStaysBounded(int decoys, int copies, bool expired)
    {
        (ValidationOptions o, Certificate leaf) = Build(decoys, copies, expired);
        var sw = Stopwatch.StartNew();
        ValidationReport r = PathValidator.Validate(leaf, o);
        sw.Stop();
        TestContext.Current.SendDiagnosticMessage($"pool {decoys + copies + 2}, signer copies {copies} (expired {expired}): {sw.ElapsedMilliseconds} ms, verdict {r.Verdict}, revocation {r.RevocationSummary} ({r.SelectedPath?.Certificates[^1].Revocation.Reason}), limit {r.LimitReached}");
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30), $"took {sw.Elapsed}");
    }
}
