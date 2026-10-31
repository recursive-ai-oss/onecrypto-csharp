using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Validation;

/// <summary>Behaviour of the validator on generated chains: verdicts, rules, revocation, the past-time model, the work limits and the optional sources.</summary>
public class ValidatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private sealed class Node : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public Node(string cn, Node? issuer, bool ca, IReadOnlyList<Extension>? extra = null, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
        {
            Signer = X509Signer.FromECDsa(_key);
            var ext = new List<Extension>();
            if (ca)
            {
                ext.Add(Extension.Create(new BasicConstraints(true), true));
                ext.Add(Extension.Create(new KeyUsageExtension(KeyUsages.KeyCertSign | KeyUsages.CrlSign | KeyUsages.DigitalSignature), true));
            }
            else
            {
                ext.Add(Extension.Create(new BasicConstraints(false), true));
                ext.Add(Extension.Create(new SubjectAlternativeName([GeneralName.Dns("leaf.example.test")]), false));
                ext.Add(Extension.Create(new ExtendedKeyUsage([KnownOids.ServerAuth]), false));
            }

            foreach (Extension x in extra ?? [])
            {
                ext.RemoveAll(e => e.Oid == x.Oid);
                ext.Add(x);
            }

            var o = new CertificateOptions
            {
                Subject = DistinguishedName.FromString("CN=" + cn),
                PublicKey = PublicKeyInfo.FromAsymmetricAlgorithm(_key),
                NotBefore = notBefore ?? Now.AddYears(-1),
                NotAfter = notAfter ?? Now.AddYears(1),
                Extensions = ext,
            };
            Certificate = issuer is null ? CertificateBuilder.CreateSelfSigned(o, Signer) : CertificateBuilder.Create(o, issuer.Certificate, issuer.Signer);
        }

        public X509Signer Signer { get; }

        public Certificate Certificate { get; }

        public void Dispose() => _key.Dispose();
    }

    private static ValidationOptions Opts(Node root, IEnumerable<Node> inter, DateTimeOffset? at = null, RevocationData? rev = null, RevocationScope scope = RevocationScope.None, bool fatal = false) => new()
    {
        TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
        Intermediates = inter.Select(n => n.Certificate).ToList(),
        ReferenceTime = at ?? Now,
        Revocation = rev,
        RevocationRequired = scope,
        UnknownRevocationIsFatal = fatal,
    };

    private static CertificateRevocationList Crl(Node issuer, DateTimeOffset thisUpdate, params RevokedCertificateInfo[] revoked) =>
        RevocationListBuilder.Create(
            new RevocationListOptions { ThisUpdate = thisUpdate, NextUpdate = thisUpdate.AddDays(7), Number = 1, Revoked = revoked },
            issuer.Signer,
            issuer.Certificate);

    [Fact]
    public void ValidChainReportsEveryRuleForEveryCertificate()
    {
        using var root = new Node("Root", null, true);
        using var ca = new Node("CA", root, true);
        using var leaf = new Node("leaf", ca, false);
        ValidationReport r = PathValidator.Validate(leaf.Certificate, Opts(root, [ca]));
        Assert.Equal(ValidationVerdict.Valid, r.Verdict);
        Assert.Null(r.DecidingRule);
        PathReport p = r.SelectedPath!;
        Assert.Equal(2, p.Certificates.Length);
        Assert.Equal(RevocationStatus.NotChecked, r.RevocationSummary);
        foreach (CertificateReport c in p.Certificates)
        {
            Assert.Contains(c.Results, x => x.Rule == ValidationRule.Signature && x.Outcome == RuleOutcome.Pass && x.Clause.Contains("6.1.3", StringComparison.Ordinal));
            Assert.Contains(c.Results, x => x.Rule == ValidationRule.Validity);
        }
    }

    [Fact]
    public void ReferenceTimeDecidesValidity()
    {
        using var root = new Node("Root", null, true, notBefore: Now.AddYears(-3));
        using var leaf = new Node("leaf", root, false, notBefore: Now.AddYears(-2), notAfter: Now.AddYears(-1));
        ValidationReport late = PathValidator.Validate(leaf.Certificate, Opts(root, []));
        Assert.Equal(ValidationVerdict.Invalid, late.Verdict);
        Assert.Equal(ValidationRule.Validity, late.DecidingRule!.Rule);
        ValidationReport earlier = PathValidator.Validate(leaf.Certificate, Opts(root, [], at: Now.AddMonths(-18)));
        Assert.Equal(ValidationVerdict.Valid, earlier.Verdict);
    }

    [Fact]
    public void AnUntrustedChainHasNoPathAndSurfacesIssuerLocations()
    {
        using var root = new Node("Root", null, true);
        using var other = new Node("Other", null, true);
        using var leaf = new Node("leaf", root, false);
        ValidationReport r = PathValidator.Validate(leaf.Certificate, Opts(other, []));
        Assert.Equal(ValidationVerdict.Invalid, r.Verdict);
        Assert.Equal(ValidationRule.PathBuilding, r.DecidingRule!.Rule);
        Assert.Single(r.Unchained);
    }

    [Fact]
    public void NameConstraintsAndPathLengthApplyBelowTheConstrainingCa()
    {
        using var root = new Node("Root", null, true);
        var nc = Extension.Create(new NameConstraints([new GeneralSubtree(GeneralName.Dns("other.test"))], null), true);
        using var ca = new Node("CA", root, true, [nc]);
        using var leaf = new Node("leaf", ca, false);
        ValidationReport r = PathValidator.Validate(leaf.Certificate, Opts(root, [ca]));
        Assert.Equal(ValidationRule.NameConstraints, r.DecidingRule!.Rule);

        using var pl = new Node("PL", root, true, [Extension.Create(new BasicConstraints(true, 0), true)]);
        using var sub = new Node("Sub", pl, true);
        using var leaf2 = new Node("leaf", sub, false);
        ValidationReport r2 = PathValidator.Validate(leaf2.Certificate, Opts(root, [pl, sub]));
        Assert.Equal(ValidationRule.PathLengthConstraint, r2.DecidingRule!.Rule);
    }

    [Fact]
    public void RevocationFromCrlsIsReportedAndOfflineIsUnknownNeverGood()
    {
        using var root = new Node("Root", null, true);
        using var leaf = new Node("leaf", root, false);
        var rev = new BigInteger(leaf.Certificate.SerialNumber.Span, isUnsigned: false, isBigEndian: true);

        ValidationReport none = PathValidator.Validate(leaf.Certificate, Opts(root, [], scope: RevocationScope.EndEntity));
        Assert.Equal(ValidationVerdict.Valid, none.Verdict);
        Assert.Equal(RevocationStatus.Unknown, none.RevocationSummary);
        Assert.Equal(ValidationVerdict.Indeterminate, PathValidator.Validate(leaf.Certificate, Opts(root, [], scope: RevocationScope.EndEntity, fatal: true)).Verdict);

        CertificateRevocationList empty = Crl(root, Now.AddDays(-1));
        ValidationReport good = PathValidator.Validate(leaf.Certificate, Opts(root, [], rev: new RevocationData { Crls = [empty] }, scope: RevocationScope.EndEntity, fatal: true));
        Assert.Equal(ValidationVerdict.Valid, good.Verdict);
        Assert.Equal(RevocationStatus.Good, good.RevocationSummary);

        CertificateRevocationList listed = Crl(root, Now.AddDays(-1), new RevokedCertificateInfo(rev, Now.AddDays(-2), RevocationReason.KeyCompromise));
        ValidationReport bad = PathValidator.Validate(leaf.Certificate, Opts(root, [], rev: new RevocationData { Crls = [listed] }));
        Assert.Equal(ValidationVerdict.Invalid, bad.Verdict);
        Assert.Equal(RevocationStatus.Revoked, bad.SelectedPath!.Certificates[0].Revocation.Status);

        CertificateRevocationList stale = Crl(root, Now.AddDays(-30));
        ValidationReport old = PathValidator.Validate(leaf.Certificate, Opts(root, [], rev: new RevocationData { Crls = [stale] }, scope: RevocationScope.EndEntity));
        Assert.Equal(RevocationStatus.Unknown, old.RevocationSummary);
    }

    [Fact]
    public void PastTimeModelForgivesLaterRevocationUnlessTheKeyWasCompromised()
    {
        using var root = new Node("Root", null, true);
        using var leaf = new Node("leaf", root, false);
        var serial = new BigInteger(leaf.Certificate.SerialNumber.Span, isUnsigned: false, isBigEndian: true);
        DateTimeOffset t = Now.AddMonths(-3); // validate as of three months ago, with a CRL collected now that lists the certificate as revoked a month ago
        CertificateRevocationList superseded = Crl(root, Now.AddDays(-1), new RevokedCertificateInfo(serial, Now.AddMonths(-1), RevocationReason.Superseded));
        CertificateRevocationList compromised = Crl(root, Now.AddDays(-1), new RevokedCertificateInfo(serial, Now.AddMonths(-1), RevocationReason.KeyCompromise));

        ValidationOptions Make(CertificateRevocationList c, RevocationModel m) => new()
        {
            TrustAnchors = [TrustAnchor.FromCertificate(root.Certificate)],
            ReferenceTime = t,
            RevocationDataTime = Now,
            Revocation = new RevocationData { Crls = [c] },
            RevocationRequired = RevocationScope.EndEntity,
            RevocationModel = m,
        };

        Assert.Equal(ValidationVerdict.Invalid, PathValidator.Validate(leaf.Certificate, Make(superseded, RevocationModel.Current)).Verdict);
        Assert.Equal(ValidationVerdict.Valid, PathValidator.Validate(leaf.Certificate, Make(superseded, RevocationModel.PastTime)).Verdict);
        Assert.Equal(ValidationVerdict.Invalid, PathValidator.Validate(leaf.Certificate, Make(compromised, RevocationModel.PastTime)).Verdict);
    }

    [Fact]
    public void OcspResponsesAreCheckedForAuthorityAndFreshness()
    {
        using var root = new Node("Root", null, true);
        using var leaf = new Node("leaf", root, false);
        using var rogue = new Node("Rogue", null, true);
        OcspCertId id = OcspCertId.Create(leaf.Certificate, root.Certificate);

        OcspBasicResponse Respond(Node signer, OcspCertStatus status, DateTimeOffset thisUpdate) => OcspResponseBuilder.CreateSuccessful(
            new OcspResponseOptions
            {
                Responder = new OcspResponderId(signer.Certificate.Subject),
                ProducedAt = thisUpdate,
                Responses = [new OcspSingleResponseInfo(id, status, thisUpdate, thisUpdate.AddDays(1), status == OcspCertStatus.Revoked ? thisUpdate.AddHours(-1) : null, null)],
            },
            signer.Signer).BasicResponse!;

        ValidationOptions With(OcspBasicResponse r) => Opts(root, [], rev: new RevocationData { OcspResponses = [r] }, scope: RevocationScope.EndEntity);

        Assert.Equal(RevocationStatus.Good, PathValidator.Validate(leaf.Certificate, With(Respond(root, OcspCertStatus.Good, Now.AddHours(-1)))).RevocationSummary);
        Assert.Equal(ValidationVerdict.Invalid, PathValidator.Validate(leaf.Certificate, With(Respond(root, OcspCertStatus.Revoked, Now.AddHours(-1)))).Verdict);
        Assert.Equal(RevocationStatus.Unknown, PathValidator.Validate(leaf.Certificate, With(Respond(root, OcspCertStatus.Good, Now.AddDays(-5)))).RevocationSummary); // stale
        Assert.Equal(RevocationStatus.Unknown, PathValidator.Validate(leaf.Certificate, With(Respond(rogue, OcspCertStatus.Good, Now.AddHours(-1)))).RevocationSummary); // not the issuer, not delegated
    }

    [Fact]
    public async Task SourcesAreAskedOnlyByTheAsyncCallAndOnlyForWhatIsMissing()
    {
        using var root = new Node("Root", null, true);
        using var ca = new Node("CA", root, true);
        using var leaf = new Node("leaf", ca, false);
        var source = new Source(ca.Certificate);
        ValidationOptions o = Opts(root, []) is var b ? new ValidationOptions { TrustAnchors = b.TrustAnchors, ReferenceTime = Now, CertificateSource = source } : null!;
        Assert.Equal(ValidationVerdict.Invalid, PathValidator.Validate(leaf.Certificate, o).Verdict);
        Assert.Equal(0, source.Calls);
        ValidationReport r = await PathValidator.ValidateAsync(leaf.Certificate, o, CancellationToken.None);
        Assert.Equal(ValidationVerdict.Valid, r.Verdict);
        Assert.Equal(1, source.Calls);
    }

    private sealed class Source(Certificate found) : ICertificateSource
    {
        public int Calls { get; private set; }

        public ValueTask<IReadOnlyList<Certificate>> FindIssuersAsync(Certificate subject, IReadOnlyList<string> caIssuersUris, CancellationToken cancellationToken)
        {
            Calls++;
            return new ValueTask<IReadOnlyList<Certificate>>([found]);
        }
    }

    [Fact]
    public void TheSideBySideReportAgreesOnAPlainChainAndDisagreesWhereTheRulesDiffer()
    {
        using var root = new Node("Root", null, true);
        using var leaf = new Node("leaf", root, false);
        ValidationOptions o = Opts(root, []);
        ChainDiagnostic same = ChainDiagnostics.Compare(leaf.Certificate, o, PathValidator.Validate(leaf.Certificate, o));
        Assert.True(same.Agrees, same.Note + " " + same.PlatformStatus);

        // Excluding the leaf's name makes us refuse a chain the platform engine (which ignores nothing here, but is not asked about names) may accept.
        var nc = Extension.Create(new NameConstraints(null, [new GeneralSubtree(GeneralName.Dns("leaf.example.test"))]), true);
        using var ca = new Node("CA", root, true, [nc]);
        using var leaf2 = new Node("leaf", ca, false);
        ValidationOptions o2 = Opts(root, [ca]);
        ValidationReport r2 = PathValidator.Validate(leaf2.Certificate, o2);
        Assert.False(r2.IsValid);
        ChainDiagnostic diff = ChainDiagnostics.Compare(leaf2.Certificate, o2, r2);
        Assert.Equal(ValidationVerdict.Invalid, diff.OurVerdict);
    }

    [Fact]
    public void TheOsStoreLoaderYieldsAnchorsWithoutThrowing()
    {
        IReadOnlyList<TrustAnchor> roots = OsTrustStore.LoadRoots();
        Assert.All(roots, a => Assert.NotNull(a.Certificate));
    }

    // ---------------------------------------------------------------- denial-of-service constructions

    [Fact]
    public void PolicyTreeExplosionStopsAtTheNodeLimit()
    {
        // Every CA asserts ten policies and maps each to all ten, so each node of the tree gets ten children per level: 10^levels nodes.
        const int K = 10;
        string[] pol = [.. Enumerable.Range(1, K).Select(i => "2.16.840.1.101.3.2.1.48." + i)];
        Extension policies = Extension.Create(new CertificatePolicies([.. pol.Select(p => new PolicyInformation(p, []))]), false);
        Extension mappings = Extension.Create(new PolicyMappings([.. pol.SelectMany(a => pol.Where(b => b != a).Select(b => new PolicyMapping(a, b)))]), false);
        using var root = new Node("Root", null, true);
        var nodes = new List<Node>();
        Node parent = root;
        for (int i = 0; i < 12; i++)
        {
            var n = new Node("CA" + i, parent, true, [policies, mappings]);
            nodes.Add(n);
            parent = n;
        }

        using var leaf = new Node("leaf", parent, false, [policies]);
        var sw = Stopwatch.StartNew();
        ValidationReport r = PathValidator.Validate(leaf.Certificate, Opts(root, nodes));
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"took {sw.Elapsed}");
        Assert.Equal(ValidationVerdict.Invalid, r.Verdict);
        Assert.Equal(ValidationRule.Policy, r.DecidingRule!.Rule);
        Assert.Contains("nodes", r.DecidingRule.Reason, StringComparison.Ordinal);
        foreach (Node n in nodes)
        {
            n.Dispose();
        }
    }

    [Fact]
    public void ACrossCertificateLatticeIsSearchedWithinTheStepLimit()
    {
        // Eight levels of six keys each, every key certified by every key of the level above under one name: 6^8 paths, none reaching the anchor.
        const int Levels = 8;
        const int Width = 6;
        var keys = new Node[Levels + 1][];
        using var anchor = new Node("Anchor", null, true);
        var all = new List<Node>();
        var pool = new List<Certificate>();
        for (int level = 0; level <= Levels; level++)
        {
            keys[level] = new Node[Width];
            for (int k = 0; k < Width; k++)
            {
                // One certificate per (key, issuing key above) pair; the issuing keys of the top level belong to an unrelated root.
                keys[level][k] = new Node("L" + level, level == 0 ? null : keys[level - 1][k], true);
                all.Add(keys[level][k]);
            }
        }

        // Cross certificates: key j of level L certified by key i of level L-1, for every pair.
        for (int level = 1; level <= Levels; level++)
        {
            for (int i = 0; i < Width; i++)
            {
                for (int j = 0; j < Width; j++)
                {
                    pool.Add(CrossCertificate(keys[level][j], keys[level - 1][i]));
                }
            }
        }

        using var leaf = new Node("leaf", keys[Levels][0], false);
        var sw = Stopwatch.StartNew();
        ValidationReport r = PathValidator.Validate(leaf.Certificate, new ValidationOptions
        {
            TrustAnchors = [TrustAnchor.FromCertificate(anchor.Certificate)],
            Intermediates = pool,
            ReferenceTime = Now,
        });
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"took {sw.Elapsed}");
        Assert.NotEqual(ValidationVerdict.Valid, r.Verdict);
        Assert.True(r.LimitReached);
        foreach (Node n in all)
        {
            n.Dispose();
        }
    }

    private static Certificate CrossCertificate(Node subject, Node issuer) => CertificateBuilder.Create(
        new CertificateOptions
        {
            Subject = subject.Certificate.Subject,
            PublicKey = subject.Certificate.PublicKey,
            NotBefore = Now.AddYears(-1),
            NotAfter = Now.AddYears(1),
            Extensions = [Extension.Create(new BasicConstraints(true), true), Extension.Create(new KeyUsageExtension(KeyUsages.KeyCertSign), true)],
        },
        issuer.Certificate,
        issuer.Signer);
}
