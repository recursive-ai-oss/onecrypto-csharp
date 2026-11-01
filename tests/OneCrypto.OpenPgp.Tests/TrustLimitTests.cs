using System.Diagnostics;
using RecursiveAI.OneCrypto.OpenPgp.Trust;
using Xunit;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>The matcher, the limits and a dense network of 10,000 certificates.</summary>
public sealed class TrustLimitTests
{
    private static readonly DateTimeOffset Now = new(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("<[^>]+[@.]example\\.org>$", "A <a@example.org>", true)]
    [InlineData("<[^>]+[@.]example\\.org>$", "A <a@evil-example.org>", false)]
    [InlineData("^abc$", "abc", true)]
    [InlineData("a|b", "xbx", true)]
    [InlineData("a(b|c)+d", "xabcbd", true)]
    [InlineData("a(b|c)+d", "xad", false)]
    [InlineData("x{2}", "axxb", true)]
    public void RegexMatches(string pattern, string text, bool expected)
    {
        Assert.True(TrustRegex.TryCompile(pattern, out TrustRegex? re));
        Assert.Equal(expected, re!.IsMatch(text));
    }

    [Fact]
    public void HostileRegexesAreBoundedAndFast()
    {
        // The classic catastrophic-backtracking shape must not blow up: the matcher simulates states instead of backtracking.
        Assert.True(TrustRegex.TryCompile("(a+)+$", out TrustRegex? re));
        var sw = Stopwatch.StartNew();
        Assert.False(re!.IsMatch(new string('a', 20_000) + "b"));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30), sw.Elapsed.ToString());

        // Too long, or too many states: not compiled, never a match.
        Assert.False(TrustRegex.TryCompile(new string('a', 2_000), out _));
        Assert.False(TrustRegex.TryCompile("(((a{100}){100}){100})", out _));
        Assert.False(TrustRegex.TryCompile("(unclosed", out _));
        Assert.Throws<FormatException>(() => TrustRegex.Compile("(unclosed"));
    }

    [Fact]
    public void LimitsRaiseTypedErrors()
    {
        string[] nodes = ["a", "b", "c"];
        TrustCertification[] edges = [new("a", "b", "b"), new("b", "c", "c")];

        var e1 = Assert.Throws<TrustLimitExceededException>(() => TrustNetwork.FromEdges(nodes, edges, Now, new TrustLimits { MaxCertificates = 2 }));
        Assert.Equal(TrustLimit.Certificates, e1.Limit);
        var e2 = Assert.Throws<TrustLimitExceededException>(() => TrustNetwork.FromEdges(nodes, edges, Now, new TrustLimits { MaxCertifications = 1 }));
        Assert.Equal(TrustLimit.Certifications, e2.Limit);

        TrustNetwork net = TrustNetwork.FromEdges(nodes, edges, Now);
        var e3 = Assert.Throws<TrustLimitExceededException>(() => WebOfTrust.Authenticate(net, ["a", "b", "c"], "c", "c", limits: new TrustLimits { MaxRoots = 2 }));
        Assert.Equal(TrustLimit.Roots, e3.Limit);
        var e4 = Assert.Throws<TrustLimitExceededException>(() => WebOfTrust.Authenticate(net, ["a"], "c", "c", limits: new TrustLimits { MaxWork = 1 }));
        Assert.Equal(TrustLimit.Work, e4.Limit);
    }

    [Fact]
    public void ChainOfFullTrustSignaturesAuthenticates()
    {
        TrustNetwork net = TrustNetwork.FromEdges(["a", "b", "c"], [new("a", "b", "b", depth: 1), new("b", "c", "c")], Now);
        FlowAuthentication r = WebOfTrust.Authenticate(net, ["a"], "c", "c");
        Assert.True(r.IsAuthenticated);
        Assert.Equal(120, r.Amount);
    }

    [Fact]
    public void DenseNetworkOf10000CertificatesFinishesOrStopsWithTheTypedError()
    {
        // Every certificate certifies its next 40 neighbours (400,000 edges), all as introducers with depth 255.
        const int n = 10_000;
        const int fan = 40;
        var nodes = new List<string>(n);
        for (int i = 0; i < n; i++)
        {
            nodes.Add("n" + i);
        }

        var edges = new List<TrustCertification>(n * (fan + 1));
        for (int i = 0; i < n; i++)
        {
            // The self-certification is what makes a User ID exist for the classic model.
            edges.Add(new TrustCertification(nodes[i], nodes[i], nodes[i]));
            for (int j = 1; j <= fan; j++)
            {
                string t = "n" + ((i + j) % n);
                edges.Add(new TrustCertification(nodes[i], t, t, depth: 255, amount: 60));
            }
        }

        TrustNetwork net = TrustNetwork.FromEdges(nodes, edges, Now);
        var sw = Stopwatch.StartNew();
        try
        {
            FlowAuthentication r = WebOfTrust.Authenticate(net, ["n0"], "n9999", "n9999", stopAtRequired: true);
            Assert.True(r.Amount >= 0);
            TestContext.Current.SendDiagnosticMessage("flow: amount {0}, {1} ms", r.Amount, sw.ElapsedMilliseconds);
        }
        catch (TrustLimitExceededException e)
        {
            TestContext.Current.SendDiagnosticMessage("flow: limit {0}", e.Limit);
            Assert.Equal(TrustLimit.Work, e.Limit);
        }

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(120), "flow " + sw.Elapsed);

        sw.Restart();
        try
        {
            FlowAuthentication full = WebOfTrust.Authenticate(net, ["n0"], "n9999", "n9999");
            TestContext.Current.SendDiagnosticMessage("full flow: amount {0}, {1} ms", full.Amount, sw.ElapsedMilliseconds);
        }
        catch (TrustLimitExceededException e)
        {
            TestContext.Current.SendDiagnosticMessage("full flow: limit {0}, {1} ms", e.Limit, sw.ElapsedMilliseconds);
            Assert.Equal(TrustLimit.Work, e.Limit);
        }

        sw.Restart();
        try
        {
            var owner = new Dictionary<string, RecursiveAI.OneCrypto.OpenPgp.GnuPG.OwnerTrustLevel> { ["n0"] = RecursiveAI.OneCrypto.OpenPgp.GnuPG.OwnerTrustLevel.Ultimate };
            ClassicTrustReport report = ClassicTrust.Evaluate(net, owner);
            Assert.Equal(n, report.Certificates.Count);
            TestContext.Current.SendDiagnosticMessage("classic: {0} ms", sw.ElapsedMilliseconds);
        }
        catch (TrustLimitExceededException e)
        {
            TestContext.Current.SendDiagnosticMessage("classic: limit {0}", e.Limit);
            Assert.Equal(TrustLimit.Work, e.Limit);
        }

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(120), "classic " + sw.Elapsed);
    }

    [Fact]
    public void ClassicModelOnAHandDescribedNetwork()
    {
        TrustNetwork net = TrustNetwork.FromEdges(["a", "b"], [new("a", "b", "B <b@example.org>", depth: 1), new("b", "b", "B <b@example.org>")], Now);
        var owner = new Dictionary<string, RecursiveAI.OneCrypto.OpenPgp.GnuPG.OwnerTrustLevel> { ["a"] = RecursiveAI.OneCrypto.OpenPgp.GnuPG.OwnerTrustLevel.Ultimate };
        Assert.Equal(ClassicValidity.Full, ClassicTrust.Evaluate(net, owner).ValidityOf("b", "B <b@example.org>"));
    }

    [Fact]
    public void OwnerTrustExportFeedsTheClassicModel()
    {
        string fpr = new('A', 40);
        var entries = RecursiveAI.OneCrypto.OpenPgp.GnuPG.OwnerTrustExport.Parse("# comment\n" + fpr + ":6:\n");
        var owner = ClassicTrust.OwnerTrustFrom(entries);
        Assert.Equal(RecursiveAI.OneCrypto.OpenPgp.GnuPG.OwnerTrustLevel.Ultimate, owner[fpr]);
        TrustNetwork net = TrustNetwork.FromEdges([fpr, "b"], [new(fpr, "b", "B <b@example.org>"), new("b", "b", "B <b@example.org>")], Now);
        Assert.Equal(ClassicValidity.Full, ClassicTrust.Evaluate(net, owner).ValidityOf("b", "B <b@example.org>"));
    }
}
