using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using RecursiveAI.OneCrypto.OpenPgp.GnuPG;
using RecursiveAI.OneCrypto.OpenPgp.Trust;

namespace RecursiveAI.OneCrypto.OpenPgp.Tests;

/// <summary>
/// The generated trust scenarios (testdata/openpgp/trust, made by tools/oracles/trust-scenarios.py) against what the reference tools said:
/// the classic model against GnuPG's colon listing, the flow model against Sequoia's authenticate command.
/// </summary>
public sealed partial class TrustScenarioTests
{
    private static string Root { get; } = TestFiles.OpenPgp("trust");

    public static IEnumerable<object[]> FlowScenarios => Names("flow");

    public static IEnumerable<object[]> ClassicScenarios => Names("classic");

    private static IEnumerable<object[]> Names(string kind)
    {
        foreach (string dir in Directory.GetDirectories(Root).OrderBy(d => d, StringComparer.Ordinal))
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "scenario.json")));
            if (doc.RootElement.GetProperty("kind").GetString() == kind)
            {
                yield return new object[] { Path.GetFileName(dir) };
            }
        }
    }

    // Deviations from the reference tool that are understood and deliberate. The test pins our answer, so a change in either direction is noticed.
    // Key: scenario name; value: what we answer for the query at that index, and why.
    private static readonly Dictionary<(string Scenario, int Query), (ClassicValidity Ours, string Why)> ClassicDeviations = new()
    {
        // GnuPG does not look at the certification's creation time against the clock; a certification dated after the reference time is trusted.
        // We answer for the reference time, as the web-of-trust draft (section 4.2) asks.
        [("c27-future-certification", 0)] = (ClassicValidity.Unknown, "A certification made after the reference time does not exist yet."),

        // GnuPG lets an ultimately trusted key vouch even when the key itself is revoked. We do not: a revoked trust anchor vouches for nothing.
        [("c44-ultimate-revoked", 1)] = (ClassicValidity.Unknown, "The certifying key is revoked."),
    };

    [Theory]
    [MemberData(nameof(ClassicScenarios))]
    public void ClassicMatchesGnuPG(string scenario)
    {
        string dir = Path.Combine(Root, scenario);
        using JsonDocument meta = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "scenario.json")));
        IReadOnlyList<PgpCertificate> certs = PgpCertificate.ParseAll(File.ReadAllBytes(Path.Combine(dir, "certs.pgp")));
        var owner = new Dictionary<string, OwnerTrustLevel>(StringComparer.Ordinal);
        foreach (JsonProperty p in meta.RootElement.GetProperty("ownertrust").EnumerateObject())
        {
            owner[p.Name] = p.Value.GetString() switch
            {
                "u" => OwnerTrustLevel.Ultimate,
                "f" => OwnerTrustLevel.Full,
                "m" => OwnerTrustLevel.Marginal,
                "n" => OwnerTrustLevel.Never,
                _ => OwnerTrustLevel.Undefined,
            };
        }

        var options = ReadOptions(meta.RootElement.GetProperty("gpgArgs"));
        string[] expectedFiles = Directory.GetFiles(dir, "expected.gnupg-*.json");
        Assert.NotEmpty(expectedFiles);
        var problems = new List<string>();
        foreach (string file in expectedFiles.OrderBy(f => f, StringComparer.Ordinal))
        {
            using JsonDocument expected = JsonDocument.Parse(File.ReadAllText(file));
            int index = 0;
            foreach (JsonElement r in expected.RootElement.GetProperty("results").EnumerateArray())
            {
                JsonElement q = r.GetProperty("query");
                var at = DateTimeOffset.FromUnixTimeSeconds(q.GetProperty("at").GetInt64());
                TrustNetwork net = TrustNetwork.Build(certs, at);
                ClassicTrustReport report = ClassicTrust.Evaluate(net, owner, options);
                string target = q.GetProperty("target").GetString()!;
                foreach (JsonElement u in r.GetProperty("uids").EnumerateArray())
                {
                    string uid = u.GetProperty("userId").GetString()!;
                    string theirs = u.GetProperty("validity").GetString()!;
                    ClassicValidity ours = report.ValidityOf(target, uid);
                    if (ClassicDeviations.TryGetValue((scenario, index), out var dev))
                    {
                        Assert.True(dev.Ours == ours, $"{scenario} query {index} {uid}: deviation is pinned to {dev.Ours} but the answer is {ours}");
                        Assert.NotEqual(Letter(ours), theirs);
                        continue;
                    }

                    if (Letter(ours) != theirs)
                    {
                        problems.Add($"query {index} {q.GetProperty("targetName").GetString()} {uid} ({Path.GetFileName(file)}): GnuPG {theirs}, ours {Letter(ours)} [{Why(report, target, uid)}]");
                    }
                }

                index++;
            }
        }

        Assert.True(problems.Count == 0, scenario + ": " + string.Join(" || ", problems));
    }

    private static string Why(ClassicTrustReport report, string target, string uid) =>
        report.Certificates.TryGetValue(target, out CertificateValidity? c)
            ? string.Join("; ", c.UserIds.Where(x => x.UserId == uid).Select(x => x.Reason + " [" + string.Join(", ", x.Contributions.Select(k => k.Certifier[..8] + ":" + k.Counted + "/" + k.Source)) + "]"))
            : "unknown certificate";

    private static ClassicTrustOptions ReadOptions(JsonElement args)
    {
        int marginals = 3, completes = 1, depth = 5;
        string[] a = args.EnumerateArray().Select(x => x.GetString()!).ToArray();
        for (int i = 0; i + 1 < a.Length; i += 2)
        {
            int v = int.Parse(a[i + 1], CultureInfo.InvariantCulture);
            switch (a[i])
            {
                case "--marginals-needed": marginals = v; break;
                case "--completes-needed": completes = v; break;
                case "--max-cert-depth": depth = v; break;
                default: throw new InvalidOperationException(a[i]);
            }
        }

        return new ClassicTrustOptions { MarginalsNeeded = marginals, CompletesNeeded = completes, MaxCertDepth = depth };
    }

    private static string Letter(ClassicValidity v) => v switch
    {
        ClassicValidity.Unknown => "-",
        ClassicValidity.Undefined => "q",
        ClassicValidity.Marginal => "m",
        ClassicValidity.Full => "f",
        ClassicValidity.Ultimate => "u",
        ClassicValidity.Expired => "e",
        ClassicValidity.Revoked => "r",
        _ => "?",
    };

    // The flow model's deviations from the reference tool. None are known at the moment.
    private static readonly Dictionary<(string Scenario, int Query), string> FlowDeviations = new();

    [Theory]
    [MemberData(nameof(FlowScenarios))]
    public void FlowMatchesSequoia(string scenario)
    {
        string dir = Path.Combine(Root, scenario);
        using JsonDocument meta = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "scenario.json")));
        IReadOnlyList<PgpCertificate> certs = PgpCertificate.ParseAll(File.ReadAllBytes(Path.Combine(dir, "certs.pgp")));
        string[] roots = meta.RootElement.GetProperty("roots").EnumerateArray().Select(x => x.GetString()!).ToArray();
        string[] expectedFiles = Directory.GetFiles(dir, "expected.sq-*.json");
        Assert.NotEmpty(expectedFiles);
        foreach (string file in expectedFiles)
        {
            using JsonDocument expected = JsonDocument.Parse(File.ReadAllText(file));
            int index = 0;
            foreach (JsonElement r in expected.RootElement.GetProperty("results").EnumerateArray())
            {
                JsonElement q = r.GetProperty("query");
                var at = DateTimeOffset.FromUnixTimeSeconds(q.GetProperty("at").GetInt64());
                string target = q.GetProperty("target").GetString()!;
                string uid = q.GetProperty("userId").GetString()!;
                TrustNetwork net = TrustNetwork.Build(certs, at);
                FlowAuthentication ours = WebOfTrust.Authenticate(net, roots, target, uid);
                (AuthenticationLevel level, int amount, List<int> paths) = ParseSequoia(r.GetProperty("stdout").GetString()!, uid);
                string label = $"{scenario} query {index} ({file})";
                if (FlowDeviations.ContainsKey((scenario, index)))
                {
                    index++;
                    continue;
                }

                Assert.True(level == ours.Level, $"{label}: Sequoia says {level} {amount}, we say {ours.Level} {ours.Amount} [{string.Join(' ', ours.Reasons)}]");
                if (level == AuthenticationLevel.Partial)
                {
                    Assert.True(amount == ours.Amount, $"{label}: Sequoia says {amount}, we say {ours.Amount}");
                }

                // Sequoia lists no paths when the User ID is the root's own or has no self-signature; the verdict is compared in every case.
                if (level != AuthenticationLevel.NotAuthenticated && paths.Count > 0)
                {
                    // Sequoia and we find equally short paths in different orders, so the amounts are compared as a set.
                    int[] mine = ours.Paths.Select(p => p.Amount).Order().ToArray();
                    paths.Sort();
                    Assert.True(paths.SequenceEqual(mine), $"{label}: path amounts differ: Sequoia [{string.Join(',', paths)}], ours [{string.Join(',', mine)}]");
                }

                if (level == AuthenticationLevel.NotAuthenticated)
                {
                    Assert.Equal(0, ours.Amount);
                }

                index++;
            }
        }
    }

    [GeneratedRegex(@"\[\s*(✓|\d+/120)\s*\]\s*(.*)$")]
    private static partial Regex Bracket();

    [GeneratedRegex(@"Path\s+#\d+\s+of\s+\d+,\s+trust\s+amount\s+(\d+):")]
    private static partial Regex PathLine();

    private static (AuthenticationLevel Level, int Amount, List<int> Paths) ParseSequoia(string stdout, string userId)
    {
        AuthenticationLevel level = AuthenticationLevel.NotAuthenticated;
        int amount = 0;
        var paths = new List<int>();
        foreach (string line in stdout.Split('\n'))
        {
            Match m = Bracket().Match(line.Trim());
            if (m.Success && m.Groups[2].Value.Trim() == userId)
            {
                string v = m.Groups[1].Value;
                if (v == "✓")
                {
                    level = AuthenticationLevel.Authenticated;
                }
                else
                {
                    amount = int.Parse(v.Split('/')[0], CultureInfo.InvariantCulture);
                    level = amount > 0 ? AuthenticationLevel.Partial : AuthenticationLevel.NotAuthenticated;
                }

                continue;
            }

            Match p = PathLine().Match(line);
            if (p.Success && int.Parse(p.Groups[1].Value, CultureInfo.InvariantCulture) is > 0 and var n)
            {
                paths.Add(n);
            }
        }

        return (level, amount, paths);
    }
}
