using System.Text.Json;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Validation;

/// <summary>
/// Runs the BetterTLS name-constraints and path-building suites (exported by tools/fetch-bettertls.sh) through the server-authentication profile.
/// Skipped unless <c>ONECRYPTO_BETTERTLS</c> names the export folder. <c>ONECRYPTO_BETTERTLS_RESULTS</c> names a file for one line per test case.
/// </summary>
public class BetterTlsTests
{
    [Fact]
    public void RunsBothSuites()
    {
        string? dir = Environment.GetEnvironmentVariable("ONECRYPTO_BETTERTLS");
        Assert.SkipWhen(dir is null, "ONECRYPTO_BETTERTLS is not set");
        var lines = new List<string>();
        foreach (string suite in new[] { "nameconstraints", "pathbuilding" })
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir!, suite + ".json")));
            JsonElement root = doc.RootElement;
            var anchor = TrustAnchor.FromCertificate(Certificate.Parse(Convert.FromBase64String(root.GetProperty("trustRoot").GetString()!)));
            var results = new System.Collections.Concurrent.ConcurrentBag<string>();
            List<JsonElement> cases = [.. root.GetProperty("suites").GetProperty(suite).GetProperty("testCases").EnumerateArray()];
            Parallel.ForEach(cases, new ParallelOptions { MaxDegreeOfParallelism = 8 }, tc => results.Add(Run(suite, anchor, tc)));
            lines.AddRange(results.OrderBy(l => l, StringComparer.Ordinal));
        }

        string[] differing = [.. lines.Select(l => l.Split('	')).Where(f => f[1] != f[2]).Select(f => f[0])];
        Assert.True(differing.Length == 0, "differences from the expected results: " + string.Join(", ", differing.Take(20)));

        string? outPath = Environment.GetEnvironmentVariable("ONECRYPTO_BETTERTLS_RESULTS");
        if (!string.IsNullOrEmpty(outPath))
        {
            File.WriteAllLines(outPath, lines);
        }
    }

    private static string Run(string suite, TrustAnchor anchor, JsonElement tc)
    {
        int id = tc.GetProperty("id").GetInt32();
        string expected = tc.GetProperty("expected").GetString()!;
        bool warning = tc.GetProperty("failureIsWarning").GetBoolean();
        try
        {
            var chain = tc.GetProperty("certificates").EnumerateArray().Select(c => Certificate.Parse(Convert.FromBase64String(c.GetString()!))).ToList();
            var o = new ValidationOptions
            {
                TrustAnchors = [anchor],
                Intermediates = chain.Skip(1).ToList(),
                ReferenceTime = DateTimeOffset.UtcNow,
                WebPki = new WebPkiProfile { ServerName = tc.GetProperty("hostname").GetString() },
            };
            ValidationReport r = PathValidator.Validate(chain[0], o);
            string got = r.IsValid ? "ACCEPT" : "REJECT";
            string why = r.DecidingRule?.Reason ?? "-";
            return $"{suite}/{id:D5}\t{expected}\t{got}\t{(warning ? "warning" : "-")}\t{why.Replace('\t', ' ')}";
        }
        catch (Exception e) when (e is X509ParseException or FormatException)
        {
            return $"{suite}/{id:D5}\t{expected}\tERROR\t{(warning ? "warning" : "-")}\t{e.Message}";
        }
    }
}
