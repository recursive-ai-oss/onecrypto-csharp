using System.Collections.Concurrent;
using System.Text.Json;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Validation;

/// <summary>
/// Validates the cases of a cases.jsonl (tools/diff/export-cases.py) and writes `id, ACCEPT|REJECT, reason` lines, the third column of the
/// differential against `openssl verify` and Go's crypto/x509 (tools/diff/compare.py). Skipped unless <c>ONECRYPTO_DIFF_CASES</c> is set;
/// <c>ONECRYPTO_DIFF_OURS</c> names the output file.
/// </summary>
public class DifferentialCases
{
    [Fact]
    public void ValidatesTheCases()
    {
        string? path = Environment.GetEnvironmentVariable("ONECRYPTO_DIFF_CASES");
        Assert.SkipWhen(path is null, "ONECRYPTO_DIFF_CASES is not set");
        var results = new ConcurrentBag<string>();
        Parallel.ForEach(File.ReadLines(path!), new ParallelOptions { MaxDegreeOfParallelism = 8 }, line => results.Add(Run(line)));
        File.WriteAllLines(Environment.GetEnvironmentVariable("ONECRYPTO_DIFF_OURS") ?? "ours.tsv", results.OrderBy(l => l, StringComparer.Ordinal));
    }

    private static string Run(string line)
    {
        using JsonDocument doc = JsonDocument.Parse(line);
        JsonElement c = doc.RootElement;
        string id = c.GetProperty("id").GetString()!;
        try
        {
            var anchors = c.GetProperty("trusted").EnumerateArray().Select(e => TrustAnchor.FromCertificate(Certificate.FromPem(e.GetString()!))).ToList();
            var pool = c.GetProperty("untrusted").EnumerateArray().Select(e => Certificate.FromPem(e.GetString()!)).ToList();
            Certificate leaf = Certificate.FromPem(c.GetProperty("leaf").GetString()!);
            bool webpki = c.GetProperty("profile").GetString() == "webpki";
            string? eku = c.GetProperty("eku").GetString();
            string? name = c.GetProperty("name").GetString();
            JsonElement t = c.GetProperty("time");
            JsonElement d = c.GetProperty("maxDepth");
            var o = new ValidationOptions
            {
                TrustAnchors = anchors,
                Intermediates = pool,
                ReferenceTime = t.ValueKind == JsonValueKind.String ? DateTimeOffset.Parse(t.GetString()!, System.Globalization.CultureInfo.InvariantCulture) : DateTimeOffset.UtcNow,
                RequiredExtendedKeyUsage = eku switch { "serverAuth" => KnownOids.ServerAuth, "clientAuth" => KnownOids.ClientAuth, _ => null },
                MaxIntermediates = d.ValueKind == JsonValueKind.Number ? d.GetInt32() : null,
                WebPki = new WebPkiProfile { ServerName = name, RequireServerAuth = webpki, EnforceBaselineRequirements = webpki },
            };
            ValidationReport r = PathValidator.Validate(leaf, o);
            return $"{id}\t{(r.IsValid ? "ACCEPT" : "REJECT")}\t{(r.DecidingRule?.Reason ?? "-").Replace('\t', ' ')}";
        }
        catch (Exception e) when (e is X509ParseException or FormatException or KeyNotFoundException)
        {
            return $"{id}\tREJECT\tparse: {e.Message}";
        }
    }
}
