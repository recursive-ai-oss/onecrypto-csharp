using System.Text.Json;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Validation;

/// <summary>
/// Runs NIST's PKITS path-validation tests (sections 4.1 to 4.16 of the PKITS document, listed in Data/pkits-tests.json)
/// through the validator. Skipped unless <c>ONECRYPTO_PKITS</c> names the folder PKITS_data.zip was extracted into
/// (tools/fetch-pkits.sh). When <c>ONECRYPTO_PKITS_RESULTS</c> names a file, one line per run is written there.
/// </summary>
public class PkitsTests
{
    private const string AnyPolicyOid = "2.5.29.32.0";

    // The PKITS "current time" is any instant between 2010-01-01 and 2030-01-01; its certificates and CRLs are built around it.
    private static readonly DateTimeOffset Now = new(2020, 6, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RunsTheManifest()
    {
        string? dir = Environment.GetEnvironmentVariable("ONECRYPTO_PKITS");
        Assert.SkipWhen(dir is null, "ONECRYPTO_PKITS is not set");
        string manifest = Path.Combine(AppContext.BaseDirectory, "Validation", "Data", "pkits-tests.json");
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(manifest));
        var lines = new List<string>();
        foreach (JsonElement t in doc.RootElement.GetProperty("tests").EnumerateArray())
        {
            string id = t.GetProperty("id").GetString()!;
            int n = 0;
            foreach (JsonElement run in t.GetProperty("runs").EnumerateArray())
            {
                n++;
                lines.Add(RunOne(dir!, t, run, id + "#" + n));
            }
        }

        string? outPath = Environment.GetEnvironmentVariable("ONECRYPTO_PKITS_RESULTS");
        if (!string.IsNullOrEmpty(outPath))
        {
            File.WriteAllLines(outPath, lines);
        }
    }

    private static string RunOne(string dir, JsonElement t, JsonElement run, string id)
    {
        string expected = run.GetProperty("expected").GetString()!;
        try
        {
            var certs = new List<Certificate>();
            foreach (JsonElement f in t.GetProperty("certs").EnumerateArray())
            {
                certs.Add(Certificate.Parse(File.ReadAllBytes(Path.Combine(dir, "certs", f.GetString()!))));
            }

            var crls = new List<CertificateRevocationList>();
            foreach (JsonElement f in t.GetProperty("crls").EnumerateArray())
            {
                crls.Add(CertificateRevocationList.Parse(File.ReadAllBytes(Path.Combine(dir, "crls", f.GetString()!))));
            }

            Certificate anchor = Certificate.Parse(File.ReadAllBytes(Path.Combine(dir, "certs", "TrustAnchorRootCertificate.crt")));
            JsonElement s = run.GetProperty("settings");
            var policies = new List<string>();
            if (s.TryGetProperty("policies", out JsonElement ps))
            {
                policies.AddRange(ps.EnumerateArray().Select(p => p.GetString()!));
            }

            var o = new ValidationOptions
            {
                TrustAnchors = [TrustAnchor.FromCertificate(anchor)],
                Intermediates = certs.Take(certs.Count - 1).ToList(),
                ReferenceTime = Now,
                Revocation = new RevocationData { Crls = crls },
                RevocationRequired = RevocationScope.AllCertificates,
                UnknownRevocationIsFatal = true,
                AlgorithmCheck = AlgorithmChecks.Rfc5280Only,
                InitialPolicySet = policies,
                InitialExplicitPolicy = s.TryGetProperty("explicit", out _),
                InitialPolicyMappingInhibit = s.TryGetProperty("inhibitMapping", out _),
                InitialAnyPolicyInhibit = s.TryGetProperty("inhibitAny", out _),
                // PKITS predates the profile rules about key identifiers and criticality; it is a test of the path algorithm.
                StrictStructure = false,
            };
            ValidationReport r = PathValidator.Validate(certs[^1], o);
            if (Environment.GetEnvironmentVariable("ONECRYPTO_PKITS_DUMP") == id)
            {
                File.AppendAllText(Environment.GetEnvironmentVariable("ONECRYPTO_PKITS_RESULTS") + ".dump", ReportText.Describe(r));
            }

            string got = r.IsValid ? "valid" : "invalid";
            string why = r.DecidingRule is { } d ? $"{d.Rule}: {d.Reason}" : "-";
            return $"{id}\t{expected}\t{got}\t{t.GetProperty("title").GetString()}\t{why}";
        }
        catch (Exception e) when (e is X509ParseException or IOException or FormatException)
        {
            return $"{id}\t{expected}\tERROR\t{t.GetProperty("title").GetString()}\t{e.Message}";
        }
    }
}
