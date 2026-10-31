using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Validation;

/// <summary>
/// Runs every x509-limbo testcase through the validator. Skipped unless <c>ONECRYPTO_LIMBO</c> names limbo.json.
/// When <c>ONECRYPTO_LIMBO_RESULTS</c> names a file, one tab-separated line per testcase is written there:
/// id, expected, our verdict, the deciding rule and its reason.
/// </summary>
public class LimboTests
{
    [Fact]
    public void RunsTheWholeSuite()
    {
        string? path = Environment.GetEnvironmentVariable("ONECRYPTO_LIMBO");
        Assert.SkipWhen(path is null, "ONECRYPTO_LIMBO is not set");
        using FileStream fs = File.OpenRead(path!);
        using JsonDocument doc = JsonDocument.Parse(fs);
        List<JsonElement> cases = [.. doc.RootElement.GetProperty("testcases").EnumerateArray()];
        string? only = Environment.GetEnvironmentVariable("ONECRYPTO_LIMBO_FILTER");
        if (!string.IsNullOrEmpty(only))
        {
            cases = [.. cases.Where(c => c.GetProperty("id").GetString()!.StartsWith(only, StringComparison.Ordinal))];
        }

        var lines = new ConcurrentBag<string>();
        Parallel.ForEach(cases, new ParallelOptions { MaxDegreeOfParallelism = 8 }, tc => lines.Add(Run(tc)));
        string? outPath = Environment.GetEnvironmentVariable("ONECRYPTO_LIMBO_RESULTS");
        if (!string.IsNullOrEmpty(outPath))
        {
            File.WriteAllLines(outPath, lines.OrderBy(l => l, StringComparer.Ordinal));
        }
    }

    internal static ValidationOptions? Options(JsonElement tc, out Certificate? target, out string? error)
    {
        target = null;
        error = null;
        try
        {
            var anchors = new List<TrustAnchor>();
            foreach (JsonElement e in tc.GetProperty("trusted_certs").EnumerateArray())
            {
                anchors.Add(TrustAnchor.FromCertificate(Certificate.FromPem(e.GetString()!)));
            }

            var pool = new List<Certificate>();
            foreach (JsonElement e in tc.GetProperty("untrusted_intermediates").EnumerateArray())
            {
                pool.Add(Certificate.FromPem(e.GetString()!));
            }

            target = Certificate.FromPem(tc.GetProperty("peer_certificate").GetString()!);
            var crls = new List<CertificateRevocationList>();
            if (tc.TryGetProperty("crls", out JsonElement cr))
            {
                foreach (JsonElement e in cr.EnumerateArray())
                {
                    crls.Add(CertificateRevocationList.FromPem(e.GetString()!));
                }
            }

            bool server = tc.GetProperty("validation_kind").GetString() == "SERVER";
            string id = tc.GetProperty("id").GetString()!;
            bool webpki = id.StartsWith("webpki::", StringComparison.Ordinal) || id.StartsWith("bettertls::", StringComparison.Ordinal);
            string? name = null;
            if (server && tc.TryGetProperty("expected_peer_name", out JsonElement pn) && pn.ValueKind == JsonValueKind.Object)
            {
                name = pn.GetProperty("value").GetString();
            }

            string? eku = null;
            if (tc.TryGetProperty("extended_key_usage", out JsonElement ek) && ek.GetArrayLength() > 0)
            {
                eku = ek[0].GetString() switch
                {
                    "serverAuth" => KnownOids.ServerAuth,
                    "clientAuth" => KnownOids.ClientAuth,
                    "codeSigning" => KnownOids.CodeSigning,
                    "emailProtection" => KnownOids.EmailProtection,
                    "timeStamping" => KnownOids.TimeStamping,
                    "OCSPSigning" => KnownOids.OcspSigning,
                    { } other => other,
                    _ => null,
                };
            }

            KeyUsages ku = KeyUsages.None;
            if (tc.TryGetProperty("key_usage", out JsonElement kus))
            {
                foreach (JsonElement k in kus.EnumerateArray())
                {
                    ku |= k.GetString() switch
                    {
                        "digitalSignature" => KeyUsages.DigitalSignature,
                        "keyCertSign" => KeyUsages.KeyCertSign,
                        "cRLSign" => KeyUsages.CrlSign,
                        "keyEncipherment" => KeyUsages.KeyEncipherment,
                        "keyAgreement" => KeyUsages.KeyAgreement,
                        "contentCommitment" or "nonRepudiation" => KeyUsages.NonRepudiation,
                        _ => KeyUsages.None,
                    };
                }
            }

            int? depth = tc.TryGetProperty("max_chain_depth", out JsonElement md) && md.ValueKind == JsonValueKind.Number ? md.GetInt32() : null;
            return new ValidationOptions
            {
                TrustAnchors = anchors,
                Intermediates = pool,
                // A testcase without a validation time means "now": the harness is the caller, so it supplies the instant.
                ReferenceTime = tc.TryGetProperty("validation_time", out JsonElement vt) && vt.ValueKind == JsonValueKind.String
                    ? DateTimeOffset.Parse(vt.GetString()!, System.Globalization.CultureInfo.InvariantCulture)
                    : DateTimeOffset.UtcNow,
                RequiredExtendedKeyUsage = eku ?? (server ? KnownOids.ServerAuth : KnownOids.ClientAuth),
                RequiredKeyUsage = ku,
                MaxIntermediates = depth,
                Revocation = crls.Count > 0 ? new RevocationData { Crls = crls } : null,
                RevocationRequired = crls.Count > 0 ? RevocationScope.AllCertificates : RevocationScope.None,
                UnknownRevocationIsFatal = crls.Count > 0,
                // The webpki and bettertls testcases are about the server-authentication profile; the others test RFC 5280 itself, with host name matching only.
                WebPki = new WebPkiProfile { ServerName = name, RequireServerAuth = server && webpki, EnforceBaselineRequirements = webpki, RequireCommonNameInSan = id.StartsWith("webpki::cn::", StringComparison.Ordinal) },
            };
        }
        catch (Exception e) when (e is X509ParseException or FormatException or ArgumentException or KeyNotFoundException or InvalidOperationException)
        {
            error = e.Message;
            return null;
        }
    }

    private static string Run(JsonElement tc)
    {
        string id = tc.GetProperty("id").GetString()!;
        string expected = tc.GetProperty("expected_result").GetString()!;
        ValidationOptions? o = Options(tc, out Certificate? target, out string? error);
        if (o is null || target is null)
        {
            return $"{id}\t{expected}\tPARSE\t-\t{Clean(error)}";
        }

        ValidationReport r = PathValidator.Validate(target, o);
        if (Environment.GetEnvironmentVariable("ONECRYPTO_LIMBO_DUMP") == id)
        {
            File.AppendAllText(Environment.GetEnvironmentVariable("ONECRYPTO_LIMBO_RESULTS") + ".dump", ReportText.Describe(r));
        }

        string rule = r.DecidingRule is { } d ? d.Rule.ToString() : "-";
        string why = r.DecidingRule?.Reason ?? "-";
        return $"{id}\t{expected}\t{r.Verdict}\t{rule}\t{Clean(why)}";
    }

    private static string Clean(string? s) => (s ?? string.Empty).Replace('\t', ' ').Replace('\n', ' ').Replace('\r', ' ');
}
