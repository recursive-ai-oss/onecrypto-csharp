using System.Text;
using System.Text.Json;
using RecursiveAI.OneCrypto.Pem;
using Xunit.Sdk;

namespace OneCrypto.Tests.Asn1;

/// <summary>
/// Differential run against System.Formats.Asn1. Corpus roots come from ONECRYPTO_VECTORS (x509-limbo and wycheproof folders) and the
/// generated count from ONECRYPTO_DIFF_N (default small, so the ordinary test run stays quick). Counts and every difference are
/// written to the file named by ONECRYPTO_DIFF_REPORT when set.
/// </summary>
public class DifferentialTests
{
    private sealed class Stats
    {
        public string Name = string.Empty;
        public long Inputs;
        public long Comparisons;
        public long BothAccept;
        public long BothReject;
        public long OursOnlyAccepts;
        public long OracleOnlyAccepts;
        public long ValueMismatch;
        public readonly List<string> Samples = [];
        public readonly Dictionary<string, long> Classes = [];

        public void Add(byte[] data, bool der)
        {
            Comparisons++;
            (bool same, bool ours, bool oracle) = Differential.Compare(data, der);
            if (same)
            {
                if (ours)
                {
                    BothAccept++;
                }
                else
                {
                    BothReject++;
                }

                return;
            }

            string kind = ours == oracle ? "value" : ours ? "ours-accepts" : "oracle-accepts";
            if (ours == oracle)
            {
                ValueMismatch++;
            }
            else if (ours)
            {
                OursOnlyAccepts++;
            }
            else
            {
                OracleOnlyAccepts++;
            }

            string cls = Classify(data, der, kind);
            Classes[cls] = Classes.GetValueOrDefault(cls) + 1;
            if (Samples.Count < 400)
            {
                Samples.Add($"{(der ? "DER" : "BER")} {kind} [{cls}] {Convert.ToHexString(data.AsSpan(0, Math.Min(data.Length, 200)))}");
            }
        }

        public string Summary() =>
            $"{Name}: inputs={Inputs} comparisons={Comparisons} bothAccept={BothAccept} bothReject={BothReject} oursOnlyAccepts={OursOnlyAccepts} oracleOnlyAccepts={OracleOnlyAccepts} valueMismatch={ValueMismatch}";
    }

    // Names the first transcript line where the two sides part, so differences group by cause.
    private static string Classify(byte[] data, bool der, string kind)
    {
        List<string> a = Differential.Ours(data, der ? RecursiveAI.OneCrypto.Asn1.Asn1Rules.Der : RecursiveAI.OneCrypto.Asn1.Asn1Rules.Ber);
        List<string> b = Differential.Oracle(data, der ? System.Formats.Asn1.AsnEncodingRules.DER : System.Formats.Asn1.AsnEncodingRules.BER);
        int i = 0;
        while (i < a.Count && i < b.Count && a[i] == b[i])
        {
            i++;
        }

        string x = i < a.Count ? Norm(a[i]) : "end";
        string y = i < b.Count ? Norm(b[i]) : "end";
        return $"{kind}: ours={x} oracle={y}";
    }

    private static string Norm(string line)
    {
        string tok = line.Split(' ')[0];
        return tok.StartsWith("CTX", StringComparison.Ordinal) ? "CTX(" : tok;
    }

    private static void Report(params Stats[] all)
    {
        var sb = new StringBuilder();
        foreach (Stats s in all)
        {
            sb.AppendLine(s.Summary());
            foreach (KeyValuePair<string, long> c in s.Classes.OrderByDescending(c => c.Value))
            {
                sb.AppendLine($"  class {c.Key}: {c.Value}");
            }

            foreach (string line in s.Samples)
            {
                sb.AppendLine("  sample " + line);
            }
        }

        string? path = Environment.GetEnvironmentVariable("ONECRYPTO_DIFF_REPORT");
        if (path is not null)
        {
            File.AppendAllText(path, sb.ToString());
        }
    }

    [Fact]
    public void GeneratedAndMutatedEncodingsAgree()
    {
        long n = long.TryParse(Environment.GetEnvironmentVariable("ONECRYPTO_DIFF_N"), out long v) ? v : 3000;
        int seed = int.TryParse(Environment.GetEnvironmentVariable("ONECRYPTO_DIFF_SEED"), out int sd) ? sd : 1;
        var rng = new Random(seed);
        var valid = new Stats { Name = "generated-valid" };
        var mutated = new Stats { Name = "generated-mutated" };
        for (long i = 0; i < n; i++)
        {
            Node root = Node.Random(rng, 0);
            byte[] der = root.Serialize();
            byte[] ber = root.Serialize(rng, 30);
            Assert.True(Differential.Compare(der, true).OursAccepts, "DER output of the generator must be accepted in DER mode");
            valid.Inputs += 2;
            foreach (byte[] d in new[] { der, ber })
            {
                valid.Add(d, true);
                valid.Add(d, false);
            }

            byte[] md = Node.Mutate(der, rng);
            byte[] mb = Node.Mutate(ber, rng);
            mutated.Inputs += 2;
            foreach (byte[] d in new[] { md, mb })
            {
                mutated.Add(d, true);
                mutated.Add(d, false);
            }
        }

        Report(valid, mutated);
        AssertClean(valid, mutated);
    }

    private static void AssertClean(params Stats[] all)
    {
        foreach (Stats s in all)
        {
            long unexplained = s.Classes.Where(c => !Known(c.Key)).Sum(c => c.Value);
            if (unexplained != 0)
            {
                throw new XunitException(s.Summary() + "\n" + string.Join("\n", s.Samples.Take(10)));
            }
        }
    }

    // Differences explained in docs/asn1-differences.md. Anything else fails the run.
    private static bool Known(string cls) => KnownClasses.Contains(cls);

    // Fractions of a minute or hour in a BER GeneralizedTime (X.680 clause 46): the oracle reads them, this library rejects them.
    private static readonly HashSet<string> KnownClasses = ["oracle-accepts: ours=REJECT oracle=GEN"];

    private static string? VectorRoot(string folder)
    {
        string root = Environment.GetEnvironmentVariable("ONECRYPTO_VECTORS") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "onecrypto", "vectors");
        string p = Path.Combine(root, folder);
        return Directory.Exists(p) ? p : null;
    }

    [Fact]
    public void X509LimboCertificatesCrlsAndKeysAgree()
    {
        string? dir = VectorRoot("x509-limbo");
        if (dir is null)
        {
            return;
        }

        var stats = new Stats { Name = "x509-limbo" };
        foreach (string file in Directory.EnumerateFiles(dir, "limbo.json", SearchOption.AllDirectories))
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(file));
            Walk(doc.RootElement);
        }

        Report(stats);
        Assert.True(stats.Inputs > 0);
        AssertClean(stats);

        void Walk(JsonElement e)
        {
            switch (e.ValueKind)
            {
                case JsonValueKind.String:
                    string s = e.GetString()!;
                    if (s.Contains("-----BEGIN ", StringComparison.Ordinal))
                    {
                        foreach (PemBlock b in PemCodec.ParseAll(s, PemMode.Lax))
                        {
                            stats.Inputs++;
                            stats.Add(b.Data, true);
                            stats.Add(b.Data, false);
                        }
                    }

                    break;
                case JsonValueKind.Array:
                    foreach (JsonElement c in e.EnumerateArray())
                    {
                        Walk(c);
                    }

                    break;
                case JsonValueKind.Object:
                    foreach (JsonProperty p in e.EnumerateObject())
                    {
                        Walk(p.Value);
                    }

                    break;
            }
        }
    }

    [Fact]
    public void WycheproofDerInputsAgree()
    {
        string? dir = VectorRoot("wycheproof");
        if (dir is null)
        {
            return;
        }

        var stats = new Stats { Name = "wycheproof" };
        foreach (string file in Directory.EnumerateFiles(dir, "*.json", SearchOption.AllDirectories))
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(file));
            Walk(doc.RootElement);
        }

        Report(stats);
        Assert.True(stats.Inputs > 0);
        AssertClean(stats);

        void Walk(JsonElement e)
        {
            switch (e.ValueKind)
            {
                case JsonValueKind.String:
                    string s = e.GetString()!;
                    if (s.Length >= 8 && (s.Length & 1) == 0 && s.StartsWith("30", StringComparison.Ordinal) && IsHex(s))
                    {
                        byte[] data = Convert.FromHexString(s);
                        stats.Inputs++;
                        stats.Add(data, true);
                        stats.Add(data, false);
                    }
                    else if (s.Contains("-----BEGIN ", StringComparison.Ordinal) && PemCodec.TryParseAll(s, PemMode.Lax, out IReadOnlyList<PemBlock> blocks, out _))
                    {
                        foreach (PemBlock b in blocks)
                        {
                            stats.Inputs++;
                            stats.Add(b.Data, true);
                            stats.Add(b.Data, false);
                        }
                    }

                    break;
                case JsonValueKind.Array:
                    foreach (JsonElement c in e.EnumerateArray())
                    {
                        Walk(c);
                    }

                    break;
                case JsonValueKind.Object:
                    foreach (JsonProperty p in e.EnumerateObject())
                    {
                        Walk(p.Value);
                    }

                    break;
            }
        }
    }

    private static bool IsHex(string s)
    {
        foreach (char c in s)
        {
            if (!Uri.IsHexDigit(c))
            {
                return false;
            }
        }

        return true;
    }
}
