using System.Diagnostics;
using System.Globalization;
using System.Linq;
using OneCrypto.Fuzz;
using SharpFuzz;

// One fuzz executable, one target per input surface. The target is chosen by the ONECRYPTO_FUZZ_TARGET environment variable because
// libFuzzer's .NET host starts the program without command-line arguments.
//
// To add a target: write a static method `Run(ReadOnlySpan<byte> data)` that lets only the library's typed exceptions escape, then
// add one line to `Targets` below and its seeds to `SeedsFor`.
//
// Without a libFuzzer host there are three local modes:
//   mutate <target> <seconds> <seed file or directory>...   random byte-level mutation of the seeds, in process
//   replay <target> <file>...                                runs saved inputs once each (reproduces a finding)
//   seeds <target> <out dir>                                 writes starting inputs for a target (used by run.sh)
internal static class Program
{
    private delegate void Target(ReadOnlySpan<byte> data);

    private static readonly Dictionary<string, Target> Targets = new(StringComparer.Ordinal)
    {
        ["noop"] = static data => _ = data.Length,
        ["cms"] = CmsTarget.Run,
        ["cmsenv"] = CmsEnvelopedTarget.Run,
        ["asn1"] = Asn1Target.Run,
        ["pem"] = PemTarget.Run,
        ["x509"] = X509Target.Run,
        ["ocsp"] = OcspTarget.Run,
        ["pkcs8"] = Pkcs8Target.Run,
        ["pkcs12"] = Pkcs12Target.Run,
        ["ssh"] = SshTarget.Run,
        ["verify"] = VerifyTarget.Run,
        ["validate"] = ValidateTarget.Run,
        ["keys"] = KeysTarget.Run,
        ["tsa"] = IssuerTarget.RunTsa,
        ["ocspresp"] = IssuerTarget.RunOcsp,
        ["load"] = LoadTarget.Run,
        ["phc"] = PhcTarget.Run,
        ["pades"] = PadesTarget.Run,
        ["placeholder"] = PlaceholderTarget.Run,
        ["online"] = OnlineTarget.Run,
        ["pgppacket"] = PgpPacketTarget.Run,
        ["pgpmessage"] = PgpMessageTarget.Run,
    };

    private static IEnumerable<byte[]> SeedsFor(string target) => target switch
    {
        "cms" => CmsTarget.Seeds(),
        "cmsenv" => CmsEnvelopedTarget.Seeds(),
        "asn1" => Asn1Target.Seeds(),
        "pem" => PemTarget.Seeds(),
        "x509" => X509Target.Seeds(),
        "ocsp" => OcspTarget.Seeds(),
        "pkcs8" => Pkcs8Target.Seeds(),
        "pkcs12" => Pkcs12Target.Seeds(),
        "ssh" => SshTarget.Seeds(),
        "verify" => VerifyTarget.Seeds(),
        "validate" => ValidateTarget.Seeds(),
        "keys" => KeysTarget.Seeds(),
        "tsa" => IssuerTarget.SeedsTsa(),
        "ocspresp" => IssuerTarget.SeedsOcsp(),
        "load" => LoadTarget.Seeds(),
        "phc" => PhcTarget.Seeds(),
        "pades" => PadesTarget.Seeds(),
        "placeholder" => PlaceholderTarget.Seeds(),
        "online" => OnlineTarget.Seeds(),
        "pgppacket" => PgpPacketTarget.Seeds(),
        "pgpmessage" => PgpMessageTarget.Seeds(),
        _ => [],
    };

    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "mutate")
        {
            return Mutate(args);
        }

        if (args.Length > 2 && args[0] == "replay")
        {
            return Replay(args);
        }

        if (args.Length > 2 && args[0] == "seeds")
        {
            return WriteSeeds(args);
        }

        string? name = Environment.GetEnvironmentVariable("ONECRYPTO_FUZZ_TARGET") ?? (args.Length > 0 ? args[0] : null);
        if (name is null || !Targets.TryGetValue(name, out Target? target))
        {
            Console.Error.WriteLine("usage: set ONECRYPTO_FUZZ_TARGET to one of: " + string.Join(", ", Targets.Keys));
            return 2;
        }

        Fuzzer.LibFuzzer.Run(data => target(data));
        return 0;
    }

    private static int WriteSeeds(string[] args)
    {
        Directory.CreateDirectory(args[2]);
        int n = 0;
        foreach (byte[] seed in SeedsFor(args[1]))
        {
            File.WriteAllBytes(Path.Combine(args[2], $"seed-{n++:D3}"), seed);
        }

        Console.WriteLine($"wrote {n} seeds");
        return 0;
    }

    private static int Replay(string[] args)
    {
        if (!Targets.TryGetValue(args[1], out Target? target))
        {
            Console.Error.WriteLine("unknown target " + args[1]);
            return 2;
        }

        int failures = 0;
        foreach (string f in args.Skip(2))
        {
            var sw = Stopwatch.StartNew();
            try
            {
                target(File.ReadAllBytes(f));
                Console.WriteLine($"ok {f} ({sw.Elapsed.TotalSeconds:F2}s)");
            }
            catch (Exception ex)
            {
                failures++;
                Console.WriteLine($"FAIL {f}: {ex}");
            }
        }

        return failures == 0 ? 0 : 1;
    }

    private static int Mutate(string[] args)
    {
        if (args.Length < 4 || !Targets.TryGetValue(args[1], out Target? target))
        {
            Console.Error.WriteLine("usage: mutate <target> <seconds> <seed>...");
            return 2;
        }

        var seeds = new List<byte[]>();
        foreach (string p in args.Skip(3))
        {
            foreach (string f in Directory.Exists(p) ? Directory.EnumerateFiles(p, "*", SearchOption.AllDirectories) : [p])
            {
                if (new FileInfo(f).Length < 1 << 20)
                {
                    seeds.Add(File.ReadAllBytes(f));
                }
            }
        }

        // A fixed seed keeps a run reproducible; this is a smoke mode, not a source of randomness for anything secret.
        var rnd = new Random(12345);
        var clock = Stopwatch.StartNew();
        double limit = double.Parse(args[2], CultureInfo.InvariantCulture);
        long runs = 0;
        while (clock.Elapsed.TotalSeconds < limit)
        {
            var buf = new List<byte>(seeds[rnd.Next(seeds.Count)]);
            int edits = 1 + rnd.Next(8);
            for (int e = 0; e < edits && buf.Count > 0; e++)
            {
                int at = rnd.Next(buf.Count);
                switch (rnd.Next(4))
                {
                    case 0: buf[at] = (byte)rnd.Next(256); break;
                    case 1: buf[at] ^= (byte)(1 << rnd.Next(8)); break;
                    case 2: buf.RemoveRange(at, Math.Min(1 + rnd.Next(16), buf.Count - at)); break;
                    default:
                        int from = rnd.Next(buf.Count);
                        buf.InsertRange(at, buf.GetRange(from, Math.Min(64, buf.Count - from)));
                        break;
                }
            }

            byte[] input = [.. buf];
            try
            {
                target(input);
            }
            catch (Exception ex)
            {
                string? work = Environment.GetEnvironmentVariable("ONECRYPTO_FUZZ_WORK");
                string saved = "not saved (set ONECRYPTO_FUZZ_WORK)";
                if (!string.IsNullOrEmpty(work))
                {
                    string dir = Path.Combine(work, "findings", "mutate");
                    Directory.CreateDirectory(dir);
                    saved = Path.Combine(dir, $"crash-{args[1]}-{runs}.bin");
                    File.WriteAllBytes(saved, input);
                }

                Console.WriteLine($"CRASH {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}\nsaved {saved}");
                return 1;
            }

            runs++;
        }

        Console.WriteLine($"target={args[1]} seeds={seeds.Count} runs={runs} crashes=0");
        return 0;
    }
}
