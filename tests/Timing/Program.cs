using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace OneCrypto.Timing;

internal static class Program
{
    private const string Usage =
        "usage: timing list\n" +
        "       timing selfcheck [--preset short|full] [--n N] [--out FILE]\n" +
        "       timing run <primitive/operation|primitive> [--preset short|full] [--n N] [--out FILE]\n" +
        "Exit code 0: every target met its expectation (selfcheck) or showed no leak (run); 1: not; 2: usage.";

    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine(Usage);
            return 2;
        }

        string command = args[0];
        TimingOptions options = TimingOptions.Quick;
        string? outFile = null;
        string? name = args.Length > 1 && !args[1].StartsWith("--", StringComparison.Ordinal) ? args[1] : null;
        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--preset" when i + 1 < args.Length:
                    options = args[++i] == "full" ? TimingOptions.Full : TimingOptions.Quick;
                    break;
                case "--n" when i + 1 < args.Length:
                    options = options with { Measurements = int.Parse(args[++i], CultureInfo.InvariantCulture) };
                    break;
                case "--out" when i + 1 < args.Length:
                    outFile = args[++i];
                    break;
            }
        }

        switch (command)
        {
            case "list":
                foreach (TimingTarget t in Targets.All)
                {
                    Console.WriteLine($"{t.Primitive}/{t.Operation}");
                }

                return 0;

            case "selfcheck":
                return SelfCheckRun(options, outFile);

            case "run" when name is not null:
                var chosen = Targets.All.Where(t => t.Primitive == name || $"{t.Primitive}/{t.Operation}" == name).ToList();
                if (chosen.Count == 0)
                {
                    Console.Error.WriteLine("no such target; try 'list'");
                    return 2;
                }

                var results = chosen.Select(t => Measure(t, options)).ToList();
                Write(outFile, results);
                return results.Any(r => r.Leak) ? 1 : 0;

            default:
                Console.Error.WriteLine(Usage);
                return 2;
        }
    }

    private static TimingResult Measure(TimingTarget target, TimingOptions options)
    {
        TimingResult r = Dudect.Run(target, options);
        Console.WriteLine(r.Summary());
        return r;
    }

    // The harness is only trustworthy if it flags a known leak and passes a known constant-time compare.
    private static int SelfCheckRun(TimingOptions options, string? outFile)
    {
        TimingResult leaky = Measure(SelfCheck.Leaky, options);
        TimingResult clean = Measure(SelfCheck.ConstantTime, options);
        Write(outFile, [leaky, clean]);
        bool ok = leaky.Leak && !clean.Leak;
        Console.WriteLine(ok
            ? "selfcheck: ok (leaky compare flagged, FixedTimeEquals clean)"
            : "selfcheck: FAILED (leaky flagged=" + leaky.Leak + ", FixedTimeEquals clean=" + !clean.Leak + ")");
        return ok ? 0 : 1;
    }

    private static void Write(string? path, List<TimingResult> results)
    {
        if (path is null)
        {
            return;
        }

        using var stream = File.Create(path);
        using (var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            w.WriteString("machine", Machine());
            w.WriteString("cpu", Cpu());
            w.WriteNumber("cores", Environment.ProcessorCount);
            w.WriteString("runtime", RuntimeInformation.FrameworkDescription);
            w.WriteString("tieredCompilation", Environment.GetEnvironmentVariable("DOTNET_TieredCompilation") ?? "default");
            w.WriteString("thresholdAbsT", TimingResult.Threshold.ToString(CultureInfo.InvariantCulture));
            w.WriteStartArray("results");
            foreach (TimingResult r in results)
            {
                w.WriteStartObject();
                w.WriteString("primitive", r.Primitive);
                w.WriteString("operation", r.Operation);
                w.WriteNumber("measurements", r.Measurements);
                w.WriteNumber("maxAbsT", Math.Round(r.MaxAbsT, 3));
                w.WriteNumber("cropAtMax", r.CropAtMax);
                w.WriteNumber("meanNsFixed", Math.Round(r.MeanTicksFixed * 1e9 / r.TicksPerSecond, 2));
                w.WriteNumber("meanNsRandom", Math.Round(r.MeanTicksRandom * 1e9 / r.TicksPerSecond, 2));
                w.WriteNumber("timerHz", r.TicksPerSecond);
                w.WriteString("verdict", r.Leak ? "leak" : "pass");
                w.WriteEndObject();
            }

            w.WriteEndArray();
            w.WriteEndObject();
        }
    }

    private static string Machine() => $"{RuntimeInformation.OSDescription} {RuntimeInformation.ProcessArchitecture}";

    private static string Cpu()
    {
        try
        {
            if (OperatingSystem.IsLinux())
            {
                foreach (string line in File.ReadLines("/proc/cpuinfo"))
                {
                    if (line.StartsWith("model name", StringComparison.Ordinal))
                    {
                        return line[(line.IndexOf(':', StringComparison.Ordinal) + 1)..].Trim();
                    }
                }
            }
            else if (OperatingSystem.IsMacOS())
            {
                var psi = new ProcessStartInfo("sysctl", "-n machine.cpu.brand_string") { RedirectStandardOutput = true };
                using var p = Process.Start(psi);
                if (p is not null)
                {
                    string s = p.StandardOutput.ReadToEnd().Trim();
                    p.WaitForExit();
                    return s;
                }
            }
        }
        catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception)
        {
            // Fall through: the CPU name is informational only.
        }

        return "unknown";
    }
}
