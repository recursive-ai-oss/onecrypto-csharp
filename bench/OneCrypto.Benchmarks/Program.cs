using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Exporters.Json;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;

namespace OneCrypto.Benchmarks;

/// <summary>
/// Runs the benchmark rows in this assembly. Besides BenchmarkDotNet's own options, it takes <c>--quick</c> (fewer iterations,
/// for checking a row) and <c>--summary &lt;file&gt;</c> (where to write the per-area summary as JSON).
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        bool quick = false;
        string? summaryFile = null;
        var rest = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--quick")
            {
                quick = true;
            }
            else if (args[i] == "--summary" && i + 1 < args.Length)
            {
                summaryFile = args[++i];
            }
            else
            {
                rest.Add(args[i]);
            }
        }

        // In-process: no generated project per run, so no restore or build on the bench machine and no queue time spent compiling.
        Job job = Job.Default.WithToolchain(InProcessNoEmitToolchain.Instance);
        if (quick)
        {
            job = job.WithWarmupCount(2).WithIterationCount(6);
        }

        IConfig config = DefaultConfig.Instance
            .AddJob(job)
            .AddDiagnoser(MemoryDiagnoser.Default)
            .AddColumn(StatisticColumn.Median)
            .AddExporter(JsonExporter.Full)
            .AddExporter(MarkdownExporter.GitHub);

        var summaries = BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(rest.ToArray(), config);
        var areas = AreaSummary.Build(summaries);
        AreaSummary.Print(areas, Console.Out);
        if (summaryFile is not null)
        {
            AreaSummary.Write(areas, summaryFile);
        }

        return 0;
    }
}
