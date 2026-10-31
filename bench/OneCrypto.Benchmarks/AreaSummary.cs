using System.Globalization;
using System.Reflection;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Reports;

namespace OneCrypto.Benchmarks;

/// <summary>One comparison: our implementation against one comparator on one input.</summary>
internal sealed record RowResult(
    string Area,
    string Row,
    string Comparator,
    bool Native,
    double OursMedianNs,
    double ComparatorMedianNs,
    long OursBytesPerOp,
    long ComparatorBytesPerOp)
{
    public double Ratio => OursMedianNs / ComparatorMedianNs;
}

/// <summary>Geometric mean of the gating ratios of one area, and the worst row.</summary>
internal sealed record AreaResult(string Area, IReadOnlyList<RowResult> Rows, double GateGeomean, double WorstGateRatio, double NativeGeomean)
{
    /// <summary>The bar: geomean at most 1.0 and no row above 1.25 against the fastest managed comparator.</summary>
    public bool MeetsBar => double.IsNaN(GateGeomean) || (GateGeomean <= 1.0 && WorstGateRatio <= 1.25);
}

/// <summary>
/// Turns BenchmarkDotNet's reports into the comparison table. Convention for a row class (see <c>Rows/Sha256Rows.cs</c>):
/// a class-level <c>[BenchmarkCategory("area")]</c>, one method named <c>Ours</c>, and one method per comparator named for it,
/// with <c>[BenchmarkCategory("native")]</c> on comparators that are native or native-backed. The gate compares against the
/// fastest managed comparator; native comparators are reported against a non-gating 1.5 target.
/// </summary>
internal static class AreaSummary
{
    public const double GateGeomean = 1.0;
    public const double GateWorstRow = 1.25;
    public const double NativeTarget = 1.5;

    public static IReadOnlyList<AreaResult> Build(IEnumerable<Summary> summaries)
    {
        var rows = new List<RowResult>();
        foreach (Summary summary in summaries)
        {
            // Group: one class and one parameter set is one row of the table.
            foreach (var group in summary.Reports.GroupBy(r => (r.BenchmarkCase.Descriptor.Type, r.BenchmarkCase.Parameters.DisplayInfo)))
            {
                var reports = group.Where(r => r.ResultStatistics is not null).ToList();
                BenchmarkReport? ours = reports.FirstOrDefault(r => r.BenchmarkCase.Descriptor.WorkloadMethod.Name == "Ours");
                if (ours is null)
                {
                    continue;
                }

                string area = group.Key.Type.GetCustomAttribute<BenchmarkCategoryAttribute>()?.Categories.FirstOrDefault() ?? group.Key.Type.Name;
                foreach (BenchmarkReport other in reports.Where(r => r != ours))
                {
                    rows.Add(new RowResult(
                        area,
                        $"{group.Key.Type.Name} {group.Key.DisplayInfo}".Trim(),
                        other.BenchmarkCase.Descriptor.WorkloadMethod.Name,
                        other.BenchmarkCase.Descriptor.Categories.Contains("native", StringComparer.Ordinal),
                        ours.ResultStatistics!.Median,
                        other.ResultStatistics!.Median,
                        Bytes(ours),
                        Bytes(other)));
                }
            }
        }

        var areas = new List<AreaResult>();
        foreach (var byArea in rows.GroupBy(r => r.Area))
        {
            // Per input, the gate is the fastest managed comparator.
            var gateRatios = byArea.Where(r => !r.Native).GroupBy(r => r.Row)
                .Select(g => g.Max(r => r.Ratio)) // ours / fastest comparator is the largest ratio
                .ToList();
            var nativeRatios = byArea.Where(r => r.Native).GroupBy(r => r.Row).Select(g => g.Max(r => r.Ratio)).ToList();
            areas.Add(new AreaResult(byArea.Key, byArea.ToList(), Geomean(gateRatios), gateRatios.Count == 0 ? double.NaN : gateRatios.Max(), Geomean(nativeRatios)));
        }

        return areas;
    }

    private static long Bytes(BenchmarkReport r) => r.GcStats.GetBytesAllocatedPerOperation(r.BenchmarkCase) ?? -1;

    private static double Geomean(List<double> values) =>
        values.Count == 0 ? double.NaN : Math.Exp(values.Average(Math.Log));

    public static void Print(IReadOnlyList<AreaResult> areas, TextWriter w)
    {
        CultureInfo c = CultureInfo.InvariantCulture;
        w.WriteLine();
        w.WriteLine("| area | row | comparator | ours median | comparator median | ratio | ours B/op | comparator B/op | kind |");
        w.WriteLine("|---|---|---|---:|---:|---:|---:|---:|---|");
        foreach (AreaResult a in areas)
        {
            foreach (RowResult r in a.Rows)
            {
                w.WriteLine(string.Create(c, $"| {a.Area} | {r.Row} | {r.Comparator} | {r.OursMedianNs:F1} ns | {r.ComparatorMedianNs:F1} ns | {r.Ratio:F2} | {r.OursBytesPerOp} | {r.ComparatorBytesPerOp} | {(r.Native ? "native, reported" : "managed, gating")} |"));
            }
        }

        w.WriteLine();
        foreach (AreaResult a in areas)
        {
            w.WriteLine(string.Create(c, $"area {a.Area}: gate geomean {a.GateGeomean:F3} (bar {GateGeomean:F1}), worst row {a.WorstGateRatio:F2} (bar {GateWorstRow}), native geomean {a.NativeGeomean:F3} (target {NativeTarget}) => {(a.MeetsBar ? "meets the bar" : "ABOVE THE BAR")}"));
        }
    }

    public static void Write(IReadOnlyList<AreaResult> areas, string path)
    {
        using var stream = File.Create(path);
        using var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        w.WriteStartObject();
        w.WriteStartArray("areas");
        foreach (AreaResult a in areas)
        {
            w.WriteStartObject();
            w.WriteString("area", a.Area);
            WriteNumber(w, "gateGeomean", a.GateGeomean);
            WriteNumber(w, "worstGateRatio", a.WorstGateRatio);
            WriteNumber(w, "nativeGeomean", a.NativeGeomean);
            w.WriteBoolean("meetsBar", a.MeetsBar);
            w.WriteStartArray("rows");
            foreach (RowResult r in a.Rows)
            {
                w.WriteStartObject();
                w.WriteString("row", r.Row);
                w.WriteString("comparator", r.Comparator);
                w.WriteBoolean("native", r.Native);
                w.WriteNumber("oursMedianNs", r.OursMedianNs);
                w.WriteNumber("comparatorMedianNs", r.ComparatorMedianNs);
                w.WriteNumber("ratio", r.Ratio);
                w.WriteNumber("oursBytesPerOp", r.OursBytesPerOp);
                w.WriteNumber("comparatorBytesPerOp", r.ComparatorBytesPerOp);
                w.WriteEndObject();
            }

            w.WriteEndArray();
            w.WriteEndObject();
        }

        w.WriteEndArray();
        w.WriteEndObject();
    }

    private static void WriteNumber(Utf8JsonWriter w, string name, double v)
    {
        if (double.IsNaN(v))
        {
            w.WriteNull(name);
        }
        else
        {
            w.WriteNumber(name, v);
        }
    }
}
