using System.Diagnostics;

namespace OneCrypto.Benchmarks;

/// <summary>
/// Peak memory of a streaming row. BenchmarkDotNet reports allocations, not residency, so a row that has to show constant memory
/// (a large stream through a small buffer) measures the peak working set of its own process here. Run such a row alone in its
/// own process: the working set includes everything else the process has touched.
/// </summary>
internal static class PeakMemory
{
    /// <summary>Runs <paramref name="work"/> and returns the highest working set seen, in bytes, sampled every 10 ms.</summary>
    public static long Measure(Action work)
    {
        ArgumentNullException.ThrowIfNull(work);
        using var self = Process.GetCurrentProcess();
        long peak = 0;
        using var stop = new CancellationTokenSource();
        var sampler = Task.Run(
            async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    self.Refresh();
                    peak = Math.Max(peak, self.WorkingSet64);
                    await Task.Delay(10, CancellationToken.None).ConfigureAwait(false);
                }
            },
            CancellationToken.None);
        try
        {
            work();
        }
        finally
        {
            stop.Cancel();
            sampler.GetAwaiter().GetResult();
        }

        self.Refresh();
        return Math.Max(peak, self.WorkingSet64);
    }
}
