using System.Diagnostics;
using System.Security.Cryptography;

namespace OneCrypto.Timing;

/// <summary>How much to measure.</summary>
/// <param name="Measurements">Timed calls in total, split between the two classes at random.</param>
/// <param name="BatchSize">Inputs prepared at a time; bounds memory for targets with large inputs.</param>
public sealed record TimingOptions(int Measurements, int BatchSize = 10_000)
{
    /// <summary>Quick run, suitable for gating a merge.</summary>
    public static TimingOptions Quick { get; } = new(200_000);

    /// <summary>Milestone run.</summary>
    public static TimingOptions Full { get; } = new(5_000_000);
}

/// <summary>The outcome of one timing test.</summary>
/// <param name="Primitive">Primitive name.</param>
/// <param name="Operation">Operation name.</param>
/// <param name="Measurements">Timed calls taken, both classes together.</param>
/// <param name="MaxAbsT">Largest |t| over the uncropped data and every percentile crop.</param>
/// <param name="CropAtMax">Which crop gave that value; -1 is uncropped.</param>
/// <param name="Leak">True when MaxAbsT reaches the threshold.</param>
/// <param name="MeanTicksFixed">Mean time per call in the fixed class, in timer ticks.</param>
/// <param name="MeanTicksRandom">Mean time per call in the random class, in timer ticks.</param>
/// <param name="TicksPerSecond">Timer frequency.</param>
public sealed record TimingResult(
    string Primitive,
    string Operation,
    int Measurements,
    double MaxAbsT,
    int CropAtMax,
    bool Leak,
    double MeanTicksFixed,
    double MeanTicksRandom,
    long TicksPerSecond)
{
    /// <summary>The paper's threshold: |t| above this is evidence of a timing difference.</summary>
    public const double Threshold = 4.5;

    /// <summary>A one-line summary.</summary>
    public string Summary() =>
        FormattableString.Invariant(
            $"{Primitive}/{Operation}: N={Measurements} max|t|={MaxAbsT:F2} (crop {CropAtMax}) mean fixed={MeanTicksFixed * 1e9 / TicksPerSecond:F1}ns random={MeanTicksRandom * 1e9 / TicksPerSecond:F1}ns => {(Leak ? "LEAK" : "pass")}");
}

/// <summary>
/// The dudect method: time one operation on two input classes (fixed and random secrets), interleaved at random, then test
/// whether the timing distributions differ with Welch's t-test, on the raw data and on data cropped at a series of percentiles
/// to discard the slow tail (interrupts, other tenants).
/// </summary>
public static class Dudect
{
    // Crop levels from the paper: the k-th keeps the fastest 1 - 0.5^(10 k / 100) of the measurements.
    private const int Crops = 100;

    /// <summary>Runs one target and returns the verdict.</summary>
    public static TimingResult Run(TimingTarget target, TimingOptions options)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(options);
        int total = options.Measurements;
        int batch = Math.Min(options.BatchSize, total);
        var times = new long[total];
        var classes = new TimingClass[total];
        var batchClasses = new TimingClass[batch];

        // Warm-up: untimed passes until the JIT has promoted the hot methods. Both classes are exercised.
        Warm(target, batchClasses);

        // The class sequence is drawn up front from the CSPRNG so it is independent of timing.
        byte[] coin = RandomNumberGenerator.GetBytes(total);
        for (int i = 0; i < total; i++)
        {
            classes[i] = (coin[i] & 1) == 0 ? TimingClass.Fixed : TimingClass.Random;
        }

        // No allocation inside this loop: the arrays exist, Prepare reuses its buffers, Run is allocation-free by contract.
        GC.Collect();
        for (int start = 0; start < total; start += batch)
        {
            int n = Math.Min(batch, total - start);
            ReadOnlySpan<TimingClass> slice = classes.AsSpan(start, n);
            target.Prepare(slice);
            for (int i = 0; i < n; i++)
            {
                target.Before(i);
                long t0 = Stopwatch.GetTimestamp();
                target.Run(i);
                long t1 = Stopwatch.GetTimestamp();
                times[start + i] = t1 - t0;
            }
        }

        return Analyse(target, times, classes);
    }

    private static void Warm(TimingTarget target, TimingClass[] batchClasses)
    {
        for (int i = 0; i < batchClasses.Length; i++)
        {
            batchClasses[i] = (i & 1) == 0 ? TimingClass.Fixed : TimingClass.Random;
        }

        long start = Stopwatch.GetTimestamp();
        long budget = Stopwatch.Frequency / 2; // at least half a second so background tier-up has happened
        for (int round = 0; round < 2 || Stopwatch.GetTimestamp() - start < budget; round++)
        {
            target.Prepare(batchClasses);
            for (int i = 0; i < batchClasses.Length; i++)
            {
                target.Before(i);
                target.Run(i);
            }
        }
    }

    internal static TimingResult Analyse(TimingTarget target, long[] times, TimingClass[] classes)
    {
        var sorted = (long[])times.Clone();
        Array.Sort(sorted);

        double max = Welch(times, classes, long.MaxValue, out double meanFixed, out double meanRandom);
        int maxCrop = -1;
        for (int k = 0; k < Crops; k++)
        {
            double q = 1.0 - Math.Pow(0.5, 10.0 * (k + 1) / Crops);
            long limit = sorted[Math.Min(sorted.Length - 1, (int)(q * sorted.Length))];
            double t = Welch(times, classes, limit, out _, out _);
            if (t > max)
            {
                max = t;
                maxCrop = k;
            }
        }

        return new TimingResult(
            target.Primitive, target.Operation, times.Length, max, maxCrop, !(max < TimingResult.Threshold),
            meanFixed, meanRandom, Stopwatch.Frequency);
    }

    /// <summary>|t| of Welch's t-test between the classes, using only measurements at or below <paramref name="limit"/>.</summary>
    internal static double Welch(long[] times, TimingClass[] classes, long limit, out double mean0, out double mean1)
    {
        // Welford's online mean and variance, one accumulator per class.
        long n0 = 0, n1 = 0;
        double m0 = 0, m1 = 0, s0 = 0, s1 = 0;
        for (int i = 0; i < times.Length; i++)
        {
            long v = times[i];
            if (v > limit)
            {
                continue;
            }

            double x = v;
            if (classes[i] == TimingClass.Fixed)
            {
                n0++;
                double d = x - m0;
                m0 += d / n0;
                s0 += d * (x - m0);
            }
            else
            {
                n1++;
                double d = x - m1;
                m1 += d / n1;
                s1 += d * (x - m1);
            }
        }

        mean0 = m0;
        mean1 = m1;
        if (n0 < 2 || n1 < 2)
        {
            return 0;
        }

        double se = Math.Sqrt((s0 / (n0 - 1) / n0) + (s1 / (n1 - 1) / n1));
        // Both classes constant (a timer too coarse to see anything): no evidence of a difference.
        return se == 0 ? 0 : Math.Abs(m0 - m1) / se;
    }
}
