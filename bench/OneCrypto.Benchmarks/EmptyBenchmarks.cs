using BenchmarkDotNet.Attributes;

namespace OneCrypto.Benchmarks;

/// <summary>Placeholder so the harness runs end to end; the real suites replace it.</summary>
[MemoryDiagnoser]
public class EmptyBenchmarks
{
    private readonly byte[] _data = new byte[64];

    [Benchmark]
    public int Baseline() => _data.Length;
}
