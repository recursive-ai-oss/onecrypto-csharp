using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Digests;

namespace OneCrypto.Benchmarks;

/// <summary>
/// Demonstration row, and the template for every other: one file, one class. SHA-256 comes from the platform in both
/// libraries' case, so this row shows the pipeline rather than a primitive of ours; BouncyCastle is the managed comparator.
/// To add a row, copy this file: change the category (the area), the parameters and the method bodies. Keep <c>Ours</c> as
/// the name of our method; name each comparator method for the comparator.
/// </summary>
[BenchmarkCategory("hash")]
public class Sha256Rows
{
    private byte[] _data = [];
    private readonly byte[] _digest = new byte[32];
    private readonly Sha256Digest _bc = new();

    /// <summary>Input size in bytes.</summary>
    [Params(64, 4096, 1 << 20)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup() => _data = RandomNumberGenerator.GetBytes(Size);

    [Benchmark]
    public byte[] Ours()
    {
        SHA256.HashData(_data, _digest);
        return _digest;
    }

    [Benchmark]
    public byte[] BouncyCastle()
    {
        _bc.BlockUpdate(_data, 0, _data.Length);
        _bc.DoFinal(_digest, 0);
        return _digest;
    }
}
