using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Generators;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Benchmarks;

/// <summary>scrypt (r = 8, p = 1, 32-byte output) against BouncyCastle, the managed comparator, and the native library behind NSec.</summary>
[BenchmarkCategory("scrypt")]
public class ScryptRows
{
    private static readonly byte[] Password = "correct horse battery staple"u8.ToArray();
    // NSec takes exactly a 32-byte salt, so every method gets one.
    private static readonly byte[] Salt = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private readonly byte[] _key = new byte[32];
    private global::NSec.Cryptography.PasswordBasedKeyDerivationAlgorithm? _nsec;

    /// <summary>N, the CPU and memory cost.</summary>
    [Params(1 << 14, 1 << 17)]
    public int N { get; set; }

    [GlobalSetup]
    public void Setup() =>
        _nsec = global::NSec.Cryptography.PasswordBasedKeyDerivationAlgorithm.Scrypt(new global::NSec.Cryptography.ScryptParameters
        {
            Cost = N,
            BlockSize = 8,
            Parallelization = 1,
        });

    [Benchmark]
    public byte[] Ours()
    {
        Scrypt.DeriveKey(Password, Salt, N, 8, 1, _key);
        return _key;
    }

    [Benchmark]
    public byte[] BouncyCastle() => SCrypt.Generate(Password, Salt, N, 8, 1, 32);

    [Benchmark]
    [BenchmarkCategory("native")]
    public byte[] NSec() => _nsec!.DeriveBytes(Password, Salt, 32);
}
