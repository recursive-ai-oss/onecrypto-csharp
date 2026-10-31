using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Benchmarks;

/// <summary>
/// Argon2id key derivation against the managed .NET implementations. Both parameter sets derive a 32-byte key from a 16-byte
/// salt with no secret or associated data; the memory, passes and lanes are the same in every method.
/// </summary>
[BenchmarkCategory("argon2")]
public class Argon2Rows
{
    private static readonly byte[] Password = "correct horse battery staple"u8.ToArray();
    private static readonly byte[] Salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    private readonly byte[] _tag = new byte[32];
    private int _memoryKiB;
    private int _passes;
    private int _lanes;

    /// <summary>The parameter set: memory in MiB, passes, lanes.</summary>
    [Params("m64t3p4", "m19t2p1")]
    public string Config { get; set; } = string.Empty;

    [GlobalSetup]
    public void Setup()
    {
        (_memoryKiB, _passes, _lanes) = Config switch
        {
            "m64t3p4" => (64 * 1024, 3, 4),
            _ => (19 * 1024, 2, 1),
        };
    }

    [Benchmark]
    public byte[] Ours()
    {
        Argon2.DeriveKey(Argon2Type.Argon2id, Password, Salt, _memoryKiB, _passes, _lanes, _tag);
        return _tag;
    }

    [Benchmark]
    public byte[] BouncyCastle()
    {
        var generator = new Argon2BytesGenerator();
        generator.Init(new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithSalt(Salt)
            .WithIterations(_passes)
            .WithMemoryAsKB(_memoryKiB)
            .WithParallelism(_lanes)
            .Build());
        byte[] result = new byte[32];
        generator.GenerateBytes(Password, result);
        return result;
    }

    [Benchmark]
    public byte[] Konscious()
    {
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(Password)
        {
            Salt = Salt,
            DegreeOfParallelism = _lanes,
            Iterations = _passes,
            MemorySize = _memoryKiB,
        };
        return argon2.GetBytes(32);
    }

    [Benchmark]
    public byte[] Isopoh()
    {
        var config = new global::Isopoh.Cryptography.Argon2.Argon2Config
        {
            Type = global::Isopoh.Cryptography.Argon2.Argon2Type.HybridAddressing,
            Version = global::Isopoh.Cryptography.Argon2.Argon2Version.Nineteen,
            TimeCost = _passes,
            MemoryCost = _memoryKiB,
            Lanes = _lanes,
            Threads = _lanes,
            Password = Password,
            Salt = Salt,
            HashLength = 32,
        };
        using var argon2 = new global::Isopoh.Cryptography.Argon2.Argon2(config);
        using var hash = argon2.Hash();
        return hash.Buffer.ToArray();
    }
}

/// <summary>
/// The single-lane set against the native library behind NSec (reported, not gating). libsodium's Argon2id has one lane, so
/// only the single-lane parameter set is comparable.
/// </summary>
[BenchmarkCategory("argon2")]
public class Argon2NativeRows
{
    private static readonly byte[] Password = "correct horse battery staple"u8.ToArray();
    private static readonly byte[] Salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    private readonly byte[] _tag = new byte[32];
    private global::NSec.Cryptography.PasswordBasedKeyDerivationAlgorithm? _nsec;

    [GlobalSetup]
    public void Setup() =>
        _nsec = global::NSec.Cryptography.PasswordBasedKeyDerivationAlgorithm.Argon2id(new global::NSec.Cryptography.Argon2Parameters
        {
            DegreeOfParallelism = 1,
            MemorySize = 19L * 1024, // NSec counts in KiB, like the RFC
            NumberOfPasses = 2,
        });

    [Benchmark]
    public byte[] Ours()
    {
        Argon2.DeriveKey(Argon2Type.Argon2id, Password, Salt, 19 * 1024, 2, 1, _tag);
        return _tag;
    }

    [Benchmark]
    [BenchmarkCategory("native")]
    public byte[] NSec() => _nsec!.DeriveBytes(Password, Salt, 32);
}
