using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Benchmarks;

// Camellia in CBC without padding, one message per call under a fixed key and IV. Ours and the comparator get the same key, IV and
// message; the comparator is re-initialised per call without the key, as a caller reusing a key must do.

/// <summary>Camellia CBC encryption against the comparator.</summary>
[BenchmarkCategory("camellia")]
public class CamelliaCbcEncryptRows : IDisposable
{
    private readonly byte[] _iv = RandomNumberGenerator.GetBytes(16);
    private byte[] _plain = [];
    private byte[] _cipher = [];
    private byte[] _bcOut = [];
    private Camellia _ours = null!;
    private CbcBlockCipher _bc = null!;

    /// <summary>Key size in bits.</summary>
    [Params(128, 256)]
    public int KeyBits { get; set; }

    /// <summary>Message size in bytes.</summary>
    [Params(1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        byte[] key = RandomNumberGenerator.GetBytes(KeyBits / 8);
        _plain = RandomNumberGenerator.GetBytes(Size);
        _cipher = new byte[Size];
        _bcOut = new byte[Size];
        _ours = new Camellia(key);
        _bc = new CbcBlockCipher(new CamelliaEngine());
        _bc.Init(true, new ParametersWithIV(new KeyParameter(key), _iv));
    }

    [Benchmark]
    public int Ours() => _ours.EncryptCbc(_plain, _iv, _cipher, PaddingMode.None);

    [Benchmark]
    public int BouncyCastle()
    {
        _bc.Init(true, new ParametersWithIV(null, _iv));
        for (int i = 0; i < Size; i += 16)
        {
            _bc.ProcessBlock(_plain, i, _bcOut, i);
        }

        return Size;
    }

    public void Dispose()
    {
        _ours.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>Camellia CBC decryption against the comparator.</summary>
[BenchmarkCategory("camellia")]
public class CamelliaCbcDecryptRows : IDisposable
{
    private readonly byte[] _iv = RandomNumberGenerator.GetBytes(16);
    private byte[] _cipher = [];
    private byte[] _plain = [];
    private byte[] _bcOut = [];
    private Camellia _ours = null!;
    private CbcBlockCipher _bc = null!;

    /// <summary>Key size in bits.</summary>
    [Params(128, 256)]
    public int KeyBits { get; set; }

    /// <summary>Message size in bytes.</summary>
    [Params(1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        byte[] key = RandomNumberGenerator.GetBytes(KeyBits / 8);
        _cipher = RandomNumberGenerator.GetBytes(Size);
        _plain = new byte[Size];
        _bcOut = new byte[Size];
        _ours = new Camellia(key);
        _bc = new CbcBlockCipher(new CamelliaEngine());
        _bc.Init(false, new ParametersWithIV(new KeyParameter(key), _iv));
    }

    [Benchmark]
    public int Ours() => _ours.DecryptCbc(_cipher, _iv, _plain, PaddingMode.None);

    [Benchmark]
    public int BouncyCastle()
    {
        _bc.Init(false, new ParametersWithIV(null, _iv));
        for (int i = 0; i < Size; i += 16)
        {
            _bc.ProcessBlock(_cipher, i, _bcOut, i);
        }

        return Size;
    }

    public void Dispose()
    {
        _ours.Dispose();
        GC.SuppressFinalize(this);
    }
}
