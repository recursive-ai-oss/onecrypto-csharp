using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Benchmarks;

// CBC decryption without padding with the legacy ciphers, one message per call under a fixed key and IV. These ciphers are decrypt-only
// here and are reported against the comparator; the speed bar is not applied to them (the area name says so).

/// <summary>Legacy cipher CBC decryption against the comparator.</summary>
[BenchmarkCategory("legacy-report-only")]
public class LegacyCbcDecryptRows : IDisposable
{
    private byte[] _cipher = [];
    private byte[] _plain = [];
    private byte[] _bcOut = [];
    private byte[] _iv = [];
    private IDisposable _ours = null!;
    private Func<int> _oursRun = null!;
    private CbcBlockCipher _bc = null!;

    /// <summary>The cipher.</summary>
    [Params("cast5", "idea", "blowfish", "twofish")]
    public string Cipher { get; set; } = "";

    /// <summary>Message size in bytes.</summary>
    [Params(1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        int block = Cipher == "twofish" ? 16 : 8;
        byte[] key = RandomNumberGenerator.GetBytes(Cipher == "twofish" ? 32 : 16);
        _iv = RandomNumberGenerator.GetBytes(block);
        _cipher = RandomNumberGenerator.GetBytes(Size);
        _plain = new byte[Size];
        _bcOut = new byte[Size];
        IBlockCipher engine;
        switch (Cipher)
        {
            case "cast5":
                var c = new Cast5(key);
                (_ours, _oursRun, engine) = (c, () => c.DecryptCbc(_cipher, _iv, _plain, PaddingMode.None), new Cast5Engine());
                break;
            case "idea":
                var i = new Idea(key);
                (_ours, _oursRun, engine) = (i, () => i.DecryptCbc(_cipher, _iv, _plain, PaddingMode.None), new IdeaEngine());
                break;
            case "blowfish":
                var b = new Blowfish(key);
                (_ours, _oursRun, engine) = (b, () => b.DecryptCbc(_cipher, _iv, _plain, PaddingMode.None), new BlowfishEngine());
                break;
            default:
                var t = new Twofish(key);
                (_ours, _oursRun, engine) = (t, () => t.DecryptCbc(_cipher, _iv, _plain, PaddingMode.None), new TwofishEngine());
                break;
        }

        _bc = new CbcBlockCipher(engine);
        _bc.Init(false, new ParametersWithIV(new KeyParameter(key), _iv));
    }

    [Benchmark]
    public int Ours() => _oursRun();

    [Benchmark]
    public int BouncyCastle()
    {
        _bc.Init(false, new ParametersWithIV(null, _iv));
        int block = _bc.GetBlockSize();
        for (int i = 0; i < Size; i += block)
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
