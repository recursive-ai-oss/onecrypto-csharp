using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Benchmarks;

// EAX with AES-128, 16-byte nonce, 16-byte tag, 13 bytes of associated data (the shape OpenPGP uses), one message per call under a
// fixed key. Ours and the comparator get the same key, nonce, associated data and message. The comparator is re-initialised per
// call without the key, as a caller reusing a key must do, so neither side redoes its key schedule.

/// <summary>EAX encrypt against the comparator.</summary>
[BenchmarkCategory("ocb-eax")]
public class EaxEncryptRows : IDisposable
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(16);
    private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(16);
    private readonly byte[] _aad = RandomNumberGenerator.GetBytes(13);
    private readonly byte[] _tag = new byte[16];
    private byte[] _plain = [];
    private byte[] _cipher = [];
    private byte[] _bcOut = [];
    private readonly byte[] _nonce2 = RandomNumberGenerator.GetBytes(16);
    private bool _flip = true;
    private AesEax _ours = null!;
    private EaxBlockCipher _bc = null!;

    /// <summary>Message size in bytes.</summary>
    [Params(64, 1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _plain = RandomNumberGenerator.GetBytes(Size);
        _cipher = new byte[Size];
        _bcOut = new byte[Size + 16];
        _ours = new AesEax(_key);
        _bc = new EaxBlockCipher(new AesEngine());
        _bc.Init(true, new AeadParameters(new KeyParameter(_key), 128, _nonce, _aad));
    }

    [Benchmark]
    public void Ours() => _ours.Encrypt(_nonce, _plain, _cipher, _tag, _aad);

    [Benchmark]
    public int BouncyCastle()
    {
        // The comparator refuses to encrypt twice under the same nonce, so it alternates between two; the work is the same.
        _flip = !_flip;
        _bc.Init(true, new AeadParameters(null, 128, _flip ? _nonce : _nonce2, _aad));
        int n = _bc.ProcessBytes(_plain, 0, Size, _bcOut, 0);
        return n + _bc.DoFinal(_bcOut, n);
    }

    public void Dispose()
    {
        _ours.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>EAX decrypt (with tag check) against the comparator.</summary>
[BenchmarkCategory("ocb-eax")]
public class EaxDecryptRows : IDisposable
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(16);
    private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(16);
    private readonly byte[] _aad = RandomNumberGenerator.GetBytes(13);
    private readonly byte[] _tag = new byte[16];
    private byte[] _cipher = [];
    private byte[] _plainOut = [];
    private byte[] _bcIn = [];
    private byte[] _bcOut = [];
    private AesEax _ours = null!;
    private EaxBlockCipher _bc = null!;

    /// <summary>Message size in bytes.</summary>
    [Params(64, 1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(Size);
        _cipher = new byte[Size];
        _plainOut = new byte[Size];
        _ours = new AesEax(_key);
        _ours.Encrypt(_nonce, plain, _cipher, _tag, _aad);
        _bcIn = [.. _cipher, .. _tag];
        _bcOut = new byte[Size];
        _bc = new EaxBlockCipher(new AesEngine());
        _bc.Init(false, new AeadParameters(new KeyParameter(_key), 128, _nonce, _aad));
    }

    [Benchmark]
    public void Ours() => _ours.Decrypt(_nonce, _cipher, _tag, _plainOut, _aad);

    [Benchmark]
    public int BouncyCastle()
    {
        _bc.Init(false, new AeadParameters(null, 128, _nonce, _aad));
        int n = _bc.ProcessBytes(_bcIn, 0, _bcIn.Length, _bcOut, 0);
        return n + _bc.DoFinal(_bcOut, n);
    }

    public void Dispose()
    {
        _ours.Dispose();
        GC.SuppressFinalize(this);
    }
}
