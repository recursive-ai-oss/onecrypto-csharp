using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Benchmarks;

// OCB3 with AES-128, 15-byte nonce, 16-byte tag, 13 bytes of associated data (the shape OpenPGP uses), one message per call under a
// fixed key. Ours and the comparator get the same key, nonce, associated data and message. The comparator is re-initialised per
// call without the key, as a caller reusing a key must do, so neither side redoes its key schedule.

/// <summary>OCB3 encrypt against the comparator.</summary>
[BenchmarkCategory("ocb-eax")]
public class OcbEncryptRows : IDisposable
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(16);
    private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(15);
    private readonly byte[] _aad = RandomNumberGenerator.GetBytes(13);
    private readonly byte[] _tag = new byte[16];
    private byte[] _plain = [];
    private byte[] _cipher = [];
    private byte[] _bcOut = [];
    private AesOcb _ours = null!;
    private OcbBlockCipher _bc = null!;

    /// <summary>Message size in bytes.</summary>
    [Params(64, 1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _plain = RandomNumberGenerator.GetBytes(Size);
        _cipher = new byte[Size];
        _bcOut = new byte[Size + 16];
        _ours = new AesOcb(_key);
        _bc = new OcbBlockCipher(new AesEngine(), new AesEngine());
        _bc.Init(true, new AeadParameters(new KeyParameter(_key), 128, _nonce, _aad));
    }

    [Benchmark]
    public void Ours() => _ours.Encrypt(_nonce, _plain, _cipher, _tag, _aad);

    [Benchmark]
    public int BouncyCastle()
    {
        _bc.Init(true, new AeadParameters(null, 128, _nonce, _aad));
        int n = _bc.ProcessBytes(_plain, 0, Size, _bcOut, 0);
        return n + _bc.DoFinal(_bcOut, n);
    }

    public void Dispose()
    {
        _ours.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>OCB3 decrypt (with tag check) against the comparator.</summary>
[BenchmarkCategory("ocb-eax")]
public class OcbDecryptRows : IDisposable
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(16);
    private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(15);
    private readonly byte[] _aad = RandomNumberGenerator.GetBytes(13);
    private readonly byte[] _tag = new byte[16];
    private byte[] _cipher = [];
    private byte[] _plainOut = [];
    private byte[] _bcIn = [];
    private byte[] _bcOut = [];
    private AesOcb _ours = null!;
    private OcbBlockCipher _bc = null!;

    /// <summary>Message size in bytes.</summary>
    [Params(64, 1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(Size);
        _cipher = new byte[Size];
        _plainOut = new byte[Size];
        _ours = new AesOcb(_key);
        _ours.Encrypt(_nonce, plain, _cipher, _tag, _aad);
        _bcIn = [.. _cipher, .. _tag];
        _bcOut = new byte[Size];
        _bc = new OcbBlockCipher(new AesEngine(), new AesEngine());
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
