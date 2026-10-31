using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Benchmarks;

// Each benchmark encrypts or decrypts one message under a fixed key with a fresh nonce per call, which is what OpenPGP and CMS do.
// Ours and the comparator are given the same key, nonce, associated data and message; the comparator is initialised without the
// key after the first call so that it does not redo its key schedule either.

/// <summary>OCB3 with AES-128 (15-byte nonce, 16-byte tag, as OpenPGP uses it) against the comparator.</summary>
[MemoryDiagnoser]
public class OcbBenchmarks : IDisposable
{
    private readonly byte[] _key = new byte[16];
    private readonly byte[] _nonce = new byte[15];
    private readonly byte[] _aad = new byte[13];
    private byte[] _plain = [];
    private byte[] _cipher = [];
    private readonly byte[] _tag = new byte[16];
    private byte[] _out = [];
    private AesOcb _ours = null!;
    private OcbBlockCipher _bcEnc = null!;
    private OcbBlockCipher _bcDec = null!;
    private byte[] _bcCipherWithTag = [];
    private byte[] _bcOut = [];

    [Params(64, 1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        RandomNumberGenerator.Fill(_key);
        RandomNumberGenerator.Fill(_nonce);
        _plain = RandomNumberGenerator.GetBytes(Size);
        _cipher = new byte[Size];
        _out = new byte[Size];
        _ours = new AesOcb(_key);
        _ours.Encrypt(_nonce, _plain, _cipher, _tag, _aad);
        _bcEnc = new OcbBlockCipher(new AesEngine(), new AesEngine());
        _bcDec = new OcbBlockCipher(new AesEngine(), new AesEngine());
        _bcEnc.Init(true, new AeadParameters(new KeyParameter(_key), 128, _nonce, _aad));
        _bcCipherWithTag = new byte[Size + 16];
        int produced = _bcEnc.ProcessBytes(_plain, 0, Size, _bcCipherWithTag, 0);
        _bcEnc.DoFinal(_bcCipherWithTag, produced);
        _bcDec.Init(false, new AeadParameters(new KeyParameter(_key), 128, _nonce, _aad));
        _bcOut = new byte[Size + 16];
    }

    [Benchmark]
    public void OursEncrypt() => _ours.Encrypt(_nonce, _plain, _cipher, _tag, _aad);

    [Benchmark]
    public void OursDecrypt() => _ours.Decrypt(_nonce, _cipher, _tag, _out, _aad);

    [Benchmark]
    public int ComparatorEncrypt()
    {
        _bcEnc.Init(true, new AeadParameters(null, 128, _nonce, _aad));
        int n = _bcEnc.ProcessBytes(_plain, 0, Size, _bcOut, 0);
        return n + _bcEnc.DoFinal(_bcOut, n);
    }

    [Benchmark]
    public int ComparatorDecrypt()
    {
        _bcDec.Init(false, new AeadParameters(null, 128, _nonce, _aad));
        int n = _bcDec.ProcessBytes(_bcCipherWithTag, 0, Size + 16, _bcOut, 0);
        return n + _bcDec.DoFinal(_bcOut, n);
    }

    [GlobalCleanup]
    public void Dispose()
    {
        _ours.Dispose();
        GC.SuppressFinalize(this);
    }
}
[MemoryDiagnoser]
public class EaxBenchmarks : IDisposable
{
    private readonly byte[] _key = new byte[16];
    private readonly byte[] _nonce = new byte[16];
    private readonly byte[] _aad = new byte[13];
    private byte[] _plain = [];
    private byte[] _cipher = [];
    private readonly byte[] _tag = new byte[16];
    private byte[] _out = [];
    private AesEax _ours = null!;
    private EaxBlockCipher _bcEnc = null!;
    private EaxBlockCipher _bcDec = null!;
    private byte[] _bcCipherWithTag = [];
    private byte[] _bcOut = [];

    [Params(64, 1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        RandomNumberGenerator.Fill(_key);
        RandomNumberGenerator.Fill(_nonce);
        _plain = RandomNumberGenerator.GetBytes(Size);
        _cipher = new byte[Size];
        _out = new byte[Size];
        _ours = new AesEax(_key);
        _ours.Encrypt(_nonce, _plain, _cipher, _tag, _aad);
        _bcEnc = new EaxBlockCipher(new AesEngine());
        _bcDec = new EaxBlockCipher(new AesEngine());
        _bcEnc.Init(true, new AeadParameters(new KeyParameter(_key), 128, _nonce, _aad));
        _bcCipherWithTag = new byte[Size + 16];
        int produced = _bcEnc.ProcessBytes(_plain, 0, Size, _bcCipherWithTag, 0);
        _bcEnc.DoFinal(_bcCipherWithTag, produced);
        _bcDec.Init(false, new AeadParameters(new KeyParameter(_key), 128, _nonce, _aad));
        _bcOut = new byte[Size + 16];
    }

    [Benchmark]
    public void OursEncrypt() => _ours.Encrypt(_nonce, _plain, _cipher, _tag, _aad);

    [Benchmark]
    public void OursDecrypt() => _ours.Decrypt(_nonce, _cipher, _tag, _out, _aad);

    [Benchmark]
    public int ComparatorEncrypt()
    {
        _bcEnc.Init(true, new AeadParameters(null, 128, _nonce, _aad));
        int n = _bcEnc.ProcessBytes(_plain, 0, Size, _bcOut, 0);
        return n + _bcEnc.DoFinal(_bcOut, n);
    }

    [Benchmark]
    public int ComparatorDecrypt()
    {
        _bcDec.Init(false, new AeadParameters(null, 128, _nonce, _aad));
        int n = _bcDec.ProcessBytes(_bcCipherWithTag, 0, Size + 16, _bcOut, 0);
        return n + _bcDec.DoFinal(_bcOut, n);
    }

    [GlobalCleanup]
    public void Dispose()
    {
        _ours.Dispose();
        GC.SuppressFinalize(this);
    }
}
[MemoryDiagnoser]
public class KeyWrapBenchmarks : IDisposable
{
    private readonly byte[] _kek = new byte[32];
    private byte[] _data = [];
    private readonly byte[] _wrapped = new byte[40];
    private readonly byte[] _out = new byte[32];
    private AesKeyWrap _ours = null!;
    private Rfc3394WrapEngine _bcWrap = null!;
    private Rfc3394WrapEngine _bcUnwrap = null!;
    private byte[] _bcWrapped = [];

    [GlobalSetup]
    public void Setup()
    {
        RandomNumberGenerator.Fill(_kek);
        _data = RandomNumberGenerator.GetBytes(32);
        _ours = new AesKeyWrap(_kek);
        _ours.Wrap(_data, _wrapped);
        _bcWrap = new Rfc3394WrapEngine(new AesEngine());
        _bcWrap.Init(true, new KeyParameter(_kek));
        _bcUnwrap = new Rfc3394WrapEngine(new AesEngine());
        _bcUnwrap.Init(false, new KeyParameter(_kek));
        _bcWrapped = _bcWrap.Wrap(_data, 0, _data.Length);
    }

    [Benchmark]
    public void OursWrap() => _ours.Wrap(_data, _wrapped);

    [Benchmark]
    public void OursUnwrap() => _ours.Unwrap(_wrapped, _out);

    [Benchmark]
    public byte[] ComparatorWrap() => _bcWrap.Wrap(_data, 0, _data.Length);

    [Benchmark]
    public byte[] ComparatorUnwrap() => _bcUnwrap.Unwrap(_bcWrapped, 0, _bcWrapped.Length);

    [GlobalCleanup]
    public void Dispose()
    {
        _ours.Dispose();
        GC.SuppressFinalize(this);
    }
}
