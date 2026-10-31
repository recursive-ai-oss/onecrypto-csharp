using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Benchmarks;

// AES key wrap (RFC 3394) of 32 bytes of key data under an AES-256 key-encryption key. The platform has no non-padded key wrap,
// so this is the one row where each step is a call into the platform's AES.

/// <summary>AES key wrap against the comparator.</summary>
[BenchmarkCategory("aes-kw")]
public class KeyWrapRows : IDisposable
{
    private readonly byte[] _kek = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _data = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _wrapped = new byte[40];
    private AesKeyWrap _ours = null!;
    private Rfc3394WrapEngine _bc = null!;

    [GlobalSetup]
    public void Setup()
    {
        _ours = new AesKeyWrap(_kek);
        _bc = new Rfc3394WrapEngine(new AesEngine());
        _bc.Init(true, new KeyParameter(_kek));
    }

    [Benchmark]
    public void Ours() => _ours.Wrap(_data, _wrapped);

    [Benchmark]
    public byte[] BouncyCastle() => _bc.Wrap(_data, 0, _data.Length);

    public void Dispose()
    {
        _ours.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>AES key unwrap (with integrity check) against the comparator.</summary>
[BenchmarkCategory("aes-kw")]
public class KeyUnwrapRows : IDisposable
{
    private readonly byte[] _kek = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _out = new byte[32];
    private byte[] _wrapped = [];
    private AesKeyWrap _ours = null!;
    private Rfc3394WrapEngine _bc = null!;

    [GlobalSetup]
    public void Setup()
    {
        _ours = new AesKeyWrap(_kek);
        _wrapped = new byte[40];
        _ours.Wrap(RandomNumberGenerator.GetBytes(32), _wrapped);
        _bc = new Rfc3394WrapEngine(new AesEngine());
        _bc.Init(false, new KeyParameter(_kek));
    }

    [Benchmark]
    public void Ours() => _ours.Unwrap(_wrapped, _out);

    [Benchmark]
    public byte[] BouncyCastle() => _bc.Unwrap(_wrapped, 0, _wrapped.Length);

    public void Dispose()
    {
        _ours.Dispose();
        GC.SuppressFinalize(this);
    }
}
