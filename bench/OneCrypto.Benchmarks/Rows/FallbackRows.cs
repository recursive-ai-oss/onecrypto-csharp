using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using RecursiveAI.OneCrypto.Primitives.Fallback;

namespace OneCrypto.Benchmarks;

// The managed fallbacks run only where the platform lacks the primitive, so these rows are for information: the fallback against the
// fastest managed comparator, and the platform's own implementation as the native reference.

/// <summary>SHA3-256 of a message: the managed Keccak against the comparators.</summary>
[BenchmarkCategory("fallback-sha3")]
public class Sha3FallbackRows
{
    private byte[] _message = [];
    private readonly byte[] _digest = new byte[32];
    private readonly Sha3Digest _bc = new(256);

    /// <summary>Message size in bytes.</summary>
    [Params(64, 1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup() => _message = RandomNumberGenerator.GetBytes(Size);

    [Benchmark]
    public void Ours() => Keccak.Hash(Keccak.RateSha3_256, Keccak.SuffixSha3, _digest, _message);

    [Benchmark]
    public int BouncyCastle()
    {
        _bc.BlockUpdate(_message, 0, _message.Length);
        return _bc.DoFinal(_digest, 0);
    }

    [Benchmark]
    [BenchmarkCategory("native")]
    public int Platform() => SHA3_256.HashData(_message, _digest);
}

/// <summary>ChaCha20-Poly1305 encryption of a message with 13 bytes of associated data: the managed code against the comparators.</summary>
[BenchmarkCategory("fallback-chacha")]
public class ChaChaFallbackRows : IDisposable
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _nonce = RandomNumberGenerator.GetBytes(12);
    private readonly byte[] _nonce2 = RandomNumberGenerator.GetBytes(12);
    private readonly byte[] _aad = RandomNumberGenerator.GetBytes(13);
    private readonly byte[] _tag = new byte[16];
    private byte[] _plain = [];
    private byte[] _cipher = [];
    private byte[] _bcOut = [];
    private bool _flip;
    private System.Security.Cryptography.ChaCha20Poly1305 _platform = null!;
    private Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305 _bc = null!;

    /// <summary>Message size in bytes.</summary>
    [Params(64, 1024, 65536)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _plain = RandomNumberGenerator.GetBytes(Size);
        _cipher = new byte[Size];
        _bcOut = new byte[Size + 16];
        _platform = new System.Security.Cryptography.ChaCha20Poly1305(_key);
        _bc = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
    }

    [Benchmark]
    public void Ours() => ChaCha20Poly1305Managed.Encrypt(_key, _nonce, _plain, _cipher, _tag, _aad);

    [Benchmark]
    public int BouncyCastle()
    {
        // The comparator refuses to reuse a nonce under one key, so the two nonces alternate.
        _flip = !_flip;
        _bc.Init(true, new AeadParameters(new KeyParameter(_key), 128, _flip ? _nonce : _nonce2, _aad));
        int n = _bc.ProcessBytes(_plain, 0, _plain.Length, _bcOut, 0);
        return n + _bc.DoFinal(_bcOut, n);
    }

    [Benchmark]
    [BenchmarkCategory("native")]
    public void Platform() => _platform.Encrypt(_nonce, _plain, _cipher, _tag, _aad);

    public void Dispose()
    {
        _platform.Dispose();
        GC.SuppressFinalize(this);
    }
}
