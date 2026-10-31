using System.Linq;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Benchmarks;

// Ed25519, Ed448, X25519 and X448 against BouncyCastle (the managed comparator the bar is set against) and NSec (libsodium
// underneath; reported, not gating). Each row does the same work on the same inputs: a 1 KiB message, fixed keys.

internal static class CurveBenchData
{
    public static readonly byte[] Message = Enumerable.Range(0, 1024).Select(i => (byte)(i * 31)).ToArray();
    public static readonly byte[] Seed25519 = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    public static readonly byte[] Seed448 = Convert.FromHexString("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
    public static readonly byte[] PeerX25519 = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    public static readonly byte[] PeerX448 = Convert.FromHexString("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
}

[MemoryDiagnoser]
public class Ed25519Benchmarks
{
    private readonly byte[] _seed = CurveBenchData.Seed25519;
    private readonly byte[] _msg = CurveBenchData.Message;
    private byte[] _pub = new byte[32];
    private byte[] _sig = new byte[64];
    private Ed25519PrivateKey _key = null!;
    private Ed25519PrivateKeyParameters _bcPriv = null!;
    private Ed25519PublicKeyParameters _bcPub = null!;
    private NSec.Cryptography.Key _nsecKey = null!;
    private NSec.Cryptography.PublicKey _nsecPub = null!;

    [GlobalSetup]
    public void Setup()
    {
        _key = Ed25519PrivateKey.FromSeed(_seed);
        _key.PublicKey.Export(_pub);
        Ed25519.TrySign(_seed, _msg, _sig, out _);
        _bcPriv = new Ed25519PrivateKeyParameters(_seed, 0);
        _bcPub = _bcPriv.GeneratePublicKey();
        _nsecKey = NSec.Cryptography.Key.Import(NSec.Cryptography.SignatureAlgorithm.Ed25519, _seed, NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
        _nsecPub = _nsecKey.PublicKey;
    }

    [Benchmark(Description = "OneCrypto sign")]
    public int OursSign() { _key.TrySign(_msg, _sig, out int n); return n; }

    [Benchmark(Description = "BouncyCastle sign")]
    public byte[] BcSign()
    {
        var s = new Ed25519Signer();
        s.Init(true, _bcPriv);
        s.BlockUpdate(_msg, 0, _msg.Length);
        return s.GenerateSignature();
    }

    [Benchmark(Description = "NSec sign")]
    public byte[] NSecSign() => NSec.Cryptography.SignatureAlgorithm.Ed25519.Sign(_nsecKey, _msg);

    [Benchmark(Description = "OneCrypto verify")]
    public bool OursVerify() => Ed25519.Verify(_pub, _msg, _sig);

    [Benchmark(Description = "BouncyCastle verify")]
    public bool BcVerify()
    {
        var s = new Ed25519Signer();
        s.Init(false, _bcPub);
        s.BlockUpdate(_msg, 0, _msg.Length);
        return s.VerifySignature(_sig);
    }

    [Benchmark(Description = "NSec verify")]
    public bool NSecVerify() => NSec.Cryptography.SignatureAlgorithm.Ed25519.Verify(_nsecPub, _msg, _sig);

    [Benchmark(Description = "OneCrypto keygen (seed to public key)")]
    public int OursKeygen() { Ed25519.DerivePublicKey(_seed, _pub); return _pub[0]; }

    [Benchmark(Description = "BouncyCastle keygen")]
    public byte[] BcKeygen() => new Ed25519PrivateKeyParameters(_seed, 0).GeneratePublicKey().GetEncoded();

    [Benchmark(Description = "NSec keygen")]
    public byte[] NSecKeygen()
    {
        using var k = NSec.Cryptography.Key.Import(NSec.Cryptography.SignatureAlgorithm.Ed25519, _seed, NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
        return k.PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey);
    }
}

[MemoryDiagnoser]
public class Ed448Benchmarks
{
    private readonly byte[] _seed = CurveBenchData.Seed448;
    private readonly byte[] _msg = CurveBenchData.Message;
    private byte[] _pub = new byte[57];
    private byte[] _sig = new byte[114];
    private Ed448PrivateKey _key = null!;
    private Ed448PrivateKeyParameters _bcPriv = null!;
    private Ed448PublicKeyParameters _bcPub = null!;

    [GlobalSetup]
    public void Setup()
    {
        _key = Ed448PrivateKey.FromSeed(_seed);
        _key.PublicKey.Export(_pub);
        Ed448.TrySign(_seed, _msg, [], _sig, out _);
        _bcPriv = new Ed448PrivateKeyParameters(_seed, 0);
        _bcPub = _bcPriv.GeneratePublicKey();
    }

    [Benchmark(Description = "OneCrypto sign")]
    public int OursSign() { _key.TrySign(_msg, [], _sig, out int n); return n; }

    [Benchmark(Description = "BouncyCastle sign")]
    public byte[] BcSign()
    {
        var s = new Ed448Signer([]);
        s.Init(true, _bcPriv);
        s.BlockUpdate(_msg, 0, _msg.Length);
        return s.GenerateSignature();
    }

    [Benchmark(Description = "OneCrypto verify")]
    public bool OursVerify() => Ed448.Verify(_pub, _msg, [], _sig);

    [Benchmark(Description = "BouncyCastle verify")]
    public bool BcVerify()
    {
        var s = new Ed448Signer([]);
        s.Init(false, _bcPub);
        s.BlockUpdate(_msg, 0, _msg.Length);
        return s.VerifySignature(_sig);
    }

    [Benchmark(Description = "OneCrypto keygen (seed to public key)")]
    public int OursKeygen() { Ed448.DerivePublicKey(_seed, _pub); return _pub[0]; }

    [Benchmark(Description = "BouncyCastle keygen")]
    public byte[] BcKeygen() => new Ed448PrivateKeyParameters(_seed, 0).GeneratePublicKey().GetEncoded();
}

[MemoryDiagnoser]
public class X25519Benchmarks
{
    private readonly byte[] _priv = CurveBenchData.Seed25519;
    private readonly byte[] _peer = CurveBenchData.PeerX25519;
    private byte[] _out = new byte[32];
    private X25519PrivateKeyParameters _bcPriv = null!;
    private X25519PublicKeyParameters _bcPeer = null!;
    private NSec.Cryptography.Key _nsecKey = null!;
    private NSec.Cryptography.PublicKey _nsecPeer = null!;

    [GlobalSetup]
    public void Setup()
    {
        _bcPriv = new X25519PrivateKeyParameters(_priv, 0);
        _bcPeer = new X25519PublicKeyParameters(_peer, 0);
        _nsecKey = NSec.Cryptography.Key.Import(NSec.Cryptography.KeyAgreementAlgorithm.X25519, _priv, NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
        _nsecPeer = NSec.Cryptography.PublicKey.Import(NSec.Cryptography.KeyAgreementAlgorithm.X25519, _peer, NSec.Cryptography.KeyBlobFormat.RawPublicKey);
    }

    [Benchmark(Description = "OneCrypto agreement")]
    public bool OursAgree() => X25519.TryDeriveSharedSecret(_priv, _peer, _out);

    [Benchmark(Description = "BouncyCastle agreement")]
    public byte[] BcAgree()
    {
        var a = new X25519Agreement();
        a.Init(_bcPriv);
        byte[] o = new byte[32];
        a.CalculateAgreement(_bcPeer, o, 0);
        return o;
    }

    [Benchmark(Description = "NSec agreement")]
    public NSec.Cryptography.SharedSecret? NSecAgree() => NSec.Cryptography.KeyAgreementAlgorithm.X25519.Agree(_nsecKey, _nsecPeer);

    [Benchmark(Description = "OneCrypto keygen (private to public)")]
    public int OursKeygen() { X25519.DerivePublicKey(_priv, _out); return _out[0]; }

    [Benchmark(Description = "BouncyCastle keygen")]
    public byte[] BcKeygen() => new X25519PrivateKeyParameters(_priv, 0).GeneratePublicKey().GetEncoded();

    [Benchmark(Description = "NSec keygen")]
    public byte[] NSecKeygen()
    {
        using var k = NSec.Cryptography.Key.Import(NSec.Cryptography.KeyAgreementAlgorithm.X25519, _priv, NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
        return k.PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey);
    }
}

[MemoryDiagnoser]
public class X448Benchmarks
{
    private readonly byte[] _priv = CurveBenchData.Seed448[..56];
    private readonly byte[] _peer = CurveBenchData.PeerX448;
    private byte[] _out = new byte[56];
    private X448PrivateKeyParameters _bcPriv = null!;
    private X448PublicKeyParameters _bcPeer = null!;

    [GlobalSetup]
    public void Setup()
    {
        _bcPriv = new X448PrivateKeyParameters(_priv, 0);
        _bcPeer = new X448PublicKeyParameters(_peer, 0);
    }

    [Benchmark(Description = "OneCrypto agreement")]
    public bool OursAgree() => X448.TryDeriveSharedSecret(_priv, _peer, _out);

    [Benchmark(Description = "BouncyCastle agreement")]
    public byte[] BcAgree()
    {
        var a = new X448Agreement();
        a.Init(_bcPriv);
        byte[] o = new byte[56];
        a.CalculateAgreement(_bcPeer, o, 0);
        return o;
    }

    [Benchmark(Description = "OneCrypto keygen (private to public)")]
    public int OursKeygen() { X448.DerivePublicKey(_priv, _out); return _out[0]; }

    [Benchmark(Description = "BouncyCastle keygen")]
    public byte[] BcKeygen() => new X448PrivateKeyParameters(_priv, 0).GeneratePublicKey().GetEncoded();
}
