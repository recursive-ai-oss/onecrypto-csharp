using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>An incremental message digest chosen by object identifier, as CMS names its hash functions.</summary>
internal sealed class CmsDigest : IDisposable
{
    // RFC 8419 §3.1: Ed448 signatures use SHAKE256 with a 512-bit output as the message digest.
    private const int ShakeOutput = 64;

    private readonly IncrementalHash? _hash;
    private readonly Shake256? _shake;
    private MemoryStream? _shakeFallback;

    private CmsDigest(IncrementalHash? hash, Shake256? shake, MemoryStream? fallback)
    {
        _hash = hash;
        _shake = shake;
        _shakeFallback = fallback;
    }

    /// <summary>True when the platform (or the library) can compute the digest named by <paramref name="oid"/>.</summary>
    public static bool IsSupported(string oid) => oid switch
    {
        CmsOids.Shake256 => true,
        KnownOids.Sha3256 => SHA3_256.IsSupported,
        KnownOids.Sha3384 => SHA3_384.IsSupported,
        KnownOids.Sha3512 => SHA3_512.IsSupported,
        _ => SignatureAlgorithms.TryHash(oid, out _),
    };

    public static bool TryCreate(string oid, out CmsDigest? digest)
    {
        digest = null;
        if (oid == CmsOids.Shake256)
        {
            digest = Shake256.IsSupported ? new CmsDigest(null, new Shake256(), null) : new CmsDigest(null, null, new MemoryStream());
            return true;
        }

        if (!IsSupported(oid) || !SignatureAlgorithms.TryHash(oid, out HashAlgorithmName name))
        {
            return false;
        }

        digest = new CmsDigest(IncrementalHash.CreateHash(name), null, null);
        return true;
    }

    public static bool TryHash(string oid, ReadOnlySpan<byte> data, out byte[] hash)
    {
        hash = [];
        if (!TryCreate(oid, out CmsDigest? d))
        {
            return false;
        }

        using (d)
        {
            d!.Append(data);
            hash = d.Finish();
        }

        return true;
    }

    public void Append(ReadOnlySpan<byte> data)
    {
        if (_hash is not null)
        {
            _hash.AppendData(data);
        }
        else if (_shake is not null)
        {
            _shake.AppendData(data);
        }
        else
        {
            // Platforms without SHAKE256 hash through the library's own Keccak, which has no incremental form: the input is held.
            if (_shakeFallback!.Length + data.Length > (64 << 20))
            {
                throw new NotSupportedException("SHAKE256 is not available on this platform, and the input is too large to hash in memory.");
            }

            _shakeFallback.Write(data);
        }
    }

    public byte[] Finish()
    {
        if (_hash is not null)
        {
            return _hash.GetHashAndReset();
        }

        if (_shake is not null)
        {
            return _shake.GetHashAndReset(ShakeOutput);
        }

        var output = new byte[ShakeOutput];
        EdHash.Shake256(output, _shakeFallback!.GetBuffer().AsSpan(0, (int)_shakeFallback.Length));
        _shakeFallback = new MemoryStream();
        return output;
    }

    public void Dispose()
    {
        _hash?.Dispose();
        _shake?.Dispose();
        _shakeFallback?.Dispose();
    }
}
