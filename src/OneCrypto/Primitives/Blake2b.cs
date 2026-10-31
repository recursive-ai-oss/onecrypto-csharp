using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace RecursiveAI.OneCrypto.Primitives;

/// <summary>
/// Unkeyed BLAKE2b (RFC 7693) with an output of 1 to 64 bytes. The platform has no BLAKE2b; Argon2 needs it for its
/// pre-hash and for the variable-length hash H'. It handles no secret-dependent control flow: the schedule depends only on the
/// message length.
/// </summary>
internal sealed class Blake2b
{
    private const int BlockBytes = 128;

    // RFC 7693 §2.6: the initialisation vector is the SHA-512 IV.
    private static ReadOnlySpan<ulong> Iv =>
    [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];

    // RFC 7693 §2.7: message word schedule, rounds 10 and 11 reuse rows 0 and 1.
    private static ReadOnlySpan<byte> Sigma =>
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    ];

    private readonly ulong[] _h = new ulong[8];
    private readonly ulong[] _v = new ulong[16];
    private readonly ulong[] _m = new ulong[16];
    private readonly byte[] _buffer = new byte[BlockBytes];
    private readonly int _outputLength;
    private int _buffered;
    private ulong _counter;

    /// <summary>Starts a hash with an output of <paramref name="outputLength"/> bytes (1 to 64).</summary>
    public Blake2b(int outputLength)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(outputLength, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(outputLength, 64);
        _outputLength = outputLength;
        Iv.CopyTo(_h);

        // RFC 7693 §2.5: parameter block word 0 = digest length | key length << 8 | fanout 1 << 16 | depth 1 << 24.
        _h[0] ^= 0x01010000UL ^ (ulong)outputLength;
    }

    /// <summary>One-shot hash of <paramref name="data"/> into <paramref name="destination"/> (its length is the digest length).</summary>
    public static void Hash(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        var hash = new Blake2b(destination.Length);
        hash.Update(data);
        hash.Finish(destination);
    }

    /// <summary>Absorbs more input.</summary>
    public void Update(ReadOnlySpan<byte> data)
    {
        // The last block is held back until Finish, because it must be compressed with the final flag.
        while (data.Length > 0)
        {
            if (_buffered == BlockBytes)
            {
                _counter += BlockBytes;
                Compress(_buffer, false);
                _buffered = 0;
            }

            int take = Math.Min(BlockBytes - _buffered, data.Length);
            data[..take].CopyTo(_buffer.AsSpan(_buffered));
            _buffered += take;
            data = data[take..];
        }
    }

    /// <summary>Absorbs a little-endian 32-bit integer.</summary>
    public void UpdateLe32(uint value)
    {
        Span<byte> b = stackalloc byte[4]; // fixed 4-byte buffer
        BinaryPrimitives.WriteUInt32LittleEndian(b, value);
        Update(b);
    }

    /// <summary>Completes the hash; <paramref name="destination"/> must be exactly the digest length.</summary>
    public void Finish(Span<byte> destination)
    {
        if (destination.Length != _outputLength)
        {
            throw new ArgumentException("The destination must be exactly the digest length.", nameof(destination));
        }

        _counter += (ulong)_buffered;
        _buffer.AsSpan(_buffered).Clear();
        Compress(_buffer, true);

        Span<byte> full = stackalloc byte[64]; // fixed 64-byte buffer
        for (int i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(full[(8 * i)..], _h[i]);
        }

        full[.._outputLength].CopyTo(destination);
        CryptographicOperations.ZeroMemory(full);
        Array.Clear(_buffer);
        Array.Clear(_m);
        Array.Clear(_h);
        Array.Clear(_v);
    }

    private void Compress(byte[] block, bool last)
    {
        ulong[] v = _v;
        ulong[] m = _m;
        for (int i = 0; i < 16; i++)
        {
            m[i] = BinaryPrimitives.ReadUInt64LittleEndian(block.AsSpan(8 * i));
        }

        for (int i = 0; i < 8; i++)
        {
            v[i] = _h[i];
            v[i + 8] = Iv[i];
        }

        v[12] ^= _counter; // the high half of the 128-bit counter stays zero: inputs are far below 2^64 bytes
        if (last)
        {
            v[14] = ~v[14];
        }

        ReadOnlySpan<byte> sigma = Sigma;
        for (int round = 0; round < 12; round++)
        {
            ReadOnlySpan<byte> s = sigma.Slice((round % 10) * 16, 16);
            G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for (int i = 0; i < 8; i++)
        {
            _h[i] ^= v[i] ^ v[i + 8];
        }
    }

    // RFC 7693 §3.1: the mixing function G.
    private static void G(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = BitOperations.RotateRight(v[d] ^ v[a], 32);
        v[c] += v[d];
        v[b] = BitOperations.RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = BitOperations.RotateRight(v[d] ^ v[a], 16);
        v[c] += v[d];
        v[b] = BitOperations.RotateRight(v[b] ^ v[c], 63);
    }
}
