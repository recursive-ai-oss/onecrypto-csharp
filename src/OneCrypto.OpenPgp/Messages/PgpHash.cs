using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>
/// A running hash for signature and string-to-key work. SHA-224 and RIPEMD-160 are not offered by the platform, and old OpenPGP data still uses them, so
/// they are computed here, for verification and key reading only: the public inputs make constant-time coding unnecessary, and no signing path
/// reaches them. Every other algorithm is the platform's.
/// </summary>
internal sealed class PgpHash : IDisposable
{
    private readonly IncrementalHash? _platform;
    private readonly BlockHash? _managed;

    internal PgpHash(PgpHashAlgorithm hash)
    {
        switch (hash)
        {
            case PgpHashAlgorithm.Sha224:
                _managed = new Sha224Engine();
                break;
            case PgpHashAlgorithm.Ripemd160:
                _managed = new Ripemd160Engine();
                break;
            default:
                _platform = IncrementalHash.CreateHash(PgpAlgorithms.HashName(hash));
                break;
        }
    }

    internal static bool IsManaged(PgpHashAlgorithm hash) => hash is PgpHashAlgorithm.Sha224 or PgpHashAlgorithm.Ripemd160;

    internal void Append(ReadOnlySpan<byte> data)
    {
        if (_platform is not null)
        {
            _platform.AppendData(data);
        }
        else
        {
            _managed!.Append(data);
        }
    }

    /// <summary>Returns the digest and leaves the hash ready for a new message.</summary>
    internal byte[] Finish() => _platform is not null ? _platform.GetHashAndReset() : _managed!.Finish();

    public void Dispose() => _platform?.Dispose();

    /// <summary>The digest of one buffer.</summary>
    internal static byte[] Compute(PgpHashAlgorithm hash, ReadOnlySpan<byte> data)
    {
        using var h = new PgpHash(hash);
        h.Append(data);
        return h.Finish();
    }

    /// <summary>A Merkle-Damgard hash over 64-octet blocks with the 0x80, zeros, length padding.</summary>
    private abstract class BlockHash
    {
        private readonly byte[] _block = new byte[64];
        private int _filled;
        private ulong _length;

        protected abstract bool BigEndianLength { get; }

        protected abstract void Reset();

        protected abstract void Compress(ReadOnlySpan<byte> block);

        protected abstract byte[] Output();

        protected BlockHash() => Reset();

        internal void Append(ReadOnlySpan<byte> data)
        {
            _length += (ulong)data.Length;
            while (!data.IsEmpty)
            {
                if (_filled == 0 && data.Length >= 64)
                {
                    Compress(data[..64]);
                    data = data[64..];
                    continue;
                }

                int n = Math.Min(64 - _filled, data.Length);
                data[..n].CopyTo(_block.AsSpan(_filled));
                _filled += n;
                data = data[n..];
                if (_filled == 64)
                {
                    Compress(_block);
                    _filled = 0;
                }
            }
        }

        internal byte[] Finish()
        {
            ulong bits = _length * 8;
            Span<byte> pad = stackalloc byte[72]; // bounds: at most 63 zeros, the 0x80 and the eight length octets
            pad.Clear();
            pad[0] = 0x80;
            int zeros = (int)((55 - (_length % 64) + 64) % 64);
            int padLength = 1 + zeros;
            Span<byte> total = pad[..(padLength + 8)];
            if (BigEndianLength)
            {
                BinaryPrimitives.WriteUInt64BigEndian(total[padLength..], bits);
            }
            else
            {
                BinaryPrimitives.WriteUInt64LittleEndian(total[padLength..], bits);
            }

            ulong saved = _length;
            Append(total);
            _length = saved;
            byte[] digest = Output();
            Reset();
            _filled = 0;
            _length = 0;
            return digest;
        }
    }

    /// <summary>SHA-224 (FIPS 180-4 §6.3): the SHA-256 function from a different initial value, cut to 28 octets.</summary>
    private sealed class Sha224Engine : BlockHash
    {
        private static readonly uint[] K =
        [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];

        private readonly uint[] _h = new uint[8];
        private readonly uint[] _w = new uint[64];

        protected override bool BigEndianLength => true;

        // FIPS 180-4 §5.3.2.
        protected override void Reset() => new uint[] { 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 }.CopyTo(_h, 0);

        protected override void Compress(ReadOnlySpan<byte> block)
        {
            uint[] w = _w;
            for (int i = 0; i < 16; i++)
            {
                w[i] = BinaryPrimitives.ReadUInt32BigEndian(block[(4 * i)..]);
            }

            for (int i = 16; i < 64; i++)
            {
                uint s0 = BitOperations.RotateRight(w[i - 15], 7) ^ BitOperations.RotateRight(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint s1 = BitOperations.RotateRight(w[i - 2], 17) ^ BitOperations.RotateRight(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            uint a = _h[0], b = _h[1], c = _h[2], d = _h[3], e = _h[4], f = _h[5], g = _h[6], h = _h[7];
            for (int i = 0; i < 64; i++)
            {
                uint t1 = h + (BitOperations.RotateRight(e, 6) ^ BitOperations.RotateRight(e, 11) ^ BitOperations.RotateRight(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
                uint t2 = (BitOperations.RotateRight(a, 2) ^ BitOperations.RotateRight(a, 13) ^ BitOperations.RotateRight(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            _h[0] += a;
            _h[1] += b;
            _h[2] += c;
            _h[3] += d;
            _h[4] += e;
            _h[5] += f;
            _h[6] += g;
            _h[7] += h;
        }

        protected override byte[] Output()
        {
            byte[] r = new byte[28];
            for (int i = 0; i < 7; i++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(4 * i), _h[i]);
            }

            return r;
        }
    }

    /// <summary>RIPEMD-160 (Dobbertin, Bosselaers, Preneel 1996): two parallel lines of five rounds of sixteen steps, combined at the end of each block.</summary>
    private sealed class Ripemd160Engine : BlockHash
    {
        private static readonly byte[] RL =
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
        ];

        private static readonly byte[] RR =
        [
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
        ];

        private static readonly byte[] SL =
        [
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
        ];

        private static readonly byte[] SR =
        [
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
        ];

        private static readonly uint[] KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
        private static readonly uint[] KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];

        private readonly uint[] _h = new uint[5];
        private readonly uint[] _x = new uint[16];

        protected override bool BigEndianLength => false;

        protected override void Reset() => new uint[] { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }.CopyTo(_h, 0);

        private static uint F(int round, uint x, uint y, uint z) => round switch
        {
            0 => x ^ y ^ z,
            1 => (x & y) | (~x & z),
            2 => (x | ~y) ^ z,
            3 => (x & z) | (y & ~z),
            _ => x ^ (y | ~z),
        };

        protected override void Compress(ReadOnlySpan<byte> block)
        {
            for (int i = 0; i < 16; i++)
            {
                _x[i] = BinaryPrimitives.ReadUInt32LittleEndian(block[(4 * i)..]);
            }

            uint al = _h[0], bl = _h[1], cl = _h[2], dl = _h[3], el = _h[4];
            uint ar = al, br = bl, cr = cl, dr = dl, er = el;
            for (int j = 0; j < 80; j++)
            {
                int round = j / 16;
                uint t = BitOperations.RotateLeft(al + F(round, bl, cl, dl) + _x[RL[j]] + KL[round], SL[j]) + el;
                al = el;
                el = dl;
                dl = BitOperations.RotateLeft(cl, 10);
                cl = bl;
                bl = t;
                t = BitOperations.RotateLeft(ar + F(4 - round, br, cr, dr) + _x[RR[j]] + KR[round], SR[j]) + er;
                ar = er;
                er = dr;
                dr = BitOperations.RotateLeft(cr, 10);
                cr = br;
                br = t;
            }

            uint tmp = _h[1] + cl + dr;
            _h[1] = _h[2] + dl + er;
            _h[2] = _h[3] + el + ar;
            _h[3] = _h[4] + al + br;
            _h[4] = _h[0] + bl + cr;
            _h[0] = tmp;
        }

        protected override byte[] Output()
        {
            byte[] r = new byte[20];
            for (int i = 0; i < 5; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(4 * i), _h[i]);
            }

            return r;
        }
    }
}
