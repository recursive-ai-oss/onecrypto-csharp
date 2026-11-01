using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.OpenPgp.Packets;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.OpenPgp;

/// <summary>Maps OpenPGP algorithm identifiers onto the platform's and the library's primitives.</summary>
internal static class PgpAlgorithms
{
    internal static HashAlgorithmName HashName(PgpHashAlgorithm hash) => hash switch
    {
        PgpHashAlgorithm.Md5 => HashAlgorithmName.MD5,
        PgpHashAlgorithm.Sha1 => HashAlgorithmName.SHA1,
        PgpHashAlgorithm.Sha256 => HashAlgorithmName.SHA256,
        PgpHashAlgorithm.Sha384 => HashAlgorithmName.SHA384,
        PgpHashAlgorithm.Sha512 => HashAlgorithmName.SHA512,
        PgpHashAlgorithm.Sha3256 when SHA3_256.IsSupported => HashAlgorithmName.SHA3_256,
        PgpHashAlgorithm.Sha3512 when SHA3_512.IsSupported => HashAlgorithmName.SHA3_512,
        _ => throw new PgpException(PgpFailure.Unsupported, $"The hash algorithm {(byte)hash} ({hash}) is not supported on this platform."),
    };

    internal static int HashSize(PgpHashAlgorithm hash) => hash switch
    {
        PgpHashAlgorithm.Md5 => 16,
        PgpHashAlgorithm.Sha1 => 20,
        PgpHashAlgorithm.Sha256 or PgpHashAlgorithm.Sha3256 => 32,
        PgpHashAlgorithm.Sha384 => 48,
        PgpHashAlgorithm.Sha512 or PgpHashAlgorithm.Sha3512 => 64,
        _ => throw new PgpException(PgpFailure.Unsupported, $"The hash algorithm {(byte)hash} is not supported."),
    };

    /// <summary>Key size in bytes of a symmetric algorithm this library can decrypt with; others are reported as unsupported.</summary>
    internal static int KeySize(SymmetricAlgorithm cipher) => cipher switch
    {
        SymmetricAlgorithm.Idea or SymmetricAlgorithm.Cast5 or SymmetricAlgorithm.Blowfish => 16,
        SymmetricAlgorithm.TripleDes => 24,
        SymmetricAlgorithm.Aes128 or SymmetricAlgorithm.Camellia128 => 16,
        SymmetricAlgorithm.Aes192 or SymmetricAlgorithm.Camellia192 => 24,
        SymmetricAlgorithm.Aes256 or SymmetricAlgorithm.Camellia256 or SymmetricAlgorithm.Twofish => 32,
        _ => throw new PgpException(PgpFailure.Unsupported, $"The symmetric algorithm {(byte)cipher} ({cipher}) is not supported."),
    };

    /// <summary>Block size in bytes (RFC 9580 §9.3): 8 for IDEA, TripleDES, CAST5 and Blowfish, 16 for the rest.</summary>
    internal static int BlockSize(SymmetricAlgorithm cipher) => cipher switch
    {
        SymmetricAlgorithm.Idea or SymmetricAlgorithm.TripleDes or SymmetricAlgorithm.Cast5 or SymmetricAlgorithm.Blowfish => 8,
        _ => 16,
    };

    /// <summary>True for the ciphers that may only decrypt (legacy ciphers); the writer never chooses them.</summary>
    internal static bool IsLegacy(SymmetricAlgorithm cipher) => cipher is not (SymmetricAlgorithm.Aes128 or SymmetricAlgorithm.Aes192 or SymmetricAlgorithm.Aes256);

    /// <summary>
    /// OpenPGP CFB decryption for any supported cipher, in place and continuing from <paramref name="iv"/> (which is updated after whole
    /// blocks). Call with whole blocks except for the very last call.
    /// </summary>
    internal static void CfbDecrypt(SymmetricAlgorithm cipher, ReadOnlySpan<byte> key, Span<byte> iv, Span<byte> data)
    {
        if (cipher is SymmetricAlgorithm.Aes128 or SymmetricAlgorithm.Aes192 or SymmetricAlgorithm.Aes256)
        {
            CfbDecrypt(key, iv, data);
            return;
        }

        int bs = BlockSize(cipher);
        int whole = data.Length - (data.Length % bs); // public: depends on the length only
        byte[] next = new byte[bs];
        if (whole > 0)
        {
            data.Slice(whole - bs, bs).CopyTo(next);
        }

        switch (cipher)
        {
            case SymmetricAlgorithm.Idea:
                using (var c = new Idea(key)) { c.DecryptCfb(data, iv[..bs], data); }
                break;
            case SymmetricAlgorithm.Cast5:
                using (var c = new Cast5(key)) { c.DecryptCfb(data, iv[..bs], data); }
                break;
            case SymmetricAlgorithm.Blowfish:
                using (var c = new Blowfish(key)) { c.DecryptCfb(data, iv[..bs], data); }
                break;
            case SymmetricAlgorithm.Twofish:
                using (var c = new Twofish(key)) { c.DecryptCfb(data, iv[..bs], data); }
                break;
            case SymmetricAlgorithm.Camellia128 or SymmetricAlgorithm.Camellia192 or SymmetricAlgorithm.Camellia256:
                using (var c = new Camellia(key)) { c.DecryptCfb(data, iv[..bs], data); }
                break;
            case SymmetricAlgorithm.TripleDes:
#pragma warning disable CA5350 // Triple DES is read-only here: it exists to open old messages and keys.
                using (var t = TripleDES.Create())
#pragma warning restore CA5350
                {
                    t.Key = key.ToArray();
                    if (whole > 0)
                    {
                        t.DecryptCfb(data[..whole], iv[..bs], data[..whole], PaddingMode.None, 64);
                        next.CopyTo(iv);
                    }

                    if (whole < data.Length)
                    {
                        // A short last block uses the first bytes of the encrypted feedback register.
                        Span<byte> ks = new byte[bs];
                        t.EncryptEcb(iv[..bs], ks, PaddingMode.None);
                        for (int i = whole; i < data.Length; i++)
                        {
                            data[i] ^= ks[i - whole];
                        }
                    }
                }

                return;
            default:
                throw new PgpException(PgpFailure.Unsupported, $"The symmetric algorithm {(byte)cipher} ({cipher}) is not supported.");
        }

        if (whole > 0)
        {
            next.CopyTo(iv);
        }
    }

    /// <summary>RFC 9580 §5.13: the nonce length of each AEAD mode.</summary>
    internal static int NonceSize(AeadAlgorithm aead) => aead switch
    {
        AeadAlgorithm.Eax => 16,
        AeadAlgorithm.Ocb => 15,
        AeadAlgorithm.Gcm => 12,
        _ => throw new PgpException(PgpFailure.Unsupported, $"The AEAD algorithm {(byte)aead} is not supported."),
    };

    /// <summary>Applies an OpenPGP CFB step (full-block CFB with a zero or given IV) in place, continuing from <paramref name="iv"/>.</summary>
    internal static void CfbDecrypt(ReadOnlySpan<byte> key, Span<byte> iv, Span<byte> data)
    {
        // The BCL's CFB takes whole blocks when padding is none; the caller supplies a multiple of 16 except for the very last call.
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        int whole = data.Length & ~15;
        Span<byte> nextIv = new byte[16];
        if (whole > 0)
        {
            data.Slice(whole - 16, 16).CopyTo(nextIv);
            aes.DecryptCfb(data[..whole], iv, data[..whole], PaddingMode.None, 128);
            nextIv.CopyTo(iv);
        }

        if (whole < data.Length)
        {
            // Partial last block: CFB-128 keystream is the encryption of the IV; the tail is xored with its first bytes.
            Span<byte> ks = new byte[16];
            aes.EncryptEcb(iv, ks, PaddingMode.None);
            for (int i = whole; i < data.Length; i++)
            {
                data[i] ^= ks[i - whole];
            }
        }
    }

    internal static void CfbEncrypt(ReadOnlySpan<byte> key, Span<byte> iv, Span<byte> data)
    {
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        int whole = data.Length & ~15;
        if (whole > 0)
        {
            aes.EncryptCfb(data[..whole], iv, data[..whole], PaddingMode.None, 128);
            data.Slice(whole - 16, 16).CopyTo(iv);
        }

        if (whole < data.Length)
        {
            Span<byte> ks = new byte[16];
            aes.EncryptEcb(iv, ks, PaddingMode.None);
            for (int i = whole; i < data.Length; i++)
            {
                data[i] ^= ks[i - whole];
            }
        }
    }

    /// <summary>SHA-1 where the format fixes it: the secret-key integrity hash and the MDC (RFC 9580 §5.5.3, §5.14). It guards against accidents and the MDC is only trusted inside an encryption layer.</summary>
    internal static byte[] Sha1(ReadOnlySpan<byte> data)
    {
#pragma warning disable CA5350
        return SHA1.HashData(data);
#pragma warning restore CA5350
    }

    internal static ushort Checksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        foreach (byte b in data)
        {
            sum += b;
        }

        return (ushort)sum;
    }

    /// <summary>
    /// RFC 9580 §3.7: derives <paramref name="length"/> octets of key from a password with the S2K specifier. Argon2 costs are checked against
    /// <paramref name="limits"/> before any memory is allocated.
    /// </summary>
    internal static byte[] S2k(S2kSpecifier s2k, ReadOnlySpan<byte> password, int length, KdfLimits limits)
    {
        if (!s2k.IsKnown)
        {
            throw new PgpException(PgpFailure.Unsupported, "Unknown string-to-key specifier.");
        }

        if (s2k.Type == S2kType.Argon2)
        {
            // RFC 9580 §3.7.1.4: memory is 2^m KiB; the salt is 16 octets; the variant is Argon2id.
            if (s2k.MemoryExponent > 31)
            {
                throw new PgpException(PgpFailure.LimitExceeded, "Argon2 memory exponent is too large.");
            }

            byte[] key = new byte[length];
            try
            {
                Argon2.DeriveKey(Argon2Type.Argon2id, password, s2k.Salt.Span, checked(1 << s2k.MemoryExponent), s2k.Passes, s2k.Parallelism, key, limits: limits);
            }
            catch (KdfLimitExceededException e)
            {
                throw new PgpException(PgpFailure.LimitExceeded, "The Argon2 parameters exceed the limits.", e);
            }

            return key;
        }

        HashAlgorithmName name = HashName(s2k.Hash);
        int digest = HashSize(s2k.Hash);
        byte[] output = new byte[length];
        int instances = (length + digest - 1) / digest;
        byte[] salt = s2k.Type == S2kType.Simple ? [] : s2k.Salt.ToArray();
        long total = s2k.Type == S2kType.IteratedSalted ? Math.Max(s2k.IterationCount, salt.Length + password.Length) : salt.Length + password.Length;
        for (int i = 0; i < instances; i++)
        {
            using var h = IncrementalHash.CreateHash(name);
            h.AppendData(new byte[i]);
            long left = total;
            byte[] unit = new byte[salt.Length + password.Length];
            salt.CopyTo(unit, 0);
            password.CopyTo(unit.AsSpan(salt.Length));
            while (left > 0)
            {
                int n = (int)Math.Min(left, unit.Length);
                h.AppendData(unit.AsSpan(0, n));
                left -= n;
            }

            byte[] d = h.GetHashAndReset();
            int take = Math.Min(digest, length - i * digest);
            d.AsSpan(0, take).CopyTo(output.AsSpan(i * digest));
            CryptographicOperations.ZeroMemory(unit);
            CryptographicOperations.ZeroMemory(d);
        }

        return output;
    }

    /// <summary>One AEAD instance of the three RFC 9580 modes with a 16-octet tag.</summary>
    internal sealed class Aead : IDisposable
    {
        private readonly AesOcb? _ocb;
        private readonly AesEax? _eax;
        private readonly AesGcm? _gcm;

        internal Aead(AeadAlgorithm mode, ReadOnlySpan<byte> key)
        {
            switch (mode)
            {
                case AeadAlgorithm.Ocb:
                    _ocb = new AesOcb(key, 16);
                    break;
                case AeadAlgorithm.Eax:
                    _eax = new AesEax(key, 16);
                    break;
                case AeadAlgorithm.Gcm:
                    _gcm = new AesGcm(key, 16);
                    break;
                default:
                    throw new PgpException(PgpFailure.Unsupported, $"The AEAD algorithm {(byte)mode} is not supported.");
            }
        }

        internal void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> ad)
        {
            if (_ocb is not null)
            {
                _ocb.Encrypt(nonce, plaintext, ciphertext, tag, ad);
            }
            else if (_eax is not null)
            {
                _eax.Encrypt(nonce, plaintext, ciphertext, tag, ad);
            }
            else
            {
                _gcm!.Encrypt(nonce, plaintext, ciphertext, tag, ad);
            }
        }

        /// <summary>Decrypts and authenticates; on failure the output is zeroed and false is returned.</summary>
        internal bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> ad)
        {
            if (_ocb is not null)
            {
                return _ocb.TryDecrypt(nonce, ciphertext, tag, plaintext, ad);
            }

            if (_eax is not null)
            {
                return _eax.TryDecrypt(nonce, ciphertext, tag, plaintext, ad);
            }

            try
            {
                _gcm!.Decrypt(nonce, ciphertext, tag, plaintext, ad);
                return true;
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                return false;
            }
        }

        public void Dispose()
        {
            _ocb?.Dispose();
            _eax?.Dispose();
            _gcm?.Dispose();
        }
    }

    internal static byte[] BigEndian(ulong value)
    {
        byte[] b = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(b, value);
        return b;
    }
}
