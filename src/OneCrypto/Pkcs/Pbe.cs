using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.Pkcs;

/// <summary>The cipher PBES2 (RFC 8018 §6.2) encrypts with.</summary>
public enum Pbes2Cipher
{
    /// <summary>AES-256 in CBC mode with PKCS#7 padding (aes256-CBC-PAD, the OpenSSL and BCL default).</summary>
    Aes256Cbc,

    /// <summary>AES-192 in CBC mode.</summary>
    Aes192Cbc,

    /// <summary>AES-128 in CBC mode.</summary>
    Aes128Cbc,

    /// <summary>AES-256-GCM (RFC 5084), with a 12-byte nonce and a 16-byte tag appended to the ciphertext.</summary>
    Aes256Gcm,

    /// <summary>AES-128-GCM (RFC 5084).</summary>
    Aes128Gcm,
}

/// <summary>The key-derivation function PBES2 uses.</summary>
public enum Pbes2Kdf
{
    /// <summary>PBKDF2 (RFC 8018 §5.2) with an HMAC pseudo-random function.</summary>
    Pbkdf2,

    /// <summary>scrypt (RFC 7914 §7 for the PBES2 parameters).</summary>
    Scrypt,
}

/// <summary>Parameters for encrypting with PBES2. The defaults are AES-256-CBC, PBKDF2-HMAC-SHA-256, 600,000 iterations and a 16-byte random salt.</summary>
public sealed class Pbes2Options
{
    /// <summary>The defaults.</summary>
    public static Pbes2Options Default { get; } = new();

    /// <summary>The encryption scheme. Default <see cref="Pbes2Cipher.Aes256Cbc"/>.</summary>
    public Pbes2Cipher Cipher { get; init; } = Pbes2Cipher.Aes256Cbc;

    /// <summary>The key-derivation function. Default <see cref="Pbes2Kdf.Pbkdf2"/>.</summary>
    public Pbes2Kdf Kdf { get; init; } = Pbes2Kdf.Pbkdf2;

    /// <summary>The PBKDF2 hash: SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512. Default SHA-256.</summary>
    public HashAlgorithmName Prf { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>The PBKDF2 iteration count. Default 600,000.</summary>
    public int Iterations { get; init; } = 600_000;

    /// <summary>The salt length in bytes. Default 16.</summary>
    public int SaltLength { get; init; } = 16;

    /// <summary>The scrypt CPU/memory cost N (a power of two). Default 2^15.</summary>
    public int ScryptCost { get; init; } = 1 << 15;

    /// <summary>The scrypt block size r. Default 8.</summary>
    public int ScryptBlockSize { get; init; } = 8;

    /// <summary>The scrypt parallelism p. Default 1.</summary>
    public int ScryptParallelism { get; init; } = 1;
}

/// <summary>Password-based encryption: PBES2 (RFC 8018) and the PKCS#12 key-derivation PBEs (RFC 7292 Appendix B and C).</summary>
internal static class Pbe
{
    public const string Pbes2 = "1.2.840.113549.1.5.13";
    public const string Pbkdf2Oid = "1.2.840.113549.1.5.12";
    public const string ScryptOid = "1.3.6.1.4.1.11591.4.11";
    public const string Pbmac1 = "1.2.840.113549.1.5.14";
    public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
    public const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
    public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";
    public const string Aes128Gcm = "2.16.840.1.101.3.4.1.6";
    public const string Aes192Gcm = "2.16.840.1.101.3.4.1.26";
    public const string Aes256Gcm = "2.16.840.1.101.3.4.1.46";
    public const string DesEde3Cbc = "1.2.840.113549.3.7";
    public const string P12Rc4_128 = "1.2.840.113549.1.12.1.1";
    public const string P12Rc4_40 = "1.2.840.113549.1.12.1.2";
    public const string P12TripleDes3 = "1.2.840.113549.1.12.1.3";
    public const string P12TripleDes2 = "1.2.840.113549.1.12.1.4";
    public const string P12Rc2_128 = "1.2.840.113549.1.12.1.5";
    public const string P12Rc2_40 = "1.2.840.113549.1.12.1.6";

    // SHA-224 is deliberately absent from both tables: the platform has no SHA-224 hash or HMAC, so a file that uses it is reported
    // as an unsupported algorithm rather than approximated.
    public static string? HashOidName(string oid) => oid switch
    {
        "1.3.14.3.2.26" => "SHA1",
        "2.16.840.1.101.3.4.2.1" => "SHA256",
        "2.16.840.1.101.3.4.2.2" => "SHA384",
        "2.16.840.1.101.3.4.2.3" => "SHA512",
        _ => null,
    };

    public static string? HashToOid(string name) => name switch
    {
        "SHA1" => "1.3.14.3.2.26",
        "SHA256" => "2.16.840.1.101.3.4.2.1",
        "SHA384" => "2.16.840.1.101.3.4.2.2",
        "SHA512" => "2.16.840.1.101.3.4.2.3",
        _ => null,
    };

    public static string? HmacOidHash(string oid) => oid switch
    {
        "1.2.840.113549.2.7" => "SHA1",
        "1.2.840.113549.2.9" => "SHA256",
        "1.2.840.113549.2.10" => "SHA384",
        "1.2.840.113549.2.11" => "SHA512",
        _ => null,
    };

    public static string HmacOid(string hash) => hash switch
    {
        "SHA1" => "1.2.840.113549.2.7",
        "SHA384" => "1.2.840.113549.2.10",
        "SHA512" => "1.2.840.113549.2.11",
        _ => "1.2.840.113549.2.9",
    };

    /// <summary>The password as the UTF-8 bytes PBES2 and PBMAC1 use (RFC 8018 §3).</summary>
    public static PinnedSecret Utf8(ReadOnlySpan<char> password)
    {
        var s = new PinnedSecret(System.Text.Encoding.UTF8.GetByteCount(password));
        System.Text.Encoding.UTF8.GetBytes(password, s.Span);
        return s;
    }

    /// <summary>The password as a PKCS#12 BMPString: UTF-16BE with a terminating zero character (RFC 7292 Appendix B.1). With <paramref name="nullPassword"/>, zero bytes.</summary>
    public static PinnedSecret Bmp(ReadOnlySpan<char> password, bool nullPassword)
    {
        if (nullPassword)
        {
            return new PinnedSecret(0);
        }

        var s = new PinnedSecret((password.Length * 2) + 2);
        for (int i = 0; i < password.Length; i++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(s.Span[(2 * i)..], password[i]);
        }

        return s;
    }

    // ---- PKCS#12 key derivation (RFC 7292 Appendix B.2) ----

    /// <summary>Fills the output with bytes for purpose <paramref name="id"/> (1 key, 2 IV, 3 MAC key).</summary>
    public static void Pkcs12Kdf(HashAlgorithmName hash, byte id, ReadOnlySpan<byte> passwordBmp, ReadOnlySpan<byte> salt, long iterations, Span<byte> output)
    {
        int u = HashLength(hash);
        int v = hash == HashAlgorithmName.SHA384 || hash == HashAlgorithmName.SHA512 ? 128 : 64;
        int sLen = salt.Length == 0 ? 0 : v * ((salt.Length + v - 1) / v);
        int pLen = passwordBmp.Length == 0 ? 0 : v * ((passwordBmp.Length + v - 1) / v);
        byte[] input = new byte[v + sLen + pLen];
        Span<byte> a = stackalloc byte[64]; // fixed size, 64 bytes
        a = a[..u];
        Span<byte> b = stackalloc byte[128]; // fixed size, 128 bytes
        b = b[..v];
        try
        {
            input.AsSpan(0, v).Fill(id);
            for (int i = 0; i < sLen; i++)
            {
                input[v + i] = salt[i % salt.Length];
            }

            for (int i = 0; i < pLen; i++)
            {
                input[v + sLen + i] = passwordBmp[i % passwordBmp.Length];
            }

            int produced = 0;
            while (produced < output.Length)
            {
                CryptographicOperations.HashData(hash, input, a);
                for (long r = 1; r < iterations; r++)
                {
                    CryptographicOperations.HashData(hash, a, a);
                }

                int take = Math.Min(u, output.Length - produced);
                a[..take].CopyTo(output[produced..]);
                produced += take;
                if (produced >= output.Length)
                {
                    break;
                }

                for (int i = 0; i < v; i++)
                {
                    b[i] = a[i % u];
                }

                // I_j = (I_j + B + 1) mod 2^(8v) for each v-byte block of I (the D block is not part of it).
                for (int off = v; off < input.Length; off += v)
                {
                    int carry = 1;
                    for (int k = v - 1; k >= 0; k--)
                    {
                        int sum = input[off + k] + b[k] + carry;
                        input[off + k] = (byte)sum;
                        carry = sum >> 8;
                    }
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(a);
            CryptographicOperations.ZeroMemory(b);
        }
    }

    private static int HashLength(HashAlgorithmName h) => h.Name switch
    {
        "SHA1" => 20,
        "SHA256" => 32,
        "SHA384" => 48,
        "SHA512" => 64,
        "SHA224" => 28,
        _ => throw new CryptographicException("Unsupported hash for the PKCS#12 key derivation."),
    };

    // ---- decrypt ----

    /// <summary>
    /// Decrypts <paramref name="data"/> as described by the PBES2 or PKCS#12 PBE algorithm identifier. On failure nothing is returned.
    /// </summary>
    public static PkcsStatus Decrypt(AlgorithmIdentifier alg, ReadOnlySpan<char> password, bool nullPassword, ReadOnlySpan<byte> data, PkcsLimits limits, out PinnedSecret? plaintext)
    {
        plaintext = null;
        try
        {
            if (alg.Oid == Pbes2)
            {
                return DecryptPbes2(alg, password, data, limits, out plaintext);
            }

            return DecryptPkcs12Pbe(alg, password, nullPassword, data, limits, out plaintext);
        }
        catch (Asn1ParseException)
        {
            return PkcsStatus.Malformed;
        }
        catch (X509ParseException)
        {
            return PkcsStatus.Malformed;
        }
        catch (ArgumentException)
        {
            // A KDF refused parameters from the file that the checks above did not anticipate.
            return PkcsStatus.Malformed;
        }
        catch (PkcsParseException ex)
        {
            return ex.Error == PkcsError.LimitExceeded ? PkcsStatus.LimitExceeded : ex.Error == PkcsError.Unsupported ? PkcsStatus.UnsupportedAlgorithm : PkcsStatus.Malformed;
        }
        catch (KdfLimitExceededException)
        {
            return PkcsStatus.LimitExceeded;
        }
        catch (CryptographicException)
        {
            return PkcsStatus.WrongPasswordOrCorrupt;
        }
    }

    private static PkcsStatus DecryptPbes2(AlgorithmIdentifier alg, ReadOnlySpan<char> password, ReadOnlySpan<byte> data, PkcsLimits limits, out PinnedSecret? plaintext)
    {
        plaintext = null;
        const string what = "PBES2-params";
        var r = new Asn1Reader(alg.Parameters.Span, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader seq = r.ReadSequence();
        r.ThrowIfNotEmpty();
        AlgorithmIdentifier kdf = AlgorithmIdentifier.Parse(seq.ReadEncodedValue().ToArray());
        AlgorithmIdentifier enc = AlgorithmIdentifier.Parse(seq.ReadEncodedValue().ToArray());
        seq.ThrowIfNotEmpty();

        (int keyLen, bool gcm, bool des3) = enc.Oid switch
        {
            Aes128Cbc => (16, false, false),
            Aes192Cbc => (24, false, false),
            Aes256Cbc => (32, false, false),
            Aes128Gcm => (16, true, false),
            Aes192Gcm => (24, true, false),
            Aes256Gcm => (32, true, false),
            DesEde3Cbc => (24, false, true),
            _ => (0, false, false),
        };
        if (keyLen == 0)
        {
            return PkcsStatus.UnsupportedAlgorithm;
        }

        ReadOnlySpan<byte> iv;
        int tagLen = 16;
        var er = new Asn1Reader(enc.Parameters.Span, Asn1Rules.Ber, limits.Asn1);
        if (gcm)
        {
            Asn1Reader g = er.ReadSequence();
            iv = g.ReadOctetString();
            if (g.HasData)
            {
                tagLen = g.ReadInt32();
            }

            g.ThrowIfNotEmpty();
            if (iv.Length != 12 || tagLen < 12 || tagLen > 16)
            {
                throw PkcsFail.Invalid(what, "GCM nonce must be 12 bytes and the tag 12 to 16.");
            }
        }
        else
        {
            iv = er.ReadOctetString();
            if (iv.Length != (des3 ? 8 : 16))
            {
                throw PkcsFail.Invalid(what, "The CBC IV has the wrong length.");
            }
        }

        using var key = new PinnedSecret(keyLen);
        PkcsStatus ks = DeriveKey(kdf, password, keyLen, limits, key.Span);
        if (ks != PkcsStatus.Ok)
        {
            return ks;
        }

        return gcm ? DecryptGcm(key.ReadOnlySpan, iv, data, tagLen, out plaintext) : DecryptCbc(des3, key.ReadOnlySpan, iv, data, out plaintext);
    }

    private static PkcsStatus DeriveKey(AlgorithmIdentifier kdf, ReadOnlySpan<char> password, int keyLen, PkcsLimits limits, Span<byte> key)
    {
        const string what = "PBES2 key derivation";
        var r = new Asn1Reader(kdf.Parameters.Span, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader p = r.ReadSequence();
        using PinnedSecret pw = Utf8(password);
        if (kdf.Oid == Pbkdf2Oid)
        {
            ReadOnlySpan<byte> salt = p.ReadOctetString();
            long iterations = p.ReadInt64();
            if (iterations < 1)
            {
                throw PkcsFail.Invalid(what, "The PBKDF2 iteration count must be positive.");
            }

            if (salt.Length > limits.MaxSaltLength || iterations > limits.MaxIterations)
            {
                return PkcsStatus.LimitExceeded;
            }

            string hash = "SHA1";
            if (p.HasData && p.PeekTag() == Asn1Tag.Universal(Asn1Tags.IntegerType))
            {
                if (p.ReadInt32() != keyLen)
                {
                    throw PkcsFail.Invalid(what, "keyLength does not match the cipher.");
                }
            }

            if (p.HasData)
            {
                AlgorithmIdentifier prf = AlgorithmIdentifier.Parse(p.ReadEncodedValue().ToArray());
                hash = HmacOidHash(prf.Oid) ?? string.Empty;
                if (hash.Length == 0)
                {
                    return PkcsStatus.UnsupportedAlgorithm;
                }
            }

            p.ThrowIfNotEmpty();
            Rfc2898DeriveBytes.Pbkdf2(pw.ReadOnlySpan, salt, key, (int)iterations, new HashAlgorithmName(hash));
            return PkcsStatus.Ok;
        }

        if (kdf.Oid == ScryptOid)
        {
            ReadOnlySpan<byte> salt = p.ReadOctetString();
            long n = p.ReadInt64();
            long blockSize = p.ReadInt64();
            long par = p.ReadInt64();
            if (p.HasData && p.ReadInt32() != keyLen)
            {
                throw PkcsFail.Invalid(what, "keyLength does not match the cipher.");
            }

            p.ThrowIfNotEmpty();
            if (salt.Length > limits.MaxSaltLength)
            {
                return PkcsStatus.LimitExceeded;
            }

            if (n < 2 || n > int.MaxValue || (n & (n - 1)) != 0 || blockSize < 1 || blockSize > 1024 || par < 1 || par > 1024)
            {
                throw PkcsFail.Invalid(what, "The scrypt parameters are out of range.");
            }

            Scrypt.DeriveKey(pw.ReadOnlySpan, salt, (int)n, (int)blockSize, (int)par, key, limits.Kdf);
            return PkcsStatus.Ok;
        }

        return PkcsStatus.UnsupportedAlgorithm;
    }

    private static PkcsStatus DecryptGcm(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> data, int tagLen, out PinnedSecret? plaintext)
    {
        plaintext = null;
        if (data.Length < tagLen)
        {
            return PkcsStatus.WrongPasswordOrCorrupt;
        }

        var pt = new PinnedSecret(data.Length - tagLen);
        try
        {
            Platform.RequireAesGcm();
            using var gcm = new AesGcm(key, tagLen);
            gcm.Decrypt(nonce, data[..^tagLen], data[^tagLen..], pt.Span);
            plaintext = pt;
            return PkcsStatus.Ok;
        }
        catch (CryptographicException)
        {
            pt.Dispose();
            return PkcsStatus.WrongPasswordOrCorrupt;
        }
    }

    private static PkcsStatus DecryptCbc(bool tripleDes, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, out PinnedSecret? plaintext)
    {
        plaintext = null;
        int block = tripleDes ? 8 : 16;
        if (data.Length == 0 || data.Length % block != 0)
        {
            return PkcsStatus.WrongPasswordOrCorrupt;
        }

        var buf = new PinnedSecret(data.Length);
        try
        {
            if (tripleDes)
            {
                LegacyCrypto.TripleDesCbcDecrypt(key, iv, data, buf.Span);
            }
            else
            {
                using Aes a = Aes.Create();
                a.SetKey(key);
                a.DecryptCbc(data, iv, buf.Span, PaddingMode.None);
            }

            return Unpad(buf, block, out plaintext);
        }
        finally
        {
            buf.Dispose();
        }
    }

    /// <summary>Removes PKCS#7 padding (RFC 5652 §6.3). A bad pad means a wrong key or damaged data; no plaintext comes out.</summary>
    private static PkcsStatus Unpad(PinnedSecret buf, int block, out PinnedSecret? plaintext)
    {
        plaintext = null;
        ReadOnlySpan<byte> b = buf.ReadOnlySpan;
        int pad = b[^1];
        int bad = (pad == 0 ? 1 : 0) | (pad > block ? 1 : 0);
        int check = Math.Min(pad, block);
        for (int i = 1; i <= check; i++)
        {
            bad |= b[^i] ^ pad;
        }

        if (bad != 0)
        {
            return PkcsStatus.WrongPasswordOrCorrupt;
        }

        plaintext = new PinnedSecret(b[..^pad]);
        return PkcsStatus.Ok;
    }

    private static PkcsStatus DecryptPkcs12Pbe(AlgorithmIdentifier alg, ReadOnlySpan<char> password, bool nullPassword, ReadOnlySpan<byte> data, PkcsLimits limits, out PinnedSecret? plaintext)
    {
        plaintext = null;
        (int keyLen, string kind) = alg.Oid switch
        {
            P12TripleDes3 => (24, "3des"),
            P12TripleDes2 => (16, "3des"),
            P12Rc2_128 => (16, "rc2"),
            P12Rc2_40 => (5, "rc2"),
            _ => (0, string.Empty),
        };
        if (keyLen == 0)
        {
            // RC4 (OIDs ...12.1.1 and .2) and the PKCS#5 v1.5 password schemes are not read: the platform has no RC4 and they are obsolete.
            return PkcsStatus.UnsupportedAlgorithm;
        }

        var r = new Asn1Reader(alg.Parameters.Span, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader p = r.ReadSequence();
        ReadOnlySpan<byte> salt = p.ReadOctetString();
        long iterations = p.HasData ? p.ReadInt64() : 1;
        p.ThrowIfNotEmpty();
        if (iterations < 1)
        {
            throw PkcsFail.Invalid("pkcs-12PbeParams", "The iteration count must be positive.");
        }

        if (iterations > limits.MaxIterations || salt.Length > limits.MaxSaltLength)
        {
            return PkcsStatus.LimitExceeded;
        }

        using PinnedSecret pw = Bmp(password, nullPassword);
        using var key = new PinnedSecret(kind == "3des" ? 24 : keyLen);
        Span<byte> iv = stackalloc byte[8]; // fixed size, 8 bytes
        Pkcs12Kdf(HashAlgorithmName.SHA1, 1, pw.ReadOnlySpan, salt, iterations, key.Span[..keyLen]);
        Pkcs12Kdf(HashAlgorithmName.SHA1, 2, pw.ReadOnlySpan, salt, iterations, iv);
        if (kind == "3des")
        {
            if (keyLen == 16)
            {
                // Two-key triple DES: K3 = K1 (RFC 7292 Appendix C).
                key.Span[..8].CopyTo(key.Span[16..]);
            }

            return DecryptCbc(true, key.ReadOnlySpan, iv, data, out plaintext);
        }

        return DecryptRc2(key.ReadOnlySpan[..keyLen], iv, data, out plaintext);
    }

    private static PkcsStatus DecryptRc2(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data, out PinnedSecret? plaintext)
    {
        plaintext = null;
        if (data.Length == 0 || data.Length % 8 != 0)
        {
            return PkcsStatus.WrongPasswordOrCorrupt;
        }

        var buf = new PinnedSecret(data.Length);
        try
        {
            LegacyCrypto.Rc2CbcDecrypt(key, iv, data, buf.Span);
            return Unpad(buf, 8, out plaintext);
        }
        finally
        {
            buf.Dispose();
        }
    }

    // ---- encrypt ----

    /// <summary>Encrypts with PBES2 and returns the ciphertext and the encoded AlgorithmIdentifier.</summary>
    public static byte[] EncryptPbes2(ReadOnlySpan<byte> plaintext, ReadOnlySpan<char> password, Pbes2Options o, out byte[] algorithm)
    {
        (int keyLen, string cipherOid, bool gcm) = o.Cipher switch
        {
            Pbes2Cipher.Aes256Cbc => (32, Aes256Cbc, false),
            Pbes2Cipher.Aes192Cbc => (24, Aes192Cbc, false),
            Pbes2Cipher.Aes128Cbc => (16, Aes128Cbc, false),
            Pbes2Cipher.Aes256Gcm => (32, Aes256Gcm, true),
            Pbes2Cipher.Aes128Gcm => (16, Aes128Gcm, true),
            _ => throw new ArgumentOutOfRangeException(nameof(o)),
        };
        if (o.SaltLength < 8 || o.SaltLength > 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(o), "The salt must be 8 to 1024 bytes.");
        }

        byte[] salt = RandomNumberGenerator.GetBytes(o.SaltLength);
        using var key = new PinnedSecret(keyLen);
        using PinnedSecret pw = Utf8(password);
        var w = new Asn1Writer();
        w.PushSequence();
        w.WriteObjectIdentifier(Pbes2);
        w.PushSequence();

        // keyDerivationFunc
        w.PushSequence();
        if (o.Kdf == Pbes2Kdf.Pbkdf2)
        {
            if (o.Iterations < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(o), "Iterations must be positive.");
            }

            string hash = o.Prf.Name ?? "SHA256";
            if (hash is not ("SHA1" or "SHA256" or "SHA384" or "SHA512"))
            {
                throw new ArgumentOutOfRangeException(nameof(o), "PBKDF2 supports SHA-1, SHA-256, SHA-384 and SHA-512 here.");
            }

            Rfc2898DeriveBytes.Pbkdf2(pw.ReadOnlySpan, salt, key.Span, o.Iterations, o.Prf);
            w.WriteObjectIdentifier(Pbkdf2Oid);
            w.PushSequence();
            w.WriteOctetString(salt);
            w.WriteInteger(o.Iterations);
            w.WriteInteger(keyLen);
            w.PushSequence();
            w.WriteObjectIdentifier(HmacOid(hash));
            w.WriteNull();
            w.Pop();
            w.Pop();
        }
        else
        {
            Scrypt.DeriveKey(pw.ReadOnlySpan, salt, o.ScryptCost, o.ScryptBlockSize, o.ScryptParallelism, key.Span);
            w.WriteObjectIdentifier(ScryptOid);
            w.PushSequence();
            w.WriteOctetString(salt);
            w.WriteInteger(o.ScryptCost);
            w.WriteInteger(o.ScryptBlockSize);
            w.WriteInteger(o.ScryptParallelism);
            w.WriteInteger(keyLen);
            w.Pop();
        }

        w.Pop();

        // encryptionScheme
        byte[] ciphertext;
        w.PushSequence();
        w.WriteObjectIdentifier(cipherOid);
        if (gcm)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            ciphertext = new byte[plaintext.Length + 16];
            Platform.RequireAesGcm();
            using var g = new AesGcm(key.ReadOnlySpan, 16);
            g.Encrypt(nonce, plaintext, ciphertext.AsSpan(0, plaintext.Length), ciphertext.AsSpan(plaintext.Length, 16));
            w.PushSequence();
            w.WriteOctetString(nonce);
            w.WriteInteger(16);
            w.Pop();
        }
        else
        {
            byte[] iv = RandomNumberGenerator.GetBytes(16);
            using Aes a = Aes.Create();
            a.SetKey(key.ReadOnlySpan);
            ciphertext = a.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);

            w.WriteOctetString(iv);
        }

        w.Pop();
        w.Pop();
        w.Pop();
        algorithm = w.Encode();
        return ciphertext;
    }
}
