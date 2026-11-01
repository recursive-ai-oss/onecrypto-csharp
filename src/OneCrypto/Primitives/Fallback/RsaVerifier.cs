using System.Numerics;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Primitives.Fallback;

/// <summary>
/// RSA signature verification (RFC 8017 section 8: RSASSA-PKCS1-v1_5 and RSASSA-PSS) for platforms whose cryptography cannot do it
/// (the browser) and for PSS parameter sets the platform cannot express (a salt length other than the digest size, or a mask
/// function hash that differs from the message hash). Verify-only: the modulus, the exponent, the digest and the signature are all
/// public, so it uses <see cref="BigInteger"/> and makes no constant-time claim. There is no signing or decryption here, and
/// none will be.
/// </summary>
internal static class RsaVerifier
{
    // Bounds on public input, so a hostile key cannot make a verification expensive.
    internal const int MaxModulusBits = 16384;
    internal const int MaxExponentBits = 256;

    /// <summary>RSASSA-PKCS1-v1_5-VERIFY (RFC 8017 section 8.2.2) over a digest.</summary>
    /// <param name="modulus">The modulus n, big-endian.</param>
    /// <param name="exponent">The public exponent e, big-endian.</param>
    /// <param name="hash">The digest algorithm; SHA-1, SHA-256, SHA-384, SHA-512 and SHA3-224/256/384/512 have DigestInfo prefixes here.</param>
    /// <param name="digest">The message digest.</param>
    /// <param name="signature">The signature; exactly as long as the modulus.</param>
    /// <returns>True when valid. False for a bad signature, a hash with no DigestInfo prefix, or a digest of the wrong size.</returns>
    /// <exception cref="ArgumentException">The key is not a usable RSA public key.</exception>
    public static bool VerifyPkcs1(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent, HashAlgorithmName hash, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        ReadOnlySpan<byte> oid = DigestOid(hash);
        if (oid.IsEmpty || digest.Length != Pkcs1DigestSize(hash))
        {
            return false;
        }

        if (!TryRecover(modulus, exponent, signature, out byte[]? em, out int k) || em is null)
        {
            return false;
        }

        // Section 9.2: EM = 0x00 || 0x01 || PS (0xFF, at least 8) || 0x00 || DigestInfo. The expected block is built and compared whole,
        // so no lenient reading of the DigestInfo (a missing NULL, trailing bytes) is accepted.
        // DigestInfo ::= SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING digest }
        int algLen = 2 + oid.Length + 2;
        int infoLen = 2 + algLen + 2 + digest.Length;
        int total = 2 + infoLen;
        if (k < total + 11)
        {
            return false;
        }

        byte[] expected = new byte[k];
        expected[1] = 0x01;
        expected.AsSpan(2, k - total - 3).Fill(0xFF);
        int pos = k - total;
        expected[pos - 1] = 0x00;
        expected[pos++] = 0x30;
        expected[pos++] = (byte)infoLen;
        expected[pos++] = 0x30;
        expected[pos++] = (byte)algLen;
        expected[pos++] = 0x06;
        expected[pos++] = (byte)oid.Length;
        oid.CopyTo(expected.AsSpan(pos));
        pos += oid.Length;
        expected[pos++] = 0x05;
        expected[pos++] = 0x00;
        expected[pos++] = 0x04;
        expected[pos++] = (byte)digest.Length;
        digest.CopyTo(expected.AsSpan(pos));
        return CryptographicOperations.FixedTimeEquals(em, expected);
    }

    /// <summary>RSASSA-PSS-VERIFY (RFC 8017 section 8.1.2, EMSA-PSS-VERIFY in section 9.1.2) over a digest.</summary>
    /// <param name="modulus">The modulus n, big-endian.</param>
    /// <param name="exponent">The public exponent e, big-endian.</param>
    /// <param name="hash">The message digest algorithm, also the hash inside the encoding.</param>
    /// <param name="mgfHash">The hash MGF1 runs on.</param>
    /// <param name="saltLength">The salt length in bytes (0 or more).</param>
    /// <param name="digest">The message digest.</param>
    /// <param name="signature">The signature; exactly as long as the modulus.</param>
    /// <returns>True when valid.</returns>
    /// <exception cref="ArgumentException">The key is not a usable RSA public key.</exception>
    public static bool VerifyPss(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent, HashAlgorithmName hash, HashAlgorithmName mgfHash, int saltLength, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        int hLen = DigestSize(hash);
        if (hLen == 0 || DigestSize(mgfHash) == 0 || digest.Length != hLen || saltLength < 0)
        {
            return false;
        }

        if (!TryRecover(modulus, exponent, signature, out byte[]? full, out int k) || full is null)
        {
            return false;
        }

        int modBits = (int)new BigInteger(modulus, isUnsigned: true, isBigEndian: true).GetBitLength();
        int emBits = modBits - 1;
        int emLen = (emBits + 7) / 8;
        // Section 8.1.2 step 2.c: the integer is converted to emLen octets; when that is one fewer than k, the top octet must be zero.
        if (emLen < k && full[0] != 0)
        {
            return false;
        }

        ReadOnlySpan<byte> em = full.AsSpan(k - emLen);
        // Section 9.1.2 steps 3 to 6.
        if (saltLength > emLen || emLen < hLen + saltLength + 2 || em[emLen - 1] != 0xBC)
        {
            return false;
        }

        int dbLen = emLen - hLen - 1;
        ReadOnlySpan<byte> maskedDb = em[..dbLen];
        ReadOnlySpan<byte> h = em.Slice(dbLen, hLen);
        int unusedBits = (8 * emLen) - emBits;
        byte topMask = (byte)(0xFF >> unusedBits);
        if ((maskedDb[0] & ~topMask) != 0)
        {
            return false;
        }

        byte[] db = new byte[dbLen];
        Mgf1(mgfHash, h, db);
        for (int i = 0; i < dbLen; i++)
        {
            db[i] ^= maskedDb[i];
        }

        db[0] &= topMask;
        int padLen = dbLen - saltLength - 1;
        for (int i = 0; i < padLen; i++)
        {
            if (db[i] != 0)
            {
                return false;
            }
        }

        if (db[padLen] != 0x01)
        {
            return false;
        }

        // M' = eight zero octets || mHash || salt; H' = Hash(M').
        byte[] mPrime = new byte[8 + hLen + saltLength];
        digest.CopyTo(mPrime.AsSpan(8));
        db.AsSpan(dbLen - saltLength).CopyTo(mPrime.AsSpan(8 + hLen));
        byte[] expected = PlatformHash.Digest(hash, mPrime)!;
        return CryptographicOperations.FixedTimeEquals(expected, h);
    }

    // RSAVP1 (RFC 8017 section 5.2.2) on a signature of exactly k octets, returned as k octets.
    private static bool TryRecover(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent, ReadOnlySpan<byte> signature, out byte[]? em, out int k)
    {
        em = null;
        modulus = TrimLeadingZeros(modulus);
        exponent = TrimLeadingZeros(exponent);
        var n = new BigInteger(modulus, isUnsigned: true, isBigEndian: true);
        var e = new BigInteger(exponent, isUnsigned: true, isBigEndian: true);
        if (n.GetBitLength() < 16 || n.GetBitLength() > MaxModulusBits || n.IsEven || e < 3 || e.IsEven || e.GetBitLength() > MaxExponentBits)
        {
            throw new ArgumentException("The RSA public key is not usable: the modulus must be odd and at most 16384 bits, the exponent odd, at least 3 and at most 256 bits.");
        }

        k = modulus.Length;
        if (signature.Length != k)
        {
            return false;
        }

        var s = new BigInteger(signature, isUnsigned: true, isBigEndian: true);
        if (s >= n)
        {
            return false;
        }

        BigInteger m = BigInteger.ModPow(s, e, n);
        em = new byte[k];
        return m.TryWriteBytes(em.AsSpan(), out int written, isUnsigned: true, isBigEndian: true)
            && ShiftRight(em, written);
    }

    // TryWriteBytes writes the minimal big-endian form at the start; move it to the end of the k-octet block.
    private static bool ShiftRight(byte[] block, int written)
    {
        if (written < block.Length)
        {
            Array.Copy(block, 0, block, block.Length - written, written);
            Array.Clear(block, 0, block.Length - written);
        }

        return true;
    }

    private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        int i = 0;
        while (i < value.Length - 1 && value[i] == 0)
        {
            i++;
        }

        return value[i..];
    }

    // MGF1 (RFC 8017 appendix B.2.1).
    private static void Mgf1(HashAlgorithmName hash, ReadOnlySpan<byte> seed, Span<byte> mask)
    {
        byte[] input = new byte[seed.Length + 4];
        seed.CopyTo(input);
        int pos = 0;
        for (uint counter = 0; pos < mask.Length; counter++)
        {
            input[seed.Length] = (byte)(counter >> 24);
            input[seed.Length + 1] = (byte)(counter >> 16);
            input[seed.Length + 2] = (byte)(counter >> 8);
            input[seed.Length + 3] = (byte)counter;
            byte[] block = PlatformHash.Digest(hash, input)!;
            int n = Math.Min(block.Length, mask.Length - pos);
            block.AsSpan(0, n).CopyTo(mask[pos..]);
            pos += n;
        }
    }

    /// <summary>The digest size in bytes of a hash this verifier knows, or 0.</summary>
    internal static int DigestSize(HashAlgorithmName hash) => PlatformHash.DigestSize(hash);

    /// <summary>SHA-224 as a hash name (the platform has no enumerated one); only its PKCS#1 DigestInfo is known here, the caller supplies the digest.</summary>
    internal static readonly HashAlgorithmName Sha224Name = new("SHA224");

    /// <summary>RIPEMD-160 as a hash name, with the same limit as <see cref="Sha224Name"/>.</summary>
    internal static readonly HashAlgorithmName Ripemd160Name = new("RIPEMD160");

    // PKCS#1 v1.5 verification takes a finished digest, so it also covers the two hashes the platform does not compute.
    private static int Pkcs1DigestSize(HashAlgorithmName hash) => hash == Sha224Name ? 28 : hash == Ripemd160Name ? 20 : DigestSize(hash);

    // DER content octets of the hash's OID: RFC 8017 section 9.2 note 1 (SHA-1, SHA-2) and NIST's csor hash OID arc 2.16.840.1.101.3.4.2.
    private static ReadOnlySpan<byte> DigestOid(HashAlgorithmName hash)
    {
        if (hash == HashAlgorithmName.SHA1)
        {
            return [0x2B, 0x0E, 0x03, 0x02, 0x1A];
        }

        if (hash == Sha224Name)
        {
            return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
        }

        if (hash == Ripemd160Name)
        {
            // ISO/IEC 10118-3 RIPEMD-160, 1.3.36.3.2.1 (RFC 8017 does not list it; OpenPGP uses it with this DigestInfo).
            return [0x2B, 0x24, 0x03, 0x02, 0x01];
        }

        if (hash == HashAlgorithmName.SHA256)
        {
            return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        }

        if (hash == HashAlgorithmName.SHA384)
        {
            return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
        }

        if (hash == HashAlgorithmName.SHA512)
        {
            return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        }

        if (hash == PlatformHash.Sha3_224Name)
        {
            return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07];
        }

        if (hash == HashAlgorithmName.SHA3_256)
        {
            return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08];
        }

        if (hash == HashAlgorithmName.SHA3_384)
        {
            return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09];
        }

        if (hash == HashAlgorithmName.SHA3_512)
        {
            return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A];
        }

        return default;
    }
}
