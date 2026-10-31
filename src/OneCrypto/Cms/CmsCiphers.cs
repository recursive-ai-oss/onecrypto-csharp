using System.Buffers.Binary;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>How a content-encryption algorithm works.</summary>
internal enum CipherKind
{
    Cbc,
    Gcm,
    Ccm,
    TripleDesCbc,
}

/// <summary>A content-encryption algorithm by object identifier.</summary>
internal sealed record ContentCipher(string Oid, CipherKind Kind, int KeyBytes, string Name)
{
    public bool Authenticated => Kind is CipherKind.Gcm or CipherKind.Ccm;

    public int BlockBytes => Kind == CipherKind.TripleDesCbc ? 8 : 16;
}

/// <summary>Content ciphers, key derivation for key agreement and password wrapping: the glue around the platform's AES, HMAC and HKDF.</summary>
internal static class CmsCiphers
{
    private static readonly ContentCipher[] Table =
    [
        new(CmsOids.Aes128Cbc, CipherKind.Cbc, 16, "AES-128-CBC"),
        new(CmsOids.Aes192Cbc, CipherKind.Cbc, 24, "AES-192-CBC"),
        new(CmsOids.Aes256Cbc, CipherKind.Cbc, 32, "AES-256-CBC"),
        new(CmsOids.Aes128Gcm, CipherKind.Gcm, 16, "AES-128-GCM"),
        new(CmsOids.Aes192Gcm, CipherKind.Gcm, 24, "AES-192-GCM"),
        new(CmsOids.Aes256Gcm, CipherKind.Gcm, 32, "AES-256-GCM"),
        new(CmsOids.Aes128Ccm, CipherKind.Ccm, 16, "AES-128-CCM"),
        new(CmsOids.Aes192Ccm, CipherKind.Ccm, 24, "AES-192-CCM"),
        new(CmsOids.Aes256Ccm, CipherKind.Ccm, 32, "AES-256-CCM"),
        new(CmsOids.TripleDesCbc, CipherKind.TripleDesCbc, 24, "3DES-CBC"),
    ];

    public static bool TryGet(string oid, out ContentCipher cipher)
    {
        foreach (ContentCipher c in Table)
        {
            if (c.Oid == oid)
            {
                cipher = c;
                return true;
            }
        }

        cipher = null!;
        return false;
    }

    public static ContentCipher Require(string oid) =>
        TryGet(oid, out ContentCipher c) ? c : throw new NotSupportedException($"The content-encryption algorithm {oid} is not supported.");

    /// <summary>The identifier with its parameters: the IV for CBC (RFC 3565 §4.1), the nonce and tag length for GCM and CCM (RFC 5084 §3.2, §3.3).</summary>
    public static AlgorithmIdentifier Describe(ContentCipher c, byte[] ivOrNonce, int tagBytes) => c.Kind switch
    {
        CipherKind.Cbc or CipherKind.TripleDesCbc => AlgorithmIdentifier.Create(c.Oid, DerWriter.OctetString(ivOrNonce)),
        _ => AlgorithmIdentifier.Create(c.Oid, DerWriter.Sequence(DerWriter.OctetString(ivOrNonce), DerWriter.SignedInteger(tagBytes))),
    };

    /// <summary>Reads the IV or nonce, and the tag length for the AEAD modes, from the algorithm parameters.</summary>
    public static void ReadParameters(ContentCipher c, AlgorithmIdentifier alg, out byte[] ivOrNonce, out int tagBytes)
    {
        tagBytes = 0;
        try
        {
            if (alg.Parameters.IsEmpty)
            {
                throw CmsRead.Bad("EncryptedContentInfo", "the content-encryption algorithm has no parameters");
            }

            var r = new Asn1Reader(alg.Parameters.Span, Asn1Rules.Ber);
            if (c.Kind is CipherKind.Cbc or CipherKind.TripleDesCbc)
            {
                ivOrNonce = r.ReadOctetStringBytes();
                if (ivOrNonce.Length != c.BlockBytes)
                {
                    throw CmsRead.Bad("EncryptedContentInfo", $"the IV must be {c.BlockBytes} octets");
                }

                return;
            }

            Asn1Reader seq = r.ReadSequence();
            ivOrNonce = seq.ReadOctetStringBytes();
            tagBytes = 12; // RFC 5084 §3.2: aes-ICVlen defaults to 12.
            if (seq.HasData)
            {
                tagBytes = seq.ReadInt32();
            }

            seq.ThrowIfNotEmpty();
            bool ok = c.Kind == CipherKind.Gcm
                ? ivOrNonce.Length == 12 && tagBytes is >= 12 and <= 16
                : ivOrNonce.Length is >= 7 and <= 13 && tagBytes is 4 or 6 or 8 or 10 or 12 or 14 or 16;
            if (!ok)
            {
                throw CmsRead.Bad("EncryptedContentInfo", "the nonce or tag length is not allowed");
            }
        }
        catch (Asn1ParseException e)
        {
            throw new CmsParseException("EncryptedContentInfo", e);
        }
    }

    /// <summary>CBC with PKCS #7 padding (RFC 5652 §6.3).</summary>
    public static byte[] EncryptCbc(ContentCipher c, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plaintext)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        return aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
    }

    /// <summary>CBC decryption; false when the padding is wrong (which also happens, by chance, with a wrong key).</summary>
    public static bool TryDecryptCbc(ContentCipher c, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, out byte[] plaintext)
    {
        plaintext = [];
        if (ciphertext.Length == 0 || ciphertext.Length % c.BlockBytes != 0)
        {
            return false;
        }

        try
        {
            if (c.Kind == CipherKind.TripleDesCbc)
            {
#pragma warning disable CA5350 // Triple DES is read-only here: it exists to open old messages and is gated by an option.
                using TripleDES des = TripleDES.Create();
#pragma warning restore CA5350
                des.Key = key.ToArray();
                plaintext = des.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
                return true;
            }

            using Aes aes = Aes.Create();
            aes.Key = key.ToArray();
            plaintext = aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>AEAD encryption; returns the ciphertext and the tag.</summary>
    public static byte[] EncryptAead(ContentCipher c, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, int tagBytes, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, out byte[] tag)
    {
        byte[] ct = new byte[plaintext.Length];
        tag = new byte[tagBytes];
        if (c.Kind == CipherKind.Gcm)
        {
            using var gcm = new AesGcm(key, tagBytes);
            gcm.Encrypt(nonce, plaintext, ct, tag, aad);
        }
        else
        {
            using var ccm = new AesCcm(key);
            ccm.Encrypt(nonce, plaintext, ct, tag, aad);
        }

        return ct;
    }

    /// <summary>AEAD decryption. The plaintext is only produced when the tag verifies; false otherwise.</summary>
    public static bool TryDecryptAead(ContentCipher c, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> aad, out byte[] plaintext)
    {
        plaintext = [];
        try
        {
            byte[] pt = new byte[ciphertext.Length];
            if (c.Kind == CipherKind.Gcm)
            {
                using var gcm = new AesGcm(key, tag.Length);
                gcm.Decrypt(nonce, ciphertext, tag, pt, aad);
            }
            else
            {
                using var ccm = new AesCcm(key);
                ccm.Decrypt(nonce, ciphertext, tag, pt, aad);
            }

            plaintext = pt;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>ANSI-X9.63-KDF (RFC 5753 §7.1.2, SEC 1 §3.6.1): hash(Z || counter || SharedInfo) with the counter starting at 1.</summary>
    public static byte[] X963Kdf(HashAlgorithmName hash, ReadOnlySpan<byte> z, ReadOnlySpan<byte> sharedInfo, int length)
    {
        byte[] output = new byte[length];
        Span<byte> counter = stackalloc byte[4]; // fixed small buffer
        using IncrementalHash h = IncrementalHash.CreateHash(hash);
        int done = 0;
        for (uint i = 1; done < length; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(counter, i);
            h.AppendData(z);
            h.AppendData(counter);
            h.AppendData(sharedInfo);
            byte[] block = h.GetHashAndReset();
            int n = Math.Min(block.Length, length - done);
            block.AsSpan(0, n).CopyTo(output.AsSpan(done));
            done += n;
        }

        return output;
    }

    /// <summary>ECC-CMS-SharedInfo (RFC 5753 §7.2): the key-wrap algorithm, the optional UKM and the KEK length in bits.</summary>
    public static byte[] EccCmsSharedInfo(AlgorithmIdentifier wrap, ReadOnlySpan<byte> ukm, int kekBytes)
    {
        byte[] bits = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bits, (uint)(kekBytes * 8));
        var parts = new List<byte[]> { wrap.Encoded.ToArray() };
        if (!ukm.IsEmpty)
        {
            parts.Add(DerWriter.Context(0, DerWriter.OctetString(ukm)));
        }

        parts.Add(DerWriter.Context(2, DerWriter.OctetString(bits)));
        return DerWriter.Sequence([.. parts]);
    }

    /// <summary>The hash and KDF family behind a key-agreement algorithm identifier (RFC 5753 §7.1, RFC 8418 §2.1).</summary>
    public static bool TryAgreementKdf(string oid, out HashAlgorithmName hash, out bool hkdf)
    {
        hkdf = false;
        switch (oid)
        {
            case CmsOids.StdDhSha1Kdf or "1.3.133.16.840.63.0.3": hash = HashAlgorithmName.SHA1; return true;
            case CmsOids.StdDhSha256Kdf or "1.3.132.1.14.1": hash = HashAlgorithmName.SHA256; return true;
            case CmsOids.StdDhSha384Kdf or "1.3.132.1.14.2": hash = HashAlgorithmName.SHA384; return true;
            case CmsOids.StdDhSha512Kdf or "1.3.132.1.14.3": hash = HashAlgorithmName.SHA512; return true;
            case CmsOids.StdDhHkdfSha256: hash = HashAlgorithmName.SHA256; hkdf = true; return true;
            case CmsOids.StdDhHkdfSha384: hash = HashAlgorithmName.SHA384; hkdf = true; return true;
            case CmsOids.StdDhHkdfSha512: hash = HashAlgorithmName.SHA512; hkdf = true; return true;
            default: hash = default; return false;
        }
    }

    /// <summary>Derives the KEK from a key-agreement secret: X9.63 for the <c>sha*kdf</c> schemes, HKDF with the UKM as salt for the <c>hkdf</c> schemes (RFC 8418 §2.1).</summary>
    public static byte[] AgreementKek(string schemeOid, ReadOnlySpan<byte> z, AlgorithmIdentifier wrap, ReadOnlySpan<byte> ukm, int kekBytes)
    {
        if (!TryAgreementKdf(schemeOid, out HashAlgorithmName hash, out bool hkdf))
        {
            throw new NotSupportedException($"The key-agreement algorithm {schemeOid} is not supported.");
        }

        byte[] info = EccCmsSharedInfo(wrap, ukm, kekBytes);
        if (!hkdf)
        {
            return X963Kdf(hash, z, info, kekBytes);
        }

        byte[] okm = new byte[kekBytes];
        HKDF.DeriveKey(hash, z, okm, ukm, info);
        return okm;
    }

    /// <summary>RFC 9629 §5: HKDF over the KEM secret, with CMSORIforKEMOtherInfo (the wrap algorithm, the KEK length and the UKM) as the info and no salt.</summary>
    public static byte[] KemKek(string kdfOid, ReadOnlySpan<byte> secret, AlgorithmIdentifier wrap, int kekLength, ReadOnlySpan<byte> ukm)
    {
        HashAlgorithmName hash = kdfOid switch
        {
            CmsOids.HkdfSha256 => HashAlgorithmName.SHA256,
            CmsOids.HkdfSha384 => HashAlgorithmName.SHA384,
            CmsOids.HkdfSha512 => HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException($"The key-derivation function {kdfOid} is not supported."),
        };
        var parts = new List<byte[]> { wrap.Encoded.ToArray(), DerWriter.SignedInteger(kekLength) };
        if (!ukm.IsEmpty)
        {
            parts.Add(DerWriter.Context(0, DerWriter.OctetString(ukm)));
        }

        byte[] okm = new byte[kekLength];
        HKDF.DeriveKey(hash, secret, okm, default, DerWriter.Sequence([.. parts]));
        return okm;
    }

    /// <summary>The key-wrap algorithm identifier (RFC 3565 §2.3.2) for a KEK of this size.</summary>
    public static string WrapOid(int kekBytes) => kekBytes switch
    {
        16 => CmsOids.Aes128Wrap,
        24 => CmsOids.Aes192Wrap,
        32 => CmsOids.Aes256Wrap,
        _ => throw new ArgumentOutOfRangeException(nameof(kekBytes), "AES key wrap needs a 16, 24 or 32 octet key."),
    };

    public static int WrapKeyBytes(string oid) => oid switch
    {
        CmsOids.Aes128Wrap => 16,
        CmsOids.Aes192Wrap => 24,
        CmsOids.Aes256Wrap or CmsOids.Aes256WrapPad => 32,
        CmsOids.Aes128WrapPad => 16,
        CmsOids.Aes192WrapPad => 24,
        _ => 0,
    };

    public static bool IsPadded(string wrapOid) => wrapOid is CmsOids.Aes128WrapPad or CmsOids.Aes192WrapPad or CmsOids.Aes256WrapPad;

    /// <summary>The wrap-with-padding identifier (RFC 5649, RFC 3565 §2.3.2) for a KEK of this size.</summary>
    public static string WrapPadOid(int kekBytes) => kekBytes switch
    {
        16 => CmsOids.Aes128WrapPad,
        24 => CmsOids.Aes192WrapPad,
        32 => CmsOids.Aes256WrapPad,
        _ => throw new ArgumentOutOfRangeException(nameof(kekBytes), "AES key wrap needs a 16, 24 or 32 octet key."),
    };

    /// <summary>Unwraps with the algorithm the identifier names: RFC 3394 from our primitives, RFC 5649 from the platform.</summary>
    public static byte[]? Unwrap(string wrapOid, ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrapped)
    {
        if (!IsPadded(wrapOid))
        {
            return AesUnwrap(kek, wrapped);
        }

        try
        {
            using Aes aes = Aes.Create();
            aes.Key = kek.ToArray();
            return aes.DecryptKeyWrapPadded(wrapped);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>RFC 5649 wrap, by the platform.</summary>
    public static byte[] AesWrapPadded(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> key)
    {
        using Aes aes = Aes.Create();
        aes.Key = kek.ToArray();
        return aes.EncryptKeyWrapPadded(key);
    }

    /// <summary>RFC 3394 wrap of a content-encryption or MAC key.</summary>
    public static byte[] AesWrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> key)
    {
        using var kw = new Primitives.AesKeyWrap(kek);
        byte[] wrapped = new byte[key.Length + Primitives.AesKeyWrap.Overhead];
        kw.Wrap(key, wrapped);
        return wrapped;
    }

    /// <summary>RFC 3394 unwrap; null when the integrity check fails.</summary>
    public static byte[]? AesUnwrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrapped)
    {
        if (wrapped.Length < Primitives.AesKeyWrap.MinKeyDataSize + Primitives.AesKeyWrap.Overhead || wrapped.Length % 8 != 0)
        {
            return null;
        }

        using var kw = new Primitives.AesKeyWrap(kek);
        byte[] key = new byte[wrapped.Length - Primitives.AesKeyWrap.Overhead];
        if (kw.TryUnwrap(wrapped, key))
        {
            return key;
        }

        CryptographicOperations.ZeroMemory(key);
        return null;
    }

    /// <summary>RFC 3211 §2.3.1: the key is formatted (length, check bytes, key, padding) and encrypted twice in CBC mode.</summary>
    public static byte[] Rfc3211Wrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> cek)
    {
        int block = 16;
        int total = Math.Max(2 * block, (4 + cek.Length + block - 1) / block * block);
        byte[] formatted = new byte[total];
        RandomNumberGenerator.Fill(formatted);
        formatted[0] = (byte)cek.Length;
        formatted[1] = (byte)~cek[0];
        formatted[2] = (byte)~cek[1];
        formatted[3] = (byte)~cek[2];
        cek.CopyTo(formatted.AsSpan(4));
        using Aes aes = Aes.Create();
        aes.Key = kek.ToArray();
        byte[] first = aes.EncryptCbc(formatted, iv, PaddingMode.None);
        return aes.EncryptCbc(first, first.AsSpan(first.Length - block, block), PaddingMode.None);
    }

    /// <summary>RFC 3211 §2.3.2; null when the format check fails.</summary>
    public static byte[]? Rfc3211Unwrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> wrapped)
    {
        int block = 16;
        if (wrapped.Length < 2 * block || wrapped.Length % block != 0 || iv.Length != block)
        {
            return null;
        }

        try
        {
            using Aes aes = Aes.Create();
            aes.Key = kek.ToArray();
            int n = wrapped.Length;
            byte[] lastInner = aes.DecryptCbc(wrapped[(n - block)..], wrapped.Slice(n - 2 * block, block), PaddingMode.None);
            byte[] head = aes.DecryptCbc(wrapped[..(n - block)], lastInner, PaddingMode.None);
            byte[] inner = [.. head, .. lastInner];
            byte[] formatted = aes.DecryptCbc(inner, iv, PaddingMode.None);
            int len = formatted[0];
            bool ok = len >= 3 && len <= formatted.Length - 4
                && (byte)~formatted[1] == formatted[4] && (byte)~formatted[2] == formatted[5] && (byte)~formatted[3] == formatted[6];
            return ok ? formatted.AsSpan(4, len).ToArray() : null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
