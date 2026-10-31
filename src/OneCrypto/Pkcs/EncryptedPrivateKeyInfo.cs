using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Pem;

namespace RecursiveAI.OneCrypto.Pkcs;

/// <summary>
/// A password-encrypted PKCS#8 key (<c>EncryptedPrivateKeyInfo</c>, RFC 5208 §6, RFC 5958 §3). Reads PBES2 (RFC 8018) with PBKDF2 or
/// scrypt and AES-CBC, AES-GCM or triple DES, and the PKCS#12 PBEs with triple DES or RC2. Writes PBES2 only.
/// </summary>
/// <remarks>Nothing is decrypted until <see cref="TryDecrypt"/> or <see cref="Decrypt"/> is called, and no plaintext is released when the password is wrong or the data is damaged.</remarks>
public sealed class EncryptedPrivateKeyInfo
{
    private readonly byte[] _encoded;
    private readonly byte[] _data;
    private readonly PkcsLimits _limits;

    private EncryptedPrivateKeyInfo(byte[] encoded, AlgorithmIdentifier alg, byte[] data, PkcsLimits limits)
    {
        _encoded = encoded;
        EncryptionAlgorithm = alg;
        _data = data;
        _limits = limits;
    }

    /// <summary>The <c>encryptionAlgorithm</c>.</summary>
    public AlgorithmIdentifier EncryptionAlgorithm { get; }

    /// <summary>The <c>encryptedData</c> octets.</summary>
    public ReadOnlyMemory<byte> EncryptedData => _data;

    /// <summary>The whole encoding as received.</summary>
    public ReadOnlyMemory<byte> Encoded => _encoded;

    /// <summary>Reads an EncryptedPrivateKeyInfo.</summary>
    /// <exception cref="PkcsParseException">The input is not an EncryptedPrivateKeyInfo.</exception>
    public static EncryptedPrivateKeyInfo Parse(ReadOnlySpan<byte> encoded, PkcsLimits? limits = null)
    {
        limits ??= PkcsLimits.Default;
        const string what = "EncryptedPrivateKeyInfo";
        if (encoded.Length > limits.MaxEncodedSize)
        {
            throw PkcsFail.Limit(what, "The input is larger than the configured limit.");
        }

        byte[] copy = encoded.ToArray();
        return PkcsFail.Run(what, () =>
        {
            var r = new Asn1Reader(copy, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader s = r.ReadSequence();
            r.ThrowIfNotEmpty();
            AlgorithmIdentifier alg = AlgorithmIdentifier.Parse(s.ReadEncodedValue().ToArray());
            byte[] data = s.ReadOctetStringBytes();
            s.ThrowIfNotEmpty();
            return new EncryptedPrivateKeyInfo(copy, alg, data, limits);
        });
    }

    /// <summary>Reads an EncryptedPrivateKeyInfo, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlySpan<byte> encoded, out EncryptedPrivateKeyInfo? value, PkcsLimits? limits = null)
    {
        try
        {
            value = Parse(encoded, limits);
            return true;
        }
        catch (PkcsParseException)
        {
            value = null;
            return false;
        }
    }

    /// <summary>Reads an <c>ENCRYPTED PRIVATE KEY</c> PEM block.</summary>
    public static EncryptedPrivateKeyInfo FromPem(string pem, PkcsLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(pem);
        if (!PemCodec.TryParseAll(pem, PemMode.Lax, out IReadOnlyList<PemBlock> blocks, out PemError error))
        {
            throw new PkcsParseException("EncryptedPrivateKeyInfo", PkcsError.Malformed, $"Invalid PEM: {error}.");
        }

        foreach (PemBlock b in blocks)
        {
            if (b.Label == "ENCRYPTED PRIVATE KEY")
            {
                return Parse(b.Data, limits);
            }
        }

        throw PkcsFail.Bad("EncryptedPrivateKeyInfo", "There is no ENCRYPTED PRIVATE KEY block.");
    }

    /// <summary>The key as an <c>ENCRYPTED PRIVATE KEY</c> PEM block.</summary>
    public string ToPem() => PemCodec.Write("ENCRYPTED PRIVATE KEY", _encoded);

    /// <summary>Encrypts <paramref name="key"/> with PBES2.</summary>
    public static EncryptedPrivateKeyInfo Create(PrivateKeyInfo key, ReadOnlySpan<char> password, Pbes2Options? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        byte[] ct = Pbe.EncryptPbes2(key.Encoded, password, options ?? Pbes2Options.Default, out byte[] alg);
        var w = new Asn1Writer();
        w.PushSequence();
        w.WriteEncodedValue(alg);
        w.WriteOctetString(ct);
        w.Pop();
        return Parse(w.Encode());
    }

    /// <summary>Decrypts with <paramref name="password"/> (UTF-8 for PBES2, a BMPString for the PKCS#12 PBEs).</summary>
    /// <param name="password">The password.</param>
    /// <param name="key">The key when the result is <see cref="PkcsStatus.Ok"/>; the caller disposes it. Null otherwise: no partial plaintext is returned.</param>
    public PkcsStatus TryDecrypt(ReadOnlySpan<char> password, out PrivateKeyInfo? key) => TryDecryptWith(password, false, out key);

    internal PkcsStatus TryDecryptWith(ReadOnlySpan<char> password, bool nullPassword, out PrivateKeyInfo? key)
    {
        key = null;
        PkcsStatus st = Pbe.Decrypt(EncryptionAlgorithm, password, nullPassword, _data, _limits, out PinnedSecret? plain);
        if (st != PkcsStatus.Ok)
        {
            return st;
        }

        try
        {
            key = PrivateKeyInfo.Adopt(plain!, _limits);
            return PkcsStatus.Ok;
        }
        catch (PkcsParseException)
        {
            // A wrong password that happens to give valid padding yields garbage, not a PrivateKeyInfo.
            return PkcsStatus.WrongPasswordOrCorrupt;
        }
    }

    /// <summary>Decrypts with <paramref name="password"/>.</summary>
    /// <exception cref="PkcsPasswordException">The password is wrong, the data is damaged, or the algorithm is not supported; see <see cref="PkcsPasswordException.Status"/>.</exception>
    public PrivateKeyInfo Decrypt(ReadOnlySpan<char> password)
    {
        PkcsStatus st = TryDecrypt(password, out PrivateKeyInfo? key);
        return st == PkcsStatus.Ok ? key! : throw new PkcsPasswordException(st);
    }
}

/// <summary>
/// Reads private keys from PEM text in every form OpenSSL writes: <c>PRIVATE KEY</c>, <c>ENCRYPTED PRIVATE KEY</c>, and the legacy
/// <c>RSA PRIVATE KEY</c> and <c>EC PRIVATE KEY</c> blocks, optionally encrypted with the <c>Proc-Type</c>/<c>DEK-Info</c> headers.
/// </summary>
public static class PrivateKeyPem
{
    /// <summary>Reads the first private-key block of <paramref name="pem"/>.</summary>
    /// <param name="pem">PEM text.</param>
    /// <param name="password">The password for an encrypted block; empty for none.</param>
    /// <param name="limits">Limits; null for <see cref="PkcsLimits.Default"/>.</param>
    /// <exception cref="PkcsParseException">There is no private-key block, or it is malformed.</exception>
    /// <exception cref="PkcsPasswordException">The block is encrypted and the password is missing or wrong.</exception>
    public static PrivateKeyInfo Parse(string pem, ReadOnlySpan<char> password, PkcsLimits? limits = null)
    {
        PkcsStatus st = TryParse(pem, password, out PrivateKeyInfo? key, limits);
        return st == PkcsStatus.Ok ? key! : throw new PkcsPasswordException(st);
    }

    /// <summary>Reads the first private-key block; the status says why it failed. Malformed input gives <see cref="PkcsStatus.Malformed"/>.</summary>
    public static PkcsStatus TryParse(string pem, ReadOnlySpan<char> password, out PrivateKeyInfo? key, PkcsLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(pem);
        limits ??= PkcsLimits.Default;
        key = null;
        if (!PemCodec.TryParseAll(pem, PemMode.Lax, out IReadOnlyList<PemBlock> blocks, out _))
        {
            return PkcsStatus.Malformed;
        }

        foreach (PemBlock b in blocks)
        {
            try
            {
                switch (b.Label)
                {
                    case "PRIVATE KEY":
                        key = PrivateKeyInfo.Parse(b.Data, limits);
                        return PkcsStatus.Ok;
                    case "ENCRYPTED PRIVATE KEY":
                        if (password.IsEmpty)
                        {
                            return PkcsStatus.PasswordRequired;
                        }

                        return EncryptedPrivateKeyInfo.Parse(b.Data, limits).TryDecrypt(password, out key);
                    case "RSA PRIVATE KEY" or "EC PRIVATE KEY" or "DSA PRIVATE KEY":
                        return Legacy(b, password, out key, limits);
                }
            }
            catch (PkcsParseException)
            {
                return PkcsStatus.Malformed;
            }
        }

        return PkcsStatus.Malformed;
    }

    private static PkcsStatus Legacy(PemBlock b, ReadOnlySpan<char> password, out PrivateKeyInfo? key, PkcsLimits limits)
    {
        key = null;
        byte[] body = b.Data;
        PinnedSecret? plain = null;
        try
        {
            if (b.IsLegacyEncrypted)
            {
                if (password.IsEmpty)
                {
                    return PkcsStatus.PasswordRequired;
                }

                PkcsStatus st = DecryptLegacy(b, password, out plain);
                if (st != PkcsStatus.Ok)
                {
                    return st;
                }

                body = plain!.ReadOnlySpan.ToArray();
            }

            try
            {
                key = b.Label switch
                {
                    "RSA PRIVATE KEY" => PrivateKeyInfo.FromRsaPrivateKey(body),
                    "DSA PRIVATE KEY" => PrivateKeyInfo.FromDsaPrivateKey(body),
                    _ => PrivateKeyInfo.FromEcPrivateKey(body),
                };
                return PkcsStatus.Ok;
            }
            catch (PkcsParseException)
            {
                return plain is null ? PkcsStatus.Malformed : PkcsStatus.WrongPasswordOrCorrupt;
            }
        }
        finally
        {
            plain?.Dispose();
            if (!ReferenceEquals(body, b.Data))
            {
                CryptographicOperations.ZeroMemory(body);
            }
        }
    }

    /// <summary>
    /// Traditional OpenSSL PEM encryption (RFC 1421 §4.6 headers). The key is derived with EVP_BytesToKey from MD5, the first eight
    /// IV bytes as salt and one iteration, as the <c>EVP_BytesToKey(3)</c> manual page describes. MD5 is used because the format
    /// requires it; this is read-only, and the format has no integrity check beyond the padding and the structure that follows.
    /// </summary>
    private static PkcsStatus DecryptLegacy(PemBlock b, ReadOnlySpan<char> password, out PinnedSecret? plaintext)
    {
        plaintext = null;
        string? dek = b.DekInfo;
        if (dek is null)
        {
            return PkcsStatus.Malformed;
        }

        int comma = dek.IndexOf(',', StringComparison.Ordinal);
        if (comma < 0)
        {
            return PkcsStatus.Malformed;
        }

        string cipher = dek[..comma].Trim().ToUpperInvariant();
        byte[] iv;
        try
        {
            iv = Convert.FromHexString(dek[(comma + 1)..].Trim());
        }
        catch (FormatException)
        {
            return PkcsStatus.Malformed;
        }

        (int keyLen, int block, int kind) = cipher switch
        {
            "AES-128-CBC" => (16, 16, 0),
            "AES-192-CBC" => (24, 16, 0),
            "AES-256-CBC" => (32, 16, 0),
            "DES-EDE3-CBC" => (24, 8, 1),
            _ => (0, 0, 0),
        };
        if (keyLen == 0)
        {
            return PkcsStatus.UnsupportedAlgorithm;
        }

        if (iv.Length != block || b.Data.Length == 0 || b.Data.Length % block != 0)
        {
            return PkcsStatus.Malformed;
        }

        using PinnedSecret pw = Pbe.Utf8(password);
        using var key = new PinnedSecret(keyLen);
        using var d = new PinnedSecret(16 * ((keyLen + 15) / 16));
        byte[] prev = [];
        for (int off = 0; off < d.Length; off += 16)
        {
            byte[] input = new byte[prev.Length + pw.Length + 8];
            prev.CopyTo(input, 0);
            pw.ReadOnlySpan.CopyTo(input.AsSpan(prev.Length));
            iv.AsSpan(0, 8).CopyTo(input.AsSpan(prev.Length + pw.Length));
            prev = LegacyCrypto.Md5(input);
            CryptographicOperations.ZeroMemory(input);
            prev.CopyTo(d.Span[off..]);
        }

        d.ReadOnlySpan[..keyLen].CopyTo(key.Span);
        var buf = new PinnedSecret(b.Data.Length);
        try
        {
            if (kind == 0)
            {
                using Aes a = Aes.Create();
                a.SetKey(key.ReadOnlySpan);
                a.DecryptCbc(b.Data, iv, buf.Span, PaddingMode.None);
            }
            else
            {
                LegacyCrypto.TripleDesCbcDecrypt(key.ReadOnlySpan, iv, b.Data, buf.Span);
            }

            int pad = buf.ReadOnlySpan[^1];
            int bad = (pad == 0 ? 1 : 0) | (pad > block ? 1 : 0);
            for (int i = 1; i <= Math.Min(pad, block); i++)
            {
                bad |= buf.ReadOnlySpan[^i] ^ pad;
            }

            if (bad != 0)
            {
                return PkcsStatus.WrongPasswordOrCorrupt;
            }

            plaintext = new PinnedSecret(buf.ReadOnlySpan[..^pad]);
            return PkcsStatus.Ok;
        }
        finally
        {
            buf.Dispose();
        }
    }
}
