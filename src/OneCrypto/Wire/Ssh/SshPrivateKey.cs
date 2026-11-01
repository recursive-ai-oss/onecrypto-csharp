using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.Pkcs;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.Wire.Ssh;

/// <summary>The cipher that protects an OpenSSH private key file.</summary>
public enum SshKeyCipher
{
    /// <summary>No encryption.</summary>
    None,

    /// <summary><c>aes256-ctr</c>, the <c>ssh-keygen</c> default.</summary>
    Aes256Ctr,

    /// <summary><c>aes192-ctr</c>.</summary>
    Aes192Ctr,

    /// <summary><c>aes128-ctr</c>.</summary>
    Aes128Ctr,

    /// <summary><c>aes256-gcm@openssh.com</c>.</summary>
    Aes256Gcm,

    /// <summary><c>aes128-gcm@openssh.com</c>.</summary>
    Aes128Gcm,
}

/// <summary>How to write an OpenSSH private key. The defaults are those of <c>ssh-keygen</c>: <c>aes256-ctr</c> and 16 bcrypt rounds.</summary>
public sealed class SshKeyWriteOptions
{
    /// <summary>The defaults.</summary>
    public static SshKeyWriteOptions Default { get; } = new();

    /// <summary>The cipher used when a passphrase is given. Default <see cref="SshKeyCipher.Aes256Ctr"/>.</summary>
    public SshKeyCipher Cipher { get; init; } = SshKeyCipher.Aes256Ctr;

    /// <summary>The bcrypt-pbkdf round count. Default 16, as <c>ssh-keygen</c> writes; a larger value costs more to guess and to open.</summary>
    public int Rounds { get; init; } = 16;
}

/// <summary>The decrypted content of an OpenSSH private key file. Dispose it to zero the key.</summary>
public sealed class SshPrivateKeyContents : IDisposable
{
    internal SshPrivateKeyContents(SshPublicKey publicKey, string comment, PrivateKeyInfo? key, byte[] keyHandle, byte flags)
    {
        PublicKey = publicKey;
        Comment = comment;
        PrivateKey = key;
        KeyHandle = keyHandle;
        Flags = flags;
    }

    /// <summary>The public key.</summary>
    public SshPublicKey PublicKey { get; }

    /// <summary>The comment stored inside the encrypted section.</summary>
    public string Comment { get; }

    /// <summary>
    /// The private key as PKCS#8 (RSA, ECDSA P-256/384/521 and Ed25519). Null for FIDO (<c>sk-</c>) keys, whose secret stays on the
    /// authenticator.
    /// </summary>
    public PrivateKeyInfo? PrivateKey { get; }

    /// <summary>For FIDO keys, the key handle the authenticator needs; otherwise empty.</summary>
    public ReadOnlyMemory<byte> KeyHandle { get; }

    /// <summary>For FIDO keys, the flags octet (user presence, user verification); otherwise 0.</summary>
    public byte Flags { get; }

    /// <summary>Zeroes the key.</summary>
    public void Dispose() => PrivateKey?.Dispose();
}

/// <summary>
/// An OpenSSH private key file (<c>openssh-key-v1</c>, PROTOCOL.key): the public key in the clear and the private fields either plain
/// or encrypted with a key derived by bcrypt-pbkdf. Reads RSA, ECDSA P-256/384/521, Ed25519 and FIDO keys; the ciphers
/// <c>none</c>, <c>aes{128,192,256}-ctr</c>, <c>aes{128,192,256}-cbc</c> and <c>aes{128,256}-gcm@openssh.com</c>. The file's bytes are kept as received.
/// </summary>
/// <remarks><c>chacha20-poly1305@openssh.com</c> and <c>3des-cbc</c> files parse, and opening them gives <see cref="PkcsStatus.UnsupportedAlgorithm"/>.</remarks>
public sealed class SshPrivateKey
{
    private const string Magic = "openssh-key-v1\0";
    private const string Label = "OPENSSH PRIVATE KEY";
    private const int MaxSize = 1 << 20;

    private readonly byte[] _encoded;
    private readonly byte[] _kdfOptions;
    private readonly byte[] _encrypted;
    private readonly byte[] _tag;

    private SshPrivateKey(byte[] encoded, string cipher, string kdf, byte[] kdfOptions, SshPublicKey publicKey, byte[] encrypted, byte[] tag)
    {
        _encoded = encoded;
        CipherName = cipher;
        KdfName = kdf;
        _kdfOptions = kdfOptions;
        PublicKey = publicKey;
        _encrypted = encrypted;
        _tag = tag;
    }

    /// <summary>The cipher name, <c>none</c> for an unencrypted key.</summary>
    public string CipherName { get; }

    /// <summary>The key-derivation function name, <c>none</c> or <c>bcrypt</c>.</summary>
    public string KdfName { get; }

    /// <summary>True when a passphrase is needed.</summary>
    public bool IsEncrypted => CipherName != "none";

    /// <summary>The public key stored in the clear.</summary>
    public SshPublicKey PublicKey { get; }

    /// <summary>The file as received (the binary form, not the PEM text).</summary>
    public ReadOnlyMemory<byte> Encoded => _encoded;

    private readonly record struct CipherInfo(int KeyLength, int IvLength, int BlockSize, int Kind, int TagLength);

    private static bool TryCipher(string name, out CipherInfo info)
    {
        // Kind: 0 none, 1 CTR, 2 CBC, 3 GCM.
        info = name switch
        {
            "none" => new CipherInfo(0, 0, 8, 0, 0),
            "aes128-ctr" => new CipherInfo(16, 16, 16, 1, 0),
            "aes192-ctr" => new CipherInfo(24, 16, 16, 1, 0),
            "aes256-ctr" => new CipherInfo(32, 16, 16, 1, 0),
            "aes128-cbc" => new CipherInfo(16, 16, 16, 2, 0),
            "aes192-cbc" => new CipherInfo(24, 16, 16, 2, 0),
            "aes256-cbc" => new CipherInfo(32, 16, 16, 2, 0),
            "aes128-gcm@openssh.com" => new CipherInfo(16, 12, 16, 3, 16),
            "aes256-gcm@openssh.com" => new CipherInfo(32, 12, 16, 3, 16),
            _ => default,
        };
        return info.BlockSize != 0;
    }

    // ---- parse ----

    /// <summary>Reads the binary <c>openssh-key-v1</c> structure.</summary>
    /// <exception cref="SshParseException">The data is malformed or holds more than one key.</exception>
    public static SshPrivateKey Parse(ReadOnlySpan<byte> data)
    {
        const string what = "OpenSSH private key";
        if (data.Length > MaxSize)
        {
            throw new SshParseException(what, SshError.LimitExceeded, "the file is larger than 1 MiB");
        }

        var r = new SshReader(data, what);
        ReadOnlySpan<byte> magic = "openssh-key-v1\0"u8;
        if (data.Length < magic.Length || !data[..magic.Length].SequenceEqual(magic))
        {
            throw new SshParseException(what, SshError.InvalidValue, "missing the openssh-key-v1 magic");
        }

        for (int i = 0; i < magic.Length; i++)
        {
            r.ReadByte();
        }

        string cipher = r.ReadAscii();
        string kdf = r.ReadAscii();
        byte[] kdfOptions = r.ReadString().ToArray();
        uint nkeys = r.ReadUInt32();
        if (nkeys != 1)
        {
            throw new SshParseException(what, SshError.Unsupported, "only files with exactly one key are read");
        }

        SshPublicKey pub = SshPublicKey.Parse(r.ReadString());
        byte[] encrypted = r.ReadString().ToArray();
        int tagLen = TryCipher(cipher, out CipherInfo ci) ? ci.TagLength : (cipher == "chacha20-poly1305@openssh.com" ? 16 : 0);
        byte[] tag = [];
        if (tagLen > 0)
        {
            if (r.Remaining.Length != tagLen)
            {
                throw new SshParseException(what, SshError.InvalidValue, "the authentication tag is missing or the file has trailing data");
            }

            tag = r.Remaining.ToArray();
        }
        else
        {
            r.ThrowIfNotEmpty();
        }

        if (kdf is not ("none" or "bcrypt"))
        {
            throw new SshParseException(what, SshError.Unsupported, $"key-derivation function {kdf} is not supported");
        }

        if ((cipher == "none") != (kdf == "none"))
        {
            throw new SshParseException(what, SshError.InvalidValue, "the cipher and the key-derivation function disagree about encryption");
        }

        return new SshPrivateKey(data.ToArray(), cipher, kdf, kdfOptions, pub, encrypted, tag);
    }

    /// <summary>Reads the binary structure, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out SshPrivateKey? key)
    {
        try
        {
            key = Parse(data);
            return true;
        }
        catch (SshParseException)
        {
            key = null;
            return false;
        }
    }

    /// <summary>Reads an <c>OPENSSH PRIVATE KEY</c> PEM block.</summary>
    /// <exception cref="SshParseException">There is no such block or it is malformed.</exception>
    public static SshPrivateKey FromPem(string pem)
    {
        ArgumentNullException.ThrowIfNull(pem);
        if (!PemCodec.TryParseAll(pem, PemMode.Lax, out IReadOnlyList<PemBlock> blocks, out _))
        {
            throw new SshParseException("OpenSSH private key", SshError.InvalidValue, "the PEM text is malformed");
        }

        foreach (PemBlock b in blocks)
        {
            if (b.Label == Label)
            {
                return Parse(b.Data);
            }
        }

        throw new SshParseException("OpenSSH private key", SshError.InvalidValue, $"there is no {Label} block");
    }

    /// <summary>The key as an <c>OPENSSH PRIVATE KEY</c> PEM block.</summary>
    public string ToPem() => PemCodec.Write(Label, _encoded);

    // ---- open ----

    /// <summary>
    /// Decrypts the private section and reads the key. A wrong passphrase and a damaged file both give
    /// <see cref="PkcsStatus.WrongPasswordOrCorrupt"/> (the two check integers differ, or the GCM tag fails) and release nothing.
    /// </summary>
    /// <param name="passphrase">The passphrase (UTF-8); ignored for an unencrypted key.</param>
    /// <param name="contents">The key when the status is <see cref="PkcsStatus.Ok"/>; the caller disposes it.</param>
    /// <param name="limits">Limits for the bcrypt round count; null for <see cref="KdfLimits.Default"/>.</param>
    public PkcsStatus TryOpen(ReadOnlySpan<char> passphrase, out SshPrivateKeyContents? contents, KdfLimits? limits = null)
    {
        contents = null;
        PinnedSecret? plain = null;
        try
        {
            if (!TryCipher(CipherName, out CipherInfo ci))
            {
                return PkcsStatus.UnsupportedAlgorithm;
            }

            if (_encrypted.Length % ci.BlockSize != 0 || _encrypted.Length == 0)
            {
                return PkcsStatus.Malformed;
            }

            if (ci.Kind == 0)
            {
                plain = new PinnedSecret(_encrypted);
            }
            else
            {
                if (passphrase.IsEmpty)
                {
                    return PkcsStatus.PasswordRequired;
                }

                var kr = new SshReader(_kdfOptions, "OpenSSH kdf options");
                ReadOnlySpan<byte> salt = kr.ReadString();
                uint rounds = kr.ReadUInt32();
                kr.ThrowIfNotEmpty();
                if (rounds == 0 || salt.Length == 0 || salt.Length > 1024)
                {
                    return PkcsStatus.Malformed;
                }

                using PinnedSecret pw = Pbe.Utf8(passphrase);
                using var km = new PinnedSecret(ci.KeyLength + ci.IvLength);
                if (rounds > int.MaxValue)
                {
                    return PkcsStatus.LimitExceeded;
                }

                BcryptPbkdf.DeriveKey(pw.ReadOnlySpan, salt, (int)rounds, km.Span, limits);
                plain = new PinnedSecret(_encrypted.Length);
                ReadOnlySpan<byte> key = km.ReadOnlySpan[..ci.KeyLength];
                ReadOnlySpan<byte> iv = km.ReadOnlySpan[ci.KeyLength..];
                switch (ci.Kind)
                {
                    case 1:
                        Ctr(key, iv, _encrypted, plain.Span);
                        break;
                    case 2:
                        using (Aes a = Platform.CreateAes())
                        {
                            a.SetKey(key);
                            a.DecryptCbc(_encrypted, iv, plain.Span, PaddingMode.None);
                        }

                        break;
                    default:
                        try
                        {
                            Platform.RequireAesGcm();
                            using var g = new AesGcm(key, 16);
                            g.Decrypt(iv, _encrypted, _tag, plain.Span);
                        }
                        catch (CryptographicException)
                        {
                            return PkcsStatus.WrongPasswordOrCorrupt;
                        }

                        break;
                }
            }

            return ReadPrivateSection(plain.ReadOnlySpan, ci.Kind != 0, out contents);
        }
        catch (KdfLimitExceededException)
        {
            return PkcsStatus.LimitExceeded;
        }
        catch (SshParseException)
        {
            return PkcsStatus.Malformed;
        }
        finally
        {
            plain?.Dispose();
        }
    }

    /// <summary>Opens the key; see <see cref="TryOpen"/>.</summary>
    /// <exception cref="PkcsPasswordException">The passphrase is wrong or missing, the file is damaged, or its cipher is not supported.</exception>
    public SshPrivateKeyContents Open(ReadOnlySpan<char> passphrase, KdfLimits? limits = null)
    {
        PkcsStatus st = TryOpen(passphrase, out SshPrivateKeyContents? c, limits);
        return st == PkcsStatus.Ok ? c! : throw new PkcsPasswordException(st);
    }

    /// <summary>AES in counter mode as SSH uses it (RFC 4344 §4): a 128-bit big-endian counter starting at the IV. Built on the platform's AES block function.</summary>
    private static void Ctr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Platform.CreateAes();
        aes.SetKey(key);
        Span<byte> counter = stackalloc byte[16]; // fixed size, 16 bytes
        Span<byte> ks = stackalloc byte[16]; // fixed size, 16 bytes
        iv.CopyTo(counter);
        for (int off = 0; off < input.Length; off += 16)
        {
            aes.EncryptEcb(counter, ks, PaddingMode.None);
            int n = Math.Min(16, input.Length - off);
            for (int i = 0; i < n; i++)
            {
                output[off + i] = (byte)(input[off + i] ^ ks[i]);
            }

            for (int i = 15; i >= 0; i--)
            {
                if (++counter[i] != 0)
                {
                    break;
                }
            }
        }

        CryptographicOperations.ZeroMemory(ks);
    }

    private PkcsStatus ReadPrivateSection(ReadOnlySpan<byte> section, bool wasEncrypted, out SshPrivateKeyContents? contents)
    {
        contents = null;
        var r = new SshReader(section, "OpenSSH private section");
        uint c1 = r.ReadUInt32();
        uint c2 = r.ReadUInt32();
        if (c1 != c2)
        {
            // The check integers are the format's only integrity test for CTR and CBC: a wrong passphrase decrypts to noise.
            return wasEncrypted ? PkcsStatus.WrongPasswordOrCorrupt : PkcsStatus.Malformed;
        }

        string type = r.ReadAscii();
        PrivateKeyInfo? pk = null;
        byte[] handle = [];
        byte flags = 0;
        try
        {
            SshPublicKey declared = PublicKey;
            if (type != declared.TypeName)
            {
                return PkcsStatus.Malformed;
            }

            switch (declared.Type)
            {
                case SshKeyType.Rsa:
                {
                    ReadOnlySpan<byte> n = r.ReadMpint();
                    ReadOnlySpan<byte> e = r.ReadMpint();
                    ReadOnlySpan<byte> d = r.ReadMpint();
                    ReadOnlySpan<byte> iqmp = r.ReadMpint();
                    ReadOnlySpan<byte> p = r.ReadMpint();
                    ReadOnlySpan<byte> q = r.ReadMpint();
                    if (!n.SequenceEqual(declared.RsaModulus.Span) || !e.SequenceEqual(declared.RsaExponent.Span))
                    {
                        return PkcsStatus.Malformed;
                    }

                    pk = RsaToPkcs8(n, e, d, iqmp, p, q);
                    break;
                }

                case SshKeyType.EcdsaP256 or SshKeyType.EcdsaP384 or SshKeyType.EcdsaP521:
                {
                    string curve = r.ReadAscii();
                    ReadOnlySpan<byte> point = r.ReadString();
                    ReadOnlySpan<byte> d = r.ReadMpint();
                    if (curve != declared.CurveName || !point.SequenceEqual(declared.EcPoint.Span))
                    {
                        return PkcsStatus.Malformed;
                    }

                    pk = EcToPkcs8(declared.Type, point, d);
                    break;
                }

                case SshKeyType.Ed25519:
                {
                    ReadOnlySpan<byte> pub = r.ReadString();
                    ReadOnlySpan<byte> sk = r.ReadString();
                    if (sk.Length != 64 || !pub.SequenceEqual(declared.Ed25519Key.Span) || !sk[32..].SequenceEqual(pub))
                    {
                        return PkcsStatus.Malformed;
                    }

                    using Ed25519PrivateKey key = Ed25519PrivateKey.FromSeed(sk[..32]);
                    pk = PrivateKeyInfo.FromEd25519(key);
                    Span<byte> derived = stackalloc byte[32]; // fixed size, 32 bytes
                    key.PublicKey.Export(derived);
                    if (!derived.SequenceEqual(pub))
                    {
                        return PkcsStatus.Malformed;
                    }

                    break;
                }

                case SshKeyType.SkEd25519:
                    r.ReadString();
                    r.ReadString();
                    flags = r.ReadByte();
                    handle = r.ReadString().ToArray();
                    r.ReadString();
                    break;
                case SshKeyType.SkEcdsaP256:
                    r.ReadString();
                    r.ReadString();
                    r.ReadString();
                    flags = r.ReadByte();
                    handle = r.ReadString().ToArray();
                    r.ReadString();
                    break;
                default:
                    return PkcsStatus.UnsupportedAlgorithm;
            }

            string comment = System.Text.Encoding.UTF8.GetString(r.ReadString());

            // PROTOCOL.key: the section is padded with 1, 2, 3, ... to the cipher block size.
            ReadOnlySpan<byte> pad = r.Remaining;
            if (pad.Length >= 256)
            {
                return PkcsStatus.Malformed;
            }

            for (int i = 0; i < pad.Length; i++)
            {
                if (pad[i] != i + 1)
                {
                    return PkcsStatus.Malformed;
                }
            }

            contents = new SshPrivateKeyContents(declared, comment, pk, handle, flags);
            pk = null;
            return PkcsStatus.Ok;
        }
        catch (CryptographicException)
        {
            return PkcsStatus.Malformed;
        }
        finally
        {
            pk?.Dispose();
        }
    }

    private static PrivateKeyInfo RsaToPkcs8(ReadOnlySpan<byte> n, ReadOnlySpan<byte> e, ReadOnlySpan<byte> d, ReadOnlySpan<byte> iqmp, ReadOnlySpan<byte> p, ReadOnlySpan<byte> q)
    {
        int half = (n.Length + 1) / 2;
        if (p.IsEmpty || q.IsEmpty || (p[^1] & 1) == 0 || (q[^1] & 1) == 0)
        {
            throw new CryptographicException("RSA primes must be odd.");
        }

        // The file omits d mod (p-1) and d mod (q-1). p and q are odd, so p-1 is p with its lowest bit cleared.
        byte[] pm1 = p.ToArray();
        pm1[^1] &= 0xFE;
        byte[] qm1 = q.ToArray();
        qm1[^1] &= 0xFE;
        byte[] dp = new byte[pm1.Length];
        byte[] dq = new byte[qm1.Length];
        var prm = new RSAParameters
        {
            Modulus = n.ToArray(),
            Exponent = e.ToArray(),
            D = SecretMod.Fixed(d, n.Length),
            P = SecretMod.Fixed(p, half),
            Q = SecretMod.Fixed(q, half),
            InverseQ = SecretMod.Fixed(iqmp, half),
        };
        try
        {
            SecretMod.Reduce(d, pm1, dp);
            SecretMod.Reduce(d, qm1, dq);
            prm.DP = SecretMod.Fixed(dp, half);
            prm.DQ = SecretMod.Fixed(dq, half);
            using RSA rsa = Platform.CreateRsa("RSA private key");
            rsa.ImportParameters(prm);
            byte[] pkcs8 = rsa.ExportPkcs8PrivateKey();
            try
            {
                return PrivateKeyInfo.Parse(pkcs8);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }
        }
        finally
        {
            foreach (byte[]? x in new[] { pm1, qm1, dp, dq, prm.D, prm.P, prm.Q, prm.InverseQ, prm.DP, prm.DQ })
            {
                if (x is not null)
                {
                    CryptographicOperations.ZeroMemory(x);
                }
            }
        }
    }

    private static PrivateKeyInfo EcToPkcs8(SshKeyType type, ReadOnlySpan<byte> point, ReadOnlySpan<byte> d)
    {
        (ECCurve curve, int size) = type switch
        {
            SshKeyType.EcdsaP256 => (ECCurve.NamedCurves.nistP256, 32),
            SshKeyType.EcdsaP384 => (ECCurve.NamedCurves.nistP384, 48),
            _ => (ECCurve.NamedCurves.nistP521, 66),
        };
        byte[] dd = SecretMod.Fixed(d, size);
        try
        {
            var prm = new ECParameters { Curve = curve, D = dd, Q = new ECPoint { X = point[1..(1 + size)].ToArray(), Y = point[(1 + size)..].ToArray() } };
            using ECDsa ec = Platform.CreateEcdsa(prm, "EC private key import");
            byte[] pkcs8 = ec.ExportPkcs8PrivateKey();
            try
            {
                return PrivateKeyInfo.Parse(pkcs8);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dd);
        }
    }

    // ---- write ----

    /// <summary>Builds an OpenSSH private key file from a PKCS#8 key (RSA, ECDSA P-256/384/521 or Ed25519).</summary>
    /// <param name="key">The key.</param>
    /// <param name="comment">The comment stored in the private section (ssh-keygen shows it).</param>
    /// <param name="passphrase">The passphrase; empty writes an unencrypted file.</param>
    /// <param name="options">Cipher and rounds; null for <see cref="SshKeyWriteOptions.Default"/>.</param>
    /// <exception cref="NotSupportedException">The key type has no OpenSSH form.</exception>
    public static SshPrivateKey Create(PrivateKeyInfo key, string comment, ReadOnlySpan<char> passphrase, SshKeyWriteOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(comment);
        options ??= SshKeyWriteOptions.Default;
        string cipherName = passphrase.IsEmpty ? "none" : options.Cipher switch
        {
            SshKeyCipher.Aes256Ctr => "aes256-ctr",
            SshKeyCipher.Aes192Ctr => "aes192-ctr",
            SshKeyCipher.Aes128Ctr => "aes128-ctr",
            SshKeyCipher.Aes256Gcm => "aes256-gcm@openssh.com",
            SshKeyCipher.Aes128Gcm => "aes128-gcm@openssh.com",
            _ => "aes256-ctr",
        };
        TryCipher(cipherName, out CipherInfo ci);
        SshPublicKey pub = SshPublicKey.FromPublicKeyInfo(key.GetPublicKey());

        using var s = new SshWriter();
        uint check = BinaryPrimitivesRandom();
        s.WriteUInt32(check);
        s.WriteUInt32(check);
        s.WriteString(pub.TypeName);
        switch (key.KeyAlgorithm)
        {
            case KeyAlgorithm.Rsa:
                using (RSA rsa = key.ToRsa())
                {
                    RSAParameters p = rsa.ExportParameters(true);
                    try
                    {
                        s.WriteMpint(p.Modulus);
                        s.WriteMpint(p.Exponent);
                        s.WriteMpint(p.D);
                        s.WriteMpint(p.InverseQ);
                        s.WriteMpint(p.P);
                        s.WriteMpint(p.Q);
                    }
                    finally
                    {
                        foreach (byte[]? x in new[] { p.D, p.P, p.Q, p.DP, p.DQ, p.InverseQ })
                        {
                            if (x is not null)
                            {
                                CryptographicOperations.ZeroMemory(x);
                            }
                        }
                    }
                }

                break;
            case KeyAlgorithm.EllipticCurve:
                using (ECDsa ec = key.ToECDsa())
                {
                    ECParameters p = ec.ExportParameters(true);
                    try
                    {
                        s.WriteString(pub.CurveName!);
                        s.WriteString(pub.EcPoint.Span);
                        s.WriteMpint(p.D);
                    }
                    finally
                    {
                        if (p.D is not null)
                        {
                            CryptographicOperations.ZeroMemory(p.D);
                        }
                    }
                }

                break;
            case KeyAlgorithm.Ed25519:
                using (Ed25519PrivateKey k = key.ToEd25519())
                {
                    Span<byte> sk = stackalloc byte[64]; // fixed size, 64 bytes
                    k.ExportSeed(sk[..32]);
                    k.PublicKey.Export(sk[32..]);
                    s.WriteString(pub.Ed25519Key.Span);
                    s.WriteString(sk);
                    CryptographicOperations.ZeroMemory(sk);
                }

                break;
            default:
                throw new NotSupportedException($"{key.Algorithm.Name} keys have no OpenSSH private-key form.");
        }

        s.WriteString(System.Text.Encoding.UTF8.GetBytes(comment));
        for (byte i = 1; s.Written.Length % ci.BlockSize != 0; i++)
        {
            s.WriteByte(i);
        }

        byte[] kdfOptions = [];
        byte[] encrypted;
        byte[] tag = [];
        if (ci.Kind == 0)
        {
            encrypted = s.ToArray();
        }
        else
        {
            if (options.Rounds < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(options), "Rounds must be positive.");
            }

            byte[] salt = RandomNumberGenerator.GetBytes(16);
            using var ko = new SshWriter();
            ko.WriteString(salt);
            ko.WriteUInt32((uint)options.Rounds);
            kdfOptions = ko.ToArray();
            using PinnedSecret pw = Pbe.Utf8(passphrase);
            using var km = new PinnedSecret(ci.KeyLength + ci.IvLength);
            BcryptPbkdf.DeriveKey(pw.ReadOnlySpan, salt, options.Rounds, km.Span, new KdfLimits { MaxBcryptRounds = Math.Max(options.Rounds, KdfLimits.Default.MaxBcryptRounds) });
            encrypted = new byte[s.Written.Length];
            ReadOnlySpan<byte> kk = km.ReadOnlySpan[..ci.KeyLength];
            ReadOnlySpan<byte> iv = km.ReadOnlySpan[ci.KeyLength..];
            if (ci.Kind == 1)
            {
                Ctr(kk, iv, s.Written, encrypted);
            }
            else
            {
                tag = new byte[16];
                Platform.RequireAesGcm();
                using var g = new AesGcm(kk, 16);
                g.Encrypt(iv, s.Written, encrypted, tag);
            }
        }

        using var w = new SshWriter();
        w.WriteRaw("openssh-key-v1\0"u8);
        w.WriteString(cipherName);
        w.WriteString(ci.Kind == 0 ? "none" : "bcrypt");
        w.WriteString(kdfOptions);
        w.WriteUInt32(1);
        w.WriteString(pub.Blob.Span);
        w.WriteString(encrypted);
        w.WriteRaw(tag);
        return Parse(w.Written);
    }

    private static uint BinaryPrimitivesRandom() => System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(RandomNumberGenerator.GetBytes(4));
}
