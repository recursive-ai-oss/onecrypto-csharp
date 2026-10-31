using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.Pkcs;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Wire.Ssh;

namespace OneCrypto.Fuzz;

/// <summary>
/// PKCS#8, encrypted PKCS#8 and legacy PEM private keys. The first byte picks the structure. Costs from the input are capped low so a
/// hostile iteration count cannot stall the run; the limit checks themselves are what is being exercised. Only
/// <see cref="PkcsParseException"/> may come out.
/// </summary>
internal static class Pkcs8Target
{
    private static readonly PkcsLimits Tight = new() { MaxIterations = 300, Kdf = new KdfLimits { MaxScryptWork = 1 << 12, MaxMemoryBytes = 1 << 22 } };

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        try
        {
            switch (data[0] % 3)
            {
                case 0:
                    if (PrivateKeyInfo.TryParse(rest, out PrivateKeyInfo? k, Tight) && k is not null)
                    {
                        using (k)
                        {
                            _ = k.Algorithm.Oid + k.Version + k.PrivateKey.Length + k.PublicKeyBits.Length + k.Attributes.Count + k.CurveOid;
                            Convert(k);
                        }
                    }

                    break;
                case 1:
                    if (EncryptedPrivateKeyInfo.TryParse(rest, out EncryptedPrivateKeyInfo? e, Tight) && e is not null)
                    {
                        _ = e.TryDecrypt("fuzz", out PrivateKeyInfo? key);
                        key?.Dispose();
                    }

                    break;
                default:
                    _ = PrivateKeyPem.TryParse(Encoding.UTF8.GetString(rest), "fuzz", out PrivateKeyInfo? p, Tight);
                    p?.Dispose();
                    break;
            }
        }
        catch (PkcsParseException)
        {
        }
    }

    private static void Convert(PrivateKeyInfo k)
    {
        try
        {
            switch (k.KeyAlgorithm)
            {
                case KeyAlgorithm.Ed25519:
                    k.ToEd25519().Dispose();
                    break;
                case KeyAlgorithm.Ed448:
                    k.ToEd448().Dispose();
                    break;
                case KeyAlgorithm.X25519:
                    k.ToX25519().Dispose();
                    break;
                case KeyAlgorithm.X448:
                    k.ToX448().Dispose();
                    break;
                case KeyAlgorithm.EllipticCurve:
                    k.ToECDsa().Dispose();
                    break;
                case KeyAlgorithm.Rsa:
                    k.ToRsa().Dispose();
                    break;
            }
        }
        catch (PlatformNotSupportedException)
        {
            // An unknown or unavailable curve is the platform's typed answer.
        }
        catch (CryptographicException)
        {
            // The platform may refuse a structurally valid but cryptographically invalid key; that is a typed platform error.
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        using Ed25519PrivateKey ed = Ed25519PrivateKey.FromSeed(new byte[32]);
        using PrivateKeyInfo plain = PrivateKeyInfo.FromEd25519(ed, includePublicKey: true);
        yield return [0, .. plain.Encoded];
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using PrivateKeyInfo ep = PrivateKeyInfo.FromAsymmetricAlgorithm(ec);
        yield return [0, .. ep.Encoded];
        var o = new Pbes2Options { Iterations = 100, ScryptCost = 256 };
        yield return [1, .. plain.Encrypt("fuzz", o).Encoded.Span];
        yield return [1, .. plain.Encrypt("fuzz", new Pbes2Options { Cipher = Pbes2Cipher.Aes128Gcm, Iterations = 100 }).Encoded.Span];
        yield return [1, .. plain.Encrypt("fuzz", new Pbes2Options { Kdf = Pbes2Kdf.Scrypt, ScryptCost = 256 }).Encoded.Span];
        yield return [2, .. Encoding.ASCII.GetBytes(plain.ToPem())];
        yield return [2, .. Encoding.ASCII.GetBytes("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nAAECAwQFBgcICQoLDA0ODw==\n-----END RSA PRIVATE KEY-----\n")];
    }
}

/// <summary>PKCS#12 files: structure, MAC check, decryption and bag reading with a low cost cap. Only <see cref="PkcsParseException"/> may come out.</summary>
internal static class Pkcs12Target
{
    private static readonly PkcsLimits Tight = new() { MaxIterations = 300, MaxBags = 64, Kdf = new KdfLimits { MaxScryptWork = 1 << 12, MaxMemoryBytes = 1 << 22 } };

    public static void Run(ReadOnlySpan<byte> data)
    {
        try
        {
            if (!Pkcs12File.TryParse(data, out Pkcs12File? f, Tight) || f is null)
            {
                return;
            }

            _ = f.MacKind + f.SafeCount + f.VerifyMac("fuzz").ToString();
            foreach (bool requireMac in new[] { true, false })
            {
                if (f.TryOpen("fuzz", out Pkcs12Contents? c, requireMac) == PkcsStatus.Ok && c is not null)
                {
                    using (c)
                    {
                        foreach (Pkcs12Bag b in c.AllBags())
                        {
                            _ = b.FriendlyName + b.LocalKeyId.Length + b.Attributes.Count + b.Kind + b.Value.Length + b.SecretValue.Length;
                        }

                        _ = c.Certificates.Count + c.PrivateKeys.Count;
                    }
                }
            }
        }
        catch (PkcsParseException)
        {
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using PrivateKeyInfo key = PrivateKeyInfo.FromAsymmetricAlgorithm(ec);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=fuzz", ec, HashAlgorithmName.SHA256);
        using var bcl = req.CreateSelfSigned(DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(30));
        Certificate cert = Certificate.FromX509Certificate2(bcl);
        var fast = new Pbes2Options { Iterations = 100 };
        yield return Pkcs12File.Create(key, cert, null, "fuzz", "n", new Pkcs12WriteOptions { Encryption = fast, MacIterations = 100 }).Encoded.ToArray();
        yield return Pkcs12File.Create(key, cert, null, "fuzz", null, new Pkcs12WriteOptions { Encryption = fast, MacIterations = 100, Mac = Pkcs12MacKind.Pbmac1 }).Encoded.ToArray();
        yield return Pkcs12File.Create(key, cert, null, "fuzz", null, new Pkcs12WriteOptions { Encryption = fast, EncryptCertificates = false, Mac = Pkcs12MacKind.None }).Encoded.ToArray();
        yield return bcl.ExportPkcs12(System.Security.Cryptography.X509Certificates.Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, "fuzz");
    }
}

/// <summary>
/// OpenSSH public keys (blob, authorized_keys line, RFC 4716 text), certificates (with signature check) and private key files (with
/// a bcrypt round cap). Only <see cref="SshParseException"/> may come out.
/// </summary>
internal static class SshTarget
{
    private static readonly KdfLimits Tight = new() { MaxBcryptRounds = 2 };

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        try
        {
            switch (data[0] % 5)
            {
                case 0:
                    if (SshPublicKey.TryParse(rest, out SshPublicKey? k) && k is not null)
                    {
                        _ = k.ToAuthorizedKey() + k.ToRfc4716() + k.Fingerprint + k.KeySizeBits;
                        try
                        {
                            _ = k.ToPublicKeyInfo();
                        }
                        catch (NotSupportedException)
                        {
                        }
                        catch (CryptographicException)
                        {
                        }
                    }

                    break;
                case 1:
                    _ = SshPublicKey.TryParseAuthorizedKey(Encoding.UTF8.GetString(rest), out _);
                    break;
                case 2:
                    _ = SshPublicKey.ParseRfc4716(Encoding.UTF8.GetString(rest));
                    break;
                case 3:
                    if (SshCertificate.TryParse(rest, out SshCertificate? c) && c is not null)
                    {
                        _ = c.VerifySignature() + c.Fingerprint + c.ValidAfter.ToString() + c.ValidBefore + c.IsValidAt(DateTimeOffset.UnixEpoch).ToString();
                    }

                    break;
                default:
                    if (SshPrivateKey.TryParse(rest, out SshPrivateKey? p) && p is not null)
                    {
                        _ = p.TryOpen("fuzz", out SshPrivateKeyContents? contents, Tight);
                        contents?.Dispose();
                        _ = p.TryOpen(string.Empty, out contents, Tight);
                        contents?.Dispose();
                    }

                    break;
            }
        }
        catch (SshParseException)
        {
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        using Ed25519PrivateKey ed = Ed25519PrivateKey.FromSeed(new byte[32]);
        using PrivateKeyInfo pk = PrivateKeyInfo.FromEd25519(ed);
        SshPublicKey pub = SshPublicKey.FromPublicKeyInfo(pk.GetPublicKey());
        yield return [0, .. pub.Blob.Span];
        yield return [1, .. Encoding.ASCII.GetBytes(pub.ToAuthorizedKey("fuzz"))];
        yield return [2, .. Encoding.ASCII.GetBytes(pub.ToRfc4716("fuzz"))];
        yield return [4, .. SshPrivateKey.Create(pk, "fuzz", string.Empty).Encoded.Span];
        yield return [4, .. SshPrivateKey.Create(pk, "fuzz", "fuzz", new SshKeyWriteOptions { Rounds = 2 }).Encoded.Span];
        yield return [4, .. SshPrivateKey.Create(pk, "fuzz", "fuzz", new SshKeyWriteOptions { Rounds = 2, Cipher = SshKeyCipher.Aes256Gcm }).Encoded.Span];
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using PrivateKeyInfo ek = PrivateKeyInfo.FromAsymmetricAlgorithm(ec);
        yield return [4, .. SshPrivateKey.Create(ek, "ec", string.Empty).Encoded.Span];
        yield return [3, .. CertificateSeed(pk, pub)];
    }

    /// <summary>A minimal certificate blob signed by an Ed25519 key, built here so the signature path has a valid starting point.</summary>
    private static byte[] CertificateSeed(PrivateKeyInfo ca, SshPublicKey subject)
    {
        using Ed25519PrivateKey caKey = ca.ToEd25519();
        SshPublicKey caPub = SshPublicKey.FromPublicKeyInfo(ca.GetPublicKey());
        using var w = new SshWriter();
        w.WriteString("ssh-ed25519-cert-v01@openssh.com");
        w.WriteString(new byte[32]);
        w.WriteString(subject.Ed25519Key.Span);
        w.WriteUInt64(1);
        w.WriteUInt32(1);
        w.WriteString("id");
        using (var pr = new SshWriter())
        {
            pr.WriteString("user");
            w.WriteString(pr.Written);
        }

        w.WriteUInt64(0);
        w.WriteUInt64(ulong.MaxValue);
        w.WriteString([]);
        w.WriteString([]);
        w.WriteString([]);
        w.WriteString(caPub.Blob.Span);
        byte[] signed = w.ToArray();
        Span<byte> sig = stackalloc byte[64];
        caKey.TrySign(signed, sig, out _);
        using var sb = new SshWriter();
        sb.WriteString("ssh-ed25519");
        sb.WriteString(sig);
        w.WriteString(sb.Written);
        return w.ToArray();
    }
}
