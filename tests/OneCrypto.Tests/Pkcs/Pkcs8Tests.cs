using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Pkcs;
using RecursiveAI.OneCrypto.Primitives;

namespace OneCrypto.Tests.Pkcs;

public class Pkcs8Tests
{
    private static readonly Pbes2Options Fast = new() { Iterations = 1000 };

    private static PrivateKeyInfo Make(string kind)
    {
        switch (kind)
        {
            case "rsa":
                using (RSA r = RSA.Create(2048))
                {
                    return PrivateKeyInfo.FromAsymmetricAlgorithm(r);
                }

            case "p256" or "p384" or "p521":
                using (ECDsa e = ECDsa.Create(kind == "p256" ? ECCurve.NamedCurves.nistP256 : kind == "p384" ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP521))
                {
                    return PrivateKeyInfo.FromAsymmetricAlgorithm(e);
                }

            case "ed25519":
                using (Ed25519PrivateKey k = Ed25519PrivateKey.Generate())
                {
                    return PrivateKeyInfo.FromEd25519(k);
                }

            case "x25519":
                using (X25519PrivateKey k = X25519PrivateKey.Generate())
                {
                    return PrivateKeyInfo.FromX25519(k);
                }

            default:
                throw new ArgumentException(kind);
        }
    }

    [Theory]
    [InlineData("rsa")]
    [InlineData("p256")]
    [InlineData("p384")]
    [InlineData("p521")]
    [InlineData("ed25519")]
    [InlineData("x25519")]
    public void EncodingIsKeptAndPublicKeyIsDerived(string kind)
    {
        using PrivateKeyInfo k = Make(kind);
        byte[] enc = k.ExportEncoded();
        using PrivateKeyInfo again = PrivateKeyInfo.Parse(enc);
        Assert.True(enc.AsSpan().SequenceEqual(again.Encoded));
        Assert.Equal(0, again.Version);
        PublicKeyInfo pub = again.GetPublicKey();
        Assert.Equal(again.KeyAlgorithm, pub.KeyAlgorithm);
    }

    [Fact]
    public void Version2KeyCarriesPublicKey()
    {
        using Ed25519PrivateKey key = Ed25519PrivateKey.Generate();
        using PrivateKeyInfo k = PrivateKeyInfo.FromEd25519(key, includePublicKey: true);
        Assert.Equal(1, k.Version);
        Span<byte> pub = stackalloc byte[32];
        key.PublicKey.Export(pub);
        Assert.True(k.PublicKeyBits.Span.SequenceEqual(pub));
        using PrivateKeyInfo back = PrivateKeyInfo.Parse(k.Encoded);
        using Ed25519PrivateKey k2 = back.ToEd25519();
        Span<byte> pub2 = stackalloc byte[32];
        k2.PublicKey.Export(pub2);
        Assert.True(pub.SequenceEqual(pub2));
    }

    [Fact]
    public void CurveKeysConvertToLibraryTypes()
    {
        using X25519PrivateKey x = X25519PrivateKey.Generate();
        using PrivateKeyInfo xi = PrivateKeyInfo.FromX25519(x);
        using X25519PrivateKey x2 = xi.ToX25519();
        Span<byte> a = stackalloc byte[32];
        Span<byte> b = stackalloc byte[32];
        x.PublicKey.Export(a);
        x2.PublicKey.Export(b);
        Assert.True(a.SequenceEqual(b));
        Assert.Throws<InvalidOperationException>(() => xi.ToEd25519());
    }

    [Fact]
    public void BclKeysConvertBack()
    {
        using RSA rsa = RSA.Create(2048);
        using PrivateKeyInfo k = PrivateKeyInfo.FromAsymmetricAlgorithm(rsa);
        using RSA back = k.ToRsa();
        Assert.Equal(rsa.ExportParameters(false).Modulus, back.ExportParameters(false).Modulus);
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using PrivateKeyInfo ek = PrivateKeyInfo.FromAsymmetricAlgorithm(ec);
        using ECDsa eb = ek.ToECDsa();
        Assert.Equal(ec.ExportParameters(false).Q.X, eb.ExportParameters(false).Q.X);
    }

    [Theory]
    [InlineData(Pbes2Cipher.Aes256Cbc, Pbes2Kdf.Pbkdf2)]
    [InlineData(Pbes2Cipher.Aes128Cbc, Pbes2Kdf.Pbkdf2)]
    [InlineData(Pbes2Cipher.Aes192Cbc, Pbes2Kdf.Pbkdf2)]
    [InlineData(Pbes2Cipher.Aes256Gcm, Pbes2Kdf.Pbkdf2)]
    [InlineData(Pbes2Cipher.Aes128Gcm, Pbes2Kdf.Pbkdf2)]
    [InlineData(Pbes2Cipher.Aes256Cbc, Pbes2Kdf.Scrypt)]
    public void EncryptedKeyRoundTrips(Pbes2Cipher cipher, Pbes2Kdf kdf)
    {
        using PrivateKeyInfo k = Make("p256");
        var opt = new Pbes2Options { Cipher = cipher, Kdf = kdf, Iterations = 1000, ScryptCost = 1024 };
        EncryptedPrivateKeyInfo e = k.Encrypt("correct horse", opt);
        EncryptedPrivateKeyInfo parsed = EncryptedPrivateKeyInfo.Parse(e.Encoded.Span);
        Assert.Equal(PkcsStatus.Ok, parsed.TryDecrypt("correct horse", out PrivateKeyInfo? back));
        using (back)
        {
            Assert.True(k.Encoded.SequenceEqual(back!.Encoded));
        }

        Assert.Equal(PkcsStatus.WrongPasswordOrCorrupt, parsed.TryDecrypt("wrong", out PrivateKeyInfo? none));
        Assert.Null(none);
        Assert.Throws<PkcsPasswordException>(() => parsed.Decrypt("wrong"));
    }

    [Fact]
    public void TamperedDataFailsClosed()
    {
        using PrivateKeyInfo k = Make("ed25519");
        foreach (Pbes2Cipher c in new[] { Pbes2Cipher.Aes256Cbc, Pbes2Cipher.Aes256Gcm })
        {
            byte[] enc = k.Encrypt("pw", new Pbes2Options { Cipher = c, Iterations = 1000 }).Encoded.ToArray();
            enc[^3] ^= 1;
            EncryptedPrivateKeyInfo e = EncryptedPrivateKeyInfo.Parse(enc);
            Assert.NotEqual(PkcsStatus.Ok, e.TryDecrypt("pw", out PrivateKeyInfo? key));
            Assert.Null(key);
        }
    }

    private static byte[] Pbes2With(long iterations, byte[] salt)
    {
        var w = new Asn1Writer();
        w.PushSequence();
        w.PushSequence();
        w.WriteObjectIdentifier("1.2.840.113549.1.5.13");
        w.PushSequence();
        w.PushSequence();
        w.WriteObjectIdentifier("1.2.840.113549.1.5.12");
        w.PushSequence();
        w.WriteOctetString(salt);
        w.WriteInteger(iterations);
        w.Pop();
        w.Pop();
        w.PushSequence();
        w.WriteObjectIdentifier("2.16.840.1.101.3.4.1.42");
        w.WriteOctetString(new byte[16]);
        w.Pop();
        w.Pop();
        w.Pop();
        w.WriteOctetString(new byte[32]);
        w.Pop();
        return w.Encode();
    }

    [Fact]
    public void HostileCostsAreRefusedBeforeDerivation()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        EncryptedPrivateKeyInfo huge = EncryptedPrivateKeyInfo.Parse(Pbes2With(2_000_000_000, new byte[16]));
        Assert.Equal(PkcsStatus.LimitExceeded, huge.TryDecrypt("pw", out _));
        EncryptedPrivateKeyInfo salty = EncryptedPrivateKeyInfo.Parse(Pbes2With(1000, new byte[5000]));
        Assert.Equal(PkcsStatus.LimitExceeded, salty.TryDecrypt("pw", out _));
        EncryptedPrivateKeyInfo zero = EncryptedPrivateKeyInfo.Parse(Pbes2With(0, new byte[16]));
        Assert.Equal(PkcsStatus.Malformed, zero.TryDecrypt("pw", out _));
        Assert.True(sw.ElapsedMilliseconds < 2000);

        // The default limit can be lowered per call.
        EncryptedPrivateKeyInfo ok = EncryptedPrivateKeyInfo.Parse(Pbes2With(2000, new byte[16]), new PkcsLimits { MaxIterations = 1000 });
        Assert.Equal(PkcsStatus.LimitExceeded, ok.TryDecrypt("pw", out _));
    }

    [Fact]
    public void BclEncryptedPkcs8Opens()
    {
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        foreach (HashAlgorithmName prf in new[] { HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA512 })
        {
            byte[] enc = ec.ExportEncryptedPkcs8PrivateKey("bcl pw", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, prf, 1500));
            using PrivateKeyInfo k = EncryptedPrivateKeyInfo.Parse(enc).Decrypt("bcl pw");
            using ECDsa back = k.ToECDsa();
            Assert.Equal(ec.ExportParameters(false).Q.X, back.ExportParameters(false).Q.X);
        }

        // The platform's PKCS#12 triple-DES PBE.
        byte[] tdes = ec.ExportEncryptedPkcs8PrivateKey("bcl pw", new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2000));
        using PrivateKeyInfo k2 = EncryptedPrivateKeyInfo.Parse(tdes).Decrypt("bcl pw");
        Assert.Equal(KeyAlgorithm.EllipticCurve, k2.KeyAlgorithm);
    }

    [Fact]
    public void BclImportsOurEncryptedPkcs8()
    {
        using PrivateKeyInfo k = Make("p384");
        foreach (Pbes2Cipher c in new[] { Pbes2Cipher.Aes256Cbc, Pbes2Cipher.Aes128Cbc })
        {
            byte[] enc = k.Encrypt("our pw", new Pbes2Options { Cipher = c, Iterations = 2000, Prf = HashAlgorithmName.SHA512 }).Encoded.ToArray();
            using ECDsa ec = ECDsa.Create();
            ec.ImportEncryptedPkcs8PrivateKey("our pw", enc, out _);
            using ECDsa orig = k.ToECDsa();
            Assert.Equal(orig.ExportParameters(false).Q.X, ec.ExportParameters(false).Q.X);
        }
    }

    [Fact]
    public void MalformedInputRaisesTypedErrors()
    {
        Assert.Throws<PkcsParseException>(() => PrivateKeyInfo.Parse([1, 2, 3]));
        Assert.False(PrivateKeyInfo.TryParse([0x30, 0x03, 0x02, 0x01, 0x05], out PrivateKeyInfo? _));
        Assert.False(EncryptedPrivateKeyInfo.TryParse([0x30, 0x00], out _));
        Assert.Equal(PkcsStatus.Malformed, PrivateKeyPem.TryParse("not pem", default, out _));
    }

    // ---- OpenSSL, both directions ----

    [Theory]
    [InlineData("RSA -pkeyopt rsa_keygen_bits:2048")]
    [InlineData("EC -pkeyopt ec_paramgen_curve:P-256")]
    [InlineData("EC -pkeyopt ec_paramgen_curve:P-384")]
    [InlineData("EC -pkeyopt ec_paramgen_curve:P-521")]
    [InlineData("EC -pkeyopt ec_paramgen_curve:brainpoolP256r1")]
    [InlineData("ED25519")]
    [InlineData("ED448")]
    [InlineData("X25519")]
    [InlineData("X448")]
    public void OpenSslKeysLoadAndOurKeysLoadInOpenSsl(string spec)
    {
        OpenSslTool.RequireOrSkip();
        string dir = ToolRunner.TempDir("pkcs8-openssl");
        string[] g = spec.Split(' ');
        string key = Path.Combine(dir, "k.pem");
        var args = new List<string> { "genpkey", "-algorithm", g[0], "-out", key };
        args.AddRange(g[1..]);
        Assert.Equal(0, OpenSslTool.Run([.. args]).Code);
        string spkiOf = OpenSslTool.Run("pkey", "-in", key, "-pubout").Output.Replace("\r", string.Empty, StringComparison.Ordinal);

        using PrivateKeyInfo plain = PrivateKeyInfo.FromPem(File.ReadAllText(key));
        string ourSpki;
        try
        {
            ourSpki = SpkiPem(plain.GetPublicKey()).Trim();
        }
        catch (AlgorithmNotSupportedException e) when (spec.Contains("brainpool", StringComparison.Ordinal))
        {
            // The platform lacks the curve and says so with the typed error; the availability table lists it.
            Assert.Skip(e.Message);
            return;
        }

        Assert.Equal(spkiOf.Trim(), ourSpki);

        foreach (string[] extra in new[]
        {
            new[] { "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256" },
            new[] { "-v2", "aes-128-cbc", "-v2prf", "hmacWithSHA1" },
            new[] { "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA512", "-iter", "5000" },
            new[] { "-scrypt" },
            new[] { "-scrypt", "-scrypt_N", "1024", "-scrypt_r", "4", "-scrypt_p", "2" },
        })
        {
            string enc = Path.Combine(dir, "enc.pem");
            var a = new List<string> { "pkcs8", "-topk8", "-in", key, "-out", enc, "-passout", "pass:ossl-pw" };
            a.AddRange(extra);
            (int code, string output) = OpenSslTool.Run([.. a]);
            if (code != 0 && extra[0] == "-scrypt")
            {
                continue; // an openssl without scrypt support
            }

            Assert.True(code == 0, output);
            using PrivateKeyInfo got = PrivateKeyPem.Parse(File.ReadAllText(enc), "ossl-pw");
            Assert.True(plain.Encoded.SequenceEqual(got.Encoded), string.Join(' ', extra));
        }

        foreach (Pbes2Options o in new[] { Fast, new Pbes2Options { Cipher = Pbes2Cipher.Aes128Cbc, Iterations = 1000, Prf = HashAlgorithmName.SHA512 }, new Pbes2Options { Kdf = Pbes2Kdf.Scrypt, ScryptCost = 2048 }, new Pbes2Options { Cipher = Pbes2Cipher.Aes256Gcm, Iterations = 1000 } })
        {
            string ours = Path.Combine(dir, "ours.pem");
            File.WriteAllText(ours, plain.Encrypt("our-pw", o).ToPem());
            (int code, string output) = OpenSslTool.Run("pkey", "-in", ours, "-passin", "pass:our-pw", "-pubout");
            if (code != 0 && o.Cipher == Pbes2Cipher.Aes256Gcm)
            {
                continue; // OpenSSL does not read AES-GCM in PBES2
            }

            Assert.True(code == 0, $"{o.Cipher}/{o.Kdf}: {output}");
            Assert.Equal(spkiOf.Trim(), output.Replace("\r", string.Empty, StringComparison.Ordinal).Trim());
        }
    }

    private static string SpkiPem(PublicKeyInfo k) => RecursiveAI.OneCrypto.Pem.PemCodec.Write("PUBLIC KEY", k.Encoded.Span);

    [Theory]
    [InlineData("aes-128-cbc")]
    [InlineData("aes-192-cbc")]
    [InlineData("aes-256-cbc")]
    [InlineData("des3")]
    public void LegacyPemEncryptionIsRead(string cipher)
    {
        OpenSslTool.RequireOrSkip();
        string dir = ToolRunner.TempDir("pkcs8-legacy");
        foreach (string alg in new[] { "RSA", "EC" })
        {
            string plainKey = Path.Combine(dir, "plain.pem");
            string args = alg == "RSA" ? "rsa_keygen_bits:2048" : "ec_paramgen_curve:P-256";
            Assert.Equal(0, OpenSslTool.Run("genpkey", "-algorithm", alg, "-pkeyopt", args, "-out", plainKey).Code);
            string trad = Path.Combine(dir, "trad.pem");
            (int c1, string o1) = OpenSslTool.Run("pkey", "-in", plainKey, "-traditional", "-out", trad);
            Assert.True(c1 == 0, o1);
            string enc = Path.Combine(dir, "enc.pem");
            (int c2, string o2) = OpenSslTool.Run("pkey", "-in", trad, "-" + cipher, "-traditional", "-passout", "pass:legacy pw", "-out", enc);
            Assert.True(c2 == 0, o2);
            string text = File.ReadAllText(enc);
            Assert.Contains("DEK-Info", text, StringComparison.Ordinal);
            using PrivateKeyInfo expect = PrivateKeyPem.Parse(File.ReadAllText(trad), default);
            using PrivateKeyInfo got = PrivateKeyPem.Parse(text, "legacy pw");
            Assert.Equal(expect.GetPublicKey().Encoded.ToArray(), got.GetPublicKey().Encoded.ToArray());
            Assert.Equal(PkcsStatus.PasswordRequired, PrivateKeyPem.TryParse(text, default, out _));
            Assert.NotEqual(PkcsStatus.Ok, PrivateKeyPem.TryParse(text, "bad", out _));
        }
    }

    [Fact]
    public void TraditionalDsaKeysAreWrappedAsPkcs8()
    {
        OpenSslTool.RequireOrSkip();
        string dir = ToolRunner.TempDir("pkcs8-dsa");
        string prm = Path.Combine(dir, "p.pem"), key = Path.Combine(dir, "k.pem"), trad = Path.Combine(dir, "t.pem");
        Assert.Equal(0, OpenSslTool.Run("genpkey", "-genparam", "-algorithm", "DSA", "-pkeyopt", "dsa_paramgen_bits:1024", "-out", prm).Code);
        Assert.Equal(0, OpenSslTool.Run("genpkey", "-paramfile", prm, "-out", key).Code);
        Assert.Equal(0, OpenSslTool.Run("pkey", "-in", key, "-traditional", "-out", trad).Code);
        string text = File.ReadAllText(trad);
        Assert.Contains("BEGIN DSA PRIVATE KEY", text, StringComparison.Ordinal);
        using PrivateKeyInfo ours = PrivateKeyPem.Parse(text, default);
        using PrivateKeyInfo theirs = PrivateKeyInfo.FromPem(File.ReadAllText(key));
        Assert.True(theirs.Encoded.SequenceEqual(ours.Encoded));
    }
}
