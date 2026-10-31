using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Wire.Ssh;

namespace OneCrypto.Tests.Load;

public class CryptoLoadTests
{
    private static readonly string[] MixedNames = ["rsa.cert.pem", "p256.cert.pem", "ca.crl.pem", "p256.csr.pem", "rsa.pub.pem", "ed25519.pk8.pem"];

    private static readonly byte[] Message = "load me"u8.ToArray();

    private static string Dir(string name)
    {
        string d = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-load", name, Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(d);
        return d;
    }

    private static string? Pw(string? password, string _) => password;

    private static int PlatformGaps;

    private static readonly Dictionary<KeyAlgorithm, bool> PqSupport = [];

    private static bool PostQuantumPrivateKeysSupported(KeyAlgorithm alg)
    {
        if (PqSupport.TryGetValue(alg, out bool known))
        {
            return known;
        }

        return PqSupport[alg] = ProbePq(alg);
    }

    private static bool ProbePq(KeyAlgorithm alg)
    {
        try
        {
            using LoadedItems probe = Crypto.Load(GeneratedPq(alg));
            return true;
        }
        catch (CryptoLoadException ex) when (ex.Error == CryptoLoadError.Unsupported)
        {
            return false;
        }
    }

    private static byte[] GeneratedPq(KeyAlgorithm alg)
    {
        string dir = Dir("pq");
        (int code, string output) = OpenSslTool.RunIn(dir, "genpkey", "-algorithm", alg == KeyAlgorithm.MlDsa ? "ML-DSA-65" : "ML-KEM-768", "-out", "k.pem");
        Assert.True(code == 0, output);
        return File.ReadAllBytes(Path.Combine(dir, "k.pem"));
    }

    /// <summary>Checks one corpus case: the right type, the right algorithm, the right public key, and keys that work.</summary>
    private static void Check(CorpusCase c)
    {
        if (c.Algorithm is KeyAlgorithm.MlDsa or KeyAlgorithm.MlKem && c.Expect == Expect.PrivateKey && !PostQuantumPrivateKeysSupported(c.Algorithm.Value))
        {
            // The platform has no such key: the answer is a typed refusal that names the algorithm and platform, never a partial load.
            CryptoLoadException refused = Assert.Throws<CryptoLoadException>(() => Crypto.Load(c.Data, d => Pw(c.Password, d)));
            Assert.Equal(CryptoLoadError.Unsupported, refused.Error);
            Assert.Contains("not supported on this platform", refused.Message, StringComparison.Ordinal);
            PlatformGaps++;
            return;
        }

        using LoadedItems items = Crypto.Load(c.Data, d => Pw(c.Password, d));
        string why = $"{c.Name} ({c.Format}) loaded as {items.Format}";
        switch (c.Expect)
        {
            case Expect.PrivateKey:
            case Expect.SshPrivate:
                Assert.True(items.Count == 1 && items.PrivateKeys.Count == 1, why);
                LoadedPrivateKey k = items.PrivateKeys[0];
                Assert.True(c.Algorithm == k.Algorithm, why + " algorithm " + k.Algorithm);
                Assert.True(k.PublicKey is not null && k.PublicKey.Encoded.Span.SequenceEqual(c.ExpectedSpki), why + " public key");
                Exercise(k, why);
                if (c.Expect == Expect.SshPrivate)
                {
                    Assert.StartsWith("comment ", k.Comment, StringComparison.Ordinal);
                    Assert.NotNull(k.SshPublicKey);
                }

                break;
            case Expect.PublicKey:
                Assert.True(items.Count == 1 && items.PublicKeys.Count == 1, why);
                Assert.True(items.PublicKeys[0].Encoded.Span.SequenceEqual(c.ExpectedSpki), why + " public key");
                break;
            case Expect.Certificate:
                Assert.True(items.Count == Math.Max(1, c.Certificates) && items.Certificates.Count == items.Count, why);
                if (c.ExpectedSpki is not null)
                {
                    Assert.True(items.Certificates[0].PublicKey.Encoded.Span.SequenceEqual(c.ExpectedSpki), why + " certificate key");
                }

                break;
            case Expect.Csr:
                Assert.True(items.Count == 1 && items.CertificateRequests.Count == 1, why);
                Assert.True(items.CertificateRequests[0].PublicKey.Encoded.Span.SequenceEqual(c.ExpectedSpki), why + " request key");
                Assert.True(items.CertificateRequests[0].VerifySignature().IsValid || (c.Algorithm == KeyAlgorithm.MlDsa && !MLDsa.IsSupported), why + " request signature");
                break;
            case Expect.Crl:
                Assert.True(items.Count == 1 && items.Crls.Count == 1, why);
                break;
            case Expect.Ocsp:
                Assert.True(items.Count == 1 && items.OcspResponses.Count == 1, why);
                break;
            case Expect.P7b:
                Assert.True(items.Count == c.Certificates && items.Certificates.Count == c.Certificates, why);
                break;
            case Expect.P12:
                Assert.True(items.Certificates.Count == c.Certificates && items.PrivateKeys.Count == 1 && items.Count == c.Certificates + 1, why);
                LoadedPrivateKey pk = items.PrivateKeys[0];
                Assert.True(c.Algorithm == pk.Algorithm, why + " algorithm");
                Assert.True(pk.PublicKey!.Encoded.Span.SequenceEqual(c.ExpectedSpki), why + " key");
                Assert.NotNull(pk.Certificate);
                Assert.True(pk.Certificate!.PublicKey.Encoded.Span.SequenceEqual(c.ExpectedSpki), why + " key/certificate pair");
                Exercise(pk, why);
                break;
            case Expect.SshPublic:
                Assert.True(items.Count >= 1 && items.SshPublicKeys.Count == items.Count, why);
                break;
            case Expect.SshCertificate:
                Assert.True(items.Count == 1 && items.SshCertificates.Count == 1, why);
                Assert.Equal(SshSignatureStatus.Valid, items.SshCertificates[0].VerifySignature());
                break;
        }
    }

    /// <summary>Uses a loaded key: signs and verifies, decrypts what the public key encrypted, or agrees with a peer.</summary>
    private static void Exercise(LoadedPrivateKey k, string why)
    {
        if (k.Signing is { } s)
        {
            SignatureSpec spec = s.DefaultSpec;
            byte[] sig = s.Sign(Message, spec);
            Assert.True(spec.Verify(k.PublicKey!, Message, sig).IsValid, why + " signature");
        }

        if (k.Decryption is { } d && k.Algorithm == KeyAlgorithm.Rsa)
        {
            using RSA pub = k.PublicKey!.ToRsa();
            byte[] ct = pub.Encrypt(Message, RSAEncryptionPadding.OaepSHA256);
            Assert.Equal(Message, d.Decrypt(ct, DecryptionSpec.RsaOaep(HashAlgorithmName.SHA256)));
        }

        if (k.Agreement is { } a)
        {
            // Agree with a fresh peer of the same kind, and check against the peer's own computation.
            switch (k.Algorithm)
            {
                case KeyAlgorithm.EllipticCurve:
                    using (var peer = ECDiffieHellman.Create(ECCurve.CreateFromValue(k.Info.CurveOid!)))
                    {
                        byte[] ours = a.Agree(PublicKeyInfo.Parse(peer.ExportSubjectPublicKeyInfo()));
                        using var mine = ECDiffieHellman.Create();
                        mine.ImportSubjectPublicKeyInfo(k.PublicKey!.Encoded.Span, out _);
                        Assert.Equal(peer.DeriveRawSecretAgreement(mine.PublicKey), ours);
                    }

                    break;
                default:
                    // X25519 / X448: a second loaded key of the same kind gives the same secret both ways.
                    using (LoadedItems other = Crypto.Load(GenSame(k.Algorithm)))
                    {
                        LoadedPrivateKey o = other.PrivateKeys[0];
                        Assert.Equal(a.Agree(o.PublicKey!), o.Agreement!.Agree(k.PublicKey!));
                    }

                    break;
            }
        }

        if (k.Algorithm == KeyAlgorithm.MlKem)
        {
            Assert.NotNull(k.Decryption);
        }
    }

    private static byte[] GenSame(KeyAlgorithm alg)
    {
        string name = alg == KeyAlgorithm.X25519 ? "X25519" : "X448";
        string dir = Dir("peer");
        (int code, string output) = OpenSslTool.RunIn(dir, "genpkey", "-algorithm", name, "-out", "peer.pem");
        Assert.True(code == 0, output);
        return File.ReadAllBytes(Path.Combine(dir, "peer.pem"));
    }

    [Fact]
    public void GeneratedCorpusLoadsAsTheRightTypeWithWorkingKeys()
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("corpus");
        List<CorpusCase> cases = LoadCorpus.Build(dir);
        var counts = new SortedDictionary<string, int>(StringComparer.Ordinal);
        var failures = new List<string>();
        foreach (CorpusCase c in cases)
        {
            try
            {
                Check(c);
                counts[c.Format] = counts.GetValueOrDefault(c.Format) + 1;
            }
            catch (Exception ex) when (ex is Xunit.Sdk.XunitException or CryptoLoadException)
            {
                failures.Add($"{c.Name}: {ex.Message.ReplaceLineEndings(" ")[..Math.Min(300, ex.Message.Length)]}");
            }
        }

        string table = string.Join(", ", counts.Select(kv => $"{kv.Key}={kv.Value}"));
        File.WriteAllText(Path.Combine(dir, "counts.txt"), $"{cases.Count} files, {PlatformGaps} refused for platform gaps: {table}\n");
        Assert.True(failures.Count == 0, $"{failures.Count} of {cases.Count} misloaded:\n" + string.Join('\n', failures));
        Assert.True(cases.Count > 100, "the corpus is unexpectedly small: " + cases.Count);
    }

    [Fact]
    public void PasswordRulesAreStrict()
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("pw");
        List<CorpusCase> cases = LoadCorpus.Build(dir);
        CorpusCase enc = cases.First(c => c.Name == "p256.enc.pem");
        CorpusCase p12 = cases.First(c => c.Name == "default.p12");

        CryptoLoadException e1 = Assert.Throws<CryptoLoadException>(() => Crypto.Load(enc.Data));
        Assert.Equal(CryptoLoadError.PasswordRequired, e1.Error);
        CryptoLoadException e2 = Assert.Throws<CryptoLoadException>(() => Crypto.Load(enc.Data, _ => "wrong"));
        Assert.Equal(CryptoLoadError.WrongPasswordOrCorrupt, e2.Error);
        CryptoLoadException e3 = Assert.Throws<CryptoLoadException>(() => Crypto.Load(p12.Data, _ => "wrong"));
        Assert.Equal(CryptoLoadError.WrongPasswordOrCorrupt, e3.Error);
        Assert.Equal(CryptoLoadError.PasswordRequired, Assert.Throws<CryptoLoadException>(() => Crypto.Load(p12.Data)).Error);
        Assert.Equal(CryptoLoadError.PasswordRequired, Assert.Throws<CryptoLoadException>(() => Crypto.Load(p12.Data, _ => null)).Error);

        // A file with two encrypted keys under one password asks once.
        byte[] both = [.. enc.Data, .. cases.First(c => c.Name == "rsa.enc.pem").Data];
        int asked = 0;
        using LoadedItems two = Crypto.Load(both, _ =>
        {
            asked++;
            return LoadCorpus.Password;
        });
        Assert.Equal(2, two.PrivateKeys.Count);
        Assert.Equal(1, asked);

        // A wrong password on a later item loads nothing, not even the key and the plain certificate before it.
        using var other = RSA.Create(2048);
        string second = other.ExportEncryptedPkcs8PrivateKeyPem("other password", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000));
        byte[] mixed = [.. cases.First(c => c.Name == "rsa.cert.pem").Data, .. enc.Data, .. System.Text.Encoding.ASCII.GetBytes(second)];
        int n = 0;
        CryptoLoadException e4 = Assert.Throws<CryptoLoadException>(() => Crypto.Load(mixed, _ => n++ == 0 ? LoadCorpus.Password : "not it"));
        Assert.Equal(CryptoLoadError.WrongPasswordOrCorrupt, e4.Error);
        Assert.Equal(2, n);
        using LoadedItems right = Crypto.Load(mixed, d => d.Contains("block 2", StringComparison.Ordinal) ? LoadCorpus.Password : "other password");
        Assert.Equal(2, right.PrivateKeys.Count);
    }

    [Fact]
    public void MixedPemFilesKeepEverythingInOrder()
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("mixed");
        List<CorpusCase> cases = LoadCorpus.Build(dir);
        string text = "some notes\n" + string.Concat(MixedNames
            .Select(n => System.Text.Encoding.ASCII.GetString(cases.First(c => c.Name == n).Data) + "\nbetween blocks\n"));
        using LoadedItems items = Crypto.Load(System.Text.Encoding.ASCII.GetBytes(text));
        Assert.Equal(2, items.Certificates.Count);
        Assert.Single(items.Crls);
        Assert.Single(items.CertificateRequests);
        Assert.Single(items.PublicKeys);
        Assert.Single(items.PrivateKeys);
        Assert.Equal("PEM", items.Format);
    }

    [Fact]
    public void BadInputGivesTypedErrorsWithReasons()
    {
        byte[] pgp = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ==\n-----END PGP PUBLIC KEY BLOCK-----\n"u8.ToArray();
        CryptoLoadException pg = Assert.Throws<CryptoLoadException>(() => Crypto.Load(pgp));
        Assert.Equal(CryptoLoadError.Unrecognized, pg.Error);
        Assert.Contains("OpenPGP", pg.Message, StringComparison.Ordinal);

        Assert.Equal(CryptoLoadError.Empty, Assert.Throws<CryptoLoadException>(() => Crypto.Load([])).Error);
        Assert.Equal(CryptoLoadError.Empty, Assert.Throws<CryptoLoadException>(() => Crypto.Load("  \n\t"u8)).Error);

        Assert.False(Crypto.TryLoad("hello, world"u8, out LoadedItems? none, out CryptoLoadException? err));
        Assert.Null(none);
        Assert.Equal(CryptoLoadError.Unrecognized, err!.Error);
        Assert.NotEmpty(err.Considered);
        Assert.Contains(err.Considered, a => a.Format == "authorized_keys");

        byte[] truncated = [0x30, 0x82, 0x03, 0x00, 0x01, 0x02];
        CryptoLoadException tr = Assert.Throws<CryptoLoadException>(() => Crypto.Load(truncated));
        Assert.Equal(CryptoLoadError.Malformed, tr.Error);

        byte[] unknownDer = [0x30, 0x03, 0x02, 0x01, 0x05];
        Assert.Equal(CryptoLoadError.Unrecognized, Assert.Throws<CryptoLoadException>(() => Crypto.Load(unknownDer)).Error);

        // Nesting past the depth limit is a limit error, not a stack problem.
        byte[] deep = [];
        for (int i = 0; i < 200; i++)
        {
            deep = [0x30, .. DerLength(deep.Length), .. deep];
        }

        Assert.Throws<CryptoLoadException>(() => Crypto.Load(deep));
    }

    private static byte[] DerLength(int n) => n < 0x80 ? [(byte)n] : n < 0x100 ? [0x81, (byte)n] : [0x82, (byte)(n >> 8), (byte)n];

    [Fact]
    public void FilesAndStreamsLoadThroughTheSameParser()
    {
        using var rsa = RSA.Create(2048);
        string dir = Dir("io");
        string path = Path.Combine(dir, "key.pem");
        File.WriteAllText(path, rsa.ExportPkcs8PrivateKeyPem());
        using (LoadedItems a = Crypto.Load(path))
        using (LoadedItems b = Crypto.Load(File.OpenRead(path)))
        using (LoadedItems c = Crypto.LoadAsync(path).GetAwaiter().GetResult())
        {
            Assert.Single(a.PrivateKeys);
            Assert.Equal(a.PrivateKeys[0].PublicKey, b.PrivateKeys[0].PublicKey);
            Assert.Equal(a.PrivateKeys[0].PublicKey, c.PrivateKeys[0].PublicKey);
        }

        Assert.True(Crypto.TryLoad(path, out LoadedItems? d, out _));
        d!.Dispose();
    }

    [Fact]
    public void MutatedCorpusFilesOnlyEverRaiseCryptoLoadException()
    {
        OpenSslTool.RequireOrSkip();
        List<CorpusCase> cases = LoadCorpus.Build(Dir("mutate"));
        var rng = new Random(20261031);
        int loaded = 0, refused = 0;
        foreach (CorpusCase c in cases)
        {
            for (int i = 0; i < 12; i++)
            {
                byte[] m = Mutate(c.Data, rng, i);
                try
                {
                    using LoadedItems it = Crypto.Load(m, _ => c.Password ?? LoadCorpus.Password);
                    loaded++;
                }
                catch (CryptoLoadException)
                {
                    refused++;
                }
            }
        }

        Assert.True(refused > loaded, $"{refused} refused, {loaded} loaded");
    }

    internal static byte[] Mutate(byte[] data, Random rng, int round)
    {
        byte[] m = (byte[])data.Clone();
        switch (round % 6)
        {
            case 0:
                return m.Length > 1 ? m[..rng.Next(1, m.Length)] : m;
            case 1:
                m[rng.Next(m.Length)] ^= (byte)(1 << rng.Next(8));
                return m;
            case 2:
                m[rng.Next(m.Length)] = (byte)rng.Next(256);
                return m;
            case 3:
                int at = rng.Next(m.Length);
                return [.. m[..at], .. m[(at + rng.Next(1, Math.Min(20, m.Length - at + 1)))..]];
            case 4:
                int ins = rng.Next(m.Length);
                return [.. m[..ins], .. new[] { (byte)rng.Next(256), (byte)rng.Next(256) }, .. m[ins..]];
            default:
                for (int k = 0; k < 4; k++)
                {
                    m[rng.Next(m.Length)] ^= (byte)rng.Next(1, 256);
                }

                return m;
        }
    }
}
