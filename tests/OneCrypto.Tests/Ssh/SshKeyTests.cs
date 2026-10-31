using System.Numerics;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Pkcs;
using RecursiveAI.OneCrypto.Wire.Ssh;

namespace OneCrypto.Tests.Ssh;

public class SshKeyTests
{
    private static readonly string? Keygen = ToolRunner.Find("ssh-keygen");

    private static string Gen(string dir, string name, string type, string passphrase, params string[] extra)
    {
        string path = Path.Combine(dir, name);
        var a = new List<string> { "-q", "-t", type, "-N", passphrase, "-C", "c-" + name, "-f", path };
        a.AddRange(extra);
        (int code, string output) = ToolRunner.Run(Keygen!, dir, [.. a]);
        Assert.True(code == 0, output);
        return path;
    }

    private static string PublicOf(string dir, string path, string passphrase)
    {
        (int code, string output) = ToolRunner.Run(Keygen!, dir, "-y", "-P", passphrase, "-f", path);
        Assert.True(code == 0, output);
        return output.Trim();
    }

    [Theory]
    [InlineData("ed25519", "", "")]
    [InlineData("ed25519", "pass phrase", "")]
    [InlineData("ed25519", "pass phrase", "aes256-gcm@openssh.com")]
    [InlineData("ed25519", "pass phrase", "aes128-gcm@openssh.com")]
    [InlineData("ed25519", "pass phrase", "aes128-ctr")]
    [InlineData("ed25519", "pass phrase", "aes192-ctr")]
    [InlineData("ed25519", "pass phrase", "aes256-cbc")]
    [InlineData("rsa", "", "")]
    [InlineData("rsa", "pw", "")]
    [InlineData("rsa", "pw", "aes256-gcm@openssh.com")]
    [InlineData("ecdsa", "", "")]
    [InlineData("ecdsa", "pw", "")]
    public void SshKeygenKeysLoadAndPublicKeysMatch(string type, string passphrase, string cipher)
    {
        Assert.SkipWhen(Keygen is null, "ssh-keygen is not installed");
        string dir = ToolRunner.TempDir("ssh-load");
        var extra = new List<string>();
        if (cipher.Length > 0)
        {
            extra.AddRange(["-Z", cipher]);
        }

        if (type == "rsa")
        {
            extra.AddRange(["-b", "2048"]);
        }

        string path = Gen(dir, "k", type, passphrase, [.. extra]);
        SshPrivateKey key = SshPrivateKey.FromPem(File.ReadAllText(path));
        Assert.Equal(passphrase.Length > 0, key.IsEncrypted);
        Assert.Equal(PublicOf(dir, path, passphrase).Split(' ')[1], Convert.ToBase64String(key.PublicKey.Blob.Span));

        SshPublicKey pub = SshPublicKey.ParseAuthorizedKey(File.ReadAllText(path + ".pub"));
        Assert.Equal(pub, key.PublicKey);
        Assert.Equal("c-k", pub.Comment);
        Assert.Equal(PkcsStatus.Ok, key.TryOpen(passphrase, out SshPrivateKeyContents? c));
        using (c)
        {
            Assert.Equal("c-k", c!.Comment);
            Assert.NotNull(c.PrivateKey);
            Assert.Equal(pub.ToPublicKeyInfo(), c.PrivateKey!.GetPublicKey());
        }

        if (passphrase.Length > 0)
        {
            Assert.Equal(PkcsStatus.WrongPasswordOrCorrupt, key.TryOpen("wrong", out SshPrivateKeyContents? none));
            Assert.Null(none);
            Assert.Equal(PkcsStatus.PasswordRequired, key.TryOpen(string.Empty, out _));
        }
    }

    [Theory]
    [InlineData(256)]
    [InlineData(384)]
    [InlineData(521)]
    public void EcdsaCurvesLoad(int bits)
    {
        Assert.SkipWhen(Keygen is null, "ssh-keygen is not installed");
        string dir = ToolRunner.TempDir("ssh-ec");
        string path = Gen(dir, "k", "ecdsa", "pw", "-b", bits.ToString(System.Globalization.CultureInfo.InvariantCulture));
        SshPrivateKey key = SshPrivateKey.FromPem(File.ReadAllText(path));
        using SshPrivateKeyContents c = key.Open("pw");
        Assert.Equal(bits, key.PublicKey.KeySizeBits);
        Assert.Equal(key.PublicKey.ToPublicKeyInfo(), c.PrivateKey!.GetPublicKey());
        using ECDsa ec = c.PrivateKey.ToECDsa();
        byte[] sig = ec.SignData(new byte[] { 1, 2, 3 }, HashAlgorithmName.SHA256);
        Assert.True(key.PublicKey.ToPublicKeyInfo().ToECDsa().VerifyData(new byte[] { 1, 2, 3 }, sig, HashAlgorithmName.SHA256));
    }

    [Fact]
    public void RecoveredRsaKeySigns()
    {
        Assert.SkipWhen(Keygen is null, "ssh-keygen is not installed");
        string dir = ToolRunner.TempDir("ssh-rsa");
        string path = Gen(dir, "k", "rsa", string.Empty, "-b", "3072");
        using SshPrivateKeyContents c = SshPrivateKey.FromPem(File.ReadAllText(path)).Open(string.Empty);
        using RSA rsa = c.PrivateKey!.ToRsa();
        byte[] sig = rsa.SignData(new byte[] { 9, 9 }, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using RSA pub = c.PublicKey.ToPublicKeyInfo().ToRsa();
        Assert.True(pub.VerifyData(new byte[] { 9, 9 }, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Theory]
    [InlineData("ed25519", "")]
    [InlineData("ed25519", "pw")]
    [InlineData("rsa", "pw")]
    [InlineData("ecdsa", "")]
    [InlineData("ecdsa", "pw")]
    public void OurKeysLoadInSshKeygen(string type, string passphrase)
    {
        Assert.SkipWhen(Keygen is null, "ssh-keygen is not installed");
        string dir = ToolRunner.TempDir("ssh-write");
        using PrivateKeyInfo pk = type switch
        {
            "ed25519" => FromEd(),
            "rsa" => FromBcl(RSA.Create(2048)),
            _ => FromBcl(ECDsa.Create(ECCurve.NamedCurves.nistP384)),
        };
        foreach (SshKeyCipher cipher in passphrase.Length == 0 ? [SshKeyCipher.None] : new[] { SshKeyCipher.Aes256Ctr, SshKeyCipher.Aes256Gcm, SshKeyCipher.Aes128Ctr })
        {
            SshPrivateKey k = SshPrivateKey.Create(pk, "ours", passphrase, new SshKeyWriteOptions { Cipher = cipher, Rounds = 16 });
            string path = Path.Combine(dir, "ours");
            File.WriteAllText(path, k.ToPem());
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            string expected = SshPublicKey.FromPublicKeyInfo(pk.GetPublicKey()).ToAuthorizedKey().Split(' ')[1];
            Assert.Equal(expected, PublicOf(dir, path, passphrase).Split(' ')[1]);

            // And back through our own reader.
            using SshPrivateKeyContents back = SshPrivateKey.FromPem(File.ReadAllText(path)).Open(passphrase);
            Assert.Equal("ours", back.Comment);
            Assert.True(pk.Encoded.SequenceEqual(back.PrivateKey!.Encoded));
            if (passphrase.Length > 0)
            {
                // ssh-keygen -p can change the passphrase of a file we wrote, proving it decrypts the private part.
                (int code, string output) = ToolRunner.Run(Keygen!, dir, "-p", "-P", passphrase, "-N", "new", "-f", path);
                Assert.True(code == 0, output);
            }
        }
    }

    private static PrivateKeyInfo FromEd()
    {
        using var k = RecursiveAI.OneCrypto.Primitives.Ed25519PrivateKey.Generate();
        return PrivateKeyInfo.FromEd25519(k);
    }

    private static PrivateKeyInfo FromBcl(AsymmetricAlgorithm a)
    {
        using (a)
        {
            return PrivateKeyInfo.FromAsymmetricAlgorithm(a);
        }
    }

    [Fact]
    public void PublicKeyTextFormsMatchSshKeygen()
    {
        Assert.SkipWhen(Keygen is null, "ssh-keygen is not installed");
        string dir = ToolRunner.TempDir("ssh-pub");
        foreach (string type in new[] { "ed25519", "rsa", "ecdsa" })
        {
            string path = Gen(dir, type, type, string.Empty);
            SshPublicKey k = SshPublicKey.ParseAuthorizedKey(File.ReadAllText(path + ".pub"));
            Assert.Equal(File.ReadAllText(path + ".pub").Trim(), k.ToAuthorizedKey());
            (int c1, string rfc) = ToolRunner.Run(Keygen!, dir, "-e", "-m", "RFC4716", "-f", path + ".pub");
            Assert.Equal(0, c1);
            SshPublicKey fromRfc = SshPublicKey.ParseRfc4716(rfc);
            Assert.Equal(k, fromRfc);
            File.WriteAllText(Path.Combine(dir, "ours.rfc"), k.ToRfc4716());
            (int c2, string imported) = ToolRunner.Run(Keygen!, dir, "-i", "-m", "RFC4716", "-f", Path.Combine(dir, "ours.rfc"));
            Assert.Equal(0, c2);
            Assert.Equal(k.ToAuthorizedKey(string.Empty), imported.Trim());
            (int c3, string fp) = ToolRunner.Run(Keygen!, dir, "-l", "-f", path + ".pub");
            Assert.Contains(k.Fingerprint, fp, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("ed25519", "ed25519")]
    [InlineData("rsa", "ed25519")]
    [InlineData("ecdsa", "ecdsa")]
    [InlineData("ed25519", "rsa")]
    public void CertificatesFromSshKeygenParseAndVerify(string subject, string ca)
    {
        Assert.SkipWhen(Keygen is null, "ssh-keygen is not installed");
        string dir = ToolRunner.TempDir("ssh-cert");
        string s = Gen(dir, "subject", subject, string.Empty);
        string c = Gen(dir, "ca", ca, string.Empty);
        (int code, string output) = ToolRunner.Run(Keygen!, dir, "-q", "-s", c, "-I", "key id 1", "-n", "alice,bob", "-V", "-5m:+1h", "-z", "42", "-O", "force-command=/bin/true", "-O", "source-address=10.0.0.0/8", s + ".pub");
        Assert.True(code == 0, output);
        SshCertificate cert = SshCertificate.ParseLine(File.ReadAllText(s + "-cert.pub"));
        Assert.Equal("key id 1", cert.KeyId);
        Assert.Equal(42UL, cert.Serial);
        Assert.Equal(SshCertificateType.User, cert.CertificateType);
        Assert.Equal(["alice", "bob"], cert.Principals);
        Assert.Equal(SshPublicKey.ParseAuthorizedKey(File.ReadAllText(s + ".pub")), cert.PublicKey);
        Assert.Equal(SshPublicKey.ParseAuthorizedKey(File.ReadAllText(c + ".pub")), cert.SignatureKey);
        Assert.Contains(cert.CriticalOptions, o => o.Name == "force-command");
        Assert.Contains(cert.Extensions, o => o.Name == "permit-pty");
        Assert.True(cert.IsValidAt(DateTimeOffset.UtcNow));
        Assert.False(cert.IsValidAt(DateTimeOffset.UtcNow.AddHours(2)));
        Assert.Equal(SshSignatureStatus.Valid, cert.VerifySignature());

        // A changed byte in the signed part must not verify.
        byte[] blob = cert.Blob.ToArray();
        blob[blob.Length / 2] ^= 1;
        if (SshCertificate.TryParse(blob, out SshCertificate? bad))
        {
            Assert.NotEqual(SshSignatureStatus.Valid, bad!.VerifySignature());
        }
    }

    [Fact]
    public void HostCertificateAndNoEndDate()
    {
        Assert.SkipWhen(Keygen is null, "ssh-keygen is not installed");
        string dir = ToolRunner.TempDir("ssh-hostcert");
        string s = Gen(dir, "host", "ed25519", string.Empty);
        string c = Gen(dir, "ca", "ecdsa", string.Empty);
        (int code, string output) = ToolRunner.Run(Keygen!, dir, "-q", "-s", c, "-I", "host1", "-h", "-n", "example.org", s + ".pub");
        Assert.True(code == 0, output);
        SshCertificate cert = SshCertificate.ParseLine(File.ReadAllText(s + "-cert.pub"));
        Assert.Equal(SshCertificateType.Host, cert.CertificateType);
        Assert.Equal(DateTimeOffset.MaxValue, cert.ValidBefore);
        Assert.Equal(SshSignatureStatus.Valid, cert.VerifySignature());
    }

    // ---- unit tests that need no tools ----

    [Fact]
    public void SecretModMatchesBigInteger()
    {
        var rng = new Random(7);
        for (int i = 0; i < 300; i++)
        {
            byte[] v = new byte[rng.Next(1, 300)];
            byte[] m = new byte[rng.Next(1, 130)];
            rng.NextBytes(v);
            rng.NextBytes(m);
            m[0] |= i % 3 == 0 ? (byte)1 : (byte)0x80;
            if (i % 5 == 0)
            {
                m[0] = 1;
            }

            var mb = new BigInteger(m, isUnsigned: true, isBigEndian: true);
            if (mb.IsZero)
            {
                continue;
            }

            byte[] r = new byte[m.Length];
            SecretMod.Reduce(v, m, r);
            BigInteger expect = BigInteger.Remainder(new BigInteger(v, isUnsigned: true, isBigEndian: true), mb);
            Assert.Equal(expect, new BigInteger(r, isUnsigned: true, isBigEndian: true));
        }
    }

    [Fact]
    public void MalformedKeysRaiseTypedErrors()
    {
        Assert.Throws<SshParseException>(() => SshPublicKey.Parse([0, 0, 0, 3, 1, 2, 3]));
        Assert.Throws<SshParseException>(() => SshPublicKey.ParseAuthorizedKey("ssh-ed25519 !!!"));
        Assert.Throws<SshParseException>(() => SshPrivateKey.Parse("openssh-key-v1\0"u8));
        Assert.False(SshPrivateKey.TryParse([1, 2, 3], out _));
        Assert.False(SshCertificate.TryParse([0, 0, 0, 1, 65], out _));
        // A string that claims to be longer than the data.
        Assert.Throws<SshParseException>(() => SshPublicKey.Parse([0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0xFF, 0xFF, 0xFF, 0xFF]));
    }

    [Fact]
    public void HostileBcryptRoundsAreLimited()
    {
        using PrivateKeyInfo pk = FromEd();
        SshPrivateKey k = SshPrivateKey.Create(pk, "x", "pw", new SshKeyWriteOptions { Rounds = 4 });
        Assert.Equal(PkcsStatus.LimitExceeded, k.TryOpen("pw", out _, new RecursiveAI.OneCrypto.Primitives.KdfLimits { MaxBcryptRounds = 2 }));
        Assert.Equal(PkcsStatus.Ok, k.TryOpen("pw", out SshPrivateKeyContents? c));
        c!.Dispose();
    }
}
