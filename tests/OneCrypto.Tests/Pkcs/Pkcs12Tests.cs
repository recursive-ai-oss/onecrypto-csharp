using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Pkcs;

namespace OneCrypto.Tests.Pkcs;

public class Pkcs12Tests
{
    private static readonly Pkcs12WriteOptions Fast = new() { Encryption = new Pbes2Options { Iterations = 1000 }, MacIterations = 1000 };

    /// <summary>A self-signed certificate and its key, made with the platform.</summary>
    private static (PrivateKeyInfo Key, Certificate Cert, X509Certificate2 Bcl) Pki(bool ec = false)
    {
        using AsymmetricAlgorithm k = ec ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : RSA.Create(2048);
        var req = ec
            ? new CertificateRequest("CN=p12 test", (ECDsa)k, HashAlgorithmName.SHA256)
            : new CertificateRequest("CN=p12 test", (RSA)k, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        X509Certificate2 c = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return (PrivateKeyInfo.FromAsymmetricAlgorithm(k), Certificate.FromX509Certificate2(c), c);
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 0)]
    [InlineData(false, 1)]
    public void OurFilesRoundTrip(bool ec, int macKind)
    {
        (PrivateKeyInfo key, Certificate cert, X509Certificate2 bcl) = Pki(ec);
        using (key)
        using (bcl)
        {
            Pkcs12File f = Pkcs12File.Create(key, cert, null, "pässword", "my key", new Pkcs12WriteOptions { Encryption = Fast.Encryption, MacIterations = 1000, Mac = macKind == 0 ? Pkcs12MacKind.Pkcs12 : Pkcs12MacKind.Pbmac1 });
            Pkcs12File back = Pkcs12File.Parse(f.Encoded.Span);
            Assert.Equal(macKind == 0 ? Pkcs12MacKind.Pkcs12 : Pkcs12MacKind.Pbmac1, back.MacKind);
            Assert.Equal(PkcsStatus.Ok, back.VerifyMac("pässword"));
            Assert.Equal(PkcsStatus.WrongPasswordOrCorrupt, back.VerifyMac("password"));
            Assert.Equal(PkcsStatus.Ok, back.TryOpen("pässword", out Pkcs12Contents? c));
            using (c)
            {
                Assert.Single(c!.Certificates);
                Assert.Equal(cert, c.Certificates[0]);
                Assert.True(key.Encoded.SequenceEqual(c.PrivateKeys[0].Encoded));
                Pkcs12Bag keyBag = c.Bags.First(b => b.Kind == Pkcs12BagKind.ShroudedKey);
                Assert.Equal("my key", keyBag.FriendlyName);
                Pkcs12Bag? found = c.FindCertificateFor(keyBag);
                Assert.NotNull(found);
                Assert.Equal(cert, found!.Certificate);
            }

            Assert.Equal(PkcsStatus.WrongPasswordOrCorrupt, back.TryOpen("wrong", out Pkcs12Contents? none));
            Assert.Null(none);
            Assert.Throws<PkcsPasswordException>(() => back.Open("wrong"));
        }
    }

    [Fact]
    public void EveryMacHashAndTheEmptyPasswordWork()
    {
        (PrivateKeyInfo key, Certificate cert, X509Certificate2 bcl) = Pki(true);
        using (key)
        using (bcl)
        {
            foreach (string h in new[] { "SHA1", "SHA256", "SHA384", "SHA512" })
            {
                Pkcs12File f = Pkcs12File.Create(key, cert, null, string.Empty, null, new Pkcs12WriteOptions { Encryption = Fast.Encryption, MacIterations = 700, MacHash = new HashAlgorithmName(h) });
                Assert.Equal(PkcsStatus.Ok, f.TryOpen(string.Empty, out Pkcs12Contents? c));
                c!.Dispose();
                Assert.Equal(PkcsStatus.WrongPasswordOrCorrupt, f.VerifyMac("x"));
            }
        }
    }

    [Fact]
    public void TamperingFailsClosed()
    {
        (PrivateKeyInfo key, Certificate cert, X509Certificate2 bcl) = Pki(true);
        using (key)
        using (bcl)
        {
            byte[] good = Pkcs12File.Create(key, cert, null, "pw", null, Fast).Encoded.ToArray();
            for (int i = 8; i < good.Length; i += good.Length / 40)
            {
                byte[] bad = (byte[])good.Clone();
                bad[i] ^= 0x01;
                if (!Pkcs12File.TryParse(bad, out Pkcs12File? f))
                {
                    continue;
                }

                PkcsStatus st = f!.TryOpen("pw", out Pkcs12Contents? c);
                Assert.NotEqual(PkcsStatus.Ok, st);
                Assert.Null(c);
            }
        }
    }

    [Fact]
    public void FileWithoutMacNeedsExplicitConsent()
    {
        (PrivateKeyInfo key, Certificate cert, X509Certificate2 bcl) = Pki(true);
        using (key)
        using (bcl)
        {
            Pkcs12File f = Pkcs12File.Create(key, cert, null, "pw", null, new Pkcs12WriteOptions { Encryption = Fast.Encryption, Mac = Pkcs12MacKind.None });
            Assert.Equal(Pkcs12MacKind.None, f.MacKind);
            Assert.Equal(PkcsStatus.IntegrityMissing, f.TryOpen("pw", out _));
            Assert.Equal(PkcsStatus.Ok, f.TryOpen("pw", out Pkcs12Contents? c, requireMac: false));
            c!.Dispose();
        }
    }

    [Fact]
    public void BclExportsOpenInOurs()
    {
        (PrivateKeyInfo key, Certificate cert, X509Certificate2 bcl) = Pki();
        using (key)
        using (bcl)
        {
            foreach (Pkcs12ExportPbeParameters p in new[] { Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, Pkcs12ExportPbeParameters.Pbes2Aes256Sha256 })
            {
                byte[] pfx = bcl.ExportPkcs12(p, "bcl-pw");
                Pkcs12File f = Pkcs12File.Parse(pfx);
                Assert.Equal(PkcsStatus.Ok, f.TryOpen("bcl-pw", out Pkcs12Contents? c));
                using (c)
                {
                    Assert.Equal(cert, c!.Certificates[0]);
                    Assert.Equal(key.GetPublicKey(), c.PrivateKeys[0].GetPublicKey());
                }
            }
        }
    }

    [Fact]
    public void OurFilesOpenInBcl()
    {
        (PrivateKeyInfo key, Certificate cert, X509Certificate2 bcl) = Pki();
        using (key)
        using (bcl)
        {
            Pkcs12File f = Pkcs12File.Create(key, cert, null, "pw", "name", Fast);
            using X509Certificate2 loaded = X509CertificateLoader.LoadPkcs12(f.Encoded.ToArray(), "pw");
            Assert.True(loaded.HasPrivateKey);
            Assert.Equal(bcl.Thumbprint, loaded.Thumbprint);
            using RSA? rsa = loaded.GetRSAPrivateKey();
            Assert.NotNull(rsa);
            Assert.Throws<CryptographicException>(() => X509CertificateLoader.LoadPkcs12(f.Encoded.ToArray(), "bad"));
        }
    }

    // ---- OpenSSL, both directions ----

    [Theory]
    [InlineData("")]
    [InlineData("-legacy")]
    [InlineData("-keypbe AES-256-CBC -certpbe AES-128-CBC -macalg sha512")]
    [InlineData("-keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha1 -iter 5")]
    [InlineData("-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -legacy")]
    [InlineData("-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-RC2-40 -macalg sha1 -legacy")]
    [InlineData("-keypbe PBE-SHA1-2DES -certpbe PBE-SHA1-RC2-128 -macalg sha1 -legacy")]
    [InlineData("-pbmac1_pbkdf2")]
    [InlineData("-nomac")]
    [InlineData("-certpbe NONE")]
    public void OpenSslFilesOpenInOursAndOursOpenInOpenSsl(string flags)
    {
        OpenSslTool.RequireOrSkip();
        string dir = ToolRunner.TempDir("pkcs12-openssl");
        string key = Path.Combine(dir, "key.pem");
        string crt = Path.Combine(dir, "crt.pem");
        Assert.Equal(0, OpenSslTool.Run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-subj", "/CN=interop", "-days", "3").Code);
        string pfx = Path.Combine(dir, "o.p12");
        var a = new List<string> { "pkcs12", "-export", "-inkey", key, "-in", crt, "-out", pfx, "-passout", "pass:ossl pw", "-name", "ossl-name" };
        a.AddRange(flags.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        (int code, string output) = OpenSslTool.Run([.. a]);
        Assert.SkipWhen(code != 0 && (flags.Contains("legacy", StringComparison.Ordinal) || flags.Contains("pbmac1", StringComparison.Ordinal)), $"this openssl cannot write the profile: {output.Trim()}");
        Assert.True(code == 0, output);

        Pkcs12File f = Pkcs12File.Parse(File.ReadAllBytes(pfx));
        Assert.Equal(flags.Contains("nomac", StringComparison.Ordinal) ? PkcsStatus.IntegrityMissing : PkcsStatus.Ok, f.TryOpen("ossl pw", out Pkcs12Contents? c0));
        c0?.Dispose();
        Assert.Equal(PkcsStatus.Ok, f.TryOpen("ossl pw", out Pkcs12Contents? c, requireMac: false));
        using (c)
        {
            Certificate expectCert = Certificate.FromPem(File.ReadAllText(crt));
            Assert.Equal(expectCert, c!.Certificates[0]);
            using PrivateKeyInfo expectKey = PrivateKeyInfo.FromPem(File.ReadAllText(key));
            Assert.Equal(expectKey.GetPublicKey(), c.PrivateKeys[0].GetPublicKey());
            Assert.Contains(c.AllBags(), b => b.FriendlyName == "ossl-name");

            // ours -> openssl, same content
            string ours = Path.Combine(dir, "ours.p12");
            foreach (Pkcs12Mac mk in new[] { new Pkcs12Mac(Pkcs12MacKind.Pkcs12, "SHA256"), new Pkcs12Mac(Pkcs12MacKind.Pkcs12, "SHA1"), new Pkcs12Mac(Pkcs12MacKind.Pbmac1, "SHA256") })
            {
                var opt = new Pkcs12WriteOptions { Encryption = Fast.Encryption, MacIterations = 2000, Mac = mk.Kind, MacHash = new HashAlgorithmName(mk.Hash) };
                File.WriteAllBytes(ours, Pkcs12File.Create(c.PrivateKeys[0], expectCert, null, "our pw", "ours", opt).Encoded.ToArray());
                (int c2, string o2) = OpenSslTool.Run("pkcs12", "-in", ours, "-nodes", "-passin", "pass:our pw");
                if (c2 != 0 && mk.Kind == Pkcs12MacKind.Pbmac1)
                {
                    continue; // an openssl before RFC 9579 support
                }

                Assert.True(c2 == 0, $"{mk}: {o2}");
                Assert.Contains("BEGIN CERTIFICATE", o2, StringComparison.Ordinal);
                Assert.Contains("PRIVATE KEY", o2, StringComparison.Ordinal);
                Assert.Contains("friendlyName: ours", o2, StringComparison.Ordinal);
            }
        }
    }

    private sealed record Pkcs12Mac(Pkcs12MacKind Kind, string Hash);

    // ---- hostile input ----

    [Fact]
    public void HostileCostsAndStructuresAreLimited()
    {
        (PrivateKeyInfo key, Certificate cert, X509Certificate2 bcl) = Pki(true);
        using (key)
        using (bcl)
        {
            byte[] good = Pkcs12File.Create(key, cert, null, "pw", null, new Pkcs12WriteOptions { Encryption = Fast.Encryption, MacIterations = 1000 }).Encoded.ToArray();

            // A file that asks for more iterations than the caller allows is refused before any derivation.
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Assert.Equal(PkcsStatus.LimitExceeded, Pkcs12File.Parse(good, new PkcsLimits { MaxIterations = 500 }).TryOpen("pw", out _));
            Assert.True(sw.ElapsedMilliseconds < 2000);

            Assert.Throws<PkcsParseException>(() => Pkcs12File.Parse(new byte[] { 0x30, 0x80, 0x00, 0x00 }));
            Assert.Throws<PkcsParseException>(() => Pkcs12File.Parse(good, new PkcsLimits { MaxEncodedSize = 100 }));
        }
    }

    [Fact]
    public void DeepNestingOfSafeContentsBagsIsLimited()
    {
        // Build unauthenticated PFX with safeContentsBag nested 10 deep.
        byte[] inner = Seq();
        for (int i = 0; i < 10; i++)
        {
            var w = new Asn1Writer();
            w.PushSequence();
            w.PushSequence();
            w.WriteObjectIdentifier("1.2.840.113549.1.12.10.1.6");
            w.PushConstructed(Asn1Tag.Context(0, true));
            w.WriteEncodedValue(inner);
            w.Pop();
            w.Pop();
            w.Pop();
            inner = w.Encode();
        }

        var pfx = new Asn1Writer();
        pfx.PushSequence();
        pfx.WriteInteger(3);
        pfx.PushSequence();
        pfx.WriteObjectIdentifier("1.2.840.113549.1.7.1");
        pfx.PushConstructed(Asn1Tag.Context(0, true));
        var auth = new Asn1Writer();
        auth.PushSequence();
        auth.PushSequence();
        auth.WriteObjectIdentifier("1.2.840.113549.1.7.1");
        auth.PushConstructed(Asn1Tag.Context(0, true));
        auth.WriteOctetString(inner);
        auth.Pop();
        auth.Pop();
        auth.Pop();
        pfx.WriteOctetString(auth.Encode());
        pfx.Pop();
        pfx.Pop();
        pfx.Pop();
        Pkcs12File f = Pkcs12File.Parse(pfx.Encode());
        Assert.Equal(PkcsStatus.LimitExceeded, f.TryOpen(string.Empty, out _, requireMac: false));
    }

    private static byte[] Seq()
    {
        var w = new Asn1Writer();
        w.PushSequence();
        w.Pop();
        return w.Encode();
    }
}
