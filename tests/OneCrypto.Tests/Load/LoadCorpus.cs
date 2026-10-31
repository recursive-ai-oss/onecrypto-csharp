using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;

namespace OneCrypto.Tests.Load;

/// <summary>What a corpus file must load as.</summary>
internal enum Expect
{
    PrivateKey,
    PublicKey,
    Certificate,
    Crl,
    Csr,
    Ocsp,
    P7b,
    P12,
    SshPrivate,
    SshPublic,
    SshCertificate,
}

/// <summary>One generated file: its bytes, how it is counted, what it must load as, and the password it needs.</summary>
internal sealed record CorpusCase(string Name, string Format, byte[] Data, Expect Expect, KeyAlgorithm? Algorithm = null, string? Password = null, byte[]? ExpectedSpki = null, int Certificates = 0);

/// <summary>
/// Generates the load corpus with openssl and ssh-keygen as black boxes, and with the platform's own exporters. Nothing here is
/// committed as data: the generator is the fixture.
/// </summary>
internal static class LoadCorpus
{
    public const string Password = "hunter2 pässwörd";

    private static readonly (string Name, KeyAlgorithm Algorithm, string[] Gen)[] KeyTypes =
    [
        ("rsa", KeyAlgorithm.Rsa, ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
        ("p256", KeyAlgorithm.EllipticCurve, ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
        ("p384", KeyAlgorithm.EllipticCurve, ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"]),
        ("p521", KeyAlgorithm.EllipticCurve, ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"]),
        ("ed25519", KeyAlgorithm.Ed25519, ["-algorithm", "ED25519"]),
        ("ed448", KeyAlgorithm.Ed448, ["-algorithm", "ED448"]),
        ("x25519", KeyAlgorithm.X25519, ["-algorithm", "X25519"]),
        ("x448", KeyAlgorithm.X448, ["-algorithm", "X448"]),
        ("mldsa65", KeyAlgorithm.MlDsa, ["-algorithm", "ML-DSA-65"]),
        ("mlkem768", KeyAlgorithm.MlKem, ["-algorithm", "ML-KEM-768"]),
    ];

    private static string Pw => "pass:" + Password;

    public static List<CorpusCase> Build(string dir)
    {
        var cases = new List<CorpusCase>();
        Directory.CreateDirectory(dir);
        if (OpenSslTool.Available)
        {
            BuildOpenSsl(dir, cases);
        }

        BuildDotNet(cases);
        string? keygen = ToolRunner.Find("ssh-keygen");
        if (keygen is not null)
        {
            BuildSsh(keygen, dir, cases);
        }

        foreach (CorpusCase c in cases)
        {
            File.WriteAllBytes(Path.Combine(dir, c.Name), c.Data);
        }

        return cases;
    }

    private static void Ok((int Code, string Output) r, string what) => Assert.True(r.Code == 0, what + ": " + r.Output);

    private static void BuildOpenSsl(string dir, List<CorpusCase> cases)
    {
        void Add(string name, string format, Expect expect, KeyAlgorithm? alg = null, string? pw = null, byte[]? spki = null, int certs = 0) =>
            cases.Add(new CorpusCase(name, format, File.ReadAllBytes(Path.Combine(dir, name)), expect, alg, pw, spki, certs));

        string O(string name) => Path.Combine(dir, name);
        void Run(params string[] args) => Ok(OpenSslTool.RunIn(dir, args), string.Join(' ', args));

        foreach ((string n, KeyAlgorithm alg, string[] gen) in KeyTypes)
        {
            if (alg is KeyAlgorithm.MlDsa or KeyAlgorithm.MlKem && !OpenSslTool.Has(alg == KeyAlgorithm.MlDsa ? "ML-DSA-65" : "ML-KEM-768"))
            {
                continue;
            }

            Run(["genpkey", .. gen, "-out", n + ".pk8.pem"]);
            Run("pkey", "-in", n + ".pk8.pem", "-pubout", "-outform", "DER", "-out", n + ".spki.der");
            byte[] spki = File.ReadAllBytes(O(n + ".spki.der"));
            Run("pkey", "-in", n + ".pk8.pem", "-outform", "DER", "-out", n + ".pk8.der");
            Run("pkey", "-in", n + ".pk8.pem", "-pubout", "-out", n + ".pub.pem");
            Run("pkey", "-in", n + ".pk8.pem", "-pubout", "-outform", "DER", "-out", n + ".pub.der");
            Run("pkey", "-in", n + ".pk8.pem", "-aes-256-cbc", "-passout", Pw, "-out", n + ".enc.pem");
            Run("pkcs8", "-topk8", "-in", n + ".pk8.pem", "-v2", "aes-256-cbc", "-passout", Pw, "-outform", "DER", "-out", n + ".enc.der");
            Run("pkcs8", "-topk8", "-in", n + ".pk8.pem", "-scrypt", "-v2", "aes-256-cbc", "-passout", Pw, "-out", n + ".scrypt.pem");
            Add(n + ".pk8.pem", "pem-pkcs8", Expect.PrivateKey, alg, null, spki);
            Add(n + ".pk8.der", "der-pkcs8", Expect.PrivateKey, alg, null, spki);
            Add(n + ".enc.pem", "pem-pkcs8-encrypted", Expect.PrivateKey, alg, Password, spki);
            Add(n + ".enc.der", "der-pkcs8-encrypted", Expect.PrivateKey, alg, Password, spki);
            Add(n + ".scrypt.pem", "pem-pkcs8-scrypt", Expect.PrivateKey, alg, Password, spki);
            Add(n + ".pub.pem", "pem-spki", Expect.PublicKey, alg, null, spki);
            Add(n + ".pub.der", "der-spki", Expect.PublicKey, alg, null, spki);

            if (alg is KeyAlgorithm.Rsa or KeyAlgorithm.EllipticCurve)
            {
                Run("pkey", "-in", n + ".pk8.pem", "-traditional", "-out", n + ".trad.pem");
                Run("pkey", "-in", n + ".pk8.pem", "-traditional", "-outform", "DER", "-out", n + ".trad.der");
                Run("pkey", "-in", n + ".pk8.pem", "-traditional", "-aes-128-cbc", "-passout", Pw, "-out", n + ".dek.pem");
                Run("pkey", "-in", n + ".pk8.pem", "-traditional", "-des3", "-passout", Pw, "-out", n + ".dek3.pem");
                Add(n + ".trad.pem", "pem-traditional", Expect.PrivateKey, alg, null, spki);
                Add(n + ".trad.der", "der-traditional", Expect.PrivateKey, alg, null, spki);
                Add(n + ".dek.pem", "pem-dek-info", Expect.PrivateKey, alg, Password, spki);
                Add(n + ".dek3.pem", "pem-dek-info", Expect.PrivateKey, alg, Password, spki);
            }

            if (alg == KeyAlgorithm.Rsa)
            {
                Run("rsa", "-in", n + ".pk8.pem", "-RSAPublicKey_out", "-out", n + ".rsapub.pem");
                Run("rsa", "-in", n + ".pk8.pem", "-RSAPublicKey_out", "-outform", "DER", "-out", n + ".rsapub.der");
                Add(n + ".rsapub.pem", "pem-rsa-public", Expect.PublicKey, alg, null, spki);
                Add(n + ".rsapub.der", "der-rsa-public", Expect.PublicKey, alg, null, spki);
            }
        }

        // Certificates, requests, bags and containers: signing keys only.
        foreach (string n in new[] { "rsa", "p256", "p384", "ed25519", "ed448", "mldsa65" })
        {
            if (!File.Exists(O(n + ".pk8.pem")))
            {
                continue;
            }

            KeyAlgorithm alg = KeyTypes.First(k => k.Name == n).Algorithm;
            byte[] spki = File.ReadAllBytes(O(n + ".spki.der"));
            Run("req", "-x509", "-key", n + ".pk8.pem", "-subj", "/CN=" + n, "-days", "30", "-out", n + ".cert.pem");
            Run("x509", "-in", n + ".cert.pem", "-outform", "DER", "-out", n + ".cert.der");
            Run("req", "-new", "-key", n + ".pk8.pem", "-subj", "/CN=" + n, "-out", n + ".csr.pem");
            Run("req", "-in", n + ".csr.pem", "-outform", "DER", "-out", n + ".csr.der");
            Add(n + ".cert.pem", "pem-certificate", Expect.Certificate, alg, null, spki);
            Add(n + ".cert.der", "der-certificate", Expect.Certificate, alg, null, spki);
            Add(n + ".csr.pem", "pem-csr", Expect.Csr, alg, null, spki);
            Add(n + ".csr.der", "der-csr", Expect.Csr, alg, null, spki);
        }

        foreach (string n in new[] { "rsa", "p256" })
        {
            Run("x509", "-in", n + ".cert.pem", "-text", "-out", n + ".cert.text.pem");
            Run("x509", "-in", n + ".cert.pem", "-trustout", "-out", n + ".cert.trusted.pem");
            Add(n + ".cert.text.pem", "pem-certificate-with-text", Expect.Certificate, null, null, File.ReadAllBytes(O(n + ".spki.der")));
            Add(n + ".cert.trusted.pem", "pem-trusted-certificate", Expect.Certificate, null, null, File.ReadAllBytes(O(n + ".spki.der")));
        }

        // A PKCS#7 certificate bag (what .p7b holds) of two certificates, PEM and DER.
        File.WriteAllText(O("bundle.pem"), File.ReadAllText(O("rsa.cert.pem")) + File.ReadAllText(O("p256.cert.pem")));
        Run("crl2pkcs7", "-nocrl", "-certfile", "bundle.pem", "-out", "bag.p7b.pem");
        Run("crl2pkcs7", "-nocrl", "-certfile", "bundle.pem", "-outform", "DER", "-out", "bag.p7b.der");
        Add("bundle.pem", "pem-certificate-chain", Expect.Certificate, certs: 2);
        Add("bag.p7b.pem", "pem-pkcs7", Expect.P7b, certs: 2);
        Add("bag.p7b.der", "der-pkcs7", Expect.P7b, certs: 2);

        // PKCS#12: the default, and the older 3DES/SHA-1 protection that legacy tools write.
        Run("pkcs12", "-export", "-inkey", "rsa.pk8.pem", "-in", "rsa.cert.pem", "-certfile", "p256.cert.pem", "-out", "default.p12", "-passout", Pw);
        Run("pkcs12", "-export", "-inkey", "p256.pk8.pem", "-in", "p256.cert.pem", "-out", "legacy-pbe.p12", "-passout", Pw, "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1");
        Run("pkcs12", "-export", "-inkey", "ed25519.pk8.pem", "-in", "ed25519.cert.pem", "-out", "empty-password.p12", "-passout", "pass:");
        Add("default.p12", "pkcs12", Expect.P12, KeyAlgorithm.Rsa, Password, File.ReadAllBytes(O("rsa.spki.der")), 2);
        Add("legacy-pbe.p12", "pkcs12-legacy", Expect.P12, KeyAlgorithm.EllipticCurve, Password, File.ReadAllBytes(O("p256.spki.der")), 1);
        Add("empty-password.p12", "pkcs12-empty-password", Expect.P12, KeyAlgorithm.Ed25519, null, File.ReadAllBytes(O("ed25519.spki.der")), 1);
        if (OpenSslTool.RunIn(dir, "pkcs12", "-export", "-legacy", "-inkey", "rsa.pk8.pem", "-in", "rsa.cert.pem", "-out", "legacy.p12", "-passout", Pw).Code == 0)
        {
            Add("legacy.p12", "pkcs12-legacy", Expect.P12, KeyAlgorithm.Rsa, Password, File.ReadAllBytes(O("rsa.spki.der")), 1);
        }

        // A CRL and an OCSP response from a throwaway CA directory.
        string ca = O("ca");
        Directory.CreateDirectory(ca);
        File.WriteAllText(Path.Combine(ca, "index.txt"), "R\t270101000000Z\t260601000000Z,keyCompromise\t0A\tunknown\t/CN=revoked\nV\t270101000000Z\t\t0B\tunknown\t/CN=good\n");
        File.WriteAllText(Path.Combine(ca, "crlnumber"), "0F\n");
        File.WriteAllText(Path.Combine(ca, "openssl.cnf"), "[ca]\ndefault_ca=c\n[c]\ndatabase=index.txt\ncrlnumber=crlnumber\ndefault_md=sha256\ndefault_crl_days=7\npolicy=p\n[p]\ncommonName=supplied\n");
        Ok(OpenSslTool.RunIn(ca, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Load CA", "-days", "30"), "ca");
        Ok(OpenSslTool.RunIn(ca, "ca", "-config", "openssl.cnf", "-gencrl", "-keyfile", "ca.key", "-cert", "ca.pem", "-out", "crl.pem", "-batch"), "gencrl");
        Ok(OpenSslTool.RunIn(ca, "crl", "-in", "crl.pem", "-outform", "DER", "-out", "crl.der"), "crl der");
        File.Copy(Path.Combine(ca, "crl.pem"), O("ca.crl.pem"), true);
        File.Copy(Path.Combine(ca, "crl.der"), O("ca.crl.der"), true);
        Add("ca.crl.pem", "pem-crl", Expect.Crl);
        Add("ca.crl.der", "der-crl", Expect.Crl);
        Ok(OpenSslTool.RunIn(ca, "ocsp", "-issuer", "ca.pem", "-cert", "ca.pem", "-reqout", "req.der"), "ocsp req");
        (int oc, string oo) = OpenSslTool.RunIn(ca, "ocsp", "-index", "index.txt", "-rsigner", "ca.pem", "-rkey", "ca.key", "-CA", "ca.pem", "-reqin", "req.der", "-respout", "resp.der");
        if (oc == 0)
        {
            File.Copy(Path.Combine(ca, "resp.der"), O("ocsp.resp.der"), true);
            Add("ocsp.resp.der", "der-ocsp-response", Expect.Ocsp);
        }
        else
        {
            Assert.Fail("ocsp: " + oo);
        }
    }

    private static void BuildDotNet(List<CorpusCase> cases)
    {
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 2000);
        foreach ((string n, AsymmetricAlgorithm k, KeyAlgorithm alg) in new (string, AsymmetricAlgorithm, KeyAlgorithm)[] { ("net-rsa", rsa, KeyAlgorithm.Rsa), ("net-p256", ec, KeyAlgorithm.EllipticCurve) })
        {
            byte[] spki = k.ExportSubjectPublicKeyInfo();
            cases.Add(new CorpusCase(n + ".pk8.der", "der-pkcs8", k.ExportPkcs8PrivateKey(), Expect.PrivateKey, alg, null, spki));
            cases.Add(new CorpusCase(n + ".pk8.pem", "pem-pkcs8", Encoding.ASCII.GetBytes(k.ExportPkcs8PrivateKeyPem()), Expect.PrivateKey, alg, null, spki));
            cases.Add(new CorpusCase(n + ".enc.der", "der-pkcs8-encrypted", k.ExportEncryptedPkcs8PrivateKey(Password, pbe), Expect.PrivateKey, alg, Password, spki));
            cases.Add(new CorpusCase(n + ".enc.pem", "pem-pkcs8-encrypted", Encoding.ASCII.GetBytes(k.ExportEncryptedPkcs8PrivateKeyPem(Password, pbe)), Expect.PrivateKey, alg, Password, spki));
            cases.Add(new CorpusCase(n + ".pub.pem", "pem-spki", Encoding.ASCII.GetBytes(k.ExportSubjectPublicKeyInfoPem()), Expect.PublicKey, alg, null, spki));
        }

        cases.Add(new CorpusCase("net-rsa.rsapriv.der", "der-traditional", rsa.ExportRSAPrivateKey(), Expect.PrivateKey, KeyAlgorithm.Rsa, null, rsa.ExportSubjectPublicKeyInfo()));
        cases.Add(new CorpusCase("net-p256.ecpriv.der", "der-traditional", ec.ExportECPrivateKey(), Expect.PrivateKey, KeyAlgorithm.EllipticCurve, null, ec.ExportSubjectPublicKeyInfo()));

        var req = new CertificateRequest("CN=net-rsa", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        byte[] rsaSpki = rsa.ExportSubjectPublicKeyInfo();
        cases.Add(new CorpusCase("net-rsa.cert.der", "der-certificate", cert.RawData, Expect.Certificate, KeyAlgorithm.Rsa, null, rsaSpki));
        cases.Add(new CorpusCase("net-rsa.csr.der", "der-csr", req.CreateSigningRequest(), Expect.Csr, KeyAlgorithm.Rsa, null, rsaSpki));
        cases.Add(new CorpusCase("net-rsa.p12", "pkcs12", cert.Export(X509ContentType.Pfx, Password), Expect.P12, KeyAlgorithm.Rsa, Password, rsaSpki, 1));
        cases.Add(new CorpusCase("net-rsa-aes.p12", "pkcs12", cert.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, Password), Expect.P12, KeyAlgorithm.Rsa, Password, rsaSpki, 1));
        cases.Add(new CorpusCase("net-rsa-nopw.p12", "pkcs12-empty-password", cert.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, ""), Expect.P12, KeyAlgorithm.Rsa, null, rsaSpki, 1));
    }

    private static void BuildSsh(string keygen, string dir, List<CorpusCase> cases)
    {
        string sdir = Path.Combine(dir, "ssh");
        Directory.CreateDirectory(sdir);
        string K(params string[] args)
        {
            (int code, string output) = ToolRunner.Run(keygen, sdir, args);
            return code == 0 ? output : throw new InvalidOperationException("ssh-keygen " + string.Join(' ', args) + ": " + output);
        }

        K("-q", "-t", "ed25519", "-N", "", "-C", "ca", "-f", "ca");
        foreach ((string type, KeyAlgorithm alg, string[] extra) in new (string, KeyAlgorithm, string[])[]
        {
            ("rsa", KeyAlgorithm.Rsa, ["-b", "2048"]),
            ("ecdsa", KeyAlgorithm.EllipticCurve, []),
            ("ed25519", KeyAlgorithm.Ed25519, []),
        })
        {
            foreach (string pass in new[] { "", Password })
            {
                string name = $"id_{type}{(pass.Length > 0 ? "_pw" : string.Empty)}";
                K(["-q", "-t", type, .. extra, "-N", pass, "-C", "comment " + name, "-f", name]);
                byte[] spki = ssh_spki(name);
                cases.Add(new CorpusCase("ssh-" + name, pass.Length > 0 ? "openssh-private-encrypted" : "openssh-private", File.ReadAllBytes(Path.Combine(sdir, name)), Expect.SshPrivate, alg, pass.Length > 0 ? pass : null, spki));
            }

            string pub = $"id_{type}.pub";
            cases.Add(new CorpusCase("ssh-" + pub, "openssh-public", File.ReadAllBytes(Path.Combine(sdir, pub)), Expect.SshPublic, alg));
            string rfc = K("-e", "-m", "RFC4716", "-f", pub);
            cases.Add(new CorpusCase($"ssh-id_{type}.rfc4716", "openssh-rfc4716", Encoding.ASCII.GetBytes(rfc), Expect.SshPublic, alg));
            K("-q", "-s", "ca", "-I", "id-" + type, "-n", "user", "-V", "+1d", pub);
            cases.Add(new CorpusCase($"ssh-id_{type}-cert.pub", "openssh-certificate", File.ReadAllBytes(Path.Combine(sdir, $"id_{type}-cert.pub")), Expect.SshCertificate));
        }

        string authorized = "# a comment\n" + File.ReadAllText(Path.Combine(sdir, "id_rsa.pub")) + "command=\"/bin/true\",no-pty " + File.ReadAllText(Path.Combine(sdir, "id_ed25519.pub")) + "\n" + File.ReadAllText(Path.Combine(sdir, "id_ecdsa.pub"));
        cases.Add(new CorpusCase("ssh-authorized_keys", "authorized_keys", Encoding.ASCII.GetBytes(authorized), Expect.SshPublic));

        byte[] ssh_spki(string name)
        {
            // The public key as SubjectPublicKeyInfo, from ssh-keygen's PKCS#8 export of the public half.
            string pubFile = Path.Combine(sdir, name + ".pub");
            if (name.Contains("ed25519", StringComparison.Ordinal))
            {
                // ssh-keygen cannot export Ed25519 as PKCS#8; RFC 8410 §4 gives the fixed prefix, and the key is the last 32 bytes of the blob.
                byte[] blob = Convert.FromBase64String(File.ReadAllText(pubFile).Split(' ')[1]);
                return [.. Convert.FromHexString("302a300506032b6570032100"), .. blob[^32..]];
            }

            return PemToDer(K("-e", "-m", "PKCS8", "-f", pubFile));
        }
    }

    private static byte[] PemToDer(string pem)
    {
        string[] lines = pem.Split('\n', StringSplitOptions.RemoveEmptyEntries).Where(l => !l.StartsWith("-----", StringComparison.Ordinal)).ToArray();
        return Convert.FromBase64String(string.Concat(lines).Trim());
    }
}
