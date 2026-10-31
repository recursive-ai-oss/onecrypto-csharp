using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.X509;

/// <summary>Two-way checks against the openssl command-line program, used as a compiled program only.</summary>
public class OpenSslInteropTests
{
    private static string Dir(string name) => OpenSslTool.TempDir(name);

    private static void Ok((int Code, string Output) r, string what)
    {
        Assert.True(r.Code == 0, $"{what}: {r.Output}");
    }

    public static IEnumerable<object[]> OurKinds() => Enum.GetValues<KeyKind>().Where(TestKey.IsAvailable).Select(k => new object[] { k });

    private static bool CanDo(KeyKind k) => k != KeyKind.MlDsa65 || OpenSslTool.Has("ML-DSA-65");

    [Theory]
    [MemberData(nameof(OurKinds))]
    public void OpenSslAcceptsTheRequestsWeBuild(KeyKind kind)
    {
        OpenSslTool.RequireOrSkip();
        Assert.SkipUnless(CanDo(kind), "openssl lacks the algorithm");
        string dir = Dir("csr");
        using var key = new TestKey(kind);
        CertificateSigningRequest csr = CertificateSigningRequestBuilder.Create(
            new CertificateSigningRequestOptions
            {
                Subject = DistinguishedName.Create((KnownOids.Country, "DE"), (KnownOids.Organization, "Org"), (KnownOids.CommonName, "csr.example.test")),
                Extensions = [Extension.Create(new SubjectAlternativeName([GeneralName.Dns("csr.example.test")]), false)],
            },
            key.Signer);
        Assert.True(csr.VerifySignature().IsValid);
        Assert.Equal("csr.example.test", csr.RequestedExtensions.Get<SubjectAlternativeName>()!.Names[0].Value);
        string path = Path.Combine(dir, kind + ".csr.pem");
        File.WriteAllText(path, csr.ToPem());
        (int code, string text) = OpenSslTool.Run("req", "-in", path, "-noout", "-verify", "-text");
        Assert.True(code == 0 && text.Contains("verify OK", StringComparison.Ordinal), text);
        Assert.Contains("DNS:csr.example.test", text, StringComparison.Ordinal);
    }

    public static IEnumerable<object[]> OpenSslKeys() =>
    [
        ["rsa:2048", ""],
        ["ec", "ec_paramgen_curve:P-256"],
        ["ec", "ec_paramgen_curve:P-384"],
        ["ec", "ec_paramgen_curve:brainpoolP256r1"],
        ["ed25519", ""],
        ["ed448", ""],
        ["ML-DSA-65", ""],
        ["ML-DSA-44", ""],
    ];

    private static (string KeyPem, bool Ok) GenKey(string dir, string alg, string opt, string name)
    {
        string key = Path.Combine(dir, name + ".key");
        var args = new List<string> { "genpkey", "-algorithm", alg.StartsWith("rsa:", StringComparison.Ordinal) ? "RSA" : alg, "-out", key };
        if (alg.StartsWith("rsa:", StringComparison.Ordinal))
        {
            args.AddRange(["-pkeyopt", "rsa_keygen_bits:2048"]);
        }

        if (opt.Length > 0)
        {
            args.AddRange(["-pkeyopt", opt]);
        }

        (int code, _) = OpenSslTool.Run([.. args]);
        return (key, code == 0);
    }

    [Theory]
    [MemberData(nameof(OpenSslKeys))]
    public void WeReadTheRequestsAndCertificatesOpenSslBuilds(string alg, string opt)
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("fromssl");
        string tag = (alg + opt).Replace(':', '-').Replace('_', '-');
        (string key, bool ok) = GenKey(dir, alg, opt, tag);
        Assert.SkipUnless(ok, "openssl cannot make this key here");

        string csrPath = Path.Combine(dir, tag + ".csr");
        Ok(OpenSslTool.Run("req", "-new", "-key", key, "-subj", "/C=US/O=Ossl Org/CN=ossl.example.test", "-addext", "subjectAltName=DNS:ossl.example.test,IP:192.0.2.9", "-out", csrPath), "req");
        CertificateSigningRequest csr = CertificateSigningRequest.FromPem(File.ReadAllText(csrPath));
        Assert.Equal("CN=ossl.example.test,O=Ossl Org,C=US", csr.Subject.ToString());
        Assert.Equal(["DNS:ossl.example.test", "IP:192.0.2.9"], csr.RequestedExtensions.Get<SubjectAlternativeName>()!.Names.Select(n => n.ToString()));
        SignatureVerification v = csr.VerifySignature();
        Assert.True(v.IsValid || (alg.StartsWith("ed", StringComparison.Ordinal) && v.Status == SignatureStatus.AlgorithmNotSupported), v.Status + " " + v.Reason);

        string certPath = Path.Combine(dir, tag + ".pem");
        Ok(OpenSslTool.Run("req", "-x509", "-new", "-key", key, "-days", "30", "-subj", "/CN=ossl.example.test", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=keyCertSign,cRLSign", "-out", certPath), "req -x509");
        Certificate cert = Certificate.FromPem(File.ReadAllText(certPath));
        Assert.True(cert.IsDer);
        Assert.Equal(3, cert.Version);
        Assert.True(cert.BasicConstraints!.IsCA);
        Assert.Equal(KeyUsages.KeyCertSign | KeyUsages.CrlSign, cert.KeyUsage!.Usages);
        SignatureVerification sv = cert.VerifySignature(cert.PublicKey);
        Assert.True(sv.IsValid || (alg.StartsWith("ed", StringComparison.Ordinal) && sv.Status == SignatureStatus.AlgorithmNotSupported), sv.Status + " " + sv.Reason);
        if (cert.TryToX509Certificate2(out X509Certificate2? bcl))
        {
            using (bcl)
            {
                Assert.Equal(bcl!.SubjectName.RawData, cert.Subject.Encoded.ToArray());
                Assert.Equal(bcl.PublicKey.EncodedKeyValue.RawData, cert.PublicKey.KeyBits.ToArray());
            }
        }
    }

    [Fact]
    public void OpenSslAcceptsTheCrlsWeBuildAndWeReadItsCrls()
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("crl");
        using var rootKey = new TestKey(KeyKind.EcP256);
        Certificate root = Pki.Root(rootKey);
        var revoked = new List<RevokedCertificateInfo>
        {
            new(0x1234, Pki.Now, RevocationReason.KeyCompromise, Pki.Now.AddDays(-3)),
            new(BigInteger.Pow(2, 150), Pki.Now.AddHours(1)),
            new(77, Pki.Now.AddHours(2), RevocationReason.CertificateHold),
        };
        CertificateRevocationList crl = RevocationListBuilder.Create(
            new RevocationListOptions { ThisUpdate = Pki.Now, NextUpdate = Pki.Now.AddDays(7), Revoked = revoked, Number = 5 }, rootKey.Signer, root);
        CertificateRevocationList delta = RevocationListBuilder.Create(
            new RevocationListOptions { ThisUpdate = Pki.Now, NextUpdate = Pki.Now.AddDays(1), Revoked = revoked.Take(1).ToList(), Number = 6, DeltaBaseNumber = 5 }, rootKey.Signer, root);

        Assert.True(crl.VerifySignature(root).IsValid);
        Assert.Equal(3, crl.Entries.Count());
        Assert.Equal(RevocationReason.KeyCompromise, crl.Find(new byte[] { 0x12, 0x34 })!.Reason);
        Assert.Null(crl.Find(new byte[] { 0x99 }));
        Assert.Equal((BigInteger)5, crl.Number);
        Assert.False(crl.IsDelta);
        Assert.True(delta.IsDelta);
        Assert.Equal((BigInteger)5, delta.BaseNumber);
        Assert.Equal(crl.Issuer, root.Subject);

        File.WriteAllText(Path.Combine(dir, "root.pem"), root.ToPem());
        foreach ((string name, CertificateRevocationList c) in new[] { ("full", crl), ("delta", delta) })
        {
            string p = Path.Combine(dir, name + ".crl.pem");
            File.WriteAllText(p, c.ToPem());
            (int code, string text) = OpenSslTool.Run("crl", "-in", p, "-noout", "-text", "-CAfile", Path.Combine(dir, "root.pem"));
            Assert.True(code == 0 && text.Contains("verify OK", StringComparison.Ordinal), text);
            Assert.Contains("Key Compromise", text, StringComparison.Ordinal);
        }

        // OpenSSL issues one: a throwaway CA directory.
        string ca = Path.Combine(dir, "ca");
        Directory.CreateDirectory(ca);
        File.WriteAllText(Path.Combine(ca, "index.txt"), "R\t270101000000Z\t260601000000Z,keyCompromise\t0A\tunknown\t/CN=revoked\nV\t270101000000Z\t\t0B\tunknown\t/CN=good\n");
        File.WriteAllText(Path.Combine(ca, "crlnumber"), "0F\n");
        File.WriteAllText(Path.Combine(ca, "openssl.cnf"), "[ca]\ndefault_ca=c\n[c]\ndatabase=index.txt\ncrlnumber=crlnumber\ndefault_md=sha256\ndefault_crl_days=7\npolicy=p\n[p]\ncommonName=supplied\n");
        Ok(OpenSslTool.RunIn(ca, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Ossl CA", "-days", "30"), "ca");
        Ok(OpenSslTool.RunIn(ca, "ca", "-config", "openssl.cnf", "-gencrl", "-keyfile", "ca.key", "-cert", "ca.pem", "-out", "ossl.crl.pem", "-batch"), "gencrl");
        CertificateRevocationList theirs = CertificateRevocationList.FromPem(File.ReadAllText(Path.Combine(ca, "ossl.crl.pem")));
        Certificate caCert = Certificate.FromPem(File.ReadAllText(Path.Combine(ca, "ca.pem")));
        Assert.True(theirs.VerifySignature(caCert).IsValid);
        Assert.Equal((BigInteger)15, theirs.Number);
        RevokedCertificate entry = Assert.Single(theirs.Entries);
        Assert.Equal((BigInteger)10, entry.SerialNumberValue);
        Assert.Equal(RevocationReason.KeyCompromise, entry.Reason);
        Assert.Equal(new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero), entry.RevocationDate);
    }

    [Fact]
    public void OcspMessagesGoBothWays()
    {
        OpenSslTool.RequireOrSkip();
        string dir = Dir("ocsp");
        using var rootKey = new TestKey(KeyKind.EcP256);
        using var leafKey = new TestKey(KeyKind.EcP256);
        using var responderKey = new TestKey(KeyKind.EcP256);
        Certificate root = Pki.Root(rootKey);
        Certificate leaf = Pki.Leaf(leafKey, root, rootKey);
        Certificate responder = CertificateBuilder.Create(
            new CertificateOptions
            {
                Subject = DistinguishedName.Create((KnownOids.CommonName, "Responder")),
                PublicKey = responderKey.Signer.PublicKey,
                NotBefore = Pki.Now.AddDays(-1),
                NotAfter = Pki.Now.AddYears(1),
                Extensions = [Extension.Create(new ExtendedKeyUsage([KnownOids.OcspSigning]), true), Extension.Create(new OcspNoCheck(), false)],
            },
            root,
            rootKey.Signer);
        File.WriteAllText(Path.Combine(dir, "root.pem"), root.ToPem());
        File.WriteAllText(Path.Combine(dir, "leaf.pem"), leaf.ToPem());
        File.WriteAllText(Path.Combine(dir, "responder.pem"), responder.ToPem());

        OcspCertId id = OcspCertId.Create(leaf, root);
        Assert.True(id.Matches(leaf, root));
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        OcspRequest request = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [id], Nonce = nonce });
        Assert.Equal(nonce, request.Nonce!.Value.ToArray());
        File.WriteAllBytes(Path.Combine(dir, "ours.req"), request.Encoded.ToArray());
        (int code, string text) = OpenSslTool.Run("ocsp", "-reqin", Path.Combine(dir, "ours.req"), "-text");
        Assert.True(code == 0, text);
        Assert.Contains("OCSP Request Data", text, StringComparison.Ordinal);
        Assert.Contains("Nonce", text, StringComparison.Ordinal);

        // A request OpenSSL builds reads in ours with the same certificate identity.
        Ok(OpenSslTool.Run("ocsp", "-issuer", Path.Combine(dir, "root.pem"), "-cert", Path.Combine(dir, "leaf.pem"), "-reqout", Path.Combine(dir, "theirs.req")), "reqout");
        OcspRequest theirReq = OcspRequest.Parse(File.ReadAllBytes(Path.Combine(dir, "theirs.req")));
        Assert.True(theirReq.Requests[0].CertId.Matches(leaf, root));
        Assert.Equal(id, theirReq.Requests[0].CertId);
        Assert.NotNull(theirReq.Nonce);

        // Our response, checked by OpenSSL.
        OcspResponse response = OcspResponseBuilder.CreateSuccessful(
            new OcspResponseOptions
            {
                Responder = new OcspResponderId(responder.Subject),
                ProducedAt = Pki.Now,
                Responses = [new OcspSingleResponseInfo(id, OcspCertStatus.Revoked, Pki.Now, Pki.Now.AddDays(1), Pki.Now.AddHours(-5), RevocationReason.KeyCompromise)],
                Nonce = nonce,
                Certificates = [responder],
            },
            responderKey.Signer);
        OcspBasicResponse basic = response.BasicResponse!;
        Assert.True(basic.VerifySignature(responder.PublicKey).IsValid);
        Assert.True(basic.ResponderId.Matches(responder));
        Assert.Equal(OcspCertStatus.Revoked, basic.Responses[0].Status);
        File.WriteAllBytes(Path.Combine(dir, "ours.resp"), response.Encoded.ToArray());
        (code, text) = OpenSslTool.Run("ocsp", "-respin", Path.Combine(dir, "ours.resp"), "-reqin", Path.Combine(dir, "ours.req"), "-CAfile", Path.Combine(dir, "root.pem"), "-VAfile", Path.Combine(dir, "responder.pem"), "-no_cert_checks", "-attime", Pki.Now.ToUnixTimeSeconds().ToString());
        Assert.True(code == 0, text);
        Assert.Contains("Response verify OK", text, StringComparison.Ordinal);
        (code, text) = OpenSslTool.Run("ocsp", "-respin", Path.Combine(dir, "ours.resp"), "-resp_text", "-noverify");
        Assert.Contains("revoked", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("keyCompromise", text, StringComparison.Ordinal);

        // OpenSSL answers our request; we read and verify it.
        string index = Path.Combine(dir, "index.txt");
        string serialHex = Convert.ToHexString(leaf.SerialNumber.Span.ToArray().SkipWhile(b => b == 0).ToArray());
        File.WriteAllText(index, $"V\t270101000000Z\t\t{serialHex}\tunknown\t/CN=leaf\n");
        string respKey = Path.Combine(dir, "responder.key");
        File.WriteAllText(respKey, ExportKey(responderKey).ExportPkcs8PrivateKeyPem());
        Ok(OpenSslTool.Run("ocsp", "-index", index, "-CA", Path.Combine(dir, "root.pem"), "-rsigner", Path.Combine(dir, "responder.pem"), "-rkey", respKey, "-reqin", Path.Combine(dir, "ours.req"), "-respout", Path.Combine(dir, "theirs.resp"), "-ndays", "1"), "ocsp responder");
        OcspResponse theirs = OcspResponse.Parse(File.ReadAllBytes(Path.Combine(dir, "theirs.resp")));
        Assert.Equal(OcspResponseStatus.Successful, theirs.Status);
        OcspBasicResponse tb = theirs.BasicResponse!;
        Assert.Equal(OcspCertStatus.Good, tb.Responses[0].Status);
        Assert.True(tb.Responses[0].CertId.Matches(leaf, root));
        Assert.NotNull(tb.Nonce);
        Assert.Equal(nonce, tb.Nonce!.Value.ToArray());
        Assert.True(tb.VerifySignature(responder.PublicKey).IsValid);
        Assert.Single(tb.Certificates);

        OcspResponse err = OcspResponseBuilder.CreateError(OcspResponseStatus.Unauthorized);
        File.WriteAllBytes(Path.Combine(dir, "err.resp"), err.Encoded.ToArray());
        (code, text) = OpenSslTool.Run("ocsp", "-respin", Path.Combine(dir, "err.resp"), "-resp_text");
        Assert.Contains("unauthorized", text, StringComparison.OrdinalIgnoreCase);
        Assert.Null(OcspResponse.Parse(err.Encoded).BasicResponse);
    }

    private static ECDsa ExportKey(TestKey k) => k.Ec!;
}
