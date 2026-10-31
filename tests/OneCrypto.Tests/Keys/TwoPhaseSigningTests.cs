using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OneCrypto.Tests.Support;
using OneCrypto.Tests.X509;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Keys;

public class TwoPhaseSigningTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Document = "a document that is signed somewhere else"u8.ToArray();

    private static string Dir(string name)
    {
        string d = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-twophase", name);
        Directory.CreateDirectory(d);
        return d;
    }

    /// <summary>Runs the signer program in a separate dotnet process on the serialised state and returns the signature it wrote.</summary>
    private static byte[] SignInOtherProcess(string dir, string kind, byte[] keyFile, byte[] state)
    {
        string signer = Directory.GetFiles(AppContext.BaseDirectory, "*TwoPhaseSigner.dll").Single();
        string keyPath = Path.Combine(dir, "key.bin"), statePath = Path.Combine(dir, "state.der"), sigPath = Path.Combine(dir, "sig.bin");
        File.WriteAllBytes(keyPath, keyFile);
        File.WriteAllBytes(statePath, state);
        File.Delete(sigPath);
        string? root = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        string dotnet = root is not null && File.Exists(Path.Combine(root, "dotnet")) ? Path.Combine(root, "dotnet") : "dotnet";
        var psi = new ProcessStartInfo(dotnet) { RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (string a in new[] { signer, kind, keyPath, statePath, sigPath })
        {
            psi.ArgumentList.Add(a);
        }

        using Process p = Process.Start(psi)!;
        Task<string> err = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, "signer process failed: " + err.Result);
        return File.ReadAllBytes(sigPath);
    }

    public static TheoryData<string> Kinds => ["rsa", "rsa-pss", "ecdsa", "ecdsa-p1363", "ed25519"];

    private sealed record Material(string Kind, byte[] KeyFile, PublicKeyInfo Public, SignatureSpec Spec, IDisposable Owner);

    private static Material Make(string kind)
    {
        switch (kind)
        {
            case "rsa" or "rsa-pss":
                var rsa = RSA.Create(2048);
                return new("rsa", rsa.ExportPkcs8PrivateKey(), PublicKeyInfo.FromAsymmetricAlgorithm(rsa), kind == "rsa" ? SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256) : SignatureSpec.RsaPss(HashAlgorithmName.SHA256), rsa);
            case "ecdsa" or "ecdsa-p1363":
                var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                return new("ecdsa", ec.ExportPkcs8PrivateKey(), PublicKeyInfo.FromAsymmetricAlgorithm(ec), SignatureSpec.Ecdsa(HashAlgorithmName.SHA256, kind == "ecdsa" ? EcdsaSignatureFormat.Der : EcdsaSignatureFormat.Rfc4754), ec);
            default:
                var ed = Ed25519PrivateKey.Generate();
                var seed = new byte[32];
                ed.ExportSeed(seed);
                using (ISigningKey k = PrivateKey.FromEd25519(ed))
                {
                    return new("ed25519", seed, k.PublicKey, SignatureSpec.Ed25519(), ed);
                }
        }
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public void RawSignatureIsCompletedAfterAnotherProcessSignsIt(string kind)
    {
        string dir = Dir("raw-" + kind);
        Material m = Make(kind);
        using (m.Owner)
        {
            // Process A: prepare and serialise. The signer process never sees the document for digest schemes.
            byte[] state = PreparedSignature.Prepare(m.Public, m.Spec, Document, CryptoPolicy.Standard, Now).Encode();

            byte[] signature = SignInOtherProcess(dir, m.Kind, m.KeyFile, state);

            // Process A again, later: reads the state back and completes.
            PreparedSignature restored = PreparedSignature.Decode(state);
            Assert.Equal(m.Spec.SignsDigest ? SigningInput.Digest : SigningInput.Message, restored.Input);
            byte[] done = restored.Complete(signature);
            Assert.Equal(signature, done);
            Assert.True(m.Spec.Verify(m.Public, Document, done).IsValid);
        }
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public void ATamperedOrWrongKeySignatureIsRefusedAtCompletion(string kind)
    {
        string dir = Dir("tamper-" + kind);
        Material m = Make(kind);
        Material other = Make(kind);
        using (m.Owner)
        using (other.Owner)
        {
            PreparedSignature state = PreparedSignature.Prepare(m.Public, m.Spec, Document, CryptoPolicy.Standard, Now);
            byte[] good = SignInOtherProcess(dir, m.Kind, m.KeyFile, state.Encode());

            byte[] flipped = (byte[])good.Clone();
            flipped[^1] ^= 0x01;
            Assert.False(state.TryComplete(flipped, out _, out SignatureVerification r1));
            Assert.NotEqual(SignatureStatus.Valid, r1.Status);

            byte[] wrongKey = SignInOtherProcess(dir, other.Kind, other.KeyFile, state.Encode());
            var e = Assert.Throws<InvalidSignatureException>(() => state.Complete(wrongKey));
            Assert.NotEmpty(e.Result.Reason);

            // A signature over other data (made with the right key) is refused too.
            PreparedSignature otherDoc = PreparedSignature.Prepare(m.Public, m.Spec, "another document"u8, CryptoPolicy.Standard, Now);
            byte[] forOther = SignInOtherProcess(dir, m.Kind, m.KeyFile, otherDoc.Encode());
            Assert.Throws<InvalidSignatureException>(() => state.Complete(forOther));

            state.Complete(good);
        }
    }

    [Fact]
    public void SignWithRefusesAKeyThatIsNotTheRecordedOne()
    {
        using RSA a = RSA.Create(2048);
        using RSA b = RSA.Create(2048);
        PreparedSignature s = PreparedSignature.Prepare(PublicKeyInfo.FromAsymmetricAlgorithm(a), SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256), Document, CryptoPolicy.Standard, Now);
        using ISigningKey wrong = PrivateKey.FromRsa(b);
        Assert.Throws<ArgumentException>(() => s.SignWith(wrong));
        using ISigningKey right = PrivateKey.FromRsa(a);
        Assert.True(SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256).Verify(s.PublicKey, Document, s.SignWith(right)).IsValid);
    }

    [Fact]
    public void ADigestOnlyStateCompletesWithoutTheDocument()
    {
        using RSA rsa = RSA.Create(2048);
        PublicKeyInfo pub = PublicKeyInfo.FromAsymmetricAlgorithm(rsa);
        SignatureSpec spec = SignatureSpec.RsaPss(HashAlgorithmName.SHA384);
        byte[] digest = SHA384.HashData(Document);
        PreparedSignature s = PreparedSignature.PrepareDigest(pub, spec, digest, CryptoPolicy.Standard, Now);
        Assert.True(s.Data.IsEmpty);
        using ISigningKey key = PrivateKey.FromRsa(rsa);
        byte[] sig = PreparedSignature.Decode(s.Encode()).SignWith(key);
        Assert.True(spec.Verify(pub, Document, sig).IsValid);
        Assert.Throws<InvalidSignatureException>(() => s.Complete(new byte[sig.Length]));
        Assert.Throws<ArgumentException>(() => PreparedSignature.PrepareDigest(pub, spec, new byte[10], CryptoPolicy.Standard, Now));
    }

    [Fact]
    public void ThePolicyDecidesAtPreparation()
    {
        using RSA rsa = RSA.Create(2048);
        PublicKeyInfo pub = PublicKeyInfo.FromAsymmetricAlgorithm(rsa);
        var e = Assert.Throws<PolicyViolationException>(() => PreparedSignature.Prepare(pub, SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA1), Document, CryptoPolicy.Standard, Now));
        Assert.Contains(e.Report.Decisions, d => d.Rule == "hash.sha-1.new");
        using RSA small = RSA.Create(1024);
        Assert.Throws<PolicyViolationException>(() => PreparedSignature.Prepare(PublicKeyInfo.FromAsymmetricAlgorithm(small), SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256), Document, CryptoPolicy.Standard, Now));
        Assert.Throws<ArgumentException>(() => PreparedSignature.Prepare(pub, SignatureSpec.Ed25519(), Document, CryptoPolicy.Standard, Now));
    }

    [Fact]
    public void TheStateIsVersionedAndDamageIsReported()
    {
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] der = PreparedSignature.Prepare(PublicKeyInfo.FromAsymmetricAlgorithm(ec), SignatureSpec.Ecdsa(HashAlgorithmName.SHA256), Document, CryptoPolicy.Standard, Now).Encode();
        Assert.True(PreparedSignature.TryDecode(der, out PreparedSignature? ok, out _));
        Assert.Equal(PreparedSignature.FormatVersion, 1);
        Assert.Equal("raw", ok!.Purpose);

        byte[] future = (byte[])der.Clone();
        int at = Array.IndexOf(future, (byte)0x02); // the version INTEGER 02 01 01 follows the SEQUENCE header
        Assert.Equal(1, future[at + 2]);
        future[at + 2] = 2;
        Assert.False(PreparedSignature.TryDecode(future, out _, out string? error));
        Assert.Contains("version 2", error);

        Assert.False(PreparedSignature.TryDecode(der.AsSpan(0, der.Length - 3), out _, out _));
        Assert.False(PreparedSignature.TryDecode([], out _, out _));
        Assert.Throws<FormatException>(() => PreparedSignature.Decode([0x30, 0x00]));
        for (int i = 0; i < der.Length; i++)
        {
            byte[] m = (byte[])der.Clone();
            m[i] ^= 0xFF;
            _ = PreparedSignature.TryDecode(m, out _, out _); // never throws
        }
    }

    [Fact]
    public void AStateWhoseSchemeDoesNotFitItsKeyIsRefusedAtDecoding()
    {
        // Found by fuzzing: an ML-DSA scheme over a key that is not an ML-DSA key used to reach the verifier and throw.
        byte[] state = Convert.FromBase64String("MGECAQEMA3JhdzAKAgEGDAACAQAEADAqMAUGAzBlcAMhALRbAugo4UjJ/LXSEe2sHDAFBgMrZXADIR4YG+1fMvV7CgECBA1zZWVkIGRvY3VtZW50BA1zZWVkIGRvY3VtZW50");
        Assert.False(PreparedSignature.TryDecode(state, out _, out string? error));
        Assert.Contains("does not fit", error);
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        SignatureVerification v = SignatureSpec.MlDsa().Verify(PublicKeyInfo.FromAsymmetricAlgorithm(ec), Document, new byte[64]);
        Assert.Equal(SignatureStatus.KeyMismatch, v.Status);
    }

    [Fact]
    public void ASpecWithFieldsThatDoNotApplyIsNotCanonicalAndIsRefused()
    {
        // Found by fuzzing: a P1363 format flag on an RSA scheme decoded, then re-encoded differently.
        byte[] state = Convert.FromBase64String("MIIBbAIBAQwIeDUwOS5jcmwwEAIBAQwGU0hBMjU2AgEBBAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwB4gAUA7vMdVMWiEPMNi34FNWoeugi70+4tIWvqvleSBQ5p+DE/ARofHVvuI5cfVkR72zr8f4IV/UMJdgpPssgM/HhuIjVBDOuVPOXct7a3AHKJ2UOjHRx2aDOLSEmwzza2p+HskXED52BW0lcgrOgSgS/yLRocjhMrElrg2zeXYer+U4t/9Zyxms3RHRx2aDOLSEmwzwkO2ytZ4XJLZ2ZXSGrurNx2MHVbpcYvf/07ijgh7W+sku7zHVTFohDzDYsMAAIBAAQAMCr//3iABQEEDAACAQEAAHgwKhUFBIACKwMhAJTciWbivn7Gh/jjpodOmLSjbiI1QQzrlTzl3Le2twByidlDo+EJAgMBAAEKAQEEIIdaTb+VexLPsSENQ6e8scvBrM4eoc+SsdRqFkzFKMWUBAA=");
        Assert.False(PreparedSignature.TryDecode(state, out _, out string? error));
        Assert.Contains("damaged", error);
    }

    [Theory]
    [InlineData("rsa")]
    [InlineData("ecdsa")]
    [InlineData("ed25519")]
    public void CertificateIsBuiltInTwoPhasesAcrossProcesses(string kind)
    {
        string dir = Dir("cert-" + kind);
        Material m = Make(kind);
        using (m.Owner)
        {
            var options = new CertificateOptions
            {
                Subject = DistinguishedName.FromString("CN=Two Phase Root,O=Test"),
                NotBefore = Now,
                NotAfter = Now.AddYears(2),
                Extensions = [Extension.Create(new BasicConstraints(true, null), true)],
            };
            PreparedSignature state = CertificateBuilder.PrepareSelfSigned(options, m.Public, m.Spec.Kind == SignatureKind.Ecdsa ? SignatureSpec.Ecdsa(HashAlgorithmName.SHA256) : m.Spec, CryptoPolicy.Standard, Now);
            Assert.Equal("x509.certificate", state.Purpose);
            byte[] encoded = state.Encode();

            byte[] signature = SignInOtherProcess(dir, m.Kind, m.KeyFile, encoded);

            Certificate cert = CertificateBuilder.Complete(PreparedSignature.Decode(encoded), signature);
            Assert.True(cert.IsSelfSigned);
            Assert.True(cert.VerifySignature(m.Public).IsValid);
            Assert.Equal(state.Spec.ToAlgorithmIdentifier(m.Public), cert.SignatureAlgorithm);
            Assert.Equal("CN=Two Phase Root,O=Test", cert.Subject.ToString());

            // A signature made for a different structure is refused.
            byte[] bad = (byte[])signature.Clone();
            bad[bad.Length / 2] ^= 0x40;
            Assert.Throws<InvalidSignatureException>(() => CertificateBuilder.Complete(state, bad));
            // A certificate state cannot complete a revocation list.
            Assert.Throws<ArgumentException>(() => RevocationListBuilder.Complete(state, signature));

            if (OpenSslTool.Available)
            {
                File.WriteAllText(Path.Combine(dir, "root.pem"), cert.ToPem());
                (int code, string output) = OpenSslTool.RunIn(dir, "verify", "-check_ss_sig", "-attime", Now.AddDays(1).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), "-CAfile", "root.pem", "root.pem");
                Assert.True(code == 0, output);
            }
        }
    }

    [Fact]
    public void RequestAndRevocationListAlsoBuildInTwoPhases()
    {
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ISigningKey key = PrivateKey.FromECDsa(ec);
        SignatureSpec spec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);

        PreparedSignature rq = CertificateSigningRequestBuilder.Prepare(new CertificateSigningRequestOptions { Subject = DistinguishedName.FromString("CN=req.test") }, key.PublicKey, spec, CryptoPolicy.Standard, Now);
        CertificateSigningRequest csr = CertificateSigningRequestBuilder.Complete(PreparedSignature.Decode(rq.Encode()), rq.SignWith(key));
        Assert.True(csr.VerifySignature().IsValid);

        PreparedSignature cl = RevocationListBuilder.Prepare(new RevocationListOptions { Issuer = DistinguishedName.FromString("CN=ca.test"), ThisUpdate = Now, Number = 3 }, key.PublicKey, spec, CryptoPolicy.Standard, Now);
        CertificateRevocationList crl = RevocationListBuilder.Complete(cl, cl.SignWith(key));
        Assert.True(crl.VerifySignature(key.PublicKey).IsValid);
        Assert.Throws<ArgumentException>(() => CertificateSigningRequestBuilder.Complete(cl, cl.SignWith(key)));
    }

    [Fact]
    public void IssuedCertificateInTwoPhasesIsSignedByTheIssuerKey()
    {
        using var rootKey = new TestKey(KeyKind.EcP256);
        using var leafKey = new TestKey(KeyKind.EcP256);
        Certificate root = Pki.Root(rootKey);
        var options = new CertificateOptions { Subject = DistinguishedName.FromString("CN=leaf.test"), PublicKey = leafKey.Signer.PublicKey, NotBefore = Now, NotAfter = Now.AddYears(1) };
        PreparedSignature s = CertificateBuilder.Prepare(options, root, SignatureSpec.Ecdsa(HashAlgorithmName.SHA256), CryptoPolicy.Standard, Now);
        Certificate leaf = CertificateBuilder.Complete(s, s.SignWith(rootKey.Signer.Key!));
        Assert.True(leaf.VerifySignature(root).IsValid);
        Assert.NotNull(leaf.AuthorityKeyIdentifier);
    }

    // ---- operating-system keys ----

    [Fact]
    public void ACertificateKeyInTheUserStoreSignsThroughTheInterface()
    {
        OpenSslTool.RequireOrSkip();
        // Linux uses the certificate store under the user's profile. On macOS the login keychain may ask for consent, so it runs only when asked.
        bool allowed = OperatingSystem.IsLinux() || Environment.GetEnvironmentVariable("ONECRYPTO_TEST_KEYCHAIN") == "1";
        Assert.SkipUnless(allowed, "set ONECRYPTO_TEST_KEYCHAIN=1 to use the platform's certificate store on this system");

        // A PFX made by openssl is loaded into the current user's store, used through the interface, and removed again.
        string dir = Dir("os-store");
        string cn = "OneCrypto OS key test " + Guid.NewGuid().ToString("N");
        File.WriteAllText(Path.Combine(dir, "req.cnf"), "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=" + cn + "\n[ext]\nbasicConstraints=CA:FALSE\n");
        Assert.Equal(0, OpenSslTool.RunIn(dir, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem", "-days", "2", "-config", "req.cnf").Code);
        (int pc, string po) = OpenSslTool.RunIn(dir, "pkcs12", "-export", "-inkey", "k.pem", "-in", "c.pem", "-out", "t.pfx", "-passout", "pass:testpass", "-certpbe", "AES-256-CBC", "-keypbe", "AES-256-CBC", "-macalg", "SHA256");
        Assert.True(pc == 0, po);

        X509Certificate2 loaded;
        try
        {
            loaded = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(dir, "t.pfx"), "testpass", X509KeyStorageFlags.PersistKeySet);
        }
        catch (CryptographicException e) when (e.Message.Contains("User interaction is not allowed", StringComparison.Ordinal))
        {
            // A login keychain asks the user for consent; a non-interactive session cannot answer.
            Assert.Skip("the keychain needs user interaction in this session: " + e.Message);
            return;
        }

        using X509Certificate2 owned = loaded;
        Certificate cert = Certificate.FromX509Certificate2(loaded);
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        try
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(loaded);
        }
        catch (CryptographicException e) when (e.Message.Contains("User interaction is not allowed", StringComparison.Ordinal))
        {
            // A login keychain asks the user for consent; a non-interactive session cannot answer. The key is not used.
            Assert.Skip("the keychain needs user interaction in this session: " + e.Message);
        }

        try
        {
            Assert.True(PrivateKey.TryFromStore(cert, out IKey? found));
            using IKey key = found!;
            var rsa = Assert.IsAssignableFrom<IRsaKey>(key);
            foreach (SignatureSpec spec in new[] { SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256), SignatureSpec.RsaPss(HashAlgorithmName.SHA256) })
            {
                byte[] sig = rsa.Sign(Document, spec);
                Assert.True(spec.Verify(cert.PublicKey, Document, sig).IsValid);
            }

            // The certificate can issue another certificate through the same key.
            using var leaf = new TestKey(KeyKind.EcP256);
            Certificate issued = CertificateBuilder.Create(
                new CertificateOptions { Subject = DistinguishedName.FromString("CN=issued.test"), PublicKey = leaf.Signer.PublicKey, NotBefore = Now, NotAfter = Now.AddDays(1) },
                cert,
                X509Signer.FromKey(rsa));
            Assert.True(issued.VerifySignature(cert).IsValid);

            using X509Certificate2 viaCert = X509CertificateLoader.LoadCertificate(loaded.RawData);
            Assert.Throws<ArgumentException>(() => PrivateKey.FromCertificate(viaCert)); // no private key on this copy
        }
        finally
        {
            foreach (X509Certificate2 c in store.Certificates.Find(X509FindType.FindBySubjectName, cn, false))
            {
                store.Remove(c);
                c.Dispose();
            }
        }
    }

    [Fact]
    public void ACertificateWithItsKeyGivesAKeyAndTheStoreMissIsReported()
    {
        using RSA rsa = RSA.Create(2048);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=pfx.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 self = req.CreateSelfSigned(Now, Now.AddDays(5));
        using IKey key = PrivateKey.FromCertificate(self);
        Assert.Equal(KeyCapabilities.Sign | KeyCapabilities.Decrypt, key.Capabilities);
        Assert.True(key.PublicKey.Equals(Certificate.FromX509Certificate2(self).PublicKey));
        Assert.False(PrivateKey.TryFromStore(Certificate.FromX509Certificate2(self), out IKey? none));
        Assert.Null(none);
    }
}
