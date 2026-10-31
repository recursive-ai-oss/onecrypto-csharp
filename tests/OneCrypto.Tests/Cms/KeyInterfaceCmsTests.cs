using System.Diagnostics;
using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Cms;

/// <summary>CMS signing and decryption through the key interfaces, two-phase CMS signing across processes, and the policy at every decision point.</summary>
public class KeyInterfaceCmsTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Doc = "a CMS document signed by a key that is somewhere else"u8.ToArray();
    private static readonly CryptoPolicy Legacy = CryptoPolicy.Standard with { HashRules = [] };

    private static string Dir(string name)
    {
        string d = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR") ?? Path.GetTempPath(), "onecrypto-cms-twophase", name);
        Directory.CreateDirectory(d);
        return d;
    }

    // ---- key material ----

    private sealed record Material(string Kind, byte[] KeyFile, ISigningKey Key, SignatureSpec Spec, Certificate Certificate, IDisposable Owner);

    public static TheoryData<string> Kinds => ["rsa", "rsa-pss", "ecdsa", "ed25519"];

    private static Material Make(string kind)
    {
        switch (kind)
        {
            case "rsa" or "rsa-pss":
                var rsa = RSA.Create(2048);
                ISigningKey rk = PrivateKey.FromRsa(rsa);
                SignatureSpec rs = kind == "rsa" ? SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256) : SignatureSpec.RsaPss(HashAlgorithmName.SHA256);
                return new("rsa", rsa.ExportPkcs8PrivateKey(), rk, rs, CmsKeys.SelfSigned("two phase " + kind, X509Signer.FromKey(rk, rs)), rsa);
            case "ecdsa":
                var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                ISigningKey ek = PrivateKey.FromECDsa(ec);
                SignatureSpec es = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
                return new("ecdsa", ec.ExportPkcs8PrivateKey(), ek, es, CmsKeys.SelfSigned("two phase ecdsa", X509Signer.FromKey(ek, es)), ec);
            default:
                var ed = Ed25519PrivateKey.Generate();
                var seed = new byte[32];
                ed.ExportSeed(seed);
                ISigningKey dk = PrivateKey.FromEd25519(ed);
                return new("ed25519", seed, dk, SignatureSpec.Ed25519(), CmsKeys.SelfSigned("two phase ed25519", X509Signer.FromKey(dk)), ed);
        }
    }

    /// <summary>Runs the signer program in a separate dotnet process on a serialised state and returns the signature it wrote.</summary>
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

    // ---- signing through the key interfaces ----

    [Theory]
    [InlineData(SigKind.Rsa)]
    [InlineData(SigKind.RsaPss)]
    [InlineData(SigKind.P256)]
    [InlineData(SigKind.P384)]
    [InlineData(SigKind.Ed25519)]
    [InlineData(SigKind.Ed448)]
    [InlineData(SigKind.MlDsa65)]
    public void ASignerCanBeAKeyBehindTheInterface(SigKind kind)
    {
        Assert.SkipUnless(CmsKeys.IsAvailable(kind), "the platform lacks this algorithm");
        SignerKit k = CmsKeys.Get(kind);
        // The EdDSA kits sign with a delegate; for them the test makes a key behind the interface of its own.
        ISigningKey inner = k.Signer.Key ?? (kind == SigKind.Ed25519 ? PrivateKey.FromEd25519(Ed25519PrivateKey.Generate(), ownsKey: true) : PrivateKey.FromEd448(Ed448PrivateKey.Generate(), ownsKey: true));
        SignatureSpec used = k.Signer.Spec ?? inner.DefaultSpec;
        Certificate cert = k.Signer.Key is not null ? k.Certificate : CmsKeys.SelfSigned("eddsa key", X509Signer.FromKey(inner));
        var counting = new CountingSigningKey(inner);
        SignedData sd = SignedData.Create(Doc, [new CmsSignerSpec { Certificate = cert, Key = counting, SignatureSpec = used }]);
        Assert.True(sd.Verify().IsValid);
        // RSA and ECDSA keys are handed the digest of the signed attributes; EdDSA and ML-DSA the attributes themselves.
        if (used.SignsDigest)
        {
            Assert.Equal(1, counting.DigestCalls);
            Assert.Equal(0, counting.MessageCalls);
        }
        else
        {
            Assert.Equal(0, counting.DigestCalls);
            Assert.Equal(1, counting.MessageCalls);
        }
    }

    [Fact]
    public void ASignerFromX509SignerFromKeyStillWorks()
    {
        SignerKit k = CmsKeys.Get(SigKind.P256);
        SignedData sd = SignedData.Create(Doc, [new CmsSignerSpec { Certificate = k.Certificate, Signer = X509Signer.FromKey(k.Signer.Key!) }]);
        Assert.True(sd.Verify().IsValid);
        Assert.Throws<ArgumentException>(() => SignedData.Create(Doc, [new CmsSignerSpec { Certificate = k.Certificate }]));
    }

    private sealed class CountingSigningKey(ISigningKey inner) : ISigningKey
    {
        public int DigestCalls { get; private set; }

        public int MessageCalls { get; private set; }

        public PublicKeyInfo PublicKey => inner.PublicKey;

        public KeyCapabilities Capabilities => inner.Capabilities;

        public SignatureSpec DefaultSpec => inner.DefaultSpec;

        public bool Supports(SignatureSpec spec) => inner.Supports(spec);

        public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec)
        {
            MessageCalls++;
            return inner.Sign(data, spec);
        }

        public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec)
        {
            DigestCalls++;
            return inner.SignDigest(digest, spec);
        }

        public void Dispose()
        {
        }
    }

    // ---- decryption through the key interfaces ----

    [Theory]
    [InlineData(KeyTransportScheme.OaepSha256)]
    [InlineData(KeyTransportScheme.OaepSha1)]
    [InlineData(KeyTransportScheme.Pkcs1V15)]
    public void ARecipientKeyIsOpenedThroughTheDecryptionInterface(KeyTransportScheme scheme)
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        EnvelopedData ed = EnvelopedData.Create(Doc, [CmsRecipient.KeyTransport(kit.Certificate, scheme)], new CmsEncryptOptions { AllowLegacy = true });
        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(kit.Pkcs8Pem);
        var counting = new CountingDecryptionKey(PrivateKey.FromRsa(rsa));
        using CmsDecryptionKey key = CmsDecryptionKey.FromKey(counting, kit.Certificate);
        Assert.Equal(Doc, ed.Decrypt(key));
        Assert.Equal(1, counting.Calls);
        Assert.Equal(scheme == KeyTransportScheme.Pkcs1V15 ? DecryptionKind.RsaPkcs1 : DecryptionKind.RsaOaep, counting.LastKind);
    }

    [Fact]
    public void AWrongRsaKeyStillFailsUniformly()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        EnvelopedData ed = EnvelopedData.Create(Doc, [CmsRecipient.KeyTransport(kit.Certificate, KeyTransportScheme.Pkcs1V15)], new CmsEncryptOptions { AllowLegacy = true });
        using RSA other = RSA.Create(2048);
        using CmsDecryptionKey wrong = CmsDecryptionKey.FromKey(PrivateKey.FromRsa(other));
        CmsParseException e = Assert.Throws<CmsParseException>(() => ed.Decrypt(wrong));
        Assert.Equal(CmsError.DecryptionFailed, e.Error);
    }

    [Fact]
    public void AgreementKeysOpenThroughTheAgreementInterface()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.X25519);
        EnvelopedData ed = EnvelopedData.Create(Doc, [CmsRecipient.KeyAgreement(kit.Certificate)]);
        using CmsDecryptionKey key = kit.Key();
        Assert.Equal(Doc, ed.Decrypt(key));
    }

    private sealed class CountingDecryptionKey(IRsaKey inner) : IRsaKey
    {
        public int Calls { get; private set; }

        public DecryptionKind LastKind { get; private set; }

        public PublicKeyInfo PublicKey => inner.PublicKey;

        public KeyCapabilities Capabilities => inner.Capabilities;

        public SignatureSpec DefaultSpec => inner.DefaultSpec;

        public bool Supports(SignatureSpec spec) => inner.Supports(spec);

        public bool Supports(DecryptionSpec spec) => inner.Supports(spec);

        public byte[] Sign(ReadOnlySpan<byte> data, SignatureSpec spec) => inner.Sign(data, spec);

        public byte[] SignDigest(ReadOnlySpan<byte> digest, SignatureSpec spec) => inner.SignDigest(digest, spec);

        public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, DecryptionSpec spec)
        {
            Calls++;
            LastKind = spec.Kind;
            return inner.Decrypt(ciphertext, spec);
        }

        public void Dispose() => inner.Dispose();
    }

    // ---- two-phase CMS signing ----

    [Theory]
    [MemberData(nameof(Kinds))]
    public void SignedDataIsCompletedAfterAnotherProcessSignsIt(string kind)
    {
        foreach (bool detached in new[] { false, true })
        {
            string dir = Dir($"{kind}-{(detached ? "detached" : "attached")}");
            Material m = Make(kind);
            using (m.Owner)
            {
                // Process A: prepare and serialise.
                byte[] encoded = SignedData.Prepare(Doc, [new CmsSignerSpec { Certificate = m.Certificate, SignatureSpec = m.Spec, SigningTime = Now }], Now, new SignedDataOptions { Detached = detached }).Encode();

                // Process B signs what the state asks for and never sees the document for the digest schemes.
                PreparedSignedData restored = PreparedSignedData.Decode(encoded);
                Assert.Equal("cms.signerinfo", restored.Signatures[0].Purpose);
                byte[] signature = SignInOtherProcess(dir, m.Kind, m.KeyFile, restored.Signatures[0].Encode());

                // Process A again: completes.
                SignedData sd = restored.Complete(signature);
                SignedDataReport report = detached ? sd.Verify(Doc) : sd.Verify();
                Assert.True(report.IsValid, string.Join("; ", report.Signers[0].Checks.Where(c => c.Status is CmsCheckStatus.Failed).Select(c => c.Rule + ": " + c.Reason)));
                Assert.Equal(detached, !sd.HasEncapsulatedContent);

                // Older OpenSSL cannot verify an EdDSA signature over signed attributes in CMS, so that kind is checked there only by us.
                if (OpenSslTool.Available && (kind != "ed25519" || OpenSslTool.AtLeast(3, 5)))
                {
                    File.WriteAllBytes(Path.Combine(dir, "m.der"), sd.Encoded.ToArray());
                    File.WriteAllBytes(Path.Combine(dir, "c.bin"), Doc);
                    var args = new List<string> { "cms", "-verify", "-inform", "DER", "-in", "m.der", "-noverify", "-binary", "-out", "o.bin" };
                    if (detached)
                    {
                        args.AddRange(["-content", "c.bin"]);
                    }

                    (int code, string output) = OpenSslTool.RunIn(dir, [.. args]);
                    Assert.True(code == 0, "openssl cms -verify: " + output);
                    Assert.Equal(Doc, File.ReadAllBytes(Path.Combine(dir, "o.bin")));
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public void ATamperedOrWrongKeySignatureIsRefusedWhenCompleting(string kind)
    {
        string dir = Dir("tamper-" + kind);
        Material m = Make(kind);
        Material other = Make(kind);
        using (m.Owner)
        using (other.Owner)
        {
            PreparedSignedData state = SignedData.Prepare(Doc, [new CmsSignerSpec { Certificate = m.Certificate, SignatureSpec = m.Spec }], Now);
            byte[] good = SignInOtherProcess(dir, m.Kind, m.KeyFile, state.Signatures[0].Encode());
            byte[] flipped = (byte[])good.Clone();
            flipped[^1] ^= 1;
            Assert.Throws<InvalidSignatureException>(() => state.Complete(flipped));
            byte[] wrongKey = SignInOtherProcess(dir, other.Kind, other.KeyFile, state.Signatures[0].Encode());
            Assert.Throws<InvalidSignatureException>(() => state.Complete(wrongKey));
            Assert.Throws<ArgumentException>(() => state.Complete(new List<byte[]> { good, good }));
            Assert.True(state.Complete(good).Verify().IsValid);
        }
    }

    [Fact]
    public void StreamedContentIsHashedInPhaseOneAndAttachedOrDetachedLater()
    {
        string dir = Dir("stream");
        Material m = Make("ecdsa");
        using (m.Owner)
        {
            var spec = new CmsSignerSpec { Certificate = m.Certificate, SignatureSpec = m.Spec };

            // Detached: only the digests are kept.
            PreparedSignedData detached = SignedData.PrepareStream(new MemoryStream(Doc), [spec], Now, new SignedDataOptions { Detached = true });
            SignedData d = detached.Complete(SignInOtherProcess(dir, m.Kind, m.KeyFile, detached.Signatures[0].Encode()));
            Assert.True(d.Verify(new MemoryStream(Doc)).IsValid);

            // Attached: the content is written again while completing, and must hash the same.
            PreparedSignedData attached = PreparedSignedData.Decode(SignedData.PrepareStream(new MemoryStream(Doc), [spec], Now).Encode());
            Assert.Throws<InvalidOperationException>(() => attached.Complete(new List<byte[]> { new byte[8] }));
            byte[] sig = SignInOtherProcess(dir, m.Kind, m.KeyFile, attached.Signatures[0].Encode());
            var output = new MemoryStream();
            attached.CompleteStream([sig], new MemoryStream(Doc), output);
            Assert.True(SignedData.Parse(output.ToArray()).Verify().IsValid);
            Assert.True(SignedData.VerifyStream(new MemoryStream(output.ToArray())).IsValid);

            // Content that changed since phase one is caught.
            Assert.Throws<CryptographicException>(() => attached.CompleteStream([sig], new MemoryStream("another document"u8.ToArray()), new MemoryStream()));
            // A bad signature is refused before anything is written.
            var untouched = new MemoryStream();
            Assert.Throws<InvalidSignatureException>(() => attached.CompleteStream([new byte[sig.Length]], new MemoryStream(Doc), untouched));
            Assert.Equal(0, untouched.Length);
        }
    }

    [Fact]
    public void TheStateIsVersionedAndDamageIsReported()
    {
        Material m = Make("ecdsa");
        using (m.Owner)
        {
            byte[] der = SignedData.Prepare(Doc, [new CmsSignerSpec { Certificate = m.Certificate, SignatureSpec = m.Spec }], Now).Encode();
            Assert.True(PreparedSignedData.TryDecode(der, out PreparedSignedData? ok, out _));
            Assert.True(ok!.IsAttached);
            Assert.False(PreparedSignedData.TryDecode(der.AsSpan(0, der.Length - 3), out _, out _));
            Assert.Throws<FormatException>(() => PreparedSignedData.Decode([0x30, 0x00]));
            for (int i = 0; i < der.Length; i += 7)
            {
                byte[] bad = (byte[])der.Clone();
                bad[i] ^= 0xFF;
                _ = PreparedSignedData.TryDecode(bad, out _, out _); // never throws
            }

            // A prepared signature of another purpose cannot stand in for a signer.
            PreparedSignature raw = PreparedSignature.Prepare(m.Key.PublicKey, m.Spec, Doc, CryptoPolicy.Standard, Now);
            Assert.NotEqual(PreparedSignedData.SignerPurpose, raw.Purpose);
        }
    }

    [Fact]
    public void ThePolicyDecidesAtPreparation()
    {
        using RSA rsa = RSA.Create(2048);
        ISigningKey key = PrivateKey.FromRsa(rsa);
        SignatureSpec sha1 = SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA1);
        Certificate cert = CmsKeys.SelfSigned("sha1 cms", X509Signer.FromKey(key, sha1), policy: Legacy);
        var e = Assert.Throws<PolicyViolationException>(() => SignedData.Prepare(Doc, [new CmsSignerSpec { Certificate = cert, SignatureSpec = sha1 }], Now));
        Assert.Contains(e.Report.Decisions, d => d.Rule == "hash.sha-1.new");
        Assert.NotNull(SignedData.Prepare(Doc, [new CmsSignerSpec { Certificate = cert, SignatureSpec = sha1 }], Now, new SignedDataOptions { Policy = Legacy }));
    }

    // ---- policy ----

    [Fact]
    public void ASha1SignerIsJudgedAtTheReferenceTime()
    {
        using RSA rsa = RSA.Create(2048);
        ISigningKey key = PrivateKey.FromRsa(rsa);
        SignatureSpec sha1 = SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA1);
        Certificate cert = CmsKeys.SelfSigned("sha1 policy", X509Signer.FromKey(key, sha1), policy: Legacy);
        SignedData sd = SignedData.Create(Doc, [new CmsSignerSpec { Certificate = cert, Key = key, SignatureSpec = sha1 }], new SignedDataOptions { Policy = Legacy });

        SignerReport At(int year, int month = 1) => sd.Verify(new SignedDataVerifyOptions { Policy = CryptoPolicy.Standard, ReferenceTime = new DateTimeOffset(year, month, 1, 0, 0, 0, TimeSpan.Zero) }).Signers[0];

        // Before the deprecation date: accepted, no finding.
        SignerReport before = At(2010, 12);
        Assert.Equal(CmsCheckStatus.Passed, before.Find("policy")!.Status);
        Assert.Equal(PolicyVerdict.Accepted, before.Policy!.Verdict);

        // From 2011-01-01 to 2030-12-31: flagged, still valid.
        SignerReport flagged = At(2011);
        Assert.Equal(CmsCheckStatus.Warning, flagged.Find("policy")!.Status);
        Assert.Contains(flagged.Policy!.Decisions, d => d.Rule == "hash.sha-1.flagged-from" && d.Verdict == PolicyVerdict.Flagged);
        Assert.True(flagged.IsValid);
        Assert.Equal(CmsCheckStatus.Warning, At(2030, 12).Find("policy")!.Status);

        // From 2031-01-01: rejected.
        SignerReport rejected = At(2031);
        Assert.Equal(CmsCheckStatus.Failed, rejected.Find("policy")!.Status);
        Assert.Contains(rejected.Policy!.Decisions, d => d.Rule == "hash.sha-1.rejected-from");
        Assert.False(rejected.IsValid);

        // Strict never accepts it.
        SignedDataReport strict = sd.Verify(new SignedDataVerifyOptions { Policy = CryptoPolicy.Strict, ReferenceTime = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero) });
        Assert.False(strict.IsValid);

        // A policy without a reference time is a programming error, not a guess.
        Assert.Throws<ArgumentException>(() => sd.Verify(new SignedDataVerifyOptions { Policy = CryptoPolicy.Standard }));
        // Without a policy the report keeps its plain warning.
        Assert.Equal(CmsCheckStatus.Warning, sd.Verify().Signers[0].Find("digest-algorithm")!.Status);

        // New data under the default policy is refused.
        var e = Assert.Throws<PolicyViolationException>(() => SignedData.Create(Doc, [new CmsSignerSpec { Certificate = cert, Key = key, SignatureSpec = sha1 }]));
        Assert.Contains(e.Report.Decisions, d => d.Rule == "hash.sha-1.new");
    }

    [Fact]
    public void ASmallRsaSignerIsRefusedForNewDataAndFlaggedWhenVerified()
    {
        using RSA small = RSA.Create(1024);
        ISigningKey key = PrivateKey.FromRsa(small);
        SignatureSpec spec = SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256);
        CryptoPolicy allowSmall = CryptoPolicy.Standard with { MinRsaBitsNew = 1024 };
        Certificate cert = CmsKeys.SelfSigned("small rsa", X509Signer.FromKey(key, spec), policy: allowSmall);
        var e = Assert.Throws<PolicyViolationException>(() => SignedData.Create(Doc, [new CmsSignerSpec { Certificate = cert, Key = key, SignatureSpec = spec }]));
        Assert.Contains(e.Report.Decisions, d => d.Rule == "key.rsa.min-new");
        SignedData sd = SignedData.Create(Doc, [new CmsSignerSpec { Certificate = cert, Key = key, SignatureSpec = spec }], new SignedDataOptions { Policy = allowSmall });
        SignerReport r = sd.Verify(new SignedDataVerifyOptions { Policy = CryptoPolicy.Standard, ReferenceTime = Now }).Signers[0];
        Assert.Contains(r.Policy!.Decisions, d => d.Rule == "key.rsa.weak-from");
        Assert.Equal(CmsCheckStatus.Warning, r.Find("policy")!.Status);
    }

    [Fact]
    public void AWeakRsaRecipientIsRefusedUnderStrictWithTheRuleId()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa); // 2048-bit
        Assert.Equal(2048, kit.Certificate.PublicKey.KeySizeBits);
        CmsRecipient r = CmsRecipient.KeyTransport(kit.Certificate);

        var e = Assert.Throws<PolicyViolationException>(() => AuthEnvelopedData.Create(Doc, [r], new CmsEncryptOptions { Policy = CryptoPolicy.Strict }));
        Assert.Contains(e.Report.Decisions, d => d.Rule == "key.rsa.min-new" && d.Verdict == PolicyVerdict.Rejected);
        Assert.Contains("key.rsa.min-new", e.Message);

        // The same recipient is fine under Standard.
        Assert.NotNull(AuthEnvelopedData.Create(Doc, [r]));
        Assert.NotNull(AuthEnvelopedData.Create(Doc, [r], new CmsEncryptOptions { Policy = CryptoPolicy.Standard with { MinRsaBitsNew = 2048 } }));
    }

    [Fact]
    public void CbcContentEncryptionIsFlaggedByStandardAndRefusedByStrict()
    {
        RecipientKit kit = RecipientKit.Get(RecipKind.Rsa);
        CmsRecipient r = CmsRecipient.KeyTransport(kit.Certificate);
        EnvelopedData ed = EnvelopedData.Create(Doc, [r]);
        using CmsDecryptionKey key = kit.Key();

        // Standard decrypts it (S/MIME relies on CBC) with a flag the policy would report.
        Assert.Equal(Doc, ed.Decrypt(key, new CmsDecryptOptions { Policy = CryptoPolicy.Standard, ReferenceTime = Now }));
        PolicyDecision flag = CryptoPolicy.Standard.CheckContentCipher("AES-256-CBC", CryptoUse.Decrypt);
        Assert.Equal(PolicyVerdict.Flagged, flag.Verdict);
        Assert.Equal("cipher.cbc.unauthenticated.decrypt", flag.Rule);

        // Strict refuses it before any key is used, and opting in lets it through.
        var e = Assert.Throws<PolicyViolationException>(() => ed.Decrypt(key, new CmsDecryptOptions { Policy = CryptoPolicy.Strict, ReferenceTime = Now }));
        Assert.Contains(e.Report.Decisions, d => d.Rule == "cipher.cbc.unauthenticated.decrypt");
        Assert.Equal(Doc, ed.Decrypt(key, new CmsDecryptOptions { Policy = CryptoPolicy.Strict with { AllowUnauthenticatedDecryption = true, MinRsaBitsVerify = 1024 }, ReferenceTime = Now }));
        Assert.Throws<PolicyViolationException>(() => EnvelopedData.Create(Doc, [r], new CmsEncryptOptions { Policy = CryptoPolicy.Strict with { MinRsaBitsNew = 2048 } }));
        Assert.Throws<ArgumentException>(() => ed.Decrypt(key, new CmsDecryptOptions { Policy = CryptoPolicy.Standard }));

        // AuthEnvelopedData has no such finding under Strict.
        AuthEnvelopedData ae = AuthEnvelopedData.Create(Doc, [r]);
        Assert.Equal(Doc, ae.Decrypt(key, new CmsDecryptOptions { Policy = CryptoPolicy.Strict with { MinRsaBitsVerify = 1024 }, ReferenceTime = Now }));
    }

    [Fact]
    public void TheX509BuildersRefuseSha1ForNewCertificates()
    {
        using RSA rsa = RSA.Create(2048);
        X509Signer sha1 = X509Signer.FromRsa(rsa, HashAlgorithmName.SHA1);
        var options = new CertificateOptions { Subject = DistinguishedName.FromString("CN=sha1.test"), NotBefore = Now, NotAfter = Now.AddDays(10) };
        var e = Assert.Throws<PolicyViolationException>(() => CertificateBuilder.CreateSelfSigned(options, sha1));
        Assert.Contains(e.Report.Decisions, d => d.Rule == "hash.sha-1.new");
        Assert.Throws<PolicyViolationException>(() => CertificateSigningRequestBuilder.Create(new CertificateSigningRequestOptions { Subject = options.Subject }, sha1));
        Assert.Throws<PolicyViolationException>(() => RevocationListBuilder.Create(new RevocationListOptions { Issuer = options.Subject, ThisUpdate = Now }, sha1));
        // An explicit permissive policy is the escape hatch for interop with an old peer.
        Certificate old = CertificateBuilder.CreateSelfSigned(options, sha1, Legacy);

        // Small RSA keys are refused too.
        using RSA small = RSA.Create(1024);
        Assert.Throws<PolicyViolationException>(() => CertificateBuilder.CreateSelfSigned(options, X509Signer.FromRsa(small, HashAlgorithmName.SHA256)));

        // And the verification result carries the policy's decisions at the reference time.
        SignatureVerification plain = old.VerifySignature(old.PublicKey);
        Assert.True(plain.IsValid);
        Assert.Null(plain.Policy);
        SignatureVerification y2010 = old.VerifySignature(old.PublicKey, CryptoPolicy.Standard, new DateTimeOffset(2010, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.True(y2010.IsValid);
        SignatureVerification y2020 = old.VerifySignature(old.PublicKey, CryptoPolicy.Standard, new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.True(y2020.IsValid);
        Assert.Equal(PolicyVerdict.Flagged, y2020.Policy!.Verdict);
        SignatureVerification y2032 = old.VerifySignature(old.PublicKey, CryptoPolicy.Standard, new DateTimeOffset(2032, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.False(y2032.IsValid);
        Assert.Equal(SignatureStatus.PolicyRejected, y2032.Status);
        Assert.Contains("hash.sha-1.rejected-from", y2032.Reason);
    }

    // ---- OCSP in two phases ----

    [Fact]
    public void OcspRequestAndResponseAreBuiltInTwoPhases()
    {
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ISigningKey key = PrivateKey.FromECDsa(ec);
        SignatureSpec spec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
        Certificate issuer = CmsKeys.SelfSigned("ocsp ca", X509Signer.FromKey(key, spec));
        Certificate subject = CmsKeys.SelfSigned("ocsp subject", X509Signer.FromKey(key, spec));

        var rq = new OcspRequestOptions { Requests = [OcspCertId.Create(subject, issuer)], Nonce = new byte[] { 1, 2, 3, 4 } };
        PreparedSignature prepared = OcspRequestBuilder.Prepare(rq, key.PublicKey, spec, CryptoPolicy.Standard, Now);
        Assert.Equal("ocsp.request", prepared.Purpose);
        OcspRequest request = OcspRequestBuilder.Complete(PreparedSignature.Decode(prepared.Encode()), prepared.SignWith(key), [issuer]);
        Assert.True(request.VerifySignature(key.PublicKey).IsValid);
        OcspRequest oneShot = OcspRequestBuilder.Create(rq, X509Signer.FromKey(key, spec), [issuer]);
        Assert.Equal(oneShot.TbsRequest.ToArray(), request.TbsRequest.ToArray());
        Assert.Throws<InvalidSignatureException>(() => OcspRequestBuilder.Complete(prepared, new byte[70], [issuer]));
        Assert.Throws<PolicyViolationException>(() => OcspRequestBuilder.Prepare(rq, key.PublicKey, SignatureSpec.Ecdsa(HashAlgorithmName.SHA1), CryptoPolicy.Standard, Now));

        var ro = new OcspResponseOptions
        {
            Responder = new OcspResponderId(issuer.Subject),
            ProducedAt = Now,
            Responses = [new OcspSingleResponseInfo(rq.Requests[0], OcspCertStatus.Good, Now, Now.AddDays(1))],
            Certificates = [issuer],
        };
        PreparedSignature rp = OcspResponseBuilder.Prepare(ro, key.PublicKey, spec, CryptoPolicy.Standard, Now);
        Assert.Equal("ocsp.response", rp.Purpose);
        OcspResponse response = OcspResponseBuilder.Complete(PreparedSignature.Decode(rp.Encode()), rp.SignWith(key), ro.Certificates);
        Assert.True(response.BasicResponse!.VerifySignature(key.PublicKey).IsValid);
        Assert.Throws<ArgumentException>(() => OcspResponseBuilder.Complete(prepared, new byte[8]));
    }

    /// <summary>A fuzz finding: a state whose digest entry carried bytes after the digest used to decode and then re-encode to something shorter.</summary>
    [Fact]
    public void PreparedStateWithTrailingBytesInADigestEntryIsRefused()
    {
        byte[] state = File.ReadAllBytes(Path.Combine(TestFiles.TestData, "fuzz", "prepared-signeddata-digest-trailing-bytes.bin"));
        Assert.False(PreparedSignedData.TryDecode(state, out _, out string? error));
        Assert.False(string.IsNullOrEmpty(error));
    }
}
