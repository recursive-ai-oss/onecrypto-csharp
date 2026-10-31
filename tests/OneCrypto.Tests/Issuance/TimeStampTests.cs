using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Issuance;

/// <summary>The time-stamp client messages and the authority handler, on their own and against the openssl <c>ts</c> command as a black box.</summary>
public class TimeStampTests
{
    internal const string Policy = "1.2.3.4.1";
    private static readonly DateTimeOffset T0 = IssuanceKit.T0.AddHours(1);

    internal sealed record Tsa(SigKind Kind, SignerKit Kit, Certificate Certificate, TimeStampAuthority Authority, TimeStampAuthorityOptions Options);

    private static readonly Dictionary<SigKind, Certificate> Certs = [];

    internal static Certificate CertificateFor(SigKind kind)
    {
        lock (Certs)
        {
            if (!Certs.TryGetValue(kind, out Certificate? c))
            {
                SignerKit kit = CmsKeys.Get(kind);
                c = IssuanceKit.Get().Intermediate.Issue(kit.Signer.PublicKey, DistinguishedName.Create((KnownOids.Organization, "OneCrypto Tests"), (KnownOids.CommonName, "TSA " + kind)),
                    new CertificateIssueOptions { Profile = CertificateProfile.TimeStamping, NotBefore = IssuanceKit.T0.AddDays(-1) });
                Certs[kind] = c;
            }

            return c;
        }
    }

    private static SignatureSpec? SpecFor(SigKind kind) => kind switch
    {
        SigKind.Ed25519 => SignatureSpec.Ed25519(),
        SigKind.Ed448 => SignatureSpec.Ed448(),
        _ => null,
    };

    internal static Tsa Make(SigKind kind, Func<TimeStampAuthorityOptions, TimeStampAuthorityOptions>? tweak = null, bool certChain = true)
    {
        SignerKit kit = CmsKeys.Get(kind);
        Certificate cert = CertificateFor(kind);
        var o = new TimeStampAuthorityOptions
        {
            Certificate = cert,
            Signer = kit.Signer,
            SignatureSpec = SpecFor(kind),
            DefaultPolicy = Policy,
            AcceptedPolicies = ["1.2.3.4.5"],
            Accuracy = new TimeStampAccuracy(Seconds: 1),
            ChainCertificates = certChain ? [IssuanceKit.Get().Intermediate.Certificate] : [],
        };
        o = tweak?.Invoke(o) ?? o;
        return new Tsa(kind, kit, cert, new TimeStampAuthority(o, new CounterTimeStampSerialSource(100)), o);
    }

    private static TimeStampRequest Request(HashAlgorithmName hash, byte[] data, bool nonce = true, bool certReq = true, string? policy = null) =>
        TimeStampRequest.Create(new TimeStampRequestOptions
        {
            Hash = hash,
            MessageImprint = CryptographicOperations.HashData(hash, data),
            Nonce = nonce ? TimeStampRequest.NewNonce() : default,
            CertReq = certReq,
            Policy = policy,
        });

    public static TheoryData<SigKind> Kinds => [SigKind.Rsa, SigKind.RsaPss, SigKind.P256, SigKind.P384, SigKind.Ed25519, SigKind.Ed448];

    [Theory]
    [MemberData(nameof(Kinds))]
    public void AnswerVerifiesAgainstItsRequest(SigKind kind)
    {
        Tsa t = Make(kind);
        TimeStampRequest req = Request(HashAlgorithmName.SHA256, "hello"u8.ToArray());
        TimeStampResponse resp = t.Authority.Handle(req.Encoded, T0);
        Assert.Equal(TimeStampStatus.Granted, resp.Status);
        TimeStampReport report = TimeStampVerifier.Verify(req, resp.Encoded);
        Assert.True(report.IsValid, string.Join("; ", report.Checks.Where(c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported).Select(c => c.Rule + ": " + c.Reason)));
        Assert.Equal(T0.ToUnixTimeSeconds(), report.GenTime!.Value.ToUnixTimeSeconds());
        Assert.Equal(Policy, report.Info!.Policy);
        Assert.Equal(1, report.Info.Accuracy!.Seconds);
        Assert.Equal(t.Certificate, report.SignerCertificate);
        Assert.Equal(CmsCheckStatus.NotApplicable, report.Find("trust")!.Status);
        foreach (string rule in new[] { "status", "token", "message-imprint", "nonce", "single-signer", "signature", "tsa-eku", "ess-cert-id", "tsa-name", "tsa-validity", "policy" })
        {
            Assert.Equal(CmsCheckStatus.Passed, report.Find(rule)?.Status);
        }
    }

    [Fact]
    public void SerialsAreTakenFromTheSourceAndNeverReused()
    {
        Tsa t = Make(SigKind.P256);
        var seen = new HashSet<string>();
        for (int i = 0; i < 5; i++)
        {
            TimeStampResponse r = t.Authority.Handle(Request(HashAlgorithmName.SHA256, [1]).Encoded, T0);
            Assert.True(seen.Add(Convert.ToHexString(TstInfo.FromSignedData(r.Token!).SerialNumber.Span)));
        }

        Assert.Contains("64", seen); // the counter started at 100
    }

    [Theory]
    [InlineData(SigKind.Rsa)]
    [InlineData(SigKind.P256)]
    [InlineData(SigKind.Ed25519)]
    public void TheAuthorityChainsToTheSuppliedAnchorAtGenTimeOrTheTrustCheckFails(SigKind kind)
    {
        Tsa t = Make(kind);
        TimeStampRequest req = Request(HashAlgorithmName.SHA256, [4]);
        TimeStampResponse resp = t.Authority.Handle(req.Encoded, T0);
        var anchor = new[] { TrustAnchor.FromCertificate(IssuanceKit.Get().Root.Certificate) };

        TimeStampReport ok = TimeStampVerifier.Verify(req, resp.Encoded, new TimeStampVerifyOptions { TrustAnchors = anchor });
        Assert.True(ok.IsValid, string.Join("; ", ok.Checks.Where(static c => c.Status != CmsCheckStatus.Passed).Select(static c => c.Rule + ":" + c.Reason)));
        Assert.Equal(CmsCheckStatus.Warning, ok.Find("trust")!.Status); // chains, revocation unknown: never "valid" silently

        // A different root is not an anchor for this authority.
        var other = CertificateAuthority.CreateRoot(DistinguishedName.Create((KnownOids.CommonName, "Other Root")), X509Signer.FromECDsa(ECDsa.Create(ECCurve.NamedCurves.nistP256)), IssuanceKit.T0, TimeSpan.FromDays(30));
        TimeStampReport bad = TimeStampVerifier.Verify(req, resp.Encoded, new TimeStampVerifyOptions { TrustAnchors = [TrustAnchor.FromCertificate(other.Certificate)] });
        Assert.Equal(CmsCheckStatus.Failed, bad.Find("trust")!.Status);
        Assert.False(bad.IsValid);

        // Without anchors the check stays not-applicable.
        Assert.Equal(CmsCheckStatus.NotApplicable, TimeStampVerifier.Verify(req, resp.Encoded).Find("trust")!.Status);
    }

    // Found by fuzzing: a token whose authority certificate has an unreadable subjectAltName made Verify throw instead of failing the tsa-name rule.
    [Fact]
    public void ATokenWithAnUnreadableSubjectAltNameIsReportedNotThrown()
    {
        byte[] response = File.ReadAllBytes(Path.Combine(TestFiles.TestData, "fuzz-repros", "tsa-response-malformed-san.der"));
        TimeStampReport report = TimeStampVerifier.Verify(TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = new byte[32] }), response);
        Assert.False(report.IsValid);
    }

    [Fact]
    public void WithoutCertReqTheTokenCarriesNoCertificateAndTheCallerSuppliesIt()
    {
        Tsa t = Make(SigKind.P256);
        TimeStampRequest req = Request(HashAlgorithmName.SHA384, [9], certReq: false);
        TimeStampResponse resp = t.Authority.Handle(req.Encoded, T0);
        Assert.Empty(resp.Token!.Certificates);
        TimeStampReport without = TimeStampVerifier.Verify(req, resp.Encoded);
        Assert.False(without.IsValid);
        Assert.Equal(CmsCheckStatus.Unsupported, without.Find("tsa-certificate")!.Status);
        Assert.True(TimeStampVerifier.Verify(req, resp.Encoded, new TimeStampVerifyOptions { ExtraCertificates = [t.Certificate] }).IsValid);
    }

    [Fact]
    public void CertReqAddsTheChain()
    {
        Tsa t = Make(SigKind.Rsa);
        TimeStampResponse resp = t.Authority.Handle(Request(HashAlgorithmName.SHA512, [9]).Encoded, T0);
        Assert.Equal(2, resp.Token!.Certificates.Count);
    }

    [Fact]
    public void NonceIsEchoedAndAMissingOrWrongOneIsCaught()
    {
        Tsa t = Make(SigKind.P256);
        TimeStampRequest req = Request(HashAlgorithmName.SHA256, [1]);
        TimeStampResponse resp = t.Authority.Handle(req.Encoded, T0);
        TimeStampRequest other = Request(HashAlgorithmName.SHA256, [1]);
        // The same data but another nonce: a replayed token is not accepted.
        Assert.Equal(CmsCheckStatus.Failed, TimeStampVerifier.Verify(other, resp.Encoded).Find("nonce")!.Status);
        TimeStampRequest noNonce = Request(HashAlgorithmName.SHA256, [1], nonce: false);
        TimeStampResponse resp2 = t.Authority.Handle(noNonce.Encoded, T0);
        Assert.False(TstInfo.FromSignedData(resp2.Token!).HasNonce);
        Assert.Equal(CmsCheckStatus.NotApplicable, TimeStampVerifier.Verify(noNonce, resp2.Encoded).Find("nonce")!.Status);
        Assert.Equal(CmsCheckStatus.Failed, TimeStampVerifier.Verify(req, resp2.Encoded).Find("nonce")!.Status);
    }

    [Fact]
    public void DifferentImprintIsCaught()
    {
        Tsa t = Make(SigKind.P256);
        TimeStampRequest req = Request(HashAlgorithmName.SHA256, [1]);
        TimeStampResponse resp = t.Authority.Handle(req.Encoded, T0);
        TimeStampRequest forged = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData([2]), Nonce = req.Nonce.ToArray() });
        TimeStampReport r = TimeStampVerifier.Verify(forged, resp.Encoded);
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Find("message-imprint")!.Status);
    }

    [Fact]
    public void ATamperedTokenFailsTheSignature()
    {
        Tsa t = Make(SigKind.Rsa);
        TimeStampRequest req = Request(HashAlgorithmName.SHA256, [1]);
        byte[] bytes = t.Authority.Handle(req.Encoded, T0).Encoded.ToArray();
        // Flip a bit inside the TSTInfo's accuracy seconds (the integer 1 right after the genTime).
        int at = bytes.AsSpan().IndexOf(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 });
        Assert.True(at > 0);
        bytes[at + 4] = 0x02;
        TimeStampReport r = TimeStampVerifier.Verify(req, bytes);
        Assert.False(r.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, r.Find("signature")!.Status);
    }

    [Fact]
    public void AnotherPolicyIsRefusedAndRequestedPolicyIsHonoured()
    {
        Tsa t = Make(SigKind.P256);
        TimeStampResponse bad = t.Authority.Handle(Request(HashAlgorithmName.SHA256, [1], policy: "1.2.3.99").Encoded, T0);
        Assert.Equal(TimeStampStatus.Rejection, bad.Status);
        Assert.Equal(TimeStampFailure.UnacceptedPolicy, bad.FailureInfo);
        Assert.Empty(bad.TokenEncoded.ToArray());
        TimeStampRequest req = Request(HashAlgorithmName.SHA256, [1], policy: "1.2.3.4.5");
        TimeStampResponse ok = t.Authority.Handle(req.Encoded, T0);
        Assert.Equal("1.2.3.4.5", TstInfo.FromSignedData(ok.Token!).Policy);
        Assert.True(TimeStampVerifier.Verify(req, ok.Encoded).IsValid);
    }

    [Fact]
    public void RejectionsCarryTheRfc3161FailureBits()
    {
        Tsa t = Make(SigKind.P256);
        byte[] sha1Imprint = DerWriter.Sequence(DerWriter.SignedInteger(1), DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(KnownOids.Sha1)), DerWriter.OctetString(new byte[20])));
        Assert.Equal(TimeStampFailure.BadAlg, t.Authority.Handle(sha1Imprint, T0).FailureInfo);

        byte[] shortImprint = DerWriter.Sequence(DerWriter.SignedInteger(1), DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(KnownOids.Sha256)), DerWriter.OctetString(new byte[31])));
        Assert.Equal(TimeStampFailure.BadDataFormat, t.Authority.Handle(shortImprint, T0).FailureInfo);

        Assert.Equal(TimeStampFailure.BadDataFormat, t.Authority.Handle(new byte[] { 0x30, 0x80, 0x01 }, T0).FailureInfo);
        Assert.Equal(TimeStampFailure.BadDataFormat, t.Authority.Handle(Array.Empty<byte>(), T0).FailureInfo);

        TimeStampResponse r = t.Authority.Handle(DerWriter.Sequence(DerWriter.SignedInteger(1), DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(KnownOids.Sha256)), DerWriter.OctetString(new byte[32])),
            DerWriter.Retag(DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid("1.2.3.4.9"), DerWriter.Boolean(true), DerWriter.OctetString([5, 0]))), 0xA0)), T0);
        Assert.Equal(TimeStampFailure.UnacceptedExtension, r.FailureInfo);

        // The certificate is not valid in 2040: the authority will not stamp with it.
        Assert.Equal(TimeStampFailure.TimeNotAvailable, t.Authority.Handle(Request(HashAlgorithmName.SHA256, [1]).Encoded, new DateTimeOffset(2060, 1, 1, 0, 0, 0, TimeSpan.Zero)).FailureInfo);

        // A refusal parses as a response and a client reports it, never throws.
        TimeStampReport report = TimeStampVerifier.Verify(Request(HashAlgorithmName.SHA256, [1]), t.Authority.Handle(sha1Imprint, T0).Encoded);
        Assert.False(report.IsValid);
        Assert.Equal(CmsCheckStatus.Failed, report.Find("status")!.Status);
    }

    [Fact]
    public void AUserSerialSourceThatFailsIsASystemFailure()
    {
        SignerKit kit = CmsKeys.Get(SigKind.P256);
        var a = new TimeStampAuthority(new TimeStampAuthorityOptions { Certificate = CertificateFor(SigKind.P256), Signer = kit.Signer, DefaultPolicy = Policy }, new ThrowingSerials());
        Assert.Equal(TimeStampFailure.SystemFailure, a.Handle(Request(HashAlgorithmName.SHA256, [1]).Encoded, T0).FailureInfo);
    }

    private sealed class ThrowingSerials : ITimeStampSerialSource
    {
        public byte[] NextSerial() => throw new InvalidOperationException("database down");
    }

    [Fact]
    public void ACertificateWithoutTheCriticalTimeStampingUsageIsRefusedAtConstruction()
    {
        SignerKit kit = CmsKeys.Get(SigKind.P256);
        Certificate plain = IssuanceKit.Get().Intermediate.Issue(kit.Signer.PublicKey, DistinguishedName.Create((KnownOids.CommonName, "not a TSA")),
            new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = IssuanceKit.T0 });
        Assert.Throws<ArgumentException>(() => new TimeStampAuthority(new TimeStampAuthorityOptions { Certificate = plain, Signer = kit.Signer, DefaultPolicy = Policy }, new RandomTimeStampSerialSource()));
        Certificate nonCritical = IssuanceKit.Get().Intermediate.Issue(kit.Signer.PublicKey, DistinguishedName.Create((KnownOids.CommonName, "weak TSA")),
            new CertificateIssueOptions
            {
                Profile = new CertificateProfile { Name = "weak", KeyUsages = KeyUsages.DigitalSignature, ExtendedKeyUsages = [KnownOids.TimeStamping], MaxValidity = TimeSpan.FromDays(10) },
                NotBefore = IssuanceKit.T0,
            });
        Assert.Throws<ArgumentException>(() => new TimeStampAuthority(new TimeStampAuthorityOptions { Certificate = nonCritical, Signer = kit.Signer, DefaultPolicy = Policy }, new RandomTimeStampSerialSource()));
    }

    [Fact]
    public void ARequestIsReadBackFieldForField()
    {
        byte[] nonce = TimeStampRequest.NewNonce();
        TimeStampRequest r = TimeStampRequest.Create(new TimeStampRequestOptions
        {
            Hash = HashAlgorithmName.SHA512,
            MessageImprint = SHA512.HashData([1]),
            Policy = "1.2.3.4.5",
            Nonce = nonce,
            CertReq = true,
            Extensions = [Extension.Create("1.2.3.4.7", false, [5, 0])],
        });
        TimeStampRequest back = TimeStampRequest.Parse(r.Encoded);
        Assert.Equal(1, back.Version);
        Assert.Equal(KnownOids.Sha512, back.HashAlgorithm.Oid);
        Assert.Equal("1.2.3.4.5", back.Policy);
        Assert.True(back.HasNonce);
        Assert.True(back.CertReq);
        Assert.Equal("1.2.3.4.7", Assert.Single(back.Extensions).Oid);
        Assert.Throws<ArgumentException>(() => TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = new byte[31] }));
        Assert.Throws<ArgumentException>(() => TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA1, MessageImprint = new byte[20] }));
    }

    [Fact]
    public void ParsersRefuseHostileInputWithTypedErrors()
    {
        Assert.False(TimeStampRequest.TryParse(Array.Empty<byte>(), out _));
        Assert.False(TimeStampRequest.TryParse(new byte[1 << 17], out _));
        Assert.False(TimeStampResponse.TryParse(new byte[] { 0x30, 0x03, 0x30, 0x01, 0x07 }, out _));
        Assert.False(TstInfo.TryParse(new byte[] { 0x30, 0x00 }, out _));
        // A nonce past the limit.
        byte[] longNonce = DerWriter.Sequence(DerWriter.SignedInteger(1), DerWriter.Sequence(DerWriter.Sequence(DerWriter.Oid(KnownOids.Sha256)), DerWriter.OctetString(new byte[32])), DerWriter.UnsignedInteger(Enumerable.Repeat((byte)0x55, 100).ToArray()));
        Assert.Throws<TimeStampParseException>(() => TimeStampRequest.Parse(longNonce));
        // Deep nesting is an ASN.1 limit, reported as a time-stamp parse error.
        byte[] deep = new byte[200];
        for (int i = 0; i < 100; i++)
        {
            deep[i] = 0x30;
            deep[i + 100] = 0;
        }

        Assert.False(TimeStampRequest.TryParse(deep, out _));
        // Seed lift: the reshaped BuildRequest still writes version 1, imprint, nonce and certReq.
        byte[] seedStyle = Rfc3161.BuildRequest(HashAlgorithmName.SHA256, SHA256.HashData([1]), new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        TimeStampRequest p = TimeStampRequest.Parse(seedStyle);
        Assert.True(p.CertReq);
        Assert.True(p.HasNonce);
    }

    [Theory]
    [InlineData(SigKind.Rsa, "rsa")]
    [InlineData(SigKind.P256, "ecdsa")]
    [InlineData(SigKind.Ed25519, "ed25519")]
    public void TokenIsSignedInAnotherProcessFromSerialisedState(SigKind kind, string signerKind)
    {
        Tsa t = Make(kind);
        TimeStampRequest req = Request(HashAlgorithmName.SHA256, "two phase"u8.ToArray());
        PreparedTimeStamp prepared = t.Authority.Prepare(req.Encoded, T0);
        Assert.Null(prepared.Rejection);
        byte[] state = prepared.Encode();

        string dir = IssuanceKit.Dir("tsa-two-phase-" + kind);
        SignerKit kit = t.Kit;
        byte[] pkcs8 = Convert.FromBase64String(string.Concat(kit.Pkcs8Pem.Split('\n').Where(static l => !l.StartsWith("-----", StringComparison.Ordinal))));
        byte[] keyFile = signerKind == "ed25519" ? pkcs8.AsSpan(pkcs8.Length - 32).ToArray() : pkcs8;
        byte[] sig = IssuanceKit.SignInOtherProcess(dir, signerKind, keyFile, prepared.Signature!.Encode());

        // Only the serialised state survives into the "second process".
        PreparedTimeStamp restored = PreparedTimeStamp.Decode(state);
        TimeStampResponse resp = restored.Complete(sig);
        TimeStampReport report = TimeStampVerifier.Verify(req, resp.Encoded);
        Assert.True(report.IsValid, string.Join("; ", report.Checks.Where(c => c.Status is CmsCheckStatus.Failed).Select(c => c.Rule + ": " + c.Reason)));

        byte[] wrong = sig.ToArray();
        wrong[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => restored.Complete(wrong));
        Assert.Throws<FormatException>(() => PreparedTimeStamp.Decode(state.AsSpan(0, state.Length - 3)));
    }

    [Fact]
    public void TwoPhaseRefusalNeedsNoSignature()
    {
        Tsa t = Make(SigKind.P256, o => new TimeStampAuthorityOptions
        {
            Certificate = o.Certificate, Signer = o.Signer, DefaultPolicy = o.DefaultPolicy, SignatureSpec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256),
        });
        PreparedTimeStamp p = t.Authority.Prepare(new byte[] { 1, 2, 3 }, T0);
        Assert.NotNull(p.Rejection);
        Assert.Equal(TimeStampFailure.BadDataFormat, p.Rejection!.FailureInfo);
        Assert.Throws<InvalidOperationException>(() => p.Complete([1]));
    }

    // ---------------------------------------------------------------- openssl ts

    private static string RootPem => IssuanceKit.Get().Root.Certificate.ToPem();

    public static TheoryData<SigKind, string, bool, bool> OpenSslMatrix()
    {
        var d = new TheoryData<SigKind, string, bool, bool>();
        foreach (SigKind k in new[] { SigKind.Rsa, SigKind.P256, SigKind.Ed25519 })
        {
            foreach (string h in new[] { "sha256", "sha384", "sha512" })
            {
                foreach (bool nonce in new[] { true, false })
                {
                    foreach (bool cert in new[] { true, false })
                    {
                        d.Add(k, h, nonce, cert);
                    }
                }
            }
        }

        return d;
    }

    [Theory]
    [MemberData(nameof(OpenSslMatrix))]
    public void OpenSslVerifiesWhatOurAuthorityIssues(SigKind kind, string hash, bool nonce, bool certReq)
    {
        OpenSslTool.RequireOrSkip();
        if (kind == SigKind.Ed25519)
        {
            OpenSslTool.RequireOrSkip(3, 5, "EdDSA signatures over signed attributes in CMS");
        }

        string dir = IssuanceKit.Dir($"ts-b-{kind}-{hash}-{nonce}-{certReq}");
        byte[] data = RandomNumberGenerator.GetBytes(3000);
        string dataFile = IssuanceKit.Write(dir, "data.bin", data);
        string q = Path.Combine(dir, "q.tsq");
        var args = new List<string> { "ts", "-query", "-data", dataFile, "-" + hash, "-out", q };
        if (!nonce)
        {
            args.Add("-no_nonce");
        }

        if (certReq)
        {
            args.Add("-cert");
        }

        IssuanceKit.Ok(OpenSslTool.Run([.. args]), "ts -query");
        Tsa t = Make(kind);
        TimeStampResponse resp = t.Authority.Handle(File.ReadAllBytes(q), T0);
        Assert.True(resp.IsGranted, $"{resp.Status} {resp.FailureInfo}");
        string tsr = IssuanceKit.Write(dir, "r.tsr", resp.Encoded.ToArray());
        IssuanceKit.Write(dir, "root.pem", RootPem);
        IssuanceKit.Write(dir, "untrusted.pem", IssuanceKit.Get().Intermediate.Certificate.ToPem() + t.Certificate.ToPem());
        var v = new List<string> { "ts", "-verify", "-in", tsr, "-queryfile", q, "-CAfile", Path.Combine(dir, "root.pem"), "-untrusted", Path.Combine(dir, "untrusted.pem"), "-attime", IssuanceKit.Epoch(T0).ToString() };
        (int code, string output) = OpenSslTool.Run([.. v]);
        if (kind == SigKind.Ed25519)
        {
            // openssl ts verifies through its PKCS #7 code, which has no EdDSA; the same token is checked by openssl cms instead.
            Assert.True(code != 0 || output.Contains("Verification: OK", StringComparison.Ordinal));
            string token = IssuanceKit.Write(dir, "token.der", resp.TokenEncoded.ToArray());
            IssuanceKit.Ok(OpenSslTool.Run("cms", "-verify", "-inform", "DER", "-in", token, "-certfile", Path.Combine(dir, "untrusted.pem"), "-noverify", "-binary", "-out", Path.Combine(dir, "tst.der")), "cms -verify of the Ed25519 token");
            Assert.Equal(TstInfo.FromSignedData(resp.Token!).Encoded.ToArray(), File.ReadAllBytes(Path.Combine(dir, "tst.der")));
            return;
        }

        Assert.True(code == 0, "ts -verify: " + output);
        Assert.Contains("Verification: OK", output);

        // The token as text: policy, nonce echo, serial, accuracy and the tsa field are what we asked for.
        (int c2, string text) = OpenSslTool.Run("ts", "-reply", "-in", tsr, "-text");
        Assert.Equal(0, c2);
        Assert.Contains("Status: Granted.", text);
        Assert.Contains("Policy OID: " + Policy, text);
        Assert.Contains(nonce ? "Nonce: 0x" : "Nonce: unspecified", text);
        Assert.Contains("Accuracy: 0x01 seconds", text);
    }

    [Theory]
    [MemberData(nameof(OpenSslMatrix))]
    public void OurClientVerifiesWhatOpenSslIssues(SigKind kind, string hash, bool nonce, bool certReq)
    {
        OpenSslTool.RequireOrSkip();
        string dir = IssuanceKit.Dir($"ts-a-{kind}-{hash}-{nonce}-{certReq}");
        SignerKit kit = CmsKeys.Get(kind);
        Certificate tsaCert = CertificateFor(kind);
        HashAlgorithmName name = hash == "sha256" ? HashAlgorithmName.SHA256 : hash == "sha384" ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA512;
        TimeStampRequest req = Request(name, RandomNumberGenerator.GetBytes(500), nonce, certReq);
        string q = IssuanceKit.Write(dir, "q.tsq", req.Encoded.ToArray());
        string conf = IssuanceKit.Write(dir, "ts.cnf", $$"""
            [ tsa ]
            default_tsa = tsa1
            [ tsa1 ]
            serial = {{dir}}/serial
            crypto_device = builtin
            signer_cert = {{IssuanceKit.Write(dir, "tsa.pem", tsaCert.ToPem())}}
            certs = {{IssuanceKit.Write(dir, "chain.pem", IssuanceKit.Get().Intermediate.Certificate.ToPem())}}
            signer_key = {{IssuanceKit.Write(dir, "tsa.key", kit.Pkcs8Pem)}}
            signer_digest = sha256
            default_policy = {{Policy}}
            other_policies = 1.2.3.4.5
            digests = sha256, sha384, sha512
            accuracy = secs:1
            ordering = yes
            tsa_name = yes
            ess_cert_id_chain = no
            ess_cert_id_alg = sha256
            """);
        IssuanceKit.Write(dir, "serial", "0A\n");
        string tsr = Path.Combine(dir, "r.tsr");
        (int code, string output) = OpenSslTool.Run("ts", "-reply", "-queryfile", q, "-config", conf, "-out", tsr);
        if (kind == SigKind.Ed25519 && (code != 0 || TimeStampResponse.Parse(File.ReadAllBytes(tsr)).Status != TimeStampStatus.Granted))
        {
            Assert.Skip("openssl ts -reply does not sign with Ed25519 (it answers a rejection); the Ed25519 token is covered by the cms check in the other direction");
        }

        Assert.True(code == 0, "ts -reply: " + output);
        TimeStampReport report = TimeStampVerifier.Verify(req, File.ReadAllBytes(tsr), new TimeStampVerifyOptions { ExtraCertificates = certReq ? [] : [tsaCert] });
        Assert.True(report.IsValid, string.Join("; ", report.Checks.Where(c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported).Select(c => c.Rule + ": " + c.Reason)));
        Assert.True(report.Info!.Ordering);
        Assert.Equal(Policy, report.Info.Policy);
    }
}
