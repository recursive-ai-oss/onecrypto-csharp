using System.Security.Cryptography;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Issuance;

/// <summary>The OCSP responder handler on its own and against the openssl <c>ocsp</c> command as a black box.</summary>
public class OcspResponderTests
{
    // openssl judges response times against the real clock, so these tests issue "now" for real. The library never reads it.
    private static readonly DateTimeOffset Now = new(DateTimeOffset.UtcNow.UtcDateTime.Date.AddHours(DateTimeOffset.UtcNow.Hour), TimeSpan.Zero);

    private static IssuanceKit Kit => IssuanceKit.Get();

    private static DistinguishedName Name(string cn) => DistinguishedName.Create((KnownOids.Organization, "OneCrypto Tests"), (KnownOids.CommonName, cn));

    private static readonly Dictionary<SigKind, Certificate> Delegates = [];

    private static Certificate DelegateCertificate(SigKind kind)
    {
        lock (Delegates)
        {
            if (!Delegates.TryGetValue(kind, out Certificate? c))
            {
                c = Kit.Intermediate.Issue(CmsKeys.Get(kind).Signer.PublicKey, Name("OCSP responder " + kind),
                    new CertificateIssueOptions { Profile = CertificateProfile.OcspSigning, NotBefore = Now.AddDays(-1) });
                Delegates[kind] = c;
            }

            return c;
        }
    }

    private sealed record Fixture(Certificate Good, Certificate Revoked, Certificate Unknown, InMemoryRevocationSource Source);

    private static readonly DateTimeOffset RevokedAt = Now.AddHours(-5);

    private static Fixture MakeFixture()
    {
        Certificate Leaf(string cn) => Kit.Intermediate.Issue(CmsKeys.Get(SigKind.P256).Signer.PublicKey, Name(cn),
            new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = IssuanceKit.T0 });
        var f = new Fixture(Leaf("good"), Leaf("revoked"), Leaf("unknown"), new InMemoryRevocationSource(TimeSpan.FromHours(12)));
        f.Source.SetGood(f.Good.SerialNumber.Span);
        f.Source.SetRevoked(f.Revoked.SerialNumber.Span, RevokedAt, RevocationReason.KeyCompromise);
        return f;
    }

    private static readonly Lazy<Fixture> Shared = new(MakeFixture);

    private static Fixture Fx => Shared.Value;

    private static OcspResponder Make(SigKind? delegated = null, Func<OcspResponderOptions, OcspResponderOptions>? tweak = null, IRevocationStatusSource? source = null)
    {
        Certificate issuer = Kit.Intermediate.Certificate;
        X509Signer signer;
        Certificate cert;
        SignatureSpec? spec = null;
        if (delegated is { } kind)
        {
            cert = DelegateCertificate(kind);
            signer = CmsKeys.Get(kind).Signer;
            spec = kind == SigKind.Ed25519 ? SignatureSpec.Ed25519() : null;
        }
        else
        {
            cert = issuer;
            signer = X509Signer.FromECDsa(Kit.InterKey);
        }

        var o = new OcspResponderOptions { Issuer = issuer, ResponderCertificate = cert, Signer = signer, SignatureSpec = spec, Source = source ?? Fx.Source };
        return new OcspResponder(tweak?.Invoke(o) ?? o);
    }

    private static OcspRequest Request(IEnumerable<Certificate> certs, byte[]? nonce = null, Certificate? issuer = null, HashAlgorithmName? hash = null) =>
        OcspRequestBuilder.Create(new OcspRequestOptions
        {
            Requests = [.. certs.Select(c => OcspCertId.Create(c, issuer ?? Kit.Intermediate.Certificate, hash))],
            Nonce = nonce ?? default,
        });

    private static OcspSingleResponse Only(OcspResponse r)
    {
        Assert.Equal(OcspResponseStatus.Successful, r.Status);
        return Assert.Single(r.BasicResponse!.Responses);
    }

    /// <summary>What a client must establish about a response before believing it: signer, signature, nonce and certificate id.</summary>
    private static void AssertSound(OcspResponse r, OcspRequest request, Certificate? expectedDelegate)
    {
        OcspBasicResponse b = r.BasicResponse!;
        PublicKeyInfo signerKey;
        if (expectedDelegate is null)
        {
            Assert.True(b.ResponderId.Matches(Kit.Intermediate.Certificate));
            signerKey = Kit.Intermediate.Certificate.PublicKey;
            Assert.Empty(b.Certificates);
        }
        else
        {
            Certificate d = Assert.Single(b.Certificates);
            Assert.Equal(expectedDelegate, d);
            Assert.True(b.ResponderId.Matches(d));
            Assert.True(d.VerifySignature(Kit.Intermediate.Certificate).IsValid);
            Assert.Contains(KnownOids.OcspSigning, d.ExtendedKeyUsage!.Purposes);
            Assert.True(d.Extensions.Contains(KnownOids.OcspNoCheck));
            signerKey = d.PublicKey;
        }

        Assert.True(b.VerifySignature(signerKey).IsValid);
        if (request.Nonce is { } n)
        {
            Assert.True(b.Nonce!.Value.Span.SequenceEqual(n.Span));
        }
        else
        {
            Assert.Null(b.Nonce);
        }

        for (int i = 0; i < request.Requests.Count; i++)
        {
            Assert.Equal(request.Requests[i].CertId, b.Responses[i].CertId);
        }
    }

    public static TheoryData<bool, SigKind, bool> Modes()
    {
        var d = new TheoryData<bool, SigKind, bool>();
        foreach (bool byName in new[] { false, true })
        {
            foreach (SigKind k in new[] { SigKind.Rsa, SigKind.P256, SigKind.Ed25519 })
            {
                foreach (bool deleg in new[] { false, true })
                {
                    if (deleg || k == SigKind.Rsa)
                    {
                        d.Add(byName, k, deleg);
                    }
                }
            }
        }

        return d;
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public void AnswersGoodRevokedAndUnknownSigned(bool byName, SigKind kind, bool isDelegated)
    {
        OcspResponder r = Make(isDelegated ? kind : null, o => new OcspResponderOptions
        {
            Issuer = o.Issuer, ResponderCertificate = o.ResponderCertificate, Signer = o.Signer, Source = o.Source,
            ResponderId = byName ? OcspResponderIdKind.ByName : OcspResponderIdKind.ByKey,
        });
        Certificate? del = isDelegated ? DelegateCertificate(kind) : null;
        foreach ((Certificate cert, OcspCertStatus expected) in new[] { (Fx.Good, OcspCertStatus.Good), (Fx.Revoked, OcspCertStatus.Revoked), (Fx.Unknown, OcspCertStatus.Unknown) })
        {
            OcspRequest req = Request([cert], RandomNumberGenerator.GetBytes(16));
            OcspResponse resp = r.Handle(req.Encoded, Now);
            OcspSingleResponse s = Only(resp);
            Assert.Equal(expected, s.Status);
            AssertSound(resp, req, del);
            Assert.Equal(Now, resp.BasicResponse!.ProducedAt);
            Assert.Equal(Now, s.ThisUpdate);
            Assert.Equal(expected == OcspCertStatus.Unknown ? null : Now.AddHours(12), s.NextUpdate); // the in-memory source gives no window for what it does not know
            Assert.Equal(byName, resp.BasicResponse.ResponderId.Name is not null);
            if (expected == OcspCertStatus.Revoked)
            {
                Assert.Equal(RevokedAt, s.RevocationTime);
                Assert.Equal(RevocationReason.KeyCompromise, s.RevocationReason);
            }
        }
    }

    [Fact]
    public void SeveralCertificatesInOneRequestAreAnsweredInOrder()
    {
        OcspRequest req = Request([Fx.Revoked, Fx.Unknown, Fx.Good], hash: HashAlgorithmName.SHA256);
        OcspResponse resp = Make().Handle(req.Encoded, Now);
        Assert.Equal([OcspCertStatus.Revoked, OcspCertStatus.Unknown, OcspCertStatus.Good], resp.BasicResponse!.Responses.Select(static s => s.Status));
        AssertSound(resp, req, null);
    }

    /// <summary>A request with a nonce of any length, which the builder refuses to make for lengths RFC 8954 forbids.</summary>
    private static byte[] RawRequest(byte[] nonce)
    {
        byte[] certId = OcspCertId.Create(Fx.Good, Kit.Intermediate.Certificate).Encoded.ToArray();
        byte[] ext = Extension.Create(KnownOids.OcspNonce, false, DerWriter.OctetString(nonce)).Encoded.ToArray();
        return DerWriter.Sequence(DerWriter.Sequence(DerWriter.Sequence(DerWriter.Sequence(certId)), DerWriter.Context(2, DerWriter.Sequence(ext))));
    }

    [Fact]
    public void NonceLengthBoundsFollowRfc8954()
    {
        OcspResponder r = Make();
        foreach (int len in new[] { 1, 16, 32 })
        {
            OcspRequest req = Request([Fx.Good], RandomNumberGenerator.GetBytes(len));
            OcspResponse resp = r.Handle(req.Encoded, Now);
            Assert.Equal(OcspResponseStatus.Successful, resp.Status);
            AssertSound(resp, req, null);
        }

        Assert.Equal(OcspResponseStatus.MalformedRequest, r.Handle(RawRequest(RandomNumberGenerator.GetBytes(33)), Now).Status);
        Assert.Equal(OcspResponseStatus.MalformedRequest, r.Handle(RawRequest([]), Now).Status);
        Assert.Equal(OcspResponseStatus.Successful, r.Handle(RawRequest(RandomNumberGenerator.GetBytes(32)), Now).Status);
        OcspRequest noNonce = Request([Fx.Good]);
        Assert.Null(r.Handle(noNonce.Encoded, Now).BasicResponse!.Nonce);
    }

    [Fact]
    public void ErrorsAreStatusesNeverExceptions()
    {
        Assert.Equal(OcspResponseStatus.MalformedRequest, Make().Handle(new byte[] { 1, 2, 3 }, Now).Status);
        Assert.Equal(OcspResponseStatus.MalformedRequest, Make().Handle(Array.Empty<byte>(), Now).Status);
        Assert.Equal(OcspResponseStatus.MalformedRequest, Make().Handle(new byte[1 << 17], Now).Status);

        // Too many certificates in one request.
        OcspRequest many = Request(Enumerable.Repeat(Fx.Good, 5));
        Assert.Equal(OcspResponseStatus.MalformedRequest, Make(null, o => new OcspResponderOptions { Issuer = o.Issuer, ResponderCertificate = o.ResponderCertificate, Signer = o.Signer, Source = o.Source, MaxRequests = 4 }).Handle(many.Encoded, Now).Status);

        // sigRequired for an unsigned request; unauthorized when the host's check says no.
        OcspRequest plain = Request([Fx.Good]);
        Assert.Equal(OcspResponseStatus.SigRequired, Make(null, o => new OcspResponderOptions { Issuer = o.Issuer, ResponderCertificate = o.ResponderCertificate, Signer = o.Signer, Source = o.Source, RequireSignedRequests = true }).Handle(plain.Encoded, Now).Status);
        Assert.Equal(OcspResponseStatus.Unauthorized, Make(null, o => new OcspResponderOptions { Issuer = o.Issuer, ResponderCertificate = o.ResponderCertificate, Signer = o.Signer, Source = o.Source, AuthorizeRequest = _ => false }).Handle(plain.Encoded, Now).Status);
        Assert.Equal(OcspResponseStatus.InternalError, Make(null, o => new OcspResponderOptions { Issuer = o.Issuer, ResponderCertificate = o.ResponderCertificate, Signer = o.Signer, Source = o.Source, AuthorizeRequest = _ => throw new InvalidOperationException() }).Handle(plain.Encoded, Now).Status);

        // A signed request passes the host's authorisation when its signature is right.
        SignerKit requestor = CmsKeys.Get(SigKind.P256);
        OcspRequest signed = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [OcspCertId.Create(Fx.Good, Kit.Intermediate.Certificate)] }, requestor.Signer, [requestor.Certificate]);
        OcspResponder strict = Make(null, o => new OcspResponderOptions
        {
            Issuer = o.Issuer, ResponderCertificate = o.ResponderCertificate, Signer = o.Signer, Source = o.Source, RequireSignedRequests = true,
            AuthorizeRequest = q => q.Certificates.Count == 1 && q.VerifySignature(q.Certificates[0].PublicKey).IsValid,
        });
        Assert.Equal(OcspResponseStatus.Successful, strict.Handle(signed.Encoded, Now).Status);

        // Another CA's certificate: unauthorized as a whole (RFC 6960 §2.3, RFC 5019 §2.2.3); mixed requests mark only the foreign one unknown.
        Certificate foreign = Kit.Root.Certificate;
        OcspRequest all = Request([Fx.Good], issuer: foreign);
        Assert.Equal(OcspResponseStatus.Unauthorized, Make().Handle(all.Encoded, Now).Status);
        OcspRequest mixed = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [OcspCertId.Create(Fx.Good, Kit.Intermediate.Certificate), OcspCertId.Create(Fx.Good, foreign)] });
        Assert.Equal([OcspCertStatus.Good, OcspCertStatus.Unknown], Make().Handle(mixed.Encoded, Now).BasicResponse!.Responses.Select(static s => s.Status));
    }

    private sealed class Stale : IRevocationStatusSource
    {
        public RevocationStatus? Lookup(OcspCertId id, DateTimeOffset now) => RevocationStatus.Good(now.AddDays(-2), now.AddDays(-1));
    }

    private sealed class Broken : IRevocationStatusSource
    {
        public RevocationStatus? Lookup(OcspCertId id, DateTimeOffset now) => throw new InvalidOperationException("database down");
    }

    [Fact]
    public void StaleOrBrokenSourcesAndExpiredResponderCertificatesAreNotAnsweredAsFacts()
    {
        OcspRequest req = Request([Fx.Good]);
        Assert.Equal(OcspResponseStatus.TryLater, Make(source: new Stale()).Handle(req.Encoded, Now).Status);
        Assert.Equal(OcspResponseStatus.InternalError, Make(source: new Broken()).Handle(req.Encoded, Now).Status);
        Assert.Equal(OcspResponseStatus.InternalError, Make().Handle(req.Encoded, Now.AddYears(40)).Status);
    }

    [Fact]
    public void ADelegatedResponderMustBeTheCasOwnOcspSigningCertificate()
    {
        Certificate notOcsp = Kit.Intermediate.Issue(CmsKeys.Get(SigKind.P256).Signer.PublicKey, Name("not a responder"), new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = Now.AddDays(-1) });
        Assert.Throws<ArgumentException>(() => new OcspResponder(new OcspResponderOptions { Issuer = Kit.Intermediate.Certificate, ResponderCertificate = notOcsp, Signer = CmsKeys.Get(SigKind.P256).Signer, Source = Fx.Source }));
        // A responder certificate from a different CA.
        Certificate other = Kit.Root.Issue(CmsKeys.Get(SigKind.P256).Signer.PublicKey, Name("other CA's responder"), new CertificateIssueOptions { Profile = CertificateProfile.OcspSigning, NotBefore = Now.AddDays(-1) });
        Assert.Throws<ArgumentException>(() => new OcspResponder(new OcspResponderOptions { Issuer = Kit.Intermediate.Certificate, ResponderCertificate = other, Signer = CmsKeys.Get(SigKind.P256).Signer, Source = Fx.Source }));
        // The signer must hold the certificate's key.
        Assert.Throws<ArgumentException>(() => new OcspResponder(new OcspResponderOptions { Issuer = Kit.Intermediate.Certificate, ResponderCertificate = DelegateCertificate(SigKind.P256), Signer = CmsKeys.Get(SigKind.Rsa).Signer, Source = Fx.Source }));
    }

    [Fact]
    public void PreproducedResponsesAreServedWhileCurrentAndOnlyWithoutANonce()
    {
        var store = new InMemoryPreproducedResponses();
        OcspResponder r = Make(null, o => new OcspResponderOptions { Issuer = o.Issuer, ResponderCertificate = o.ResponderCertificate, Signer = o.Signer, Source = o.Source, Preproduced = store });
        OcspCertId id = OcspCertId.Create(Fx.Revoked, Kit.Intermediate.Certificate);
        OcspResponse stored = r.Preproduce([id], Now);
        store.Set(id, stored);

        OcspRequest plain = Request([Fx.Revoked]);
        Assert.Equal(stored.Encoded.ToArray(), r.Handle(plain.Encoded, Now.AddHours(1)).Encoded.ToArray());
        Assert.Null(stored.BasicResponse!.Nonce);

        // A request with a nonce needs a fresh signature, since the stored one cannot echo it.
        OcspRequest withNonce = Request([Fx.Revoked], RandomNumberGenerator.GetBytes(8));
        OcspResponse fresh = r.Handle(withNonce.Encoded, Now.AddHours(1));
        Assert.NotEqual(stored.Encoded.ToArray(), fresh.Encoded.ToArray());
        AssertSound(fresh, withNonce, null);

        // Past its nextUpdate the stored answer is not served; a new one is signed.
        OcspResponse later = r.Handle(plain.Encoded, Now.AddHours(13));
        Assert.NotEqual(stored.Encoded.ToArray(), later.Encoded.ToArray());
        Assert.Equal(OcspCertStatus.Revoked, Only(later).Status);
    }

    [Theory]
    [InlineData(null, "ecdsa")]
    [InlineData(SigKind.Ed25519, "ed25519")]
    public void AResponseIsSignedInAnotherProcessFromSerialisedState(SigKind? delegated, string signerKind)
    {
        OcspResponder r = Make(delegated, o => new OcspResponderOptions
        {
            Issuer = o.Issuer, ResponderCertificate = o.ResponderCertificate, Signer = o.Signer, Source = o.Source,
            SignatureSpec = delegated is null ? SignatureSpec.Ecdsa(HashAlgorithmName.SHA384) : o.SignatureSpec,
        });
        OcspRequest req = Request([Fx.Revoked], RandomNumberGenerator.GetBytes(12));
        PreparedOcspResponse prepared = r.Prepare(req.Encoded, Now);
        Assert.Null(prepared.Immediate);
        byte[] state = prepared.Encode();

        string dir = IssuanceKit.Dir("ocsp-two-phase-" + signerKind);
        byte[] keyFile;
        if (delegated is null)
        {
            keyFile = Kit.InterKey.ExportPkcs8PrivateKey();
        }
        else
        {
            byte[] pkcs8 = Convert.FromBase64String(string.Concat(CmsKeys.Get(delegated.Value).Pkcs8Pem.Split('\n').Where(static l => !l.StartsWith("-----", StringComparison.Ordinal))));
            keyFile = pkcs8.AsSpan(pkcs8.Length - 32).ToArray();
        }

        byte[] sig = IssuanceKit.SignInOtherProcess(dir, signerKind, keyFile, prepared.Signature!.Encode());
        OcspResponse resp = PreparedOcspResponse.Decode(state).Complete(sig);
        Assert.Equal(OcspCertStatus.Revoked, Only(resp).Status);
        AssertSound(resp, req, delegated is null ? null : DelegateCertificate(delegated.Value));

        byte[] wrong = sig.ToArray();
        wrong[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => PreparedOcspResponse.Decode(state).Complete(wrong));
        Assert.Throws<FormatException>(() => PreparedOcspResponse.Decode(state.AsSpan(0, state.Length - 2)));

        // An error answer needs no signature.
        PreparedOcspResponse err = r.Prepare(new byte[] { 0x30, 0x00 }, Now);
        Assert.Equal(OcspResponseStatus.MalformedRequest, err.Immediate!.Status);
        Assert.Throws<InvalidOperationException>(() => err.Complete([1]));
    }

    [Fact]
    public void MutatedRequestsNeverEscapeAsExceptions()
    {
        byte[] seed = Request([Fx.Good, Fx.Revoked], RandomNumberGenerator.GetBytes(8)).Encoded.ToArray();
        OcspResponder r = Make();
        var rng = new Random(15);
        for (int i = 0; i < 2000; i++)
        {
            byte[] m = (byte[])seed.Clone();
            int flips = 1 + rng.Next(4);
            for (int f = 0; f < flips; f++)
            {
                m[rng.Next(m.Length)] = (byte)rng.Next(256);
            }

            OcspResponse resp = r.Handle(i % 7 == 0 ? m.AsMemory(0, rng.Next(m.Length)) : m, Now);
            Assert.True(Enum.IsDefined(resp.Status));
        }
    }

    // ---------------------------------------------------------------- openssl ocsp

    private static string IndexLine(Certificate c, bool revoked) =>
        revoked
            ? $"R\t301231000000Z\t{RevokedAt.UtcDateTime:yyMMddHHmmss}Z,keyCompromise\t{Convert.ToHexString(c.SerialNumber.Span)}\tunknown\t/O=OneCrypto Tests/CN=revoked\n"
            : $"V\t301231000000Z\t\t{Convert.ToHexString(c.SerialNumber.Span)}\tunknown\t/O=OneCrypto Tests/CN=good\n";

    public static TheoryData<string, string, bool> OpenSslMatrix()
    {
        var d = new TheoryData<string, string, bool>();
        foreach (string signer in new[] { "ca", "rsa", "p256", "ed25519" })
        {
            foreach (string status in new[] { "good", "revoked", "unknown" })
            {
                foreach (bool nonce in new[] { true, false })
                {
                    d.Add(signer, status, nonce);
                }
            }
        }

        return d;
    }

    private static SigKind? KindOf(string signer) => signer switch { "rsa" => SigKind.Rsa, "p256" => SigKind.P256, "ed25519" => SigKind.Ed25519, _ => null };

    private static Certificate CertFor(string status) => status switch { "good" => Fx.Good, "revoked" => Fx.Revoked, _ => Fx.Unknown };

    [Theory]
    [MemberData(nameof(OpenSslMatrix))]
    public void OurRequestIsAnsweredByOpenSslAndWeVerifyItsResponse(string signer, string status, bool nonce)
    {
        OpenSslTool.RequireOrSkip();
        string dir = IssuanceKit.Dir($"ocsp-a-{signer}-{status}-{nonce}");
        Certificate leaf = CertFor(status);
        OcspRequest req = Request([leaf], nonce ? RandomNumberGenerator.GetBytes(16) : null);
        string reqFile = IssuanceKit.Write(dir, "req.der", req.Encoded.ToArray());
        IssuanceKit.Write(dir, "index.txt", IndexLine(Fx.Good, false) + IndexLine(Fx.Revoked, true));
        string ca = IssuanceKit.Write(dir, "ca.pem", Kit.Intermediate.Certificate.ToPem());
        SigKind? kind = KindOf(signer);
        Certificate? del = kind is { } k ? DelegateCertificate(k) : null;
        string sCert = IssuanceKit.Write(dir, "signer.pem", (del ?? Kit.Intermediate.Certificate).ToPem());
        string sKey = IssuanceKit.Write(dir, "signer.key", kind is { } k2 ? CmsKeys.Get(k2).Pkcs8Pem : Kit.InterKey.ExportPkcs8PrivateKeyPem());
        string respFile = Path.Combine(dir, "resp.der");

        (int code, string output) = OpenSslTool.Run("ocsp", "-index", Path.Combine(dir, "index.txt"), "-CA", ca, "-rsigner", sCert, "-rkey", sKey, "-reqin", reqFile, "-respout", respFile, "-ndays", "1");
        if (kind == SigKind.Ed25519 && (code != 0 || !File.Exists(respFile) || OcspResponse.Parse(File.ReadAllBytes(respFile)).Status != OcspResponseStatus.Successful))
        {
            Assert.Skip("this openssl's ocsp responder does not sign with Ed25519: " + output.Trim());
        }

        Assert.True(code == 0, "ocsp responder: " + output);
        OcspResponse resp = OcspResponse.Parse(File.ReadAllBytes(respFile));
        OcspSingleResponse s = Only(resp);
        Assert.Equal(status == "good" ? OcspCertStatus.Good : status == "revoked" ? OcspCertStatus.Revoked : OcspCertStatus.Unknown, s.Status);
        if (status == "revoked")
        {
            Assert.Equal(RevocationReason.KeyCompromise, s.RevocationReason);
            Assert.Equal(RevokedAt.ToUnixTimeSeconds(), s.RevocationTime!.Value.ToUnixTimeSeconds());
        }

        // Our checks of what openssl signed: its responder id, the signature, the nonce and the certificate id.
        OcspBasicResponse b = resp.BasicResponse!;
        PublicKeyInfo key;
        if (del is null)
        {
            Assert.True(b.ResponderId.Matches(Kit.Intermediate.Certificate));
            key = Kit.Intermediate.Certificate.PublicKey;
        }
        else
        {
            Certificate included = Assert.Single(b.Certificates);
            Assert.Equal(del, included);
            Assert.True(b.ResponderId.Matches(included));
            key = included.PublicKey;
        }

        Assert.True(b.VerifySignature(key).IsValid);
        Assert.Equal(req.Requests[0].CertId, s.CertId);
        if (nonce)
        {
            Assert.True(b.Nonce!.Value.Span.SequenceEqual(req.Nonce!.Value.Span));
        }
        else
        {
            Assert.Null(b.Nonce);
        }
    }

    [Theory]
    [MemberData(nameof(OpenSslMatrix))]
    public void OpenSslVerifiesWhatOurResponderSigns(string signer, string status, bool nonce)
    {
        OpenSslTool.RequireOrSkip();
        string dir = IssuanceKit.Dir($"ocsp-b-{signer}-{status}-{nonce}");
        Certificate leaf = CertFor(status);
        string root = IssuanceKit.Write(dir, "root.pem", Kit.Root.Certificate.ToPem());
        string ca = IssuanceKit.Write(dir, "ca.pem", Kit.Intermediate.Certificate.ToPem());
        string leafFile = IssuanceKit.Write(dir, "leaf.pem", leaf.ToPem());
        string reqFile = Path.Combine(dir, "req.der");
        var q = new List<string> { "ocsp", "-issuer", ca, "-cert", leafFile, "-reqout", reqFile };
        if (!nonce)
        {
            q.Add("-no_nonce");
        }

        IssuanceKit.Ok(OpenSslTool.Run([.. q]), "ocsp -reqout");
        SigKind? kind = KindOf(signer);
        OcspResponder r = Make(kind);
        OcspResponse resp = r.Handle(File.ReadAllBytes(reqFile), Now);
        Assert.Equal(OcspResponseStatus.Successful, resp.Status);
        string respFile = IssuanceKit.Write(dir, "resp.der", resp.Encoded.ToArray());

        // With -reqin openssl checks the nonce echo against our request (naming -cert as well makes it build a new request with a new nonce).
        (int code0, string output0) = OpenSslTool.Run("ocsp", "-respin", respFile, "-reqin", reqFile, "-CAfile", root, "-verify_other", ca);
        if (kind == SigKind.Ed25519 && code0 != 0)
        {
            Assert.Skip("this openssl's ocsp does not verify an Ed25519 responder: " + output0.Trim());
        }

        Assert.True(code0 == 0, "ocsp -respin -reqin: " + output0);
        Assert.Contains("Response verify OK", output0);
        Assert.DoesNotContain("WARNING", output0);
        var v = new List<string> { "ocsp", "-respin", respFile, "-no_nonce", "-issuer", ca, "-cert", leafFile, "-CAfile", root, "-verify_other", ca };
        (int code, string output) = OpenSslTool.Run([.. v]);
        if (kind == SigKind.Ed25519 && code != 0)
        {
            // openssl ocsp checks an Ed25519 responder through OCSP_basic_verify, which does not take EdDSA; the response is checked as ours above.
            Assert.Skip("this openssl's ocsp does not verify an Ed25519 responder: " + output.Trim());
        }

        Assert.True(code == 0, "ocsp -respin: " + output);
        Assert.Contains("Response verify OK", output);
        Assert.Contains($"leaf.pem: {status}", output);
        if (status == "revoked")
        {
            Assert.Contains("Reason: keyCompromise", output);
        }
    }
}
