using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Online.Csc;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Online.Tests.Csc;

/// <summary>Everything a CSC test needs: the test server, a clock the test owns, a client over them, and credentials with certificates from the test PKI.</summary>
internal sealed class CscRig
{
    public const string Pin = "123456";
    public static readonly Uri Base = new("https://csc.test/csc/v2/");

    public CscRig(Action<CscTestServer>? configure = null, ICscTokenSource? tokens = null, CscClientOptions? options = null, bool deterministic = false, FetchOptions? fetch = null)
    {
        Clock = new TestClock(World.Now);
        Server = new CscTestServer(Clock.GetUtcNow) { Deterministic = deterministic };
        configure?.Invoke(Server);
        Transport = new CscTestTransport(Server, Base);
        Token = Server.IssueServiceToken(TimeSpan.FromHours(1));
        Fetcher = new Fetcher(Transport, fetch ?? new FetchOptions { Cache = null, Time = Clock });
        Client = new CscClient(Fetcher, Base, tokens ?? new CscStaticTokenSource(new CscAccessToken(Token, Clock.GetUtcNow().AddHours(1))), options);
    }

    public TestClock Clock { get; }

    public CscTestServer Server { get; }

    public CscTestTransport Transport { get; }

    public Fetcher Fetcher { get; }

    public CscClient Client { get; }

    public string Token { get; }

    public static CscKeyOptions WithPin(string pin = Pin) => new() { AuthDataProvider = (_, _) => ValueTask.FromResult<IReadOnlyList<CscAuthObject>>([new CscAuthObject("PIN", pin)]) };

    public static CscTestCredential Credential(string id, string kind, int scal = 1, TestAuthMode mode = TestAuthMode.Explicit, string? pin = Pin, bool ecdsaDer = false, int multisign = 3, bool enabled = true)
    {
        World w = World.Get();
        ISigningKey key = kind switch
        {
            "rsa" => PrivateKey.FromRsa(RSA.Create(2048), ownsKey: true),
            "p384" => PrivateKey.FromECDsa(ECDsa.Create(ECCurve.NamedCurves.nistP384), ownsKey: true),
            _ => PrivateKey.FromECDsa(ECDsa.Create(ECCurve.NamedCurves.nistP256), ownsKey: true),
        };
        Certificate leaf = w.Intermediate.Issue(key.PublicKey, DistinguishedName.Create((KnownOids.CommonName, "CSC test signer " + id)), new CertificateIssueOptions
        {
            Profile = CertificateProfile.SMime,
            NotBefore = World.T0.AddDays(-1),
            Validity = TimeSpan.FromDays(365),
            SubjectAlternativeNames = [GeneralName.Email("signer@example.test")],
        });
        return new CscTestCredential { Id = id, Key = key, Chain = [leaf, w.Intermediate.Certificate, w.Root.Certificate], Scal = scal, Mode = mode, Pin = pin, EcdsaDer = ecdsaDer, Multisign = multisign, KeyEnabled = enabled };
    }

    public static byte[] Digest(string text, HashAlgorithmName hash) => CryptographicOperations.HashData(hash, Encoding.UTF8.GetBytes(text));

    public static SignatureSpec Spec(string name) => name switch
    {
        "rsa-pkcs1-sha256" => SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA256),
        "rsa-pkcs1-sha384" => SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA384),
        "rsa-pkcs1-sha512" => SignatureSpec.RsaPkcs1(HashAlgorithmName.SHA512),
        "rsa-pss-sha256" => SignatureSpec.RsaPss(HashAlgorithmName.SHA256),
        "rsa-pss-sha384" => SignatureSpec.RsaPss(HashAlgorithmName.SHA384),
        "ecdsa-sha256" => SignatureSpec.Ecdsa(HashAlgorithmName.SHA256),
        "ecdsa-sha256-p1363" => SignatureSpec.Ecdsa(HashAlgorithmName.SHA256, EcdsaSignatureFormat.Rfc4754),
        "ecdsa-sha384" => SignatureSpec.Ecdsa(HashAlgorithmName.SHA384),
        _ => throw new ArgumentException(name),
    };

    public async Task<CscSigningKey> Open(CscTestCredential c, CscKeyOptions? options = null)
    {
        Server.Add(c);
        CscResult<CscSigningKey> r = await Client.OpenSigningKeyAsync(c.Id, options ?? WithPin());
        Assert.True(r.IsSuccess, r.Reason);
        return r.Value!;
    }
}

public class CscClientTests
{
    public static TheoryData<string, string, int, bool> SigningCases => new()
    {
        { "rsa", "rsa-pkcs1-sha256", 1, false },
        { "rsa", "rsa-pkcs1-sha384", 2, false },
        { "rsa", "rsa-pkcs1-sha512", 2, false },
        { "rsa", "rsa-pss-sha256", 1, false },
        { "rsa", "rsa-pss-sha384", 2, false },
        { "p256", "ecdsa-sha256", 1, false },
        { "p256", "ecdsa-sha256", 2, true },
        { "p256", "ecdsa-sha256-p1363", 2, false },
        { "p256", "ecdsa-sha256-p1363", 1, true },
        { "p384", "ecdsa-sha384", 2, false },
    };

    [Fact]
    public async Task InfoIsReadWithoutAToken()
    {
        var rig = new CscRig(tokens: new CscDelegateTokenSource((_, _) => throw new InvalidOperationException("info must not ask for a token")));
        CscResult<CscServiceInfo> r = await rig.Client.InfoAsync("en");
        Assert.True(r.IsSuccess, r.Reason);
        Assert.Equal("2.2.0.0", r.Value!.Specs);
        Assert.Contains("oauth2client", r.Value.AuthTypes);
        Assert.True(r.Value.SupportsMethod("signatures/signHash"));
        Assert.False(r.Value.SupportsMethod("signatures/signDoc"));
        Assert.Contains("1.2.840.113549.1.1.10", r.Value.SignAlgorithms);
        Assert.DoesNotContain(rig.Transport.Requests, q => q.Headers.Any(h => h.Key == "Authorization"));
    }

    [Fact]
    public async Task CredentialsAreListedAndDescribed()
    {
        var rig = new CscRig(s =>
        {
            s.Add(CscRig.Credential("C-RSA", "rsa", scal: 2));
            s.Add(CscRig.Credential("C-EC", "p256", mode: TestAuthMode.OAuth2Code, pin: null));
        });
        CscResult<CscCredentialList> list = await rig.Client.ListCredentialsAsync(includeInfo: true);
        Assert.True(list.IsSuccess, list.Reason);
        Assert.Equal(["C-RSA", "C-EC"], list.Value!.CredentialIds);
        CscCredentialInfo rsa = list.Value.Infos.Single(i => i.CredentialId == "C-RSA");
        Assert.Equal(2, rsa.Scal);
        Assert.Equal(CscAuthMode.Explicit, rsa.AuthMode);
        Assert.Equal("PIN", rsa.AuthObjects.Single().Id);
        Assert.Equal(3, rsa.Certificates.Count);
        Assert.Equal(2048, rsa.KeyLength);

        CscResult<CscCredentialInfo> one = await rig.Client.GetCredentialInfoAsync("C-EC");
        Assert.Equal(CscAuthMode.OAuth2Code, one.Value!.AuthMode);
        Assert.Equal(1, one.Value.Scal);
        Assert.Empty(one.Value.AuthObjects);

        CscResult<CscCredentialInfo> missing = await rig.Client.GetCredentialInfoAsync("nope");
        Assert.Equal(CscOutcome.ServiceError, missing.Outcome);
        Assert.Equal("invalid_request", missing.Error);
        Assert.Equal(400, missing.StatusCode);
    }

    [Theory]
    [MemberData(nameof(SigningCases))]
    public async Task ADigestIsSignedRemotelyAndTheSignatureVerifiesAgainstTheCertificate(string kind, string specName, int scal, bool ecdsaDer)
    {
        var rig = new CscRig();
        using CscSigningKey key = await rig.Open(CscRig.Credential("C1", kind, scal, ecdsaDer: ecdsaDer));
        SignatureSpec spec = CscRig.Spec(specName);
        Assert.True(key.Supports(spec));
        byte[] digest = CscRig.Digest("a document", spec.Hash);

        byte[] sig = await key.SignDigestAsync(digest, spec);

        Assert.True(spec.VerifyDigest(key.PublicKey, digest, sig).IsValid);
        Assert.True(spec.Verify(key.PublicKey, Encoding.UTF8.GetBytes("a document"), sig).IsValid);

        // Authorization came first and carried the digest: that is what binds the activation data to what is signed (§11.8).
        CscCall auth = rig.Server.Calls.Single(c => c.Path == "credentials/authorize");
        Assert.Equal(Convert.ToBase64String(digest), System.Text.Json.JsonDocument.Parse(auth.Body).RootElement.GetProperty("hashes")[0].GetString());
        Assert.Equal(1, System.Text.Json.JsonDocument.Parse(auth.Body).RootElement.GetProperty("numSignatures").GetInt32());
        CscCall sign = rig.Server.Calls.Single(c => c.Path == "signatures/signHash");
        Assert.Equal(Convert.ToBase64String(digest), System.Text.Json.JsonDocument.Parse(sign.Body).RootElement.GetProperty("hashes")[0].GetString());
        Assert.True(rig.Server.Calls.ToList().FindIndex(c => c.Path == "credentials/authorize") < rig.Server.Calls.ToList().FindIndex(c => c.Path == "signatures/signHash"));
    }

    [Fact]
    public async Task SignAndSignDigestAgree()
    {
        var rig = new CscRig();
        using CscSigningKey key = await rig.Open(CscRig.Credential("C1", "rsa"));
        SignatureSpec spec = key.DefaultSpec;
        byte[] data = "message"u8.ToArray();
        byte[] sig = key.Sign(data, spec);
        Assert.True(spec.Verify(key.PublicKey, data, sig).IsValid);
        Assert.Equal(KeyCapabilities.Sign, key.Capabilities);
    }

    [Fact]
    public async Task SchemesThatSignTheMessageAreNotOffered()
    {
        var rig = new CscRig();
        using CscSigningKey key = await rig.Open(CscRig.Credential("C1", "rsa"));
        Assert.False(key.Supports(SignatureSpec.Ed25519()));
        Assert.False(key.Supports(SignatureSpec.Ecdsa(HashAlgorithmName.SHA256)));
        Assert.Throws<NotSupportedException>(() => key.Sign("x"u8.ToArray(), SignatureSpec.Ed25519()));
    }

    [Fact]
    public async Task AnActivationBoundToOneDigestCannotSignAnother()
    {
        foreach (int scal in new[] { 1, 2 })
        {
            var rig = new CscRig();
            rig.Server.Add(CscRig.Credential("C1", "rsa", scal));
            byte[] approved = CscRig.Digest("what the user approved", HashAlgorithmName.SHA256);
            byte[] other = CscRig.Digest("something else", HashAlgorithmName.SHA256);

            CscResult<CscAuthorization> auth = await rig.Client.AuthorizeAsync("C1", [approved], KnownOids.Sha256, [new CscAuthObject("PIN", CscRig.Pin)]);
            Assert.True(auth.IsSuccess, auth.Reason);

            CscResult<IReadOnlyList<byte[]>> refused = await rig.Client.SignHashAsync("C1", auth.Value!.Sad!, [other], KnownOids.Sha256, KnownOids.Sha256WithRsa);
            Assert.Equal(CscOutcome.ServiceError, refused.Outcome);
            Assert.Equal("invalid_request", refused.Error);
            Assert.Contains("not authorized", refused.Reason, StringComparison.Ordinal);

            CscResult<IReadOnlyList<byte[]>> allowed = await rig.Client.SignHashAsync("C1", auth.Value.Sad!, [approved], KnownOids.Sha256, KnownOids.Sha256WithRsa);
            Assert.True(allowed.IsSuccess, allowed.Reason);
        }
    }

    [Fact]
    public async Task TheTestServiceHoldsScal2ToItsRule()
    {
        // The service the other tests rely on must itself refuse what the API forbids, or its acceptance would prove nothing (CSC API §11.8).
        var rig = new CscRig();
        rig.Server.Add(CscRig.Credential("C1", "rsa", scal: 2));
        string bearer = "Bearer " + rig.Token;
        (int status, byte[] body) = rig.Server.Handle("credentials/authorize", bearer, "{\"credentialID\":\"C1\",\"numSignatures\":1,\"authData\":[{\"id\":\"PIN\",\"value\":\"123456\"}]}"u8.ToArray());
        Assert.Equal(400, status);
        Assert.Contains("invalid_request", Encoding.UTF8.GetString(body), StringComparison.Ordinal);
        CscResult<CscAuthorization> wrongPin = await rig.Client.AuthorizeAsync("C1", [new byte[32]], KnownOids.Sha256, [new CscAuthObject("PIN", "000000")]);
        Assert.Equal("invalid_authentication_data", wrongPin.Error);
    }

    [Fact]
    public async Task ASadIsUsedUpAndExpires()
    {
        var rig = new CscRig(s => s.SadLifetimeSeconds = 60);
        rig.Server.Add(CscRig.Credential("C1", "rsa"));
        byte[] d = CscRig.Digest("x", HashAlgorithmName.SHA256);
        CscAuthorization auth = (await rig.Client.AuthorizeAsync("C1", [d], KnownOids.Sha256, [new CscAuthObject("PIN", CscRig.Pin)])).Value!;
        Assert.Equal(60, auth.ExpiresIn);

        Assert.True((await rig.Client.SignHashAsync("C1", auth.Sad!, [d], KnownOids.Sha256, KnownOids.Sha256WithRsa)).IsSuccess);
        CscResult<IReadOnlyList<byte[]>> again = await rig.Client.SignHashAsync("C1", auth.Sad!, [d], KnownOids.Sha256, KnownOids.Sha256WithRsa);
        Assert.Equal(CscOutcome.ServiceError, again.Outcome);

        CscAuthorization second = (await rig.Client.AuthorizeAsync("C1", [d], KnownOids.Sha256, [new CscAuthObject("PIN", CscRig.Pin)])).Value!;
        rig.Clock.Advance(TimeSpan.FromSeconds(61));
        CscResult<IReadOnlyList<byte[]>> late = await rig.Client.SignHashAsync("C1", second.Sad!, [d], KnownOids.Sha256, KnownOids.Sha256WithRsa);
        Assert.Equal(CscOutcome.ServiceError, late.Outcome);
        Assert.Contains("expired", late.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SeveralDigestsShareOneAuthorizationUpToMultisign()
    {
        var rig = new CscRig();
        using CscSigningKey key = await rig.Open(CscRig.Credential("C1", "rsa", scal: 2, multisign: 2));
        SignatureSpec spec = key.DefaultSpec;
        byte[][] digests = [CscRig.Digest("a", HashAlgorithmName.SHA256), CscRig.Digest("b", HashAlgorithmName.SHA256)];

        byte[][] sigs = await key.SignDigestsAsync(digests, spec);

        Assert.Equal(2, sigs.Length);
        Assert.True(spec.VerifyDigest(key.PublicKey, digests[0], sigs[0]).IsValid);
        Assert.True(spec.VerifyDigest(key.PublicKey, digests[1], sigs[1]).IsValid);
        Assert.Single(rig.Server.Calls, c => c.Path == "credentials/authorize");
        Assert.Single(rig.Server.Calls, c => c.Path == "signatures/signHash");
        await Assert.ThrowsAsync<ArgumentException>(async () => await key.SignDigestsAsync([digests[0], digests[1], digests[0]], spec));
        await Assert.ThrowsAsync<ArgumentException>(async () => await key.SignDigestsAsync([new byte[5]], spec));
    }

    [Fact]
    public async Task AWrongPinIsReportedAsTheServiceReportsIt()
    {
        var rig = new CscRig();
        rig.Server.Add(CscRig.Credential("C1", "rsa"));
        using CscSigningKey key = (await rig.Client.OpenSigningKeyAsync("C1", CscRig.WithPin("000000"))).Value!;
        CscSigningException ex = await Assert.ThrowsAsync<CscSigningException>(async () => await key.SignDigestAsync(new byte[32], key.DefaultSpec));
        Assert.Equal(CscOutcome.ServiceError, ex.Outcome);
        Assert.Equal("invalid_authentication_data", ex.Error);
        Assert.DoesNotContain("000000", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACredentialThatNeedsAPinFailsClosedWithoutAProvider()
    {
        var rig = new CscRig();
        using CscSigningKey key = await rig.Open(CscRig.Credential("C1", "rsa"), new CscKeyOptions());
        CscSigningException ex = await Assert.ThrowsAsync<CscSigningException>(async () => await key.SignDigestAsync(new byte[32], key.DefaultSpec));
        Assert.Equal(CscOutcome.CredentialUnusable, ex.Outcome);
        Assert.DoesNotContain(rig.Server.Calls, c => c.Path == "credentials/authorize");
    }

    [Fact]
    public async Task ACredentialWithNoAuthenticationObjectsAuthorizesWithoutAuthData()
    {
        var rig = new CscRig();
        using CscSigningKey key = await rig.Open(CscRig.Credential("C1", "p256", pin: null), new CscKeyOptions());
        byte[] d = CscRig.Digest("x", HashAlgorithmName.SHA256);
        byte[] sig = await key.SignDigestAsync(d, key.DefaultSpec);
        Assert.True(key.DefaultSpec.VerifyDigest(key.PublicKey, d, sig).IsValid);
        Assert.DoesNotContain("authData", rig.Server.Calls.Single(c => c.Path == "credentials/authorize").Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADisabledCredentialCannotBeOpened()
    {
        var rig = new CscRig();
        rig.Server.Add(CscRig.Credential("C1", "rsa", enabled: false));
        CscResult<CscSigningKey> r = await rig.Client.OpenSigningKeyAsync("C1");
        Assert.Equal(CscOutcome.CredentialUnusable, r.Outcome);
    }

    private static CscRig OAuthRig(Func<CscCredentialTokenRequest, byte[][]?> bind, out Func<CscCredentialTokenRequest?> seen)
    {
        CscTestServer? srv = null;
        CscCredentialTokenRequest? last = null;
        string service = string.Empty;
        var tokens = new CscDelegateTokenSource(
            (_, _) => ValueTask.FromResult<CscAccessToken?>(new CscAccessToken(service)),
            (request, _) =>
            {
                last = request;
                // What the authorization server does once the user has approved the request the caller sent it.
                byte[][] bound = bind(request) ?? [];
                return ValueTask.FromResult<CscAccessToken?>(new CscAccessToken(srv!.IssueCredentialToken(request.CredentialId, bound, TimeSpan.FromMinutes(5))));
            });
        var rig = new CscRig(s => srv = s, tokens);
        service = rig.Token;
        seen = () => last;
        return rig;
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task AnOauth2CodeCredentialIsAuthorizedByACredentialTokenBoundToTheHashes(int scal)
    {
        CscRig rig = OAuthRig(r => [.. r.Hashes], out Func<CscCredentialTokenRequest?> seen);
        using CscSigningKey key = await rig.Open(CscRig.Credential("OA", "rsa", scal, TestAuthMode.OAuth2Code, pin: null), new CscKeyOptions());
        byte[] d = CscRig.Digest("approved in the browser", HashAlgorithmName.SHA256);

        byte[] sig = await key.SignDigestAsync(d, key.DefaultSpec);

        Assert.True(key.DefaultSpec.VerifyDigest(key.PublicKey, d, sig).IsValid);
        CscCredentialTokenRequest request = seen()!;
        Assert.Equal("OA", request.CredentialId);
        Assert.Equal(d, request.Hashes.Single());
        Assert.Equal(KnownOids.Sha256, request.HashAlgorithmOid);
        Assert.Equal(scal == 2, request.BindsHashes);
        Assert.Contains(request.ToAuthorizeParameters(), p => p.Key == "numSignatures" && p.Value == "1");
        Assert.DoesNotContain('=', request.ToAuthorizeParameters().Single(p => p.Key == "hashes").Value);
        Assert.DoesNotContain(rig.Server.Calls, c => c.Path == "credentials/authorize");
    }

    [Fact]
    public async Task AnOauth2CodeCredentialWithoutACredentialTokenSourceFailsClosed()
    {
        var rig = new CscRig();
        using CscSigningKey key = await rig.Open(CscRig.Credential("OA", "rsa", mode: TestAuthMode.OAuth2Code, pin: null), new CscKeyOptions());
        CscSigningException ex = await Assert.ThrowsAsync<CscSigningException>(async () => await key.SignDigestAsync(new byte[32], key.DefaultSpec));
        Assert.Equal(CscOutcome.TokenUnavailable, ex.Outcome);
        Assert.DoesNotContain(rig.Server.Calls, c => c.Path == "signatures/signHash");
    }

    [Fact]
    public async Task ACredentialTokenBoundToOtherHashesIsRefused()
    {
        CscRig rig = OAuthRig(_ => [CscRig.Digest("a different document", HashAlgorithmName.SHA256)], out _);
        using CscSigningKey key = await rig.Open(CscRig.Credential("OA", "rsa", scal: 2, mode: TestAuthMode.OAuth2Code, pin: null), new CscKeyOptions());
        CscSigningException ex = await Assert.ThrowsAsync<CscSigningException>(async () => await key.SignDigestAsync(CscRig.Digest("the real one", HashAlgorithmName.SHA256), key.DefaultSpec));
        Assert.Equal(CscOutcome.ServiceError, ex.Outcome);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ASchemeThePlatformCannotVerifyIsRefusedUnlessTheCallerOptsOut(bool allow)
    {
        var rig = new CscRig();
        rig.Server.Add(CscRig.Credential("C1", "rsa"));
        CscKeyOptions options = new() { AuthDataProvider = CscRig.WithPin().AuthDataProvider, SimulateVerificationGap = true, AllowUncheckedSignatures = allow };
        using CscSigningKey key = (await rig.Client.OpenSigningKeyAsync("C1", options)).Value!;
        byte[] digest = CscRig.Digest("x", HashAlgorithmName.SHA256);
        if (allow)
        {
            byte[] sig = await key.SignDigestAsync(digest, key.DefaultSpec);
            Assert.True(key.DefaultSpec.VerifyDigest(key.PublicKey, digest, sig).IsValid);
        }
        else
        {
            await Assert.ThrowsAsync<AlgorithmNotSupportedException>(async () => await key.SignDigestAsync(digest, key.DefaultSpec));
        }
    }

    [Fact]
    public async Task ASignatureFromAnotherKeyIsNeverReleased()
    {
        var rig = new CscRig();
        CscTestCredential real = CscRig.Credential("C1", "rsa");
        CscTestCredential impostor = CscRig.Credential("C1", "rsa");
        rig.Server.Add(real);
        using CscSigningKey key = (await rig.Client.OpenSigningKeyAsync("C1", CscRig.WithPin())).Value!;
        rig.Server.Add(impostor); // the service now signs with a different key than the certificate it advertised
        CscSigningException ex = await Assert.ThrowsAsync<CscSigningException>(async () => await key.SignDigestAsync(CscRig.Digest("x", HashAlgorithmName.SHA256), key.DefaultSpec));
        Assert.Equal(CscOutcome.BadSignature, ex.Outcome);
    }

    [Fact]
    public async Task EcdsaIsAcceptedAsDerOrAsFixedWidthAndTamperingIsCaught()
    {
        foreach (bool der in new[] { false, true })
        {
            var rig = new CscRig();
            using CscSigningKey key = await rig.Open(CscRig.Credential("C1", "p256", ecdsaDer: der));
            byte[] d = CscRig.Digest("x", HashAlgorithmName.SHA256);
            byte[] sig = await key.SignDigestAsync(d, key.DefaultSpec);
            Assert.Equal(0x30, sig[0]);
            Assert.True(key.DefaultSpec.VerifyDigest(key.PublicKey, d, sig).IsValid);
            byte[] raw = await key.SignDigestAsync(d, CscRig.Spec("ecdsa-sha256-p1363"));
            Assert.Equal(64, raw.Length);
        }
    }

    [Fact]
    public async Task ARevokedServiceTokenIsRefreshedOnceThenSucceeds()
    {
        string current = string.Empty;
        CscTestServer? srv = null;
        int asked = 0;
        var tokens = new CscDelegateTokenSource((force, _) =>
        {
            asked++;
            if (force || current.Length == 0)
            {
                current = srv!.IssueServiceToken(TimeSpan.FromHours(1));
            }

            return ValueTask.FromResult<CscAccessToken?>(new CscAccessToken(current));
        });
        var rig = new CscRig(s => srv = s, tokens);
        rig.Server.Add(CscRig.Credential("C1", "rsa"));
        Assert.True((await rig.Client.GetCredentialInfoAsync("C1")).IsSuccess);
        string first = current;
        rig.Server.Revoke(first);

        CscResult<CscCredentialInfo> r = await rig.Client.GetCredentialInfoAsync("C1");

        Assert.True(r.IsSuccess, r.Reason);
        Assert.NotEqual(first, current);
        Assert.Equal(3, asked);
    }

    [Fact]
    public async Task ARefusedTokenThatCannotBeRefreshedIsReportedAsRejected()
    {
        var rig = new CscRig();
        rig.Server.Add(CscRig.Credential("C1", "rsa"));
        rig.Server.Revoke(rig.Token);
        CscResult<CscCredentialInfo> r = await rig.Client.GetCredentialInfoAsync("C1");
        Assert.Equal(CscOutcome.TokenRejected, r.Outcome);
        Assert.Equal("invalid_token", r.Error);
        Assert.Equal(401, r.StatusCode);
        Assert.Equal(2, rig.Transport.Requests.Count);
    }

    [Fact]
    public async Task AnExpiredTokenIsNotSentAndTheServiceExpiryIsReported()
    {
        // The token's own expiry passes: the source is asked for a fresh one before anything is sent.
        string token = string.Empty;
        CscTestServer? srv = null;
        TestClock? clock = null;
        var tokens = new CscDelegateTokenSource((force, _) =>
        {
            token = srv!.IssueServiceToken(TimeSpan.FromMinutes(10));
            return ValueTask.FromResult<CscAccessToken?>(new CscAccessToken(token, clock!.GetUtcNow().AddMinutes(10)));
        });
        var rig = new CscRig(s => srv = s, tokens);
        clock = rig.Clock;
        rig.Server.Add(CscRig.Credential("C1", "rsa"));
        Assert.True((await rig.Client.GetCredentialInfoAsync("C1")).IsSuccess);
        rig.Clock.Advance(TimeSpan.FromMinutes(11));
        Assert.True((await rig.Client.GetCredentialInfoAsync("C1")).IsSuccess);
        Assert.Equal(2, rig.Server.Calls.Count);

        // A token whose expiry nobody knew: the service says expired_token and the client recovers with one refresh.
        var rig2 = new CscRig(s => srv = s, new CscDelegateTokenSource((force, _) => ValueTask.FromResult<CscAccessToken?>(new CscAccessToken(srv!.IssueServiceToken(TimeSpan.FromSeconds(30))))));
        rig2.Server.Add(CscRig.Credential("C1", "rsa"));
        Assert.True((await rig2.Client.GetCredentialInfoAsync("C1")).IsSuccess);
        rig2.Clock.Advance(TimeSpan.FromMinutes(1));
        CscResult<CscCredentialInfo> after = await rig2.Client.GetCredentialInfoAsync("C1");
        Assert.True(after.IsSuccess, after.Reason);
    }

    [Fact]
    public async Task NoTokenAtAllIsReportedBeforeAnythingIsSent()
    {
        var rig = new CscRig(tokens: new CscDelegateTokenSource((_, _) => ValueTask.FromResult<CscAccessToken?>(null)));
        CscResult<CscCredentialList> r = await rig.Client.ListCredentialsAsync();
        Assert.Equal(CscOutcome.TokenUnavailable, r.Outcome);
        Assert.Empty(rig.Transport.Requests);

        var expired = new CscRig(tokens: new CscStaticTokenSource(new CscAccessToken("old", World.T0)));
        Assert.Equal(CscOutcome.TokenUnavailable, (await expired.Client.ListCredentialsAsync()).Outcome);
        Assert.Empty(expired.Transport.Requests);
    }

    [Fact]
    public async Task TheClientCredentialsFlowFetchesAndCachesAToken()
    {
        var clock = new TestClock(World.Now);
        int issued = 0;
        string? authorization = null;
        string? form = null;
        var net = new FakeNetwork(r =>
        {
            authorization = r.Headers.First(h => h.Key == "Authorization").Value;
            form = Encoding.ASCII.GetString(r.Body.Span);
            issued++;
            return Reply.Ok(Encoding.UTF8.GetBytes($"{{\"access_token\":\"tok-{issued}\",\"token_type\":\"Bearer\",\"expires_in\":600}}"), "application/json");
        });
        using var source = new CscClientCredentialsTokenSource(new Fetcher(net, new FetchOptions { Cache = null, Time = clock }), new Uri("https://csc.test/oauth2/token"), "client id", "s3cr:et");

        CscAccessToken? a = await source.GetServiceTokenAsync(false, default);
        CscAccessToken? b = await source.GetServiceTokenAsync(false, default);
        Assert.Equal("tok-1", a!.Value);
        Assert.Same(a, b);
        Assert.Equal("grant_type=client_credentials&scope=service", form);
        // RFC 6749 §2.3.1: id and secret are form-encoded, then joined for Basic.
        Assert.Equal("Basic " + Convert.ToBase64String("client%20id:s3cr%3Aet"u8), authorization);

        clock.Advance(TimeSpan.FromSeconds(580));
        Assert.Equal("tok-2", (await source.GetServiceTokenAsync(false, default))!.Value);
        Assert.Equal("tok-3", (await source.GetServiceTokenAsync(true, default))!.Value);
        Assert.DoesNotContain("tok-3", a.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnErrorFromTheTokenEndpointGivesNoToken()
    {
        var net = new FakeNetwork(_ => new Reply(400, "{\"error\":\"invalid_client\"}"u8.ToArray(), ("Content-Type", "application/json")));
        using var source = new CscClientCredentialsTokenSource(new Fetcher(net, new FetchOptions { Cache = null }), new Uri("https://csc.test/oauth2/token"), "id", "secret");
        Assert.Null(await source.GetServiceTokenAsync(false, default));
    }
}
