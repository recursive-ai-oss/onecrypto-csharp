using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Online.Csc;

namespace OneCrypto.Online.Tests.Csc;

/// <summary>
/// The CSC client against recorded exchanges of the test service (<c>testdata/online/csc-*.exchanges.json</c>). The recordings are made by
/// <see cref="RecordFixtures"/> (set <c>ONECRYPTO_ONLINE_RECORD</c> to a directory) and replayed everywhere else, so the client's reading of the documented JSON
/// is pinned by files a reviewer can open. Request headers are not recorded; the activation value in the authorization answer is replaced by a placeholder.
/// </summary>
public class CscFixtureTests
{
    private static readonly byte[] Message = "OneCrypto CSC fixture"u8.ToArray();

    private static string Data(string name) => Path.Combine(TestFiles.TestData, "online", name + ".exchanges.json");

    private static string? RecordDir => Environment.GetEnvironmentVariable("ONECRYPTO_ONLINE_RECORD");

    private static CscClient Client(ITransport transport, ICscTokenSource tokens) =>
        new(new Fetcher(transport, new FetchOptions { Cache = null }), CscRig.Base, tokens);

    /// <summary>The scenarios: explicit authorization at SCAL 2 with RSA, and OAuth 2.0 authorization with ECDSA. Each returns the signature after checking it.</summary>
    private static async Task<byte[]> Explicit(ITransport transport, string token)
    {
        CscClient client = Client(transport, new CscStaticTokenSource(new CscAccessToken(token)));
        CscServiceInfo info = (await client.InfoAsync()).Value!;
        Assert.True(info.SupportsMethod("credentials/authorize"));
        Assert.Equal("C-RSA", (await client.ListCredentialsAsync()).Value!.CredentialIds.Single());
        using CscSigningKey key = (await client.OpenSigningKeyAsync("C-RSA", CscRig.WithPin("246810"), info)).Value!;
        Assert.Equal(2, key.Credential.Scal);
        SignatureSpec spec = SignatureSpec.RsaPss(HashAlgorithmName.SHA256);
        byte[] sig = await key.SignDigestAsync(CryptographicOperations.HashData(HashAlgorithmName.SHA256, Message), spec);
        Assert.True(spec.Verify(key.PublicKey, Message, sig).IsValid);
        return sig;
    }

    private static async Task<byte[]> OAuth(ITransport transport, string token)
    {
        var tokens = new CscDelegateTokenSource((_, _) => ValueTask.FromResult<CscAccessToken?>(new CscAccessToken(token)), (_, _) => ValueTask.FromResult<CscAccessToken?>(new CscAccessToken(token + "-credential")));
        CscClient client = Client(transport, tokens);
        using CscSigningKey key = (await client.OpenSigningKeyAsync("C-EC")).Value!;
        Assert.Equal(CscAuthMode.OAuth2Code, key.Credential.AuthMode);
        SignatureSpec spec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA256);
        byte[] sig = await key.SignDigestAsync(CryptographicOperations.HashData(HashAlgorithmName.SHA256, Message), spec);
        Assert.True(spec.Verify(key.PublicKey, Message, sig).IsValid);
        return sig;
    }

    [Fact]
    public async Task ExplicitAuthorizationReplays()
    {
        ExchangeLog log = ExchangeLog.Parse(File.ReadAllBytes(Data("csc-explicit-scal2-rsa")));
        var replay = new ReplayTransport(log, new ReplayOptions { MatchBody = false });
        byte[] sig = await Explicit(replay, "replay-token");
        Assert.NotEmpty(sig);
        Assert.Equal(
            ["POST https://csc.test/csc/v2/info", "POST https://csc.test/csc/v2/credentials/list", "POST https://csc.test/csc/v2/credentials/info", "POST https://csc.test/csc/v2/credentials/authorize", "POST https://csc.test/csc/v2/signatures/signHash"],
            replay.Requests);
    }

    [Fact]
    public async Task OAuth2AuthorizationReplays()
    {
        ExchangeLog log = ExchangeLog.Parse(File.ReadAllBytes(Data("csc-oauth2code-ecdsa")));
        var replay = new ReplayTransport(log, new ReplayOptions { MatchBody = false });
        await OAuth(replay, "replay-token");
        Assert.DoesNotContain(replay.Requests, r => r.EndsWith("credentials/authorize", StringComparison.Ordinal));
    }

    [Fact]
    public void TheRecordingsHoldNoCredential()
    {
        foreach (string name in new[] { "csc-explicit-scal2-rsa", "csc-oauth2code-ecdsa" })
        {
            // Bodies are Base64 in the file: read them as the client would.
            string text = string.Join('\n', ExchangeLog.Parse(File.ReadAllBytes(Data(name))).Exchanges.Select(e => Encoding.UTF8.GetString(e.Body))) + File.ReadAllText(Data(name));
            Assert.DoesNotContain("246810", text, StringComparison.Ordinal);
            Assert.DoesNotContain("Bearer", text, StringComparison.Ordinal);
            Assert.DoesNotContain("svc-", text, StringComparison.Ordinal);
            Assert.DoesNotContain("sad-0", text, StringComparison.Ordinal);
            Assert.DoesNotContain("PRIVATE KEY", text, StringComparison.Ordinal);
        }
    }

    /// <summary>Makes the recordings from the test service (not from any provider). Deterministic apart from the key material, which is generated fresh and lives only in the certificate.</summary>
    [Fact]
    public async Task RecordFixtures()
    {
        Assert.SkipUnless(RecordDir is not null, "set ONECRYPTO_ONLINE_RECORD to a directory to record the fixtures");
        Directory.CreateDirectory(RecordDir!);

        var rsa = new CscRig(deterministic: true);
        rsa.Server.Add(CscRig.Credential("C-RSA", "rsa", scal: 2, pin: "246810"));
        var rsaRec = new RecordingTransport(rsa.Transport, rsa.Clock);
        _ = await Explicit(rsaRec, rsa.Token);
        Save("csc-explicit-scal2-rsa", rsaRec.Log, rsa.Token);

        CscTestServer? srv = null;
        var ec = new CscRig(s => srv = s, deterministic: true);
        srv!.Add(CscRig.Credential("C-EC", "p256", mode: TestAuthMode.OAuth2Code, pin: null));
        var ecRec = new RecordingTransport(ec.Transport, ec.Clock);
        string service = ec.Token;
        var tokens = new CscDelegateTokenSource(
            (_, _) => ValueTask.FromResult<CscAccessToken?>(new CscAccessToken(service)),
            (request, _) => ValueTask.FromResult<CscAccessToken?>(new CscAccessToken(srv.IssueCredentialToken(request.CredentialId, request.Hashes, TimeSpan.FromMinutes(5)))));
        CscClient client = Client(ecRec, tokens);
        using (CscSigningKey key = (await client.OpenSigningKeyAsync("C-EC")).Value!)
        {
            _ = await key.SignDigestAsync(CryptographicOperations.HashData(HashAlgorithmName.SHA256, Message), SignatureSpec.Ecdsa(HashAlgorithmName.SHA256));
        }

        Save("csc-oauth2code-ecdsa", ecRec.Log, ec.Token);
    }

    private static void Save(string name, ExchangeLog log, string token)
    {
        foreach (RecordedExchange e in log.Exchanges)
        {
            // The activation value is a credential of the service; the file keeps its shape and loses its value.
            if (e.Uri.EndsWith("credentials/authorize", StringComparison.Ordinal))
            {
                using JsonDocument doc = JsonDocument.Parse(e.Body);
                e.Body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Dictionary<string, object> { ["SAD"] = "SAD-REDACTED-FOR-FIXTURE", ["expiresIn"] = doc.RootElement.GetProperty("expiresIn").GetInt32() }));
            }

            e.RecordedAt = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        }

        byte[] json = log.ToJson();
        Assert.DoesNotContain(token, Encoding.UTF8.GetString(json), StringComparison.Ordinal);
        File.WriteAllBytes(Path.Combine(RecordDir!, name + ".exchanges.json"), json);
    }
}
