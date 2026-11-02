using System.Linq;
using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Online;
using RecursiveAI.OneCrypto.Online.Csc;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Fuzz;

/// <summary>
/// The answers of a Cloud Signature Consortium service as one fuzz target (<c>csc</c>). Byte 0 picks the call (<c>info</c>, <c>credentials/list</c>,
/// <c>credentials/info</c>, <c>credentials/authorize</c>, <c>signatures/signHash</c>, or opening a credential and signing with it when the service's description or its
/// signature is the input); byte 1 picks the HTTP status; the rest is the body the hostile service sends. Nothing may throw except <see cref="CscSigningException"/>
/// from the signing key, and a signature may be released only if it verifies against the certificate.
/// </summary>
internal static class CscTarget
{
    private static readonly Lazy<Rig> Shared = new(() => new Rig());

    private static readonly int[] Statuses = [200, 200, 200, 202, 400, 401, 403, 500, 302, 204];

    private sealed class Rig
    {
        public readonly byte[] CredentialInfo;
        public readonly byte[] Digest = SHA256.HashData("fuzz"u8);
        public readonly ISigningKey Key;

        public Rig()
        {
            DateTimeOffset now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
            var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            CertificateAuthority ca = CertificateAuthority.CreateRoot(DistinguishedName.Create((KnownOids.CommonName, "Fuzz CA")), X509Signer.FromECDsa(caKey), now.AddDays(-30), TimeSpan.FromDays(3650));
            Key = PrivateKey.FromECDsa(ECDsa.Create(ECCurve.NamedCurves.nistP256), ownsKey: true);
            Certificate leaf = ca.Issue(Key.PublicKey, DistinguishedName.Create((KnownOids.CommonName, "Fuzz signer")), new CertificateIssueOptions { Profile = CertificateProfile.SMime, NotBefore = now.AddDays(-1), SubjectAlternativeNames = [GeneralName.Email("f@example.test")] });
            CredentialInfo = Encoding.UTF8.GetBytes(
                "{\"key\":{\"status\":\"enabled\",\"algo\":[\"1.2.840.10045.4.3.2\"],\"len\":256},\"cert\":{\"status\":\"valid\",\"certificates\":[\"" + Convert.ToBase64String(leaf.Encoded.Span) + "\"]},"
                + "\"auth\":{\"mode\":\"explicit\",\"objects\":[{\"type\":\"Password\",\"id\":\"PIN\"}]},\"SCAL\":\"2\",\"multisign\":2}");
        }
    }

    private sealed class Network : ITransport
    {
        private readonly Func<string, TransportResponse> _answer;

        public Network(Func<string, TransportResponse> answer) => _answer = answer;

        public ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(_answer(request.Uri.AbsolutePath));
    }

    private static TransportResponse Reply(int status, byte[] body) => new(status, [new("Content-Type", "application/json")], new MemoryStream(body, writable: false));

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        int call = data[0] % 7;
        int status = Statuses[data[1] % Statuses.Length];
        byte[] body = data[2..].ToArray();
        Rig rig = Shared.Value;
        byte[] good = Encoding.UTF8.GetBytes("{\"SAD\":\"s\",\"expiresIn\":60}");

        var net = new Network(path =>
        {
            // Calls 5 and 6 open a credential and sign with it; the input stands in for one answer and the others are well-formed.
            if (call == 5)
            {
                return path.EndsWith("signHash", StringComparison.Ordinal) ? Reply(status, body) : path.EndsWith("authorize", StringComparison.Ordinal) ? Reply(200, good) : Reply(200, rig.CredentialInfo);
            }

            if (call == 6)
            {
                return path.EndsWith("info", StringComparison.Ordinal) ? Reply(status, body) : path.EndsWith("authorize", StringComparison.Ordinal) ? Reply(200, good) : Reply(200, Encoding.UTF8.GetBytes("{\"signatures\":[\"MEUCIQD\"]}"));
            }

            return Reply(status, body);
        });
        var client = new CscClient(
            new Fetcher(net, new FetchOptions { MaxResponseBytes = 1 << 16, Timeout = TimeSpan.FromSeconds(2), Cache = null }),
            new Uri("https://csc.example/csc/v2/"),
            new CscStaticTokenSource(new CscAccessToken("fuzz-token")));

        switch (call)
        {
            case 0:
                _ = client.InfoAsync().AsTask().GetAwaiter().GetResult();
                break;
            case 1:
                _ = client.ListCredentialsAsync(null, true).AsTask().GetAwaiter().GetResult();
                break;
            case 2:
                _ = client.GetCredentialInfoAsync("C").AsTask().GetAwaiter().GetResult();
                break;
            case 3:
                _ = client.AuthorizeAsync("C", [rig.Digest], KnownOids.Sha256, [new CscAuthObject("PIN", "1")]).AsTask().GetAwaiter().GetResult();
                break;
            case 4:
                _ = client.SignHashAsync("C", "sad", [rig.Digest], KnownOids.Sha256, KnownOids.EcdsaSha256).AsTask().GetAwaiter().GetResult();
                break;
            default:
                CscResult<CscSigningKey> opened = client.OpenSigningKeyAsync("C", new CscKeyOptions { AuthDataProvider = static (_, _) => ValueTask.FromResult<IReadOnlyList<CscAuthObject>>([new CscAuthObject("PIN", "1")]) }).AsTask().GetAwaiter().GetResult();
                if (opened.Value is { } key)
                {
                    try
                    {
                        byte[] sig = key.SignDigest(rig.Digest, SignatureSpec.Ecdsa(HashAlgorithmName.SHA256));
                        // Whatever was released must verify: a hostile service cannot make the key hand out a bad signature.
                        if (!SignatureSpec.Ecdsa(HashAlgorithmName.SHA256).VerifyDigest(key.PublicKey, rig.Digest, sig).IsValid)
                        {
                            throw new InvalidOperationException("the remote key released a signature that does not verify");
                        }
                    }
                    catch (CscSigningException)
                    {
                    }
                }

                break;
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        Rig rig = Shared.Value;
        byte[] Make(int call, int status, string body) => [(byte)call, (byte)status, .. Encoding.UTF8.GetBytes(body)];
        yield return Make(0, 0, "{\"specs\":\"2.2.0.0\",\"name\":\"s\",\"lang\":\"en\",\"authType\":[\"oauth2code\"],\"methods\":[\"signatures/signHash\"],\"oauth2\":\"https://x/\",\"signAlgorithms\":{\"algos\":[\"1.2.840.10045.4.3.2\"]}}");
        yield return Make(1, 0, "{\"credentialIDs\":[\"a\",\"b\"]}");
        yield return [1, 0, .. Encoding.UTF8.GetBytes("{\"credentialIDs\":[\"a\"],\"credentialInfos\":[{\"credentialID\":\"a\"," + Encoding.UTF8.GetString(rig.CredentialInfo)[1..] + "]}")];
        yield return [2, 0, .. rig.CredentialInfo];
        yield return Make(3, 0, "{\"SAD\":\"abc\",\"expiresIn\":3600}");
        yield return Make(3, 3, "{\"handle\":\"h\"}");
        yield return Make(3, 4, "{\"error\":\"invalid_request\",\"error_description\":\"Numbers of signatures is too high\"}");
        yield return Make(4, 0, "{\"signatures\":[\"MEUCIQDabc=\"]}");
        yield return Make(4, 5, "{\"error\":\"invalid_token\"}");
        yield return Make(5, 0, "{\"signatures\":[\"MEUCIQDabc=\"]}");
        yield return [6, 0, .. rig.CredentialInfo];
    }
}
