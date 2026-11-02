using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Online;

namespace OneCrypto.Online.Tests.Csc;

/// <summary>How a test credential is authorized (CSC API §11.7, <c>auth/mode</c>).</summary>
internal enum TestAuthMode
{
    Explicit,
    OAuth2Code,
}

/// <summary>A credential held by <see cref="CscTestServer"/>: a key in this process, the chain that goes with it, and the rules for authorizing its use.</summary>
internal sealed class CscTestCredential
{
    public required string Id { get; init; }

    public required ISigningKey Key { get; init; }

    public required IReadOnlyList<Certificate> Chain { get; init; }

    /// <summary>1, or 2 when the hash must be linked to the activation data.</summary>
    public int Scal { get; init; } = 1;

    public TestAuthMode Mode { get; init; } = TestAuthMode.Explicit;

    /// <summary>The PIN an explicit authorization must present; null means the credential asks for no authentication object.</summary>
    public string? Pin { get; init; } = "123456";

    public int Multisign { get; init; } = 3;

    public bool KeyEnabled { get; init; } = true;

    /// <summary>ECDSA signatures are returned as fixed-width r || s unless this is set (the API does not say which, so both must work).</summary>
    public bool EcdsaDer { get; init; }
}

/// <summary>One request the server saw, for assertions about what travelled.</summary>
internal sealed record CscCall(string Path, string? Authorization, string Body);

/// <summary>
/// A Cloud Signature Consortium API v2.2 service written from the specification, for the tests: it speaks the documented JSON for <c>info</c>,
/// <c>credentials/list</c>, <c>credentials/info</c>, <c>credentials/authorize</c> and <c>signatures/signHash</c>, answers errors with the documented status codes and
/// <c>error</c> strings, binds activation data to the hashes it was given and refuses a signature over any other, and signs with keys held in this process.
/// It models service access tokens that expire and are revoked, SAD that expires and is used up, and credential access tokens for the OAuth 2.0 mode.
/// It reads the clock through a function, so a test can age tokens without waiting.
/// </summary>
internal sealed class CscTestServer
{
    private sealed record Activation(string CredentialId, HashSet<string>? Hashes, int Remaining, DateTimeOffset Expires);

    private static readonly string[] Methods = ["credentials/list", "credentials/info", "credentials/authorize", "signatures/signHash"];
    private static readonly string[] Algorithms = ["1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13", "1.2.840.113549.1.1.10", "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4"];

    private readonly Func<DateTimeOffset> _clock;
    private readonly Dictionary<string, CscTestCredential> _credentials = [];
    private readonly Dictionary<string, DateTimeOffset> _serviceTokens = [];
    private readonly HashSet<string> _revoked = [];
    private readonly Dictionary<string, Activation> _activations = [];
    private readonly object _gate = new();
    private int _counter;

    public CscTestServer(Func<DateTimeOffset> clock)
    {
        _clock = clock;
    }

    public List<CscCall> Calls { get; } = [];

    /// <summary>When set, the SAD and tokens are derived from a counter instead of random bytes (so a recording is reproducible).</summary>
    public bool Deterministic { get; init; }

    /// <summary>Lifetime of a SAD in seconds, reported as <c>expiresIn</c>.</summary>
    public int SadLifetimeSeconds { get; set; } = 3600;

    public void Add(CscTestCredential c)
    {
        lock (_gate)
        {
            _credentials[c.Id] = c;
        }
    }

    public string IssueServiceToken(TimeSpan lifetime)
    {
        lock (_gate)
        {
            string t = NewSecret("svc");
            _serviceTokens[t] = _clock() + lifetime;
            return t;
        }
    }

    public void Revoke(string token)
    {
        lock (_gate)
        {
            _revoked.Add(token);
        }
    }

    /// <summary>What the authorization server of an OAuth 2.0 credential would hand back after the user approved: a token bound to the hashes.</summary>
    public string IssueCredentialToken(string credentialId, IReadOnlyList<byte[]> hashes, TimeSpan lifetime)
    {
        lock (_gate)
        {
            string t = NewSecret("cred");
            _activations[t] = new Activation(credentialId, hashes.Count == 0 ? null : [.. hashes.Select(Convert.ToBase64String)], Math.Max(1, hashes.Count), _clock() + lifetime);
            return t;
        }
    }

    private string NewSecret(string kind) =>
        Deterministic
            ? $"{kind}-{Interlocked.Increment(ref _counter):D4}-{Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(kind + _counter)))[..16]}"
            : kind + "-" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace('+', '-').Replace('/', '_');

    public (int Status, byte[] Body) Handle(string path, string? authorization, byte[] body)
    {
        lock (_gate)
        {
            Calls.Add(new CscCall(path, authorization, Encoding.UTF8.GetString(body)));
            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(body.Length == 0 ? "{}"u8.ToArray() : body);
            }
            catch (JsonException)
            {
                return Error(400, "invalid_request", "Malformed JSON");
            }

            using (doc)
            {
                JsonElement r = doc.RootElement;
                if (r.ValueKind != JsonValueKind.Object)
                {
                    return Error(400, "invalid_request", "Malformed JSON");
                }

                if (path == "info")
                {
                    return Info();
                }

                (int, byte[])? denied = CheckService(authorization);
                if (denied is { } d)
                {
                    return d;
                }

                return path switch
                {
                    "credentials/list" => List(r),
                    "credentials/info" => CredentialInfo(r),
                    "credentials/authorize" => Authorize(r),
                    "signatures/signHash" => SignHash(r, authorization!),
                    _ => Error(404, "invalid_request", "Unknown method"),
                };
            }
        }
    }

    private (int, byte[])? CheckService(string? authorization)
    {
        if (authorization is null || !authorization.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            return Error(400, "invalid_request", "Malformed authorization header.");
        }

        string token = authorization["Bearer ".Length..];
        if (_revoked.Contains(token) || !_serviceTokens.ContainsKey(token))
        {
            return Error(401, "invalid_token", "The access token is not valid");
        }

        return _serviceTokens[token] <= _clock() ? Error(401, "expired_token", "The access token is expired") : null;
    }

    private static (int, byte[]) Json(Action<Utf8JsonWriter> write, int status = 200)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            write(w);
            w.WriteEndObject();
        }

        return (status, buffer.WrittenSpan.ToArray());
    }

    /// <summary>CSC API §10: an error is a JSON object with <c>error</c> and <c>error_description</c>.</summary>
    internal static (int, byte[]) Error(int status, string error, string description) => Json(w =>
    {
        w.WriteString("error", error);
        w.WriteString("error_description", description);
    }, status);

    private static (int, byte[]) Info() => Json(w =>
    {
        w.WriteString("specs", "2.2.0.0");
        w.WriteString("name", "OneCrypto Test Signing Service");
        w.WriteString("logo", "https://service.test/logo.png");
        w.WriteString("region", "DE");
        w.WriteString("lang", "en-US");
        w.WriteString("description", "A remote signing service written for tests");
        w.WriteStartArray("authType");
        w.WriteStringValue("oauth2client");
        w.WriteStringValue("oauth2code");
        w.WriteEndArray();
        w.WriteString("oauth2", "https://service.test/");
        w.WriteStartArray("methods");
        foreach (string m in Methods)
        {
            w.WriteStringValue(m);
        }

        w.WriteEndArray();
        w.WriteStartObject("signAlgorithms");
        w.WriteStartArray("algos");
        foreach (string a in Algorithms)
        {
            w.WriteStringValue(a);
        }

        w.WriteEndArray();
        w.WriteEndObject();
    });

    private static void WriteInfo(Utf8JsonWriter w, CscTestCredential c)
    {
        w.WriteStartObject("key");
        w.WriteString("status", c.KeyEnabled ? "enabled" : "disabled");
        w.WriteStartArray("algo");
        PublicKeyInfo pk = c.Key.PublicKey;
        if (pk.KeyAlgorithm == KeyAlgorithm.EllipticCurve)
        {
            w.WriteStringValue("1.2.840.10045.4.3.2");
            w.WriteStringValue("1.2.840.10045.4.3.3");
            w.WriteStringValue("1.2.840.10045.4.3.4");
        }
        else
        {
            w.WriteStringValue("1.2.840.113549.1.1.11");
            w.WriteStringValue("1.2.840.113549.1.1.10");
        }

        w.WriteEndArray();
        w.WriteNumber("len", pk.KeySizeBits);
        w.WriteEndObject();
        w.WriteStartObject("cert");
        w.WriteString("status", "valid");
        w.WriteStartArray("certificates");
        foreach (Certificate cert in c.Chain)
        {
            w.WriteStringValue(Convert.ToBase64String(cert.Encoded.Span));
        }

        w.WriteEndArray();
        w.WriteEndObject();
        w.WriteStartObject("auth");
        w.WriteString("mode", c.Mode == TestAuthMode.Explicit ? "explicit" : "oauth2code");
        if (c.Mode == TestAuthMode.Explicit)
        {
            w.WriteStartArray("objects");
            if (c.Pin is not null)
            {
                w.WriteStartObject();
                w.WriteString("type", "Password");
                w.WriteString("id", "PIN");
                w.WriteString("format", "N");
                w.WriteString("label", "PIN");
                w.WriteEndObject();
            }

            w.WriteEndArray();
        }

        w.WriteEndObject();
        w.WriteString("SCAL", c.Scal.ToString(System.Globalization.CultureInfo.InvariantCulture));
        w.WriteNumber("multisign", c.Multisign);
        w.WriteString("lang", "en-US");
    }

    private (int, byte[]) List(JsonElement r)
    {
        bool withInfo = r.TryGetProperty("credentialInfo", out JsonElement ci) && ci.ValueKind == JsonValueKind.True;
        return Json(w =>
        {
            w.WriteStartArray("credentialIDs");
            foreach (string id in _credentials.Keys)
            {
                w.WriteStringValue(id);
            }

            w.WriteEndArray();
            if (withInfo)
            {
                w.WriteStartArray("credentialInfos");
                foreach (CscTestCredential c in _credentials.Values)
                {
                    w.WriteStartObject();
                    w.WriteString("credentialID", c.Id);
                    WriteInfo(w, c);
                    w.WriteEndObject();
                }

                w.WriteEndArray();
            }
        });
    }

    private (int, byte[]) CredentialInfo(JsonElement r)
    {
        if (!Str(r, "credentialID", out string? id))
        {
            return Error(400, "invalid_request", "Missing (or invalid type) string parameter credentialID");
        }

        return _credentials.TryGetValue(id!, out CscTestCredential? c) ? Json(w => WriteInfo(w, c)) : Error(400, "invalid_request", "Invalid parameter credentialID");
    }

    private static bool Str(JsonElement r, string name, out string? value)
    {
        value = r.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        return value is not null;
    }

    private (int, byte[]) Authorize(JsonElement r)
    {
        if (!Str(r, "credentialID", out string? id))
        {
            return Error(400, "invalid_request", "Missing (or invalid type) string parameter credentialID");
        }

        if (!_credentials.TryGetValue(id!, out CscTestCredential? c))
        {
            return Error(400, "invalid_request", "Invalid parameter credentialID");
        }

        if (!c.KeyEnabled)
        {
            return Error(400, "invalid_request", "The credential identified by credentialID is disabled");
        }

        if (!r.TryGetProperty("numSignatures", out JsonElement n) || n.ValueKind != JsonValueKind.Number || !n.TryGetInt32(out int num))
        {
            return Error(400, "invalid_request", "Missing (or invalid type) integer parameter numSignatures");
        }

        if (num < 1)
        {
            return Error(400, "invalid_request", "Invalid value for parameter numSignatures");
        }

        if (num > c.Multisign)
        {
            return Error(400, "invalid_request", "Numbers of signatures is too high");
        }

        if (c.Mode == TestAuthMode.OAuth2Code)
        {
            // §11.8: credentials/authorize SHALL NOT be used for OAuth 2.0 credential authorization.
            return Error(400, "invalid_request", "This credential is authorized through OAuth 2.0");
        }

        HashSet<string>? hashes = null;
        if (r.TryGetProperty("hashes", out JsonElement h) && h.ValueKind == JsonValueKind.Array)
        {
            hashes = [];
            foreach (JsonElement e in h.EnumerateArray())
            {
                if (e.ValueKind != JsonValueKind.String || !TryBase64(e.GetString()!, out _))
                {
                    return Error(400, "invalid_request", "Invalid Base64 hash string parameter");
                }

                hashes.Add(e.GetString()!);
            }

            if (hashes.Count == 0)
            {
                hashes = null;
            }
        }

        if (c.Scal == 2 && (hashes is null || hashes.Count != num))
        {
            // §11.8: for SCAL 2 the hashes parameter SHALL be used and its count corresponds to numSignatures.
            return Error(400, "invalid_request", "Missing (or invalid type) array parameter hashes");
        }

        if (hashes is not null && !Str(r, "hashAlgorithmOID", out _))
        {
            return Error(400, "invalid_request", "Missing (or invalid type) string parameter hashAlgorithmOID");
        }

        if (c.Pin is not null && !HasPin(r, c.Pin))
        {
            return Error(400, "invalid_authentication_data", "The authentication data is invalid");
        }

        string sad = NewSecret("sad");
        _activations[sad] = new Activation(c.Id, hashes, num, _clock() + TimeSpan.FromSeconds(SadLifetimeSeconds));
        return Json(w =>
        {
            w.WriteString("SAD", sad);
            w.WriteNumber("expiresIn", SadLifetimeSeconds);
        });
    }

    private static bool HasPin(JsonElement r, string pin)
    {
        if (!r.TryGetProperty("authData", out JsonElement a) || a.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (JsonElement o in a.EnumerateArray())
        {
            if (o.ValueKind == JsonValueKind.Object && Str(o, "id", out string? id) && id == "PIN" && Str(o, "value", out string? v) && v == pin)
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryBase64(string s, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(s);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }

    private (int, byte[]) SignHash(JsonElement r, string authorization)
    {
        if (!Str(r, "credentialID", out string? id))
        {
            return Error(400, "invalid_request", "Missing (or invalid type) string parameter credentialID");
        }

        if (!_credentials.TryGetValue(id!, out CscTestCredential? c))
        {
            return Error(400, "invalid_request", "Invalid parameter credentialID");
        }

        // §11.13: the activation is the SAD parameter, or an access token with scope credential in the Authorization header.
        if (!Str(r, "SAD", out string? sad))
        {
            string bearer = authorization["Bearer ".Length..];
            if (!_activations.ContainsKey(bearer))
            {
                return Error(400, "invalid_request", "Missing (or invalid type) string parameter SAD");
            }

            sad = bearer;
        }

        if (!r.TryGetProperty("hashes", out JsonElement hs) || hs.ValueKind != JsonValueKind.Array)
        {
            return Error(400, "invalid_request", "Missing (or invalid type) array parameter hashes");
        }

        if (hs.GetArrayLength() == 0)
        {
            return Error(400, "invalid_request", "Empty hashes array");
        }

        var digests = new List<(string Text, byte[] Bytes)>();
        foreach (JsonElement e in hs.EnumerateArray())
        {
            if (e.ValueKind != JsonValueKind.String || !TryBase64(e.GetString()!, out byte[] b))
            {
                return Error(400, "invalid_request", "Invalid Base64 hash string parameter");
            }

            digests.Add((e.GetString()!, b));
        }

        if (!Str(r, "signAlgo", out string? algo))
        {
            return Error(400, "invalid_request", "Missing (or invalid type) string parameter signAlgo");
        }

        (SignatureSpec? spec, string? why) = SpecFor(c, algo!, r);
        if (spec is null)
        {
            return Error(400, "invalid_request", why!);
        }

        int size = spec.Hash.Name switch { "SHA1" => 20, "SHA256" => 32, "SHA384" => 48, _ => 64 };
        if (digests.Any(d => d.Bytes.Length != size))
        {
            return Error(400, "invalid_request", "Invalid digest value length");
        }

        if (!_activations.TryGetValue(sad!, out Activation? act) || act.CredentialId != c.Id)
        {
            return Error(400, "invalid_request", "Invalid parameter SAD");
        }

        if (act.Expires <= _clock())
        {
            return Error(400, "invalid_request", "SAD expired");
        }

        if (act.Hashes is null && c.Scal == 2)
        {
            return Error(400, "invalid_request", "Hash is not authorized by neither SAD nor an access token with scope \"credential\".");
        }

        if (act.Hashes is not null && digests.Any(d => !act.Hashes.Contains(d.Text)))
        {
            return Error(400, "invalid_request", "Hash is not authorized by neither SAD nor an access token with scope \"credential\".");
        }

        if (digests.Count > act.Remaining)
        {
            return Error(400, "invalid_request", "SAD expired");
        }

        _activations[sad!] = act with { Remaining = act.Remaining - digests.Count };
        if (_activations[sad!].Remaining == 0)
        {
            _activations.Remove(sad!);
        }

        return Json(w =>
        {
            w.WriteStartArray("signatures");
            foreach ((string _, byte[] digest) in digests)
            {
                w.WriteStringValue(Convert.ToBase64String(c.Key.SignDigest(digest, spec)));
            }

            w.WriteEndArray();
        });
    }

    /// <summary>
    /// Maps <c>signAlgo</c>, <c>signAlgoParams</c> and <c>hashAlgorithmOID</c> to a scheme. A hash-specific algorithm identifier implies its hash and must not
    /// contradict <c>hashAlgorithmOID</c>; <c>rsaEncryption</c> needs <c>hashAlgorithmOID</c> (§11.13).
    /// </summary>
    private static (SignatureSpec?, string?) SpecFor(CscTestCredential c, string algo, JsonElement r)
    {
        static HashAlgorithmName? FromOid(string? oid) => oid switch
        {
            "1.3.14.3.2.26" => HashAlgorithmName.SHA1,
            "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            _ => null,
        };

        _ = Str(r, "hashAlgorithmOID", out string? hashOid);
        HashAlgorithmName? stated = FromOid(hashOid);
        if (hashOid is not null && stated is null)
        {
            return (null, "Invalid parameter hashAlgorithmOID");
        }

        HashAlgorithmName? implied = algo switch
        {
            "1.2.840.113549.1.1.5" or "1.2.840.10045.4.1" => HashAlgorithmName.SHA1,
            "1.2.840.113549.1.1.11" or "1.2.840.10045.4.3.2" => HashAlgorithmName.SHA256,
            "1.2.840.113549.1.1.12" or "1.2.840.10045.4.3.3" => HashAlgorithmName.SHA384,
            "1.2.840.113549.1.1.13" or "1.2.840.10045.4.3.4" => HashAlgorithmName.SHA512,
            _ => null,
        };
        if (implied is not null && stated is not null && implied != stated)
        {
            return (null, "String parameter hashAlgorithmOID contradicts with signAlgo signAlgoParams parameter");
        }

        HashAlgorithmName? hash = implied ?? stated;
        bool ec = c.Key.PublicKey.KeyAlgorithm == KeyAlgorithm.EllipticCurve;
        switch (algo)
        {
            case "1.2.840.113549.1.1.1" or "1.2.840.113549.1.1.5" or "1.2.840.113549.1.1.11" or "1.2.840.113549.1.1.12" or "1.2.840.113549.1.1.13" when !ec:
                return hash is { } h ? (SignatureSpec.RsaPkcs1(h), null) : (null, "Missing (or invalid type) string parameter hashAlgorithmOID");
            case "1.2.840.113549.1.1.10" when !ec:
                if (hash is not { } ph)
                {
                    return (null, "Missing (or invalid type) string parameter hashAlgorithmOID");
                }

                if (!Str(r, "signAlgoParams", out string? p))
                {
                    return (null, "Missing (or invalid type) string parameter signAlgoParams");
                }

                SignatureSpec pss = SignatureSpec.RsaPss(ph);
                return TryBase64(p!, out byte[] given) && given.AsSpan().SequenceEqual(pss.ToAlgorithmIdentifier().Parameters.Span) ? (pss, null) : (null, "Invalid parameter signAlgoParams");
            case "1.2.840.10045.4.1" or "1.2.840.10045.4.3.2" or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4" when ec:
                return (SignatureSpec.Ecdsa(hash!.Value, c.EcdsaDer ? EcdsaSignatureFormat.Der : EcdsaSignatureFormat.Rfc4754), null);
            default:
                return (null, "Invalid parameter signAlgo");
        }
    }
}

/// <summary>Carries <see cref="CscTestServer"/> over the library's transport seam, remembering the requests (including headers) it was sent.</summary>
internal sealed class CscTestTransport : ITransport
{
    private readonly CscTestServer _server;
    private readonly Uri _base;

    public CscTestTransport(CscTestServer server, Uri baseUri)
    {
        _server = server;
        _base = baseUri;
    }

    public List<TransportRequest> Requests { get; } = [];

    /// <summary>When set, answers every request with this status and a Location header (a redirecting service).</summary>
    public string? RedirectTo { get; set; }

    public ValueTask<TransportResponse> SendAsync(TransportRequest request, CancellationToken cancellationToken)
    {
        lock (Requests)
        {
            Requests.Add(request);
        }

        if (RedirectTo is not null)
        {
            return ValueTask.FromResult(new TransportResponse(302, [new("Location", RedirectTo)], new MemoryStream([], writable: false)));
        }

        string path = _base.MakeRelativeUri(request.Uri).ToString();
        string? auth = request.Headers.FirstOrDefault(h => h.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase)).Value;
        (int status, byte[] body) = _server.Handle(path, auth, request.Body.ToArray());
        return ValueTask.FromResult(new TransportResponse(status, [new("Content-Type", "application/json;charset=UTF-8")], new MemoryStream(body, writable: false)));
    }
}
