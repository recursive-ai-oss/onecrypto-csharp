using System.Globalization;
using System.Text.Json;

namespace RecursiveAI.OneCrypto.Online.Csc;

/// <summary>The authorization mode of a credential (CSC API §11.7, <c>auth/mode</c>).</summary>
public enum CscAuthMode
{
    /// <summary>The application collects the authentication objects (PIN, OTP) and sends them to <c>credentials/authorize</c>.</summary>
    Explicit = 0,

    /// <summary>The service runs the authorization through OAuth 2.0 (authorization code, scope <c>credential</c>).</summary>
    OAuth2Code = 1,
}

/// <summary>An authentication object type a credential asks for (<c>auth/objects</c>, CSC API §11.8).</summary>
public sealed class CscAuthObjectType
{
    internal CscAuthObjectType(string type, string id, string? label, string? description, string? format)
    {
        Type = type;
        Id = id;
        Label = label;
        Description = description;
        Format = format;
    }

    /// <summary>The object type (for example <c>Password</c>).</summary>
    public string Type { get; }

    /// <summary>The identifier the value is sent under.</summary>
    public string Id { get; }

    /// <summary>A label to show to the user.</summary>
    public string? Label { get; }

    /// <summary>Instructions to show to the user.</summary>
    public string? Description { get; }

    /// <summary>The password format, <c>A</c> (alphanumeric) or <c>N</c> (numeric), when stated.</summary>
    public string? Format { get; }
}

/// <summary>An authentication value for <c>credentials/authorize</c> (<c>authData</c>). The value is a secret and is never printed.</summary>
public sealed class CscAuthObject
{
    /// <summary>Creates an authentication value.</summary>
    /// <param name="id">The <see cref="CscAuthObjectType.Id"/> it answers.</param>
    /// <param name="value">The PIN, OTP or password.</param>
    public CscAuthObject(string id, string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(value);
        Id = id;
        Value = value;
    }

    /// <summary>The identifier.</summary>
    public string Id { get; }

    /// <summary>The secret value.</summary>
    public string Value { get; }

    /// <summary>A fixed text that does not contain the value.</summary>
    public override string ToString() => $"CscAuthObject({Id}, redacted)";
}

/// <summary>What <c>info</c> says about a remote signing service (CSC API §11.1). Only what this client uses is kept.</summary>
public sealed class CscServiceInfo
{
    internal CscServiceInfo(string specs, string name, string? lang, IReadOnlyList<string> authTypes, IReadOnlyList<string> methods, string? oauth2, IReadOnlyList<string> signAlgorithms)
    {
        Specs = specs;
        Name = name;
        Language = lang;
        AuthTypes = authTypes;
        Methods = methods;
        OAuth2Base = oauth2;
        SignAlgorithms = signAlgorithms;
    }

    /// <summary>The version of the specification the service implements (<c>specs</c>, for example <c>2.2.0.0</c>).</summary>
    public string Specs { get; }

    /// <summary>The commercial name.</summary>
    public string Name { get; }

    /// <summary>The language of the descriptions.</summary>
    public string? Language { get; }

    /// <summary>The service authorization mechanisms (<c>authType</c>): <c>external</c>, <c>TLS</c>, <c>basic</c>, <c>digest</c>, <c>oauth2code</c>, <c>oauth2client</c>.</summary>
    public IReadOnlyList<string> AuthTypes { get; }

    /// <summary>The API method names listed (empty when the service omitted the list; <c>info</c> may always be left out, §11.1 note).</summary>
    public IReadOnlyList<string> Methods { get; }

    /// <summary>The base URI of the OAuth 2.0 server (<c>oauth2</c>), when the service names one that way.</summary>
    public string? OAuth2Base { get; }

    /// <summary>The signature algorithm OIDs the service lists (<c>signAlgorithms.algos</c>).</summary>
    public IReadOnlyList<string> SignAlgorithms { get; }

    /// <summary>True when the service lists <paramref name="method"/> or lists no methods at all.</summary>
    public bool SupportsMethod(string method) => Methods.Count == 0 || Methods.Contains(method);
}

/// <summary>A credential as <c>credentials/info</c> describes it (CSC API §11.7).</summary>
public sealed class CscCredentialInfo
{
    internal CscCredentialInfo(string credentialId, string? description, bool keyEnabled, IReadOnlyList<string> keyAlgorithms, int keyLength, string? curveOid,
        IReadOnlyList<ReadOnlyMemory<byte>> certificates, CscAuthMode authMode, string? authExpression, IReadOnlyList<CscAuthObjectType> authObjects, int scal, int multisign)
    {
        CredentialId = credentialId;
        Description = description;
        IsKeyEnabled = keyEnabled;
        KeyAlgorithms = keyAlgorithms;
        KeyLength = keyLength;
        CurveOid = curveOid;
        Certificates = certificates;
        AuthMode = authMode;
        AuthExpression = authExpression;
        AuthObjects = authObjects;
        Scal = scal;
        Multisign = multisign;
    }

    /// <summary>The credential identifier.</summary>
    public string CredentialId { get; }

    /// <summary>The description, if any.</summary>
    public string? Description { get; }

    /// <summary>True when the key status is <c>enabled</c> (<c>key/status</c>).</summary>
    public bool IsKeyEnabled { get; }

    /// <summary>The OIDs in <c>key/algo</c>.</summary>
    public IReadOnlyList<string> KeyAlgorithms { get; }

    /// <summary>The key length in bits (<c>key/len</c>).</summary>
    public int KeyLength { get; }

    /// <summary>The curve OID of an ECDSA key (<c>key/curve</c>).</summary>
    public string? CurveOid { get; }

    /// <summary>The DER certificates returned, the end-entity certificate first (<c>cert/certificates</c>); empty when none was asked for.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Certificates { get; }

    /// <summary>The authorization mode (<c>auth/mode</c>).</summary>
    public CscAuthMode AuthMode { get; }

    /// <summary>The expression over the authentication objects, when stated.</summary>
    public string? AuthExpression { get; }

    /// <summary>The authentication objects an explicit authorization asks for.</summary>
    public IReadOnlyList<CscAuthObjectType> AuthObjects { get; }

    /// <summary>The signature activation level: 2 when the hash to be signed is linked to the activation data, otherwise 1 (the default when the service says nothing).</summary>
    public int Scal { get; }

    /// <summary>The most signatures one authorization may cover (<c>multisign</c>, at least 1).</summary>
    public int Multisign { get; }
}

/// <summary>The answer of <c>credentials/list</c> (CSC API §11.6).</summary>
public sealed class CscCredentialList
{
    internal CscCredentialList(IReadOnlyList<string> ids, IReadOnlyList<CscCredentialInfo> infos)
    {
        CredentialIds = ids;
        Infos = infos;
    }

    /// <summary>The credential identifiers.</summary>
    public IReadOnlyList<string> CredentialIds { get; }

    /// <summary>Their descriptions, when <c>credentialInfo</c> was asked for.</summary>
    public IReadOnlyList<CscCredentialInfo> Infos { get; }
}

/// <summary>The answer of <c>credentials/authorize</c> (CSC API §11.8). The activation data is a secret and is never printed.</summary>
public sealed class CscAuthorization
{
    internal CscAuthorization(string? sad, int? expiresIn, string? pendingHandle)
    {
        Sad = sad;
        ExpiresIn = expiresIn;
        PendingHandle = pendingHandle;
    }

    /// <summary>The Signature Activation Data to pass to <c>signatures/signHash</c>; null while the authorization is pending.</summary>
    public string? Sad { get; }

    /// <summary>The lifetime of the activation data in seconds (the service default is 3600 when it omits this).</summary>
    public int? ExpiresIn { get; }

    /// <summary>The handle of an authorization that is still underway (HTTP 202); null otherwise.</summary>
    public string? PendingHandle { get; }

    /// <summary>A fixed text that does not contain the activation data.</summary>
    public override string ToString() => Sad is null ? "CscAuthorization(pending)" : "CscAuthorization(redacted)";
}

/// <summary>A response that is not what the API describes. Internal: <see cref="CscClient"/> turns it into <see cref="CscOutcome.MalformedResponse"/>.</summary>
internal sealed class CscFormatException : Exception
{
    public CscFormatException(string message)
        : base(message)
    {
    }

    public CscFormatException()
        : this("malformed response")
    {
    }

    public CscFormatException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

/// <summary>Reads the JSON the CSC API returns, with limits and without reflection.</summary>
internal static class CscJson
{
    internal const int MaxItems = 256;
    internal const int MaxCertificates = 16;

    /// <summary>Depth 16, no comments, no trailing commas: the API's objects are shallow.</summary>
    internal static readonly JsonDocumentOptions Options = new() { MaxDepth = 16, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false };

    internal static JsonElement Root(ReadOnlyMemory<byte> body)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(body, Options);
            return doc.RootElement.ValueKind == JsonValueKind.Object ? doc.RootElement.Clone() : throw new CscFormatException("the answer is not a JSON object");
        }
        catch (JsonException ex)
        {
            throw new CscFormatException("the answer is not valid JSON", ex);
        }
    }

    internal static string? OptString(JsonElement o, string name, int max = 4096)
    {
        if (!o.TryGetProperty(name, out JsonElement v) || v.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (v.ValueKind != JsonValueKind.String)
        {
            throw new CscFormatException($"'{name}' is not a string");
        }

        string s = v.GetString()!;
        return s.Length > max ? throw new CscFormatException($"'{name}' is too long") : s;
    }

    internal static string ReqString(JsonElement o, string name, int max = 4096) => OptString(o, name, max) ?? throw new CscFormatException($"'{name}' is missing");

    internal static List<string> OptStrings(JsonElement o, string name, int max = 4096)
    {
        var list = new List<string>();
        if (!o.TryGetProperty(name, out JsonElement v) || v.ValueKind == JsonValueKind.Null)
        {
            return list;
        }

        if (v.ValueKind != JsonValueKind.Array || v.GetArrayLength() > MaxItems)
        {
            throw new CscFormatException($"'{name}' is not a short array");
        }

        foreach (JsonElement e in v.EnumerateArray())
        {
            list.Add(e.ValueKind == JsonValueKind.String && e.GetString()!.Length <= max ? e.GetString()! : throw new CscFormatException($"'{name}' holds something that is not a string"));
        }

        return list;
    }

    internal static JsonElement? OptObject(JsonElement o, string name)
    {
        if (!o.TryGetProperty(name, out JsonElement v) || v.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return v.ValueKind == JsonValueKind.Object ? v : throw new CscFormatException($"'{name}' is not an object");
    }

    internal static int? OptInt(JsonElement o, string name)
    {
        if (!o.TryGetProperty(name, out JsonElement v) || v.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        // Some services write numbers as strings (SCAL is a string in the specification's table, a number in examples elsewhere); both are read.
        if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out int n))
        {
            return n;
        }

        if (v.ValueKind == JsonValueKind.String && int.TryParse(v.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out int m))
        {
            return m;
        }

        throw new CscFormatException($"'{name}' is not an integer");
    }

    internal static byte[] Base64(string text, string what)
    {
        // The API says "base64"; services emit either alphabets, with or without padding.
        string t = text.Replace('-', '+').Replace('_', '/');
        t = t.PadRight(t.Length + ((4 - (t.Length % 4)) % 4), '=');
        try
        {
            return Convert.FromBase64String(t);
        }
        catch (FormatException ex)
        {
            throw new CscFormatException($"{what} is not Base64", ex);
        }
    }

    internal static CscServiceInfo ParseInfo(JsonElement r)
    {
        JsonElement? algs = OptObject(r, "signAlgorithms");
        return new CscServiceInfo(
            ReqString(r, "specs", 64),
            ReqString(r, "name", 1024),
            OptString(r, "lang", 64),
            OptStrings(r, "authType", 64),
            OptStrings(r, "methods", 128),
            OptString(r, "oauth2", 2048),
            algs is { } a ? OptStrings(a, "algos", 128) : []);
    }

    internal static CscCredentialInfo ParseCredential(JsonElement r, string credentialId)
    {
        JsonElement key = OptObject(r, "key") ?? throw new CscFormatException("'key' is missing");
        JsonElement? cert = OptObject(r, "cert");
        JsonElement auth = OptObject(r, "auth") ?? throw new CscFormatException("'auth' is missing");

        var certs = new List<ReadOnlyMemory<byte>>();
        if (cert is { } c)
        {
            List<string> encoded = OptStrings(c, "certificates", 1 << 20);
            if (encoded.Count > MaxCertificates)
            {
                throw new CscFormatException("too many certificates");
            }

            foreach (string e in encoded)
            {
                certs.Add(Base64(e, "a certificate"));
            }
        }

        string mode = ReqString(auth, "mode", 32);
        CscAuthMode authMode = mode switch
        {
            "explicit" => CscAuthMode.Explicit,
            "oauth2code" => CscAuthMode.OAuth2Code,
            _ => throw new CscFormatException("unknown authorization mode"),
        };

        var objects = new List<CscAuthObjectType>();
        if (auth.TryGetProperty("objects", out JsonElement objs) && objs.ValueKind == JsonValueKind.Array)
        {
            if (objs.GetArrayLength() > 16)
            {
                throw new CscFormatException("too many authentication objects");
            }

            foreach (JsonElement o in objs.EnumerateArray())
            {
                if (o.ValueKind != JsonValueKind.Object)
                {
                    throw new CscFormatException("an authentication object is not an object");
                }

                objects.Add(new CscAuthObjectType(ReqString(o, "type", 64), ReqString(o, "id", 128), OptString(o, "label", 512), OptString(o, "description", 1024), OptString(o, "format", 8)));
            }
        }

        int scal = OptInt(r, "SCAL") ?? 1;
        int multisign = OptInt(r, "multisign") ?? 1;
        if (scal is not (1 or 2) || multisign < 1)
        {
            throw new CscFormatException("SCAL or multisign has an impossible value");
        }

        return new CscCredentialInfo(
            credentialId,
            OptString(r, "description", 1024),
            string.Equals(OptString(key, "status", 16), "enabled", StringComparison.Ordinal),
            OptStrings(key, "algo", 128),
            OptInt(key, "len") ?? 0,
            OptString(key, "curve", 128),
            certs,
            authMode,
            OptString(auth, "expression", 1024),
            objects,
            scal,
            multisign);
    }
}
