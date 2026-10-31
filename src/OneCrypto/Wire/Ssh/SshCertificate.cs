using System.Text;

namespace RecursiveAI.OneCrypto.Wire.Ssh;

/// <summary>Whether an OpenSSH certificate authenticates a user or a host (PROTOCOL.certkeys).</summary>
public enum SshCertificateType
{
    /// <summary>A user certificate (type 1).</summary>
    User = 1,

    /// <summary>A host certificate (type 2).</summary>
    Host = 2,
}

/// <summary>A named option or extension of an OpenSSH certificate: its name and the raw data string that follows it.</summary>
public sealed record SshCertificateOption(string Name, ReadOnlyMemory<byte> Data);

/// <summary>
/// An OpenSSH certificate (<c>*-cert-v01@openssh.com</c>, format in PROTOCOL.certkeys): a public key signed by a CA key, with an
/// identity, principals, a validity window, critical options and extensions. Reading does not check the signature; call
/// <see cref="VerifySignature"/>. The blob is kept as received.
/// </summary>
public sealed class SshCertificate
{
    private const string Suffix = "-cert-v01@openssh.com";
    private readonly byte[] _blob;
    private readonly int _signedLength;

    private SshCertificate(byte[] blob, string name, byte[] nonce, SshPublicKey key, ulong serial, SshCertificateType type, string keyId, string[] principals, ulong after, ulong before, SshCertificateOption[] critical, SshCertificateOption[] extensions, byte[] reserved, SshPublicKey ca, byte[] signature, int signedLength)
    {
        _blob = blob;
        TypeName = name;
        Nonce = nonce;
        PublicKey = key;
        Serial = serial;
        CertificateType = type;
        KeyId = keyId;
        Principals = principals;
        ValidAfterSeconds = after;
        ValidBeforeSeconds = before;
        CriticalOptions = critical;
        Extensions = extensions;
        Reserved = reserved;
        SignatureKey = ca;
        Signature = signature;
        _signedLength = signedLength;
    }

    /// <summary>The wire name, for example <c>ssh-ed25519-cert-v01@openssh.com</c>.</summary>
    public string TypeName { get; }

    /// <summary>The whole certificate blob as received.</summary>
    public ReadOnlyMemory<byte> Blob => _blob;

    /// <summary>The CA-chosen random nonce.</summary>
    public ReadOnlyMemory<byte> Nonce { get; }

    /// <summary>The certified public key.</summary>
    public SshPublicKey PublicKey { get; }

    /// <summary>The serial number (0 when the CA does not use serials).</summary>
    public ulong Serial { get; }

    /// <summary>User or host certificate.</summary>
    public SshCertificateType CertificateType { get; }

    /// <summary>The free-text key identifier that sshd logs.</summary>
    public string KeyId { get; }

    /// <summary>The principals (user or host names) the certificate is valid for; empty means any.</summary>
    public IReadOnlyList<string> Principals { get; }

    /// <summary>The start of validity in seconds since the Unix epoch.</summary>
    public ulong ValidAfterSeconds { get; }

    /// <summary>The end of validity in seconds since the Unix epoch; <see cref="ulong.MaxValue"/> means no end.</summary>
    public ulong ValidBeforeSeconds { get; }

    /// <summary>The critical options, which a verifier must understand.</summary>
    public IReadOnlyList<SshCertificateOption> CriticalOptions { get; }

    /// <summary>The extensions, which a verifier may ignore.</summary>
    public IReadOnlyList<SshCertificateOption> Extensions { get; }

    /// <summary>The reserved field.</summary>
    public ReadOnlyMemory<byte> Reserved { get; }

    /// <summary>The CA's public key.</summary>
    public SshPublicKey SignatureKey { get; }

    /// <summary>The signature blob: a string with the algorithm name and a string with the signature.</summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>The bytes the CA signed: the certificate up to the signature.</summary>
    public ReadOnlyMemory<byte> SignedData => _blob.AsMemory(0, _signedLength);

    /// <summary>The start of validity.</summary>
    public DateTimeOffset ValidAfter => ToTime(ValidAfterSeconds);

    /// <summary>The end of validity, or <see cref="DateTimeOffset.MaxValue"/> when there is none.</summary>
    public DateTimeOffset ValidBefore => ToTime(ValidBeforeSeconds);

    private static DateTimeOffset ToTime(ulong s) => s > (ulong)DateTimeOffset.MaxValue.ToUnixTimeSeconds() ? DateTimeOffset.MaxValue : DateTimeOffset.FromUnixTimeSeconds((long)s);

    /// <summary>True when <paramref name="at"/> is within the validity window (inclusive of the start, exclusive of the end).</summary>
    public bool IsValidAt(DateTimeOffset at) => at >= ValidAfter && at < ValidBefore;

    /// <summary>Checks the CA's signature over <see cref="SignedData"/>. It does not decide whether the CA is trusted.</summary>
    public SshSignatureStatus VerifySignature() => SignatureKey.Verify(SignedData.Span, Signature.Span);

    /// <summary>The SHA-256 fingerprint of the certificate blob.</summary>
    public string Fingerprint => "SHA256:" + Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(_blob)).TrimEnd('=');

    /// <summary>Reads a certificate blob.</summary>
    /// <exception cref="SshParseException">The blob is malformed or of an unsupported type.</exception>
    public static SshCertificate Parse(ReadOnlySpan<byte> blob)
    {
        const string what = "SSH certificate";
        var r = new SshReader(blob, what);
        string name = r.ReadAscii();
        if (!name.EndsWith(Suffix, StringComparison.Ordinal))
        {
            throw new SshParseException(what, SshError.InvalidValue, "not a certificate type name");
        }

        string baseName = name[..^Suffix.Length];
        byte[] nonce = r.ReadString().ToArray();

        // Read the subject key's fields, then rebuild its plain public-key blob from the bytes they used.
        int before = r.Remaining.Length;
        ReadOnlySpan<byte> start = r.Remaining;
        _ = SshPublicKey.ReadFields(ref r, baseName, []);
        int used = before - r.Remaining.Length;
        using var w = new SshWriter();
        w.WriteString(baseName);
        w.WriteRaw(start[..used]);
        SshPublicKey key = SshPublicKey.Parse(w.Written);

        ulong serial = r.ReadUInt64();
        uint type = r.ReadUInt32();
        if (type is not (1 or 2))
        {
            throw new SshParseException(what, SshError.InvalidValue, "the certificate type must be 1 (user) or 2 (host)");
        }

        string keyId = Encoding.UTF8.GetString(r.ReadString());
        var principals = new List<string>();
        var pr = new SshReader(r.ReadString(), what);
        while (pr.HasData)
        {
            principals.Add(Encoding.UTF8.GetString(pr.ReadString()));
        }

        ulong after = r.ReadUInt64();
        ulong until = r.ReadUInt64();
        SshCertificateOption[] critical = Options(r.ReadString(), what);
        SshCertificateOption[] extensions = Options(r.ReadString(), what);
        byte[] reserved = r.ReadString().ToArray();
        byte[] caBlob = r.ReadString().ToArray();
        int signedLength = blob.Length - r.Remaining.Length;
        byte[] signature = r.ReadString().ToArray();
        r.ThrowIfNotEmpty();
        SshPublicKey ca = SshPublicKey.Parse(caBlob);
        return new SshCertificate(blob.ToArray(), name, nonce, key, serial, (SshCertificateType)type, keyId, [.. principals], after, until, critical, extensions, reserved, ca, signature, signedLength);
    }

    private static SshCertificateOption[] Options(ReadOnlySpan<byte> data, string what)
    {
        var list = new List<SshCertificateOption>();
        var r = new SshReader(data, what);
        while (r.HasData)
        {
            string n = r.ReadAscii();
            list.Add(new SshCertificateOption(n, r.ReadString().ToArray()));
        }

        return [.. list];
    }

    /// <summary>Reads a certificate blob, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlySpan<byte> blob, out SshCertificate? certificate)
    {
        try
        {
            certificate = Parse(blob);
            return true;
        }
        catch (SshParseException)
        {
            certificate = null;
            return false;
        }
    }

    /// <summary>Reads a <c>-cert.pub</c> line: <c>type-cert-v01@openssh.com base64 [comment]</c>.</summary>
    /// <exception cref="SshParseException">The line is not a certificate.</exception>
    public static SshCertificate ParseLine(string line)
    {
        ArgumentNullException.ThrowIfNull(line);
        string[] parts = line.Trim().Split([' ', '\t'], 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            throw new SshParseException("SSH certificate line", SshError.InvalidValue, "expected a type and a base64 certificate");
        }

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(parts[1]);
        }
        catch (FormatException)
        {
            throw new SshParseException("SSH certificate line", SshError.InvalidValue, "the certificate is not valid base64");
        }

        SshCertificate c = Parse(blob);
        return c.TypeName == parts[0] ? c : throw new SshParseException("SSH certificate line", SshError.InvalidValue, "the type in the line differs from the one inside the certificate");
    }
}
