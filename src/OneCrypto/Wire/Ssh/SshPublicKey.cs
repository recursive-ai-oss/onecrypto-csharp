using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Primitives;
using RecursiveAI.OneCrypto.Internal;

namespace RecursiveAI.OneCrypto.Wire.Ssh;

/// <summary>The kind of an OpenSSH public key.</summary>
public enum SshKeyType
{
    /// <summary><c>ssh-rsa</c> (RFC 4253 §6.6): an RSA key. The name covers the key; signatures use <c>rsa-sha2-256</c> or <c>rsa-sha2-512</c> (RFC 8332).</summary>
    Rsa,

    /// <summary><c>ecdsa-sha2-nistp256</c> (RFC 5656).</summary>
    EcdsaP256,

    /// <summary><c>ecdsa-sha2-nistp384</c>.</summary>
    EcdsaP384,

    /// <summary><c>ecdsa-sha2-nistp521</c>.</summary>
    EcdsaP521,

    /// <summary><c>ssh-ed25519</c> (RFC 8709).</summary>
    Ed25519,

    /// <summary><c>sk-ssh-ed25519@openssh.com</c>: an Ed25519 key held on a FIDO authenticator.</summary>
    SkEd25519,

    /// <summary><c>sk-ecdsa-sha2-nistp256@openssh.com</c>: a P-256 key held on a FIDO authenticator.</summary>
    SkEcdsaP256,
}

/// <summary>The result of checking an OpenSSH signature.</summary>
public enum SshSignatureStatus
{
    /// <summary>The signature verifies.</summary>
    Valid,

    /// <summary>The signature does not verify, or is malformed.</summary>
    Invalid,

    /// <summary>The signature algorithm is not one this library accepts (for example <c>ssh-rsa</c>, which signs with SHA-1).</summary>
    UnsupportedAlgorithm,
}

/// <summary>
/// An OpenSSH public key: the wire blob of RFC 4253 §6.6 with its type-specific fields, and the <c>authorized_keys</c> and RFC 4716
/// text forms. The blob is kept as received.
/// </summary>
public sealed class SshPublicKey : IEquatable<SshPublicKey>
{
    private readonly byte[] _blob;
    private readonly byte[] _a;
    private readonly byte[] _b;

    private SshPublicKey(byte[] blob, SshKeyType type, string name, byte[] a, byte[] b, string? curve, string? application)
    {
        _blob = blob;
        Type = type;
        TypeName = name;
        _a = a;
        _b = b;
        CurveName = curve;
        Application = application;
    }

    /// <summary>The key type.</summary>
    public SshKeyType Type { get; }

    /// <summary>The wire name, for example <c>ssh-ed25519</c>.</summary>
    public string TypeName { get; }

    /// <summary>The wire blob (the type name followed by the key fields), as hashed for fingerprints.</summary>
    public ReadOnlyMemory<byte> Blob => _blob;

    /// <summary>The comment of the file line the key was read from, or null.</summary>
    public string? Comment { get; private set; }

    /// <summary>The <c>authorized_keys</c> options before the key type, or null.</summary>
    public string? Options { get; private set; }

    /// <summary>For ECDSA keys, the curve identifier of RFC 5656 (<c>nistp256</c>, <c>nistp384</c> or <c>nistp521</c>); otherwise null.</summary>
    public string? CurveName { get; }

    /// <summary>For FIDO keys, the application string; otherwise null.</summary>
    public string? Application { get; }

    /// <summary>The RSA public exponent (big-endian magnitude); empty for other types.</summary>
    public ReadOnlyMemory<byte> RsaExponent => Type == SshKeyType.Rsa ? _a : default;

    /// <summary>The RSA modulus (big-endian magnitude); empty for other types.</summary>
    public ReadOnlyMemory<byte> RsaModulus => Type == SshKeyType.Rsa ? _b : default;

    /// <summary>The EC point (uncompressed, SEC 1) of an ECDSA key; empty for other types.</summary>
    public ReadOnlyMemory<byte> EcPoint => Type is SshKeyType.EcdsaP256 or SshKeyType.EcdsaP384 or SshKeyType.EcdsaP521 or SshKeyType.SkEcdsaP256 ? _a : default;

    /// <summary>The 32-byte Ed25519 public key; empty for other types.</summary>
    public ReadOnlyMemory<byte> Ed25519Key => Type is SshKeyType.Ed25519 or SshKeyType.SkEd25519 ? _a : default;

    /// <summary>The SHA-256 fingerprint in the form <c>ssh-keygen</c> prints, <c>SHA256:</c> followed by unpadded base64.</summary>
    public string Fingerprint => "SHA256:" + Convert.ToBase64String(SHA256.HashData(_blob)).TrimEnd('=');

    /// <summary>The key size in bits for RSA and ECDSA keys, 256 for Ed25519.</summary>
    public int KeySizeBits => Type switch
    {
        SshKeyType.Rsa => ((_b.Length - 1) * 8) + (32 - System.Numerics.BitOperations.LeadingZeroCount((uint)(_b.Length == 0 ? 0 : _b[0]))),
        SshKeyType.EcdsaP256 or SshKeyType.SkEcdsaP256 => 256,
        SshKeyType.EcdsaP384 => 384,
        SshKeyType.EcdsaP521 => 521,
        _ => 256,
    };

    // ---- parse ----

    /// <summary>Reads a public key wire blob.</summary>
    /// <exception cref="SshParseException">The blob is malformed or of an unsupported key type.</exception>
    public static SshPublicKey Parse(ReadOnlySpan<byte> blob)
    {
        var r = new SshReader(blob, "SSH public key");
        string name = r.ReadAscii();
        SshPublicKey key = ReadFields(ref r, name, blob.ToArray());
        r.ThrowIfNotEmpty();
        return key;
    }

    /// <summary>Reads the key fields that follow the type name (also used for the key inside a certificate).</summary>
    internal static SshPublicKey ReadFields(ref SshReader r, string name, byte[] blobForThis)
    {
        switch (name)
        {
            case "ssh-rsa":
            {
                byte[] e = r.ReadMpint().ToArray();
                byte[] n = r.ReadMpint().ToArray();
                if (e.Length == 0 || n.Length < 32)
                {
                    throw new SshParseException("SSH public key", SshError.InvalidValue, "the RSA key has an empty exponent or a tiny modulus");
                }

                return new SshPublicKey(blobForThis, SshKeyType.Rsa, name, e, n, null, null);
            }

            case "ecdsa-sha2-nistp256" or "ecdsa-sha2-nistp384" or "ecdsa-sha2-nistp521":
            {
                string curve = r.ReadAscii();
                byte[] q = r.ReadString().ToArray();
                (SshKeyType t, string expect, int len) = name switch
                {
                    "ecdsa-sha2-nistp256" => (SshKeyType.EcdsaP256, "nistp256", 65),
                    "ecdsa-sha2-nistp384" => (SshKeyType.EcdsaP384, "nistp384", 97),
                    _ => (SshKeyType.EcdsaP521, "nistp521", 133),
                };
                if (curve != expect || q.Length != len || q[0] != 4)
                {
                    throw new SshParseException("SSH public key", SshError.InvalidValue, "the EC point is not an uncompressed point on the named curve");
                }

                return new SshPublicKey(blobForThis, t, name, q, [], curve, null);
            }

            case "ssh-ed25519":
            {
                byte[] k = r.ReadString().ToArray();
                if (k.Length != 32)
                {
                    throw new SshParseException("SSH public key", SshError.InvalidValue, "an Ed25519 key is 32 bytes");
                }

                return new SshPublicKey(blobForThis, SshKeyType.Ed25519, name, k, [], null, null);
            }

            case "sk-ssh-ed25519@openssh.com":
            {
                byte[] k = r.ReadString().ToArray();
                string app = Encoding.UTF8.GetString(r.ReadString());
                if (k.Length != 32)
                {
                    throw new SshParseException("SSH public key", SshError.InvalidValue, "an Ed25519 key is 32 bytes");
                }

                return new SshPublicKey(blobForThis, SshKeyType.SkEd25519, name, k, [], null, app);
            }

            case "sk-ecdsa-sha2-nistp256@openssh.com":
            {
                string curve = r.ReadAscii();
                byte[] q = r.ReadString().ToArray();
                string app = Encoding.UTF8.GetString(r.ReadString());
                if (curve != "nistp256" || q.Length != 65 || q[0] != 4)
                {
                    throw new SshParseException("SSH public key", SshError.InvalidValue, "the EC point is not an uncompressed P-256 point");
                }

                return new SshPublicKey(blobForThis, SshKeyType.SkEcdsaP256, name, q, [], curve, app);
            }

            default:
                throw new SshParseException("SSH public key", SshError.Unsupported, $"key type {name} is not supported");
        }
    }

    /// <summary>Reads a public key wire blob, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlySpan<byte> blob, out SshPublicKey? key)
    {
        try
        {
            key = Parse(blob);
            return true;
        }
        catch (SshParseException)
        {
            key = null;
            return false;
        }
    }

    private static bool IsKeyTypeToken(string t) => t.StartsWith("ssh-", StringComparison.Ordinal) || t.StartsWith("ecdsa-sha2-", StringComparison.Ordinal) || t.StartsWith("sk-", StringComparison.Ordinal);

    /// <summary>Reads one <c>authorized_keys</c> or <c>.pub</c> line: <c>[options] type base64 [comment]</c> (sshd(8) AUTHORIZED_KEYS FILE FORMAT).</summary>
    /// <exception cref="SshParseException">The line is not a supported key.</exception>
    public static SshPublicKey ParseAuthorizedKey(string line)
    {
        ArgumentNullException.ThrowIfNull(line);
        line = line.Trim();
        int pos = 0;
        string? options = null;

        // Options are comma-separated and may contain double-quoted strings with spaces; the key type follows the first space outside quotes.
        string first = Token(line, ref pos);
        if (!IsKeyTypeToken(first))
        {
            options = first;
            first = Token(line, ref pos);
        }

        string b64 = Token(line, ref pos);
        if (!IsKeyTypeToken(first) || b64.Length == 0)
        {
            throw new SshParseException("authorized_keys line", SshError.InvalidValue, "expected a key type and a base64 key");
        }

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(b64);
        }
        catch (FormatException)
        {
            throw new SshParseException("authorized_keys line", SshError.InvalidValue, "the key is not valid base64");
        }

        SshPublicKey key = Parse(blob);
        if (key.TypeName != first)
        {
            throw new SshParseException("authorized_keys line", SshError.InvalidValue, "the key type in the line differs from the one inside the key");
        }

        string comment = line[Math.Min(pos, line.Length)..].Trim();
        key.Comment = comment.Length == 0 ? null : comment;
        key.Options = options;
        return key;
    }

    private static string Token(string s, ref int pos)
    {
        while (pos < s.Length && (s[pos] == ' ' || s[pos] == '\t'))
        {
            pos++;
        }

        int start = pos;
        bool quoted = false;
        while (pos < s.Length && (quoted || (s[pos] != ' ' && s[pos] != '\t')))
        {
            if (s[pos] == '"')
            {
                quoted = !quoted;
            }

            pos++;
        }

        return s[start..pos];
    }

    /// <summary>Reads an <c>authorized_keys</c> line, returning false instead of throwing.</summary>
    public static bool TryParseAuthorizedKey(string line, out SshPublicKey? key)
    {
        try
        {
            key = ParseAuthorizedKey(line);
            return true;
        }
        catch (SshParseException)
        {
            key = null;
            return false;
        }
    }

    /// <summary>Reads an RFC 4716 §3 "SSH2 public key" file.</summary>
    /// <exception cref="SshParseException">The text is not a valid RFC 4716 key file.</exception>
    public static SshPublicKey ParseRfc4716(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        string[] lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        int i = 0;
        while (i < lines.Length && lines[i].Trim().Length == 0)
        {
            i++;
        }

        if (i >= lines.Length || lines[i].Trim() != "---- BEGIN SSH2 PUBLIC KEY ----")
        {
            throw new SshParseException("RFC 4716 key", SshError.InvalidValue, "missing the BEGIN marker");
        }

        i++;
        string? comment = null;
        var body = new StringBuilder();
        bool ended = false;
        for (; i < lines.Length; i++)
        {
            string l = lines[i].TrimEnd();
            if (l == "---- END SSH2 PUBLIC KEY ----")
            {
                ended = true;
                break;
            }

            if (body.Length == 0 && l.Contains(':', StringComparison.Ordinal))
            {
                // A header (RFC 4716 §3.3); a line ending in a backslash continues on the next line.
                string header = l;
                while (header.EndsWith('\\') && i + 1 < lines.Length)
                {
                    header = header[..^1] + lines[++i].TrimEnd();
                }

                int c = header.IndexOf(':', StringComparison.Ordinal);
                if (header[..c].Trim().Equals("Comment", StringComparison.OrdinalIgnoreCase))
                {
                    comment = header[(c + 1)..].Trim().Trim('"');
                }

                continue;
            }

            body.Append(l.Trim());
        }

        if (!ended)
        {
            throw new SshParseException("RFC 4716 key", SshError.InvalidValue, "missing the END marker");
        }

        try
        {
            SshPublicKey k = Parse(Convert.FromBase64String(body.ToString()));
            k.Comment = comment;
            return k;
        }
        catch (FormatException)
        {
            throw new SshParseException("RFC 4716 key", SshError.InvalidValue, "the key is not valid base64");
        }
    }

    // ---- write ----

    /// <summary>The key as an <c>authorized_keys</c> / <c>.pub</c> line without a line end. The comment defaults to <see cref="Comment"/>.</summary>
    public string ToAuthorizedKey(string? comment = null)
    {
        string c = comment ?? Comment ?? string.Empty;
        string o = Options is null ? string.Empty : Options + " ";
        return $"{o}{TypeName} {Convert.ToBase64String(_blob)}{(c.Length == 0 ? string.Empty : " " + c)}";
    }

    /// <summary>The key as an RFC 4716 §3 file. Lines are 70 characters or fewer, as the RFC requires.</summary>
    public string ToRfc4716(string? comment = null)
    {
        var sb = new StringBuilder("---- BEGIN SSH2 PUBLIC KEY ----\n");
        string c = comment ?? Comment ?? string.Empty;
        if (c.Length > 0)
        {
            sb.Append("Comment: \"").Append(c).Append("\"\n");
        }

        string b64 = Convert.ToBase64String(_blob);
        for (int i = 0; i < b64.Length; i += 70)
        {
            sb.Append(b64, i, Math.Min(70, b64.Length - i)).Append('\n');
        }

        sb.Append("---- END SSH2 PUBLIC KEY ----\n");
        return sb.ToString();
    }

    /// <summary>The key as a <c>SubjectPublicKeyInfo</c> (RSA, ECDSA and Ed25519 keys).</summary>
    /// <exception cref="NotSupportedException">The key is a FIDO key, which has no SubjectPublicKeyInfo form.</exception>
    public PublicKeyInfo ToPublicKeyInfo()
    {
        switch (Type)
        {
            case SshKeyType.Rsa:
            {
                // Built from the key's numbers rather than through the platform's RSA, so it works where the platform has none (RFC 8017 A.1.1).
                var rsaKey = new Asn1.Asn1Writer();
                rsaKey.PushSequence();
                rsaKey.WriteUnsignedInteger(_b.AsSpan().TrimStart((byte)0));
                rsaKey.WriteUnsignedInteger(_a.AsSpan().TrimStart((byte)0));
                rsaKey.Pop();
                return Spki(KnownOids.RsaEncryption, null, rsaKey.Encode());
            }

            case SshKeyType.EcdsaP256 or SshKeyType.EcdsaP384 or SshKeyType.EcdsaP521:
                // The SSH point is the uncompressed point, which is also what SubjectPublicKeyInfo carries (RFC 5480 §2.2).
                return Spki(KnownOids.EcPublicKey, Type switch { SshKeyType.EcdsaP256 => KnownOids.P256, SshKeyType.EcdsaP384 => KnownOids.P384, _ => KnownOids.P521 }, _a);

            case SshKeyType.Ed25519:
                var w = new Asn1.Asn1Writer();
                w.PushSequence();
                w.PushSequence();
                w.WriteObjectIdentifier(KnownOids.Ed25519);
                w.Pop();
                w.WriteBitString(_a);
                w.Pop();
                return PublicKeyInfo.Parse(w.Encode());
            default:
                throw new NotSupportedException("FIDO keys have no SubjectPublicKeyInfo form.");
        }
    }

    private static PublicKeyInfo Spki(string algorithm, string? curve, ReadOnlySpan<byte> keyBits)
    {
        var w = new Asn1.Asn1Writer();
        w.PushSequence();
        w.PushSequence();
        w.WriteObjectIdentifier(algorithm);
        if (curve is null)
        {
            w.WriteNull();
        }
        else
        {
            w.WriteObjectIdentifier(curve);
        }

        w.Pop();
        w.WriteBitString(keyBits);
        w.Pop();
        return PublicKeyInfo.Parse(w.Encode());
    }

    private ECDsa ToECDsa()
    {
        ECCurve curve = Type switch
        {
            SshKeyType.EcdsaP256 or SshKeyType.SkEcdsaP256 => ECCurve.NamedCurves.nistP256,
            SshKeyType.EcdsaP384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        int n = (_a.Length - 1) / 2;
        var p = new ECParameters { Curve = curve, Q = new ECPoint { X = _a[1..(1 + n)], Y = _a[(1 + n)..] } };
        return Platform.CreateEcdsa(p, "EC public key import");
    }

    /// <summary>The public key of a <see cref="PublicKeyInfo"/> (RSA, P-256/384/521 and Ed25519).</summary>
    /// <exception cref="NotSupportedException">The algorithm has no OpenSSH key type.</exception>
    public static SshPublicKey FromPublicKeyInfo(PublicKeyInfo key)
    {
        ArgumentNullException.ThrowIfNull(key);
        using var w = new SshWriter();
        switch (key.KeyAlgorithm)
        {
            case KeyAlgorithm.Rsa:
                using (RSA rsa = key.ToRsa())
                {
                    RSAParameters p = rsa.ExportParameters(false);
                    w.WriteString("ssh-rsa");
                    w.WriteMpint(p.Exponent);
                    w.WriteMpint(p.Modulus);
                }

                break;
            case KeyAlgorithm.EllipticCurve:
                using (ECDsa ec = key.ToECDsa())
                {
                    ECParameters p = ec.ExportParameters(false);
                    string id = key.CurveOid switch
                    {
                        KnownOids.P256 => "nistp256",
                        KnownOids.P384 => "nistp384",
                        KnownOids.P521 => "nistp521",
                        _ => throw new NotSupportedException("Only the NIST curves P-256, P-384 and P-521 have OpenSSH key types."),
                    };
                    w.WriteString("ecdsa-sha2-" + id);
                    w.WriteString(id);
                    byte[] q = new byte[1 + p.Q.X!.Length + p.Q.Y!.Length];
                    q[0] = 4;
                    p.Q.X.CopyTo(q, 1);
                    p.Q.Y.CopyTo(q, 1 + p.Q.X.Length);
                    w.WriteString(q);
                }

                break;
            case KeyAlgorithm.Ed25519:
                w.WriteString("ssh-ed25519");
                w.WriteString(key.KeyBits.Span);
                break;
            default:
                throw new NotSupportedException($"{key.Algorithm.Name} has no OpenSSH key type.");
        }

        return Parse(w.Written);
    }

    /// <inheritdoc/>
    public bool Equals(SshPublicKey? other) => other is not null && _blob.AsSpan().SequenceEqual(other._blob);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as SshPublicKey);

    /// <inheritdoc/>
    public override int GetHashCode() => _blob.Length > 4 ? BitConverter.ToInt32(_blob, _blob.Length - 4) : 0;

    /// <inheritdoc/>
    public override string ToString() => $"{TypeName} {Fingerprint}";

    // ---- verification (used by certificates) ----

    internal SshSignatureStatus Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob)
    {
        try
        {
            var r = new SshReader(signatureBlob, "SSH signature");
            string alg = r.ReadAscii();
            ReadOnlySpan<byte> sig = r.ReadString();
            r.ThrowIfNotEmpty();
            switch (Type)
            {
                case SshKeyType.Ed25519 when alg == "ssh-ed25519":
                    return sig.Length == 64 && Ed25519.Verify(_a, data, sig) ? SshSignatureStatus.Valid : SshSignatureStatus.Invalid;
                case SshKeyType.Rsa when alg is "rsa-sha2-256" or "rsa-sha2-512":
                    using (RSA rsa = Platform.CreateRsa("RSA public key object"))
                    {
                        rsa.ImportParameters(new RSAParameters { Exponent = _a, Modulus = _b });
                        return rsa.VerifyData(data, sig, alg == "rsa-sha2-256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1) ? SshSignatureStatus.Valid : SshSignatureStatus.Invalid;
                    }

                case SshKeyType.Rsa when alg == "ssh-rsa":
                    // ssh-rsa signs with SHA-1; it is refused rather than verified.
                    return SshSignatureStatus.UnsupportedAlgorithm;
                case SshKeyType.EcdsaP256 or SshKeyType.EcdsaP384 or SshKeyType.EcdsaP521 when alg == TypeName:
                {
                    var sr = new SshReader(sig, "SSH ECDSA signature");
                    ReadOnlySpan<byte> rr = sr.ReadMpint();
                    ReadOnlySpan<byte> ss = sr.ReadMpint();
                    sr.ThrowIfNotEmpty();
                    int n = (_a.Length - 1) / 2;
                    if (rr.Length > n || ss.Length > n)
                    {
                        return SshSignatureStatus.Invalid;
                    }

                    byte[] p1363 = new byte[2 * n];
                    rr.CopyTo(p1363.AsSpan(n - rr.Length, rr.Length));
                    ss.CopyTo(p1363.AsSpan((2 * n) - ss.Length, ss.Length));
                    using ECDsa ec = ToECDsa();
                    HashAlgorithmName h = Type == SshKeyType.EcdsaP256 ? HashAlgorithmName.SHA256 : Type == SshKeyType.EcdsaP384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA512;
                    return ec.VerifyData(data, p1363, h) ? SshSignatureStatus.Valid : SshSignatureStatus.Invalid;
                }

                default:
                    return SshSignatureStatus.UnsupportedAlgorithm;
            }
        }
        catch (SshParseException)
        {
            return SshSignatureStatus.Invalid;
        }
        catch (CryptographicException)
        {
            return SshSignatureStatus.Invalid;
        }
    }
}
