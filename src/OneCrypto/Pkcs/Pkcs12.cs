using System.Linq;
using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Internal;
using RecursiveAI.OneCrypto.Pem;

namespace RecursiveAI.OneCrypto.Pkcs;

/// <summary>What a PKCS#12 SafeBag holds (RFC 7292 §4.2).</summary>
public enum Pkcs12BagKind
{
    /// <summary>keyBag: an unencrypted PKCS#8 PrivateKeyInfo.</summary>
    Key,

    /// <summary>pkcs8ShroudedKeyBag: a password-encrypted PKCS#8 key. After opening, <see cref="Pkcs12Bag.PrivateKey"/> holds the decrypted key.</summary>
    ShroudedKey,

    /// <summary>certBag holding an X.509 certificate.</summary>
    Certificate,

    /// <summary>crlBag holding an X.509 CRL.</summary>
    Crl,

    /// <summary>secretBag: an arbitrary typed value.</summary>
    Secret,

    /// <summary>safeContentsBag: nested bags.</summary>
    SafeContents,

    /// <summary>A bag type this library does not know, or a certBag of another certificate type; <see cref="Pkcs12Bag.Value"/> holds the bag value as received.</summary>
    Unknown,
}

/// <summary>A PKCS#12 bag attribute (RFC 7292 §4.2): an object identifier and its encoded values.</summary>
public sealed record Pkcs12BagAttr(string Oid, IReadOnlyList<ReadOnlyMemory<byte>> Values);

/// <summary>One SafeBag of a PKCS#12 file with its attributes. Bags that hold private keys must be disposed.</summary>
public sealed class Pkcs12Bag : IDisposable
{
    /// <summary>friendlyName (PKCS#9, RFC 2985).</summary>
    public const string FriendlyNameOid = "1.2.840.113549.1.9.20";

    /// <summary>localKeyId (PKCS#9, RFC 2985).</summary>
    public const string LocalKeyIdOid = "1.2.840.113549.1.9.21";

    private readonly PinnedSecret? _secret;

    internal Pkcs12Bag(Pkcs12BagKind kind, string bagId, IReadOnlyList<Pkcs12BagAttr> attributes, PrivateKeyInfo? key, Certificate? certificate, ReadOnlyMemory<byte> value, string? secretType, PinnedSecret? secret, IReadOnlyList<Pkcs12Bag> children)
    {
        Kind = kind;
        BagId = bagId;
        Attributes = attributes;
        PrivateKey = key;
        Certificate = certificate;
        Value = value;
        SecretTypeId = secretType;
        _secret = secret;
        Children = children;
    }

    /// <summary>The bag type.</summary>
    public Pkcs12BagKind Kind { get; }

    /// <summary>The <c>bagId</c> object identifier.</summary>
    public string BagId { get; }

    /// <summary>The bag attributes in file order, including ones this library does not interpret.</summary>
    public IReadOnlyList<Pkcs12BagAttr> Attributes { get; }

    /// <summary>The key of a <see cref="Pkcs12BagKind.Key"/> or opened <see cref="Pkcs12BagKind.ShroudedKey"/> bag.</summary>
    public PrivateKeyInfo? PrivateKey { get; }

    /// <summary>The certificate of a <see cref="Pkcs12BagKind.Certificate"/> bag.</summary>
    public Certificate? Certificate { get; }

    /// <summary>The CRL octets of a <see cref="Pkcs12BagKind.Crl"/> bag, or the received bag value of an <see cref="Pkcs12BagKind.Unknown"/> bag.</summary>
    public ReadOnlyMemory<byte> Value { get; }

    /// <summary>The <c>secretTypeId</c> of a secret bag.</summary>
    public string? SecretTypeId { get; }

    /// <summary>The encoded <c>secretValue</c> of a secret bag. Valid until <see cref="Dispose"/>.</summary>
    public ReadOnlySpan<byte> SecretValue => _secret is null ? default : _secret.ReadOnlySpan;

    /// <summary>The bags of a <see cref="Pkcs12BagKind.SafeContents"/> bag.</summary>
    public IReadOnlyList<Pkcs12Bag> Children { get; }

    /// <summary>The friendlyName attribute, or null.</summary>
    public string? FriendlyName
    {
        get
        {
            foreach (Pkcs12BagAttr a in Attributes)
            {
                if (a.Oid == FriendlyNameOid && a.Values.Count == 1 && new Asn1Reader(a.Values[0].Span, Asn1Rules.Ber).TryReadCharacterString(Asn1Tags.BmpString, out string s))
                {
                    return s;
                }
            }

            return null;
        }
    }

    /// <summary>The localKeyId attribute (it links a key to its certificate), or empty.</summary>
    public ReadOnlyMemory<byte> LocalKeyId
    {
        get
        {
            foreach (Pkcs12BagAttr a in Attributes)
            {
                if (a.Oid == LocalKeyIdOid && a.Values.Count == 1 && new Asn1Reader(a.Values[0].Span, Asn1Rules.Ber).TryReadOctetStringBytes(out byte[] id))
                {
                    return id;
                }
            }

            return default;
        }
    }

    /// <summary>Zeroes the key material of this bag and its children.</summary>
    public void Dispose()
    {
        PrivateKey?.Dispose();
        _secret?.Dispose();
        foreach (Pkcs12Bag c in Children)
        {
            c.Dispose();
        }
    }

    // ---- builders ----

    /// <summary>A bag for writing a private key. By default it is written as a shrouded (encrypted) key bag.</summary>
    /// <param name="key">The key; it is not copied, so keep it alive until the file is created.</param>
    /// <param name="friendlyName">An optional display name.</param>
    /// <param name="localKeyId">An optional identifier shared with the key's certificate bag.</param>
    /// <param name="shrouded">False writes an unencrypted keyBag (the file's other protection then rests on the MAC alone, which does not hide the key).</param>
    public static Pkcs12Bag ForPrivateKey(PrivateKeyInfo key, string? friendlyName = null, ReadOnlyMemory<byte> localKeyId = default, bool shrouded = true)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new Pkcs12Bag(shrouded ? Pkcs12BagKind.ShroudedKey : Pkcs12BagKind.Key, shrouded ? "1.2.840.113549.1.12.10.1.2" : "1.2.840.113549.1.12.10.1.1", Attrs(friendlyName, localKeyId), key, null, default, null, null, []);
    }

    /// <summary>A bag for writing a certificate.</summary>
    public static Pkcs12Bag ForCertificate(Certificate certificate, string? friendlyName = null, ReadOnlyMemory<byte> localKeyId = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new Pkcs12Bag(Pkcs12BagKind.Certificate, "1.2.840.113549.1.12.10.1.3", Attrs(friendlyName, localKeyId), null, certificate, default, null, null, []);
    }

    /// <summary>A bag for writing a CRL.</summary>
    public static Pkcs12Bag ForCrl(ReadOnlyMemory<byte> crl, string? friendlyName = null) =>
        new(Pkcs12BagKind.Crl, "1.2.840.113549.1.12.10.1.4", Attrs(friendlyName, default), null, null, crl, null, null, []);

    /// <summary>A bag for writing a secret (an object identifier and one DER-encoded value).</summary>
    public static Pkcs12Bag ForSecret(string secretTypeId, ReadOnlySpan<byte> encodedValue, string? friendlyName = null) =>
        new(Pkcs12BagKind.Secret, "1.2.840.113549.1.12.10.1.5", Attrs(friendlyName, default), null, null, default, secretTypeId, new PinnedSecret(encodedValue), []);

    private static List<Pkcs12BagAttr> Attrs(string? friendlyName, ReadOnlyMemory<byte> localKeyId)
    {
        var list = new List<Pkcs12BagAttr>();
        if (friendlyName is not null)
        {
            var w = new Asn1Writer();
            w.WriteCharacterString(Asn1Tags.BmpString, friendlyName);
            list.Add(new Pkcs12BagAttr(FriendlyNameOid, [w.Encode()]));
        }

        if (!localKeyId.IsEmpty)
        {
            var w = new Asn1Writer();
            w.WriteOctetString(localKeyId.Span);
            list.Add(new Pkcs12BagAttr(LocalKeyIdOid, [w.Encode()]));
        }

        return list;
    }
}

/// <summary>The integrity mechanism a PKCS#12 file uses.</summary>
public enum Pkcs12MacKind
{
    /// <summary>No MAC.</summary>
    None,

    /// <summary>HMAC with a key from the PKCS#12 derivation (RFC 7292 §4 and Appendix B).</summary>
    Pkcs12,

    /// <summary>PBMAC1 (RFC 9579): PBKDF2 then HMAC.</summary>
    Pbmac1,
}

/// <summary>How to write a PKCS#12 file. Defaults: AES-256-CBC with PBKDF2-HMAC-SHA-256 for keys and certificates, and an HMAC-SHA-256 MAC with the PKCS#12 derivation.</summary>
public sealed class Pkcs12WriteOptions
{
    /// <summary>The defaults.</summary>
    public static Pkcs12WriteOptions Default { get; } = new();

    /// <summary>Encryption of shrouded keys and of the certificate container.</summary>
    public Pbes2Options Encryption { get; init; } = Pbes2Options.Default;

    /// <summary>True (default) to encrypt the container with the certificates, as OpenSSL does. False writes it in the clear.</summary>
    public bool EncryptCertificates { get; init; } = true;

    /// <summary>The MAC. Default <see cref="Pkcs12MacKind.Pkcs12"/>: every reader understands it. <see cref="Pkcs12MacKind.Pbmac1"/> needs a reader of RFC 9579.</summary>
    public Pkcs12MacKind Mac { get; init; } = Pkcs12MacKind.Pkcs12;

    /// <summary>The MAC hash: SHA-1, SHA-256, SHA-384 or SHA-512. Default SHA-256.</summary>
    public HashAlgorithmName MacHash { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>The MAC key-derivation iteration count. Default 600,000.</summary>
    public int MacIterations { get; init; } = 600_000;
}

/// <summary>The decrypted content of a PKCS#12 file. Dispose it to zero the keys.</summary>
public sealed class Pkcs12Contents : IDisposable
{
    internal Pkcs12Contents(IReadOnlyList<Pkcs12Bag> bags) => Bags = bags;

    /// <summary>The top-level bags in file order, across all safes.</summary>
    public IReadOnlyList<Pkcs12Bag> Bags { get; }

    /// <summary>Every bag, nested ones included, depth first.</summary>
    public IEnumerable<Pkcs12Bag> AllBags()
    {
        foreach (Pkcs12Bag b in Bags)
        {
            foreach (Pkcs12Bag x in Flatten(b))
            {
                yield return x;
            }
        }
    }

    private static IEnumerable<Pkcs12Bag> Flatten(Pkcs12Bag b)
    {
        yield return b;
        foreach (Pkcs12Bag c in b.Children)
        {
            foreach (Pkcs12Bag x in Flatten(c))
            {
                yield return x;
            }
        }
    }

    /// <summary>The certificates in file order.</summary>
    public IReadOnlyList<Certificate> Certificates => [.. AllBags().Where(b => b.Certificate is not null).Select(b => b.Certificate!)];

    /// <summary>The private-key bags (plain and decrypted shrouded ones) in file order.</summary>
    public IReadOnlyList<PrivateKeyInfo> PrivateKeys => [.. AllBags().Where(b => b.PrivateKey is not null).Select(b => b.PrivateKey!)];

    /// <summary>The certificate bag whose localKeyId equals that of <paramref name="keyBag"/>, or null.</summary>
    public Pkcs12Bag? FindCertificateFor(Pkcs12Bag keyBag)
    {
        ArgumentNullException.ThrowIfNull(keyBag);
        ReadOnlyMemory<byte> id = keyBag.LocalKeyId;
        return id.IsEmpty ? null : AllBags().FirstOrDefault(b => b.Kind == Pkcs12BagKind.Certificate && b.LocalKeyId.Span.SequenceEqual(id.Span));
    }

    /// <summary>Zeroes every key and secret.</summary>
    public void Dispose()
    {
        foreach (Pkcs12Bag b in Bags)
        {
            b.Dispose();
        }
    }
}

/// <summary>
/// A PKCS#12 / PFX file (RFC 7292): parsing, password-checked opening, and writing. Parsing keeps the file's bytes and reads
/// only the structure; <see cref="TryOpen"/> checks the MAC and decrypts. Works without <c>X509Certificate2</c>.
/// </summary>
/// <remarks>
/// Read: password integrity (HMAC with the PKCS#12 derivation over SHA-1 or SHA-2) and PBMAC1 (RFC 9579); PBES2 (AES, 3DES, PBKDF2,
/// scrypt) and the PKCS#12 PBEs with triple DES and RC2. Not read: RC4 PBEs, public-key integrity and privacy modes (signedData,
/// envelopedData), which give <see cref="PkcsStatus.UnsupportedAlgorithm"/>.
/// </remarks>
public sealed class Pkcs12File
{
    private const string DataOid = "1.2.840.113549.1.7.1";
    private const string EncryptedDataOid = "1.2.840.113549.1.7.6";

    private readonly byte[] _encoded;
    private readonly byte[] _authSafe;
    private readonly List<Safe> _safes;
    private readonly Mac? _mac;
    private readonly PkcsLimits _limits;

    private sealed record Safe(string ContentType, byte[] Content, AlgorithmIdentifier? Algorithm);

    private sealed record Mac(string Kind, AlgorithmIdentifier DigestAlgorithm, byte[] Digest, byte[] Salt, long Iterations);

    private Pkcs12File(byte[] encoded, byte[] authSafe, List<Safe> safes, Mac? mac, PkcsLimits limits)
    {
        _encoded = encoded;
        _authSafe = authSafe;
        _safes = safes;
        _mac = mac;
        _limits = limits;
    }

    /// <summary>The file as received (or as written).</summary>
    public ReadOnlyMemory<byte> Encoded => _encoded;

    /// <summary>Which MAC the file carries.</summary>
    public Pkcs12MacKind MacKind => _mac is null ? Pkcs12MacKind.None : _mac.DigestAlgorithm.Oid == Pbe.Pbmac1 ? Pkcs12MacKind.Pbmac1 : Pkcs12MacKind.Pkcs12;

    /// <summary>The number of ContentInfo safes in the AuthenticatedSafe.</summary>
    public int SafeCount => _safes.Count;

    // ---- parsing ----

    /// <summary>Reads the structure of a PFX (BER is accepted). No password is needed.</summary>
    /// <exception cref="PkcsParseException">The input is not a PFX, or exceeds a limit.</exception>
    public static Pkcs12File Parse(ReadOnlySpan<byte> encoded, PkcsLimits? limits = null)
    {
        limits ??= PkcsLimits.Default;
        const string what = "PFX";
        if (encoded.Length > limits.MaxEncodedSize)
        {
            throw PkcsFail.Limit(what, "The file is larger than the configured limit.");
        }

        byte[] copy = encoded.ToArray();
        return PkcsFail.Run(what, () => ParseCore(copy, limits));
    }

    private static Pkcs12File ParseCore(byte[] copy, PkcsLimits limits)
    {
        const string what = "PFX";
        var r = new Asn1Reader(copy, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader pfx = r.ReadSequence();
        r.ThrowIfNotEmpty();
        int version = pfx.ReadInt32();
        if (version != 3)
        {
            throw PkcsFail.Unsupported(what, $"Version {version} is not the PKCS#12 v1.1 version 3.");
        }

        Asn1Reader ci = pfx.ReadSequence();
        if (ci.ReadObjectIdentifier() != DataOid)
        {
            throw PkcsFail.Unsupported(what, "Public-key integrity mode (signedData) is not supported.");
        }

        Asn1Reader ex = ci.ReadSequence(Asn1Tag.Context(0, true));
        byte[] authSafe = ex.ReadOctetStringBytes();
        ex.ThrowIfNotEmpty();
        ci.ThrowIfNotEmpty();

        var safes = new List<Safe>();
        var ar = new Asn1Reader(authSafe, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader seq = ar.ReadSequence();
        ar.ThrowIfNotEmpty();
        while (seq.HasData)
        {
            if (safes.Count >= limits.MaxSafes)
            {
                throw PkcsFail.Limit(what, "The AuthenticatedSafe has too many ContentInfo elements.");
            }

            Asn1Reader c = seq.ReadSequence();
            string type = c.ReadObjectIdentifier();
            Asn1Reader body = c.ReadSequence(Asn1Tag.Context(0, true));
            if (type == DataOid)
            {
                safes.Add(new Safe(type, body.ReadOctetStringBytes(), null));
            }
            else if (type == EncryptedDataOid)
            {
                // RFC 5652 §8: EncryptedData ::= SEQUENCE { version, encryptedContentInfo { contentType, algorithm, [0] IMPLICIT encryptedContent } }
                Asn1Reader ed = body.ReadSequence();
                ed.ReadInt32();
                Asn1Reader eci = ed.ReadSequence();
                if (eci.ReadObjectIdentifier() != DataOid)
                {
                    throw PkcsFail.Bad(what, "An encrypted safe must hold data.");
                }

                AlgorithmIdentifier alg = AlgorithmIdentifier.Parse(eci.ReadEncodedValue().ToArray());
                safes.Add(new Safe(type, eci.ReadOctetStringBytes(Asn1Tag.Context(0)), alg));
            }
            else
            {
                safes.Add(new Safe(type, [], null));
            }
        }

        Mac? mac = null;
        if (pfx.HasData)
        {
            Asn1Reader m = pfx.ReadSequence();
            Asn1Reader di = m.ReadSequence();
            AlgorithmIdentifier alg = AlgorithmIdentifier.Parse(di.ReadEncodedValue().ToArray());
            byte[] digest = di.ReadOctetStringBytes();
            di.ThrowIfNotEmpty();
            byte[] salt = m.ReadOctetStringBytes();
            long iterations = m.HasData ? m.ReadInt64() : 1;
            m.ThrowIfNotEmpty();
            mac = new Mac(alg.Oid == Pbe.Pbmac1 ? "pbmac1" : "pkcs12", alg, digest, salt, iterations);
        }

        pfx.ThrowIfNotEmpty();
        return new Pkcs12File(copy, authSafe, safes, mac, limits);
    }

    /// <summary>Reads the structure of a PFX, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlySpan<byte> encoded, out Pkcs12File? file, PkcsLimits? limits = null)
    {
        try
        {
            file = Parse(encoded, limits);
            return true;
        }
        catch (PkcsParseException)
        {
            file = null;
            return false;
        }
    }

    // ---- MAC ----

    /// <summary>Checks the MAC with <paramref name="password"/>.</summary>
    /// <returns><see cref="PkcsStatus.Ok"/>, <see cref="PkcsStatus.WrongPasswordOrCorrupt"/> (the file's contents have been changed or the password is wrong), <see cref="PkcsStatus.IntegrityMissing"/> when the file has no MAC, or a status naming why the MAC could not be computed.</returns>
    public PkcsStatus VerifyMac(ReadOnlySpan<char> password) => VerifyMac(password, out _);

    private PkcsStatus VerifyMac(ReadOnlySpan<char> password, out bool nullPassword)
    {
        nullPassword = false;
        if (_mac is null)
        {
            return PkcsStatus.IntegrityMissing;
        }

        PkcsStatus st = ComputeAndCompare(password, false);
        if (st == PkcsStatus.WrongPasswordOrCorrupt && password.IsEmpty && _mac.Kind == "pkcs12")
        {
            // RFC 7292 Appendix B.1 gives an empty password two encodings (zero bytes, or the terminator alone); writers differ.
            nullPassword = true;
            st = ComputeAndCompare(password, true);
        }

        return st;
    }

    private PkcsStatus ComputeAndCompare(ReadOnlySpan<char> password, bool nullPassword)
    {
        Mac mac = _mac!;
        try
        {
            if (mac.Iterations < 1)
            {
                return PkcsStatus.Malformed;
            }

            if (mac.Kind == "pkcs12")
            {
                string? hash = Pbe.HashOidName(mac.DigestAlgorithm.Oid);
                if (hash is null)
                {
                    return PkcsStatus.UnsupportedAlgorithm;
                }

                if (mac.Iterations > _limits.MaxIterations || mac.Salt.Length > _limits.MaxSaltLength)
                {
                    return PkcsStatus.LimitExceeded;
                }

                var h = new HashAlgorithmName(hash);
                using PinnedSecret pw = Pbe.Bmp(password, nullPassword);
                using var key = new PinnedSecret(mac.Digest.Length);
                if (mac.Digest.Length != HashLen(h))
                {
                    return PkcsStatus.WrongPasswordOrCorrupt;
                }

                Pbe.Pkcs12Kdf(h, 3, pw.ReadOnlySpan, mac.Salt, mac.Iterations, key.Span);
                byte[] expected = CryptographicOperations.HmacData(h, key.ReadOnlySpan, _authSafe);
                return CryptographicOperations.FixedTimeEquals(expected, mac.Digest) ? PkcsStatus.Ok : PkcsStatus.WrongPasswordOrCorrupt;
            }

            // RFC 9579 §3: PBMAC1-params ::= SEQUENCE { keyDerivationFunc (PBKDF2, keyLength present), messageAuthScheme (HMAC) }
            var r = new Asn1Reader(mac.DigestAlgorithm.Parameters.Span, Asn1Rules.Ber, _limits.Asn1);
            Asn1Reader p = r.ReadSequence();
            AlgorithmIdentifier kdf = AlgorithmIdentifier.Parse(p.ReadEncodedValue().ToArray());
            AlgorithmIdentifier scheme = AlgorithmIdentifier.Parse(p.ReadEncodedValue().ToArray());
            if (kdf.Oid != Pbe.Pbkdf2Oid || Pbe.HmacOidHash(scheme.Oid) is not { } mh)
            {
                return PkcsStatus.UnsupportedAlgorithm;
            }

            var kr = new Asn1Reader(kdf.Parameters.Span, Asn1Rules.Ber, _limits.Asn1);
            Asn1Reader kp = kr.ReadSequence();
            ReadOnlySpan<byte> salt = kp.ReadOctetString();
            long iterations = kp.ReadInt64();
            int keyLength = kp.ReadInt32();
            string prf = "SHA1";
            if (kp.HasData)
            {
                prf = Pbe.HmacOidHash(AlgorithmIdentifier.Parse(kp.ReadEncodedValue().ToArray()).Oid) ?? string.Empty;
            }

            if (prf.Length == 0)
            {
                return PkcsStatus.UnsupportedAlgorithm;
            }

            if (iterations < 1 || keyLength < 1 || keyLength > 1024)
            {
                return PkcsStatus.Malformed;
            }

            if (iterations > _limits.MaxIterations || salt.Length > _limits.MaxSaltLength)
            {
                return PkcsStatus.LimitExceeded;
            }

            using PinnedSecret upw = Pbe.Utf8(password);
            using var mk = new PinnedSecret(keyLength);
            Rfc2898DeriveBytes.Pbkdf2(upw.ReadOnlySpan, salt, mk.Span, (int)iterations, new HashAlgorithmName(prf));
            byte[] tag = CryptographicOperations.HmacData(new HashAlgorithmName(mh), mk.ReadOnlySpan, _authSafe);
            return CryptographicOperations.FixedTimeEquals(tag, mac.Digest) ? PkcsStatus.Ok : PkcsStatus.WrongPasswordOrCorrupt;
        }
        catch (Asn1ParseException)
        {
            return PkcsStatus.Malformed;
        }
        catch (X509ParseException)
        {
            return PkcsStatus.Malformed;
        }
        catch (PkcsParseException)
        {
            return PkcsStatus.Malformed;
        }
    }

    private static int HashLen(HashAlgorithmName h) => h.Name switch { "SHA1" => 20, "SHA224" => 28, "SHA256" => 32, "SHA384" => 48, _ => 64 };

    // ---- opening ----

    /// <summary>
    /// Checks the MAC, decrypts every safe and reads every bag. Nothing is returned unless the whole file opens: a wrong password, a
    /// failed MAC or a damaged safe gives a status and no contents.
    /// </summary>
    /// <param name="password">The password; an empty password is tried in both of its encodings.</param>
    /// <param name="contents">The contents when the status is <see cref="PkcsStatus.Ok"/>; the caller disposes it.</param>
    /// <param name="requireMac">True (default) refuses a file without a MAC (<see cref="PkcsStatus.IntegrityMissing"/>); false opens it, trusting nothing about its integrity.</param>
    public PkcsStatus TryOpen(ReadOnlySpan<char> password, out Pkcs12Contents? contents, bool requireMac = true)
    {
        contents = null;
        bool nullPw = false;
        if (_mac is not null)
        {
            PkcsStatus ms = VerifyMac(password, out nullPw);
            if (ms != PkcsStatus.Ok)
            {
                return ms;
            }
        }
        else if (requireMac)
        {
            return PkcsStatus.IntegrityMissing;
        }

        PkcsStatus st = OpenWith(password, nullPw, out contents);
        if (st != PkcsStatus.Ok && _mac is null && password.IsEmpty && !nullPw)
        {
            st = OpenWith(password, true, out contents);
        }

        return st;
    }

    /// <summary>Opens the file; see <see cref="TryOpen"/>.</summary>
    /// <exception cref="PkcsPasswordException">The password is wrong, the file was changed, or it uses an unsupported algorithm.</exception>
    public Pkcs12Contents Open(ReadOnlySpan<char> password, bool requireMac = true)
    {
        PkcsStatus st = TryOpen(password, out Pkcs12Contents? c, requireMac);
        return st == PkcsStatus.Ok ? c! : throw new PkcsPasswordException(st);
    }

    private PkcsStatus OpenWith(ReadOnlySpan<char> password, bool nullPassword, out Pkcs12Contents? contents)
    {
        contents = null;
        var bags = new List<Pkcs12Bag>();
        var counter = new int[1];
        try
        {
            foreach (Safe s in _safes)
            {
                PinnedSecret? plain = null;
                try
                {
                    ReadOnlySpan<byte> safeContents;
                    if (s.ContentType == DataOid)
                    {
                        safeContents = s.Content;
                    }
                    else if (s.ContentType == EncryptedDataOid)
                    {
                        PkcsStatus ds = Pbe.Decrypt(s.Algorithm!, password, nullPassword, s.Content, _limits, out plain);
                        if (ds != PkcsStatus.Ok)
                        {
                            return ds;
                        }

                        safeContents = plain!.ReadOnlySpan;
                    }
                    else
                    {
                        return PkcsStatus.UnsupportedAlgorithm;
                    }

                    PkcsStatus rs = ReadSafeContents(safeContents, password, nullPassword, 0, counter, bags);
                    if (rs != PkcsStatus.Ok)
                    {
                        return rs;
                    }
                }
                finally
                {
                    plain?.Dispose();
                }
            }

            contents = new Pkcs12Contents(bags);
            bags = [];
            return PkcsStatus.Ok;
        }
        catch (Asn1ParseException)
        {
            return PkcsStatus.Malformed;
        }
        catch (PkcsParseException ex)
        {
            return ex.Error == PkcsError.LimitExceeded ? PkcsStatus.LimitExceeded : PkcsStatus.Malformed;
        }
        catch (X509ParseException)
        {
            return PkcsStatus.Malformed;
        }
        finally
        {
            foreach (Pkcs12Bag b in bags)
            {
                b.Dispose();
            }
        }
    }

    private PkcsStatus ReadSafeContents(ReadOnlySpan<byte> data, ReadOnlySpan<char> password, bool nullPassword, int depth, int[] counter, List<Pkcs12Bag> into)
    {
        if (depth > _limits.MaxSafeNesting)
        {
            return PkcsStatus.LimitExceeded;
        }

        var r = new Asn1Reader(data, Asn1Rules.Ber, _limits.Asn1);
        Asn1Reader seq = r.ReadSequence();
        r.ThrowIfNotEmpty();
        while (seq.HasData)
        {
            if (++counter[0] > _limits.MaxBags)
            {
                return PkcsStatus.LimitExceeded;
            }

            Asn1Reader bag = seq.ReadSequence();
            string id = bag.ReadObjectIdentifier();
            Asn1Reader ex = bag.ReadSequence(Asn1Tag.Context(0, true));
            ReadOnlySpan<byte> value = ex.ReadEncodedValue();
            ex.ThrowIfNotEmpty();
            var attrs = new List<Pkcs12BagAttr>();
            if (bag.HasData)
            {
                Asn1Reader set = bag.ReadSetOf();
                while (set.HasData)
                {
                    Asn1Reader a = set.ReadSequence();
                    string oid = a.ReadObjectIdentifier();
                    Asn1Reader vs = a.ReadSetOf();
                    var values = new List<ReadOnlyMemory<byte>>();
                    while (vs.HasData)
                    {
                        values.Add(vs.ReadEncodedValue().ToArray());
                    }

                    attrs.Add(new Pkcs12BagAttr(oid, values));
                }
            }

            bag.ThrowIfNotEmpty();
            Pkcs12Bag? made;
            PkcsStatus st = MakeBag(id, value, attrs, password, nullPassword, depth, counter, out made);
            if (st != PkcsStatus.Ok)
            {
                return st;
            }

            into.Add(made!);
        }

        return PkcsStatus.Ok;
    }

    private PkcsStatus MakeBag(string id, ReadOnlySpan<byte> value, List<Pkcs12BagAttr> attrs, ReadOnlySpan<char> password, bool nullPassword, int depth, int[] counter, out Pkcs12Bag? bag)
    {
        bag = null;
        switch (id)
        {
            case "1.2.840.113549.1.12.10.1.1":
                bag = new Pkcs12Bag(Pkcs12BagKind.Key, id, attrs, PrivateKeyInfo.Parse(value, _limits), null, default, null, null, []);
                return PkcsStatus.Ok;
            case "1.2.840.113549.1.12.10.1.2":
            {
                EncryptedPrivateKeyInfo e = EncryptedPrivateKeyInfo.Parse(value, _limits);
                PkcsStatus st = e.TryDecryptWith(password, nullPassword, out PrivateKeyInfo? key);
                if (st != PkcsStatus.Ok)
                {
                    return st;
                }

                bag = new Pkcs12Bag(Pkcs12BagKind.ShroudedKey, id, attrs, key, null, default, null, null, []);
                return PkcsStatus.Ok;
            }

            case "1.2.840.113549.1.12.10.1.3":
            {
                var r = new Asn1Reader(value, Asn1Rules.Ber, _limits.Asn1);
                Asn1Reader cb = r.ReadSequence();
                string certId = cb.ReadObjectIdentifier();
                Asn1Reader ex = cb.ReadSequence(Asn1Tag.Context(0, true));
                byte[] der = ex.ReadOctetStringBytes();
                if (certId == "1.2.840.113549.1.9.22.1")
                {
                    bag = new Pkcs12Bag(Pkcs12BagKind.Certificate, id, attrs, null, Certificate.Parse(der), default, null, null, []);
                }
                else
                {
                    bag = new Pkcs12Bag(Pkcs12BagKind.Unknown, id, attrs, null, null, value.ToArray(), null, null, []);
                }

                return PkcsStatus.Ok;
            }

            case "1.2.840.113549.1.12.10.1.4":
            {
                var r = new Asn1Reader(value, Asn1Rules.Ber, _limits.Asn1);
                Asn1Reader cb = r.ReadSequence();
                cb.ReadObjectIdentifier();
                Asn1Reader ex = cb.ReadSequence(Asn1Tag.Context(0, true));
                bag = new Pkcs12Bag(Pkcs12BagKind.Crl, id, attrs, null, null, ex.ReadOctetStringBytes(), null, null, []);
                return PkcsStatus.Ok;
            }

            case "1.2.840.113549.1.12.10.1.5":
            {
                var r = new Asn1Reader(value, Asn1Rules.Ber, _limits.Asn1);
                Asn1Reader sb = r.ReadSequence();
                string type = sb.ReadObjectIdentifier();
                Asn1Reader ex = sb.ReadSequence(Asn1Tag.Context(0, true));
                bag = new Pkcs12Bag(Pkcs12BagKind.Secret, id, attrs, null, null, default, type, new PinnedSecret(ex.ReadEncodedValue()), []);
                return PkcsStatus.Ok;
            }

            case "1.2.840.113549.1.12.10.1.6":
            {
                var kids = new List<Pkcs12Bag>();
                try
                {
                    PkcsStatus st = ReadSafeContents(value, password, nullPassword, depth + 1, counter, kids);
                    if (st != PkcsStatus.Ok)
                    {
                        return st;
                    }

                    bag = new Pkcs12Bag(Pkcs12BagKind.SafeContents, id, attrs, null, null, default, null, null, kids);
                    kids = [];
                    return PkcsStatus.Ok;
                }
                finally
                {
                    foreach (Pkcs12Bag k in kids)
                    {
                        k.Dispose();
                    }
                }
            }

            default:
                bag = new Pkcs12Bag(Pkcs12BagKind.Unknown, id, attrs, null, null, value.ToArray(), null, null, []);
                return PkcsStatus.Ok;
        }
    }

    // ---- writing ----

    /// <summary>
    /// Writes a PFX holding <paramref name="bags"/>. Key and secret bags go into one unencrypted container (keys are shrouded
    /// individually), certificates and CRLs into a second container that is encrypted with PBES2 unless
    /// <see cref="Pkcs12WriteOptions.EncryptCertificates"/> is false. A MAC over the whole is added.
    /// </summary>
    /// <param name="bags">The bags to write; they are read, not disposed.</param>
    /// <param name="password">The password for the shrouded keys, the encrypted container and the MAC. Empty is written as the BMPString terminator alone.</param>
    /// <param name="options">Null for <see cref="Pkcs12WriteOptions.Default"/>.</param>
    public static Pkcs12File Create(IEnumerable<Pkcs12Bag> bags, ReadOnlySpan<char> password, Pkcs12WriteOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(bags);
        options ??= Pkcs12WriteOptions.Default;
        var keyBags = new Asn1Writer();
        var certBags = new Asn1Writer();
        keyBags.PushSequence();
        certBags.PushSequence();
        int nk = 0, nc = 0;
        foreach (Pkcs12Bag b in bags)
        {
            switch (b.Kind)
            {
                case Pkcs12BagKind.Key or Pkcs12BagKind.ShroudedKey or Pkcs12BagKind.Secret:
                    WriteBag(keyBags, b, password, options);
                    nk++;
                    break;
                case Pkcs12BagKind.Certificate or Pkcs12BagKind.Crl:
                    WriteBag(certBags, b, password, options);
                    nc++;
                    break;
                default:
                    throw new ArgumentException($"A {b.Kind} bag cannot be written.", nameof(bags));
            }
        }

        keyBags.Pop();
        certBags.Pop();

        var safe = new Asn1Writer();
        safe.PushSequence();
        if (nk > 0)
        {
            safe.PushSequence();
            safe.WriteObjectIdentifier(DataOid);
            safe.PushConstructed(Asn1Tag.Context(0, true));
            safe.WriteOctetString(keyBags.Encode());
            safe.Pop();
            safe.Pop();
        }

        if (nc > 0)
        {
            safe.PushSequence();
            byte[] contents = certBags.Encode();
            if (options.EncryptCertificates)
            {
                byte[] ct = Pbe.EncryptPbes2(contents, password, options.Encryption, out byte[] alg);
                safe.WriteObjectIdentifier(EncryptedDataOid);
                safe.PushConstructed(Asn1Tag.Context(0, true));
                safe.PushSequence();
                safe.WriteInteger(0);
                safe.PushSequence();
                safe.WriteObjectIdentifier(DataOid);
                safe.WriteEncodedValue(alg);
                safe.WriteOctetString(ct, Asn1Tag.Context(0));
                safe.Pop();
                safe.Pop();
                safe.Pop();
            }
            else
            {
                safe.WriteObjectIdentifier(DataOid);
                safe.PushConstructed(Asn1Tag.Context(0, true));
                safe.WriteOctetString(contents);
                safe.Pop();
            }

            safe.Pop();
        }

        safe.Pop();
        byte[] authSafe = safe.Encode();

        var pfx = new Asn1Writer();
        pfx.PushSequence();
        pfx.WriteInteger(3);
        pfx.PushSequence();
        pfx.WriteObjectIdentifier(DataOid);
        pfx.PushConstructed(Asn1Tag.Context(0, true));
        pfx.WriteOctetString(authSafe);
        pfx.Pop();
        pfx.Pop();
        if (options.Mac != Pkcs12MacKind.None)
        {
            WriteMac(pfx, authSafe, password, options);
        }

        pfx.Pop();
        return Parse(pfx.Encode());
    }

    /// <summary>
    /// Writes the usual file: a private key (shrouded), its certificate and any chain certificates. The key and the first
    /// certificate share a localKeyId (the SHA-1 of the certificate, which is what other tools write).
    /// </summary>
    public static Pkcs12File Create(PrivateKeyInfo key, Certificate certificate, IEnumerable<Certificate>? chain, ReadOnlySpan<char> password, string? friendlyName = null, Pkcs12WriteOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(certificate);
        byte[] id = LegacyCrypto.Sha1(certificate.Encoded.Span);
        var bags = new List<Pkcs12Bag>
        {
            Pkcs12Bag.ForPrivateKey(key, friendlyName, id),
            Pkcs12Bag.ForCertificate(certificate, friendlyName, id),
        };
        if (chain is not null)
        {
            bags.AddRange(chain.Select(c => Pkcs12Bag.ForCertificate(c)));
        }

        return Create(bags, password, options);
    }

    private static void WriteBag(Asn1Writer w, Pkcs12Bag b, ReadOnlySpan<char> password, Pkcs12WriteOptions options)
    {
        w.PushSequence();
        w.WriteObjectIdentifier(b.BagId);
        w.PushConstructed(Asn1Tag.Context(0, true));
        switch (b.Kind)
        {
            case Pkcs12BagKind.Key:
                w.WriteEncodedValue(b.PrivateKey!.Encoded);
                break;
            case Pkcs12BagKind.ShroudedKey:
                w.WriteEncodedValue(EncryptedPrivateKeyInfo.Create(b.PrivateKey!, password, options.Encryption).Encoded.Span);
                break;
            case Pkcs12BagKind.Certificate:
                w.PushSequence();
                w.WriteObjectIdentifier("1.2.840.113549.1.9.22.1");
                w.PushConstructed(Asn1Tag.Context(0, true));
                w.WriteOctetString(b.Certificate!.Encoded.Span);
                w.Pop();
                w.Pop();
                break;
            case Pkcs12BagKind.Crl:
                w.PushSequence();
                w.WriteObjectIdentifier("1.2.840.113549.1.9.23.1");
                w.PushConstructed(Asn1Tag.Context(0, true));
                w.WriteOctetString(b.Value.Span);
                w.Pop();
                w.Pop();
                break;
            default:
                w.PushSequence();
                w.WriteObjectIdentifier(b.SecretTypeId!);
                w.PushConstructed(Asn1Tag.Context(0, true));
                w.WriteEncodedValue(b.SecretValue);
                w.Pop();
                w.Pop();
                break;
        }

        w.Pop();
        if (b.Attributes.Count > 0)
        {
            w.PushSetOf();
            foreach (Pkcs12BagAttr a in b.Attributes)
            {
                w.PushSequence();
                w.WriteObjectIdentifier(a.Oid);
                w.PushSetOf();
                foreach (ReadOnlyMemory<byte> v in a.Values)
                {
                    w.WriteEncodedValue(v.Span);
                }

                w.Pop();
                w.Pop();
            }

            w.Pop();
        }

        w.Pop();
    }

    private static void WriteMac(Asn1Writer pfx, byte[] authSafe, ReadOnlySpan<char> password, Pkcs12WriteOptions o)
    {
        string hash = o.MacHash.Name ?? "SHA256";
        string hashOid = Pbe.HashToOid(hash) ?? throw new ArgumentOutOfRangeException(nameof(o), "The MAC hash must be SHA-1, SHA-256, SHA-384 or SHA-512.");
        if (o.MacIterations < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(o), "MacIterations must be positive.");
        }

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        pfx.PushSequence();
        pfx.PushSequence();
        if (o.Mac == Pkcs12MacKind.Pkcs12)
        {
            using PinnedSecret pw = Pbe.Bmp(password, false);
            using var key = new PinnedSecret(HashLen(o.MacHash));
            Pbe.Pkcs12Kdf(o.MacHash, 3, pw.ReadOnlySpan, salt, o.MacIterations, key.Span);
            byte[] digest = CryptographicOperations.HmacData(o.MacHash, key.ReadOnlySpan, authSafe);
            pfx.PushSequence();
            pfx.WriteObjectIdentifier(hashOid);
            pfx.WriteNull();
            pfx.Pop();
            pfx.WriteOctetString(digest);
            pfx.Pop();
            pfx.WriteOctetString(salt);
            pfx.WriteInteger(o.MacIterations);
        }
        else
        {
            // RFC 9579 §3: the PBKDF2 parameters live inside the algorithm identifier; macSalt and iterations are present for the old syntax.
            using PinnedSecret pw = Pbe.Utf8(password);
            int keyLen = HashLen(o.MacHash);
            using var key = new PinnedSecret(keyLen);
            Rfc2898DeriveBytes.Pbkdf2(pw.ReadOnlySpan, salt, key.Span, o.MacIterations, o.MacHash);
            byte[] digest = CryptographicOperations.HmacData(o.MacHash, key.ReadOnlySpan, authSafe);
            pfx.PushSequence();
            pfx.WriteObjectIdentifier(Pbe.Pbmac1);
            pfx.PushSequence();
            pfx.PushSequence();
            pfx.WriteObjectIdentifier(Pbe.Pbkdf2Oid);
            pfx.PushSequence();
            pfx.WriteOctetString(salt);
            pfx.WriteInteger(o.MacIterations);
            pfx.WriteInteger(keyLen);
            pfx.PushSequence();
            pfx.WriteObjectIdentifier(Pbe.HmacOid(hash));
            pfx.WriteNull();
            pfx.Pop();
            pfx.Pop();
            pfx.Pop();
            pfx.PushSequence();
            pfx.WriteObjectIdentifier(Pbe.HmacOid(hash));
            pfx.WriteNull();
            pfx.Pop();
            pfx.Pop();
            pfx.Pop();
            pfx.WriteOctetString(digest);
            pfx.Pop();
            pfx.WriteOctetString(salt);
            pfx.WriteInteger(1);
        }

        pfx.Pop();
    }
}
