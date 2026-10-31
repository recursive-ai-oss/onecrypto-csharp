using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.Pkcs;
using RecursiveAI.OneCrypto.Wire.Ssh;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// The decision table behind <see cref="Crypto.Load(ReadOnlySpan{byte}, Func{string, string?}?)"/>. It looks at the first bytes, the PEM
/// labels and the outline of the ASN.1 structure, picks one parser, and calls it; it never tries several parsers and keeps the one that
/// did not throw. Each parser is the one the format's own type already has.
/// </summary>
internal sealed class CryptoLoader
{
    private enum Kind
    {
        Certificate,
        TrustedCertificate,
        Crl,
        Csr,
        Ocsp,
        SubjectPublicKey,
        RsaPublicKey,
        Pkcs8,
        Pkcs8Encrypted,
        RsaPrivateKey,
        EcPrivateKey,
        DsaPrivateKey,
        Pkcs12,
        CmsCertificates,
        SshPrivate,
        SshPublicBlob,
        AttributeCertificate,
        Ignored,
    }

    private static readonly byte[] SshKeyMagic = "openssh-key-v1\0"u8.ToArray();

    private readonly Func<string, string?>? _callback;
    private readonly PkcsLimits _limits;
    private readonly List<string> _known = [];
    private readonly List<Certificate> _certs = [];
    private readonly List<CertificateRevocationList> _crls = [];
    private readonly List<CertificateSigningRequest> _csrs = [];
    private readonly List<OcspResponse> _ocsp = [];
    private readonly List<PublicKeyInfo> _pubs = [];
    private readonly List<LoadedPrivateKey> _keys = [];
    private readonly List<SshPublicKey> _sshPubs = [];
    private readonly List<SshCertificate> _sshCerts = [];
    private string _format = "";

    public CryptoLoader(Func<string, string?>? callback, PkcsLimits? limits)
    {
        _callback = callback;
        _limits = limits ?? PkcsLimits.Default;
    }

    public static LoadedItems Run(ReadOnlySpan<byte> data, Func<string, string?>? callback, PkcsLimits? limits = null)
    {
        var loader = new CryptoLoader(callback, limits);
        try
        {
            loader.Dispatch(data);
            return new LoadedItems(loader._format, loader._certs, loader._crls, loader._csrs, loader._ocsp, loader._pubs, loader._keys, loader._sshPubs, loader._sshCerts);
        }
        catch
        {
            // A failed load returns nothing, so keys that were already made are released here.
            foreach (LoadedPrivateKey k in loader._keys)
            {
                k.Dispose();
            }

            throw;
        }
    }

    // ---- top level ----

    private void Dispatch(ReadOnlySpan<byte> data)
    {
        if (data.Length > _limits.MaxEncodedSize)
        {
            throw new CryptoLoadException(CryptoLoadError.LimitExceeded, $"The input is {data.Length} bytes; the limit is {_limits.MaxEncodedSize}.");
        }

        if (data.StartsWith("\uFEFF"u8))
        {
            data = data[3..];
        }

        int start = 0;
        while (start < data.Length && IsSpace(data[start]))
        {
            start++;
        }

        if (start == data.Length)
        {
            throw new CryptoLoadException(CryptoLoadError.Empty, "The input is empty.");
        }

        // Binary forms are told by their first byte, with no leading white space: 0x30 is the SEQUENCE every DER/BER structure here
        // starts with (RFC 5280 §4.1, RFC 5208 §5, RFC 7292 §4, RFC 6960 §4.2.1, RFC 2315 §7); the OpenSSH key magic and a wire blob
        // start with a length or a name, not text a person would write first.
        ReadOnlySpan<byte> trimmed = data[start..];
        if (data[0] == 0x30)
        {
            LoadDer(data);
        }
        else if (trimmed.StartsWith(SshKeyMagic))
        {
            _format = "OpenSSH private key (binary)";
            Item(Kind.SshPrivate, trimmed.ToArray(), "OpenSSH private key");
        }
        else if (data[0] == 0 && LooksLikeSshBlob(data))
        {
            _format = "OpenSSH public key blob";
            Item(Kind.SshPublicBlob, data.ToArray(), "OpenSSH public key blob");
        }
        else
        {
            LoadText(data);
        }
    }

    private static bool IsSpace(byte b) => b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';

    private static bool LooksLikeSshBlob(ReadOnlySpan<byte> d)
    {
        // RFC 4253 §6.6: a string holding the key type name, then the key fields.
        if (d.Length < 8 || d[0] != 0 || d[1] != 0 || d[2] != 0 || d[3] is 0 or > 64 || d.Length < 4 + d[3])
        {
            return false;
        }

        ReadOnlySpan<byte> name = d.Slice(4, d[3]);
        return name.StartsWith("ssh-"u8) || name.StartsWith("ecdsa-sha2-"u8) || name.StartsWith("sk-"u8);
    }

    // ---- binary ----

    private void LoadDer(ReadOnlySpan<byte> data)
    {
        var tried = new List<CryptoLoadAttempt> { new("PEM", "the input starts with 0x30, so it is binary ASN.1, not text") };
        var r = new Asn1Reader(data, Asn1Rules.Ber, _limits.Asn1);
        if (!r.TryReadEncodedValue(out ReadOnlySpan<byte> one))
        {
            tried.Add(new("DER/BER", $"starts like a SEQUENCE but is not a complete element: {r.LastFailure}"));
            throw new CryptoLoadException(CryptoLoadError.Malformed, "The input looks like DER/BER but is truncated or malformed.", tried);
        }

        for (int i = one.Length; i < data.Length; i++)
        {
            if (!IsSpace(data[i]) && data[i] != 0)
            {
                tried.Add(new("DER/BER", $"{data.Length - one.Length} bytes of data follow the first element; one file holds one element"));
                throw new CryptoLoadException(CryptoLoadError.Malformed, "The input has data after the first ASN.1 element.", tried);
            }
        }

        Kind kind = ClassifyDer(one, _limits.Asn1, out string why);
        if (kind == Kind.Ignored)
        {
            tried.Add(new("DER/BER", why));
            throw new CryptoLoadException(CryptoLoadError.Unrecognized, "The input is ASN.1 but not a structure this loader reads: " + why, tried);
        }

        _format = FormatName(kind, "DER");
        Item(kind, one.ToArray(), FormatName(kind, "DER"));
    }

    private static string FormatName(Kind kind, string container) => kind switch
    {
        Kind.Certificate or Kind.TrustedCertificate => container + " certificate",
        Kind.Crl => container + " CRL",
        Kind.Csr => container + " certification request",
        Kind.Ocsp => container + " OCSP response",
        Kind.SubjectPublicKey or Kind.RsaPublicKey => container + " public key",
        Kind.Pkcs8 or Kind.RsaPrivateKey or Kind.EcPrivateKey or Kind.DsaPrivateKey => container + " private key",
        Kind.Pkcs8Encrypted => container + " encrypted private key",
        Kind.Pkcs12 => "PKCS#12",
        Kind.CmsCertificates => "PKCS#7 certificate bag",
        _ => container,
    };

    /// <summary>
    /// Decides what a DER/BER element is from the tags of its outline. The rules, in order (X is the outer SEQUENCE, c0, c1 … its children):
    /// <list type="number">
    /// <item>c0 is a SEQUENCE and X has three children ending in a BIT STRING: a signed structure. The first child of c0 decides:
    /// <c>[0]</c> is a Certificate (RFC 5280 §4.1, version field); an INTEGER followed by a SEQUENCE whose first child is an OID is a
    /// Certificate (v1) or a CRL (v2), told by the fourth child (SEQUENCE validity, or a time); an INTEGER followed by a SEQUENCE whose
    /// first child is a SET or nothing is a certification request (RFC 2986 §4.1); an INTEGER followed by a SEQUENCE with a context-tagged
    /// first child is an attribute certificate; a SEQUENCE is a v1 CRL (RFC 5280 §5.1).</item>
    /// <item>c0 is an ENUMERATED: an OCSPResponse (RFC 6960 §4.2.1).</item>
    /// <item>c0 is an INTEGER: c1 a SEQUENCE with a <c>[0]</c> second child is a PFX (RFC 7292 §4); c1 a SEQUENCE and c2 an OCTET STRING is
    /// PKCS#8 (RFC 5958 §2); c1 an OCTET STRING is an ECPrivateKey (RFC 5915 §3); c1 an INTEGER: two children are an RSAPublicKey (RFC 8017
    /// A.1.1), nine or more an RSAPrivateKey (A.1.2), six a DSA private key.</item>
    /// <item>c0 a SEQUENCE and two children: a BIT STRING second is a SubjectPublicKeyInfo (RFC 5280 §4.1); an OCTET STRING second is an
    /// EncryptedPrivateKeyInfo (RFC 5958 §3).</item>
    /// <item>c0 an OBJECT IDENTIFIER and c1 <c>[0]</c>: a CMS ContentInfo (RFC 5652 §3); only SignedData is read.</item>
    /// </list>
    /// </summary>
    private static Kind ClassifyDer(ReadOnlySpan<byte> element, Asn1Limits limits, out string why)
    {
        why = "";
        var outer = new Asn1Reader(element, Asn1Rules.Ber, limits);
        if (!outer.TryReadSequence(out Asn1Reader x))
        {
            why = "the outer element is not a SEQUENCE";
            return Kind.Ignored;
        }

        // The outline: the tag of each child (up to 16) and the number of children (up to 64).
        var tags = new Asn1Tag[16];
        int n = 0;
        Asn1Reader c1Reader = default;
        Asn1Reader c0Reader = default;
        while (x.HasData && n < 64)
        {
            if (!x.TryPeekTag(out Asn1Tag t))
            {
                why = "malformed child element";
                return Kind.Ignored;
            }

            if (n < 16)
            {
                tags[n] = t;
            }

            if (n == 0)
            {
                c0Reader = x;
            }
            else if (n == 1)
            {
                c1Reader = x;
            }

            if (!x.TrySkipValue())
            {
                why = "malformed child element";
                return Kind.Ignored;
            }

            n++;
        }

        if (n == 0)
        {
            why = "the outer SEQUENCE is empty";
            return Kind.Ignored;
        }

        Asn1Tag c0 = tags[0];
        bool c0Seq = c0 == Asn1Tag.Sequence;
        Asn1Tag c1 = n > 1 ? tags[1] : default;
        bool c1Seq = n > 1 && c1 == Asn1Tag.Sequence;
        Asn1Tag last = tags[Math.Min(n, 16) - 1];

        if (c0Seq && n == 3 && last.TagClass == Asn1TagClass.Universal && last.TagNumber == Asn1Tags.BitString && c1Seq)
        {
            return ClassifySigned(c0Reader, ref why);
        }

        if (c0.TagClass == Asn1TagClass.Universal && c0.TagNumber == Asn1Tags.Enumerated && n <= 2)
        {
            return Kind.Ocsp;
        }

        if (c0.TagClass == Asn1TagClass.Universal && c0.TagNumber == Asn1Tags.IntegerType && n >= 2)
        {
            if (c1Seq)
            {
                Asn1Reader seq = c1Reader;
                if (seq.TryReadSequence(out Asn1Reader inner))
                {
                    inner.TrySkipValue();
                    if (inner.TryPeekTag(out Asn1Tag second) && second.TagClass == Asn1TagClass.ContextSpecific && second.TagNumber == 0)
                    {
                        return Kind.Pkcs12;
                    }
                }

                if (n >= 3 && tags[2].TagClass == Asn1TagClass.Universal && tags[2].TagNumber == Asn1Tags.OctetString)
                {
                    return Kind.Pkcs8;
                }

                why = "an INTEGER and an algorithm SEQUENCE that is neither a PFX (no [0] content) nor a PrivateKeyInfo (no OCTET STRING key)";
                return Kind.Ignored;
            }

            if (c1.TagClass == Asn1TagClass.Universal && c1.TagNumber == Asn1Tags.OctetString)
            {
                return Kind.EcPrivateKey;
            }

            if (c1.TagClass == Asn1TagClass.Universal && c1.TagNumber == Asn1Tags.IntegerType)
            {
                if (n == 2)
                {
                    return Kind.RsaPublicKey;
                }

                if (n >= 9)
                {
                    return Kind.RsaPrivateKey;
                }

                if (n == 6)
                {
                    return Kind.DsaPrivateKey;
                }
            }

            why = $"a SEQUENCE of {n} elements starting with an INTEGER matches no key or container layout";
            return Kind.Ignored;
        }

        if (c0Seq && n == 2 && tags[1].TagClass == Asn1TagClass.Universal)
        {
            if (tags[1].TagNumber == Asn1Tags.BitString)
            {
                return Kind.SubjectPublicKey;
            }

            if (tags[1].TagNumber == Asn1Tags.OctetString)
            {
                return Kind.Pkcs8Encrypted;
            }
        }

        if (c0.TagClass == Asn1TagClass.Universal && c0.TagNumber == Asn1Tags.ObjectIdentifier && n == 2 && c1.TagClass == Asn1TagClass.ContextSpecific && c1.TagNumber == 0)
        {
            return Kind.CmsCertificates;
        }

        why = $"a SEQUENCE of {n} elements (first tag {c0}) matches no certificate, CRL, request, key or container layout";
        return Kind.Ignored;
    }

    private static Kind ClassifySigned(Asn1Reader tbsHolder, ref string why)
    {
        if (!tbsHolder.TryReadSequence(out Asn1Reader tbs) || !tbs.TryPeekTag(out Asn1Tag t0))
        {
            why = "the signed part is empty or malformed";
            return Kind.Ignored;
        }

        if (t0.TagClass == Asn1TagClass.ContextSpecific && t0.TagNumber == 0)
        {
            return Kind.Certificate;
        }

        if (t0 == Asn1Tag.Sequence)
        {
            return Kind.Crl;
        }

        if (t0.TagClass == Asn1TagClass.Universal && t0.TagNumber == Asn1Tags.IntegerType)
        {
            tbs.TrySkipValue();
            if (tbs.TryPeekTag(out Asn1Tag t1) && t1 == Asn1Tag.Sequence)
            {
                Asn1Reader copy = tbs;
                if (copy.TryReadSequence(out Asn1Reader second))
                {
                    if (!second.TryPeekTag(out Asn1Tag s0))
                    {
                        return Kind.Csr; // an empty subject name, RFC 2986 §4.1
                    }

                    if (s0.TagClass == Asn1TagClass.Universal && s0.TagNumber == Asn1Tags.ObjectIdentifier)
                    {
                        tbs.TrySkipValue(); // signature algorithm
                        tbs.TrySkipValue(); // issuer
                        if (tbs.TryPeekTag(out Asn1Tag t3))
                        {
                            bool time = t3.TagClass == Asn1TagClass.Universal && t3.TagNumber is Asn1Tags.UtcTime or Asn1Tags.GeneralizedTime;
                            return time ? Kind.Crl : Kind.Certificate;
                        }

                        why = "a signed structure that ends after the issuer name";
                        return Kind.Ignored;
                    }

                    if (s0.TagClass == Asn1TagClass.ContextSpecific)
                    {
                        return Kind.AttributeCertificate;
                    }

                    return Kind.Csr;
                }
            }
        }

        why = "a three-part signed structure that is not a certificate, CRL or request";
        return Kind.Ignored;
    }

    // ---- text ----

    private void LoadText(ReadOnlySpan<byte> data)
    {
        string text = Encoding.UTF8.GetString(data);
        var tried = new List<CryptoLoadAttempt> { new("DER/BER", "the first byte is not 0x30 (SEQUENCE), so the input is text") };

        if (text.Contains("-----BEGIN ", StringComparison.Ordinal))
        {
            LoadPem(text);
            return;
        }

        tried.Add(new("PEM", "no line starts with -----BEGIN"));
        if (text.Contains("---- BEGIN SSH2 PUBLIC KEY ----", StringComparison.Ordinal))
        {
            _format = "RFC 4716 public key";
            try
            {
                _sshPubs.Add(SshPublicKey.ParseRfc4716(text));
                return;
            }
            catch (SshParseException ex)
            {
                tried.Add(new("RFC 4716 public key", ex.Message));
                throw new CryptoLoadException(Map(ex.Error), "The RFC 4716 public key is malformed: " + ex.Message, tried, ex);
            }
        }

        tried.Add(new("RFC 4716 public key", "no ---- BEGIN SSH2 PUBLIC KEY ---- line"));
        _format = "authorized_keys";
        int lineNo = 0;
        foreach (string raw in text.Split('\n'))
        {
            lineNo++;
            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            try
            {
                if (line.Contains("-cert-v01@openssh.com", StringComparison.Ordinal))
                {
                    _sshCerts.Add(SshCertificate.ParseLine(line));
                }
                else
                {
                    _sshPubs.Add(SshPublicKey.ParseAuthorizedKey(line));
                }
            }
            catch (SshParseException ex)
            {
                tried.Add(new("authorized_keys", $"line {lineNo}: {ex.Message}"));
                throw new CryptoLoadException(lineNo == 1 && _sshPubs.Count + _sshCerts.Count == 0 ? CryptoLoadError.Unrecognized : Map(ex.Error), $"Line {lineNo} is not an OpenSSH public key or certificate: {ex.Message}", tried, ex);
            }
            catch (FormatException ex)
            {
                tried.Add(new("authorized_keys", $"line {lineNo}: {ex.Message}"));
                throw new CryptoLoadException(lineNo == 1 && _sshPubs.Count + _sshCerts.Count == 0 ? CryptoLoadError.Unrecognized : CryptoLoadError.Malformed, $"Line {lineNo} is not an OpenSSH public key or certificate.", tried, ex);
            }
        }

        if (_sshPubs.Count + _sshCerts.Count == 0)
        {
            tried.Add(new("authorized_keys", "no key lines"));
            throw new CryptoLoadException(CryptoLoadError.Unrecognized, "The input is not a recognised key or certificate format.", tried);
        }
    }

    private void LoadPem(string text)
    {
        if (!PemCodec.TryParseAll(text, PemMode.Lax, out IReadOnlyList<PemBlock> blocks, out PemError error) || blocks.Count == 0)
        {
            throw new CryptoLoadException(CryptoLoadError.Malformed, $"The PEM text is malformed ({error}).", [new("PEM", error.ToString())]);
        }

        _format = "PEM";
        int index = 0;
        foreach (PemBlock b in blocks)
        {
            index++;
            Kind kind = KindOfLabel(b.Label);
            string what = $"PEM block {index} ({b.Label})";
            if (kind == Kind.Ignored)
            {
                if (IgnoredLabel(b.Label))
                {
                    continue;
                }

                string reason = b.Label.StartsWith("PGP ", StringComparison.Ordinal)
                    ? "OpenPGP armor is not read by Crypto.Load"
                    : $"the label {b.Label} is not one the loader reads";
                throw new CryptoLoadException(CryptoLoadError.Unrecognized, $"{what}: {reason}.", [new("PEM", $"block {index}: {reason}")]);
            }

            Item(kind, b.Data, what, b);
        }
    }

    private static bool IgnoredLabel(string label) => label is "EC PARAMETERS" or "DH PARAMETERS" or "DSA PARAMETERS" or "X9.42 DH PARAMETERS" or "PARAMETERS";

    private static Kind KindOfLabel(string label) => label switch
    {
        "CERTIFICATE" or "X509 CERTIFICATE" => Kind.Certificate,
        "TRUSTED CERTIFICATE" => Kind.TrustedCertificate,
        "X509 CRL" => Kind.Crl,
        "CERTIFICATE REQUEST" or "NEW CERTIFICATE REQUEST" => Kind.Csr,
        "OCSP RESPONSE" => Kind.Ocsp,
        "PUBLIC KEY" => Kind.SubjectPublicKey,
        "RSA PUBLIC KEY" => Kind.RsaPublicKey,
        "PRIVATE KEY" => Kind.Pkcs8,
        "ENCRYPTED PRIVATE KEY" => Kind.Pkcs8Encrypted,
        "RSA PRIVATE KEY" => Kind.RsaPrivateKey,
        "EC PRIVATE KEY" => Kind.EcPrivateKey,
        "DSA PRIVATE KEY" => Kind.DsaPrivateKey,
        "OPENSSH PRIVATE KEY" => Kind.SshPrivate,
        "PKCS7" or "CMS" => Kind.CmsCertificates,
        "ATTRIBUTE CERTIFICATE" => Kind.AttributeCertificate,
        _ => Kind.Ignored,
    };

    // ---- one item ----

    private void Item(Kind kind, byte[] data, string what, PemBlock? pem = null)
    {
        try
        {
            switch (kind)
            {
                case Kind.Certificate:
                    _certs.Add(Certificate.Parse((ReadOnlyMemory<byte>)data));
                    break;
                case Kind.TrustedCertificate:
                    // OpenSSL's TRUSTED CERTIFICATE appends trust settings after the certificate (x509 -trustout); the certificate is the first element.
                    _certs.Add(Certificate.Parse((ReadOnlyMemory<byte>)FirstElement(data, _limits.Asn1)));
                    break;
                case Kind.Crl:
                    _crls.Add(CertificateRevocationList.Parse((ReadOnlyMemory<byte>)data));
                    break;
                case Kind.Csr:
                    _csrs.Add(CertificateSigningRequest.Parse((ReadOnlyMemory<byte>)data));
                    break;
                case Kind.Ocsp:
                    _ocsp.Add(OcspResponse.Parse((ReadOnlyMemory<byte>)data));
                    break;
                case Kind.SubjectPublicKey:
                    _pubs.Add(PublicKeyInfo.Parse((ReadOnlyMemory<byte>)data));
                    break;
                case Kind.RsaPublicKey:
                    _pubs.Add(PublicKeyInfo.Parse((ReadOnlyMemory<byte>)RsaPublicToSpki(data, _limits.Asn1)));
                    break;
                case Kind.CmsCertificates:
                    CmsCertificates(data);
                    break;
                case Kind.AttributeCertificate:
                    throw new CryptoLoadException(CryptoLoadError.Unsupported, $"{what}: attribute certificates are not loaded here; use AttributeCertificate.Parse.", [new(what, "attribute certificate")]);
                case Kind.SshPublicBlob:
                    if (SshPublicKey.TryParse(data, out SshPublicKey? pk))
                    {
                        _sshPubs.Add(pk!);
                    }
                    else
                    {
                        _sshCerts.Add(SshCertificate.Parse(data));
                    }

                    break;
                case Kind.Pkcs12:
                    Pkcs12(data, what);
                    break;
                case Kind.SshPrivate:
                    SshPrivate(data, what);
                    break;
                default:
                    PrivateKey(kind, data, what, pem);
                    break;
            }
        }
        catch (CryptoLoadException)
        {
            throw;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or NotSupportedException)
        {
            CryptoLoadError e = ex switch
            {
                X509ParseException { Error: X509Error.LimitExceeded } or PkcsParseException { Error: PkcsError.LimitExceeded } => CryptoLoadError.LimitExceeded,
                PkcsParseException { Error: PkcsError.Unsupported } => CryptoLoadError.Unsupported,
                SshParseException s => Map(s.Error),
                NotSupportedException => CryptoLoadError.Unsupported,
                _ => CryptoLoadError.Malformed,
            };
            throw new CryptoLoadException(e, $"{what}: {ex.Message}", [new(what, ex.Message)], ex);
        }
    }

    private static CryptoLoadError Map(SshError e) => e switch
    {
        SshError.Unsupported => CryptoLoadError.Unsupported,
        SshError.LimitExceeded => CryptoLoadError.LimitExceeded,
        _ => CryptoLoadError.Malformed,
    };

    private static byte[] FirstElement(byte[] data, Asn1Limits limits)
    {
        var r = new Asn1Reader(data, Asn1Rules.Ber, limits);
        return r.ReadEncodedValue().ToArray();
    }

    private static byte[] RsaPublicToSpki(byte[] pkcs1, Asn1Limits limits)
    {
        // RFC 8017 A.1.1: RSAPublicKey is SEQUENCE { modulus, publicExponent }; RFC 3279 §2.3.1 wraps it with rsaEncryption and NULL.
        var r = new Asn1Reader(pkcs1, Asn1Rules.Ber, limits);
        Asn1Reader s = r.ReadSequence();
        r.ThrowIfNotEmpty();
        s.ReadIntegerBytes();
        s.ReadIntegerBytes();
        s.ThrowIfNotEmpty();
        var w = new Asn1Writer();
        w.PushSequence();
        w.PushSequence();
        w.WriteObjectIdentifier("1.2.840.113549.1.1.1");
        w.WriteNull();
        w.Pop();
        w.WriteBitString(pkcs1);
        w.Pop();
        return w.Encode();
    }

    private void CmsCertificates(byte[] data)
    {
        // RFC 2315 §9 / RFC 5652 §5: a certificate bag is a SignedData with no signers and no content.
        ContentInfo ci = ContentInfo.Parse(data);
        if (ci.ContentType != "1.2.840.113549.1.7.2")
        {
            throw new CryptoLoadException(CryptoLoadError.Unsupported, $"The CMS content type {ci.ContentType} holds no certificates; only SignedData certificate bags are loaded.", [new("PKCS#7", $"content type {ci.ContentType}")]);
        }

        SignedData sd = SignedData.Parse(data);
        if (sd.Signers.Count != 0 || sd.HasEncapsulatedContent)
        {
            throw new CryptoLoadException(CryptoLoadError.Unsupported, "The SignedData carries signatures or content; open it with the CMS API. Only certificate bags are loaded.", [new("PKCS#7", "not a certificates-only SignedData")]);
        }

        _certs.AddRange(sd.Certificates);
        _crls.AddRange(sd.Crls);
    }

    // ---- passwords ----

    private PkcsStatus WithPasswords(string what, bool tryEmpty, Func<string, PkcsStatus> attempt)
    {
        foreach (string p in _known)
        {
            PkcsStatus st = attempt(p);
            if (st != PkcsStatus.WrongPasswordOrCorrupt)
            {
                return st;
            }
        }

        if (_callback is not null)
        {
            string? p = _callback(what);
            if (p is not null)
            {
                if (_known.Contains(p))
                {
                    return PkcsStatus.WrongPasswordOrCorrupt;
                }

                PkcsStatus st = attempt(p);
                if (st == PkcsStatus.Ok)
                {
                    _known.Add(p);
                }

                return st;
            }
        }

        if (tryEmpty && !_known.Contains(string.Empty))
        {
            PkcsStatus st = attempt(string.Empty);
            if (st != PkcsStatus.WrongPasswordOrCorrupt)
            {
                return st;
            }
        }

        return PkcsStatus.PasswordRequired;
    }

    private static CryptoLoadException StatusFailure(PkcsStatus st, string what)
    {
        (CryptoLoadError e, string msg) = st switch
        {
            PkcsStatus.PasswordRequired => (CryptoLoadError.PasswordRequired, "is encrypted and no password was supplied"),
            PkcsStatus.WrongPasswordOrCorrupt => (CryptoLoadError.WrongPasswordOrCorrupt, "the password is wrong or the data is damaged"),
            PkcsStatus.UnsupportedAlgorithm => (CryptoLoadError.Unsupported, "uses an algorithm that is not supported"),
            PkcsStatus.LimitExceeded => (CryptoLoadError.LimitExceeded, "asks for more work than the limits allow"),
            PkcsStatus.IntegrityMissing => (CryptoLoadError.Unsupported, "has no integrity MAC, which the loader requires"),
            _ => (CryptoLoadError.Malformed, "is malformed"),
        };
        return new CryptoLoadException(e, $"{what}: {msg}.", [new(what, msg)]);
    }

    // ---- private keys ----

    private void PrivateKey(Kind kind, byte[] data, string what, PemBlock? pem)
    {
        PrivateKeyInfo? info = null;
        try
        {
            if (pem is not null && pem.IsLegacyEncrypted)
            {
                string text = pem.ToString();
                PkcsStatus st = WithPasswords(what, false, p => PrivateKeyPem.TryParse(text, p, out info, _limits));
                if (st != PkcsStatus.Ok)
                {
                    throw StatusFailure(st, what);
                }
            }
            else if (kind == Kind.Pkcs8Encrypted)
            {
                EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfo.Parse(data, _limits);
                PkcsStatus st = WithPasswords(what, false, p => enc.TryDecrypt(p, out info));
                if (st != PkcsStatus.Ok)
                {
                    throw StatusFailure(st, what);
                }
            }
            else
            {
                info = kind switch
                {
                    Kind.Pkcs8 => PrivateKeyInfo.Parse(data, _limits),
                    Kind.RsaPrivateKey => PrivateKeyInfo.FromRsaPrivateKey(data),
                    Kind.DsaPrivateKey => PrivateKeyInfo.FromDsaPrivateKey(data),
                    _ => PrivateKeyInfo.FromEcPrivateKey(data),
                };
            }

            _keys.Add(MakeKey(info!, what));
            info = null; // owned by the LoadedPrivateKey now
        }
        finally
        {
            info?.Dispose();
        }
    }

    private static LoadedPrivateKey MakeKey(PrivateKeyInfo info, string what)
    {
        var owned = new List<IDisposable>();
        ISigningKey? signing = null;
        IDecryptionKey? decryption = null;
        IAgreementKey? agreement = null;
        try
        {
            switch (info.KeyAlgorithm)
            {
                case KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss or KeyAlgorithm.RsaOaep:
                    IRsaKey rsa = Keys.PrivateKey.FromRsa(info.ToRsa(), ownsKey: true);
                    owned.Add(rsa);
                    signing = rsa;
                    decryption = rsa;
                    break;
                case KeyAlgorithm.EllipticCurve:
                    signing = Keys.PrivateKey.FromECDsa(info.ToECDsa(), ownsKey: true);
                    owned.Add(signing);
                    agreement = Keys.PrivateKey.FromECDiffieHellman(info.ToECDiffieHellman(), ownsKey: true);
                    owned.Add(agreement);
                    break;
                case KeyAlgorithm.Ed25519:
                    signing = Keys.PrivateKey.FromEd25519(info.ToEd25519(), ownsKey: true);
                    owned.Add(signing);
                    break;
                case KeyAlgorithm.Ed448:
                    signing = Keys.PrivateKey.FromEd448(info.ToEd448(), ownsKey: true);
                    owned.Add(signing);
                    break;
                case KeyAlgorithm.X25519:
                    agreement = Keys.PrivateKey.FromX25519(info.ToX25519(), ownsKey: true);
                    owned.Add(agreement);
                    break;
                case KeyAlgorithm.X448:
                    agreement = Keys.PrivateKey.FromX448(info.ToX448(), ownsKey: true);
                    owned.Add(agreement);
                    break;
                case KeyAlgorithm.MlDsa:
                    signing = Keys.PrivateKey.FromMLDsa(info.ToMLDsa(), ownsKey: true);
                    owned.Add(signing);
                    break;
                case KeyAlgorithm.MlKem:
                    decryption = Keys.PrivateKey.FromMLKem(info.ToMLKem(), ownsKey: true);
                    owned.Add(decryption);
                    break;
            }

            PublicKeyInfo? pub = null;
            try
            {
                pub = info.GetPublicKey();
            }
            catch (NotSupportedException)
            {
                // DSA and other algorithms with no public-key derivation here: the key is still returned, without PublicKey.
            }

            return new LoadedPrivateKey(info, pub, signing, decryption, agreement, owned);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or NotSupportedException)
        {
            foreach (IDisposable d in owned)
            {
                d.Dispose();
            }

            CryptoLoadError e = ex is NotSupportedException ? CryptoLoadError.Unsupported : CryptoLoadError.Malformed;
            throw new CryptoLoadException(e, $"{what}: {ex.Message}", [new(what, ex.Message)], ex);
        }
    }

    // ---- OpenSSH private keys ----

    private void SshPrivate(byte[] data, string what)
    {
        SshPrivateKey file = SshPrivateKey.Parse(data);

        string desc = $"{what} {file.PublicKey}";
        SshPrivateKeyContents? contents = null;
        PkcsStatus st = file.IsEncrypted
            ? WithPasswords(desc, false, p => file.TryOpen(p, out contents, _limits.Kdf))
            : file.TryOpen(string.Empty, out contents, _limits.Kdf);
        if (st != PkcsStatus.Ok)
        {
            throw StatusFailure(st, what);
        }

        try
        {
            if (contents!.PrivateKey is null)
            {
                // A FIDO key file holds a handle, not a key (PROTOCOL.u2f): its public key is what there is to load.
                _sshPubs.Add(contents.PublicKey);
                return;
            }

            // The pinned PKCS#8 copy moves into the loaded key; the contents then release their own.
            PrivateKeyInfo copy = PrivateKeyInfo.Parse(contents.PrivateKey.Encoded, _limits);
            LoadedPrivateKey key = MakeKey(copy, what);
            key.Comment = contents.Comment;
            key.SshPublicKey = contents.PublicKey;
            _keys.Add(key);
        }
        finally
        {
            contents!.Dispose();
        }
    }

    // ---- PKCS#12 ----

    private void Pkcs12(byte[] data, string what)
    {
        Pkcs12File file = Pkcs12File.Parse(data, _limits);
        Pkcs12Contents? contents = null;
        PkcsStatus st = WithPasswords(what, true, p => file.TryOpen(p, out contents));
        if (st != PkcsStatus.Ok)
        {
            throw StatusFailure(st, what);
        }

        try
        {
            foreach (Pkcs12Bag bag in contents!.AllBags())
            {
                switch (bag.Kind)
                {
                    case Pkcs12BagKind.Certificate when bag.Certificate is not null:
                        _certs.Add(bag.Certificate);
                        break;
                    case Pkcs12BagKind.Crl:
                        _crls.Add(CertificateRevocationList.Parse(bag.Value));
                        break;
                    case Pkcs12BagKind.Key or Pkcs12BagKind.ShroudedKey when bag.PrivateKey is not null:
                        LoadedPrivateKey key = MakeKey(PrivateKeyInfo.Parse(bag.PrivateKey.Encoded, _limits), what);
                        key.FriendlyName = bag.FriendlyName;
                        key.Certificate = contents.FindCertificateFor(bag)?.Certificate;
                        _keys.Add(key);
                        break;
                }
            }
        }
        finally
        {
            contents!.Dispose();
        }
    }
}
