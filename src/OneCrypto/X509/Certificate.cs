using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// An X.509 certificate (RFC 5280 §4.1). Immutable and lossless: it keeps the DER (or BER) it was read from, decodes the parts on first use,
/// and signature checks hash the received <c>tbsCertificate</c> octets, never a re-encoding. Certificates the platform's own
/// <c>X509Certificate2</c> cannot load (EdDSA, unknown algorithms, odd encodings) work here.
/// </summary>
public sealed class Certificate : IEquatable<Certificate>
{
    private readonly ReadOnlyMemory<byte> _tbs;
    private readonly ReadOnlyMemory<byte> _serial;
    private readonly ReadOnlyMemory<byte> _issuer;
    private readonly ReadOnlyMemory<byte> _subject;
    private readonly ReadOnlyMemory<byte> _spki;
    private readonly ReadOnlyMemory<byte> _extensions;
    private readonly ReadOnlyMemory<byte> _signature;
    private readonly X509Limits _limits;
    private AlgorithmIdentifier? _tbsAlg;
    private AlgorithmIdentifier? _outerAlg;
    private DistinguishedName? _issuerName;
    private DistinguishedName? _subjectName;
    private PublicKeyInfo? _publicKey;
    private ExtensionCollection? _extensionList;
    private readonly ReadOnlyMemory<byte> _tbsAlgEnc;
    private readonly ReadOnlyMemory<byte> _outerAlgEnc;

    private Certificate(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        _limits = limits;
        Encoded = encoded;
        try
        {
            var top = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader cert = top.ReadSequence();
            top.ThrowIfNotEmpty();
            ReadOnlySpan<byte> tbsEnc = cert.ReadEncodedValue();
            _tbs = X509Read.Slice(encoded, tbsEnc);
            ReadOnlySpan<byte> outerAlg = cert.ReadEncodedValue();
            _outerAlgEnc = X509Read.Algorithm(outerAlg, encoded, limits);
            ReadOnlySpan<byte> sig = cert.ReadBitString(out int unused);
            cert.ThrowIfNotEmpty();
            _signature = X509Read.Slice(encoded, sig);
            SignatureUnusedBits = unused;

            var tr = new Asn1Reader(tbsEnc, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader tbs = tr.ReadSequence();
            Version = 1;
            if (tbs.TryPeekTag(out Asn1Tag t) && t == Asn1Tag.Context(0))
            {
                Asn1Reader v = tbs.ReadSequence(Asn1Tag.Context(0, true));
                int ver = v.ReadInt32();
                v.ThrowIfNotEmpty();
                if (ver is < 0 or > 2)
                {
                    throw new X509ParseException("Certificate", X509Error.UnsupportedVersion, $"version {ver + 1} is not 1, 2 or 3");
                }

                Version = ver + 1;
            }

            _serial = X509Read.Slice(encoded, tbs.ReadIntegerBytes());
            if (_serial.Length > 64)
            {
                throw X509Read.Limit("Certificate", "serial number longer than 64 octets");
            }

            _tbsAlgEnc = X509Read.Algorithm(tbs.ReadEncodedValue(), encoded, limits);
            ReadOnlySpan<byte> issuer = tbs.ReadEncodedValue();
            DistinguishedName.Validate(issuer, limits);
            _issuer = X509Read.Slice(encoded, issuer);
            Asn1Reader validity = tbs.ReadSequence();
            NotBefore = validity.ReadTime();
            NotAfter = validity.ReadTime();
            validity.ThrowIfNotEmpty();
            ReadOnlySpan<byte> subject = tbs.ReadEncodedValue();
            DistinguishedName.Validate(subject, limits);
            _subject = X509Read.Slice(encoded, subject);
            PublicKeyInfo key = PublicKeyInfo.Read(ref tbs, encoded);
            _spki = key.Encoded;
            _publicKey = key;
            if (tbs.TryPeekTag(out t) && t == Asn1Tag.Context(1))
            {
                IssuerUniqueId = X509Read.Slice(encoded, tbs.ReadBitString(out _, Asn1Tag.Context(1)));
            }

            if (tbs.TryPeekTag(out t) && t == Asn1Tag.Context(2))
            {
                SubjectUniqueId = X509Read.Slice(encoded, tbs.ReadBitString(out _, Asn1Tag.Context(2)));
            }

            if (tbs.TryPeekTag(out t) && t == Asn1Tag.Context(3))
            {
                Asn1Reader w = tbs.ReadSequence(Asn1Tag.Context(3, true));
                ReadOnlySpan<byte> list = w.ReadEncodedValue();
                w.ThrowIfNotEmpty();
                ExtensionCollection.Validate(list, limits, "Certificate");
                _extensions = X509Read.Slice(encoded, list);
            }

            tbs.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("Certificate", e);
        }
    }

    /// <summary>The complete certificate exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The <c>tbsCertificate</c> element exactly as received: the octets the signature covers.</summary>
    public ReadOnlyMemory<byte> TbsCertificate => _tbs;

    /// <summary>The certificate version: 1, 2 or 3.</summary>
    public int Version { get; }

    /// <summary>The serial number as the content octets of the INTEGER (two's complement, big-endian).</summary>
    public ReadOnlyMemory<byte> SerialNumber => _serial;

    /// <summary>The serial number as a number. Public data, so <see cref="BigInteger"/> is fine here.</summary>
    public BigInteger SerialNumberValue => new(_serial.Span, isUnsigned: false, isBigEndian: true);

    /// <summary>The signature algorithm named inside <c>tbsCertificate</c>.</summary>
    public AlgorithmIdentifier TbsSignatureAlgorithm => _tbsAlg ??= AlgorithmIdentifier.Parse(_tbsAlgEnc);

    /// <summary>The signature algorithm named outside <c>tbsCertificate</c>; RFC 5280 §4.1.1.2 requires it to equal <see cref="TbsSignatureAlgorithm"/>.</summary>
    public AlgorithmIdentifier SignatureAlgorithm => _outerAlg ??= AlgorithmIdentifier.Parse(_outerAlgEnc);

    /// <summary>The signature value (the BIT STRING content).</summary>
    public ReadOnlyMemory<byte> Signature => _signature;

    /// <summary>Unused bits of the signature BIT STRING as received (0 for every signature the library knows).</summary>
    public int SignatureUnusedBits { get; }

    /// <summary>The issuer name.</summary>
    public DistinguishedName Issuer => _issuerName ??= DistinguishedName.Parse(_issuer, _limits);

    /// <summary>The subject name (empty when the subject is in the subjectAltName extension).</summary>
    public DistinguishedName Subject => _subjectName ??= DistinguishedName.Parse(_subject, _limits);

    /// <summary>The start of the validity period. UTCTime years 50 to 99 are read as 19xx (RFC 5280 §4.1.2.5.1).</summary>
    public DateTimeOffset NotBefore { get; }

    /// <summary>The end of the validity period.</summary>
    public DateTimeOffset NotAfter { get; }

    /// <summary>The subject's public key.</summary>
    public PublicKeyInfo PublicKey => _publicKey ??= PublicKeyInfo.Parse(_spki);

    /// <summary>The issuer unique identifier bits (version 2 and 3), or empty.</summary>
    public ReadOnlyMemory<byte> IssuerUniqueId { get; }

    /// <summary>The subject unique identifier bits (version 2 and 3), or empty.</summary>
    public ReadOnlyMemory<byte> SubjectUniqueId { get; }

    /// <summary>The extensions in encoded order; empty when the certificate has none. Unknown extensions are preserved.</summary>
    public ExtensionCollection Extensions => _extensionList ??= ExtensionCollection.Decode(_extensions, _limits, "Certificate");

    /// <summary>True when issuer and subject are the same name under RFC 5280 §7.1 (the definition of self-issued, §6.1).</summary>
    public bool IsSelfIssued => Issuer.Matches(Subject);

    /// <summary>True when the signature on this certificate verifies with its own public key.</summary>
    public bool IsSelfSigned => IsSelfIssued && VerifySignature(PublicKey).IsValid;

    /// <summary>True when the certificate was read from, or is, strictly DER (checked on demand).</summary>
    public bool IsDer
    {
        get
        {
            try
            {
                var r = new Asn1Reader(Encoded.Span, Asn1Rules.Der, _limits.Asn1);
                r.SkipValue();
                return !r.HasData;
            }
            catch (Asn1ParseException)
            {
                return false;
            }
        }
    }

    /// <summary>basicConstraints, or null when absent.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public BasicConstraints? BasicConstraints => Extensions.Get<BasicConstraints>();

    /// <summary>keyUsage, or null when absent.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public KeyUsageExtension? KeyUsage => Extensions.Get<KeyUsageExtension>();

    /// <summary>extKeyUsage, or null when absent.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public ExtendedKeyUsage? ExtendedKeyUsage => Extensions.Get<ExtendedKeyUsage>();

    /// <summary>subjectAltName, or null when absent.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public SubjectAlternativeName? SubjectAlternativeName => Extensions.Get<SubjectAlternativeName>();

    /// <summary>subjectKeyIdentifier, or null when absent.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public SubjectKeyIdentifier? SubjectKeyIdentifier => Extensions.Get<SubjectKeyIdentifier>();

    /// <summary>authorityKeyIdentifier, or null when absent.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public AuthorityKeyIdentifier? AuthorityKeyIdentifier => Extensions.Get<AuthorityKeyIdentifier>();

    /// <summary>Decodes the extension <typeparamref name="T"/> without throwing, for code that handles received certificates.</summary>
    /// <param name="value">The decoded value; null when the extension is absent or malformed.</param>
    /// <returns>True when the extension is absent or decodes; false when it is present but malformed (callers decide what that means: a matcher treats it as no match, a check reports it).</returns>
    public bool TryGetExtension<T>(out T? value)
        where T : class, IExtensionValue<T>
    {
        try
        {
            return Extensions.TryGet(out value);
        }
        catch (X509ParseException)
        {
            value = null;
            return false;
        }
    }

    /// <summary>Reads a certificate with the default limits.</summary>
    /// <param name="encoded">DER (or BER) of one certificate and nothing else. The object keeps this memory: do not change it.</param>
    /// <exception cref="X509ParseException">The octets are not a certificate, or exceed the limits.</exception>
    public static Certificate Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, X509Limits.Default);

    /// <summary>Reads a certificate with the given limits.</summary>
    /// <exception cref="X509ParseException">The octets are not a certificate, or exceed the limits.</exception>
    public static Certificate Parse(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxEncodedSize)
        {
            throw X509Read.Limit("Certificate", $"{encoded.Length} octets exceed the limit of {limits.MaxEncodedSize}.");
        }

        return new Certificate(encoded, limits);
    }

    /// <summary>Reads a certificate, copying the span first.</summary>
    public static Certificate Parse(ReadOnlySpan<byte> encoded) => Parse(new ReadOnlyMemory<byte>(encoded.ToArray()));

    /// <summary>Reads a certificate, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out Certificate? certificate)
    {
        try
        {
            certificate = Parse(encoded);
            return true;
        }
        catch (X509ParseException)
        {
            certificate = null;
            return false;
        }
    }

    /// <summary>Reads the first <c>CERTIFICATE</c> block (RFC 7468 §5.1) of PEM text.</summary>
    /// <exception cref="X509ParseException">There is no such block or it is not a certificate.</exception>
    public static Certificate FromPem(string pem)
    {
        ArgumentNullException.ThrowIfNull(pem);
        foreach (PemBlock b in X509Read.Pem("Certificate", pem))
        {
            if (b.Label is "CERTIFICATE" or "X509 CERTIFICATE" or "TRUSTED CERTIFICATE")
            {
                return Parse(b.Data);
            }
        }

        throw X509Read.Bad("Certificate", "no CERTIFICATE block in the text");
    }

    /// <summary>The certificate as a <c>CERTIFICATE</c> PEM block (RFC 7468).</summary>
    public string ToPem() => PemCodec.Write("CERTIFICATE", Encoded.Span);

    /// <summary>The platform's certificate object for the same octets.</summary>
    /// <exception cref="CryptographicException">The platform cannot load this certificate (an EdDSA key, an unknown algorithm, an odd encoding).</exception>
    public X509Certificate2 ToX509Certificate2() => X509CertificateLoader.LoadCertificate(Encoded.Span);

    /// <summary>Like <see cref="ToX509Certificate2"/> but returns false when the platform cannot load the certificate.</summary>
    public bool TryToX509Certificate2(out X509Certificate2? certificate)
    {
        try
        {
            certificate = ToX509Certificate2();
            return true;
        }
        catch (CryptographicException)
        {
            certificate = null;
            return false;
        }
    }

    /// <summary>Wraps the octets of a platform certificate (the private key, if it has one, stays in the platform object).</summary>
    /// <exception cref="X509ParseException">The platform certificate does not parse here.</exception>
    public static Certificate FromX509Certificate2(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Parse(certificate.RawData);
    }

    /// <summary>The digest of the whole certificate, as used for fingerprints and CMS certificate identifiers.</summary>
    public byte[] ComputeFingerprint(HashAlgorithmName hash) => CryptographicOperations.HashData(hash, Encoded.Span);

    /// <summary>Checks this certificate's signature with <paramref name="issuerKey"/> over the received <c>tbsCertificate</c> octets.</summary>
    /// <remarks>Only the signature is checked: validity dates, name chaining and constraints are the path validator's job (RFC 5280 §6).</remarks>
    public SignatureVerification VerifySignature(PublicKeyInfo issuerKey) => VerifySignatureCore(issuerKey, null, default);

    /// <summary>
    /// Checks this certificate's signature with <paramref name="issuerKey"/> and judges its hash and the issuer's key by <paramref name="policy"/> at
    /// <paramref name="at"/>. A SHA-1 certificate verified at a time the policy rejects SHA-1 ends as <see cref="SignatureStatus.PolicyRejected"/>; the decisions
    /// are on <see cref="SignatureVerification.Policy"/>.
    /// </summary>
    /// <param name="issuerKey">The issuer's public key.</param>
    /// <param name="policy">The policy.</param>
    /// <param name="at">The reference time.</param>
    public SignatureVerification VerifySignature(PublicKeyInfo issuerKey, Policy.CryptoPolicy policy, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return VerifySignatureCore(issuerKey, policy, at);
    }

    private SignatureVerification VerifySignatureCore(PublicKeyInfo issuerKey, Policy.CryptoPolicy? policy, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(issuerKey);
        AlgorithmIdentifier outer;
        try
        {
            outer = SignatureAlgorithm;
            if (!outer.Encoded.Span.SequenceEqual(_tbsAlgEnc.Span))
            {
                return new(SignatureStatus.Invalid, outer.Name, "The signature algorithm outside tbsCertificate differs from the one inside.", "RFC 5280 §4.1.1.2");
            }
        }
        catch (X509ParseException e)
        {
            return new(SignatureStatus.Malformed, string.Empty, e.Message, "RFC 5280 §4.1.1.2");
        }

        if (SignatureUnusedBits != 0)
        {
            return new(SignatureStatus.Invalid, outer.Name, "The signature BIT STRING has unused bits.", "RFC 5280 §4.1.1.3");
        }

        return policy is null
            ? issuerKey.VerifySignature(outer, _tbs.Span, _signature.Span)
            : issuerKey.VerifySignature(outer, _tbs.Span, _signature.Span, policy, at);
    }

    /// <summary>Checks this certificate's signature with the public key of <paramref name="issuer"/>.</summary>
    public SignatureVerification VerifySignature(Certificate issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        return VerifySignature(issuer.PublicKey);
    }

    /// <summary>Equality of the encodings.</summary>
    public bool Equals(Certificate? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as Certificate);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }

    /// <inheritdoc/>
    public override string ToString()
    {
        try
        {
            return $"{Subject} (issuer {Issuer}, serial {Convert.ToHexString(_serial.Span)})";
        }
        catch (X509ParseException)
        {
            return "Certificate";
        }
    }
}
