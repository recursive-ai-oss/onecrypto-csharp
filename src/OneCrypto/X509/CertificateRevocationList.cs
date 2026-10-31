using System.Collections;
using System.Linq;
using System.Numerics;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Pem;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

/// <summary>One revoked certificate in a CRL (RFC 5280 §5.1): serial number, revocation date and entry extensions.</summary>
public sealed class RevokedCertificate
{
    private readonly ReadOnlyMemory<byte> _extensions;
    private readonly X509Limits _limits;
    private ExtensionCollection? _extensionList;

    private RevokedCertificate(ReadOnlyMemory<byte> encoded, ReadOnlyMemory<byte> serial, DateTimeOffset date, ReadOnlyMemory<byte> extensions, X509Limits limits)
    {
        Encoded = encoded;
        SerialNumber = serial;
        RevocationDate = date;
        _extensions = extensions;
        _limits = limits;
    }

    /// <summary>The entry exactly as received.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The revoked certificate's serial number, as INTEGER content octets.</summary>
    public ReadOnlyMemory<byte> SerialNumber { get; }

    /// <summary>The serial number as a number.</summary>
    public BigInteger SerialNumberValue => new(SerialNumber.Span, isUnsigned: false, isBigEndian: true);

    /// <summary>When the certificate was revoked.</summary>
    public DateTimeOffset RevocationDate { get; }

    /// <summary>The entry extensions (reason code, invalidity date, certificate issuer), possibly empty.</summary>
    public ExtensionCollection Extensions => _extensionList ??= ExtensionCollection.Decode(_extensions, _limits, "CRL entry");

    /// <summary>The reason code, or null when the entry carries none. An absent reason is the same as unspecified (RFC 5280 §5.3.1).</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public RevocationReason? Reason => Extensions.Get<CrlReasonExtension>()?.Reason;

    /// <summary>The invalidity date, or null.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public DateTimeOffset? InvalidityDate => Extensions.Get<InvalidityDate>()?.Date;

    /// <summary>The certificateIssuer names that apply to this entry in an indirect CRL, or null.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public IReadOnlyList<GeneralName>? CertificateIssuer => Extensions.Get<CertificateIssuerExtension>()?.Names;

    internal static RevokedCertificate Read(ReadOnlyMemory<byte> root, ReadOnlySpan<byte> entry, X509Limits limits, bool validateOnly)
    {
        var outer = new Asn1Reader(entry, Asn1Rules.Ber, limits.Asn1);
        Asn1Reader seq = outer.ReadSequence();
        ReadOnlySpan<byte> serial = seq.ReadIntegerBytes();
        DateTimeOffset date = seq.ReadTime();
        ReadOnlySpan<byte> exts = default;
        if (seq.HasData)
        {
            exts = seq.ReadEncodedValue();
            ExtensionCollection.Validate(exts, limits, "CRL entry");
        }

        seq.ThrowIfNotEmpty();
        return validateOnly
            ? null!
            : new RevokedCertificate(X509Read.Slice(root, entry), X509Read.Slice(root, serial), date, X509Read.Slice(root, exts), limits);
    }
}

/// <summary>
/// A certificate revocation list or delta CRL (RFC 5280 §5). Immutable and lossless: the encoding is kept, entries are read as you go
/// (a CRL can hold millions), and the signature is checked over the received <c>tbsCertList</c> octets.
/// </summary>
public sealed class CertificateRevocationList : IEquatable<CertificateRevocationList>
{
    private readonly ReadOnlyMemory<byte> _tbs;
    private readonly ReadOnlyMemory<byte> _issuer;
    private readonly ReadOnlyMemory<byte> _tbsAlgEnc;
    private readonly ReadOnlyMemory<byte> _outerAlgEnc;
    private readonly ReadOnlyMemory<byte> _entries;
    private readonly ReadOnlyMemory<byte> _extensions;
    private readonly X509Limits _limits;
    private DistinguishedName? _issuerName;
    private AlgorithmIdentifier? _tbsAlg;
    private AlgorithmIdentifier? _outerAlg;
    private ExtensionCollection? _extensionList;

    private CertificateRevocationList(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        _limits = limits;
        Encoded = encoded;
        try
        {
            var top = new Asn1Reader(encoded.Span, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader crl = top.ReadSequence();
            top.ThrowIfNotEmpty();
            ReadOnlySpan<byte> tbsEnc = crl.ReadEncodedValue();
            _tbs = X509Read.Slice(encoded, tbsEnc);
            _outerAlgEnc = X509Read.Algorithm(crl.ReadEncodedValue(), encoded, limits);
            Signature = X509Read.Slice(encoded, crl.ReadBitString(out int unused));
            SignatureUnusedBits = unused;
            crl.ThrowIfNotEmpty();

            var tr = new Asn1Reader(tbsEnc, Asn1Rules.Ber, limits.Asn1);
            Asn1Reader tbs = tr.ReadSequence();
            Version = 1;
            if (tbs.TryPeekTag(out Asn1Tag t) && t == new Asn1Tag(Asn1Tags.IntegerType))
            {
                int v = tbs.ReadInt32();
                if (v is < 0 or > 1)
                {
                    throw new X509ParseException("CertificateList", X509Error.UnsupportedVersion, $"version {v + 1} is not 1 or 2");
                }

                Version = v + 1;
            }

            _tbsAlgEnc = X509Read.Algorithm(tbs.ReadEncodedValue(), encoded, limits);
            ReadOnlySpan<byte> issuer = tbs.ReadEncodedValue();
            DistinguishedName.Validate(issuer, limits);
            _issuer = X509Read.Slice(encoded, issuer);
            ThisUpdate = tbs.ReadTime();
            if (tbs.TryPeekTag(out t) && (t == new Asn1Tag(Asn1Tags.UtcTime) || t == new Asn1Tag(Asn1Tags.GeneralizedTime)))
            {
                NextUpdate = tbs.ReadTime();
            }

            if (tbs.TryPeekTag(out t) && t == Asn1Tag.Sequence)
            {
                ReadOnlySpan<byte> list = tbs.ReadEncodedValue();
                var lr = new Asn1Reader(list, Asn1Rules.Ber, limits.Asn1);
                Asn1Reader entries = lr.ReadSequence();
                _entries = X509Read.Slice(encoded, entries.Remaining);
                while (entries.HasData)
                {
                    RevokedCertificate.Read(encoded, entries.ReadEncodedValue(), limits, validateOnly: true);
                }
            }

            if (tbs.TryPeekTag(out t) && t == Asn1Tag.Context(0))
            {
                Asn1Reader w = tbs.ReadSequence(Asn1Tag.Context(0, true));
                ReadOnlySpan<byte> list = w.ReadEncodedValue();
                w.ThrowIfNotEmpty();
                ExtensionCollection.Validate(list, limits, "CertificateList");
                _extensions = X509Read.Slice(encoded, list);
            }

            tbs.ThrowIfNotEmpty();
        }
        catch (Asn1ParseException e)
        {
            throw new X509ParseException("CertificateList", e);
        }
    }

    /// <summary>The whole list exactly as received or built.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>The <c>tbsCertList</c> element exactly as received: the octets the signature covers.</summary>
    public ReadOnlyMemory<byte> TbsCertList => _tbs;

    /// <summary>1 when the version field is absent, 2 for a version 2 list (required for extensions).</summary>
    public int Version { get; }

    /// <summary>The signature algorithm named inside <c>tbsCertList</c>.</summary>
    public AlgorithmIdentifier TbsSignatureAlgorithm => _tbsAlg ??= AlgorithmIdentifier.Parse(_tbsAlgEnc);

    /// <summary>The signature algorithm named outside <c>tbsCertList</c>.</summary>
    public AlgorithmIdentifier SignatureAlgorithm => _outerAlg ??= AlgorithmIdentifier.Parse(_outerAlgEnc);

    /// <summary>The signature value (the BIT STRING content).</summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>Unused bits of the signature BIT STRING as received.</summary>
    public int SignatureUnusedBits { get; }

    /// <summary>The issuer name.</summary>
    public DistinguishedName Issuer => _issuerName ??= DistinguishedName.Parse(_issuer, _limits);

    /// <summary>When this list was issued.</summary>
    public DateTimeOffset ThisUpdate { get; }

    /// <summary>When the next list is due, or null when the field is absent (RFC 5280 requires it; some issuers omit it).</summary>
    public DateTimeOffset? NextUpdate { get; }

    /// <summary>The revoked certificates, read one at a time from the received octets.</summary>
    public RevokedCertificateList Entries => new(Encoded, _entries, _limits);

    /// <summary>The list extensions in encoded order.</summary>
    public ExtensionCollection Extensions => _extensionList ??= ExtensionCollection.Decode(_extensions, _limits, "CertificateList");

    /// <summary>The cRLNumber, or null when absent.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public BigInteger? Number => Extensions.Get<CrlNumber>()?.Number;

    /// <summary>True when the list carries a deltaCRLIndicator (RFC 5280 §5.2.4).</summary>
    public bool IsDelta => Extensions.Contains(KnownOids.DeltaCrlIndicator);

    /// <summary>The cRLNumber of the complete list a delta builds on, or null for a complete list.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public BigInteger? BaseNumber => Extensions.Get<DeltaCrlIndicator>()?.BaseCrlNumber;

    /// <summary>The issuingDistributionPoint extension, or null.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public IssuingDistributionPoint? IssuingDistributionPoint => Extensions.Get<IssuingDistributionPoint>();

    /// <summary>True for an indirect CRL, which may list certificates issued by other CAs (the entries carry certificateIssuer).</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public bool IsIndirect => IssuingDistributionPoint?.IndirectCrl == true;

    /// <summary>The authorityKeyIdentifier, or null.</summary>
    /// <exception cref="X509ParseException">The extension is malformed.</exception>
    public AuthorityKeyIdentifier? AuthorityKeyIdentifier => Extensions.Get<AuthorityKeyIdentifier>();

    /// <summary>Looks a serial number up by scanning the entries. Leading zero octets are ignored. Returns null when the serial is not listed.</summary>
    /// <param name="serialNumber">The INTEGER content octets of the serial number.</param>
    public RevokedCertificate? Find(ReadOnlySpan<byte> serialNumber)
    {
        ReadOnlySpan<byte> want = TrimZeros(serialNumber);
        foreach (RevokedCertificate e in Entries)
        {
            if (TrimZeros(e.SerialNumber.Span).SequenceEqual(want))
            {
                return e;
            }
        }

        return null;
    }

    private static ReadOnlySpan<byte> TrimZeros(ReadOnlySpan<byte> s)
    {
        while (s.Length > 1 && s[0] == 0)
        {
            s = s[1..];
        }

        return s;
    }

    /// <summary>Reads a list with the default limits (the CRL size limit, not the certificate one, applies).</summary>
    /// <exception cref="X509ParseException">The octets are not a CRL.</exception>
    public static CertificateRevocationList Parse(ReadOnlyMemory<byte> encoded) => Parse(encoded, X509Limits.Default);

    /// <summary>Reads a list with the given limits.</summary>
    public static CertificateRevocationList Parse(ReadOnlyMemory<byte> encoded, X509Limits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (encoded.Length > limits.MaxCrlSize)
        {
            throw X509Read.Limit("CertificateList", $"{encoded.Length} octets exceed the limit of {limits.MaxCrlSize}.");
        }

        return new CertificateRevocationList(encoded, limits);
    }

    /// <summary>Reads a list, returning false instead of throwing.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> encoded, out CertificateRevocationList? list)
    {
        try
        {
            list = Parse(encoded);
            return true;
        }
        catch (X509ParseException)
        {
            list = null;
            return false;
        }
    }

    /// <summary>Reads the first <c>X509 CRL</c> block of PEM text.</summary>
    public static CertificateRevocationList FromPem(string pem)
    {
        ArgumentNullException.ThrowIfNull(pem);
        foreach (PemBlock b in X509Read.Pem("CertificateList", pem))
        {
            if (b.Label == "X509 CRL")
            {
                return Parse(new ReadOnlyMemory<byte>(b.Data));
            }
        }

        throw X509Read.Bad("CertificateList", "no X509 CRL block in the text");
    }

    /// <summary>The list as an <c>X509 CRL</c> PEM block (RFC 7468 §6).</summary>
    public string ToPem() => PemCodec.Write("X509 CRL", Encoded.Span);

    /// <summary>Checks the list's signature with the CRL issuer's public key over the received <c>tbsCertList</c> octets.</summary>
    /// <remarks>Only the signature is checked: scope, freshness and the issuer's authority belong to the validator.</remarks>
    public SignatureVerification VerifySignature(PublicKeyInfo issuerKey)
    {
        ArgumentNullException.ThrowIfNull(issuerKey);
        try
        {
            AlgorithmIdentifier outer = SignatureAlgorithm;
            if (!outer.Encoded.Span.SequenceEqual(_tbsAlgEnc.Span))
            {
                return new(SignatureStatus.Invalid, outer.Name, "The signature algorithm outside tbsCertList differs from the one inside.", "RFC 5280 §5.1.1.2");
            }

            if (SignatureUnusedBits != 0)
            {
                return new(SignatureStatus.Invalid, outer.Name, "The signature BIT STRING has unused bits.", "RFC 5280 §5.1.1.3");
            }

            return issuerKey.VerifySignature(outer, _tbs.Span, Signature.Span);
        }
        catch (X509ParseException e)
        {
            return new(SignatureStatus.Malformed, string.Empty, e.Message, "RFC 5280 §5.1.1.2");
        }
    }

    /// <summary>Checks the list's signature with the public key of <paramref name="issuer"/>.</summary>
    public SignatureVerification VerifySignature(Certificate issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        return VerifySignature(issuer.PublicKey);
    }

    /// <inheritdoc/>
    public bool Equals(CertificateRevocationList? other) => other is not null && Encoded.Span.SequenceEqual(other.Encoded.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CertificateRevocationList);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(Encoded.Span);
        return h.ToHashCode();
    }
}

/// <summary>The entries of a CRL, read lazily. Enumerating again starts over; nothing is copied.</summary>
public readonly struct RevokedCertificateList : IEnumerable<RevokedCertificate>
{
    private readonly ReadOnlyMemory<byte> _root;
    private readonly ReadOnlyMemory<byte> _entries;
    private readonly X509Limits _limits;

    internal RevokedCertificateList(ReadOnlyMemory<byte> root, ReadOnlyMemory<byte> entries, X509Limits limits)
    {
        _root = root;
        _entries = entries;
        _limits = limits;
    }

    /// <summary>True when the list has no entries.</summary>
    public bool IsEmpty => _entries.IsEmpty;

    /// <inheritdoc/>
    public IEnumerator<RevokedCertificate> GetEnumerator() => new Enumerator(_root, _entries, _limits);

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    private sealed class Enumerator : IEnumerator<RevokedCertificate>
    {
        private readonly ReadOnlyMemory<byte> _root;
        private readonly ReadOnlyMemory<byte> _entries;
        private readonly X509Limits _limits;
        private int _pos;

        public Enumerator(ReadOnlyMemory<byte> root, ReadOnlyMemory<byte> entries, X509Limits limits)
        {
            _root = root;
            _entries = entries;
            _limits = limits;
        }

        public RevokedCertificate Current { get; private set; } = null!;

        object IEnumerator.Current => Current;

        public bool MoveNext()
        {
            if (_pos >= _entries.Length)
            {
                return false;
            }

            try
            {
                var r = new Asn1Reader(_entries.Span[_pos..], Asn1Rules.Ber, _limits.Asn1);
                ReadOnlySpan<byte> one = r.ReadEncodedValue();
                Current = RevokedCertificate.Read(_root, one, _limits, validateOnly: false);
                _pos += one.Length;
                return true;
            }
            catch (Asn1ParseException e)
            {
                throw new X509ParseException("CertificateList", e);
            }
        }

        public void Reset() => _pos = 0;

        public void Dispose()
        {
        }
    }
}

/// <summary>A certificate to list in a CRL being built.</summary>
/// <param name="SerialNumber">The revoked certificate's serial number.</param>
/// <param name="RevocationDate">When it was revoked.</param>
/// <param name="Reason">The reason code, or null to omit the extension.</param>
/// <param name="InvalidityDate">The invalidity date, or null.</param>
/// <param name="Extensions">Further entry extensions (certificateIssuer for an indirect CRL, for instance), or null.</param>
public sealed record RevokedCertificateInfo(
    BigInteger SerialNumber,
    DateTimeOffset RevocationDate,
    RevocationReason? Reason = null,
    DateTimeOffset? InvalidityDate = null,
    IReadOnlyList<Extension>? Extensions = null);

/// <summary>What goes into a CRL that is about to be issued.</summary>
public sealed class RevocationListOptions
{
    /// <summary>The issuer name. Left null, it is the subject of the issuer certificate given to the builder.</summary>
    public DistinguishedName? Issuer { get; init; }

    /// <summary>When the list is issued.</summary>
    public required DateTimeOffset ThisUpdate { get; init; }

    /// <summary>When the next list is due, or null to omit the field.</summary>
    public DateTimeOffset? NextUpdate { get; init; }

    /// <summary>The revoked certificates in the order to write them.</summary>
    public IReadOnlyList<RevokedCertificateInfo> Revoked { get; init; } = [];

    /// <summary>The cRLNumber to write, or null to omit it. RFC 5280 §5.2.3 makes it mandatory for conforming CAs.</summary>
    public BigInteger? Number { get; init; }

    /// <summary>For a delta CRL, the cRLNumber of the complete list it builds on (written as a critical deltaCRLIndicator).</summary>
    public BigInteger? DeltaBaseNumber { get; init; }

    /// <summary>Further list extensions (issuingDistributionPoint, freshestCRL, and so on).</summary>
    public IReadOnlyList<Extension> Extensions { get; init; } = [];
}

/// <summary>Issues CRLs and delta CRLs (RFC 5280 §5).</summary>
public static class RevocationListBuilder
{
    /// <summary>Phase one of issuing a list in two steps; see <see cref="CertificateBuilder.PrepareSelfSigned"/>.</summary>
    public static PreparedSignature Prepare(RevocationListOptions options, PublicKeyInfo signerKey, SignatureSpec spec, CryptoPolicy policy, DateTimeOffset at, Certificate? issuer = null) =>
        X509TwoPhase.Prepare(PurposeList, signerKey, spec, policy, at, s => Create(options, s, issuer));

    /// <summary>Phase two: checks the signature and returns the list.</summary>
    /// <exception cref="InvalidSignatureException">The signature does not verify.</exception>
    public static CertificateRevocationList Complete(PreparedSignature prepared, ReadOnlySpan<byte> signature) =>
        CertificateRevocationList.Parse(X509TwoPhase.Complete(prepared, PurposeList, signature));

    private const string PurposeList = "x509.crl";

    /// <summary>Issues a list signed by <paramref name="signer"/>. With <paramref name="issuer"/> the issuer name and authorityKeyIdentifier come from that certificate.</summary>
    /// <exception cref="ArgumentException">Neither the options nor an issuer certificate give an issuer name.</exception>
    public static CertificateRevocationList Create(RevocationListOptions options, X509Signer signer, Certificate? issuer = null, CryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signer);
        DistinguishedName name = options.Issuer ?? issuer?.Subject ?? throw new ArgumentException("An issuer name or issuer certificate is needed.", nameof(options));

        var exts = new List<Extension>();
        if (issuer is not null)
        {
            ReadOnlyMemory<byte> id = issuer.SubjectKeyIdentifier?.KeyIdentifier ?? BuildHelpers.KeyIdentifier(issuer.PublicKey);
            exts.Add(Extension.Create(new AuthorityKeyIdentifier(id), false));
        }

        if (options.Number is BigInteger n)
        {
            exts.Add(Extension.Create(new CrlNumber(n), false));
        }

        if (options.DeltaBaseNumber is BigInteger b)
        {
            exts.Add(Extension.Create(new DeltaCrlIndicator(b), true));
        }

        exts.AddRange(options.Extensions);

        var entries = new List<byte[]>();
        foreach (RevokedCertificateInfo r in options.Revoked)
        {
            var entryExts = new List<Extension>();
            if (r.Reason is RevocationReason reason)
            {
                entryExts.Add(Extension.Create(new CrlReasonExtension(reason), false));
            }

            if (r.InvalidityDate is DateTimeOffset d)
            {
                entryExts.Add(Extension.Create(new InvalidityDate(d), false));
            }

            if (r.Extensions is not null)
            {
                entryExts.AddRange(r.Extensions);
            }

            entries.Add(DerWriter.Sequence(
                DerWriterExtras.Integer(r.SerialNumber),
                BuildHelpers.Time(r.RevocationDate),
                entryExts.Count > 0 ? BuildHelpers.Extensions(entryExts) : []));
        }

        // Version 2 is required once extensions are present (RFC 5280 §5.1.2.1); it is written always, as CAs do.
        byte[] tbs = DerWriter.Sequence(
            DerWriter.SignedInteger(1),
            signer.SignatureAlgorithm.Encoded.ToArray(),
            name.Encoded.ToArray(),
            BuildHelpers.Time(options.ThisUpdate),
            options.NextUpdate is DateTimeOffset next ? BuildHelpers.Time(next) : [],
            entries.Count > 0 ? DerWriter.Sequence([.. entries]) : [],
            exts.Count > 0 ? DerWriter.Context(0, BuildHelpers.Extensions(exts)) : []);
        return CertificateRevocationList.Parse(new ReadOnlyMemory<byte>(BuildHelpers.Signed(tbs, signer, policy)));
    }
}
