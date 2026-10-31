using System.Linq;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Wire.Cms;

namespace RecursiveAI.OneCrypto;

/// <summary>Which ESS signing-certificate attribute (RFC 5035) a signer writes.</summary>
public enum EssSigningCertificate
{
    /// <summary>None.</summary>
    None,

    /// <summary>signingCertificate, with a SHA-1 certificate hash (RFC 2634).</summary>
    V1,

    /// <summary>signingCertificateV2, with a SHA-256 certificate hash (RFC 5035).</summary>
    V2,
}

/// <summary>Describes one signer of a message being built: the certificate, the key and what goes into the SignerInfo.</summary>
public sealed class CmsSignerSpec
{
    /// <summary>The signer's certificate. Its public key must be the one the <see cref="Signer"/> signs with.</summary>
    public required Certificate Certificate { get; init; }

    /// <summary>Produces the signature value. Its algorithm identifier decides the signature algorithm.</summary>
    public required X509Signer Signer { get; init; }

    /// <summary>How the SignerInfo names the certificate (default issuer and serial number).</summary>
    public CmsIdentifierKind Identifier { get; init; } = CmsIdentifierKind.IssuerAndSerialNumber;

    /// <summary>
    /// The digest algorithm object identifier. By default it follows the signature algorithm: the hash RSA and ECDSA identifiers name,
    /// SHA-512 for Ed25519 (RFC 8419 §3.1), SHAKE256 for Ed448 (RFC 8419 §3.1) and SHA-512 for ML-DSA and SLH-DSA (RFC 9882 §3, RFC 9814 §4).
    /// </summary>
    public string? DigestAlgorithm { get; init; }

    /// <summary>True (the default) to sign attributes, which carry the digest of the content; false to sign the content itself, which needs the content in memory.</summary>
    public bool SignedAttributes { get; init; } = true;

    /// <summary>The signing-time attribute. Null omits it: the library never reads a clock on its own.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>The ESS signing-certificate attribute, which binds the signature to the certificate (default <see cref="EssSigningCertificate.V2"/>).</summary>
    public EssSigningCertificate SigningCertificate { get; init; } = EssSigningCertificate.V2;

    /// <summary>More signed attributes, written after the standard ones.</summary>
    public IReadOnlyList<CmsAttributeEntry> AdditionalSignedAttributes { get; init; } = [];

    /// <summary>Unsigned attributes to include.</summary>
    public IReadOnlyList<CmsAttributeEntry> UnsignedAttributes { get; init; } = [];
}

/// <summary>Choices for building a SignedData.</summary>
public sealed class SignedDataOptions
{
    /// <summary>The encapsulated content type (default id-data).</summary>
    public string ContentType { get; init; } = CmsOids.Data;

    /// <summary>True to leave the content out of the message.</summary>
    public bool Detached { get; init; }

    /// <summary>Certificates to include besides the signers' own.</summary>
    public IReadOnlyList<Certificate> Certificates { get; init; } = [];

    /// <summary>True (the default) to include each signer's certificate.</summary>
    public bool IncludeSignerCertificates { get; init; } = true;

    /// <summary>Revocation lists to include.</summary>
    public IReadOnlyList<CertificateRevocationList> Crls { get; init; } = [];
}

public sealed partial class SignedData
{
    /// <summary>Signs <paramref name="content"/> and returns the message (definite-length DER).</summary>
    /// <param name="content">The content octets.</param>
    /// <param name="signers">One or more signers.</param>
    /// <param name="options">Choices, or null for an attached id-data message.</param>
    /// <exception cref="ArgumentException">A signer's algorithm combination cannot be written.</exception>
    /// <exception cref="NotSupportedException">The digest algorithm is not available on this platform.</exception>
    public static SignedData Create(ReadOnlySpan<byte> content, IReadOnlyList<CmsSignerSpec> signers, SignedDataOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(signers);
        options ??= new SignedDataOptions();
        var plans = new List<SignerPlan>();
        foreach (CmsSignerSpec s in signers)
        {
            plans.Add(SignerPlan.For(s));
        }

        var infos = new List<byte[]>();
        foreach (SignerPlan p in plans)
        {
            byte[] digest = Digest(p.DigestOid, content);
            infos.Add(p.Build(options.ContentType, digest, content, countersignature: false));
        }

        byte[] eContent = DerWriter.Sequence(DerWriter.Oid(options.ContentType), options.Detached ? [] : DerWriter.Context(0, DerWriter.OctetString(content)));
        return Assemble(options, plans, eContent, infos);
    }

    /// <summary>Builds the SignedData structure around the signer infos.</summary>
    internal static SignedData Assemble(SignedDataOptions options, List<SignerPlan> plans, byte[] encapsulated, List<byte[]> signerInfos)
    {
        byte[] body = AssembleBody(options, plans, encapsulated, signerInfos);
        byte[] ci = DerWriter.Sequence(DerWriter.Oid(CmsOids.SignedData), DerWriter.Context(0, body));
        return Parse(ci);
    }

    internal static int VersionOf(SignedDataOptions options, List<SignerPlan> plans) =>
        options.ContentType != CmsOids.Data || plans.Any(static p => p.Spec.Identifier == CmsIdentifierKind.SubjectKeyIdentifier) ? 3 : 1;

    /// <summary>The <c>[0]</c> certificates and <c>[1]</c> revocation lists that follow the encapsulated content, as encoded elements.</summary>
    internal static List<byte[]> CertificateParts(SignedDataOptions options, List<SignerPlan> plans)
    {
        var certs = new List<byte[]>();
        void AddCert(Certificate c)
        {
            if (!certs.Any(x => x.AsSpan().SequenceEqual(c.Encoded.Span)))
            {
                certs.Add(c.Encoded.ToArray());
            }
        }

        if (options.IncludeSignerCertificates)
        {
            foreach (SignerPlan p in plans)
            {
                AddCert(p.Spec.Certificate);
            }
        }

        foreach (Certificate c in options.Certificates)
        {
            AddCert(c);
        }

        var parts = new List<byte[]>();
        if (certs.Count > 0)
        {
            parts.Add(DerWriter.Retag(DerWriter.SetOf(certs), 0xA0));
        }

        if (options.Crls.Count > 0)
        {
            parts.Add(DerWriter.Retag(DerWriter.SetOf(options.Crls.Select(static c => c.Encoded.ToArray())), 0xA1));
        }

        return parts;
    }

    internal static byte[] AssembleBody(SignedDataOptions options, List<SignerPlan> plans, byte[] encapsulated, List<byte[]> signerInfos)
    {
        var parts = new List<byte[]> { DerWriter.SignedInteger(VersionOf(options, plans)), DigestAlgorithmSet(plans), encapsulated };
        parts.AddRange(CertificateParts(options, plans));

        // SignerInfos stay in the order given (CMS does not require DER ordering here), so report index i is signer i.
        parts.Add(DerWriter.Set([.. signerInfos]));
        return DerWriter.Sequence([.. parts]);
    }

    internal static byte[] DigestAlgorithmSet(IEnumerable<SignerPlan> plans)
    {
        var algs = new List<byte[]>();
        foreach (SignerPlan p in plans)
        {
            byte[] a = DerWriter.Sequence(DerWriter.Oid(p.DigestOid));
            if (!algs.Any(x => x.AsSpan().SequenceEqual(a)))
            {
                algs.Add(a);
            }
        }

        return DerWriter.SetOf(algs);
    }

    internal static byte[] Digest(string oid, ReadOnlySpan<byte> content) =>
        CmsDigest.TryHash(oid, content, out byte[] d) ? d : throw new NotSupportedException($"The digest algorithm {AlgorithmNames.Describe(oid)} is not available on this platform.");

    /// <summary>
    /// A countersignature (RFC 5652 §11.4) of <paramref name="target"/>'s signature, as an unsigned attribute ready for
    /// <see cref="WithUnsignedAttribute"/>. Its signed attributes hold the message digest of the signature value and no content type.
    /// </summary>
    public static CmsAttributeEntry CreateCountersignature(SignerInfo target, CmsSignerSpec signer)
    {
        ArgumentNullException.ThrowIfNull(target);
        SignerPlan plan = SignerPlan.For(signer);
        byte[] digest = Digest(plan.DigestOid, target.Signature.Span);
        return CmsAttributeEntry.Create(CmsOids.Countersignature, plan.Build(CmsOids.Data, digest, target.Signature.Span, countersignature: true));
    }

    /// <summary>A copy of this message with one more unsigned attribute on the signer at <paramref name="signerIndex"/> (for a countersignature, or an embedded time-stamp token), and optionally more certificates (the countersigner's, the time-stamp authority's). Signed parts stay as received, so existing signatures remain valid. The result is re-encoded as definite-length BER.</summary>
    public SignedData WithUnsignedAttribute(int signerIndex, CmsAttributeEntry attribute, IEnumerable<Certificate>? additionalCertificates = null)
    {
        ArgumentNullException.ThrowIfNull(attribute);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(signerIndex, Signers.Count);
        var infos = new List<byte[]>();
        for (int i = 0; i < Signers.Count; i++)
        {
            SignerInfo s = Signers[i];
            if (i != signerIndex)
            {
                infos.Add(s.Encoded.ToArray());
                continue;
            }

            var unsigned = new List<CmsAttributeEntry>(s.UnsignedAttributes ?? []) { attribute };
            infos.Add(SignerInfo.Encode(s.Version, s.Identifier, s.DigestAlgorithm.Encoded.ToArray(),
                s.SignedAttributesEncoded.IsEmpty ? null : s.SignedAttributesEncoded.ToArray(), s.SignatureAlgorithm.Encoded.ToArray(), s.Signature.ToArray(),
                DerWriter.Retag(CmsAttributeEntry.EncodeSet(unsigned), 0xA1)));
        }

        var parts = new List<byte[]> { DerWriter.SignedInteger(Version), _digestAlgorithmsEncoded.ToArray(), _encapsulatedEncoded.ToArray() };
        var certs = new List<byte[]>(_certificateElements.Select(static c => c.ToArray()));
        foreach (Certificate c in additionalCertificates ?? [])
        {
            if (!certs.Any(x => x.AsSpan().SequenceEqual(c.Encoded.Span)))
            {
                certs.Add(c.Encoded.ToArray());
            }
        }

        if (certs.Count > 0)
        {
            parts.Add(DerWriter.Retag(DerWriter.Tlv(0x31, [.. certs]), 0xA0));
        }

        if (!_crlsEncoded.IsEmpty)
        {
            parts.Add(_crlsEncoded.ToArray());
        }

        parts.Add(DerWriter.Set([.. infos]));
        byte[] ci = DerWriter.Sequence(DerWriter.Oid(CmsOids.SignedData), DerWriter.Context(0, DerWriter.Sequence([.. parts])));
        return Parse(ci, Limits);
    }

    /// <summary>What is decided about one signer before any content is seen: digest, signature algorithm, and the code that builds the SignerInfo.</summary>
    internal sealed class SignerPlan
    {
        private SignerPlan(CmsSignerSpec spec, string digestOid)
        {
            Spec = spec;
            DigestOid = digestOid;
        }

        public CmsSignerSpec Spec { get; }

        public string DigestOid { get; }

        public static SignerPlan For(CmsSignerSpec spec)
        {
            ArgumentNullException.ThrowIfNull(spec);
            AlgorithmIdentifier alg = spec.Signer.SignatureAlgorithm;
            string? natural = null;
            if (SignatureAlgorithms.TryScheme(alg, out SignatureScheme scheme))
            {
                natural = scheme.HashOid;
            }
            else if (alg.Oid == KnownOids.RsaPss)
            {
                natural = PssParameters.Parse(alg.Parameters).HashOid;
            }

            string chosen = spec.DigestAlgorithm
                ?? natural
                ?? (alg.Oid == KnownOids.Ed448 ? CmsOids.Shake256 : alg.Oid is KnownOids.Ed25519 or KnownOids.MlDsa44 or KnownOids.MlDsa65 or KnownOids.MlDsa87 || AlgorithmNames.SlhDsaName(alg.Oid) is not null ? KnownOids.Sha512 : throw new ArgumentException($"No digest algorithm is known for {alg.Name}; set DigestAlgorithm.", nameof(spec)));
            if (natural is not null && natural != chosen)
            {
                throw new ArgumentException($"{alg.Name} signs with {AlgorithmNames.Describe(natural)}; the digest algorithm {AlgorithmNames.Describe(chosen)} does not match.", nameof(spec));
            }

            if (!CmsDigest.IsSupported(chosen))
            {
                throw new NotSupportedException($"The digest algorithm {AlgorithmNames.Describe(chosen)} is not available on this platform.");
            }

            return new SignerPlan(spec, chosen);
        }

        /// <summary>The signature algorithm written into the SignerInfo: rsaEncryption for PKCS #1 v1.5 (RFC 3370 §3.2), otherwise the signer's own identifier.</summary>
        private AlgorithmIdentifier SignatureAlgorithm()
        {
            AlgorithmIdentifier alg = Spec.Signer.SignatureAlgorithm;
            return alg.Oid is KnownOids.Sha1WithRsa or KnownOids.Sha224WithRsa or KnownOids.Sha256WithRsa or KnownOids.Sha384WithRsa or KnownOids.Sha512WithRsa
                ? AlgorithmIdentifier.WithNull(KnownOids.RsaEncryption)
                : alg;
        }

        /// <param name="contentType">The content type attribute value.</param>
        /// <param name="contentDigest">The digest of the content under <see cref="DigestOid"/>.</param>
        /// <param name="content">The content octets, signed directly when the signer uses no attributes; may be empty for streamed content.</param>
        /// <param name="countersignature">True for a countersignature, which carries no content-type attribute (RFC 5652 §11.4).</param>
        public byte[] Build(string contentType, byte[] contentDigest, ReadOnlySpan<byte> content, bool countersignature)
        {
            byte[] digestAlg = DerWriter.Sequence(DerWriter.Oid(DigestOid));
            byte[]? attrSet = null;
            byte[] signature;
            if (Spec.SignedAttributes)
            {
                var attrs = new List<CmsAttributeEntry>();
                if (!countersignature)
                {
                    attrs.Add(CmsAttributeEntry.Create(CmsOids.ContentType, DerWriter.Oid(contentType)));
                }

                attrs.Add(CmsAttributeEntry.Create(CmsOids.MessageDigest, DerWriter.OctetString(contentDigest)));
                if (Spec.SigningTime is { } t)
                {
                    attrs.Add(CmsAttributeEntry.Create(CmsOids.SigningTime, BuildHelpers.Time(t)));
                }

                if (Spec.SigningCertificate != EssSigningCertificate.None && !countersignature)
                {
                    attrs.Add(EssAttribute(Spec.Certificate, Spec.SigningCertificate));
                }

                attrs.AddRange(Spec.AdditionalSignedAttributes);
                attrSet = CmsAttributeEntry.EncodeSet(attrs);
                signature = Spec.Signer.Sign(attrSet);
            }
            else
            {
                signature = Spec.Signer.Sign(content);
            }

            byte[]? unsignedSet = Spec.UnsignedAttributes.Count > 0 ? CmsAttributeEntry.EncodeSet(Spec.UnsignedAttributes) : null;
            CmsIdentifier sid = CmsIdentifier.ForCertificate(Spec.Certificate, Spec.Identifier);
            int version = Spec.Identifier == CmsIdentifierKind.SubjectKeyIdentifier ? 3 : 1;
            return SignerInfo.Encode(version, sid, digestAlg, attrSet is null ? null : DerWriter.Retag(attrSet, 0xA0), SignatureAlgorithm().Encoded.ToArray(), signature,
                unsignedSet is null ? null : DerWriter.Retag(unsignedSet, 0xA1));
        }

        /// <summary>RFC 5035 §3 (ESSCertIDv2) and RFC 2634 §5.4.1 (ESSCertID): the signer certificate named by hash and by issuer and serial number.</summary>
        private static CmsAttributeEntry EssAttribute(Certificate cert, EssSigningCertificate kind)
        {
            string hashOid = kind == EssSigningCertificate.V2 ? KnownOids.Sha256 : KnownOids.Sha1;
            byte[] hash = Digest(hashOid, cert.Encoded.Span);
            byte[] issuerSerial = DerWriter.Sequence(
                DerWriter.Sequence(DerWriter.Context(4, cert.Issuer.Encoded.ToArray())),
                DerWriter.Tlv(0x02, cert.SerialNumber.ToArray()));
            // The hashAlgorithm field defaults to SHA-256 and is left out then (DER omits default values).
            byte[] id = DerWriter.Sequence(DerWriter.OctetString(hash), issuerSerial);
            return CmsAttributeEntry.Create(kind == EssSigningCertificate.V2 ? CmsOids.SigningCertificateV2 : CmsOids.SigningCertificate,
                DerWriter.Sequence(DerWriter.Sequence(id)));
        }
    }
}
