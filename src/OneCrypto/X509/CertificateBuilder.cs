using System.Linq;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

/// <summary>What goes into a certificate that is about to be issued.</summary>
public sealed class CertificateOptions
{
    /// <summary>The subject name.</summary>
    public required DistinguishedName Subject { get; init; }

    /// <summary>The subject's public key. Left null on a self-signed certificate, it is the signer's key.</summary>
    public PublicKeyInfo? PublicKey { get; init; }

    /// <summary>The start of validity. Written as UTCTime through 2049 and GeneralizedTime after (RFC 5280 §4.1.2.5).</summary>
    public required DateTimeOffset NotBefore { get; init; }

    /// <summary>The end of validity.</summary>
    public required DateTimeOffset NotAfter { get; init; }

    /// <summary>The serial number as unsigned big-endian octets (at most 20, RFC 5280 §4.1.2.2). Empty means 159 random bits.</summary>
    public ReadOnlyMemory<byte> SerialNumber { get; init; }

    /// <summary>The extensions to include, in order. The certificate is version 3 when there are any.</summary>
    public IReadOnlyList<Extension> Extensions { get; init; } = [];

    /// <summary>Adds a subjectKeyIdentifier (the leftmost 160 bits of the SHA-256 of the key bits, RFC 7093) unless one is in <see cref="Extensions"/>. Default true.</summary>
    public bool AddSubjectKeyIdentifier { get; init; } = true;

    /// <summary>Adds an authorityKeyIdentifier from the issuer unless one is in <see cref="Extensions"/>. Default true.</summary>
    public bool AddAuthorityKeyIdentifier { get; init; } = true;
}

/// <summary>Issues certificates (RFC 5280 §4.1). The result is an ordinary parsed <see cref="Certificate"/> over the new DER.</summary>
public static class CertificateBuilder
{
    /// <summary>Issues a certificate signed by its own key.</summary>
    /// <exception cref="ArgumentException">The validity period ends before it starts, or the serial number is longer than 20 octets.</exception>
    public static Certificate CreateSelfSigned(CertificateOptions options, X509Signer signer, CryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signer);
        return Build(options, options.Subject, signer.PublicKey, null, signer, policy);
    }

    /// <summary>Issues a certificate signed by <paramref name="issuer"/>'s key (held by <paramref name="signer"/>).</summary>
    public static Certificate Create(CertificateOptions options, Certificate issuer, X509Signer signer, CryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(signer);
        if (options.PublicKey is null)
        {
            throw new ArgumentException("A certificate for another subject needs the subject's public key.", nameof(options));
        }

        return Build(options, issuer.Subject, issuer.PublicKey, issuer, signer, policy);
    }

    /// <summary>
    /// Phase one of issuing a self-signed certificate in two steps: builds the to-be-signed certificate and returns the state to sign. Phase two is
    /// <see cref="Complete"/>. <paramref name="signerKey"/> is the certificate's own key.
    /// </summary>
    /// <exception cref="PolicyViolationException">The policy rejects the signature hash or the key at <paramref name="at"/>.</exception>
    public static PreparedSignature PrepareSelfSigned(CertificateOptions options, PublicKeyInfo signerKey, SignatureSpec spec, CryptoPolicy policy, DateTimeOffset at) =>
        X509TwoPhase.Prepare(PurposeCertificate, signerKey, spec, policy, at, s => CreateSelfSigned(options, s));

    /// <summary>Phase one of issuing a certificate signed by <paramref name="issuer"/>'s key in two steps; see <see cref="PrepareSelfSigned"/>.</summary>
    public static PreparedSignature Prepare(CertificateOptions options, Certificate issuer, SignatureSpec spec, CryptoPolicy policy, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        return X509TwoPhase.Prepare(PurposeCertificate, issuer.PublicKey, spec, policy, at, s => Create(options, issuer, s));
    }

    /// <summary>Phase two: checks <paramref name="signature"/> against the issuer's key and returns the certificate.</summary>
    /// <exception cref="InvalidSignatureException">The signature does not verify.</exception>
    public static Certificate Complete(PreparedSignature prepared, ReadOnlySpan<byte> signature) =>
        Certificate.Parse(X509TwoPhase.Complete(prepared, PurposeCertificate, signature));

    private const string PurposeCertificate = "x509.certificate";

    private static Certificate Build(CertificateOptions o, DistinguishedName issuerName, PublicKeyInfo issuerKey, Certificate? issuer, X509Signer signer, CryptoPolicy? policy)
    {
        if (o.NotAfter < o.NotBefore)
        {
            throw new ArgumentException("NotAfter is before NotBefore.", nameof(o));
        }

        PublicKeyInfo subjectKey = o.PublicKey ?? signer.PublicKey;
        byte[] serial = o.SerialNumber.IsEmpty ? BuildHelpers.RandomSerial() : o.SerialNumber.ToArray();
        if (serial.Length > 20)
        {
            throw new ArgumentException("A serial number is at most 20 octets.", nameof(o));
        }

        var exts = new List<Extension>(o.Extensions);
        if (o.AddSubjectKeyIdentifier && !exts.Any(e => e.Oid == KnownOids.SubjectKeyIdentifier))
        {
            exts.Add(Extension.Create(new SubjectKeyIdentifier(BuildHelpers.KeyIdentifier(subjectKey)), false));
        }

        if (o.AddAuthorityKeyIdentifier && !exts.Any(e => e.Oid == KnownOids.AuthorityKeyIdentifier))
        {
            // RFC 5280 §4.2.1.1: the issuer's own key identifier when it has one, otherwise a hash of its key.
            ReadOnlyMemory<byte> id = issuer?.SubjectKeyIdentifier?.KeyIdentifier ?? BuildHelpers.KeyIdentifier(issuerKey);
            exts.Add(Extension.Create(new AuthorityKeyIdentifier(id), false));
        }

        byte[] tbs = DerWriter.Sequence(
            exts.Count > 0 ? DerWriter.Context(0, DerWriter.SignedInteger(2)) : [],
            BuildHelpers.UnsignedInt(serial),
            signer.SignatureAlgorithm.Encoded.ToArray(),
            issuerName.Encoded.ToArray(),
            DerWriter.Sequence(BuildHelpers.Time(o.NotBefore), BuildHelpers.Time(o.NotAfter)),
            o.Subject.Encoded.ToArray(),
            subjectKey.Encoded.ToArray(),
            exts.Count > 0 ? DerWriter.Context(3, BuildHelpers.Extensions(exts)) : []);
        return Certificate.Parse(BuildHelpers.Signed(tbs, signer, policy));
    }
}
