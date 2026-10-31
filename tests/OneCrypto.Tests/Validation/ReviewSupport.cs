using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Validation;

/// <summary>A key and the certificate issued for it, for the adversarial chains of the verdict review.</summary>
internal sealed class RNode : IDisposable
{
    public static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly ECDsa _key;

    private RNode(ECDsa key, X509Signer signer, Certificate certificate)
    {
        _key = key;
        Signer = signer;
        Certificate = certificate;
    }

    public X509Signer Signer { get; }

    public Certificate Certificate { get; }

    public static Extension CaBasic { get; } = Extension.Create(new BasicConstraints(true), true);

    public static Extension CaUsage { get; } = Extension.Create(new KeyUsageExtension(KeyUsages.KeyCertSign | KeyUsages.CrlSign | KeyUsages.DigitalSignature), true);

    /// <summary>Issues a certificate for a fresh key (or <paramref name="key"/>), self-signed when <paramref name="issuer"/> is null.</summary>
    public static RNode Make(
        string cn,
        RNode? issuer,
        bool ca,
        IReadOnlyList<Extension>? extra = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        DistinguishedName? subject = null,
        string leafName = "leaf.example.test")
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Signer signer = X509Signer.FromECDsa(key);
        var ext = new List<Extension>();
        if (ca)
        {
            ext.Add(CaBasic);
            ext.Add(CaUsage);
        }
        else
        {
            ext.Add(Extension.Create(new BasicConstraints(false), true));
            ext.Add(Extension.Create(new SubjectAlternativeName([GeneralName.Dns(leafName)]), false));
            ext.Add(Extension.Create(new ExtendedKeyUsage([KnownOids.ServerAuth]), false));
        }

        foreach (Extension x in extra ?? [])
        {
            ext.RemoveAll(e => e.Oid == x.Oid);
            ext.Add(x);
        }

        var o = new CertificateOptions
        {
            Subject = subject ?? DistinguishedName.FromString("CN=" + cn),
            PublicKey = PublicKeyInfo.FromAsymmetricAlgorithm(key),
            NotBefore = notBefore ?? Now.AddYears(-1),
            NotAfter = notAfter ?? Now.AddYears(1),
            Extensions = ext,
        };
        Certificate cert = issuer is null ? CertificateBuilder.CreateSelfSigned(o, signer) : CertificateBuilder.Create(o, issuer.Certificate, issuer.Signer);
        return new RNode(key, signer, cert);
    }

    /// <summary>Another certificate for the same key and name as <paramref name="node"/>, issued by <paramref name="issuer"/> with the given extensions.</summary>
    public static Certificate Reissue(RNode node, RNode issuer, IReadOnlyList<Extension> extensions, DateTimeOffset? notAfter = null) =>
        CertificateBuilder.Create(
            new CertificateOptions
            {
                Subject = node.Certificate.Subject,
                PublicKey = node.Certificate.PublicKey,
                NotBefore = Now.AddYears(-1),
                NotAfter = notAfter ?? Now.AddYears(1),
                Extensions = extensions,
            },
            issuer.Certificate,
            issuer.Signer);

    public static System.Numerics.BigInteger Serial(Certificate c) => new(c.SerialNumber.Span, isUnsigned: false, isBigEndian: true);

    public static ValidationOptions Options(IEnumerable<RNode> anchors, IEnumerable<Certificate>? pool = null, RevocationData? revocation = null, RevocationScope scope = RevocationScope.None, bool fatal = false) => new()
    {
        TrustAnchors = [.. anchors.Select(a => TrustAnchor.FromCertificate(a.Certificate))],
        Intermediates = [.. pool ?? []],
        ReferenceTime = Now,
        Revocation = revocation,
        RevocationRequired = scope,
        UnknownRevocationIsFatal = fatal,
    };

    public static CertificateRevocationList Crl(RNode issuer, IReadOnlyList<RevokedCertificateInfo>? revoked = null, IReadOnlyList<Extension>? extensions = null, int number = 1) =>
        RevocationListBuilder.Create(
            new RevocationListOptions
            {
                ThisUpdate = Now.AddDays(-1),
                NextUpdate = Now.AddDays(6),
                Number = number,
                Revoked = revoked ?? [],
                Extensions = extensions ?? [],
            },
            issuer.Signer,
            issuer.Certificate);

    public void Dispose() => _key.Dispose();
}
