using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;
using Xunit;

namespace RecursiveAI.OneCrypto.Pdf.Tests;

/// <summary>The kinds of signing key the round trips cover.</summary>
public enum KeyKind
{
    Rsa2048,
    P256,
    P384,
}

/// <summary>A signer: certificate, key and the chain to embed.</summary>
internal sealed record TestSigner(Certificate Certificate, ISigningKey Key, IReadOnlyList<Certificate> Chain);

/// <summary>
/// A throwaway PKI built with the library itself (root, intermediate, signers of each key kind, a time-stamp authority), the revocation
/// data for it, and a one-page PDF to sign. Generated fresh in every run: nothing here is a real key.
/// </summary>
internal sealed class PadesKit
{
    private static readonly Lazy<PadesKit> Instance = new(() => new PadesKit());

    private readonly Dictionary<string, TestSigner> _signers = [];

    private PadesKit()
    {
        Now = DateTimeOffset.UtcNow;
        var rootKey = RSA.Create(3072);
        var opts = new CertificateAuthorityOptions { CrlUrls = ["http://pki.example.test/ca.crl"], OcspUrls = ["http://ocsp.example.test/"] };
        Root = CertificateAuthority.CreateRoot(DistinguishedName.Create((KnownOids.CommonName, "Test Root")), X509Signer.FromRsa(rootKey, HashAlgorithmName.SHA256), Now.AddDays(-900), TimeSpan.FromDays(3650), opts);
        InterKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Certificate inter = Root.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(InterKey), DistinguishedName.Create((KnownOids.CommonName, "Test Intermediate")),
            new CertificateIssueOptions { Profile = CertificateProfile.Intermediate, NotBefore = Now.AddDays(-800), Validity = TimeSpan.FromDays(1800) });
        Intermediate = new CertificateAuthority(inter, X509Signer.FromECDsa(InterKey), opts);
        TsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        TsaCertificate = Intermediate.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(TsaKey), DistinguishedName.Create((KnownOids.CommonName, "Test Time-Stamp Authority")),
            new CertificateIssueOptions { Profile = CertificateProfile.TimeStamping, NotBefore = Now.AddDays(-700), Validity = TimeSpan.FromDays(900) });
        Authority = new TimeStampAuthority(new TimeStampAuthorityOptions
        {
            Certificate = TsaCertificate,
            Signer = X509Signer.FromECDsa(TsaKey),
            DefaultPolicy = "1.2.3.4.5",
            ChainCertificates = [inter],
        }, new CounterTimeStampSerialSource(1000));
    }

    public static PadesKit Shared => Instance.Value;

    /// <summary>The instant the PKI was generated; "now" for the tests, so they never read the clock again.</summary>
    public DateTimeOffset Now { get; }

    public CertificateAuthority Root { get; }

    public CertificateAuthority Intermediate { get; }

    public ECDsa InterKey { get; }

    public ECDsa TsaKey { get; }

    public Certificate TsaCertificate { get; }

    public TimeStampAuthority Authority { get; }

    public TrustAnchor Anchor => TrustAnchor.FromCertificate(Root.Certificate);

    public Certificate[] Chain => [Intermediate.Certificate];

    /// <summary>A signer of the kind, valid from 400 days ago for almost two years unless told otherwise.</summary>
    public TestSigner Signer(KeyKind kind, string? name = null, DateTimeOffset? notBefore = null, TimeSpan? validity = null)
    {
        string id = $"{kind}/{name}/{notBefore}/{validity}";
        lock (_signers)
        {
            if (_signers.TryGetValue(id, out TestSigner? have))
            {
                return have;
            }

            ISigningKey key = kind switch
            {
                KeyKind.Rsa2048 => PrivateKey.FromRsa(RSA.Create(2048), ownsKey: true),
                KeyKind.P256 => PrivateKey.FromECDsa(ECDsa.Create(ECCurve.NamedCurves.nistP256), ownsKey: true),
                _ => PrivateKey.FromECDsa(ECDsa.Create(ECCurve.NamedCurves.nistP384), ownsKey: true),
            };
            Certificate cert = Intermediate.Issue(key.PublicKey, DistinguishedName.Create((KnownOids.CommonName, name ?? $"Test Signer {kind}")), new CertificateIssueOptions
            {
                Profile = CertificateProfile.SMime,
                NotBefore = notBefore ?? Now.AddDays(-400),
                Validity = validity ?? TimeSpan.FromDays(700),
                SubjectAlternativeNames = [GeneralName.Email("signer@example.test")],
            });
            return _signers[id] = new TestSigner(cert, key, Chain);
        }
    }

    /// <summary>A time-stamp function backed by the library's own authority, stamping at <paramref name="at"/>.</summary>
    public PadesTimestampFunction Tsa(Func<DateTimeOffset> at, Action<TimeStampRequest>? seen = null) => (request, ct) =>
    {
        seen?.Invoke(request);
        return ValueTask.FromResult(Authority.Handle(request.Encoded, at()).Encoded.ToArray());
    };

    public PadesTimestampFunction Tsa(DateTimeOffset at) => Tsa(() => at);

    /// <summary>CRLs from the intermediate (for its certificates) and the root (for the intermediate), dated at <paramref name="thisUpdate"/>, listing <paramref name="revoked"/>.</summary>
    public RevocationData Crls(DateTimeOffset thisUpdate, params Certificate[] revoked)
    {
        CertificateRevocationList inter = Intermediate.IssueCrl(new CrlIssueOptions
        {
            ThisUpdate = thisUpdate,
            NextUpdate = thisUpdate.AddDays(30),
            Number = 7,
            Revoked = [.. revoked.Select(r => new RevokedCertificateInfo(r.SerialNumberValue, thisUpdate.AddDays(-1), RevocationReason.Superseded))],
        });
        CertificateRevocationList root = Root.IssueCrl(new CrlIssueOptions { ThisUpdate = thisUpdate, NextUpdate = thisUpdate.AddDays(30), Number = 3 });
        return new RevocationData { Crls = [inter, root] };
    }

    /// <summary>An OCSP response from the intermediate for each certificate (good).</summary>
    public RevocationData Ocsp(DateTimeOffset at, params Certificate[] certificates)
    {
        var source = new InMemoryRevocationSource(TimeSpan.FromDays(2));
        foreach (Certificate c in certificates)
        {
            source.SetGood(c.SerialNumber.Span);
        }

        var responder = new OcspResponder(new OcspResponderOptions { Issuer = Intermediate.Certificate, ResponderCertificate = Intermediate.Certificate, Signer = X509Signer.FromECDsa(InterKey), Source = source });
        OcspRequest request = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [.. certificates.Select(c => OcspCertId.Create(c, Intermediate.Certificate))] });
        return new RevocationData { OcspResponses = [responder.Handle(request.Encoded, at).BasicResponse!] };
    }

    public static RevocationData Merge(params RevocationData[] parts) => new()
    {
        Crls = [.. parts.SelectMany(static p => p.Crls)],
        OcspResponses = [.. parts.SelectMany(static p => p.OcspResponses)],
    };

    public PadesValidationData Validation(DateTimeOffset at, RevocationData? revocation) => new()
    {
        TrustAnchors = [Anchor],
        Intermediates = Chain,
        ReferenceTime = at,
        Revocation = revocation,
    };

    public PadesVerifyOptions Verify(DateTimeOffset at, RevocationData? revocation = null, Func<PadesVerifyOptions, PadesVerifyOptions>? tweak = null)
    {
        var o = new PadesVerifyOptions { TrustAnchors = [Anchor], Intermediates = Chain, ReferenceTime = at, Revocation = revocation };
        return tweak?.Invoke(o) ?? o;
    }

    /// <summary>A one-page PDF 1.7 with a line of text.</summary>
    public static byte[] Pdf(string text = "Hello, signature")
    {
        string stream = $"BT /F1 18 Tf 40 700 Td ({text}) Tj ET";
        string[] objects =
        [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            $"<< /Length {stream.Length} >>\nstream\n{stream}\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ];
        var sb = new StringBuilder("%PDF-1.7\n%\u00e2\u00e3\u00cf\u00d3\n");
        var offsets = new List<int>();
        for (int i = 0; i < objects.Length; i++)
        {
            offsets.Add(sb.Length);
            sb.Append(i + 1).Append(" 0 obj\n").Append(objects[i]).Append("\nendobj\n");
        }

        int xref = sb.Length;
        sb.Append("xref\n0 ").Append(objects.Length + 1).Append("\n0000000000 65535 f \n");
        foreach (int o in offsets)
        {
            sb.Append(o.ToString("D10", System.Globalization.CultureInfo.InvariantCulture)).Append(" 00000 n \n");
        }

        sb.Append("trailer\n<< /Size ").Append(objects.Length + 1).Append(" /Root 1 0 R >>\nstartxref\n").Append(xref).Append("\n%%EOF\n");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }
}
