using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Fuzz;

/// <summary>
/// The issuer-side handlers, end to end, as two fuzz targets (<c>tsa</c> and <c>ocspresp</c>). The first byte picks a surface: the time-stamp authority (request
/// octets in, response out) and the time-stamp request, response and TSTInfo parsers; or the OCSP responder (request octets in, response out) and the CA's CSR path. A handler must answer every input with a response
/// and never throw; every granted time-stamp must verify against the request that was parsed from the same octets, and every successful OCSP response must verify
/// against the responder's key and echo the request's certificate ids.
/// </summary>
internal static class IssuerTarget
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly Lazy<Rig> Shared = new(() => new Rig());

    private sealed class Rig
    {
        public readonly CertificateAuthority Ca;
        public readonly Certificate Tsa, Leaf;
        public readonly TimeStampAuthority Authority;
        public readonly OcspResponder Responder;
        public readonly OcspResponder DelegatedResponder;
        public readonly Certificate DelegatedCertificate;

        public Rig()
        {
            var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Ca = CertificateAuthority.CreateRoot(DistinguishedName.Create((KnownOids.CommonName, "Fuzz CA")), X509Signer.FromECDsa(caKey), Now.AddDays(-30), TimeSpan.FromDays(3650));
            var tsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Tsa = Ca.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(tsaKey), DistinguishedName.Create((KnownOids.CommonName, "Fuzz TSA")), new CertificateIssueOptions { Profile = CertificateProfile.TimeStamping, NotBefore = Now.AddDays(-1) });
            Authority = new TimeStampAuthority(new TimeStampAuthorityOptions
            {
                Certificate = Tsa, Signer = X509Signer.FromECDsa(tsaKey), DefaultPolicy = "1.2.3.4.1", AcceptedPolicies = ["1.2.3.4.5"], Accuracy = new TimeStampAccuracy(1),
            }, new CounterTimeStampSerialSource());
            var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Leaf = Ca.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(leafKey), DistinguishedName.Create((KnownOids.CommonName, "Fuzz leaf")), new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = Now.AddDays(-1) });
            var source = new InMemoryRevocationSource(TimeSpan.FromHours(1));
            source.SetGood(Leaf.SerialNumber.Span);
            Responder = new OcspResponder(new OcspResponderOptions { Issuer = Ca.Certificate, ResponderCertificate = Ca.Certificate, Signer = X509Signer.FromECDsa(caKey), Source = source });
            var delKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            DelegatedCertificate = Ca.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(delKey), DistinguishedName.Create((KnownOids.CommonName, "Fuzz responder")), new CertificateIssueOptions { Profile = CertificateProfile.OcspSigning, NotBefore = Now.AddDays(-1) });
            DelegatedResponder = new OcspResponder(new OcspResponderOptions
            {
                Issuer = Ca.Certificate, ResponderCertificate = DelegatedCertificate, Signer = X509Signer.FromECDsa(delKey), Source = source, ResponderId = OcspResponderIdKind.ByName,
            });
        }
    }

    /// <summary>The time-stamp surface: the first byte picks the authority handler (half the inputs), the request, response or TSTInfo parser.</summary>
    public static void RunTsa(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        Rig rig = Shared.Value;
        byte[] rest = data[1..].ToArray();
        switch (data[0] % 8)
        {
            case 0 or 1 or 2 or 3:
                Tsa(rig, rest);
                break;
            case 4:
                if (TimeStampRequest.TryParse(rest, out TimeStampRequest? q) && q is not null)
                {
                    _ = q.Extensions.Count + q.Nonce.Length + q.MessageImprint.Length;
                    _ = q.HashAlgorithm.Name;
                }

                break;
            case 5 or 6:
                if (TimeStampResponse.TryParse(rest, out TimeStampResponse? r) && r is not null)
                {
                    _ = r.StatusStrings.Count;
                    _ = r.Token?.Signers.Count;
                    // A response that parses is checked against a request of our own; it must be reported, never thrown.
                    _ = TimeStampVerifier.Verify(TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = new byte[32] }), rest);
                }

                break;
            default:
                if (TstInfo.TryParse(rest, out TstInfo? t) && t is not null)
                {
                    _ = t.GenTime;
                    _ = t.Extensions.Count;
                    _ = t.Tsa?.ToString();
                }

                break;
        }
    }

    /// <summary>The OCSP responder (CA-signed or delegated, by the first byte's top bit) and the CA's certification request path.</summary>
    public static void RunOcsp(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        Rig rig = Shared.Value;
        byte[] rest = data[1..].ToArray();
        if (data[0] % 8 == 7)
        {
            if (CertificateSigningRequest.TryParse(rest, out CertificateSigningRequest? csr) && csr is not null)
            {
                try
                {
                    _ = rig.Ca.Issue(csr, new CertificateIssueOptions { Profile = CertificateProfile.TlsServer, NotBefore = Now });
                }
                catch (Exception e) when (e is IssuanceException or RecursiveAI.OneCrypto.Policy.PolicyViolationException)
                {
                }
            }

            return;
        }

        bool delegated = data[0] >= 128;
        Ocsp(rig, rest, delegated ? rig.DelegatedResponder : rig.Responder, delegated ? rig.DelegatedCertificate : null);
    }

    private static void Tsa(Rig rig, byte[] request)
    {
        TimeStampResponse resp = rig.Authority.Handle(request, Now);
        if (resp.Status == TimeStampStatus.Granted)
        {
            TimeStampRequest req = TimeStampRequest.Parse(request);
            // Without certReq the token carries no certificate, so the caller supplies it.
            TimeStampReport report = TimeStampVerifier.Verify(req, resp.Encoded, new TimeStampVerifyOptions { ExtraCertificates = [rig.Tsa] });
            if (!report.IsValid)
            {
                throw new InvalidOperationException("A granted token does not verify against its request: " + string.Join("; ", report.Checks.Where(static c => c.Status is CmsCheckStatus.Failed or CmsCheckStatus.Unsupported).Select(static c => c.Rule)));
            }
        }
        else if (resp.Status != TimeStampStatus.Rejection || resp.FailureInfo == TimeStampFailure.None)
        {
            throw new InvalidOperationException("A refusal must be a rejection with failure bits.");
        }
    }

    private static void Ocsp(Rig rig, byte[] request, OcspResponder responder, Certificate? del)
    {
        OcspResponse resp = responder.Handle(request, Now);
        if (resp.Status != OcspResponseStatus.Successful)
        {
            return;
        }

        OcspRequest req = OcspRequest.Parse(request);
        OcspBasicResponse b = resp.BasicResponse!;
        PublicKeyInfo key = (del ?? rig.Ca.Certificate).PublicKey;
        if (!b.VerifySignature(key).IsValid || b.Responses.Count != req.Requests.Count)
        {
            throw new InvalidOperationException("A successful OCSP response does not verify or does not answer every request.");
        }

        for (int i = 0; i < b.Responses.Count; i++)
        {
            if (!b.Responses[i].CertId.Equals(req.Requests[i].CertId))
            {
                throw new InvalidOperationException("An OCSP answer names another certificate than the request.");
            }
        }

        if (req.Nonce is { } n && !(b.Nonce?.Span.SequenceEqual(n.Span) ?? false))
        {
            throw new InvalidOperationException("The nonce was not echoed.");
        }
    }

    public static IEnumerable<byte[]> SeedsTsa() => Seeds().Take(4);

    public static IEnumerable<byte[]> SeedsOcsp() => Seeds().Skip(4);

    private static IEnumerable<byte[]> Seeds()
    {
        Rig rig = Shared.Value;
        TimeStampRequest tsReq = TimeStampRequest.Create(new TimeStampRequestOptions { Hash = HashAlgorithmName.SHA256, MessageImprint = SHA256.HashData([1, 2, 3]), Nonce = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08 }, Policy = "1.2.3.4.5" });
        TimeStampResponse tsResp = rig.Authority.Handle(tsReq.Encoded, Now);
        yield return [0, .. tsReq.Encoded.Span];
        yield return [4, .. tsReq.Encoded.Span];
        yield return [5, .. tsResp.Encoded.Span];
        yield return [7, .. TstInfo.FromSignedData(tsResp.Token!).Encoded.Span];
        OcspRequest oReq = OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [OcspCertId.Create(rig.Leaf, rig.Ca.Certificate), OcspCertId.Create(rig.Tsa, rig.Ca.Certificate, HashAlgorithmName.SHA256)], Nonce = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 } });
        yield return [0, .. oReq.Encoded.Span];
        yield return [128, .. oReq.Encoded.Span];
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        yield return [7, .. CertificateSigningRequestBuilder.Create(new CertificateSigningRequestOptions { Subject = DistinguishedName.Create((KnownOids.CommonName, "seed")), Extensions = [Extension.Create(new SubjectAlternativeName([GeneralName.Dns("seed.example.test")]), false)] }, X509Signer.FromECDsa(key)).Encoded.Span];
    }
}
