using System.Linq;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

public sealed partial class SignedData
{
    // id-ri-ocsp-response (RFC 6960 §4.2.1 via RFC 5940 §4.2): an OCSPResponse carried as OtherRevocationInfoFormat in the revocation set.
    private const string IdRiOcspResponse = "1.3.6.1.5.5.7.16.2";

    /// <summary>
    /// Builds the options the path validator runs with for this message: the caller's anchors, policy, reference time and revocation data, plus the certificates
    /// of the message as untrusted intermediates and the CRLs and OCSP responses it carries as revocation data. Nothing in the message is trusted by being there.
    /// </summary>
    private ValidationOptions ChainOptions(ValidationOptions chain, IReadOnlyList<Certificate> extra)
    {
        var intermediates = new List<Certificate>(chain.Intermediates);
        intermediates.AddRange(Certificates);
        intermediates.AddRange(extra);

        var crls = new List<CertificateRevocationList>(chain.Revocation?.Crls ?? []);
        crls.AddRange(Crls);
        var ocsp = new List<OcspBasicResponse>(chain.Revocation?.OcspResponses ?? []);
        foreach (ReadOnlyMemory<byte> e in RevocationElements)
        {
            if (TryReadOcspElement(e, out OcspBasicResponse? basic))
            {
                ocsp.Add(basic!);
            }
        }

        // With no revocation data at all the validator is told so by a null, not an empty set: an empty set would make it look every certificate up and
        // report "unknown" for the ones nobody asked about.
        RevocationData? revocation = crls.Count == 0 && ocsp.Count == 0 ? null : new RevocationData { Crls = crls, OcspResponses = ocsp };
        return PathValidator.With(chain, intermediates, revocation);
    }

    private static bool TryReadOcspElement(ReadOnlyMemory<byte> element, out OcspBasicResponse? basic)
    {
        basic = null;
        try
        {
            // other [1] IMPLICIT OtherRevocationInfoFormat { otherRevInfoFormat OID, otherRevInfo ANY }
            var r = new Asn1Reader(element.Span, Asn1Rules.Ber);
            if (!r.TryReadAnyContent(out Asn1Tag tag, out ReadOnlySpan<byte> content) || tag != Asn1Tag.Context(1, true))
            {
                return false;
            }

            var inner = new Asn1Reader(content, Asn1Rules.Ber);
            if (inner.ReadObjectIdentifier() != IdRiOcspResponse)
            {
                return false;
            }

            ReadOnlySpan<byte> value = inner.ReadEncodedValue();
            if (!OcspResponse.TryParse(value.ToArray(), out OcspResponse? resp) || resp?.BasicResponse is not { } b)
            {
                return false;
            }

            basic = b;
            return true;
        }
        catch (Asn1ParseException)
        {
            return false;
        }
    }

    // RFC 5280 §6: the signer's certificate must chain to a trust anchor of the caller's choosing, at the caller's reference time. The signing-time
    // attribute is only a claim of the signer, so it is never the reference time; to ask "was it valid when signed" pass a proven time (a timestamp's genTime).
    private static CmsCheck CheckChain(Certificate cert, ValidationOptions chainOptions, out ValidationReport report)
    {
        const string clause = "RFC 5280 §6";
        report = PathValidator.Validate(cert, chainOptions);
        switch (report.Verdict)
        {
            case ValidationVerdict.Valid:
                return report.RevocationSummary is RevocationStatus.Unknown
                    ? new CmsCheck("chain", CmsCheckStatus.Warning, "The certificate chains to a trust anchor, but no revocation data settled whether it is revoked.", clause)
                    : new CmsCheck("chain", CmsCheckStatus.Passed, string.Empty, clause);
            case ValidationVerdict.Indeterminate:
                return new CmsCheck("chain", CmsCheckStatus.Unsupported, "The path could not be decided: " + (report.DecidingRule?.Reason ?? "unknown"), clause);
            default:
                return new CmsCheck("chain", CmsCheckStatus.Failed, "The certificate does not validate: " + (report.DecidingRule?.Reason ?? "no path to a trust anchor"), clause);
        }
    }
}
