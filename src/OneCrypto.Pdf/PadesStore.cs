using System.Security.Cryptography;
using OnePdf;
using RecursiveAI.OneCrypto.Tsp;
using RecursiveAI.OneCrypto.Validation;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;
using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto.Pdf;

/// <summary>Collects the validation data of every signature and time-stamp in a file and writes it into the document security store.</summary>
internal static class PadesStore
{
    /// <summary>The objects one signature (or time-stamp) needs, ready to be keyed in /VRI.</summary>
    internal sealed class Needs
    {
        public required string VriKey { get; init; }

        public List<Certificate> Certificates { get; } = [];

        public List<CertificateRevocationList> Crls { get; } = [];

        public List<OcspBasicResponse> Ocsp { get; } = [];
    }

    /// <summary>
    /// Finds, for each signature, signature time-stamp and document time-stamp in <paramref name="doc"/>, the path from its certificate to
    /// a trust anchor and the revocation data that applies to the path. Data comes from <see cref="PadesValidationData.Revocation"/> and
    /// from the sources; nothing else is looked up. Throws <see cref="PadesException"/> with <see cref="PadesError.NoChain"/> when a
    /// certificate has no path.
    /// </summary>
    public static async ValueTask<List<Needs>> CollectAsync(PdfDocument doc, ReadOnlyMemory<byte> pdf, PadesValidationData vd, CancellationToken ct)
    {
        if (vd.TrustAnchors.Count == 0)
        {
            throw new PadesException(PadesError.NoChain, "Collecting validation data needs trust anchors: the chain of each certificate is found from them.");
        }

        DssStore existing = DssStore.Read(doc);
        var pool = new List<Certificate>(vd.Intermediates);
        pool.AddRange(existing.Certificates.Select(static c => c.Value));
        var targets = new List<(string Key, Certificate Cert, DateTimeOffset At, bool Tsa)>();
        var found = new List<(SignedData Cms, PdfSignature Sig, byte[] Contents)>();
        foreach (PdfSignature sig in doc.GetSignatures())
        {
            ct.ThrowIfCancellationRequested();
            if (!PdfLayout.TryRanges(sig, pdf.Span, out long a, out long b, out _) || !PdfLayout.TryContentsBytes(pdf.Span, a, b, out byte[] contents))
            {
                continue;
            }

            if (SignedData.TryParse(contents, out SignedData? cms, null, allowTrailingZeros: true) && cms is not null)
            {
                found.Add((cms, sig, contents));
                pool.AddRange(cms.Certificates);
            }
        }

        foreach ((SignedData cms, PdfSignature sig, byte[] contents) in found)
        {
            string key = PdfLayout.VriKey(contents);
            if (sig.SubFilter == "ETSI.RFC3161")
            {
                if (TokenInfo(cms, pool) is { } t)
                {
                    targets.Add((key, t.Cert, t.GenTime, true));
                    pool.AddRange(cms.Certificates);
                }

                continue;
            }

            DateTimeOffset signerAt = vd.ReferenceTime;
            if (cms.Signers.Count == 1 && cms.Signers[0].FindUnsigned(CmsOids.SignatureTimeStampToken) is { Values.Count: > 0 } attr
                && SignedData.TryParse(attr.Values[0], out SignedData? token, null, allowTrailingZeros: true) && token is not null)
            {
                pool.AddRange(token.Certificates);
                if (TokenInfo(token, pool) is { } t)
                {
                    targets.Add((key, t.Cert, t.GenTime, true));
                    signerAt = t.GenTime < signerAt ? t.GenTime : signerAt;
                }
            }

            SignedDataReport report = cms.Verify(ReadOnlySpan<byte>.Empty, new SignedDataVerifyOptions { ExtraCertificates = pool });
            if (report.Signers.Count > 0 && report.Signers[0].Certificate is { } signerCert)
            {
                targets.Add((key, signerCert, signerAt, false));
            }
        }

        var result = new Dictionary<string, Needs>(StringComparer.Ordinal);
        foreach ((string key, Certificate cert, DateTimeOffset at, bool tsa) in targets)
        {
            ct.ThrowIfCancellationRequested();
            ValidationReport report = await PathValidator.ValidateAsync(cert, new ValidationOptions
            {
                TrustAnchors = vd.TrustAnchors,
                Intermediates = pool,
                ReferenceTime = at,
                Policy = vd.Policy,
                RequiredExtendedKeyUsage = tsa ? KnownOids.TimeStamping : null,
                CertificateSource = vd.CertificateSource,
            }, ct).ConfigureAwait(false);
            if (report.SelectedPath is not { } path)
            {
                throw new PadesException(PadesError.NoChain, $"No path from {cert.Subject} to a trust anchor was found at {at:u}: {report.DecidingRule?.Reason ?? "no issuer"}.");
            }

            if (!result.TryGetValue(key, out Needs? needs))
            {
                result[key] = needs = new Needs { VriKey = key };
            }

            for (int i = 0; i < path.Certificates.Length; i++)
            {
                CertificateReport cr = path.Certificates[i];
                if (cr.IsTrustAnchor)
                {
                    if (vd.IncludeAnchors)
                    {
                        needs.Certificates.Add(cr.Certificate);
                    }

                    continue;
                }

                needs.Certificates.Add(cr.Certificate);
                Certificate? issuer = i == 0 ? path.AnchorCertificate : path.Certificates[i - 1].Certificate;
                if (issuer is null)
                {
                    continue;
                }

                await AddRevocation(needs, cr.Certificate, issuer, vd, ct).ConfigureAwait(false);
            }
        }

        return [.. result.Values];
    }

    private static (Certificate Cert, DateTimeOffset GenTime)? TokenInfo(SignedData token, List<Certificate> pool)
    {
        if (!token.HasEncapsulatedContent || token.EncapsulatedContentType != CmsOids.TstInfo)
        {
            return null;
        }

        TstInfo info;
        try
        {
            info = TstInfo.FromSignedData(token);
        }
        catch (TimeStampParseException)
        {
            return null;
        }

        SignedDataReport report = token.Verify(new SignedDataVerifyOptions { ExtraCertificates = pool });
        return report.Signers.Count > 0 && report.Signers[0].Certificate is { } cert ? (cert, info.GenTime) : null;
    }

    private static async ValueTask AddRevocation(Needs needs, Certificate cert, Certificate issuer, PadesValidationData vd, CancellationToken ct)
    {
        var candidates = new List<RevocationData>();
        if (vd.Revocation is { } supplied)
        {
            candidates.Add(supplied);
        }

        if (vd.RevocationSource is { } source)
        {
            List<string> crlUris = [];
            List<string> ocspUris = [];
            try
            {
                crlUris = [.. cert.Extensions.Get<CrlDistributionPoints>()?.Points.Select(static p => p.Name?.FullName).Where(static n => n is not null).SelectMany(static n => n!).Where(static n => n.Kind == GeneralNameKind.Uri).Select(static n => n.Value!) ?? []];
                ocspUris = [.. cert.Extensions.Get<AuthorityInfoAccess>()?.UrisFor(KnownOids.AdOcsp) ?? []];
            }
            catch (X509ParseException)
            {
                // A certificate whose locations cannot be read is asked about with none.
            }

            candidates.Add(await source.GetRevocationDataAsync(cert, issuer, crlUris, ocspUris, ct).ConfigureAwait(false));
        }

        foreach (RevocationData data in candidates)
        {
            foreach (CertificateRevocationList crl in data.Crls)
            {
                if (crl.Issuer.Matches(issuer.Subject) && !needs.Crls.Contains(crl))
                {
                    needs.Crls.Add(crl);
                }
            }

            foreach (OcspBasicResponse r in data.OcspResponses)
            {
                if (r.Responses.Any(s => s.CertId.Matches(cert, issuer)) && !needs.Ocsp.Contains(r))
                {
                    needs.Ocsp.Add(r);
                }
            }
        }
    }

    /// <summary>
    /// Writes the needs into the /DSS dictionary as an incremental update (ISO 32000-2 §12.8.4.2): new streams for objects the store lacks,
    /// the old entries kept, and one /VRI entry per signature keyed by the hash of its signature (§12.8.4.3). Returns false when nothing
    /// new was added.
    /// </summary>
    public static bool Apply(PdfDocument doc, DssStore existing, List<Needs> needs, DateTimeOffset at, bool writeVri)
    {
        var refs = new Dictionary<string, PdfReference>(StringComparer.Ordinal);
        foreach (StoredItem<Certificate> c in existing.Certificates)
        {
            Keep(refs, "C" + Id(c.Value.Encoded.Span), c.Reference);
        }

        foreach (StoredItem<CertificateRevocationList> c in existing.Crls)
        {
            Keep(refs, "L" + Id(c.Value.Encoded.Span), c.Reference);
        }

        foreach (StoredItem<OcspBasicResponse> c in existing.Ocsp)
        {
            Keep(refs, "O" + Id(c.Value.Encoded.Span), c.Reference);
        }

        var certs = new List<PdfReference>(existing.Certificates.Select(static c => c.Reference).OfType<PdfReference>().Select(static r => new PdfReference(r.Number, r.Generation)));
        var crls = new List<PdfReference>(existing.Crls.Select(static c => c.Reference).OfType<PdfReference>().Select(static r => new PdfReference(r.Number, r.Generation)));
        var ocsps = new List<PdfReference>(existing.Ocsp.Select(static c => c.Reference).OfType<PdfReference>().Select(static r => new PdfReference(r.Number, r.Generation)));
        bool added = false;
        var vriEntries = new List<(string Key, List<PdfReference> Certs, List<PdfReference> Crls, List<PdfReference> Ocsps)>();

        PdfReference Add(string id, ReadOnlySpan<byte> der, List<PdfReference> global)
        {
            if (refs.TryGetValue(id, out PdfReference? have))
            {
                return have;
            }

            PdfReference r = doc.AddObject(doc.CreateStream(der, compress: true));
            refs[id] = r;
            global.Add(r);
            added = true;
            return r;
        }

        foreach (Needs n in needs)
        {
            var vc = new List<PdfReference>();
            var vl = new List<PdfReference>();
            var vo = new List<PdfReference>();
            foreach (Certificate c in n.Certificates)
            {
                vc.Add(Copy(Add("C" + Id(c.Encoded.Span), c.Encoded.Span, certs)));
            }

            foreach (CertificateRevocationList c in n.Crls)
            {
                vl.Add(Copy(Add("L" + Id(c.Encoded.Span), c.Encoded.Span, crls)));
            }

            foreach (OcspBasicResponse c in n.Ocsp)
            {
                vo.Add(Copy(Add("O" + Id(c.Encoded.Span), OcspResponseOf(c), ocsps)));
            }

            if (writeVri && !existing.Vri.ContainsKey(n.VriKey))
            {
                vriEntries.Add((n.VriKey, vc, vl, vo));
                added = true;
            }
        }

        if (!added)
        {
            return false;
        }

        var dss = new PdfDictionary();
        dss.SetEntry("Type", new PdfName("DSS"));
        if (certs.Count > 0)
        {
            dss.SetEntry("Certs", ArrayOf(certs));
        }

        if (crls.Count > 0)
        {
            dss.SetEntry("CRLs", ArrayOf(crls));
        }

        if (ocsps.Count > 0)
        {
            dss.SetEntry("OCSPs", ArrayOf(ocsps));
        }

        var vri = new PdfDictionary();
        PdfDictionary? oldVri = doc.Catalog.GetDictionary("DSS")?.GetDictionary("VRI");
        if (oldVri is not null)
        {
            foreach (string k in oldVri.Keys)
            {
                if (oldVri.GetRaw(k) is PdfReference rr)
                {
                    vri.SetEntry(k, new PdfReference(rr.Number, rr.Generation));
                }
            }
        }

        foreach ((string key, List<PdfReference> vc, List<PdfReference> vl, List<PdfReference> vo) in vriEntries)
        {
            var entry = new PdfDictionary();
            entry.SetEntry("Type", new PdfName("VRI"));
            if (vc.Count > 0)
            {
                entry.SetEntry("Cert", ArrayOf(vc));
            }

            if (vl.Count > 0)
            {
                entry.SetEntry("CRL", ArrayOf(vl));
            }

            if (vo.Count > 0)
            {
                entry.SetEntry("OCSP", ArrayOf(vo));
            }

            entry.SetEntry("TU", PdfString.FromText(PdfLayout.PdfDate(at)));
            vri.SetEntry(key, doc.AddObject(entry));
        }

        if (vri.Count > 0)
        {
            dss.SetEntry("VRI", vri);
        }

        doc.Catalog.SetEntry("DSS", doc.AddObject(dss));
        DeclareExtension(doc);
        return true;
    }

    private static PdfReference Copy(PdfReference r) => new(r.Number, r.Generation);

    private static void Keep(Dictionary<string, PdfReference> refs, string id, PdfReference? r)
    {
        if (r is not null)
        {
            refs[id] = r;
        }
    }

    private static PdfArray ArrayOf(List<PdfReference> items)
    {
        var a = new PdfArray();
        foreach (PdfReference r in items)
        {
            a.Append(new PdfReference(r.Number, r.Generation));
        }

        return a;
    }

    private static string Id(ReadOnlySpan<byte> der) => Convert.ToHexString(SHA256.HashData(der));

    /// <summary>
    /// The DER <c>OCSPResponse</c> (RFC 6960 §4.2.1) that wraps a basic response: the store holds whole responses, as servers send them.
    /// </summary>
    internal static byte[] OcspResponseOf(OcspBasicResponse basic) =>
        DerWriter.Sequence(
            new byte[] { 0x0A, 0x01, 0x00 },
            DerWriter.Context(0, DerWriter.Sequence(DerWriter.Oid(KnownOids.OcspBasic), DerWriter.OctetString(basic.Encoded.Span))));

    /// <summary>
    /// Declares the ESIC extension for files that are not PDF 2.0, so readers that predate the document security store accept it
    /// (EN 319 142-1 §5.6: level 1 for the store, level 2 when a signature uses the ETSI.CAdES.detached sub-filter, §6.3 (l)).
    /// </summary>
    private static void DeclareExtension(PdfDocument doc)
    {
        int level = doc.GetSignatures().Any(static s => s.SubFilter == "ETSI.CAdES.detached") ? 2 : 1;
        if (doc.Version is { } v && v.StartsWith("2.", StringComparison.Ordinal))
        {
            return;
        }

        PdfDictionary catalog = doc.Catalog;
        PdfDictionary? extensions = catalog.GetDictionary("Extensions");
        if (extensions?.ContainsKey("ESIC") == true)
        {
            return;
        }

        var esic = new PdfDictionary();
        esic.SetEntry("BaseVersion", new PdfName("1.7"));
        esic.SetEntry("ExtensionLevel", new PdfInteger(level));
        if (extensions is null)
        {
            var created = new PdfDictionary();
            created.SetEntry("ESIC", esic);
            catalog.SetEntry("Extensions", created);
        }
        else
        {
            extensions.SetEntry("ESIC", esic);
        }
    }
}
