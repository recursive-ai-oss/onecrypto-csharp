using System.Security.Cryptography;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Fuzz;

/// <summary>
/// Certificate, CRL, certification request, attribute certificate, extension, name and public key surface. The first byte picks the
/// structure; the rest is parsed, and whatever parses is read back through every accessor and its signature checked against its own
/// key. Only <see cref="X509ParseException"/> may come out of a parse; nothing may come out of the accessors that is not that.
/// </summary>
internal static class X509Target
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        switch (data[0] % 8)
        {
            case 0:
                Cert(rest);
                break;
            case 1:
                Crl(rest);
                break;
            case 2:
                Csr(rest);
                break;
            case 3:
                if (AttributeCertificate.TryParse(rest, out AttributeCertificate? ac) && ac is not null)
                {
                    Same(ac.Encoded, rest);
                    _ = ac.Attributes.Count + ac.Extensions.Count;
                    _ = ac.SerialNumberValue;
                }

                break;
            case 4:
                ExtensionValue(data[1], rest.AsMemory(1));
                break;
            case 5:
                if (DistinguishedName.TryParse(rest, out DistinguishedName? dn) && dn is not null)
                {
                    _ = dn.ToString();
                    _ = dn.Matches(dn);
                    foreach (RelativeDistinguishedName r in dn.Rdns)
                    {
                        foreach (AttributeTypeAndValue a in r.Attributes)
                        {
                            _ = a.Text;
                        }
                    }
                }

                try
                {
                    DistinguishedName.FromString(System.Text.Encoding.UTF8.GetString(rest));
                }
                catch (FormatException)
                {
                }
                catch (ArgumentException)
                {
                }

                break;
            case 6:
                try
                {
                    GeneralName g = GeneralName.Parse(rest);
                    _ = g.ToString();
                    _ = g.Value;
                    _ = g.OtherNameType;
                    _ = g.OtherNameValue;
                    _ = g.DirectoryName;
                }
                catch (X509ParseException)
                {
                }

                break;
            default:
                if (PublicKeyInfo.TryParse(rest, out PublicKeyInfo? key) && key is not null)
                {
                    _ = key.ToString();
                    _ = key.CurveOid;
                    // A signature that cannot be right must be reported, not thrown.
                    SignatureVerification v = key.VerifySignature(AlgorithmIdentifier.Create(KnownOids.Sha256WithRsa), "x"u8, rest);
                    _ = v.Status;
                    v = key.VerifySignature(AlgorithmIdentifier.Create(KnownOids.EcdsaSha256), "x"u8, rest);
                    v = key.VerifySignature(AlgorithmIdentifier.Create(KnownOids.Ed25519), "x"u8, rest);
                    v = key.VerifySignature(AlgorithmIdentifier.Create(KnownOids.MlDsa65), "x"u8, rest);
                }

                break;
        }
    }

    private static void Same(ReadOnlyMemory<byte> encoded, byte[] input)
    {
        // Lossless: what parsed is exactly what was given.
        if (!encoded.Span.SequenceEqual(input))
        {
            throw new InvalidOperationException("the model does not return the received octets");
        }
    }

    private static void Cert(byte[] der)
    {
        if (!Certificate.TryParse(der, out Certificate? c) || c is null)
        {
            return;
        }

        Same(c.Encoded, der);
        _ = c.ToString();
        _ = c.Subject.ToString() + c.Issuer;
        _ = c.IsSelfIssued;
        _ = c.IsDer;
        _ = c.SerialNumberValue;
        _ = c.PublicKey.KeySizeBits;
        _ = c.SignatureAlgorithm.Name + c.TbsSignatureAlgorithm.Name;
        AllExtensions(c.Extensions);
        _ = c.VerifySignature(c.PublicKey);
        _ = c.ToPem();
        _ = c.TryToX509Certificate2(out System.Security.Cryptography.X509Certificates.X509Certificate2? x);
        x?.Dispose();
    }

    private static void Crl(byte[] der)
    {
        if (!CertificateRevocationList.TryParse(der, out CertificateRevocationList? l) || l is null)
        {
            return;
        }

        Same(l.Encoded, der);
        _ = l.Issuer.ToString();
        int n = 0;
        foreach (RevokedCertificate e in l.Entries)
        {
            _ = e.SerialNumberValue;
            _ = e.Extensions.Count;
            e.Extensions.TryGet(out CrlReasonExtension? _);
            e.Extensions.TryGet(out InvalidityDate? _);
            e.Extensions.TryGet(out CertificateIssuerExtension? _);
            n++;
        }

        _ = l.Find(new byte[] { 1 });
        AllExtensions(l.Extensions);
        _ = n + (l.NextUpdate?.Year ?? 0);
        _ = l.ToPem();
    }

    private static void Csr(byte[] der)
    {
        if (!CertificateSigningRequest.TryParse(der, out CertificateSigningRequest? r) || r is null)
        {
            return;
        }

        Same(r.Encoded, der);
        _ = r.Subject.ToString();
        _ = r.Attributes.Count;
        try
        {
            AllExtensions(r.RequestedExtensions);
        }
        catch (X509ParseException)
        {
        }

        _ = r.VerifySignature();
    }

    private static void AllExtensions(ExtensionCollection x)
    {
        _ = x.HasDuplicates;
        x.TryGet(out BasicConstraints? _);
        x.TryGet(out KeyUsageExtension? _);
        x.TryGet(out ExtendedKeyUsage? _);
        x.TryGet(out SubjectAlternativeName? _);
        x.TryGet(out IssuerAlternativeName? _);
        x.TryGet(out SubjectKeyIdentifier? _);
        x.TryGet(out AuthorityKeyIdentifier? _);
        x.TryGet(out NameConstraints? _);
        x.TryGet(out CertificatePolicies? _);
        x.TryGet(out PolicyMappings? _);
        x.TryGet(out PolicyConstraints? _);
        x.TryGet(out InhibitAnyPolicy? _);
        x.TryGet(out CrlDistributionPoints? _);
        x.TryGet(out FreshestCrl? _);
        x.TryGet(out AuthorityInfoAccess? _);
        x.TryGet(out SubjectInfoAccess? _);
        x.TryGet(out CrlNumber? _);
        x.TryGet(out DeltaCrlIndicator? _);
        x.TryGet(out IssuingDistributionPoint? _);
        x.TryGet(out OcspNonce? _);
    }

    // Every typed extension value: if it parses, it must encode again, and the encoding must parse to the same encoding.
    private static void ExtensionValue(byte which, ReadOnlyMemory<byte> value)
    {
        switch (which % 22)
        {
            case 0: Again<BasicConstraints>(value); break;
            case 1: Again<KeyUsageExtension>(value); break;
            case 2: Again<ExtendedKeyUsage>(value); break;
            case 3: Again<SubjectAlternativeName>(value); break;
            case 4: Again<IssuerAlternativeName>(value); break;
            case 5: Again<SubjectKeyIdentifier>(value); break;
            case 6: Again<AuthorityKeyIdentifier>(value); break;
            case 7: Again<NameConstraints>(value); break;
            case 8: Again<CertificatePolicies>(value); break;
            case 9: Again<PolicyMappings>(value); break;
            case 10: Again<PolicyConstraints>(value); break;
            case 11: Again<InhibitAnyPolicy>(value); break;
            case 12: Again<CrlDistributionPoints>(value); break;
            case 13: Again<FreshestCrl>(value); break;
            case 14: Again<AuthorityInfoAccess>(value); break;
            case 15: Again<SubjectInfoAccess>(value); break;
            case 16: Again<CrlNumber>(value); break;
            case 17: Again<DeltaCrlIndicator>(value); break;
            case 18: Again<IssuingDistributionPoint>(value); break;
            case 19: Again<CrlReasonExtension>(value); break;
            case 20: Again<InvalidityDate>(value); break;
            default: Again<CertificateIssuerExtension>(value); break;
        }
    }

    private static void Again<T>(ReadOnlyMemory<byte> value)
        where T : class, IExtensionValue<T>
    {
        T parsed;
        try
        {
            parsed = T.Parse(value);
        }
        catch (X509ParseException)
        {
            return;
        }

        byte[] once = parsed.Encode();
        byte[] twice = T.Parse(once).Encode();
        if (!once.AsSpan().SequenceEqual(twice))
        {
            throw new InvalidOperationException(typeof(T).Name + " does not re-encode to a fixed point");
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsa = RSA.Create(2048);
        X509Signer signer = X509Signer.FromECDsa(ec);
        DateTimeOffset now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var name = DistinguishedName.Create((KnownOids.Country, "DE"), (KnownOids.Organization, "Seed Org"), (KnownOids.CommonName, "seed.example.test"));
        Certificate root = CertificateBuilder.CreateSelfSigned(
            new CertificateOptions
            {
                Subject = name,
                NotBefore = now,
                NotAfter = now.AddYears(5),
                Extensions =
                [
                    Extension.Create(new BasicConstraints(true, 2), true),
                    Extension.Create(new KeyUsageExtension(KeyUsages.KeyCertSign | KeyUsages.CrlSign), true),
                    Extension.Create(new SubjectAlternativeName([GeneralName.Dns("seed.example.test"), GeneralName.Email("a@seed.test"), GeneralName.FromIPAddress([10, 0, 0, 1])]), false),
                    Extension.Create(new NameConstraints([new GeneralSubtree(GeneralName.Dns("seed.test"))], null), true),
                    Extension.Create(new CertificatePolicies([new PolicyInformation("1.2.3.4", [])]), false),
                    Extension.Create(new CrlDistributionPoints([new DistributionPoint(new DistributionPointName([GeneralName.FromUri("http://crl.seed.test/a.crl")]))]), false),
                    Extension.Create(new AuthorityInfoAccess([new AccessDescription(KnownOids.AdOcsp, GeneralName.FromUri("http://ocsp.seed.test"))]), false),
                    Extension.Create(new PolicyConstraints(1, 1), false),
                ],
            },
            signer);
        yield return [0, .. root.Encoded.Span];
        yield return [0, .. CertificateBuilder.CreateSelfSigned(new CertificateOptions { Subject = name, NotBefore = now, NotAfter = now.AddYears(60) }, X509Signer.FromRsa(rsa, HashAlgorithmName.SHA256, pss: true)).Encoded.Span];
        CertificateRevocationList crl = RevocationListBuilder.Create(
            new RevocationListOptions
            {
                ThisUpdate = now,
                NextUpdate = now.AddDays(7),
                Number = 3,
                Revoked = [new RevokedCertificateInfo(5, now, RevocationReason.KeyCompromise, now), new RevokedCertificateInfo(6, now)],
            },
            signer,
            root);
        yield return [1, .. crl.Encoded.Span];
        yield return [2, .. CertificateSigningRequestBuilder.Create(new CertificateSigningRequestOptions { Subject = name, Extensions = [Extension.Create(new SubjectAlternativeName([GeneralName.Dns("a.test")]), false)] }, signer).Encoded.Span];
        yield return [5, .. name.Encoded.Span];
        yield return [6, .. GeneralName.Dns("x.test").Encoded.Span];
        yield return [7, .. root.PublicKey.Encoded.Span];
        foreach (Extension e in root.Extensions)
        {
            yield return [4, (byte)Array.IndexOf(ExtensionOrder, e.Oid), .. e.Value.Span];
        }
    }

    private static readonly string[] ExtensionOrder =
    [
        KnownOids.BasicConstraints, KnownOids.KeyUsage, KnownOids.ExtendedKeyUsage, KnownOids.SubjectAltName, KnownOids.IssuerAltName, KnownOids.SubjectKeyIdentifier,
        KnownOids.AuthorityKeyIdentifier, KnownOids.NameConstraints, KnownOids.CertificatePolicies, KnownOids.PolicyMappings, KnownOids.PolicyConstraints,
        KnownOids.InhibitAnyPolicy, KnownOids.CrlDistributionPoints, KnownOids.FreshestCrl, KnownOids.AuthorityInfoAccess, KnownOids.SubjectInfoAccess,
    ];
}

/// <summary>
/// OCSP surface. The first byte picks request, response, basic response or CertID; whatever parses is read through every accessor and its
/// signature checked against a key taken from the input itself.
/// </summary>
internal static class OcspTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        byte[] rest = data[1..].ToArray();
        switch (data[0] % 4)
        {
            case 0:
                if (OcspRequest.TryParse(rest, out OcspRequest? q) && q is not null)
                {
                    Same(q.Encoded, rest);
                    foreach (OcspSingleRequest s in q.Requests)
                    {
                        _ = s.CertId.SerialNumberValue;
                        _ = s.Extensions.Count;
                    }

                    _ = q.Extensions.TryGet(out OcspNonce? _);
                    _ = q.RequestorName?.ToString();
                    _ = q.SignatureAlgorithm?.Name;
                    foreach (Certificate c in q.Certificates)
                    {
                        _ = q.VerifySignature(c.PublicKey);
                    }
                }

                break;
            case 1:
                if (OcspResponse.TryParse(rest, out OcspResponse? r) && r is not null)
                {
                    Same(r.Encoded, rest);
                    try
                    {
                        Basic(r.BasicResponse);
                    }
                    catch (X509ParseException)
                    {
                    }
                }

                break;
            case 2:
                try
                {
                    Basic(OcspBasicResponse.Parse(rest));
                }
                catch (X509ParseException)
                {
                }

                break;
            default:
                try
                {
                    OcspCertId id = OcspCertId.Parse(rest);
                    _ = id.GetHashCode() + id.SerialNumberValue.GetHashCode();
                    _ = id.Equals(id);
                }
                catch (X509ParseException)
                {
                }

                break;
        }
    }

    private static void Basic(OcspBasicResponse? b)
    {
        if (b is null)
        {
            return;
        }

        foreach (OcspSingleResponse s in b.Responses)
        {
            _ = s.CertId.SerialNumberValue;
            _ = s.Status;
            _ = s.Extensions.Count;
        }

        b.Extensions.TryGet(out OcspNonce? _);
        _ = b.ResponderId.Name?.ToString();
        _ = b.SignatureAlgorithm.Name;
        foreach (Certificate c in b.Certificates)
        {
            _ = b.ResponderId.Matches(c);
            _ = b.VerifySignature(c.PublicKey);
        }
    }

    private static void Same(ReadOnlyMemory<byte> encoded, byte[] input)
    {
        if (!encoded.Span.SequenceEqual(input))
        {
            throw new InvalidOperationException("the model does not return the received octets");
        }
    }

    public static IEnumerable<byte[]> Seeds()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Signer signer = X509Signer.FromECDsa(ec);
        DateTimeOffset now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        Certificate root = CertificateBuilder.CreateSelfSigned(
            new CertificateOptions { Subject = DistinguishedName.Create((KnownOids.CommonName, "Seed CA")), NotBefore = now, NotAfter = now.AddYears(5) }, signer);
        Certificate leaf = CertificateBuilder.Create(
            new CertificateOptions { Subject = DistinguishedName.Create((KnownOids.CommonName, "Seed leaf")), PublicKey = signer.PublicKey, NotBefore = now, NotAfter = now.AddYears(1) }, root, signer);
        OcspCertId id = OcspCertId.Create(leaf, root);
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        yield return [0, .. OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [id], Nonce = nonce }).Encoded.Span];
        yield return [0, .. OcspRequestBuilder.Create(new OcspRequestOptions { Requests = [id], RequestorName = GeneralName.Dns("req.test") }, signer, [root]).Encoded.Span];
        OcspResponse good = OcspResponseBuilder.CreateSuccessful(
            new OcspResponseOptions
            {
                Responder = new OcspResponderId(root.Subject),
                ProducedAt = now,
                Responses = [new OcspSingleResponseInfo(id, OcspCertStatus.Good, now, now.AddDays(1)), new OcspSingleResponseInfo(id, OcspCertStatus.Revoked, now, null, now, RevocationReason.Superseded)],
                Nonce = nonce,
                Certificates = [root],
            },
            signer);
        yield return [1, .. good.Encoded.Span];
        yield return [2, .. good.Response.Span];
        yield return [1, .. OcspResponseBuilder.CreateError(OcspResponseStatus.TryLater).Encoded.Span];
        yield return [3, .. id.Encoded.Span];
    }
}
