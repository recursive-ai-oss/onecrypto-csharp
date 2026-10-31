using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RecursiveAI.OneCrypto.Asn1;

namespace RecursiveAI.OneCrypto.Cms;

/// <summary>Outcome of one check. <see cref="NotChecked"/> means the check could not be run (unsupported algorithm, nothing to check).</summary>
internal enum CmsCheckStatus
{
    Valid,
    Invalid,
    NotChecked,
}

/// <summary>Result of building the signer's certificate chain.</summary>
internal enum CmsChainStatus
{
    /// <summary>The chain leads to a supplied trust anchor and every certificate was valid at the validation time.</summary>
    Trusted,
    UntrustedRoot,
    Expired,
    NotYetValid,

    /// <summary>The issuer of a certificate was not found among the embedded, extra and trusted certificates.</summary>
    Incomplete,
    Revoked,
    Invalid,
    NotChecked,
}

/// <summary>What is known about revocation of the certificates in a chain. Nothing is fetched.</summary>
internal enum CmsRevocationStatus
{
    NotChecked,
    Good,
    Revoked,
    Unknown,
}

/// <summary>Where the time used to validate the certificates came from.</summary>
internal enum CmsValidationTimeSource
{
    /// <summary>A verified time-stamp token.</summary>
    Timestamp,

    /// <summary>The <c>signingTime</c> attribute: the signer's own claim, unverified.</summary>
    SigningTime,
    Now,
    Explicit,
}

/// <summary>The time policy for certificate validation.</summary>
internal enum CmsValidationTimePolicy
{
    /// <summary>The verified time-stamp's time if there is one, else the signing time (flagged as unverified), else now.</summary>
    Auto,
    Now,
}

/// <summary>One certificate of a built chain.</summary>
internal sealed record CmsChainElement(X509Certificate2 Certificate, IReadOnlyList<string> Problems);

/// <summary>Settings for signer verification. Nothing here makes the library contact a network.</summary>
internal sealed class CmsVerifyOptions
{
    /// <summary>Certificates trusted as roots. Empty and no system store: every chain is untrusted.</summary>
    public IReadOnlyList<X509Certificate2> TrustAnchors { get; init; } = [];

    public bool UseSystemTrustStore { get; init; }

    /// <summary>Intermediate certificates to use besides the ones embedded in the signature.</summary>
    public IReadOnlyList<X509Certificate2> ExtraCertificates { get; init; } = [];

    public CmsValidationTimePolicy TimePolicy { get; init; }

    /// <summary>When set, this exact time is used and <see cref="TimePolicy"/> is ignored.</summary>
    public DateTimeOffset? ValidationTime { get; init; }

    /// <summary>The clock for <see cref="CmsValidationTimeSource.Now"/>. Defaults to the system clock.</summary>
    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>Answers revocation questions from data the caller already holds; receives a certificate and its issuer. Without it revocation is not checked.</summary>
    public Func<X509Certificate2, X509Certificate2?, CmsRevocationStatus>? RevocationCheck { get; init; }

    /// <summary>Require key usage digitalSignature or nonRepudiation and a document-signing, e-mail or any extended key usage (RFC 5280 4.2.1.3, 4.2.1.12).</summary>
    public bool RequireSigningKeyUsage { get; init; } = true;
}

/// <summary>A time-stamp token and what was checked on it (RFC 3161).</summary>
internal sealed class CmsTimestampResult
{
    public DateTimeOffset? Time { get; set; }

    /// <summary>The token's hash of the stamped data matches that data.</summary>
    public CmsCheckStatus Imprint { get; set; } = CmsCheckStatus.NotChecked;

    public CmsCheckStatus Signature { get; set; } = CmsCheckStatus.NotChecked;

    public CmsChainStatus Chain { get; set; } = CmsChainStatus.NotChecked;

    public IReadOnlyList<CmsChainElement> ChainElements { get; set; } = [];

    public X509Certificate2? Certificate { get; set; }

    public bool IsValid => Imprint == CmsCheckStatus.Valid && Signature == CmsCheckStatus.Valid;

    public IReadOnlyList<string> Warnings { get; set; } = [];
}

/// <summary>Everything found out about one signer of a CMS SignedData.</summary>
internal sealed class CmsSignerResult
{
    public bool RequireKeyUsage { get; set; } = true;

    /// <summary>The message digest attribute (or the signature, without signed attributes) matches the content.</summary>
    public CmsCheckStatus Integrity { get; set; } = CmsCheckStatus.NotChecked;

    public CmsCheckStatus SignatureCheck { get; set; } = CmsCheckStatus.NotChecked;

    public CmsCheckStatus KeyUsage { get; set; } = CmsCheckStatus.NotChecked;

    public CmsChainStatus Chain { get; set; } = CmsChainStatus.NotChecked;

    public IReadOnlyList<CmsChainElement> ChainElements { get; set; } = [];

    public X509Certificate2? SignerCertificate { get; set; }

    public CmsRevocationStatus Revocation { get; set; }

    public CmsTimestampResult? Timestamp { get; set; }

    public DateTimeOffset ValidationTime { get; set; }

    public CmsValidationTimeSource ValidationTimeSource { get; set; }

    public DateTimeOffset? ClaimedSigningTime { get; set; }

    public string? DigestAlgorithm { get; set; }

    public string? SignatureAlgorithm { get; set; }

    public bool UsesWeakAlgorithm { get; set; }

    public IReadOnlyList<string> Warnings { get; set; } = [];

    public bool IsValid =>
        Integrity == CmsCheckStatus.Valid && SignatureCheck == CmsCheckStatus.Valid && Chain == CmsChainStatus.Trusted
        && (KeyUsage != CmsCheckStatus.Invalid || !RequireKeyUsage) && (Timestamp is null || Timestamp.IsValid) && Revocation != CmsRevocationStatus.Revoked;
}

/// <summary>
/// Verifies a CMS signer using only the platform's hash, RSA, ECDSA and X.509 primitives: the CMS structure is read by
/// <see cref="CmsSignedData"/>. Nothing here touches a network: chain building has downloads turned off and revocation set to
/// "no check". The caller supplies the digest of the signed content, because the content may be a document, a byte range of
/// a container, or the TSTInfo of a time-stamp.
/// </summary>
internal static class CmsSignerVerifier
{
    /// <summary>
    /// Verifies the first signer of <paramref name="cms"/> against content whose digest <paramref name="contentDigest"/> returns
    /// for a hash algorithm (null when the content is unavailable).
    /// </summary>
    public static CmsSignerResult Verify(ReadOnlyMemory<byte> cms, Func<HashAlgorithmName, byte[]?> contentDigest, CmsVerifyOptions options, CancellationToken ct)
    {
        var result = new CmsSignerResult { RequireKeyUsage = options.RequireSigningKeyUsage };
        var warnings = new List<string>();
        result.Warnings = warnings;
        using var pool = new CertPool(options.ExtraCertificates, warnings);
        if (!CmsSignedData.TryParse(cms, out CmsSignedData? sd, out string? error))
        {
            result.Integrity = CmsCheckStatus.Invalid;
            result.SignatureCheck = CmsCheckStatus.Invalid;
            warnings.Add("The signature value is not a valid CMS SignedData: " + error);
            return result;
        }

        if (sd!.Signers.Count == 0)
        {
            result.Integrity = CmsCheckStatus.Invalid;
            result.SignatureCheck = CmsCheckStatus.Invalid;
            warnings.Add("The CMS has no signer information.");
            return result;
        }

        if (sd.Signers.Count > 1)
        {
            warnings.Add($"The CMS has {sd.Signers.Count} signers; only the first was verified.");
        }

        pool.AddEmbedded(sd);
        SignerOutcome o = CheckSigner(sd, sd.Signers[0], contentDigest, pool, warnings);
        Apply(result, o);
        Finish(result, sd.Signers[0], o, pool, options, warnings, ct);
        if (options.RevocationCheck is null && result.Chain != CmsChainStatus.NotChecked)
        {
            warnings.Add("Revocation was not checked: no revocation data was supplied, and nothing is fetched.");
        }

        return result;
    }

    /// <summary>Copies the outcome of the signature and digest checks into the result.</summary>
    internal static void Apply(CmsSignerResult v, SignerOutcome o)
    {
        v.Integrity = o.Integrity;
        v.SignatureCheck = o.Signature;
        v.SignerCertificate = o.Cert;
        v.DigestAlgorithm = o.DigestName;
        v.SignatureAlgorithm = o.SigName;
        v.UsesWeakAlgorithm |= o.Weak;
        v.ClaimedSigningTime = o.SigningTime;
    }

    /// <summary>Checks the signer's time-stamp, picks the validation time, and builds and judges the chain.</summary>
    internal static void Finish(CmsSignerResult v, CmsSignerInfo si, SignerOutcome o, CertPool pool, CmsVerifyOptions options, List<string> warnings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (si.FindUnsigned(Oids.AdobeRevocationInfo) is not null)
        {
            warnings.Add("The signature embeds revocation data (adbe-revocationInfoArchival); it is not used.");
        }

        CmsTimestampResult? ts = null;
        if (si.FindUnsigned(Oids.SignatureTimeStampToken) is { } tsAttr && tsAttr.Values.Count > 0)
        {
            // RFC 3161 / ETSI EN 319 122-1 5.3: the signature time-stamp stamps the signature value.
            ts = VerifyTimestampToken(tsAttr.Values[0], name => HashBytes(name, si.Signature), pool, options);
            v.Timestamp = ts;
        }

        if (options.ValidationTime is { } explicitTime)
        {
            v.ValidationTime = explicitTime;
            v.ValidationTimeSource = CmsValidationTimeSource.Explicit;
        }
        else if (options.TimePolicy == CmsValidationTimePolicy.Auto && ts is { IsValid: true, Time: { } tsTime })
        {
            v.ValidationTime = tsTime;
            v.ValidationTimeSource = CmsValidationTimeSource.Timestamp;
        }
        else if (options.TimePolicy == CmsValidationTimePolicy.Auto && v.ClaimedSigningTime is { } claimed)
        {
            v.ValidationTime = claimed;
            v.ValidationTimeSource = CmsValidationTimeSource.SigningTime;
            warnings.Add("Certificates were validated at the signer's own claimed signing time, which is not authenticated by a time-stamp.");
        }
        else
        {
            v.ValidationTime = options.Clock.GetUtcNow();
            v.ValidationTimeSource = CmsValidationTimeSource.Now;
        }

        if (o.Cert is not null)
        {
            v.KeyUsage = o.KeyUsageProblem is null ? CmsCheckStatus.Valid : CmsCheckStatus.Invalid;
            if (o.KeyUsageProblem is not null)
            {
                warnings.Add(o.KeyUsageProblem + (options.RequireSigningKeyUsage ? string.Empty : " (allowed by the options)"));
            }

            ChainResult chain = BuildChain(o.Cert, pool, options, v.ValidationTime, warnings);
            v.Chain = chain.Status;
            v.ChainElements = chain.Elements;
            v.Revocation = chain.Revocation;
        }
        else
        {
            v.Chain = CmsChainStatus.NotChecked;
        }
    }

    internal sealed class SignerOutcome
    {
        public CmsCheckStatus Integrity = CmsCheckStatus.Invalid;
        public CmsCheckStatus Signature = CmsCheckStatus.Invalid;
        public X509Certificate2? Cert;
        public byte[] CertDer = [];
        public string? KeyUsageProblem;
        public string? DigestName;
        public string? SigName;
        public bool Weak;
        public DateTimeOffset? SigningTime;
    }

    internal static SignerOutcome CheckSigner(CmsSignedData sd, CmsSignerInfo si, Func<HashAlgorithmName, byte[]?> contentDigest, CertPool pool, List<string> warnings)
    {
        var o = new SignerOutcome
        {
            DigestName = Oids.Name(si.DigestAlgorithm.Oid),
            SigName = Oids.Name(si.SignatureAlgorithm.Oid),
        };
        if (si.FindSigned(Oids.SigningTime) is { } st && st.TryFirst(out Asn1Element ste) && Asn1Values.TryTime(ste, out DateTimeOffset when))
        {
            o.SigningTime = when;
        }

        HashAlgorithmName? maybeHash = Oids.HashFor(si.DigestAlgorithm.Oid);
        if (maybeHash is not { } hash)
        {
            o.Integrity = CmsCheckStatus.NotChecked;
            o.Signature = CmsCheckStatus.NotChecked;
            warnings.Add($"The digest algorithm {o.DigestName} is not supported.");
            return o;
        }

        if (hash == HashAlgorithmName.SHA1)
        {
            o.Weak = true;
            warnings.Add("The signature uses SHA-1, which is weak.");
        }

        o.Cert = pool.Find(si, out byte[] certDer);
        o.CertDer = certDer;
        if (o.Cert is null)
        {
            warnings.Add("The signer's certificate is not in the signature or the extra certificates.");
        }

        byte[]? expected = contentDigest(hash);
        bool integrityKnown = true;
        byte[] signedData;
        if (si.HasSignedAttributes)
        {
            CmsAttribute? md = si.FindSigned(Oids.MessageDigest);
            if (md is null || md.Values.Count != 1 || !md.TryFirst(out Asn1Element mde) || mde.TagClass != 0 || mde.TagNumber != Asn1Tags.OctetString)
            {
                warnings.Add("The signed attributes have no messageDigest.");
                o.Integrity = CmsCheckStatus.Invalid;
            }
            else if (expected is null)
            {
                o.Integrity = CmsCheckStatus.Invalid;
                warnings.Add("The signed content could not be determined.");
            }
            else if (!mde.Content.Span.SequenceEqual(expected))
            {
                o.Integrity = CmsCheckStatus.Invalid;
                warnings.Add("The document bytes do not match the digest in the signature (the signed content was altered).");
            }
            else
            {
                o.Integrity = CmsCheckStatus.Valid;
            }

            CmsAttribute? ct = si.FindSigned(Oids.ContentType);
            if (ct is null)
            {
                warnings.Add("The signed attributes have no contentType.");
            }
            else if (!ct.TryFirst(out Asn1Element cte) || Asn1Values.TryOid(cte) != sd.ContentType)
            {
                warnings.Add("The contentType attribute differs from the encapsulated content type.");
                o.Integrity = CmsCheckStatus.Invalid;
            }

            // RFC 5652 5.4: the signature is over the DER encoding of the attributes as a SET OF.
            byte[] raw = si.SignedAttributesEncoded.ToArray();
            raw[0] = 0x31;
            signedData = HashBytes(hash, raw);
        }
        else
        {
            if (expected is null)
            {
                warnings.Add("The signed content could not be determined.");
                return o;
            }

            signedData = expected;
            integrityKnown = false;
        }

        // Which hash and padding the signature algorithm names.
        string sigOid = si.SignatureAlgorithm.Oid;
        (bool, bool, HashAlgorithmName?) scheme = sigOid switch
        {
            Oids.RsaEncryption => (true, false, (HashAlgorithmName?)hash),
            Oids.Sha1WithRsa => (true, false, HashAlgorithmName.SHA1),
            Oids.Sha256WithRsa => (true, false, HashAlgorithmName.SHA256),
            Oids.Sha384WithRsa => (true, false, HashAlgorithmName.SHA384),
            Oids.Sha512WithRsa => (true, false, HashAlgorithmName.SHA512),
            Oids.RsaPss => (true, true, null),
            Oids.EcPublicKey => (false, false, hash),
            Oids.EcdsaSha1 => (false, false, HashAlgorithmName.SHA1),
            Oids.EcdsaSha256 => (false, false, HashAlgorithmName.SHA256),
            Oids.EcdsaSha384 => (false, false, HashAlgorithmName.SHA384),
            Oids.EcdsaSha512 => (false, false, HashAlgorithmName.SHA512),
            _ => (false, false, null),
        };
        (bool rsa, bool pss, HashAlgorithmName? sigHash) = scheme;
        bool known = sigOid is Oids.RsaEncryption or Oids.Sha1WithRsa or Oids.Sha256WithRsa or Oids.Sha384WithRsa or Oids.Sha512WithRsa or Oids.RsaPss
            or Oids.EcPublicKey or Oids.EcdsaSha1 or Oids.EcdsaSha256 or Oids.EcdsaSha384 or Oids.EcdsaSha512;
        if (!known)
        {
            o.Signature = CmsCheckStatus.NotChecked;
            if (!integrityKnown)
            {
                o.Integrity = CmsCheckStatus.NotChecked;
            }

            warnings.Add($"The signature algorithm {sigOid} is not supported.");
            return o;
        }

        int saltLength = 0;
        if (pss)
        {
            if (!TryPssParameters(si.SignatureAlgorithm.Parameters, out HashAlgorithmName pssHash, out saltLength, out string? pssError))
            {
                o.Signature = CmsCheckStatus.NotChecked;
                if (!integrityKnown)
                {
                    o.Integrity = CmsCheckStatus.NotChecked;
                }

                warnings.Add("RSASSA-PSS parameters are not supported: " + pssError);
                return o;
            }

            sigHash = pssHash;
            if (pssHash == HashAlgorithmName.SHA1)
            {
                o.Weak = true;
            }
        }

        if (sigHash != hash)
        {
            o.Signature = CmsCheckStatus.Invalid;
            if (!integrityKnown)
            {
                o.Integrity = CmsCheckStatus.Invalid;
            }

            warnings.Add($"The signature algorithm uses {sigHash} but the digest algorithm is {hash}.");
            return o;
        }

        if (o.Cert is null)
        {
            o.Signature = CmsCheckStatus.NotChecked;
            if (!integrityKnown)
            {
                o.Integrity = CmsCheckStatus.NotChecked;
            }

            return o;
        }

        bool ok = false;
        try
        {
            if (rsa)
            {
                using RSA? key = o.Cert.GetRSAPublicKey();
                if (key is null)
                {
                    warnings.Add("The signer certificate does not hold an RSA key.");
                }
                else
                {
                    if (key.KeySize < 2048)
                    {
                        o.Weak = true;
                        warnings.Add($"The signer's RSA key is only {key.KeySize} bits.");
                    }

                    ok = key.VerifyHash(signedData, si.Signature, hash, pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                    if (!ok && pss)
                    {
                        warnings.Add($"RSASSA-PSS verification failed (salt length {saltLength}; the platform supports a salt as long as the hash).");
                    }
                }
            }
            else
            {
                using ECDsa? key = o.Cert.GetECDsaPublicKey();
                if (key is null)
                {
                    warnings.Add("The signer certificate does not hold an ECDSA key.");
                }
                else
                {
                    ok = key.VerifyHash(signedData, si.Signature, DSASignatureFormat.Rfc3279DerSequence);
                }
            }
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            warnings.Add("The signature could not be verified: " + e.Message);
        }

        o.Signature = ok ? CmsCheckStatus.Valid : CmsCheckStatus.Invalid;
        if (!ok)
        {
            warnings.Add("The signature value does not verify with the signer certificate's public key.");
        }

        if (!integrityKnown)
        {
            o.Integrity = o.Signature;
        }

        // The signing-certificate attribute binds the signature to one certificate (RFC 5035).
        if (!CheckSigningCertificate(si, o.CertDer, warnings))
        {
            o.Signature = CmsCheckStatus.Invalid;
        }

        o.KeyUsageProblem = KeyUsageProblem(o.Cert);

        return o;
    }

    // Purposes under which a certificate may sign a document: none stated, or one of these (RFC 5280 4.2.1.12, RFC 9336,
    // and the PDF and Adobe purposes that document signers carry). A certificate limited to other purposes (time-stamping, TLS server, code signing) is not a document signer's.
    private static readonly string[] DocumentSigningPurposes =
    [
        "2.5.29.37.0", "1.3.6.1.5.5.7.3.4", "1.2.840.113583.1.1.5", "1.3.6.1.4.1.311.10.3.12", "1.3.6.1.5.5.7.3.36",
    ];

    /// <summary>Why this certificate may not sign documents (RFC 5280 4.2.1.3 key usage, 4.2.1.12 extended key usage), or null.</summary>
    internal static string? KeyUsageProblem(X509Certificate2 cert)
    {
        try
        {
            foreach (X509Extension ext in cert.Extensions)
            {
                if (ext is X509KeyUsageExtension ku && (ku.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) == 0)
                {
                    return "The signer certificate's key usage does not include digitalSignature or nonRepudiation.";
                }

                if (ext is X509EnhancedKeyUsageExtension eku && eku.EnhancedKeyUsages.Count > 0)
                {
                    bool ok = false;
                    foreach (Oid oid in eku.EnhancedKeyUsages)
                    {
                        ok |= oid.Value is not null && Array.IndexOf(DocumentSigningPurposes, oid.Value) >= 0;
                    }

                    if (!ok)
                    {
                        return "The signer certificate's extended key usage does not allow signing documents.";
                    }
                }
            }

            return null;
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            return "The signer certificate's extensions could not be read.";
        }
    }

    // Returns false when an ESS signing-certificate attribute exists and does not match the certificate.
    private static bool CheckSigningCertificate(CmsSignerInfo si, byte[] certDer, List<string> warnings)
    {
        foreach ((string oid, bool v2) in new[] { (Oids.SigningCertificateV2, true), (Oids.SigningCertificate, false) })
        {
            if (si.FindSigned(oid) is not { } attr || !attr.TryFirst(out Asn1Element top))
            {
                continue;
            }

            var seq = new List<Asn1Element>(2);
            var ids = new List<Asn1Element>(4);
            if (!top.IsSequence || !Asn1Element.TryChildren(top, 3, seq, out _) || seq.Count == 0 || !seq[0].IsSequence || !Asn1Element.TryChildren(seq[0], 8, ids, out _) || ids.Count == 0)
            {
                warnings.Add("The signing-certificate attribute is malformed.");
                return false;
            }

            var parts = new List<Asn1Element>(3);
            if (!ids[0].IsSequence || !Asn1Element.TryChildren(ids[0], 4, parts, out _) || parts.Count == 0)
            {
                warnings.Add("The signing-certificate attribute is malformed.");
                return false;
            }

            HashAlgorithmName alg = v2 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
            int at = 0;
            if (v2 && parts[0].IsSequence)
            {
                if (!CmsAlgorithm.TryParse(parts[0], out CmsAlgorithm a) || Oids.HashFor(a.Oid) is not { } h)
                {
                    warnings.Add("The signing-certificate attribute uses an unsupported hash.");
                    return true;
                }

                alg = h;
                at = 1;
            }

            if (at >= parts.Count || !parts[at].IsUniversal(Asn1Tags.OctetString))
            {
                warnings.Add("The signing-certificate attribute is malformed.");
                return false;
            }

            if (!parts[at].Content.Span.SequenceEqual(HashBytes(alg, certDer)))
            {
                warnings.Add("The signing-certificate attribute names a different certificate than the one that signed.");
                return false;
            }

            return true;
        }

        return true;
    }

    private static bool TryPssParameters(ReadOnlyMemory<byte> p, out HashAlgorithmName hash, out int salt, out string? error)
    {
        hash = HashAlgorithmName.SHA1;
        HashAlgorithmName mgfHash = HashAlgorithmName.SHA1;
        salt = 20;
        error = null;
        if (p.IsEmpty)
        {
            return true;
        }

        if (!Asn1Element.TryRead(p, out Asn1Element seq, out _, out _))
        {
            error = "malformed";
            return false;
        }

        if (seq.IsUniversal(Asn1Tags.Null))
        {
            return true;
        }

        var kids = new List<Asn1Element>(4);
        if (!seq.IsSequence || !Asn1Element.TryChildren(seq, 5, kids, out _))
        {
            error = "malformed";
            return false;
        }

        foreach (Asn1Element k in kids)
        {
            var inner = new List<Asn1Element>(1);
            if (k.TagClass != 2 || !Asn1Element.TryChildren(k, 2, inner, out _) || inner.Count != 1)
            {
                error = "malformed";
                return false;
            }

            switch (k.TagNumber)
            {
                case 0:
                    if (!CmsAlgorithm.TryParse(inner[0], out CmsAlgorithm h) || Oids.HashFor(h.Oid) is not { } hn)
                    {
                        error = "unsupported hash";
                        return false;
                    }

                    hash = hn;
                    break;
                case 1:
                    if (!CmsAlgorithm.TryParse(inner[0], out CmsAlgorithm m) || m.Oid != Oids.Mgf1 || !Asn1Element.TryRead(m.Parameters, out Asn1Element mh, out _, out _)
                        || !CmsAlgorithm.TryParse(mh, out CmsAlgorithm mhash) || Oids.HashFor(mhash.Oid) is not { } mn)
                    {
                        error = "unsupported mask generation function";
                        return false;
                    }

                    mgfHash = mn;
                    break;
                case 2:
                    salt = Asn1Values.TrySmallInt(inner[0]);
                    if (salt < 0)
                    {
                        error = "bad salt length";
                        return false;
                    }

                    break;
                case 3:
                    if (Asn1Values.TrySmallInt(inner[0]) != 1)
                    {
                        error = "unsupported trailer field";
                        return false;
                    }

                    break;
            }
        }

        if (mgfHash != hash)
        {
            error = "the mask generation hash differs from the message hash";
            return false;
        }

        return true;
    }

    internal static CmsTimestampResult VerifyTimestampToken(ReadOnlyMemory<byte> token, Func<HashAlgorithmName, byte[]?> imprintData, CertPool pool, CmsVerifyOptions options)
    {
        var r = new CmsTimestampResult { Imprint = CmsCheckStatus.Invalid, Signature = CmsCheckStatus.Invalid };
        var w = new List<string>();
        r.Warnings = w;
        if (!CmsSignedData.TryParse(token, out CmsSignedData? sd, out string? error) || sd!.Signers.Count == 0)
        {
            w.Add("The time-stamp token is not a valid CMS SignedData: " + (error ?? "no signer"));
            return r;
        }

        if (sd.ContentType != Oids.TstInfo || sd.Content is null)
        {
            w.Add("The time-stamp token does not hold TSTInfo.");
            return r;
        }

        // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
        var f = new List<Asn1Element>(10);
        var imprint = new List<Asn1Element>(2);
        if (!Asn1Element.TryRead(sd.Content, out Asn1Element tst, out _, out _) || !tst.IsSequence || !Asn1Element.TryChildren(tst, 16, f, out _) || f.Count < 5
            || !f[2].IsSequence || !Asn1Element.TryChildren(f[2], 3, imprint, out _) || imprint.Count != 2 || !CmsAlgorithm.TryParse(imprint[0], out CmsAlgorithm imprintAlg)
            || !imprint[1].IsUniversal(Asn1Tags.OctetString) || !Asn1Values.TryTime(f[4], out DateTimeOffset genTime))
        {
            w.Add("The TSTInfo in the time-stamp token is malformed.");
            return r;
        }

        r.Time = genTime;
        if (Oids.HashFor(imprintAlg.Oid) is not { } hashName)
        {
            r.Imprint = CmsCheckStatus.NotChecked;
            r.Signature = CmsCheckStatus.NotChecked;
            w.Add($"The time-stamp imprint hash {Oids.Name(imprintAlg.Oid)} is not supported.");
            return r;
        }

        byte[]? data = imprintData(hashName);
        r.Imprint = data is not null && imprint[1].Content.Span.SequenceEqual(data) ? CmsCheckStatus.Valid : CmsCheckStatus.Invalid;
        if (r.Imprint != CmsCheckStatus.Valid)
        {
            w.Add("The time-stamp's hash does not match the data it stamps.");
        }

        // The token is a SignedData whose content is the TSTInfo; verify its signer like any other.
        byte[] content = sd.Content;
        using var tokenPool = new CertPool(options.ExtraCertificates, w);
        tokenPool.AddEmbedded(sd);
        foreach (CertPool.Entry e in pool.Entries)
        {
            tokenPool.AddCopy(e);
        }

        SignerOutcome o = CheckSigner(sd, sd.Signers[0], name => HashBytes(name, content), tokenPool, w);
        r.Signature = o.Integrity == CmsCheckStatus.Valid ? o.Signature : CmsCheckStatus.Invalid;
        r.Certificate = o.Cert is null ? null : X509CertificateLoader.LoadCertificate(o.CertDer);
        if (o.Cert is not null)
        {
            bool timestamping = false;
            try
            {
                foreach (X509Extension ext in o.Cert.Extensions)
                {
                    if (ext is X509EnhancedKeyUsageExtension eku)
                    {
                        foreach (Oid oid in eku.EnhancedKeyUsages)
                        {
                            timestamping |= oid.Value == "1.3.6.1.5.5.7.3.8";
                        }
                    }
                }
            }
            catch (Exception e) when (e is CryptographicException or ArgumentException)
            {
                w.Add("The time-stamp authority's certificate extensions could not be read.");
            }

            if (!timestamping)
            {
                // RFC 3161 2.3: the authority's certificate must carry the time-stamping purpose.
                w.Add("The time-stamp authority's certificate does not carry the time-stamping extended key usage.");
                r.Signature = CmsCheckStatus.Invalid;
            }

            ChainResult chain = BuildChain(o.Cert, tokenPool, options, options.ValidationTime ?? genTime, w);
            r.Chain = chain.Status;
            r.ChainElements = chain.Elements;
        }

        return r;
    }

    // ---- Certificates and chains ----------------------------------------------------------------------------------------

    internal sealed class ChainResult
    {
        public CmsChainStatus Status;
        public List<CmsChainElement> Elements = [];
        public CmsRevocationStatus Revocation;
    }

    internal static ChainResult BuildChain(X509Certificate2 leaf, CertPool pool, CmsVerifyOptions options, DateTimeOffset time, List<string> warnings)
    {
        ChainResult result = TryChain(leaf, pool, options, time, systemStore: false, warnings);
        if (result.Status != CmsChainStatus.Trusted && options.UseSystemTrustStore && options.TrustAnchors.Count > 0)
        {
            ChainResult system = TryChain(leaf, pool, options, time, systemStore: true, warnings);
            if (system.Status == CmsChainStatus.Trusted)
            {
                result = system;
            }
        }

        if (result.Status == CmsChainStatus.Trusted && options.RevocationCheck is { } check)
        {
            bool unknown = false;
            bool revoked = false;
            for (int i = 0; i + 1 < result.Elements.Count; i++)
            {
                CmsRevocationStatus s = check(result.Elements[i].Certificate, result.Elements[i + 1].Certificate);
                revoked |= s == CmsRevocationStatus.Revoked;
                unknown |= s is CmsRevocationStatus.Unknown or CmsRevocationStatus.NotChecked;
            }

            result.Revocation = revoked ? CmsRevocationStatus.Revoked : unknown ? CmsRevocationStatus.Unknown : CmsRevocationStatus.Good;
            if (revoked)
            {
                result.Status = CmsChainStatus.Revoked;
            }
        }

        return result;
    }

    private static ChainResult TryChain(X509Certificate2 leaf, CertPool pool, CmsVerifyOptions options, DateTimeOffset time, bool systemStore, List<string> warnings)
    {
        var result = new ChainResult();
        using var chain = new X509Chain();
        X509ChainPolicy policy = chain.ChainPolicy;
        policy.RevocationMode = X509RevocationMode.NoCheck;
        policy.DisableCertificateDownloads = true;
        policy.VerificationTime = time.UtcDateTime;
        if (systemStore)
        {
            policy.TrustMode = X509ChainTrustMode.System;
        }
        else
        {
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (X509Certificate2 a in options.TrustAnchors)
            {
                if (CertPool.IsUsable(a))
                {
                    policy.CustomTrustStore.Add(a);
                }
                else
                {
                    warnings.Add("A trust anchor is damaged and was ignored.");
                }
            }

            if (options.UseSystemTrustStore && options.TrustAnchors.Count == 0)
            {
                policy.TrustMode = X509ChainTrustMode.System;
            }
        }

        foreach (CertPool.Entry e in pool.Entries)
        {
            policy.ExtraStore.Add(e.Cert);
        }

        X509ChainStatusFlags flags = X509ChainStatusFlags.NoError;
        bool anyExpired = false;
        bool anyNotYet = false;
        try
        {
            chain.Build(leaf);
            foreach (X509ChainStatus s in chain.ChainStatus)
            {
                flags |= s.Status;
            }

            foreach (X509ChainElement el in chain.ChainElements)
            {
                var problems = new List<string>();
                foreach (X509ChainStatus s in el.ChainElementStatus)
                {
                    if (s.Status is not (X509ChainStatusFlags.NoError or X509ChainStatusFlags.RevocationStatusUnknown or X509ChainStatusFlags.OfflineRevocation))
                    {
                        problems.Add(s.Status.ToString());
                    }
                }

                DateTimeOffset nb = el.Certificate.NotBefore.ToUniversalTime();
                DateTimeOffset na = el.Certificate.NotAfter.ToUniversalTime();
                anyExpired |= na < time;
                anyNotYet |= nb > time;
                result.Elements.Add(new CmsChainElement(X509CertificateLoader.LoadCertificate(el.Certificate.RawData), problems));
            }
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            // A certificate that loads but cannot be read further (for example an unreadable validity period).
            warnings.Add("The certificate chain could not be built: " + e.Message);
            result.Status = CmsChainStatus.Invalid;
            return result;
        }

        const X509ChainStatusFlags ignorable = X509ChainStatusFlags.NoError | X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation;
        if ((flags & X509ChainStatusFlags.Revoked) != 0)
        {
            result.Status = CmsChainStatus.Revoked;
        }
        else if ((flags & X509ChainStatusFlags.NotTimeValid) != 0)
        {
            result.Status = anyExpired || !anyNotYet ? CmsChainStatus.Expired : CmsChainStatus.NotYetValid;
        }
        else if ((flags & X509ChainStatusFlags.UntrustedRoot) != 0)
        {
            result.Status = CmsChainStatus.UntrustedRoot;
        }
        else if ((flags & X509ChainStatusFlags.PartialChain) != 0)
        {
            result.Status = CmsChainStatus.Incomplete;
        }
        else if ((flags & ~ignorable) != 0)
        {
            result.Status = CmsChainStatus.Invalid;
            warnings.Add("The certificate chain is not valid: " + (flags & ~ignorable));
        }
        else
        {
            result.Status = CmsChainStatus.Trusted;
        }

        return result;
    }

    /// <summary>The certificates available for building a chain, owned and disposed here.</summary>
    internal sealed class CertPool : IDisposable
    {
        private readonly List<string> _warn;

        public CertPool(IReadOnlyList<X509Certificate2> extras, List<string> warnings)
        {
            _warn = warnings;
            for (int i = 0; i < Math.Min(extras.Count, CmsSignedData.MaxCertificates); i++)
            {
                byte[] raw;
                try
                {
                    raw = extras[i].RawData;
                }
                catch (Exception e) when (e is CryptographicException or ArgumentException)
                {
                    _warn.Add("An extra certificate could not be read and was ignored.");
                    continue;
                }

                AddDer(raw);
            }
        }

        public List<Entry> Entries { get; } = [];

        public void AddEmbedded(CmsSignedData sd)
        {
            foreach (ReadOnlyMemory<byte> der in sd.Certificates)
            {
                if (Entries.Count >= CmsSignedData.MaxCertificates * 2)
                {
                    _warn.Add("The signature carries more certificates than are used; the rest are ignored.");
                    break;
                }

                AddDer(der.ToArray());
            }
        }

        public void AddCopy(Entry e)
        {
            AddDer(e.Der);
        }

        public X509Certificate2? Find(CmsSignerInfo si, out byte[] der)
        {
            foreach (Entry e in Entries)
            {
                if (e.Identity.Matches(si))
                {
                    der = e.Der;
                    return e.Cert;
                }
            }

            der = [];
            return null;
        }

        public void Dispose()
        {
            foreach (Entry e in Entries)
            {
                e.Cert.Dispose();
            }

            Entries.Clear();
        }

        private void AddDer(byte[] der)
        {
            foreach (Entry e in Entries)
            {
                if (e.Der.AsSpan().SequenceEqual(der))
                {
                    return;
                }
            }

            X509Certificate2? cert = null;
            try
            {
                cert = X509CertificateLoader.LoadCertificate(der);
                if (!IsUsable(cert))
                {
                    cert.Dispose();
                    _warn.Add("A certificate in the signature is damaged and was ignored.");
                    return;
                }

                _ = CertificateIdentity.TryParse(der, out CertificateIdentity id);
                Entries.Add(new Entry(cert, der, id));
            }
            catch (Exception e) when (e is CryptographicException or ArgumentException)
            {
                cert?.Dispose();
                _warn.Add("A certificate in the signature could not be parsed and was ignored.");
            }
        }

        /// <summary>
        /// Some platforms (macOS) accept certificate bytes and parse them only when a property is read, so every property the
        /// verifier uses is read once here; a certificate that fails is left out instead of failing a later check.
        /// </summary>
        internal static bool IsUsable(X509Certificate2 cert)
        {
            try
            {
                _ = cert.RawData;
                _ = cert.NotBefore;
                _ = cert.NotAfter;
                _ = cert.SubjectName.RawData;
                _ = cert.IssuerName.RawData;
                _ = cert.PublicKey.Oid.Value;
                foreach (X509Extension ext in cert.Extensions)
                {
                    _ = ext.RawData;
                }

                // Decoding the key is where a damaged SubjectPublicKeyInfo shows on some platforms.
                using RSA? rsa = cert.GetRSAPublicKey();
                if (rsa is null)
                {
                    using ECDsa? ec = cert.GetECDsaPublicKey();
                }

                return true;
            }
            catch (Exception e) when (e is CryptographicException or ArgumentException)
            {
                return false;
            }
        }

        internal readonly record struct Entry(X509Certificate2 Cert, byte[] Der, CertificateIdentity Identity);
    }

    // ---- Hashing --------------------------------------------------------------------------------------------------------

    internal static byte[] HashBytes(HashAlgorithmName name, ReadOnlySpan<byte> data)
    {
        using IncrementalHash h = IncrementalHash.CreateHash(name);
        h.AppendData(data);
        return h.GetHashAndReset();
    }
}
