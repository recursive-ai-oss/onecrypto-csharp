using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Policy;
using ValidationOptions = RecursiveAI.OneCrypto.Validation.ValidationOptions;
using ValidationReport = RecursiveAI.OneCrypto.Validation.ValidationReport;
using PathValidator = RecursiveAI.OneCrypto.Validation.PathValidator;
using RevocationData = RecursiveAI.OneCrypto.Validation.RevocationData;
using RecursiveAI.OneCrypto.Wire.Cms;
using RecursiveAI.OneCrypto.X509;

namespace RecursiveAI.OneCrypto;

/// <summary>How one verification rule ended.</summary>
public enum CmsCheckStatus
{
    /// <summary>The rule holds.</summary>
    Passed,

    /// <summary>The rule holds, but something about it deserves attention (a weak digest, a small key).</summary>
    Warning,

    /// <summary>The rule is broken.</summary>
    Failed,

    /// <summary>The rule could not be decided: the algorithm or key is not available, or the data needed was not supplied.</summary>
    Unsupported,

    /// <summary>The rule does not apply to this signer.</summary>
    NotApplicable,
}

/// <summary>The result of one verification rule: what was checked, how it ended, why, and where the rule comes from.</summary>
/// <param name="Rule">A short stable name such as <c>message-digest</c>.</param>
/// <param name="Status">The outcome.</param>
/// <param name="Reason">A sentence for anything but a plain pass.</param>
/// <param name="Reference">The RFC section behind the rule.</param>
public sealed record CmsCheck(string Rule, CmsCheckStatus Status, string Reason, string Reference);

/// <summary>The verification of one signer (or countersigner): the signer's certificate, every rule's result and the countersignatures.</summary>
public sealed class SignerReport
{
    internal SignerReport(SignerInfo signer, Certificate? certificate, IReadOnlyList<CmsCheck> checks, IReadOnlyList<SignerReport> countersignatures, DateTimeOffset? signingTime, PolicyReport? policy = null, ValidationReport? chain = null)
    {
        Policy = policy;
        Chain = chain;
        Signer = signer;
        Certificate = certificate;
        Checks = checks;
        Countersignatures = countersignatures;
        SigningTime = signingTime;
    }

    /// <summary>The SignerInfo checked.</summary>
    public SignerInfo Signer { get; }

    /// <summary>
    /// What the <see cref="CryptoPolicy"/> decided about this signer's hash, signature algorithm and key at the reference time, decision by decision
    /// with the rule and standard behind each; null when the verification was given no policy. A rejection also fails the <c>policy</c> check.
    /// </summary>
    public PolicyReport? Policy { get; }

    /// <summary>
    /// The path validator's report for the signer's certificate (every rule, certificate and revocation finding), or null when the verification was given
    /// no <see cref="SignedDataVerifyOptions.Chain"/> or the signer's certificate was not found. The <c>chain</c> check summarises it.
    /// </summary>
    public ValidationReport? Chain { get; }

    /// <summary>The certificate that matched the signer identifier, or null when none was found.</summary>
    public Certificate? Certificate { get; }

    /// <summary>The results of the rules, in the order they ran.</summary>
    public IReadOnlyList<CmsCheck> Checks { get; }

    /// <summary>The reports of the countersignatures of this signature.</summary>
    public IReadOnlyList<SignerReport> Countersignatures { get; }

    /// <summary>The signing-time attribute, a claim of the signer and not a proof of time, or null when absent or unreadable.</summary>
    public DateTimeOffset? SigningTime { get; }

    /// <summary>
    /// True when no rule failed or went undecided and every countersignature is valid too. This says the signature is
    /// mathematically sound for the certificate's key; whether the certificate is trustworthy is the path validator's question.
    /// </summary>
    public bool IsValid => Checks.All(static c => c.Status is not (CmsCheckStatus.Failed or CmsCheckStatus.Unsupported)) && Countersignatures.All(static c => c.IsValid);

    /// <summary>The result of the named rule, or null when it did not run.</summary>
    public CmsCheck? Find(string rule) => Checks.FirstOrDefault(c => c.Rule == rule);
}

/// <summary>The verification of a whole SignedData: message-level rules and one report per signer.</summary>
public sealed class SignedDataReport
{
    internal SignedDataReport(IReadOnlyList<CmsCheck> checks, IReadOnlyList<SignerReport> signers)
    {
        Checks = checks;
        Signers = signers;
    }

    /// <summary>Message-level rules (for example that there is at least one signer).</summary>
    public IReadOnlyList<CmsCheck> Checks { get; }

    /// <summary>One report per SignerInfo, in the order they appear.</summary>
    public IReadOnlyList<SignerReport> Signers { get; }

    /// <summary>True when there is at least one signer, no message-level rule failed, and every signer is valid.</summary>
    public bool IsValid => Signers.Count > 0 && Checks.All(static c => c.Status is not (CmsCheckStatus.Failed or CmsCheckStatus.Unsupported)) && Signers.All(static s => s.IsValid);
}

/// <summary>Choices for verifying SignedData. The defaults suit signed messages in general.</summary>
public sealed class SignedDataVerifyOptions
{
    /// <summary>Certificates to use besides those in the message, for a signer whose certificate was not embedded.</summary>
    public IReadOnlyList<Certificate> ExtraCertificates { get; init; } = [];

    /// <summary>
    /// Key usages of which the signer's certificate must have at least one when it has a keyUsage extension (RFC 5280 §4.2.1.3).
    /// The default is digitalSignature or nonRepudiation, as S/MIME (RFC 8550 §4.4.2) expects; use <see cref="KeyUsages.None"/> to skip the check.
    /// </summary>
    public KeyUsages AnyOfKeyUsages { get; init; } = KeyUsages.DigitalSignature | KeyUsages.NonRepudiation;

    /// <summary>
    /// An extended key usage the signer's certificate must allow when it has an extendedKeyUsage extension (for example
    /// <see cref="KnownOids.EmailProtection"/> or <see cref="KnownOids.TimeStamping"/>); null skips the check.
    /// </summary>
    public string? RequiredExtendedKeyUsage { get; init; }

    /// <summary>Limits for the countersignature depth.</summary>
    public CmsLimits Limits { get; init; } = CmsLimits.Default;

    /// <summary>
    /// The policy that judges each signer's hash, signature algorithm and key. Null (the default) applies no policy and keeps the plain
    /// SHA-1 and small-RSA warnings. When set, <see cref="ReferenceTime"/> must be set too: the same signature is fine in 2012 and refused in 2032.
    /// </summary>
    public CryptoPolicy? Policy { get; init; }

    /// <summary>
    /// Validates each signer's certificate with the path validator when set (null, the default, leaves it out: the report then exposes the certificates and says
    /// nothing about trust). The options carry the trust anchors, the reference time, the algorithm policy, revocation data and any limits; the certificates and
    /// CRLs in the message (and OCSP responses in its revocation set) are added as untrusted material. Each signer, and each countersigner, gets a <c>chain</c>
    /// check and a <see cref="SignerReport.Chain"/>; a certificate that does not validate makes the signer invalid.
    /// <para>The reference time is the validation options': the signing-time attribute is a claim of the signer and is never used. To ask whether the
    /// certificate was valid when the signature was made, pass a proven time there (a time-stamp token's genTime); a certificate that has expired since is
    /// then valid, provided revocation data from after that time shows it was not revoked for a reason that reaches back (see <see cref="Validation.RevocationModel.PastTime"/>).</para>
    /// </summary>
    public ValidationOptions? Chain { get; init; }

    /// <summary>
    /// The instant the policy is asked about: now for a fresh validation, a proven existence time, or a past instant. The library never reads a clock.
    /// Required when <see cref="Policy"/> is set.
    /// </summary>
    public DateTimeOffset? ReferenceTime { get; init; }
}

public sealed partial class SignedData
{
    private const string Rfc5652 = "RFC 5652";

    /// <summary>Verifies every signer of a SignedData that carries its content.</summary>
    /// <param name="options">Choices, or null for the defaults.</param>
    /// <returns>A report; it never throws for bad signatures, only for programming errors. A detached message reports a failed <c>content</c> rule.</returns>
    public SignedDataReport Verify(SignedDataVerifyOptions? options = null)
    {
        if (!HasEncapsulatedContent)
        {
            return Fail("content", "The message has no encapsulated content; supply the detached content.", "RFC 5652 §5.2");
        }

        return VerifyCore(new BufferedSource(EncapsulatedContent), options ?? new SignedDataVerifyOptions());
    }

    /// <summary>Verifies every signer over detached content held in memory.</summary>
    /// <param name="detachedContent">The signed octets.</param>
    /// <param name="options">Choices, or null for the defaults.</param>
    public SignedDataReport Verify(ReadOnlySpan<byte> detachedContent, SignedDataVerifyOptions? options = null)
    {
        if (HasEncapsulatedContent)
        {
            return Fail("content", "The message carries its content; it is not detached.", "RFC 5652 §5.2");
        }

        return VerifyCore(new BufferedSource(detachedContent.ToArray()), options ?? new SignedDataVerifyOptions());
    }

    /// <summary>
    /// Verifies every signer over detached content read from a stream, hashing it as it goes in constant memory. A signer without signed
    /// attributes signs the content itself, which a stream does not give back: such a signer reports <see cref="CmsCheckStatus.Unsupported"/> (use the span overload).
    /// </summary>
    public SignedDataReport Verify(Stream detachedContent, SignedDataVerifyOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(detachedContent);
        using var hashes = new DigestSet(DigestOids(Signers));
        byte[] buffer = new byte[1 << 16];
        int n;
        while ((n = detachedContent.Read(buffer, 0, buffer.Length)) > 0)
        {
            hashes.Append(buffer.AsSpan(0, n));
        }

        return VerifyCore(new DigestSource(hashes.Finish()), options ?? new SignedDataVerifyOptions());
    }

    /// <summary>Asynchronous twin of <see cref="Verify(Stream, SignedDataVerifyOptions)"/>.</summary>
    public async Task<SignedDataReport> VerifyAsync(Stream detachedContent, SignedDataVerifyOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(detachedContent);
        using var hashes = new DigestSet(DigestOids(Signers));
        byte[] buffer = new byte[1 << 16];
        int n;
        while ((n = await detachedContent.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            hashes.Append(buffer.AsSpan(0, n));
        }

        return VerifyCore(new DigestSource(hashes.Finish()), options ?? new SignedDataVerifyOptions());
    }

    /// <summary>Verifies the signers of a message whose content digests were already computed (the streaming reader's path).</summary>
    internal SignedDataReport VerifyWithDigests(IReadOnlyDictionary<string, byte[]> digestsOfContent, SignedDataVerifyOptions options) =>
        VerifyCore(new DigestSource(digestsOfContent), options);

    internal static List<string> DigestOids(IReadOnlyList<SignerInfo> signers)
    {
        var oids = new List<string>();
        foreach (SignerInfo s in signers)
        {
            if (!oids.Contains(s.DigestAlgorithm.Oid) && CmsDigest.IsSupported(s.DigestAlgorithm.Oid))
            {
                oids.Add(s.DigestAlgorithm.Oid);
            }
        }

        return oids;
    }

    private static SignedDataReport Fail(string rule, string reason, string reference) =>
        new([new CmsCheck(rule, CmsCheckStatus.Failed, reason, reference)], []);

    /// <summary>Where the digests of the signed content come from.</summary>
    internal abstract class ContentSource
    {
        /// <summary>The digest of the content under <paramref name="oid"/>, or null when it was not computed.</summary>
        public abstract byte[]? DigestOf(string oid);

        /// <summary>The content octets when they are held in memory (needed by signatures made without signed attributes), otherwise null.</summary>
        public abstract ReadOnlyMemory<byte>? Direct { get; }
    }

    private sealed class BufferedSource : ContentSource
    {
        private readonly ReadOnlyMemory<byte> _content;
        private readonly Dictionary<string, byte[]?> _cache = [];

        public BufferedSource(ReadOnlyMemory<byte> content) => _content = content;

        public override ReadOnlyMemory<byte>? Direct => _content;

        public override byte[]? DigestOf(string oid)
        {
            if (!_cache.TryGetValue(oid, out byte[]? h))
            {
                h = CmsDigest.TryHash(oid, _content.Span, out byte[] d) ? d : null;
                _cache[oid] = h;
            }

            return h;
        }
    }

    private sealed class DigestSource : ContentSource
    {
        private readonly IReadOnlyDictionary<string, byte[]> _digests;

        public DigestSource(IReadOnlyDictionary<string, byte[]> digests) => _digests = digests;

        public override ReadOnlyMemory<byte>? Direct => null;

        public override byte[]? DigestOf(string oid) => _digests.TryGetValue(oid, out byte[]? h) ? h : null;
    }

    /// <summary>Several digests of one stream, computed in one pass.</summary>
    internal sealed class DigestSet : IDisposable
    {
        private readonly List<(string Oid, CmsDigest Digest)> _digests = [];

        public DigestSet(IEnumerable<string> oids)
        {
            foreach (string oid in oids)
            {
                if (CmsDigest.TryCreate(oid, out CmsDigest? d))
                {
                    _digests.Add((oid, d!));
                }
            }
        }

        public void Append(ReadOnlySpan<byte> data)
        {
            foreach ((string _, CmsDigest d) in _digests)
            {
                d.Append(data);
            }
        }

        public Dictionary<string, byte[]> Finish()
        {
            var result = new Dictionary<string, byte[]>();
            foreach ((string oid, CmsDigest d) in _digests)
            {
                result[oid] = d.Finish();
            }

            return result;
        }

        public void Dispose()
        {
            foreach ((string _, CmsDigest d) in _digests)
            {
                d.Dispose();
            }
        }
    }

    private SignedDataReport VerifyCore(ContentSource source, SignedDataVerifyOptions options)
    {
        if (options.Policy is not null && options.ReferenceTime is null)
        {
            throw new ArgumentException("A policy needs a reference time: set SignedDataVerifyOptions.ReferenceTime.", nameof(options));
        }

        var checks = new List<CmsCheck>();
        if (Signers.Count == 0)
        {
            checks.Add(new CmsCheck("signers", CmsCheckStatus.Failed, "The message has no SignerInfo.", "RFC 5652 §5.1"));
        }

        var pool = new List<Certificate>(Certificates);
        pool.AddRange(options.ExtraCertificates);
        ValidationOptions? chain = options.Chain is null ? null : ChainOptions(options.Chain, options.ExtraCertificates);
        var reports = new List<SignerReport>();
        foreach (SignerInfo si in Signers)
        {
            reports.Add(VerifySigner(si, source, EncapsulatedContentType, pool, options, chain, 0));
        }

        return new SignedDataReport(checks, reports);
    }

    private static SignerReport VerifySigner(SignerInfo si, ContentSource source, string contentType, List<Certificate> pool, SignedDataVerifyOptions options, ValidationOptions? chain, int depth)
    {
        var checks = new List<CmsCheck>();
        bool counter = depth > 0;

        // RFC 5652 §5.3: the signer identifier names the certificate whose key verifies the signature.
        Certificate? cert = null;
        foreach (Certificate c in pool)
        {
            if (si.Identifier.Matches(c))
            {
                cert = c;
                break;
            }
        }

        checks.Add(cert is null
            ? new CmsCheck("signer-certificate", CmsCheckStatus.Failed, "No certificate matching the signer identifier is in the message or the supplied certificates.", "RFC 5652 §5.3")
            : new CmsCheck("signer-certificate", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §5.3"));

        string digestOid = si.DigestAlgorithm.Oid;
        byte[]? contentDigest = null;
        if (!CmsDigest.IsSupported(digestOid))
        {
            checks.Add(new CmsCheck("digest-algorithm", CmsCheckStatus.Unsupported, $"The digest algorithm {si.DigestAlgorithm.Name} is not available here.", "RFC 5652 §5.3"));
        }
        else
        {
            contentDigest = source.DigestOf(digestOid);
            checks.Add(digestOid == KnownOids.Sha1 && options.Policy is null
                ? new CmsCheck("digest-algorithm", CmsCheckStatus.Warning, "SHA-1 is no longer collision resistant (NIST SP 800-131A).", "RFC 5652 §5.3")
                : new CmsCheck("digest-algorithm", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §5.3"));
        }

        ReadOnlyMemory<byte> signedData = default;
        bool haveSignedData = false;
        PolicyReport? policyReport = null;
        ValidationReport? chainReport = null;
        DateTimeOffset? signingTime = null;
        if (si.SignedAttributes is not null)
        {
            signedData = CheckAttributes(si, checks, contentType, counter, contentDigest, digestOid, out signingTime);
            haveSignedData = !signedData.IsEmpty;
        }
        else if (source.Direct is { } direct)
        {
            // RFC 5652 §5.4: without signed attributes the signature covers the content itself.
            signedData = direct;
            haveSignedData = true;
            checks.Add(new CmsCheck("attributes", CmsCheckStatus.NotApplicable, "No signed attributes: the signature covers the content directly.", "RFC 5652 §5.4"));
        }
        else
        {
            checks.Add(new CmsCheck("attributes", CmsCheckStatus.Unsupported, "No signed attributes, and the content was streamed: the signature cannot be checked without the content bytes.", "RFC 5652 §5.4"));
        }

        if (cert is not null)
        {
            if (haveSignedData)
            {
                checks.Add(CheckSignature(si, cert, signedData.Span));
            }
            else
            {
                checks.Add(new CmsCheck("signature", CmsCheckStatus.Failed, "There is nothing to check the signature against.", "RFC 5652 §5.4"));
            }

            checks.Add(CheckAlgorithmProtection(si));
            checks.Add(CheckKeyUsage(cert, options));
            if (options.Policy is { } policy)
            {
                policyReport = CheckPolicy(si, cert, policy, options.ReferenceTime!.Value);
                checks.Add(PolicyCheck(policyReport));
            }
            else
            {
                checks.Add(CheckStrength(cert));
            }

            checks.Add(counter ? new CmsCheck("signing-certificate", CmsCheckStatus.NotApplicable, string.Empty, "RFC 5035 §5") : CheckSigningCertificate(si, cert));
            if (chain is not null)
            {
                checks.Add(CheckChain(cert, chain, out chainReport));
            }
        }
        else
        {
            checks.Add(new CmsCheck("signature", CmsCheckStatus.Failed, "The signer's certificate is missing, so the signature cannot be checked.", "RFC 5652 §5.3"));
        }

        var counters = new List<SignerReport>();
        if (si.UnsignedAttributes is not null && depth < options.Limits.MaxCountersignatureDepth)
        {
            // RFC 5652 §11.4: a countersignature is made over the octets of the signature value of the signature it counters.
            var sigSource = new BufferedSource(si.Signature);
            foreach (SignerInfo cs in si.Countersignatures)
            {
                counters.Add(VerifySigner(cs, sigSource, contentType, pool, options, chain, depth + 1));
            }
        }

        if (counters.Count > 0)
        {
            checks.Add(new CmsCheck("countersignatures", counters.All(static c => c.IsValid) ? CmsCheckStatus.Passed : CmsCheckStatus.Failed, counters.All(static c => c.IsValid) ? string.Empty : "A countersignature is not valid.", "RFC 5652 §11.4"));
        }

        return new SignerReport(si, cert, checks, counters, signingTime, policyReport, chainReport);
    }

    /// <summary>Checks the signed attributes (RFC 5652 §5.3, §11) and returns the DER octets the signature covers, or empty when they cannot be formed.</summary>
    private static ReadOnlyMemory<byte> CheckAttributes(SignerInfo si, List<CmsCheck> checks, string contentType, bool counter, byte[]? contentDigest, string digestOid, out DateTimeOffset? signingTime)
    {
        signingTime = null;
        IReadOnlyList<CmsAttributeEntry> attrs = si.SignedAttributes!;
        var seen = new HashSet<string>();
        string? problem = null;
        foreach (CmsAttributeEntry a in attrs)
        {
            if (!seen.Add(a.Oid))
            {
                problem = $"The attribute {a.Oid} appears more than once.";
            }
        }

        // RFC 5652 §11.1-§11.3: these three have exactly one value.
        foreach (string single in new[] { CmsOids.ContentType, CmsOids.MessageDigest, CmsOids.SigningTime })
        {
            if (si.FindSigned(single) is { } one && one.Values.Count != 1)
            {
                problem = $"The attribute {single} must have exactly one value.";
            }
        }

        checks.Add(problem is null
            ? new CmsCheck("attributes", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §5.3")
            : new CmsCheck("attributes", CmsCheckStatus.Failed, problem, "RFC 5652 §5.3"));

        // RFC 5652 §11.1: content-type is required whenever signed attributes are present, and equals the encapsulated type.
        // §11.4: a countersignature must not carry one.
        CmsAttributeEntry? ct = si.FindSigned(CmsOids.ContentType);
        if (counter)
        {
            checks.Add(ct is null
                ? new CmsCheck("content-type", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §11.4")
                : new CmsCheck("content-type", CmsCheckStatus.Failed, "A countersignature must not have a content-type attribute.", "RFC 5652 §11.4"));
        }
        else if (ct is null || ct.Values.Count != 1)
        {
            checks.Add(new CmsCheck("content-type", CmsCheckStatus.Failed, "The content-type signed attribute is missing.", "RFC 5652 §11.1"));
        }
        else
        {
            bool same = false;
            try
            {
                var r = new Asn1Reader(ct.Values[0].Span, Asn1Rules.Ber);
                same = r.ReadObjectIdentifier() == contentType;
            }
            catch (Asn1ParseException)
            {
                // Not an OID: reported as a mismatch below.
            }

            checks.Add(same
                ? new CmsCheck("content-type", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §11.1")
                : new CmsCheck("content-type", CmsCheckStatus.Failed, "The content-type attribute differs from the encapsulated content type.", "RFC 5652 §11.1"));
        }

        // RFC 5652 §11.2: message-digest is the digest of the content under the signer's digest algorithm.
        CmsAttributeEntry? md = si.FindSigned(CmsOids.MessageDigest);
        if (md is null || md.Values.Count != 1)
        {
            checks.Add(new CmsCheck("message-digest", CmsCheckStatus.Failed, "The message-digest signed attribute is missing.", "RFC 5652 §11.2"));
        }
        else if (contentDigest is null)
        {
            checks.Add(new CmsCheck("message-digest", CmsCheckStatus.Unsupported, $"The content digest under {digestOid} could not be computed.", "RFC 5652 §11.2"));
        }
        else
        {
            ReadOnlySpan<byte> claimed = default;
            bool ok = false;
            try
            {
                var r = new Asn1Reader(md.Values[0].Span, Asn1Rules.Ber);
                claimed = r.ReadOctetString();
                ok = r.HasData ? false : CryptographicOperations.FixedTimeEquals(claimed, contentDigest);
            }
            catch (Asn1ParseException)
            {
                // Reported as a mismatch below.
            }

            checks.Add(ok
                ? new CmsCheck("message-digest", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §11.2")
                : new CmsCheck("message-digest", CmsCheckStatus.Failed, "The message-digest attribute does not match the content.", "RFC 5652 §11.2"));
        }

        if (si.FindSigned(CmsOids.SigningTime) is { Values.Count: 1 } st)
        {
            try
            {
                var r = new Asn1Reader(st.Values[0].Span, Asn1Rules.Ber);
                signingTime = r.ReadTime();
            }
            catch (Asn1ParseException)
            {
                checks.Add(new CmsCheck("signing-time", CmsCheckStatus.Warning, "The signing-time attribute could not be read.", "RFC 5652 §11.3"));
            }
        }

        byte[]? covered = si.SignedAttributesToVerify();
        if (covered is null)
        {
            checks.Add(new CmsCheck("attributes", CmsCheckStatus.Failed, "The signed attributes could not be re-encoded for verification.", "RFC 5652 §5.4"));
            return default;
        }

        return covered;
    }

    /// <summary>The signature algorithm to check with: rsaEncryption and id-ecPublicKey in a SignerInfo name only the key type, so the digest algorithm completes them (RFC 3370 §3.2, RFC 5753 §3.1.1).</summary>
    internal static AlgorithmIdentifier EffectiveSignatureAlgorithm(SignerInfo si)
    {
        AlgorithmIdentifier alg = si.SignatureAlgorithm;
        string? mapped = null;
        if (alg.Oid == KnownOids.RsaEncryption)
        {
            mapped = si.DigestAlgorithm.Oid switch
            {
                KnownOids.Sha1 => KnownOids.Sha1WithRsa,
                KnownOids.Sha224 => KnownOids.Sha224WithRsa,
                KnownOids.Sha256 => KnownOids.Sha256WithRsa,
                KnownOids.Sha384 => KnownOids.Sha384WithRsa,
                KnownOids.Sha512 => KnownOids.Sha512WithRsa,
                KnownOids.Sha3256 => KnownOids.RsaSha3256,
                KnownOids.Sha3384 => KnownOids.RsaSha3384,
                KnownOids.Sha3512 => KnownOids.RsaSha3512,
                _ => null,
            };
        }
        else if (alg.Oid == KnownOids.EcPublicKey)
        {
            mapped = si.DigestAlgorithm.Oid switch
            {
                KnownOids.Sha1 => KnownOids.EcdsaSha1,
                KnownOids.Sha224 => KnownOids.EcdsaSha224,
                KnownOids.Sha256 => KnownOids.EcdsaSha256,
                KnownOids.Sha384 => KnownOids.EcdsaSha384,
                KnownOids.Sha512 => KnownOids.EcdsaSha512,
                KnownOids.Sha3256 => KnownOids.EcdsaSha3256,
                KnownOids.Sha3384 => KnownOids.EcdsaSha3384,
                KnownOids.Sha3512 => KnownOids.EcdsaSha3512,
                _ => null,
            };
        }

        if (mapped is null)
        {
            return alg;
        }

        return alg.Oid == KnownOids.RsaEncryption ? AlgorithmIdentifier.WithNull(mapped) : AlgorithmIdentifier.Create(mapped);
    }

    private static CmsCheck CheckSignature(SignerInfo si, Certificate cert, ReadOnlySpan<byte> data)
    {
        AlgorithmIdentifier alg = EffectiveSignatureAlgorithm(si);

        // The hash a signature identifier names must be the digest algorithm of the SignerInfo (RFC 5754 §3, RFC 6211 §1: otherwise
        // the digest could be swapped without the signature noticing).
        string? named = null;
        if (SignatureAlgorithms.TryScheme(alg, out SignatureScheme scheme))
        {
            named = scheme.HashOid;
        }
        else if (alg.Oid == KnownOids.RsaPss)
        {
            try
            {
                named = PssParameters.Parse(alg.Parameters).HashOid;
            }
            catch (Exception e) when (e is Asn1ParseException or X509ParseException)
            {
                return new CmsCheck("signature", CmsCheckStatus.Failed, "The RSASSA-PSS parameters are malformed.", "RFC 4055 §3.1");
            }
        }

        if (named is not null && named != si.DigestAlgorithm.Oid)
        {
            return new CmsCheck("signature", CmsCheckStatus.Failed, $"The signature algorithm {alg.Name} uses a different hash than the digest algorithm {si.DigestAlgorithm.Name}.", "RFC 5754 §3");
        }

        SignatureVerification v = cert.PublicKey.VerifySignature(alg, data, si.Signature.Span);
        return v.Status switch
        {
            SignatureStatus.Valid => new CmsCheck("signature", CmsCheckStatus.Passed, string.Empty, v.Reference),
            SignatureStatus.AlgorithmNotSupported => new CmsCheck("signature", CmsCheckStatus.Unsupported, v.Reason, v.Reference),
            _ => new CmsCheck("signature", CmsCheckStatus.Failed, v.Reason, v.Reference),
        };
    }

    /// <summary>RFC 6211 §3: when the algorithm-protection attribute is signed, it must repeat the digest and signature algorithms of the SignerInfo.</summary>
    private static CmsCheck CheckAlgorithmProtection(SignerInfo si)
    {
        CmsAttributeEntry? a = si.FindSigned(CmsOids.CmsAlgorithmProtection);
        if (a is null)
        {
            return new CmsCheck("algorithm-protection", CmsCheckStatus.NotApplicable, string.Empty, "RFC 6211 §3");
        }

        try
        {
            var r = new Asn1Reader(a.Values[0].Span, Asn1Rules.Ber);
            Asn1Reader seq = r.ReadSequence();
            AlgorithmIdentifier digest = AlgorithmIdentifier.Parse(seq.ReadEncodedValue().ToArray());
            bool ok = digest.Equals(si.DigestAlgorithm);
            if (seq.HasData && seq.PeekTag() == Asn1Tag.Context(1))
            {
                // [1] IMPLICIT AlgorithmIdentifier: the same SEQUENCE under another tag.
                byte[] sig = seq.ReadEncodedValue().ToArray();
                sig[0] = 0x30;
                ok &= AlgorithmIdentifier.Parse(sig).Equals(si.SignatureAlgorithm);
            }
            else
            {
                ok = false;
            }

            return ok
                ? new CmsCheck("algorithm-protection", CmsCheckStatus.Passed, string.Empty, "RFC 6211 §3")
                : new CmsCheck("algorithm-protection", CmsCheckStatus.Failed, "The protected algorithms differ from those in the SignerInfo.", "RFC 6211 §3");
        }
        catch (Exception e) when (e is Asn1ParseException or X509ParseException)
        {
            return new CmsCheck("algorithm-protection", CmsCheckStatus.Failed, "The algorithm-protection attribute is malformed.", "RFC 6211 §3");
        }
    }

    private static CmsCheck CheckKeyUsage(Certificate cert, SignedDataVerifyOptions options)
    {
        try
        {
            if (options.AnyOfKeyUsages != KeyUsages.None && cert.KeyUsage is { } ku && (ku.Usages & options.AnyOfKeyUsages) == 0)
            {
                return new CmsCheck("key-usage", CmsCheckStatus.Failed, $"The certificate's key usage ({ku.Usages}) does not allow signing.", "RFC 5280 §4.2.1.3");
            }

            if (options.RequiredExtendedKeyUsage is { } eku && cert.ExtendedKeyUsage is { } ext && !ext.Allows(eku))
            {
                return new CmsCheck("key-usage", CmsCheckStatus.Failed, $"The certificate's extended key usage does not allow {eku}.", "RFC 5280 §4.2.1.12");
            }
        }
        catch (X509ParseException e)
        {
            return new CmsCheck("key-usage", CmsCheckStatus.Failed, "The certificate's key usage extension is malformed: " + e.Message, "RFC 5280 §4.2.1.3");
        }

        return new CmsCheck("key-usage", CmsCheckStatus.Passed, string.Empty, "RFC 5280 §4.2.1.3");
    }

    /// <summary>Asks the policy about the signature hash, the SignerInfo digest and the signer's key, at the reference time.</summary>
    private static PolicyReport CheckPolicy(SignerInfo si, Certificate cert, CryptoPolicy policy, DateTimeOffset at)
    {
        var decisions = new List<PolicyDecision>(policy.CheckSignature(EffectiveSignatureAlgorithm(si), cert.PublicKey, CryptoUse.Verify, at).Decisions);
        if (SignatureAlgorithms.TryHash(si.DigestAlgorithm.Oid, out HashAlgorithmName digest) && !decisions.Any(d => d.Use == CryptoUse.Verify && d.Algorithm == policy.CheckHash(digest, CryptoUse.Verify, at).Algorithm))
        {
            // EdDSA and ML-DSA identifiers name no hash, but the SignerInfo's digest still protects the signed attributes.
            decisions.Add(policy.CheckHash(digest, CryptoUse.Verify, at));
        }

        return new PolicyReport(decisions);
    }

    private static CmsCheck PolicyCheck(PolicyReport report)
    {
        PolicyDecision? worst = report.Findings.OrderByDescending(static d => d.Verdict).Cast<PolicyDecision?>().FirstOrDefault();
        if (worst is not { } d)
        {
            return new CmsCheck("policy", CmsCheckStatus.Passed, string.Empty, "RFC 5652 §5.3");
        }

        return new CmsCheck("policy", d.Verdict == PolicyVerdict.Rejected ? CmsCheckStatus.Failed : CmsCheckStatus.Warning, $"{d.Reason} [{d.Rule}]", d.Reference);
    }

    private static CmsCheck CheckStrength(Certificate cert)
    {
        PublicKeyInfo key = cert.PublicKey;
        if (key.KeyAlgorithm is KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss && key.KeySizeBits is > 0 and < 2048)
        {
            return new CmsCheck("key-strength", CmsCheckStatus.Warning, $"The RSA key has {key.KeySizeBits} bits; 2048 is the minimum for new signatures (NIST SP 800-131A).", "RFC 8017 §3.1");
        }

        return new CmsCheck("key-strength", CmsCheckStatus.Passed, string.Empty, "RFC 8017 §3.1");
    }

    /// <summary>RFC 5035 §5.4: the first ESSCertID names the signer's certificate by hash (and optionally by issuer and serial number).</summary>
    private static CmsCheck CheckSigningCertificate(SignerInfo si, Certificate cert)
    {
        CmsAttributeEntry? v2 = si.FindSigned(CmsOids.SigningCertificateV2);
        CmsAttributeEntry? v1 = si.FindSigned(CmsOids.SigningCertificate);
        CmsAttributeEntry? a = v2 ?? v1;
        if (a is null)
        {
            return new CmsCheck("signing-certificate", CmsCheckStatus.NotApplicable, "No signing-certificate attribute.", "RFC 5035 §5");
        }

        string reference = v2 is not null ? "RFC 5035 §5.4" : "RFC 2634 §5.4";
        try
        {
            if (a.Values.Count != 1)
            {
                return new CmsCheck("signing-certificate", CmsCheckStatus.Failed, "The attribute must have one value.", reference);
            }

            var r = new Asn1Reader(a.Values[0].Span, Asn1Rules.Ber);
            Asn1Reader sc = r.ReadSequence();
            Asn1Reader certs = sc.ReadSequence();
            if (!certs.HasData)
            {
                return new CmsCheck("signing-certificate", CmsCheckStatus.Failed, "The attribute lists no certificate.", reference);
            }

            Asn1Reader id = certs.ReadSequence();
            string hashOid = v2 is not null ? KnownOids.Sha256 : KnownOids.Sha1;
            if (v2 is not null && id.HasData && id.PeekTag() == new Asn1Tag(Asn1Tags.Sequence, true))
            {
                hashOid = AlgorithmIdentifier.Parse(id.ReadEncodedValue().ToArray()).Oid;
            }

            ReadOnlySpan<byte> certHash = id.ReadOctetString();
            if (!CmsDigest.TryHash(hashOid, cert.Encoded.Span, out byte[] actual))
            {
                return new CmsCheck("signing-certificate", CmsCheckStatus.Unsupported, "The certificate hash algorithm is not available.", reference);
            }

            if (!CryptographicOperations.FixedTimeEquals(certHash, actual))
            {
                return new CmsCheck("signing-certificate", CmsCheckStatus.Failed, "The signing-certificate attribute names a different certificate than the signer's.", reference);
            }

            if (id.HasData)
            {
                // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber }
                Asn1Reader isr = id.ReadSequence();
                Asn1Reader names = isr.ReadSequence();
                ReadOnlySpan<byte> serial = isr.ReadIntegerBytes();
                if (!CmsRead.TrimZeros(serial).SequenceEqual(CmsRead.TrimZeros(cert.SerialNumber.Span)))
                {
                    return new CmsCheck("signing-certificate", CmsCheckStatus.Failed, "The serial number in the signing-certificate attribute differs from the certificate's.", reference);
                }

                bool issuerMatch = names.HasData ? false : true;
                while (names.HasData)
                {
                    if (names.PeekTag() == Asn1Tag.Context(4))
                    {
                        Asn1Reader dn = names.ReadSequence(Asn1Tag.Context(4, true));
                        if (DistinguishedName.TryParse(dn.ReadEncodedValue().ToArray(), out DistinguishedName? n) && n!.Matches(cert.Issuer))
                        {
                            issuerMatch = true;
                        }
                    }
                    else
                    {
                        names.SkipValue();
                    }
                }

                if (!issuerMatch)
                {
                    return new CmsCheck("signing-certificate", CmsCheckStatus.Failed, "The issuer in the signing-certificate attribute differs from the certificate's.", reference);
                }
            }
        }
        catch (Asn1ParseException e)
        {
            return new CmsCheck("signing-certificate", CmsCheckStatus.Failed, "The signing-certificate attribute is malformed: " + e.Message, reference);
        }
        catch (X509ParseException e)
        {
            return new CmsCheck("signing-certificate", CmsCheckStatus.Failed, "The signing-certificate attribute is malformed: " + e.Message, reference);
        }

        return new CmsCheck("signing-certificate", CmsCheckStatus.Passed, string.Empty, reference);
    }
}
