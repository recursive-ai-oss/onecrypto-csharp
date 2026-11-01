using System.Linq;
using System.Security.Cryptography;
using RecursiveAI.OneCrypto.Asn1;
using RecursiveAI.OneCrypto.Primitives;

namespace RecursiveAI.OneCrypto.Policy;

/// <summary>What an algorithm is being used for when the policy is asked.</summary>
public enum CryptoUse
{
    /// <summary>Making a new signature.</summary>
    Sign,
    /// <summary>Checking a signature, new or old. The reference time says which it is.</summary>
    Verify,
    /// <summary>Encrypting new data.</summary>
    Encrypt,
    /// <summary>Decrypting data that already exists.</summary>
    Decrypt,
    /// <summary>Key agreement or key transport (ECDH, X25519, RSA-OAEP key wrap, KEM).</summary>
    KeyAgreement,
    /// <summary>The hash inside a signature or certificate identifier.</summary>
    SignatureHash,
    /// <summary>Deriving a key from a password.</summary>
    Kdf,
    /// <summary>A message authentication code.</summary>
    Mac,
    /// <summary>
    /// Checking a signature on a PKI object: a certificate, CRL, OCSP response or request, certificate request or attribute certificate. Judged like
    /// <see cref="Verify"/> except that an <see cref="AlgorithmRule"/> may carry its own, earlier PKI cutoffs.
    /// </summary>
    VerifyPki,
}

/// <summary>The policy's answer to one question.</summary>
public enum PolicyVerdict
{
    /// <summary>Allowed.</summary>
    Accepted = 0,
    /// <summary>Allowed, but weak or deprecated at the reference time; the caller should surface it.</summary>
    Flagged = 1,
    /// <summary>Not allowed.</summary>
    Rejected = 2,
}

/// <summary>One decision: what was asked, the answer, the rule that decided it and the section of the standard behind the rule.</summary>
/// <param name="Verdict">The answer.</param>
/// <param name="Use">What the algorithm is used for.</param>
/// <param name="Algorithm">The algorithm in readable form, with its size where it matters (<c>RSA 1024-bit</c>, <c>SHA-1</c>).</param>
/// <param name="Rule">A stable identifier of the rule that decided, for example <c>hash.sha1.rejected-from</c>. Empty when accepted by default.</param>
/// <param name="Reason">A sentence saying why, with the dates involved. Empty when accepted by default.</param>
/// <param name="Reference">The standard the rule comes from, for example <c>NIST SP 800-131A Rev. 2 §3</c>.</param>
public readonly record struct PolicyDecision(PolicyVerdict Verdict, CryptoUse Use, string Algorithm, string Rule, string Reason, string Reference)
{
    /// <summary>True unless the verdict is <see cref="PolicyVerdict.Rejected"/>.</summary>
    public bool IsAllowed => Verdict != PolicyVerdict.Rejected;

    internal static PolicyDecision Ok(CryptoUse use, string algorithm) => new(PolicyVerdict.Accepted, use, algorithm, string.Empty, string.Empty, string.Empty);
}

/// <summary>The decisions for everything one operation uses (the hash, the key, the cipher), and the worst verdict among them.</summary>
public sealed class PolicyReport
{
    /// <summary>Creates a report.</summary>
    public PolicyReport(IReadOnlyList<PolicyDecision> decisions)
    {
        ArgumentNullException.ThrowIfNull(decisions);
        Decisions = decisions;
        PolicyVerdict worst = PolicyVerdict.Accepted;
        foreach (PolicyDecision d in decisions)
        {
            if (d.Verdict > worst)
            {
                worst = d.Verdict;
            }
        }

        Verdict = worst;
    }

    /// <summary>Every decision taken, in the order asked.</summary>
    public IReadOnlyList<PolicyDecision> Decisions { get; }

    /// <summary>The worst verdict among the decisions: Rejected over Flagged over Accepted.</summary>
    public PolicyVerdict Verdict { get; }

    /// <summary>True unless something was rejected.</summary>
    public bool IsAllowed => Verdict != PolicyVerdict.Rejected;

    /// <summary>The decisions that are not plain acceptance.</summary>
    public IEnumerable<PolicyDecision> Findings => Decisions.Where(d => d.Verdict != PolicyVerdict.Accepted);
}

/// <summary>A symmetric cipher family, for <see cref="CryptoPolicy.CheckCipher"/>.</summary>
public enum CipherAlgorithm
{
    /// <summary>AES (FIPS 197).</summary>
    Aes,
    /// <summary>Camellia (RFC 3713).</summary>
    Camellia,
    /// <summary>ChaCha20 (RFC 8439).</summary>
    ChaCha20,
    /// <summary>CAST5 (RFC 2144). Legacy.</summary>
    Cast5,
    /// <summary>IDEA. Legacy.</summary>
    Idea,
    /// <summary>Blowfish. Legacy.</summary>
    Blowfish,
    /// <summary>Twofish. Legacy.</summary>
    Twofish,
    /// <summary>Triple DES. Legacy.</summary>
    TripleDes,
    /// <summary>DES, RC2 and RC4 and the like. Broken.</summary>
    Broken,
}

/// <summary>The password-based key derivation functions, for <see cref="CryptoPolicy.CheckKdf"/>.</summary>
public enum KdfAlgorithm
{
    /// <summary>PBKDF2 (RFC 8018 §5.2); the cost is the iteration count.</summary>
    Pbkdf2,
    /// <summary>The OpenPGP iterated-and-salted string-to-key (RFC 9580 §3.7.1.3); the cost is the octet count (already decoded).</summary>
    IteratedSaltedS2k,
    /// <summary>The OpenPGP simple or salted string-to-key without iteration (RFC 9580 §3.7.1.1–2): cost is irrelevant, always weak.</summary>
    SimpleS2k,
    /// <summary>Argon2 (RFC 9106); the cost is the memory in KiB.</summary>
    Argon2,
    /// <summary>scrypt (RFC 7914); the cost is N.</summary>
    Scrypt,
    /// <summary>bcrypt-pbkdf (OpenSSH keys); the cost is the rounds.</summary>
    BcryptPbkdf,
}

/// <summary>
/// A dated rule for one algorithm: flagged from one instant, rejected from another, optionally rejected outright for new data.
/// Instants are compared with the reference time of the question, so the same signature can be fine in 2012, flagged in 2020 and refused in 2031.
/// </summary>
/// <param name="Name">The algorithm's name as the policy matches it (<c>SHA-1</c>, <c>MD5</c>, …).</param>
/// <param name="FlagFrom">Verification at or after this instant is flagged. Null: never flagged by date.</param>
/// <param name="RejectFrom">Verification at or after this instant is rejected. Null: never rejected by date.</param>
/// <param name="RejectNew">Creating new data with it is rejected whatever the date.</param>
/// <param name="Reference">The standard behind the dates.</param>
public sealed record AlgorithmRule(string Name, DateTimeOffset? FlagFrom, DateTimeOffset? RejectFrom, bool RejectNew, string Reference)
{
    /// <summary>
    /// For <see cref="CryptoUse.VerifyPki"/>: flagged from this instant. Null: <see cref="FlagFrom"/> applies. A collision-prone hash in a certificate lets an
    /// attacker forge a certificate, so PKI signatures may be refused long before message signatures are.
    /// </summary>
    public DateTimeOffset? PkiFlagFrom { get; init; }

    /// <summary>For <see cref="CryptoUse.VerifyPki"/>: rejected from this instant. Null: <see cref="RejectFrom"/> applies.</summary>
    public DateTimeOffset? PkiRejectFrom { get; init; }
}

/// <summary>
/// Which algorithms, sizes and options the library accepts. Immutable: derive a variant with a <c>with</c> expression
/// (<c>CryptoPolicy.Standard with { MinRsaBitsNew = 3072 }</c>). Every question takes an explicit reference time; the policy never reads a clock.
/// </summary>
/// <remarks>
/// <para><b>Reference time.</b> It is the instant the question is about: the moment of a fresh validation, a signature's proven existence time, or the
/// past instant of an AdES validation. Callers holding a clock pass <c>timeProvider.GetUtcNow()</c> themselves. For <see cref="CryptoUse.Sign"/>,
/// <see cref="CryptoUse.Encrypt"/> and the new-data rules the date does not matter: new data is judged by the "new" rules.</para>
/// <para><b>Presets.</b> <see cref="Standard"/> keeps the world working: legacy data stays readable and is flagged. <see cref="Strict"/> accepts nothing deprecated.</para>
/// </remarks>
public sealed record CryptoPolicy
{
    private static readonly DateTimeOffset s_2009 = new(2009, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset s_2011 = new(2011, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset s_2017 = new(2017, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset s_2014 = new(2014, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset s_2031 = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// The default policy. SHA-1 signatures are never made, are flagged when verified at or after 2011-01-01 (NIST SP 800-131A Rev. 2 §3: deprecated for
    /// signature generation from 2011) and rejected at or after 2031-01-01 (the end of NIST's planned retirement, 2030-12-31). MD5 signatures are never made, are
    /// flagged before 2009-01-01 and rejected from it (RFC 6151: practical certificate forgery, December 2008). RSA below 2048 bits is refused for new
    /// data, flagged on verification at or after 2014-01-01 (SP 800-131A: 1024-bit disallowed from 2014) and below 1024 bits rejected always.
    /// Legacy ciphers decrypt with a flag and do not encrypt; unauthenticated encryption fails closed in both directions.
    /// </summary>
    public static CryptoPolicy Standard { get; } = new();

    /// <summary>
    /// The conservative policy: no SHA-1 or MD5 at any time; RSA at least 2048 bits to verify and 3072 to sign or encrypt (SP 800-57 Part 1 Rev. 5 Table 2);
    /// legacy ciphers neither encrypt nor decrypt; EC keys of at least 256 bits; PBKDF2 at least 100,000 iterations.
    /// </summary>
    public static CryptoPolicy Strict { get; } = new()
    {
        Name = "Strict",
        HashRules =
        [
            new("MD5", null, DateTimeOffset.MinValue, true, "RFC 6151 §2"),
            new("SHA-1", null, DateTimeOffset.MinValue, true, "RFC 9155 §3; NIST SP 800-131A Rev. 2 §3"),
            new("RIPEMD-160", null, DateTimeOffset.MinValue, true, "RFC 9580 §9.5: not recommended; a 160-bit digest"),
        ],
        MinRsaBitsNew = 3072,
        MinRsaBitsVerify = 2048,
        RsaWeakFrom = null,
        MinEcBits = 256,
        LegacyCiphers = LegacyCipherMode.Reject,
        MinPbkdf2Iterations = 100_000,
        FlagAsRejected = true,
    };

    /// <summary>
    /// Accepts every algorithm and key size the library can verify, with no dated cutoffs: what RFC 5280 itself requires and nothing more. For conformance
    /// suites and for reading old data; not a policy to trust new material under.
    /// </summary>
    public static CryptoPolicy Permissive { get; } = new()
    {
        Name = "Permissive",
        HashRules = [],
        MinRsaBitsNew = 0,
        MinRsaBitsVerify = 0,
        RsaWeakFrom = DateTimeOffset.MaxValue,
        MinEcBits = 0,
        LegacyCiphers = LegacyCipherMode.DecryptOnly,
        MinPbkdf2Iterations = 1,
    };

    /// <summary>A name for reports.</summary>
    public string Name { get; init; } = "Standard";

    /// <summary>The dated hash rules. A hash with no rule is accepted.</summary>
    public IReadOnlyList<AlgorithmRule> HashRules { get; init; } =
    [
        new("MD5", s_2009 - TimeSpan.FromDays(3650), s_2009, true, "RFC 6151 §2"),
        new("SHA-1", s_2011, s_2031, true, "NIST SP 800-131A Rev. 2 §3; RFC 9155 §3")
        {
            // Certificates, CRLs and OCSP responses: public CAs stopped issuing SHA-1 certificates in 2016 and chosen-prefix collisions make forgery practical.
            PkiRejectFrom = s_2017,
        },
        // RIPEMD-160 has a 160-bit digest like SHA-1 and is not recommended for OpenPGP (RFC 9580 §9.5); it follows SHA-1's dates.
        new("RIPEMD-160", s_2011, s_2031, true, "RFC 9580 §9.5; NIST SP 800-131A Rev. 2 §3 (160-bit digest)"),
    ];

    /// <summary>Smallest RSA modulus, in bits, accepted for new signatures and encryption. Default 2048 (NIST SP 800-131A Rev. 2 §3).</summary>
    public int MinRsaBitsNew { get; init; } = 2048;

    /// <summary>Smallest RSA modulus accepted at all when verifying or decrypting. Default 1024: smaller keys are factorable (NIST SP 800-57 Part 1 Rev. 5 Table 2).</summary>
    public int MinRsaBitsVerify { get; init; } = 1024;

    /// <summary>
    /// From this instant, verifying with an RSA key under 2048 bits is flagged; earlier it is accepted. Default 2014-01-01. Null: not flagged by date, so
    /// a key under <see cref="MinRsaBitsVerify"/> is the only RSA key refused (set <see cref="MinRsaBitsVerify"/> to 2048 to refuse the rest).
    /// </summary>
    public DateTimeOffset? RsaWeakFrom { get; init; } = s_2014;

    /// <summary>Smallest elliptic-curve key, in bits. Default 224 (P-224 is flagged below 256 for new data).</summary>
    public int MinEcBits { get; init; } = 224;

    /// <summary>What legacy ciphers (CAST5, IDEA, Blowfish, Twofish, 3DES) may do. Default: decrypt, flagged.</summary>
    public LegacyCipherMode LegacyCiphers { get; init; } = LegacyCipherMode.DecryptOnly;

    /// <summary>
    /// Allow decrypting data with no integrity protection (OpenPGP SED, CBC without MAC). Default false: it fails closed (RFC 9580 §5.7 deprecates the unprotected SED packet).
    /// </summary>
    public bool AllowUnauthenticatedDecryption { get; init; }

    /// <summary>Allow producing unauthenticated ciphertext. Default false. The library offers no use for it; the switch exists for interoperating with a broken peer.</summary>
    public bool AllowUnauthenticatedEncryption { get; init; }

    /// <summary>Fewest PBKDF2 iterations accepted. Default 1,000 (RFC 8018 §4.2 lower bound), flagged below 10,000.</summary>
    public int MinPbkdf2Iterations { get; init; } = 1000;

    /// <summary>When true, every Flagged verdict is returned as Rejected (the Strict behaviour).</summary>
    public bool FlagAsRejected { get; init; }

    /// <summary>Limits applied to ASN.1 read under this policy. Default <see cref="Asn1Limits.Default"/>.</summary>
    public Asn1Limits Asn1Limits { get; init; } = Asn1Limits.Default;

    /// <summary>Limits applied to certificates, requests, revocation data and OCSP read under this policy. Default <see cref="X509Limits.Default"/>.</summary>
    public X509Limits X509Limits { get; init; } = X509Limits.Default;

    /// <summary>Limits on the cost of password-based derivations from untrusted parameters. Default <see cref="KdfLimits.Default"/>.</summary>
    public KdfLimits KdfLimits { get; init; } = KdfLimits.Default;

    private PolicyDecision Finish(PolicyDecision d) =>
        FlagAsRejected && d.Verdict == PolicyVerdict.Flagged ? d with { Verdict = PolicyVerdict.Rejected, Reason = d.Reason + " (the policy rejects deprecated algorithms)" } : d;

    /// <summary>Asks about a hash used in a signature, certificate identifier or MAC.</summary>
    /// <param name="hash">The hash (<c>SHA-1</c> and <c>SHA1</c> both match).</param>
    /// <param name="use">What the hash is for. <see cref="CryptoUse.Sign"/> and <see cref="CryptoUse.Encrypt"/> mean new data.</param>
    /// <param name="at">The reference time. Used for verification; new-data uses ignore it.</param>
    public PolicyDecision CheckHash(HashAlgorithmName hash, CryptoUse use, DateTimeOffset at)
    {
        string name = Canonical(hash.Name);
        AlgorithmRule? rule = HashRules.FirstOrDefault(r => r.Name == name);
        if (rule is null || (use == CryptoUse.Mac && name == "SHA-1"))
        {
            // HMAC-SHA-1 does not depend on collision resistance (RFC 6194 §3), so the SHA-1 rule does not reach it.
            return PolicyDecision.Ok(use, name);
        }

        string id = "hash." + name.ToLowerInvariant();
        bool isNew = use is CryptoUse.Sign or CryptoUse.Encrypt;
        if (isNew && rule.RejectNew)
        {
            return Finish(new(PolicyVerdict.Rejected, use, name, id + ".new", $"{name} is not used for new signatures.", rule.Reference));
        }

        bool pki = use == CryptoUse.VerifyPki;
        if (pki)
        {
            id += ".pki";
        }

        if ((pki ? rule.PkiRejectFrom ?? rule.RejectFrom : rule.RejectFrom) is { } rej && at >= rej)
        {
            return Finish(new(PolicyVerdict.Rejected, use, name, id + ".rejected-from", $"{name} is rejected from {rej:yyyy-MM-dd}; the reference time is {at:yyyy-MM-dd}.", rule.Reference));
        }

        if ((pki ? rule.PkiFlagFrom ?? rule.FlagFrom : rule.FlagFrom) is { } flag && at >= flag)
        {
            return Finish(new(PolicyVerdict.Flagged, use, name, id + ".flagged-from", $"{name} is deprecated from {flag:yyyy-MM-dd}; the reference time is {at:yyyy-MM-dd}.", rule.Reference));
        }

        return PolicyDecision.Ok(use, name);
    }

    /// <summary>Asks about a public key's algorithm and size (RSA modulus bits, EC curve bits).</summary>
    /// <param name="key">The key.</param>
    /// <param name="use">Sign and Encrypt judge new data; Verify and Decrypt judge existing data at <paramref name="at"/>.</param>
    /// <param name="at">The reference time.</param>
    public PolicyDecision CheckKey(PublicKeyInfo key, CryptoUse use, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(key);
        int bits = key.KeySizeBits;
        string name = bits > 0 ? $"{key.Algorithm.Name} {bits}-bit" : key.Algorithm.Name;
        bool isNew = use is CryptoUse.Sign or CryptoUse.Encrypt;
        switch (key.KeyAlgorithm)
        {
            case KeyAlgorithm.Rsa or KeyAlgorithm.RsaPss or KeyAlgorithm.RsaOaep:
                if (isNew && bits < MinRsaBitsNew)
                {
                    return Finish(new(PolicyVerdict.Rejected, use, name, "key.rsa.min-new", $"RSA keys under {MinRsaBitsNew} bits are not used for new data.", "NIST SP 800-131A Rev. 2 §3; SP 800-57 Part 1 Rev. 5 Table 2"));
                }

                if (!isNew && bits < MinRsaBitsVerify)
                {
                    return Finish(new(PolicyVerdict.Rejected, use, name, "key.rsa.min-verify", $"RSA keys under {MinRsaBitsVerify} bits are too small to rely on.", "NIST SP 800-57 Part 1 Rev. 5 Table 2"));
                }

                if (!isNew && bits < 2048 && RsaWeakFrom is { } weak && at >= weak)
                {
                    return Finish(new(PolicyVerdict.Flagged, use, name, "key.rsa.weak-from", $"RSA keys under 2048 bits are deprecated from {weak:yyyy-MM-dd}; the reference time is {at:yyyy-MM-dd}.", "NIST SP 800-131A Rev. 2 §3"));
                }

                if (!isNew && bits < 2048 && RsaWeakFrom is null)
                {
                    return Finish(new(PolicyVerdict.Flagged, use, name, "key.rsa.weak", "RSA keys under 2048 bits are deprecated.", "NIST SP 800-131A Rev. 2 §3"));
                }

                return PolicyDecision.Ok(use, name);
            case KeyAlgorithm.EllipticCurve:
                if (bits > 0 && bits < MinEcBits)
                {
                    return Finish(new(PolicyVerdict.Rejected, use, name, "key.ec.min", $"EC keys under {MinEcBits} bits are not accepted.", "NIST SP 800-57 Part 1 Rev. 5 Table 2"));
                }

                if (bits > 0 && bits < 256 && isNew)
                {
                    return Finish(new(PolicyVerdict.Flagged, use, name, "key.ec.under-256", "EC keys under 256 bits give less than 128-bit security.", "NIST SP 800-57 Part 1 Rev. 5 Table 2"));
                }

                return PolicyDecision.Ok(use, name);
            default:
                return PolicyDecision.Ok(use, name);
        }
    }

    /// <summary>
    /// Asks about a signature algorithm identifier and the signer's key together: the hash it names (SHA-1 in <c>sha1WithRSAEncryption</c>, the hash in
    /// RSASSA-PSS parameters) and the key size. The report holds one decision for each.
    /// </summary>
    /// <param name="signatureAlgorithm">The identifier from the signed structure.</param>
    /// <param name="signerKey">The signer's public key.</param>
    /// <param name="use"><see cref="CryptoUse.Sign"/> or <see cref="CryptoUse.Verify"/>.</param>
    /// <param name="at">The reference time.</param>
    public PolicyReport CheckSignature(AlgorithmIdentifier signatureAlgorithm, PublicKeyInfo signerKey, CryptoUse use, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(signatureAlgorithm);
        var list = new List<PolicyDecision>(2);
        if (SignatureAlgorithms.TryScheme(signatureAlgorithm, out SignatureScheme scheme))
        {
            list.Add(CheckHash(scheme.Hash, use, at));
        }
        else if (signatureAlgorithm.Oid == KnownOids.RsaPss)
        {
            try
            {
                PssParameters p = PssParameters.Parse(signatureAlgorithm.Parameters);
                if (SignatureAlgorithms.TryHash(p.HashOid, out HashAlgorithmName h))
                {
                    list.Add(CheckHash(h, use, at));
                }
            }
            catch (Asn1ParseException)
            {
                // Unreadable parameters are reported by the verifier; the policy has no hash to judge.
            }
        }

        list.Add(CheckKey(signerKey, use, at));
        return new PolicyReport(list);
    }

    /// <summary>Asks about a signature spec and signer key for new signatures, as the identifier overload does.</summary>
    public PolicyReport CheckSignature(Keys.SignatureSpec spec, PublicKeyInfo signerKey, CryptoUse use, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(spec);
        var list = new List<PolicyDecision>(2);
        if (spec.SignsDigest)
        {
            list.Add(CheckHash(spec.Hash, use, at));
        }

        list.Add(CheckKey(signerKey, use, at));
        return new PolicyReport(list);
    }

    /// <summary>Asks about a symmetric cipher.</summary>
    /// <param name="cipher">The cipher family.</param>
    /// <param name="authenticated">True for an AEAD or a mode with a verified MAC/MDC; false for bare CBC/CFB/CTR/SED.</param>
    /// <param name="use"><see cref="CryptoUse.Encrypt"/> or <see cref="CryptoUse.Decrypt"/>.</param>
    public PolicyDecision CheckCipher(CipherAlgorithm cipher, bool authenticated, CryptoUse use)
    {
        string name = cipher.ToString();
        bool encrypt = use is CryptoUse.Encrypt or CryptoUse.Sign;
        if (cipher == CipherAlgorithm.Broken)
        {
            return new(PolicyVerdict.Rejected, use, name, "cipher.broken", "DES, RC2 and RC4 are broken.", "RFC 8429; RFC 7465");
        }

        if (!authenticated)
        {
            bool allowed = encrypt ? AllowUnauthenticatedEncryption : AllowUnauthenticatedDecryption;
            if (!allowed)
            {
                return new(PolicyVerdict.Rejected, use, name, encrypt ? "cipher.unauthenticated.encrypt" : "cipher.unauthenticated.decrypt",
                    "Encryption without integrity protection fails closed.", "RFC 9580 §5.7");
            }
        }

        if (cipher is CipherAlgorithm.Cast5 or CipherAlgorithm.Idea or CipherAlgorithm.Blowfish or CipherAlgorithm.Twofish or CipherAlgorithm.TripleDes)
        {
            if (encrypt && LegacyCiphers != LegacyCipherMode.EncryptAndDecrypt)
            {
                return new(PolicyVerdict.Rejected, use, name, "cipher.legacy.encrypt", $"{name} is decrypt-only; it is not used for new data.", "RFC 9580 §9.3");
            }

            if (!encrypt && LegacyCiphers == LegacyCipherMode.Reject)
            {
                return new(PolicyVerdict.Rejected, use, name, "cipher.legacy.decrypt", $"{name} is not accepted by this policy.", "RFC 9580 §9.3");
            }

            return Finish(new(PolicyVerdict.Flagged, use, name, "cipher.legacy", $"{name} is a legacy cipher.", "RFC 9580 §9.3"));
        }

        return PolicyDecision.Ok(use, name);
    }

    /// <summary>
    /// Asks about a content-encryption mode that has no integrity check of its own but is wrapped by a container that is meant to carry one (CBC in CMS
    /// EnvelopedData, RFC 5652 §6.3; S/MIME 4.0 asks for AuthEnvelopedData, RFC 8551 §2.7). Unlike <see cref="CheckCipher"/>, which fails bare unauthenticated
    /// encryption closed, this flags the mode: <see cref="Standard"/> still reads and writes it, <see cref="Strict"/> (which turns flags into rejections) refuses it,
    /// and setting <see cref="AllowUnauthenticatedDecryption"/> or <see cref="AllowUnauthenticatedEncryption"/> accepts it without a flag.
    /// </summary>
    /// <param name="cipherName">The cipher in readable form (<c>AES-256-CBC</c>).</param>
    /// <param name="use"><see cref="CryptoUse.Encrypt"/> or <see cref="CryptoUse.Decrypt"/>.</param>
    public PolicyDecision CheckContentCipher(string cipherName, CryptoUse use)
    {
        bool encrypt = use is CryptoUse.Encrypt or CryptoUse.Sign;
        if (encrypt ? AllowUnauthenticatedEncryption : AllowUnauthenticatedDecryption)
        {
            return PolicyDecision.Ok(use, cipherName);
        }

        return Finish(new(PolicyVerdict.Flagged, use, cipherName, encrypt ? "cipher.cbc.unauthenticated.encrypt" : "cipher.cbc.unauthenticated.decrypt",
            $"{cipherName} does not protect the content's integrity; use AuthEnvelopedData or sign the message.", "RFC 5652 §6.3; RFC 8551 §2.7"));
    }

    /// <summary>Asks about a password-based derivation's cost parameter.</summary>
    /// <param name="kdf">The function.</param>
    /// <param name="cost">The function's cost as listed on <see cref="KdfAlgorithm"/>.</param>
    public PolicyDecision CheckKdf(KdfAlgorithm kdf, long cost)
    {
        string name = kdf.ToString();
        switch (kdf)
        {
            case KdfAlgorithm.SimpleS2k:
                return Finish(new(PolicyVerdict.Flagged, CryptoUse.Kdf, name, "kdf.s2k.simple", "A string-to-key without iteration gives a password no stretching.", "RFC 9580 §3.7.1"));
            case KdfAlgorithm.Pbkdf2:
                if (cost < MinPbkdf2Iterations)
                {
                    return Finish(new(PolicyVerdict.Rejected, CryptoUse.Kdf, name, "kdf.pbkdf2.min", $"PBKDF2 with {cost} iterations is under the minimum of {MinPbkdf2Iterations}.", "RFC 8018 §4.2"));
                }

                if (cost < 10_000)
                {
                    return Finish(new(PolicyVerdict.Flagged, CryptoUse.Kdf, name, "kdf.pbkdf2.low", $"PBKDF2 with {cost} iterations is low.", "NIST SP 800-132 §5.2"));
                }

                return PolicyDecision.Ok(CryptoUse.Kdf, name);
            case KdfAlgorithm.Argon2 when cost > KdfLimits.MaxMemoryBytes / 1024:
                return new(PolicyVerdict.Rejected, CryptoUse.Kdf, name, "kdf.limit.memory", $"Argon2 memory of {cost} KiB exceeds the limit of {KdfLimits.MaxMemoryBytes / 1024} KiB.", "RFC 9106 §4");
            default:
                return PolicyDecision.Ok(CryptoUse.Kdf, name);
        }
    }

    private static string Canonical(string? name) => (name ?? string.Empty).ToUpperInvariant().Replace("_", "-", StringComparison.Ordinal) switch
    {
        "SHA1" or "SHA-1" => "SHA-1",
        "SHA224" or "SHA-224" => "SHA-224",
        "RIPEMD160" or "RIPEMD-160" => "RIPEMD-160",
        "SHA256" or "SHA-256" => "SHA-256",
        "SHA384" or "SHA-384" => "SHA-384",
        "SHA512" or "SHA-512" => "SHA-512",
        "MD5" => "MD5",
        var other => other,
    };
}

/// <summary>What legacy ciphers may do under a policy.</summary>
public enum LegacyCipherMode
{
    /// <summary>Decrypt existing data (flagged); never encrypt. The default.</summary>
    DecryptOnly = 0,
    /// <summary>Neither.</summary>
    Reject = 1,
    /// <summary>Both (flagged). For talking to a peer that needs it.</summary>
    EncryptAndDecrypt = 2,
}

/// <summary>Thrown when an operation is refused by the policy. The report says which rule decided.</summary>
public sealed class PolicyViolationException : InvalidOperationException
{
    /// <summary>Creates the exception from the report that rejected the operation.</summary>
    public PolicyViolationException(PolicyReport report)
        : base(Describe(report))
    {
        Report = report;
    }

    /// <summary>The decisions, including the rejecting ones.</summary>
    public PolicyReport Report { get; }

    private static string Describe(PolicyReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        PolicyDecision d = report.Decisions.FirstOrDefault(x => x.Verdict == PolicyVerdict.Rejected);
        return $"The policy rejects {d.Algorithm}: {d.Reason} [{d.Rule}; {d.Reference}]";
    }
}
