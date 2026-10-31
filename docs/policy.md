# Crypto policy

`CryptoPolicy` (`RecursiveAI.OneCrypto.Policy`) decides which algorithms, key sizes and options the library accepts. It is an immutable record: derive a variant with `with`.

```csharp
CryptoPolicy p = CryptoPolicy.Standard with { MinRsaBitsNew = 3072 };
```

## Reference time

Every validity question takes an explicit `DateTimeOffset at`. The policy never reads a clock; a caller that wants "now" passes `timeProvider.GetUtcNow()`. The instant means:

- for a fresh validation: the moment of validation;
- for a validation in the past (the AdES past-time model): the instant being asked about, for example the time of the signature timestamp;
- for new data (`Sign`, `Encrypt`): the date does not matter, the "new data" rules apply.

## Decisions and reports

Each question returns a `PolicyDecision`: `Verdict` (`Accepted`, `Flagged`, `Rejected`), `Use`, `Algorithm`, a stable `Rule` id (`hash.sha-1.rejected-from`), a `Reason` with the dates involved, and the `Reference` it comes from. Accepted-by-default decisions have empty rule, reason and reference. `CheckSignature` returns a `PolicyReport` with one decision per component (the hash named by the signature algorithm, including the hash inside RSASSA-PSS parameters, and the signer's key) and the worst verdict. `Flagged` means allowed but deprecated: callers surface it. An operation that is refused throws `PolicyViolationException` carrying the report. Validators and verifiers add the decisions to their per-signature results.

## Rules in `Standard`

| Rule | Behaviour | Source |
|---|---|---|
| SHA-1 in a message signature (CMS SignerInfo, and OpenPGP later; `CryptoUse.Verify`) | never for new signatures (`hash.sha-1.new`); on verification accepted before 2011-01-01, flagged from it (`hash.sha-1.flagged-from`), rejected from 2031-01-01 (`hash.sha-1.rejected-from`) | NIST SP 800-131A Rev. 2 §3 (deprecated from 2011, retirement planned by 2030-12-31); RFC 9155 |
| SHA-1 in a PKI signature (certificate, CRL, OCSP response or request, certificate request, attribute certificate; `CryptoUse.VerifyPki`) | never for new signatures; on verification accepted before 2011-01-01, flagged from it (`hash.sha-1.pki.flagged-from`), rejected from 2017-01-01 (`hash.sha-1.pki.rejected-from`) | CA/Browser Forum Baseline Requirements §7.1.3.2 (no SHA-1 certificate signatures from 2016, distrusted by browsers in 2017); RFC 9155 §3; NIST SP 800-131A Rev. 2 §3 |
| SHA-1 inside HMAC | accepted (no collision resistance needed) | RFC 6194 §3 |
| MD5 | never for new; flagged from ~1999 and rejected from 2009-01-01 | RFC 6151 (certificate forgery, Dec 2008) |
| RSA modulus, new data (sign, encrypt) | under 2048 bits rejected (`key.rsa.min-new`) | SP 800-131A Rev. 2 §3; SP 800-57-1 Rev. 5 Table 2 |
| RSA modulus, existing data (verify, decrypt) | under 1024 rejected (`key.rsa.min-verify`); under 2048 accepted before 2014-01-01, flagged from it (`key.rsa.weak-from`) | same |
| EC keys | under 224 bits rejected; under 256 flagged for new data | SP 800-57-1 Rev. 5 Table 2 |
| Legacy ciphers (CAST5, IDEA, Blowfish, Twofish, 3DES) | decrypt flagged, never encrypt (`LegacyCipherMode.DecryptOnly`) | RFC 9580 §9.3 |
| DES, RC2, RC4 | rejected | RFC 8429, RFC 7465 |
| Unauthenticated encryption (bare CBC/CFB, OpenPGP SED) | rejected both ways; `AllowUnauthenticatedDecryption` / `AllowUnauthenticatedEncryption` opt in (SED decrypts only with the first) | RFC 9580 §5.7 |
| PBKDF2 iterations | under 1,000 rejected, under 10,000 flagged | RFC 8018 §4.2; SP 800-132 |
| Simple S2K (no iteration) | flagged | RFC 9580 §3.7.1 |
| Argon2 memory | over `KdfLimits.MaxMemoryBytes` rejected | RFC 9106 §4 |

## `Strict`

No SHA-1 or MD5 at any time; RSA at least 3072 bits for new data and 2048 to verify; EC at least 256 bits; legacy ciphers neither encrypt nor decrypt; PBKDF2 at least 100,000 iterations; every `Flagged` becomes `Rejected` (`FlagAsRejected`), with the reason noted.

## Limits

The policy gathers the parser limits so one object configures a run: `Asn1Limits`, `X509Limits` and `KdfLimits` (each defaulting to the type's `Default`). The parsers take their limits as explicit parameters and use the defaults when given none; a caller passes `policy.X509Limits` and so on to apply the policy's. The limits are on whether or not a policy is used.

## Customising dates

`HashRules` is a list of `AlgorithmRule(Name, FlagFrom, RejectFrom, RejectNew, Reference)`; replace it to move a cutoff. `RsaWeakFrom` moves the RSA deprecation date (`null` flags every sub-2048 key). The dates above are this library's choices from the cited documents, not a legal standard: a validation profile (EN 319 102-1, CA/B Forum) overrides them with its own.

## Where the library asks

Every builder that signs new data takes an optional `CryptoPolicy` (default `Standard`): `CertificateBuilder.Create` / `CreateSelfSigned`, `CertificateSigningRequestBuilder.Create`, `RevocationListBuilder.Create`, `OcspRequestBuilder.Create`, `OcspResponseBuilder.CreateSuccessful`, `SignedDataOptions.Policy` for CMS and `CmsEncryptOptions.Policy` for encryption. A refusal is a `PolicyViolationException` listing the decisions. The two-phase `Prepare` methods take the policy and a time explicitly; their `Complete` does not ask again.

Verification asks only when given a policy and a time: `Certificate.VerifySignature(key, policy, at)` and `PublicKeyInfo.VerifySignature(algorithm, data, signature, policy, at)` return a `SignatureVerification` whose `Policy` holds the decisions and whose status is `PolicyRejected` when the signature is correct but refused at `at` (not valid). CMS: `SignedDataVerifyOptions.Policy` / `ReferenceTime` and `CmsDecryptOptions.Policy` / `ReferenceTime`; see `cms.md`. The path validator asks for the signatures on certificates, CRLs, delta CRLs, OCSP responses and delegated responder certificates as PKI signatures.

`CheckContentCipher` (CBC inside a container that is meant to carry integrity) is flagged under `Standard`, rejected under `Strict`, and accepted when the matching `AllowUnauthenticated…` switch is on.

## Signature use

A signature on a certificate, CRL, OCSP response or request, certificate request or attribute certificate is a PKI signature and is asked with `CryptoUse.VerifyPki`; a signature on a message (a CMS SignerInfo, an OpenPGP signature) is asked with `CryptoUse.Verify`. The two differ only where an `AlgorithmRule` carries its own PKI cutoffs (`PkiFlagFrom`, `PkiRejectFrom`; a null falls back to `FlagFrom` and `RejectFrom`). The reason is that a collision in a certificate signature lets an attacker forge a certificate (chosen-prefix collisions against SHA-1 have been practical since 2019 and the WebPKI stopped SHA-1 issuance in 2016), while a collision in a message signature needs the signer to sign attacker-influenced content; so `Standard` refuses SHA-1 in PKI signatures from 2017-01-01 and keeps the SP 800-131A dates for messages. `Strict` and `Permissive` do not distinguish the use. A PKI decision's rule id carries `.pki.` (`hash.sha-1.pki.rejected-from`) so a report shows which cutoff applied.

There is no separate `WebPki` preset. The server-authentication profile of the path validator does not ask a second policy: SHA-1 is already refused from 2017 under `Standard`, and the profile keeps its own 2048-bit RSA floor as a profile rule (`WebPkiProfile`, Baseline Requirements §6.1.5). A caller who chose `Permissive` or a tuned policy keeps that choice under the profile.

`Permissive` accepts every algorithm and key size the library can verify, with no dated cutoffs: the policy of conformance suites and of reading old data. The path validator takes a policy in `ValidationOptions.Policy` (default `Standard`) and asks `CheckSignature` for every certificate signature at the reference time; its per-certificate results carry the decision's rule id (`docs/validation.md`).
