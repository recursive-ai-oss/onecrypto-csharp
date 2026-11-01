# Path building and validation

Normative behaviour of `PathValidator` in `RecursiveAI.OneCrypto.Validation` (core package). Clause numbers are RFC 5280 unless another document is named. The validator builds on the models of `docs/x509.md` and the signature dispatch of `docs/fallbacks.md`.

## What it is

One function, `PathValidator.Validate(target, options)`, builds candidate paths from a certificate to a trust anchor and validates each by RFC 5280 §6.1, with revocation per §6.3 and RFC 6960. The verdict is a pure function of the inputs and an explicit `ReferenceTime`: nothing reads a clock, the operating system's chain engine is never consulted, and nothing is fetched. `OsTrustStore.LoadRoots()` can supply anchors; it is a source of certificates, not an engine, so the same inputs give the same verdict on every platform. Bad input is a report, never an exception.

`ValidateAsync` is the same call plus two optional interfaces. When `CertificateSource` or `RevocationSource` is set it asks them for missing issuers and revocation data (given the `caIssuers`, CRL and OCSP locations in the certificates) and validates again, at most `MaxSourceRounds` times. Without a source it does no I/O. The interfaces are all this layer knows about fetching.

## Inputs

| Option | Meaning |
|---|---|
| `TrustAnchors` | Certificates, or bare name and key (RFC 5937). Only these confer trust. |
| `Intermediates` | An untrusted pool. |
| `ReferenceTime` | Required. Validity, algorithm cutoffs and revocation freshness are judged at this instant. |
| `RevocationDataTime` | When the revocation data is judged fresh (default: the reference time). |
| `Revocation`, `RevocationRequired`, `UnknownRevocationIsFatal`, `RevocationModel` | See Revocation. |
| `Policy` | The `CryptoPolicy` (`docs/policy.md`) asked about every certificate signature at the reference time: the hash its algorithm names (including the hash inside RSASSA-PSS parameters) and the issuing key, as a PKI signature (`CryptoUse.VerifyPki`). The signatures on CRLs, delta CRLs, OCSP responses and delegated responder certificates are asked the same way at the revocation-data time, and their decisions are in `RevocationReport.PolicyDecisions` with their rule ids. Default `CryptoPolicy.Standard`; `Strict` and `Permissive` (no cutoffs: what RFC 5280 requires and nothing more) are the other presets, and `with` derives variants. |
| `RequiredExtendedKeyUsage`, `RequiredKeyUsage` | What the target must permit; extended key usage is chained through every CA that has the extension. |
| `InitialPolicySet`, `InitialExplicitPolicy`, `InitialPolicyMappingInhibit`, `InitialAnyPolicyInhibit` | §6.1.1 (c) to (h). |
| `ApplyAnchorNameConstraints`, `ApplyAnchorPolicyConstraints`, `CheckAnchorValidity` | What of an anchor certificate beyond its name and key is used (defaults: name constraints and validity yes, policy extensions no). |
| `MaxIntermediates` | Hard cap on non-self-issued intermediates. |
| `StrictStructure` | Default true. See Structure rules. |
| `WebPki` | The server-authentication profile. |
| `Limits` | See Limits. |

## Path building

Candidates come from the anchors, then the pool. A candidate must have a subject equal to the issuer name (§7.1 comparison) and its key must verify the signature. Order is deterministic: anchors before pool; candidates whose subjectKeyIdentifier equals the authorityKeyIdentifier first (RFC 4158 §4.2), then those valid at the reference time, then those that can issue (a CA by basicConstraints, with keyCertSign if keyUsage is present: a decoy that cannot is tried after every candidate that can, so a pool full of them cannot use up the budget before the real issuer), then later `notAfter`, then the encoding. Depth-first search with backtracking; a certificate may appear once in a path and so may a subject-and-key pair, which removes the cycles that mutual cross-certification makes. Signature verifications are cached per certificate and key. A target that is itself an anchor certificate is a path of length one. Certificates with no issuer are listed in `Unchained`, and their `authorityInfoAccess` `caIssuers` locations in `IssuerLocations`; they are not fetched.

The first path that validates ends the search. When none does and no limit was reached, the verdict is `Invalid`; when a work limit stopped the search (`LimitReached`) it is `Indeterminate` with a `Limit` result, because "no path found" is then not proof that none exists (RFC 4158 §3). The report carries the paths that were completed (at most `MaxReportedPaths`), the candidates refused with the reason, and the verdict of the path that got furthest.

## Rules applied to every certificate

Each result carries a rule, an outcome (`Pass`, `Warning`, `Fail`, `Indeterminate`, `NotApplicable`), a reason in words and a clause.

| Rule | What is checked | Clause |
|---|---|---|
| IssuerName | issuer equals the working issuer name | §6.1.3 (a)(4) |
| Signature | verifies over the received `tbsCertificate` octets with the issuer's key | §6.1.3 (a)(1) |
| Algorithm | the `CryptoPolicy`: one result per decision that is not a plain accept, carrying the policy's rule id (`RuleResult.PolicyRule`, for example `hash.sha-1.rejected-from`, `key.rsa.min-verify`) and its standard as the clause; `Rejected` fails, `Flagged` is a warning; a certificate with no finding gets one pass naming the policy. The key judged is the issuer's, on the signature it made, so a 1024-bit intermediate is reported on the certificates it signed. | `CryptoPolicy` |
| Validity | `notBefore <= t <= notAfter` at the reference time truncated to whole seconds (certificate times have no fractions) | §6.1.3 (a)(2) |
| NameConstraints | subject and subjectAltName against every constraint set above: directoryName (RDN-prefix), dNSName, rfc822Name, URI host, iPAddress; subject `emailAddress` and `SmtpUTF8Mailbox` (RFC 8398 §6) as rfc822Name; a trailing dot on a dNSName or URI host and percent-encoding in a URI host are normalised first (RFC 3986 §2.1, §3.2.2); self-issued intermediates exempt; a wildcard dNSName overlaps an excluded subtree it could reach; a critical constraint on a name form that cannot be evaluated fails | §6.1.3 (b)(c), §4.2.1.10 |
| Policy | the valid_policy_tree with mappings, `inhibitAnyPolicy`, `requireExplicitPolicy`, `inhibitPolicyMapping`, the user-initial-policy-set, bounded by `MaxPolicyNodes` | §6.1.3 (d)–(f), §6.1.4, §6.1.5 |
| BasicConstraints, PathLengthConstraint | CA certificates assert cA; pathLenConstraint counts non-self-issued intermediates; an anchor's own constraint applies | §6.1.4 (k)–(m) |
| KeyUsage | keyCertSign on CAs, if keyUsage is present | §6.1.4 (n) |
| ExtendedKeyUsage | the required purpose is allowed by every extKeyUsage in the chain, and by the target's own when the target is itself a trust anchor | §4.2.1.12 |
| CriticalExtension | every critical extension is one the validator processes | §6.1.4 (o), §6.1.5 (f) |
| Structure | see below | §4 |
| TrustAnchor | the anchor certificate is valid at the reference time; with `StrictStructure` its form is checked too | RFC 5937 §3 |
| Revocation | see below | §6.3, RFC 6960 |
| HostName, WebPkiProfile | profile only | RFC 9525, Baseline Requirements |

### Structure rules

Always: a malformed extension value, a repeated extension, `notAfter` before `notBefore`.
With `StrictStructure` (default): a non-empty issuer; a positive serial number of at most 20 octets (not checked on an anchor, which is trusted for its name and key); a critical subjectAltName or an empty subject without one; extensions only in version 3; subjectKeyIdentifier, authorityKeyIdentifier and authorityInfoAccess not critical, policyConstraints critical; a CA certificate with subjectKeyIdentifier and a critical basicConstraints; an authorityKeyIdentifier with a keyIdentifier on every certificate that is not self-issued (not on an anchor); keyCertSign only with cA; nameConstraints only in CAs, critical (unless the web profile is on, where browsers accept it non-critical), with at least one subtree, no minimum or maximum and no leading period in a dNSName constraint; dNSName and rfc822Name in preferred syntax; signature-only keys (ML-DSA, SLH-DSA, Ed25519, Ed448) without key-agreement or encipherment usage; an anchor certificate that is version 3 with basicConstraints and no unrecognised critical extension.

## Revocation

Data is supplied (`RevocationData`: CRLs and basic OCSP responses); nothing is fetched. `RevocationRequired` chooses which certificates need it (`None`, `EndEntity`, `AllCertificates`); data that is supplied is used for every certificate regardless. Each certificate gets a `RevocationReport`: `Good`, `Revoked` (with time and reason) or `Unknown` with the reason (no data, stale, not yet valid, out of scope, unauthorised signer, an unusable CRL). Offline, with no data, a certificate is `Unknown`, never `Good`. `Unknown` for a certificate that `RevocationRequired` covers makes the verdict `Indeterminate` by default (`UnknownRevocationIsFatal` is true: a path nothing has shown to be unrevoked is not reported valid). A caller who sets it false gets `Valid` with `ValidationReport.RevocationSummary` = `Unknown` and reads the status itself. With `RevocationRequired` at `None` nothing is required and the verdict is the path's.

CRLs (§6.3.3): applicable by issuer, issuingDistributionPoint against the certificate's distribution points (full and relative names, `cRLIssuer`, indirect CRLs with `certificateIssuer`), `onlyContainsUserCerts`, `onlyContainsCACerts`, `onlyContainsAttributeCerts`, and reason scope; good only when the usable CRLs together cover all reasons. A CRL is usable when it has no unrecognised critical extension, thisUpdate is not after the data time, its signer's keyUsage has cRLSign, the signature verifies and the algorithm policy accepts it. A CRL whose nextUpdate (mandatory, §5.1.2.5) is before the data time is stale: once its signature is authenticated it still counts for one thing, a revocation that is final. RFC 5280 §5.3.1 makes every reason except certificateHold permanent, so a stale CRL listing the certificate for another reason gives `Revoked` (the reason says the CRL is stale). A stale CRL that lists a hold, or does not list the certificate, gives `Unknown` and the report's `Notes` say that stale data named or did not name the certificate; an unauthenticated stale CRL is never read. A signer other than the issuing certificate (a separate CRL-signing certificate of the same name, or an indirect CRL's issuer) is validated as a path of its own with the caller's revocation settings, a few levels deep, and only to the trust anchor of the certificate's own path (§6.3.3 (f)): another trusted root cannot vouch for a CA it does not certify. A CRL with a critical entry extension other than reasonCode, invalidityDate and certificateIssuer is unusable for every certificate (§5.3). A certificate found on a CRL is revoked whatever the entry's reason; the CRL's reason scope only decides what it can show good (§6.3.3 (i)-(j)). With `StrictStructure`, a CRL without cRLNumber, with it critical, or listing a serial twice is unusable. Delta CRLs apply to the complete CRL with the same issuer and issuingDistributionPoint whose `BaseCRLNumber` does not exceed its number (§5.2.4); `removeFromCRL` lifts a base entry only when that entry is a `certificateHold` (§5.3.1), so a delta cannot undo any other revocation. Serial numbers compare as integers.

OCSP (RFC 6960): the response must name the certificate by `CertID` (own hash algorithm), be signed by the issuing CA, by a responder the caller trusts, or by a delegated responder with a certificate issued by the CA that carries `id-kp-OCSPSigning` and is valid; the signature verifies; `thisUpdate` is not in the future and the response is current until `nextUpdate` (or `OcspMaxAge`, default seven days, when there is none). The signature must also pass the algorithm policy. A delegated responder certificate with `id-pkix-ocsp-nocheck` is trusted for its lifetime without a revocation check (§4.2.2.2.1). Without it, the supplied CRLs are asked about the responder certificate: a CRL that lists it makes the response unusable; when no supplied CRL speaks to it, RFC 6960 leaves trust to the client, the response is used and the report's `Notes` say the responder was not checked. OCSP is not used to check the responder's own certificate (the question would be circular). Nonce checking belongs to the caller who made the request.

## Time models

`ReferenceTime` is any instant. `RevocationModel.Current` is RFC 5280: a certificate on a CRL is revoked whatever the date. `RevocationModel.PastTime` validates as of an earlier instant with revocation data collected later (`RevocationDataTime`): a certificate revoked after the reference time for a reason other than keyCompromise, cACompromise, aACompromise or unspecified is good at the reference time; a "good" answer needs data issued at or after the reference time. This is the intent of ETSI EN 319 102-1 §5.6.2.1 [agent reading]. What it does not do, and the AdES validation does: the long-term-validation algorithm (choosing the best signature time from timestamps and archive timestamps, the grace period for revocation publication, `invalidityDate`, validating the revocation data's own past-time chain). Those inputs reach the validator as the reference time and the data time.

## Server-authentication profile

`WebPkiProfile` is a layer of extra rules, not a second validator. It does not add an algorithm policy of its own: the caller's `Policy` decides (under `Standard`, SHA-1 certificate signatures are refused from 2017-01-01). With `EnforceBaselineRequirements` it requires, on top of the RFC 5280 rules: serverAuth in every extKeyUsage of the chain (and, with `EnforceBaselineRequirements`, a target with a non-critical extKeyUsage that names serverAuth and not anyExtendedKeyUsage); a dNSName or iPAddress subjectAltName; a target that is not a CA and whose keyUsage lacks keyCertSign and cRLSign; RSA keys of at least 2048 bits that are a multiple of 8, ECDSA keys on a named P-256, P-384 or P-521; no extKeyUsage on a root and a root authorityKeyIdentifier that only repeats its subjectKeyIdentifier; a non-critical subjectAltName when the subject is not empty. Host matching (RFC 9525 §6.3): subjectAltName only, never the common name; IP addresses exactly; a wildcard is only a whole left-most label standing for exactly one label, and at least two labels follow it; that label may be an A-label host (`*.example.test` matches `xn--bcher-kva.example.test`), because RFC 9525 §6.3 forbids only a wildcard inside an IDN label, which is never a pattern here. `RequireCommonNameInSan` (off by default) adds the Baseline Requirements' rule that a commonName repeats a subjectAltName entry.

## Limits

All on by default and reported (`LimitReached`), never thrown.

| Limit | Default |
|---|---|
| `MaxPathLength` | 16 certificates |
| `MaxCandidatesPerCertificate` | 64 |
| `MaxSearchSteps` | 20,000 |
| `MaxSignatureChecks` | 1,024 over the whole validation (cached per certificate and key; nested CRL-signer validations draw on the same budget) |
| `MaxSignerValidations` | 256 CRL-signer validations over the whole validation (one per signer, anchor and nesting depth) |
| `MaxPathsValidated` | 32 |
| `MaxReportedPaths` | 16 |
| `MaxPolicyNodes` | 4,000 |
| `MaxNameConstraintComparisons` | 2,000,000 per path |
| `MaxRevocationObjectsPerCertificate` | 64 |
| `MaxSourceRounds` | 8 |

The step, signature, path and signer limits are shared by a validation and every nested CRL-signer validation it starts, and the certificate pool is indexed once (by subject name and, for OCSP responders, key hash) and shared too. Before this, each nested validation had its own budgets and rebuilt the pool: a pool of 1,000 certificates holding ten reissued certificates for a CRL signer's key took 244 s and 16,105 nested validations (24 s and 1,555 with five), and now takes milliseconds (`PoolScaleTests`). A signer is also skipped, without a nested search, when its validity period does not contain the reference time. A limit reached inside a nested validation marks the whole validation `LimitReached`.

Parsing limits are `X509Limits` (`docs/x509.md`). The two published denial-of-service shapes are tested (`ValidatorTests`): a policy-tree explosion (twelve CAs each asserting ten policies and mapping every policy to the others, 10^12 nodes without the bound) ends at the node limit with a `Policy` failure; a lattice of cross-certificates (eight levels of six keys, every key certified by every key above, 6^8 paths) ends at the step limit with `LimitReached`. Both finish in a fraction of a second.

## Test results

Pins: x509-limbo `1080e565`, NIST PKITS v1.0.1 (April 14, 2011; `PKITS_data.zip` sha256 `592f6603…665665`, `PKITS.pdf` sha256 `506913f4…a74d9ea`), BetterTLS `bc5adea1` (tests exported by the generator built from that commit; root CA fixed per cache), OpenSSL 3.5.9, Go 1.26.8. The harnesses are `tests/OneCrypto.Tests/Validation/{LimboTests,PkitsTests,BetterTlsTests,DifferentialCases}.cs`; `tools/fetch-pkits.sh`, `tools/fetch-bettertls.sh`, `tools/run-validation-vectors.sh` and `tools/diff/` fetch and run them.

### x509-limbo

9,802 testcases, each run with the web profile for `webpki::` and `bettertls::` and with plain RFC 5280 rules (plus host matching) for the others; CRLs supplied with a testcase are required for every certificate and unknown status is fatal.

| Category | Testcases | Agree | Documented deviations |
|---|---|---|---|
| bettertls | 9,572 | 9,572 | 0 |
| rfc5280 | 109 | 108 | 1 |
| webpki | 56 | 54 | 2 |
| crl | 17 | 17 | 0 |
| online | 14 | 14 | 0 |
| pathlen | 13 | 13 | 0 |
| pathological | 11 | 11 | 0 |
| rfc9881 | 6 | 6 (3 only on a platform with ML-DSA) | 0 |
| cve | 3 | 3 | 0 |
| invalid | 1 | 1 | 0 |

Deviations (asserted by the test, which fails on any other difference):

* `rfc5280::aki::cross-signed-root-missing-aki` (expected failure, `pedantic-rfc5280`): a trust anchor is trusted for its name and key (RFC 5937 §2); its authorityKeyIdentifier is not demanded. Demanding it would reject `cve::cve-2024-0567`, where the trusted root is a cross-signed certificate without one and the expectation is success.
* `webpki::san::public-suffix-multi-label-wildcard-san` and `…-private-namespace-wildcard-san` (`pedantic-public-suffix-wildcard`): deciding that `*.s3.amazonaws.com` covers a registry-controlled suffix needs the Public Suffix List, which the library does not carry. Wildcards directly under a single label (`*.com`) are refused.
* `rfc9881::ml-dsa-*`: need a platform with ML-DSA (OpenSSL 3.5 or newer); on one without it the signature check reports `AlgorithmNotSupported` naming the platform and the testcase is skipped in the assertion.

### NIST PKITS

247 runs of 224 tests in sections 4.1 to 4.16 (the manifest `Data/pkits-tests.json` is generated from the PKITS document by `tools/extract-pkits.py`; where the document states a result as conditions on the inputs, the run uses the default settings or the numbered settings the document lists). Reference time 2020-06-01; revocation required for every certificate with unknown status fatal; `StrictStructure` off, because PKITS predates the profile rules about key identifiers and criticality.

| Section | Runs | Agree |
|---|---|---|
| 4.1 Signature verification | 6 | 4 |
| 4.2 Validity periods | 8 | 8 |
| 4.3 Name chaining | 11 | 11 |
| 4.4 Basic revocation | 21 | 21 |
| 4.5 Self-issued certificates | 8 | 8 |
| 4.6 Basic constraints | 17 | 17 |
| 4.7 Key usage | 5 | 5 |
| 4.8 to 4.12 Policies, mappings, inhibit | all | all |
| 4.13 Name constraints | 38 | 38 |
| 4.14 Distribution points | 35 | 35 |
| 4.15 Delta CRLs | 10 | 10 |
| 4.16 Private extensions | 2 | 2 |

Totals: 245 of 247 agree. The two deviations are 4.1.4 and 4.1.5 (valid DSA signatures, including parameter inheritance): the library has no DSA verification, so the paths are refused (a certificate with a DSA key reports `AlgorithmNotSupported`); 4.1.6 (invalid DSA signature) is refused for the same reason.

### BetterTLS

Exported with the generator at `bc5adea1` and run with the web profile and the test's host name: nameconstraints 9,491 of 9,491 agree (590 accept, 7,759 reject, 230 accepts and 912 rejects marked warnings by the suite); pathbuilding 81 of 81 agree (45 accept, 36 reject).

## Differential against OpenSSL and Go

`tools/diff/export-cases.py` writes the chains of limbo (the 9,785 testcases without CRLs) and the two BetterTLS suites (9,572; 81 + 9,491) as 19,357 cases; `openssl_driver.py` runs `openssl verify` 3.5.9 (`-attime`, `-purpose sslserver` for the web profile, `-verify_hostname` / `-verify_ip`, `-verify_depth`), `tools/diff/main.go` runs Go's `crypto/x509` (`Verify` with `CurrentTime`, key usages, then `VerifyHostname`), and the library's `DifferentialCases` test runs ours. `compare.py` prints the matrix.

All three agree on 18,916 of 19,357 cases. The other 441 are differences between one or both oracles and us. In 437 of them ours equals the published expected result of the corpus; the other 4 are the deviations above (the cross-signed root, and three ML-DSA cases that the platform of this run cannot verify; they pass on OpenSSL 3.5). The 441 split by the oracle's own message:

* **OpenSSL accepts, ours rejects (193 cases: 122 limbo, 71 BetterTLS).** The oracle accepts a rule violation that RFC 5280 or the Baseline Requirements forbid and the corpus expects rejected: key identifiers and criticality, zero, negative or over-long serial numbers, subjectAltName syntax, nameConstraints in a non-CA, root extKeyUsage and authorityKeyIdentifier fields, key types and sizes (DSA, P-192, RSA bit lengths that are not a multiple of 8, 1024-bit RSA), a CA used as a server certificate, anyExtendedKeyUsage and critical extKeyUsage on a server certificate, SHA-1 signatures at a reference time after 2017, and host names matched against the commonName when the certificate has no dNSName entry (OpenSSL falls back to the subject; RFC 9525 §2 forbids it).
* **OpenSSL rejects, ours accepts (229 cases).** 148 are "permitted subtree violation" that come from the commonName: for a leaf whose only subjectAltName is an iPAddress and whose subject is `CN=test.localhost`, with a constraint permitting `DNS:example.com`, OpenSSL reports "permitted subtree violation" because it applies DNS constraints to a host-name-shaped commonName; the names RFC 5280 §4.2.1.10 constrains are the subject's distinguished name and the subjectAltName entries, and the corpus expects acceptance (checked by hand on bettertls cases 05245, 05247 and 05248). 33 more are "excluded subtree violation", checked case by case (see below): 32 are the same commonName effect as the 148, and one is an alternative-path case. The rest are OpenSSL's `unable to get local issuer certificate` (31), `unsuitable certificate purpose` (8), `unable to get issuer certificate` (3), `certificate has expired` (2) and `invalid CA certificate` (4) on chains the corpus expects accepted (alternative paths through the pool that OpenSSL did not try, and its purpose checks on CA certificates); these were not examined case by case beyond the corpus expectation.
* **Go accepts, ours rejects (44 cases):** the same pedantic rules as OpenSSL; `crypto/x509` does not enforce them.
* **Go rejects, ours accepts (5 cases):** Go's messages are "unhandled critical extension" (2), "too many intermediates for path length constraint" (1), "a root or intermediate certificate is not authorized to sign" (1) and "certificate has expired or is not yet valid" (1: the reference time is 5 ms past `notAfter`; certificate times have whole-second granularity, ours truncates the reference time to the second, and limbo marks the case ambiguous and expects acceptance). The first four match the corpus expectation and were not examined further.

### The 33 "excluded subtree violation" cases

Inspected with `tools/diff/explain.py` on the OpenSSL 3.5.9 run of 2026-10-31. Thirty-two are 16 BetterTLS name-constraints tests (5194, 5196, 5203, 5205, 5221, 5223, 5230, 5232, 5926, 5928, 5935, 5937, 5980, 5982, 5989, 5991), each present twice in the differential under its two corpus names. In every one the leaf's only subjectAltName is `IP Address:127.0.0.1` and its subject is `CN=test.localhost` or `CN=bad.example.com`; the intermediate carries a critical nameConstraints with an excluded `DNS:localhost` or `DNS:bad.example.com` (some also with permitted and excluded IP ranges that the address satisfies). OpenSSL applies the excluded DNS subtree to the host-name-shaped commonName and reports "excluded subtree violation"; the leaf has no dNSName, so RFC 5280 §4.2.1.10 has nothing to exclude, and Go agrees with us. The corpus expects acceptance. The thirty-third is limbo `nc-forbids-same-chain-ica`, the alternative-path class of the table below (the path through the constrained intermediate violates, the one through the other issuer does not). Two further lines contain the phrase only in our own message (OpenSSL accepts, ours rejects, corpus expects rejection): `cve-2025-61727` and `nc-forbids-dnsname-wildcard-san`, a wildcard dNSName inside an excluded subtree, which OpenSSL does not test.

### OpenSSL rejects, ours accepts, checked per class

Every class below was checked against the certificates (`tools/diff/explain.py` prints subject, issuer, validity, subjectAltName, basicConstraints, keyUsage, extKeyUsage and nameConstraints of a case; `tools/diff/classes.py` groups the disagreements by oracle message). The corpus expects acceptance in all of these cases except one (`cross-signed-root-missing-aki`, a documented deviation).

| Class (OpenSSL message) | Cases | What the certificates show | RFC reading |
|---|---|---|---|
| permitted / excluded subtree violation | 181 (148 + 33) | In 176 the leaf has no dNSName at all (an iPAddress-only subjectAltName, subject `CN=test.localhost`); OpenSSL applies the DNS constraint to the commonName. In the other 5 the leaf has a dNSName that the constraint permits, and a second candidate issuer sits in the pool: the path through the constrained intermediate violates, the path through the other issuer does not (`nc-forbids-same-chain-ica`, `nc-forbids-alternate-chain-ica`, pathbuilding tc50, tc56). | RFC 5280 §4.2.1.10 constrains the subject distinguished name and subjectAltName entries, and a commonName is not a dNSName; §6.1 is applied to a path, and a valid path exists. |
| unable to get (local) issuer certificate | 34 | Cross-sign pools (BetterTLS pathbuilding; limbo `cve-2024-0567`, `root-and-intermediate-swapped`): two intermediates with one subject, one issued by an untrusted root. OpenSSL follows the candidate whose issuer is absent and does not go back; a path to the trust anchor through the other candidate exists (read through on pathbuilding 00002). | RFC 5280 §6.1 validates a given path; any valid path suffices, and building is left to the implementation. |
| unsuitable certificate purpose | 8 | A candidate intermediate carries `extKeyUsage emailProtection` only; the alternative intermediate has no EKU (pathbuilding 00051). | §4.2.1.12: an absent EKU allows every purpose, so the path through the alternative is valid. |
| invalid CA certificate | 4 | A candidate issuer has keyCertSign but no basicConstraints (pathbuilding 00052); a candidate with basicConstraints exists. | §4.2.1.9, §6.1.4(k): the unsuitable candidate is skipped, the other path is valid. |
| certificate has expired | 4 | Two (pathbuilding 00049, 00055): an alternative intermediate expired an hour before the reference time, and a valid one exists. Two (`notafter-exact`, `notafter-fractional`): the reference time equals `notAfter` (fractional: 5 ms later, truncated to the second). | §4.1.2.5: the validity period runs from notBefore through notAfter, inclusive; certificate times have whole-second granularity. |

The OpenSSL-accepts classes (193) are each one named rule of our report with its section in the message, and all have the corpus expectation REJECT; the large ones belong to the web profile: a server certificate needs a dNSName or iPAddress (73), no dNSName entry matches the host (64, commonName fallback, RFC 9525 §2) and SHA-1 after the cutoff (6). Go-rejects (5): `nc-forbids-othername-noop` and `permitted-dn-match` carry a critical extension Go does not handle, and `self-issued-certs-pathlen` and `permitted-self-issued` need the self-issued exemptions (name constraints: §6.1.3 (b), (c) and §4.2.1.10; path length: §6.1.4 (l)), which Go does not apply. `python3 tools/diff/classes.py ours.tsv openssl.tsv go.tsv cases.jsonl` regenerates the full class list.

The per-case disagreement list is regenerated by `compare.py` and is not committed.

## Determinism and platforms

No dependence on the platform beyond signature verification, which is by the dispatch of `docs/fallbacks.md`: the same path gives the same verdict wherever the algorithm is available, and `AlgorithmNotSupported` names the platform where it is not. The validator uses no reflection, no clock, no `X509Chain`; `ChainDiagnostics.Compare` runs `X509Chain` offline beside it and reports where the two disagree, informationally.

## Left to later work

AIA, CRL and OCSP fetching (the `.Online` package behind `ICertificateSource` and `IRevocationSource`); the EN 319 102-1 validation process and TS 119 102-2 reports; certificate-transparency and trusted-list inputs; DSA and Brainpool-less platforms; the Public Suffix List for wildcards.
