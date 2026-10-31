# Issuing certificates and CRLs

`RecursiveAI.OneCrypto.Issuance`: a certificate authority as a library object. It is I/O-free and reads no clock. Every time (notBefore,
thisUpdate) is an argument, every key is an `X509Signer` (so in memory, in the operating system, on a token or remote), and every
signing step has a two-phase form.

## The CA

`CertificateAuthority(Certificate, X509Signer, CertificateAuthorityOptions?)` refuses a certificate that is not a CA certificate
(basicConstraints cA, RFC 5280 §4.2.1.9) or whose key usage lacks keyCertSign (§4.2.1.3), and a signer whose key is not the certificate's.
`CertificateAuthority.CreateRoot` makes a self-signed root under the root profile.

Issuing is `Issue(CertificateSigningRequest, CertificateIssueOptions)` or `Issue(PublicKeyInfo, DistinguishedName, CertificateIssueOptions)`.

- **From a request**: the request's signature is checked first (proof of possession, RFC 2986 §3); a bad one raises `IssuanceException`
  with rule `csr-signature`. Only the subject, the key and a subject-alternative-name request are taken from the request. Every
  other requested extension (a `CA:TRUE`, an extended key usage) is ignored: the profile decides what the certificate says.
- **Serial numbers** are random: 16 octets from the system generator by default (at least 9 are required), with the top bit
  cleared and one bit fixed, leaving at least 70 random bits and a positive INTEGER of constant length (RFC 5280 §4.1.2.2;
  CA/Browser Forum TLS Baseline Requirements §7.1 asks for 64 bits).
- **Validity**: `NotBefore` is the caller's; the length is `Validity`, or the profile's longest cut back to the end of the issuing
  certificate. A requested validity beyond either limit is refused (`validity`, `issuer-validity`). The issuing certificate must itself be
  valid at notBefore (RFC 5280 §6.1.3).
- **Path length**: a CA certificate can only be issued under the issuer's constraint (`path-length`); the written value is the stricter of the
  requested one and the issuer's minus one.
- **Policy**: the subject key (`CryptoPolicy.CheckKey`, new data) and the CA's signature algorithm are checked at notBefore; a
  rejection raises `PolicyViolationException`. `Standard` refuses RSA under 2048 bits and SHA-1.
- **Extensions written**: basicConstraints (critical), keyUsage (critical), extendedKeyUsage, subjectAlternativeName (critical when the
  subject is empty, RFC 5280 §4.2.1.6), id-pkix-ocsp-nocheck for responder profiles, subjectKeyIdentifier and authorityKeyIdentifier
  (RFC 7093 method 1 / the issuer's), authorityInfoAccess (OCSP and caIssuers URLs) and cRLDistributionPoints from the CA options.
  `AdditionalExtensions` adds more (name constraints, policies); repeating one the CA writes is refused (`extensions`).
- **Two phases**: `PrepareIssue(…, SignatureSpec)` returns a `PreparedSignature` whose `ToSign` any key holder can sign;
  `CompleteIssue` checks the signature against the CA key and returns the certificate. The state serialises (docs/keys.md).

## Profiles

A `CertificateProfile` is data: key usage, extended key usages (and whether critical), basic constraints, subject alternative name rules
and the longest validity, with an optional `ValiditySchedule` of dated limits. Presets:

| Profile | Key usage | EKU | SAN | Longest validity |
|---|---|---|---|---|
| `Root` | keyCertSign, cRLSign; CA | none | none | 25 years |
| `Intermediate` | keyCertSign, cRLSign; CA | none | none | 10 years |
| `TlsServer` | digitalSignature | serverAuth | required: DNS or IP | schedule of TLS BR §6.3.2 (v2.3.1): 398 days before 2026-03-15, 200 days, 100 days from 2027-03-15, 47 days from 2029-03-15 |
| `TlsClient` | digitalSignature | clientAuth | optional: DNS, e-mail, URI, IP | 398 days |
| `SMime` | digitalSignature, nonRepudiation (+ keyEncipherment for RSA) | emailProtection | required: e-mail | 825 days |
| `CodeSigning` | digitalSignature | codeSigning | none | 1185 days |
| `OcspSigning` | digitalSignature | id-kp-OCSPSigning, ocsp-nocheck | none | 90 days |
| `TimeStamping` | digitalSignature | id-kp-timeStamping, critical (RFC 3161 §2.3) | none | 15 years |

Only the TLS server schedule comes from a requirements document; the other limits are our defaults for a development or private CA, meant
to be overridden by building your own profile.

## CRLs and delta CRLs (RFC 5280 §5)

`IssueCrl(CrlIssueOptions)`: `ThisUpdate`, `NextUpdate` (required: a list without one can never be known to be current), the
`Number` (cRLNumber, at most 20 octets), the entries (`RevokedCertificateInfo`: serial, revocation date, reason code, invalidity date) and optionally
the issuingDistributionPoint (URL, only-user / only-CA certificates) and the freshestCRL URL of the delta. With `DeltaBaseNumber`
set it is a delta CRL: a critical deltaCRLIndicator, a number greater than the base, no freshestCRL on the delta (§5.2.4, §5.2.6).
`removeFromCRL` is refused outside a delta (§5.3.1). The CA certificate must permit cRLSign and be valid at thisUpdate. `PrepareCrl` /
`CompleteCrl` are the two-phase form.

## Checked against

OpenSSL 3.5.9 `verify -x509_strict` (with `-purpose` where openssl has one) accepts a root → intermediate → leaf chain for each profile and
key type; `crl -verify` accepts our CRL and delta CRL; `verify -crl_check -extended_crl -use_deltas` revokes through the base and delta lists as it
should (openssl only reads a delta CRL, whose indicator is critical, with `-extended_crl`). The tests are in
`tests/OneCrypto.Tests/Issuance/CertificateAuthorityTests.cs`.
