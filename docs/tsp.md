# RFC 3161 time-stamping

`RecursiveAI.OneCrypto.Tsp`: the client messages, a verifier, and an authority handler. No network and no clock: bytes in, bytes out.
Fetching a token over HTTP is the online package's job.

## Messages

- `TimeStampRequest` (`TimeStampReq`, RFC 3161 §2.4.1): version 1, message imprint, policy, nonce, certReq, extensions. `Create` takes a
  `HashAlgorithmName` (SHA-256/384/512 or SHA-3), the digest (its length must fit the hash) and options; `NewNonce()` gives 8 random octets.
  `Parse` is BER-lenient and limit-checked; `TryParse` is the non-throwing twin; the error is `TimeStampParseException`.
- `TimeStampResponse` (`TimeStampResp`, §2.4.2): status (`TimeStampStatus`), status strings, failure bits (`TimeStampFailure`, named after
  PKIFailureInfo with the value `1 << bit`) and the token's bytes as received.
- `TstInfo` (§2.4.2): policy, imprint, serial number (positive), genTime (fractions kept), accuracy, ordering, nonce, tsa, extensions.
  `Encoded` is the structure as received, which is what the token's signature covers.
- Limits (`TimeStampLimits`): request 64 KiB, response 1 MiB, nonce 64 octets, imprint 128 octets, nesting depth 16.
  The seed's `Rfc3161.BuildRequest` and `TryExtractToken` stay (they serve the PDF bridge) and write and read the same messages.

## Verifying a response (`TimeStampVerifier.Verify`)

Reports one `CmsCheck` per rule (rule name, status, reason, RFC section), and never throws for bad input. The rules:

| Rule | What it checks |
|---|---|
| `status` | granted or grantedWithMods (the latter is a warning); otherwise the refusal and its failure bits are the reason (§2.4.2) |
| `token` | a CMS SignedData holding a TSTInfo that parses |
| `message-imprint` | same hash algorithm and digest as the request (§2.4.2) |
| `nonce` | the request's nonce is echoed; a request without a nonce is `NotApplicable` (a replayed token cannot be told from a fresh one); an unrequested nonce warns |
| `policy-id` | when the request asked for a policy, the token is under it |
| `single-signer` | exactly one SignerInfo (§2.4.2) |
| `signature` | the CMS layer's verification: message digest, signature, key usage, and extended key usage allowing id-kp-timeStamping |
| `tsa-eku` | the certificate has one extended key usage extension, critical, naming only id-kp-timeStamping (§2.3) |
| `ess-cert-id` | a signing-certificate or signing-certificate-v2 attribute names the signer's certificate by hash (RFC 5035 §5.4; RFC 5816) |
| `tsa-name` | when the token has a `tsa` name it identifies the signer's certificate (§2.4.2) |
| `tsa-validity` | genTime lies within the certificate's validity |
| `policy` | `CryptoPolicy` (default `Standard`) on the imprint hash and the token signature at genTime, or at `ReferenceTime` when the caller passes one |
| `trust` | `NotApplicable` without `TrustAnchors`. With anchors, the authority's certificate goes through `PathValidator` as of the token's genTime (time-stamping EKU required, the token's and `ExtraCertificates` as the pool, `Revocation` data if supplied): `Failed` when no path validates, `Warning` when it does but revocation of the certificate is not known good (offline is never reported as plain `Passed`), `Passed` when the revocation data says good |

`IsValid` means no rule failed or went undecided; it means the authority is trusted only when anchors were supplied and `trust` passed or warned. A token made without certReq has no
certificate in it, and the report says `tsa-certificate` is undecided until the caller passes it in `ExtraCertificates`. A bare token
(a ContentInfo) is accepted as an answer, with a warning.

## The authority handler (`TimeStampAuthority`)

`Handle(requestBytes, now)` returns a `TimeStampResponse`, never throws for bad input. The certificate must carry a critical extended key usage
naming only id-kp-timeStamping (§2.3), checked when the handler is built.

- **Refusals** are status `rejection` with failure bits: unparsable request or an imprint of the wrong length → `badDataFormat`; a hash
  not in `AcceptedHashes` (SHA-256/384/512; SHA-1 is not) → `badAlg`; a policy that is neither the default nor in `AcceptedPolicies`
  → `unacceptedPolicy`; a critical request extension → `unacceptedExtension` (non-critical ones are ignored); the authority's certificate not valid at `now`
  → `timeNotAvailable`; a serial source that fails or returns zero or more than 20 octets, a signature algorithm the policy rejects, or a signing error →
  `systemFailure`.
- **Granted tokens**: SignedData with eContentType id-ct-TSTInfo, one signer, a signing-certificate-v2 attribute (ESSCertIDv2, RFC 5816), no
  signing time, the nonce echoed, the policy the client asked for (else the default), accuracy and ordering as configured, the `tsa` name
  from the certificate subject. On certReq the token carries the authority's certificate and `ChainCertificates`; otherwise no certificates.
- **Serial numbers** come only from the `ITimeStampSerialSource` the host passes. `CounterTimeStampSerialSource` (in memory) and
  `RandomTimeStampSerialSource` (128 random bits) are provided; uniqueness across processes is the host's.
- **Time** is `now`, written as genTime in whole seconds by default (`GenTimeFractionDigits` adds up to 6 digits, no trailing zeros, §2.4.2).
- **Two-phase**: `Prepare(request, now)` returns a `PreparedTimeStamp`: either `Rejection`, or a `PreparedSignature` for the signed
  attributes. `Encode()` / `PreparedTimeStamp.Decode` serialise it (`SEQUENCE { version, preparedSignature, tstInfo, certReq, certificates }`), and
  `Complete(signature)` checks the signature and returns the response. Signing attributes are deterministic, so completion replays the token build
  around the supplied signature.

## Checked against

OpenSSL `ts` (3.5.9 pinned; also 3.6.2 locally): `ts -query` requests answered by our handler and accepted by `ts -verify` (SHA-256/384/512 ×
RSA, ECDSA P-256 × nonce / no nonce × certReq / no certReq), and requests we build answered by `ts -reply` and accepted by our verifier (same matrix).
`openssl ts` has no EdDSA: it verifies through PKCS #7, and `ts -reply` answers a rejection for an Ed25519 key. Ed25519 tokens from our authority are
therefore checked by `openssl cms -verify` (signature and content), and the Ed25519 rows of the other direction are skipped. Tests:
`tests/OneCrypto.Tests/Issuance/TimeStampTests.cs`; fuzz target `tsa`.
