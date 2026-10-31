# OCSP responder (RFC 6960)

`RecursiveAI.OneCrypto.Issuance.OcspResponder`: a message handler. Request octets in, a signed `OcspResponse` out; no network, no clock, no
database. The host owns the transport (HTTP POST, or GET with the base64 path of RFC 6960 Appendix A, and the caching headers) and the
revocation facts.

## Configuration (`OcspResponderOptions`)

- `Issuer`: the CA the responder answers for. A CertID names a certificate by the hash of the issuer's name and key (§4.1.1); the responder
  recomputes both with the CertID's hash (SHA-1, SHA-256, SHA-384, SHA-512) and answers only for its own CA.
- `ResponderCertificate` and `Signer`: either the `Issuer` itself (the CA answers directly), or a **delegated responder** certificate the CA issued
  with id-kp-OCSPSigning (§4.2.2.2); the handler checks that at construction (issued by the CA, signature valid, EKU present, key matches the signer) and
  includes the certificate in every response. The `OcspSigning` profile adds id-pkix-ocsp-nocheck (§4.2.2.2.1).
- `ResponderId`: `ByKey` (SHA-1 of the key bits, the default) or `ByName` (§4.2.2.3).
- `Source` (`IRevocationStatusSource`): certificate id and request time in, `RevocationStatus` out (good, revoked with time and reason, unknown;
  `ThisUpdate`, `NextUpdate`), or null for unknown. `InMemoryRevocationSource` is a small implementation for development CAs and tests.
- `Preproduced` (`IPreproducedOcspResponses`), `MaxRequests` (16), `RequireSignedRequests`, `AuthorizeRequest`, `Policy` and `Limits` (64 KiB).

## Behaviour

`Handle(requestBytes, now)` never throws for bad input; errors the client can cause are statuses (§2.3):

| Situation | Response |
|---|---|
| unparsable or oversized request, no certificate ids, more than `MaxRequests`, nonce shorter than 1 or longer than 32 octets (RFC 8954 §2.1) | `malformedRequest` |
| `RequireSignedRequests` and the request is unsigned | `sigRequired` |
| `AuthorizeRequest` returns false | `unauthorized` (a host callback that throws: `internalError`). The callback is where a signed request's signature is checked and the requestor is matched to an allow-list |
| every certificate asked about belongs to another CA | `unauthorized` (§2.3, RFC 5019 §2.2.3); in a mixed request the foreign ones are answered `unknown` |
| the source says the answer is already stale (nextUpdate not after now) | `tryLater` |
| the source throws, answers a future thisUpdate, revoked without a time, the responder certificate is not valid at `now`, or the policy rejects the signature | `internalError` |
| otherwise | `successful`: one SingleResponse per request, in order, `producedAt = now`, the nonce echoed byte for byte |

**Preproduced responses** (RFC 5019 §2.2.2): `Preproduce(ids, now)` signs a response without a nonce; store it with an `IPreproducedOcspResponses`.
A request for one certificate without a nonce is answered with the stored response while it is current (thisUpdate ≤ now < nextUpdate, signature valid under
the responder key); a request with a nonce is always signed fresh, since a stored response cannot echo it.

**Two-phase**: `Prepare(request, now)` returns a `PreparedOcspResponse`: `Immediate` (an error or a preproduced response) or a `PreparedSignature` of the
ResponseData. `Encode()`/`Decode` serialise it (`SEQUENCE { version, preparedSignature, certificates }`); `Complete(signature)` checks the signature and assembles the
BasicOCSPResponse around the signed bytes.

## Checked against

OpenSSL `ocsp` (3.5.9 pinned; 3.6.2 locally), CA-signed and delegated (RSA, P-256, Ed25519), good / revoked / unknown, with and without a nonce:
requests we build answered by `ocsp -index … -rsigner` and verified by us (signature under the responder key, responder id, nonce echo, certificate id); requests from
`ocsp -reqout` answered by our handler and accepted by `ocsp -respin … -reqin … -verify_other` (with `-reqin` alone, which checks the nonce echo, and with
`-issuer -cert -no_nonce`, which prints the status; naming `-cert` together with `-reqin` makes openssl build a new request with a new nonce). Tests:
`tests/OneCrypto.Tests/Issuance/OcspResponderTests.cs`; fuzz target `ocspresp`.

## Checking a response on the client side

There is no separate OCSP verifier: `PathValidator` takes our `OcspBasicResponse` in `RevocationData.OcspResponses` and checks the responder (the issuing CA, or a delegate with id-kp-OCSPSigning issued by it) and the status of the certificate, reporting it per certificate (`docs/validation.md`). Tests run responses of CA-signed and delegated responders (P-256, Ed25519) through it, expecting good and revoked.
