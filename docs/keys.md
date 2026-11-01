# Keys, signature specs and two-phase signing

Behaviour of the key interfaces (`RecursiveAI.OneCrypto.Keys`). A key is something that *does* an operation; the library never asks for key bytes.

## Interfaces

| Interface | Operations | Backends in the core package |
|---|---|---|
| `IKey` | `PublicKey` (`PublicKeyInfo`), `Algorithm`, `Capabilities`, `Dispose` | all |
| `ISigningKey` | `Sign(data, spec)`, `SignDigest(digest, spec)`, `Supports(spec)`, `DefaultSpec`, async twins | RSA, ECDSA, ML-DSA (platform), Ed25519, Ed448 (library) |
| `IDecryptionKey` | `Decrypt(ciphertext, spec)` (RSA PKCS #1 v1.5, RSA-OAEP, ML-KEM decapsulation), `Supports(spec)`, async twin | RSA, ML-KEM (platform) |
| `IAgreementKey` | `Agree(peerPublicKey)`, async twin | ECDH (platform), X25519, X448 (library) |
| `IRsaKey` | `ISigningKey` and `IDecryptionKey` | RSA |

- The async methods are default interface members that call the sync ones; token, agent and remote backends override both.
- Each async method takes a `CancellationToken`, checked before work starts. A backend that talks to a device or service passes it on.
- `PrivateKey.From…(key, ownsKey: false)` wraps a BCL key (`RSA`, `ECDsa`, `ECDiffieHellman`, `MLDsa`, `MLKem`) or one of the library's `Ed25519PrivateKey`, `Ed448PrivateKey`, `X25519PrivateKey`, `X448PrivateKey`. With `ownsKey: true` disposing the wrapper disposes the wrapped key; otherwise the caller keeps ownership and must keep the key alive while the wrapper is used. BCL keys stay in their handles: nothing exports key bytes. The library's own keys live in pinned buffers that are zeroed on dispose. A garbage-collected runtime cannot promise that no other copy of a secret was ever made.
- **Operating-system keys.** `PrivateKey.FromCertificate(X509Certificate2)` takes the private key from a certificate the platform holds (a PFX loaded with its key, the user's certificate store or keychain, CNG on Windows) through `GetRSAPrivateKey()` and `GetECDsaPrivateKey()`. The returned key owns its handle. `PrivateKey.SigningKeyFromCertificate(x509)` is the same call typed as `ISigningKey` (an `IRsaKey` for RSA), so `new CmsSignerSpec { Certificate = cert, Key = PrivateKey.SigningKeyFromCertificate(x509) }` needs no cast; `TrySigningKeyFromStore` is the typed store lookup. The other factories already return the narrowest useful type (`FromRsa` an `IRsaKey`, `FromECDsa`, `FromMLDsa` and the Ed keys an `ISigningKey`, the DH and X keys an `IAgreementKey`, `FromMLKem` an `IDecryptionKey`). The platform's own PIN or consent prompts, if any, pass through to the user; the library adds none. `PrivateKey.TryFromStore(certificate, …)` looks the certificate up by comparing its encoding in a store (default `My`, `CurrentUser`), read-only. ML-DSA keys from the store are not offered: the platform accessor for them is still experimental.
- Disposed wrappers throw `ObjectDisposedException`. Wrappers are safe to use from several threads to the extent the wrapped BCL key is.

## Signature specs

`SignatureSpec` fixes everything about a signature except the key:

| Kind | Hash | Signs | Output |
|---|---|---|---|
| `RsaPkcs1` | SHA-1, 256, 384, 512 | digest | RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) |
| `RsaPss` | same | digest | RSASSA-PSS, MGF1 on the same hash, salt = digest length (RFC 8017 §8.1). The platform signs with no other salt; verification accepts any salt and MGF1 hash named in a certificate's parameters |
| `Ecdsa` | same | digest | DER `SEQUENCE { r, s }` (RFC 3279 §2.2.3) or fixed-width `r || s` (`Rfc4754`, IEEE P1363) |
| `Ed25519` | – | message | 64 octets, pure EdDSA (RFC 8032 §5.1.6) |
| `Ed448` | – | message + context (default empty) | 114 octets (RFC 8032 §5.2.6) |
| `MlDsa` | – | message + context (default empty) | FIPS 204 pure signing; the parameter set follows the key |

- `Context` is at most 255 octets. X.509 (RFC 8410 §3, RFC 9881) signs with an empty one; a spec with a context has no X.509 identifier (`ToAlgorithmIdentifier` throws `NotSupportedException`), as does a P1363 ECDSA spec.
- `SignatureSpec.DefaultFor(publicKey)`: RSA gets PKCS #1 v1.5 with SHA-256 (PSS for an RSA-PSS key), ECDSA the hash that matches the curve (≤256 bits SHA-256, ≤384 SHA-384, otherwise SHA-512), the others their only form.
- `spec.Verify(publicKey, data, signature)` checks a signature with the platform's public-key operations, the verify-only fallbacks and the library's curves, and returns a `SignatureVerification` (status, reason, RFC reference). It never throws for hostile input. A P1363 signature of the wrong length for the curve is `Invalid`. DER ECDSA signatures must be strict DER.
- SHA-224 and SHA-3 are not offered for signing: the platform's signing API does not take them everywhere. They still verify in certificates (see x509.md).

## Two-phase signing

`PreparedSignature` is the first half of a signature:

1. **Prepare** (`PreparedSignature.Prepare(publicKey, spec, data, policy, at, purpose)`, or `PrepareDigest` when the caller hashed a large input). The policy is asked first (`CheckSignature` for new data at `at`); a rejection throws `PolicyViolationException` with the decision report. The state records the spec, the public key, what must be signed (`ToSign`: the digest for RSA and ECDSA, the message otherwise), the data (when known) and a purpose label.
2. **Serialise** with `Encode()`; the bytes can travel, wait, and be read again by `Decode` / `TryDecode` in any process.
3. **Sign anywhere.** Whoever holds the key signs `ToSign` under `Spec` (`SignDigest` or `Sign` on an `ISigningKey`, an HSM, a remote service) and returns the raw signature.
4. **Complete** with `Complete(signature)`: the signature is verified against the recorded public key and data, and returned; a signature that does not verify (wrong key, other data, flipped bit, wrong encoding) throws `InvalidSignatureException` carrying the `SignatureVerification`. `TryComplete` returns the result instead. A digest-only state verifies the digest.

`SignWith(ISigningKey)` runs 3 and 4 in one process; it refuses a key whose public key is not the recorded one.

### Encoding (version 1)

DER, no reflection serialiser:

```
PreparedSignature ::= SEQUENCE {
    version   INTEGER,                    -- 1
    purpose   UTF8String,                 -- "raw", "x509.certificate", "x509.request", "x509.crl"
    spec      SEQUENCE { kind INTEGER, hash UTF8String, format INTEGER, context OCTET STRING },
    publicKey SubjectPublicKeyInfo,
    input     ENUMERATED { digest(1), message(2) },
    toSign    OCTET STRING,
    data      OCTET STRING                -- empty after PrepareDigest
}
```

`kind`: 1 RSA PKCS #1, 2 RSA-PSS, 3 ECDSA, 4 Ed25519, 5 Ed448, 6 ML-DSA. `format`: 0 DER, 1 P1363. `hash` is the .NET hash name (`SHA256`) or empty. A reader refuses an unknown version (the message names it), an input kind that does not fit the scheme, a digest of the wrong length, a `data` whose hash is not `toSign`, and any damage, without throwing from `TryDecode`. A later version changes the version number; older readers refuse it rather than guess. The state holds the data for message schemes and for `Prepare`: treat it like the document. It never contains private key material.

### X.509

`CertificateBuilder.PrepareSelfSigned / Prepare`, `CertificateSigningRequestBuilder.Prepare` and `RevocationListBuilder.Prepare` build the to-be-signed structure and return a state whose `Data` is that DER; `Complete(state, signature)` on the same builder checks the signature against the signer's key and returns the parsed object. The purpose label stops a certificate state completing a CRL. The structures have the signer's `signatureAlgorithm` (`spec.ToAlgorithmIdentifier(key)`) in both places (RFC 5280 §4.1.1.2).

The one-shot builders still take an `X509Signer`: `X509Signer.FromKey(ISigningKey, SignatureSpec?)` makes one from any key interface, and `FromRsa`, `FromECDsa`, `FromMLDsa` and `FromDelegate` remain as conveniences. `Key` and `Spec` expose what it was made from. Code that signs other structures (CMS) should take an `ISigningKey` and a `SignatureSpec` and call `spec.ToAlgorithmIdentifier(key.PublicKey)` for the identifier it writes.

## Not here

PKCS #11, gpg-agent, ssh-agent, CSC and the KMS adapters implement these same interfaces in their own packages. The library has no key store and no agent of its own.

## Use in CMS and X.509

CMS signers (`CmsSignerSpec.Key`), CMS recipients (`CmsDecryptionKey.FromKey`) and `X509Signer.FromKey` all sit on these interfaces. Two-phase CMS signing uses `PreparedSignature` with purpose `cms.signerinfo` (one per signer, inside `PreparedSignedData`, see `cms.md`); the OCSP request and response builders have the same `Prepare` / `Complete` pair as the certificate, request and list builders (purposes `ocsp.request`, `ocsp.response`; the certificates sent along are given again at completion).
