# Cryptographic Message Syntax

Normative behaviour of the CMS models in `RecursiveAI.OneCrypto` (`SignedData`, `EnvelopedData`, `AuthEnvelopedData`, `AuthenticatedData`, `EncryptedData`, `DigestedData`, `CompressedData`, `ContentInfo`) and the wire constants in `RecursiveAI.OneCrypto.Wire.Cms`. Clause numbers are RFC 5652 unless another document is named. RFC 3161 time-stamp tokens are SignedData and are read with the same code. Path building, revocation and trust decisions on the signer's certificate belong to the validator, not here.

## Shape of every message

* **Immutable and lossless.** An object keeps the octets it was read from (`Encoded`) and slices them; builders write DER and return the parse of what they wrote. BER with indefinite lengths and constructed strings is read. Digests and signatures are computed over the received bytes: the encapsulated content as the OCTET STRING holds it, and the signed attributes as the received `[0]` element with its tag changed to `SET OF` (§5.4), never a re-encoding.
* **Typed errors.** `CmsParseException` (derives from `FormatException`) carries the structure and a `CmsError`: `Asn1`, `UnexpectedStructure`, `UnexpectedContentType`, `Unsupported`, `InvalidValue`, `LimitExceeded`, `NoMatchingRecipient`, `DecryptionFailed`. Every `Parse` has a `TryParse`. No other exception type comes out of a reader or of the streaming calls (the fuzz targets enforce this).
* **Results, not booleans.** `SignedData.Verify` returns a report per signer with one `CmsCheck { Rule, Status, Reason, Reference }` per rule. `AuthenticatedData.Verify` and `DigestedData.Verify` return a `CmsIntegrityReport` of checks the same way.

## Limits (`CmsLimits`, on by default)

| Limit | Default | Applies to |
|---|---|---|
| `MaxSigners` | 64 | SignerInfos of a SignedData |
| `MaxCertificates` | 1024 | certificates, and revocation lists, each |
| `MaxAttributes` / `MaxAttributeValues` | 64 / 16 | one attribute set / one attribute |
| `MaxAttributeBytes` | 4 MiB | one attribute value (a time-stamp token, revocation data) |
| `MaxRecipients` | 1024 | RecipientInfos |
| `MaxCountersignatureDepth` | 4 | countersignature levels followed |
| `MaxContentBytes` | 1 GiB | content a one-shot call holds: encrypted content of `Decrypt`, and the whole message of `AuthEnvelopedData.DecryptStream` |
| `MaxDecompressionRatio` / `MaxDecompressedBytes` | 1000 / 1 GiB | `CompressedData.Decompress` (stops at whichever is smaller) |
| `MaxPbkdf2Iterations` | 10,000,000 | a PasswordRecipientInfo from a message (a cost bomb is refused before any work) |
| `Asn1` | depth 32 | the ASN.1 limits of `docs/asn1.md` |

The streaming readers also keep the small elements around streamed content (recipient infos, certificates, signer infos) within 64 MiB together.

## SignedData

Every signature kind the platform and our primitives have: RSA PKCS #1 v1.5, RSASSA-PSS (RFC 4056), ECDSA P-256/384/521, Ed25519 and Ed448 (RFC 8419, with SHA-512 and SHAKE256 as the digest), ML-DSA (RFC 9882) where the platform has it, SLH-DSA (RFC 9814) verification through the preview path of the X.509 models. Signers are written in the order given, so report index *i* is signer *i*.

Defaults of the builder: signed attributes on (content-type, message-digest, ESS signing-certificate-v2); signing time only when the spec gives one; the digest follows the signature algorithm; `rsaEncryption` is written as the signature algorithm for PKCS #1 v1.5.

### Verification rules

By default the verifier takes no clock and builds no chain: the report says the signature is sound for the certificate's key and exposes the certificates, and trust is the path validator's question. With `SignedDataVerifyOptions.Chain` set (see Signer chains below) each signer is also path-validated. It checks every signer.

| Rule | Passes when | Reference |
|---|---|---|
| `signer-certificate` | a certificate in the message or in `ExtraCertificates` matches the signer identifier (issuer and serial, or subject key identifier) | §5.3 |
| `digest-algorithm` | the algorithm is available; SHA-1 is a warning | §5.1 |
| `attributes` | signed attributes are well formed, no attribute is duplicated, content-type and message-digest each have one value | §5.3, §11 |
| `content-type` | the attribute equals the encapsulated content type | §11.1 |
| `message-digest` | the attribute equals the digest of the content, compared in constant time | §11.2 |
| `signing-time` | readable (a warning otherwise) | §11.3 |
| `signature` | the signature is valid over the signed attributes (or the content when there are none), and the digest and signature algorithms agree | §5.4 |
| `algorithm-protection` | when present, matches the digest and signature algorithms of the SignerInfo | RFC 6211 |
| `key-usage` | a signer certificate with a keyUsage extension has at least one of `AnyOfKeyUsages` (default digitalSignature or nonRepudiation; set to `None` to skip), and, when `RequiredExtendedKeyUsage` is given, that extended key usage; nothing else is assumed (for example PDF signing EKUs are the caller's to ask for) | RFC 5280 §4.2.1.3 |
| `key-strength` | RSA of 2048 bits or more (a warning below) | CryptoPolicy |
| `signing-certificate` | ESS signing-certificate or -v2 names the signer certificate by hash | RFC 2634 §5, RFC 5035 |
| `chain` | only with `Chain` options: the signer's certificate validates to a trust anchor at the options' reference time (`Passed`; `Warning` when valid but revocation stayed unknown; `Unsupported` when the validator could not decide, for example required revocation data is missing; `Failed` otherwise) | RFC 5280 §6 |
| `countersignatures` | each countersignature verifies over the signature value of its target, to `MaxCountersignatureDepth` | §11.4 |

`Verify(content)`, `Verify(Stream)` and `VerifyStream` hash with every digest algorithm the signers use in one pass. A detached message with no content supplied fails the `content` rule.

### Signer chains

`SignedDataVerifyOptions.Chain` takes a `ValidationOptions` (`docs/validation.md`): trust anchors, the reference time, the `CryptoPolicy`, revocation data and limits. Each signer and each countersigner whose certificate was found is validated with it, and the report gets a `chain` check and `SignerReport.Chain`, the validator's full `ValidationReport` (paths, per-rule results, revocation findings). The signer is valid only if the chain check passes or warns; the message is valid only if every signer is.

* The certificates in the message and in `ExtraCertificates` join the options' `Intermediates` as an untrusted pool. The CRLs in the message, and OCSP responses carried in its revocation set as `id-ri-ocsp-response`, join the options' revocation data. Being in the message confers no trust; only the anchors do.
* With no CRL or OCSP response anywhere, the validator is given no revocation data, so a chain with `RevocationRequired = None` reports nothing unknown. With `RevocationRequired` set and no usable data the chain is undecided (`Unsupported`) unless the options set `UnknownRevocationIsFatal = false`.
* **Time.** The reference time is the options'. The signing-time attribute is the signer's own claim and is never used as the reference time. A signer whose certificate has expired is `Failed` at "now" and valid at an instant inside its validity: to validate as of the signature, pass a time that is proven (a time-stamp token's `genTime`, from a verified token) and, for revocation, `RevocationModel.PastTime` with the data time. The long-term-validation choice of that instant is the AdES validator's.
* The signing-certificate (ESS) check is independent: a substituted certificate that chains correctly but is not the one the signer named still fails it.
* RFC 3161 tokens are CMS SignedData and use the same option; `TimeStampVerifyOptions` also takes anchors directly and reports the same validation as its `trust` check.

### Streaming

`SignedData.SignStream(content, output, signers, options)` writes indefinite-length BER: header, the encapsulated content as a constructed OCTET STRING of 64 KiB segments (hashed as it goes), then certificates and signer infos. Every signer must use signed attributes, because a signature over the bare content cannot be made in one pass (`NotSupportedException` otherwise). `SignedData.VerifyStream(message, contentOutput, options, limits)` reads an attached message forward in constant memory, hashing the content as it passes (primitive or segmented, definite or indefinite), then reads the certificates and signer infos that follow and verifies them. The small elements after the content are rebuilt with definite lengths to be parsed; their contents are untouched. If `contentOutput` is given the content is copied to it while being read and is **not verified until the call returns a valid report**.

## EnvelopedData and AuthEnvelopedData

Content encryption: AES-128/192/256-CBC (EnvelopedData, EncryptedData), AES-128/192/256-GCM and CCM (AuthEnvelopedData, RFC 5084), Triple DES CBC read only and only with `AllowLegacyCiphers`. Content is encrypted with a random key; the version follows §6.1 (3 with a password or other recipient, 2 with a key agreement, key encryption key or unprotected attributes, else 0).

| RecipientInfo | Written | Read |
|---|---|---|
| KeyTransRecipientInfo | RSA-OAEP with SHA-1/256/384/512 (default SHA-256, RFC 3560); PKCS #1 v1.5 only with `AllowLegacy` | both; v1.5 can be refused with `AllowPkcs1V15KeyTransport = false` |
| KeyAgreeRecipientInfo | ephemeral-static ECDH P-256/384/521 with the X9.63 KDF, its hash following the curve (SHA-256, SHA-384, SHA-512; RFC 5753 §7.1.1), X25519 with HKDF-SHA-256 and X448 with HKDF-SHA-512 (RFC 8418), AES key wrap | the same plus SHA-1/224/384/512 KDFs; an `originatorKey` without curve parameters (as openssl writes) is taken to be on the recipient's curve |
| KEKRecipientInfo | AES-KW (RFC 3394, our primitive) or AES-KWP (RFC 5649, the platform's) | both |
| PasswordRecipientInfo | PBKDF2-HMAC-SHA-256 (default 600,000 iterations) and RFC 3211 wrapping with AES-CBC | HMAC-SHA-1/256/384/512 PRFs |
| KEMRecipientInfo (RFC 9629) | ML-KEM with HKDF-SHA-256 and AES-256 key wrap (RFC 9936), preview, where the platform has ML-KEM | the same, with HKDF-SHA-256/384/512 |
| OtherRecipientInfo | preserved on read, not opened | |

### Failing closed

* **No plaintext before the check.** `Decrypt` returns bytes only after the whole message has been decrypted and, for AuthEnvelopedData, the tag has verified over the ciphertext and the DER of the authenticated attributes (RFC 5083 §2.2). On any failure the buffer is zeroed and nothing is returned.
* **One error.** After a recipient info matched, every failure (wrong key, damaged wrapped key, bad padding, bad tag, a missing content-type attribute) raises the same `CmsParseException` with `CmsError.DecryptionFailed` and the same message. Only "no recipient info is meant for this key" is told apart, because that is a property of the public message.
* **RSA PKCS #1 v1.5 (RFC 3218 §2.3).** When key transport fails, a random key of the right length stands in, decryption runs on, and the result is rejected at the end whatever its padding looks like. A wrong-length key counts as a failure.
* **CBC without authentication.** EnvelopedData cannot detect changes that leave the padding valid. Flipping a bit in a block changes the plaintext of the next block and garbles that one; only the last block's padding is checked. Prefer AuthEnvelopedData.
* **Cost bombs.** The PBKDF2 iteration count of a message is capped (`MaxPbkdf2Iterations`).

### Streaming and memory

* `EnvelopedData.EncryptStream` writes indefinite-length BER in constant memory (AES-CBC through the platform's transform, one OCTET STRING segment per write). `EnvelopedData.DecryptStream` reads forward in constant memory and writes plaintext as it is decrypted. CBC can only be checked at the last block, so the plaintext reaches the output **before** the padding is known to be good; only the final block is held back. When the call throws, discard what was written. This releases no more than a caller gets from the one-shot call on a message with a bad last block (the failure itself); the failure is the same `DecryptionFailed` for a wrong key, bad padding and a failed v1.5 unwrap, and it comes only after the whole content has been read, so the caller has no cheaper padding oracle than submitting whole messages. Use AuthEnvelopedData where authenticity matters.
* The platform's AES-GCM and AES-CCM are one-shot. `AuthEnvelopedData.EncryptStream` and `DecryptStream` accept streams but hold the message in memory, bounded by `MaxContentBytes` (default 1 GiB). Peak memory is about the message size plus the plaintext (about 2 GiB for a 1 GiB message). Nothing reaches the output unless the tag verifies. A caller who needs bounded memory should split the data into separately encrypted chunks.
* Measured: a 1 GiB payload through `SignStream` + `VerifyStream` and `EncryptStream` + `DecryptStream` (RSA-OAEP recipient, P-256 signer, indefinite-length BER on disk) peaked at 90 MiB working set (75 MiB before the run) on the worker, release build, .NET 10.0.402.

## AuthenticatedData, DigestedData, EncryptedData, CompressedData

* **AuthenticatedData** (§9): HMAC-SHA-256/384/512 (HMAC-SHA-1 is read with a warning), key delivered through any RecipientInfo; with authenticated attributes the MAC covers their DER and the attributes carry the content type and the content digest. The MAC and digest are compared in constant time.
* **DigestedData** (§7): proves integrity against accident only.
* **EncryptedData** (§8): AES-CBC under a key both sides hold.
* **CompressedData** (RFC 3274): zlib. `Decompress` stops with `LimitExceeded` at `MaxDecompressedBytes` or `MaxDecompressionRatio` times the compressed size.

## Differences found against openssl 3.5.9

Settled by experiment (black box, `openssl cms`, 3.5.9 built with its standard toolchain, with the platform libraries on the same OpenSSL):

* Ed25519, Ed448 and ML-DSA signatures cannot be made or verified by `openssl cms` without signed attributes ("invalid eddsa instance"); those cases are checked against the attribute form only. Ed25519 and ML-DSA need `-md sha512`, Ed448 `-md shake256`.
* `openssl cms` leaves the curve parameters out of `originatorKey` in a KeyAgreeRecipientInfo. RFC 5753 asks for them; we accept their absence.
* `openssl cms` 3.5.9 cannot make or open X25519 or X448 key agreement, or KEMRecipientInfo with ML-KEM; those forms are checked among our own readers and writers only (we know of no published vectors for RFC 8418 or RFC 9629). The newer OpenSSL 3.6.2 interoperates for ML-KEM-768 in both directions (checked, not the pinned version) and still not for X25519/X448.
* The 3.5.9 build used here has no zlib, so CompressedData was checked against the distribution's openssl 3.5.5 (`cms -compress`/`-uncompress`).
* `openssl cms` ignores countersignatures; ours verify them.
* `openssl cms -encrypt` applies `-keyopt` to the `-recip` before it; an RSA-OAEP key transport needs `-keyopt rsa_padding_mode:oaep`, and the KDF of an ECDH recipient is `sha1kdf` unless `-keyopt ecdh_kdf_md:sha256`.

## Interoperability matrix

Pinned OpenSSL 3.5.9 for both the command-line tool and the platform libraries, release build, on the build worker. Direction "ours→openssl" means we write and openssl reads; "openssl→ours" the reverse. P = pass, S = skipped with the reason in the test output.

| Form | ours→openssl | openssl→ours |
|---|---|---|
| SignedData RSA PKCS #1 v1.5, RSA-PSS, ECDSA P-256/384/521, with signed attributes, attached and detached | P | P |
| the same without signed attributes (RSA, ECDSA) | P | P |
| Ed25519, Ed448, ML-DSA-65 with signed attributes, attached and detached | P | P |
| Ed25519, Ed448, ML-DSA-65 without signed attributes | S (openssl cannot) | S (openssl cannot) |
| two signers; subject key identifier signer | P | P |
| EnvelopedData KTRI RSA-OAEP (SHA-1, SHA-256), PKCS #1 v1.5 | P | P |
| EnvelopedData KARI ECDH P-256, P-384 | P | P |
| EnvelopedData KARI X25519, X448; KEMRI ML-KEM-768 | S (openssl cannot open) | S (openssl cannot make) |
| EnvelopedData KEKRI, PWRI | P | P |
| AuthEnvelopedData AES-256-GCM, KTRI and KARI; tampered ciphertext refused | P | P |
| CompressedData (openssl 3.5.5 with zlib) | P | P |
| streamed EnvelopedData and SignedData (indefinite-length BER) | P | P |

## Keys, two-phase signing and policy

### Signing and decrypting through the key interfaces

* `CmsSignerSpec` takes a `Signer` (an `X509Signer`) or a `Key` (an `ISigningKey`) with an optional `SignatureSpec`. The key is never given the content: for RSA and ECDSA it is handed the digest of the DER signed attributes (`SignDigest`), for Ed25519, Ed448 and ML-DSA the DER of the signed attributes itself (`Sign`). A signer without signed attributes signs the content itself. A bare delegate `X509Signer` still signs the attributes with its function.
* `CmsDecryptionKey` stays as the adapter the recipient code reads through. `CmsDecryptionKey.FromKey(IKey, certificate, ownsKey)` wraps anything behind `IDecryptionKey` (RSA PKCS #1 v1.5 and OAEP, ML-KEM) or `IAgreementKey` (ECDH, X25519, X448); `FromRsa`, `FromECDiffieHellman`, `FromX25519`, `FromX448` and `FromMLKem` are shortcuts over the platform and library keys and go through the same adapter. A failed unwrap of any kind becomes "no key", so the RFC 3218 §2.3 random content key and the uniform `DecryptionFailed` hold for every backend.
* Key operations are synchronous calls on the adapter; only the stream I/O of the async twins is asynchronous. Signing keys are asked through `SignAsync`/`SignDigestAsync` by `SignStreamAsync`.

### Two-phase SignedData

`SignedData.Prepare(content, signers, at, options)` and `SignedData.PrepareStream(stream, signers, at, options)` build everything except the signature values and return a `PreparedSignedData`. Each signer needs its certificate and either a key or a `SignatureSpec`; no key is used. `PreparedSignedData.Signatures` holds one `PreparedSignature` (purpose `cms.signerinfo`) per signer: the signed attributes are `Data`, and `ToSign` is their digest (RSA, ECDSA) or themselves (EdDSA, ML-DSA). `Complete(signatures)` verifies each signature against its signer's public key before it assembles the message, so a damaged, swapped or wrong-key signature raises `InvalidSignatureException` and nothing is written.

* Attached content prepared from memory is kept in the state; detached content is not. Content prepared from a stream keeps only its digests: a detached message completes with `Complete`, an attached one with `CompleteStream(signatures, content, output)`, which writes indefinite-length BER and refuses (`CryptographicException`, after writing: discard the output) when the content no longer hashes to what was signed.
* The state is DER: `SEQUENCE { version 1, "cms.signeddata", contentType, detached, contentRetained, cmsVersion, digestAlgorithms, encapsulatedContentInfo, certificateParts, contentDigests, signers }`, each signer `SEQUENCE { PreparedSignature, certificate, identifierKind, digestOid, hasSignedAttributes, unsignedAttributes }`. It re-encodes to the octets it was read from (digests in ascending OID order). Unknown versions and damage are reported by `TryDecode`.
* The policy of `SignedDataOptions` (default `Standard`) is asked at preparation.

### Policy

* **Sign.** `SignedDataOptions.Policy` (default `Standard`) judges each signer's signature hash, key and SignerInfo digest as new data (no reference time: new-data rules do not depend on the date). SHA-1 and MD5 and RSA under 2048 bits are refused with `PolicyViolationException` carrying the decisions and rule ids. The ESS signing-certificate hash only names a certificate and is not judged.
* **Verify.** `SignedDataVerifyOptions.Policy` with `ReferenceTime` (both, or `ArgumentException`: the library never reads a clock). Each `SignerReport.Policy` holds the decisions at that instant, and the `policy` check is `Passed`, `Warning` (flagged) or `Failed` (rejected, so the signer is not valid). Without a policy the report keeps the plain `digest-algorithm` and `key-strength` warnings.
* **Encrypt and decrypt.** `CmsEncryptOptions.Policy` (default `Standard`) judges the content cipher and each recipient's public key as new data; `CmsDecryptOptions.Policy` with `ReferenceTime` judges the cipher the message names and the key that opens it, before any key operation. Triple DES follows `LegacyCiphers`.
* **CBC EnvelopedData.** S/MIME uses it everywhere, so `Standard` cannot refuse it. `CryptoPolicy.CheckContentCipher` returns a *flagged* decision (`cipher.cbc.unauthenticated.encrypt` / `.decrypt`): `Standard` reads and writes it, `Strict` (which turns flags into rejections) refuses it, and `AllowUnauthenticatedEncryption` / `AllowUnauthenticatedDecryption` accept it without a flag. The bare "unauthenticated encryption fails closed" rule (`CheckCipher`) is for formats with no integrity container at all, such as the OpenPGP SED packet.

### Async twins

`SignedData.SignStreamAsync` / `VerifyStreamAsync`, `EnvelopedData.EncryptStreamAsync` / `DecryptStreamAsync`, `AuthEnvelopedData.EncryptStreamAsync` / `DecryptStreamAsync` and `CompressedData.DecompressStreamAsync` take a `CancellationToken` and share their rules with the sync forms. They read through `Asn1StreamReader.ReadTokenAsync` / `ReadAsync` / `ReadContentAsync` and write through `BerStreamWriter`'s `…Async` methods; none wraps the other form. A cancelled sign or encrypt leaves a partial message in the output (discard it). A cancelled CBC decryption has released only the plaintext of earlier blocks, never the final one; a cancelled AuthEnvelopedData decryption released nothing (the AEAD is one-shot, so the message and plaintext are held in memory up to `MaxContentBytes`, exactly as in the sync form).

### CompressedData streaming

`CompressedData.DecompressStream` / `DecompressStreamAsync` inflate a forward-only message in constant memory with the same bounds as `Decompress`: `MaxDecompressedBytes`, and `MaxDecompressionRatio` times the compressed octets read so far. They stop with `LimitExceeded` and leave a partial output, which the caller discards.
