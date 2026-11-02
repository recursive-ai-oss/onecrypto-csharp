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

### OpenPGP

`PgpPreparedSignature` (package `.OpenPgp`) is the same idea for OpenPGP signatures: the purpose is `openpgp.signature`, the state holds the signature digest and the signer's public key packet instead of a `SubjectPublicKeyInfo`, and `Complete` verifies with the OpenPGP rules. Its DER encoding is in [openpgp.md](openpgp.md); `ToSign` and `Spec` are for any `ISigningKey`.

### X.509

`CertificateBuilder.PrepareSelfSigned / Prepare`, `CertificateSigningRequestBuilder.Prepare` and `RevocationListBuilder.Prepare` build the to-be-signed structure and return a state whose `Data` is that DER; `Complete(state, signature)` on the same builder checks the signature against the signer's key and returns the parsed object. The purpose label stops a certificate state completing a CRL. The structures have the signer's `signatureAlgorithm` (`spec.ToAlgorithmIdentifier(key)`) in both places (RFC 5280 §4.1.1.2).

The one-shot builders still take an `X509Signer`: `X509Signer.FromKey(ISigningKey, SignatureSpec?)` makes one from any key interface, and `FromRsa`, `FromECDsa`, `FromMLDsa` and `FromDelegate` remain as conveniences. `Key` and `Spec` expose what it was made from. Code that signs other structures (CMS) should take an `ISigningKey` and a `SignatureSpec` and call `spec.ToAlgorithmIdentifier(key.PublicKey)` for the identifier it writes.

## PKCS #11 tokens (`RecursiveAI.OneCrypto.Keys.Pkcs11`, package `.Keys`)

A client for PKCS #11 v3.x modules (hardware tokens, HSMs, SoftHSM2). The private key never leaves the token: signing, decryption and agreement run in it, and everything else (hashing, DigestInfo, signature encodings) is done by the library with the results the in-memory keys give. Written from the OASIS PKCS #11 Specification v3.1; section numbers below are that document's.

```csharp
using Pkcs11Module module = Pkcs11Module.Load("/usr/lib/softhsm/libsofthsm2.so");    // by path; nothing is searched for
Pkcs11Slot slot = module.GetSlots().First(s => s.GetTokenInfo().Label == "my token");  // find tokens by label, not by slot number
using Pkcs11Session session = slot.OpenSession();
session.Login(pin);                                      // or LoginProtectedAuthenticationPath() for a token with its own PIN pad
Pkcs11Key key = session.OpenKey(label: "signing key");   // or by CKA_ID; the key is an IRsaKey, or an ISigningKey (EC, EdDSA) and IAgreementKey (EC)
byte[] sig = ((ISigningKey)key).Sign(data, SignatureSpec.RsaPss(HashAlgorithmName.SHA256));
```

| Class | Interfaces | Mechanisms used |
|---|---|---|
| `Pkcs11RsaKey` | `IRsaKey` | RSA PKCS #1 v1.5 signature: CKM_RSA_PKCS over a DigestInfo built here (SHA-1, 256, 384, 512). RSA-PSS: CKM_RSA_PKCS_PSS over the digest, MGF1 on the same hash, salt as long as the digest. Decryption: CKM_RSA_PKCS and CKM_RSA_PKCS_OAEP (MGF1 on the same hash, empty label) |
| `Pkcs11EcKey` | `ISigningKey`, `IAgreementKey` | ECDSA: CKM_ECDSA over a digest made here, `r \|\| s` from the token converted to DER or kept as P1363 as the spec asks. ECDH: CKM_ECDH1_DERIVE with no KDF (the x-coordinate), peer given as the raw uncompressed point, retried as a DER OCTET STRING for modules that only read that form; NIST P-256/384/521 and Brainpool as the token offers |
| `Pkcs11EdKey` | `ISigningKey` | CKM_EDDSA, pure Ed25519 (no parameters) and Ed448 (CK_EDDSA_PARAMS with the context) |

- **Finding keys.** `OpenKey` takes a label and/or an ID and requires exactly one private key to match (several is an error, never a pick). The public key comes from the caller (`publicKey:`), else a public key object with the same CKA_ID, else the RSA modulus and exponent on the private object, else a certificate with the same CKA_ID. Nothing checks it against the private key: a wrong public key shows as a signature that does not verify, and two-phase completion refuses it. `FindPrivateKeys`, `FindCertificates`, `GenerateKeyPair` (RSA 2048+, P-256/384/521, Ed25519), `ImportCertificate` and `Destroy` complete the object side. X25519/X448 (CKK_EC_MONTGOMERY) keys are listed but not opened.
- **Mechanisms.** `Supports` is true only when the token lists the mechanism (C_GetMechanismList, §5.5.5) and the object allows the operation (CKA_SIGN, CKA_DECRYPT, CKA_DERIVE). Using an unlisted mechanism raises `AlgorithmNotSupportedException` naming the mechanism and the token, before the token is called. A token that lists a mechanism and then refuses its parameters raises `Pkcs11MechanismException` (SoftHSM2 does OAEP with SHA-1 only, for example). `Pkcs11Session.SignRaw` takes any CKM number for mechanisms the interfaces do not cover.
- **PIN.** `Login(ReadOnlySpan<char>)` sends the PIN as UTF-8 and wipes the library's copies; the library never keeps or retries it. An empty PIN is refused (an empty value would mean the protected authentication path, which has its own method). The login belongs to the token, as in the specification (§5.6): a login or logout in any session of the application changes all of them, and `IsLoggedIn` reads the state from the token. A key with CKA_ALWAYS_AUTHENTICATE is refused (it needs the PIN again before every signature).
- **Failures** are always typed, all derived from `Pkcs11Exception` (itself a `CryptographicException`; `ReturnCode`, `Result` and `Function` are kept for logs): `Pkcs11ModuleException` (no such file, not a module, wrong architecture, C_Initialize failed, unsupported platform), `Pkcs11PinException` (wrong, invalid length, expired; `Pkcs11PinLockedException` when the token reports CKR_PIN_LOCKED), `Pkcs11TokenException` (no token, removed, session closed, device error, write-protected), `Pkcs11KeyException` (missing, ambiguous, removed from the token, not permitted for the operation), `Pkcs11MechanismException`. A failed RSA decryption is a plain `CryptographicException` that says nothing about the cause. A token reports a bad PKCS #1 v1.5 or OAEP ciphertext on its own terms, so a caller that tells an untrusted party whether decryption worked gives that party an oracle (RFC 8017 §7.2 note); CMS and OpenPGP do not. After a module is disposed, its sessions and keys raise `ObjectDisposedException`.
- **Threads.** Calls into one module are serialised across all its sessions. Sessions are not assumed to be concurrent-safe, and SoftHSM2 failed key generation with CKR_GENERAL_ERROR when sessions ran in parallel, so the library does not rely on modules being safe across sessions. The module is initialised with OS locking (CKF_OS_LOCKING_THREADS, §5.1). Loading one path twice shares the initialised module, which the last dispose finalises.
- **Locked tokens.** A locked PIN (CKR_PIN_LOCKED) raises `Pkcs11PinLockedException`, and the library never retries. SoftHSM2 never locks a user PIN (40 wrong tries did not), so no real locked token was exercised; the return-code mapping test covers it.
- **Platforms.** 64-bit macOS and Linux. Windows uses a 32-bit CK_ULONG and byte-packed structures; it is refused with a `Pkcs11ModuleException` rather than risk misreading structures. The calls go through the module's function list with function pointers: no marshalling code is generated, so the backend is trim- and NativeAOT-clean.
- **OpenPGP and CMS.** `CmsSignerSpec.Key`, `CmsDecryptionKey.FromKey` and `X509Signer.FromKey` take token keys like any other. For OpenPGP, `PgpSecretKey.FromExternalKey(publicKey, tokenKey)` makes a key for `PgpWriteOptions.Signers` and `PgpReadOptions.ExternalKeys` (RSA and NIST ECDH decryption, every signing algorithm the token has; X25519/X448 and the composite post-quantum keys stay in software). `PgpPreparedSignature` and `PreparedSignedData` complete with a token signature, in any process that can reach the token.

### Tested against

SoftHSM2 as a black box (2.6.1 from the distribution package on Linux x64, 2.7.0 from the Homebrew bottle on macOS arm64; `tools/oracles/softhsm2.sh --env`): every signature, decryption and agreement above checked against software verification and against OpenSSL (`cms -verify`, `cms -encrypt`) and Sequoia (`sqop verify`, `sqop encrypt`); two-phase CMS and OpenPGP signing prepared, signed against the token and completed in three processes; wrong PIN, wrong PIN length, unknown mechanism, missing and non-module paths, a key removed from the token, read-only sessions, logged-out sessions, disposed sessions. Known limits of that oracle: it never locks a user PIN (the mapping of CKR_PIN_LOCKED is tested directly), it does OAEP with SHA-1 only, and it imports private keys without CKA_DERIVE. There is no hardware token in the test set.

## Not here

gpg-agent, ssh-agent, CSC and the KMS adapters implement these same interfaces in their own packages. The library has no key store and no agent of its own.

## Use in CMS and X.509

CMS signers (`CmsSignerSpec.Key`), CMS recipients (`CmsDecryptionKey.FromKey`) and `X509Signer.FromKey` all sit on these interfaces. Two-phase CMS signing uses `PreparedSignature` with purpose `cms.signerinfo` (one per signer, inside `PreparedSignedData`, see `cms.md`); the OCSP request and response builders have the same `Prepare` / `Complete` pair as the certificate, request and list builders (purposes `ocsp.request`, `ocsp.response`; the certificates sent along are given again at completion).

## gpg-agent

> **Preview, not yet reviewed.** This backend has had no security review yet and its behaviour may still change. Do not rely on it for anything that matters until a review has been done and this note is removed.

`GpgAgentClient` (`RecursiveAI.OneCrypto.Keys.Agents`, package `.Keys`) talks to GnuPG's key agent over its local Assuan socket. The private key never leaves the agent: the client lists keys, reads their public parts and asks the agent to sign, decrypt or agree. Passphrase prompts, caching and smartcards are the agent's own (its pinentry runs where the user is: `GPG_TTY`, `TERM`, `DISPLAY` and `XAUTHORITY` are forwarded unless `ForwardEnvironment` is off). Nothing is started or fetched; no agent on the socket is an `AgentUnavailableException`.

- **Finding the socket** (`GpgAgent.LocateSocket`, or `GpgAgentOptions.SocketPath`). For the default home `~/.gnupg` it is `$XDG_RUNTIME_DIR/gnupg/S.gpg-agent`; for any other home (`GNUPGHOME` or `HomeDirectory`) it is `$XDG_RUNTIME_DIR/gnupg/d.<hash>/S.gpg-agent`, where `<hash>` is 24 characters of z-base-32 (alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`) over the first 15 octets of the SHA-1 of the absolute home path, as `gpgconf --list-dirs agent-socket` prints it (checked against gpgconf 2.4 and 2.5). Without `XDG_RUNTIME_DIR` the Linux per-user directory `/run/user/<uid>` is tried, then `S.gpg-agent` inside the home. A socket-redirection file (`%Assuan%` and a `socket=` line) is followed. The Windows redirection form (a TCP port and a nonce) is not supported.
- **Keys** are named by keygrip, 40 hexadecimal digits. `ListKeys` is `KEYINFO --list` (keygrip, passphrase-protected or not, token serial, cached or not); `GetKey(keygrip)` is `READKEY`, which gives the public key and so the key class; `FindKey(publicKey)` reads every listed key and compares, which is how an OpenPGP key or a certificate finds its keygrip without computing one.

| Key | Class | Sign | Decrypt / agree |
|---|---|---|---|
| RSA | `GpgAgentRsaKey` (`IRsaKey`) | PKCS #1 v1.5 with SHA-1, SHA-256, SHA-384, SHA-512 (`SETHASH` with the digest) | PKCS #1 v1.5 and OAEP (SHA-1, SHA-256, SHA-384, SHA-512), unpadded by the agent (`enc-val` with `flags pkcs1` or `flags oaep`), so no padding check runs in managed code |
| NIST P-256/384/521, Brainpool | `GpgAgentEcKey` | ECDSA over a digest, DER or fixed-width `r \|\| s` | ECDH: the agent returns the shared point; the x-coordinate is the secret |
| Ed25519, Ed448 | `GpgAgentEdKey` | pure EdDSA over the message, sent in the agent's `TBSDATA` inquiry (at most 2048 octets for gpg-agent 2.4; more is `AgentLimitException`) | |
| Cv25519, X448 | `GpgAgentMontgomeryKey` | | X25519 / X448; the point travels with libgcrypt's `0x40` prefix, an all-zero result is refused (RFC 7748 §6.1) |

- **Not offered.** RSA-PSS: the agent has no PSS operation in the versions tested (`SETHASH --pss` answers "Not supported"), so `Supports` is false and a PSS request is a `NotSupportedException`. DSA, ElGamal and other key types give `AlgorithmNotSupportedException`. Ed448 and X448 are mapped from the agent's curve names but were not exercised against an agent that makes such keys here.
- **Checking the agent.** Unless `VerifySignatures` is off, every signature is checked against the key's public key before it is returned, so a faulty or hostile agent cannot pass off a bad signature (`AgentProtocolException`). A decryption the agent could not do is a plain `CryptographicException` without a reason, like every RSA decryption.
- **Errors** are typed (`AgentException`): `AgentUnavailableException` (no socket, refused, timed out, `OperationTimeout`, default 10 minutes), `AgentKeyNotFoundException` (the agent's "No secret key" and "No such file"), `AgentRefusedException` (the agent's `ERR`: `Code`, `ErrorSource`, `Description`, `IsCancelled` for a cancelled pinentry, `IsBadPassphrase`), `AgentProtocolException` (anything the protocol or the limits do not allow) and `AgentLimitException`. A cancelled token closes the connection, which makes the agent abandon its prompt.
- **Limits, always on.** A line is at most 1100 octets (the protocol says 1000), one reply at most `MaxReplyBytes` (default 256 KiB) counted over every line including comments and status lines, so a server that never stops talking costs a fixed amount of memory; S-expressions are read to depth 8 and 256 nodes. Decrypted values are zeroed after use; a garbage-collected runtime cannot promise there is no other copy.
- **Each operation uses its own connection**, so a client is safe to share between threads and a failed operation leaves nothing behind.
- **With OpenPGP and CMS.** `PgpSecretKey.FromExternalKey(pgpKey, agentKey)` wraps an agent key for `PgpReadOptions.ExternalKeys`, so messages encrypted to a key in the agent decrypt through it (RSA, ECDH on the NIST curves, Cv25519); signing takes the agent key as the `ISigningKey` of `PgpPreparedSignature` or `CmsSignerSpec.Key`, and `CmsDecryptionKey.FromKey(agentKey, certificate)` opens CMS messages. The two-phase signing state works across processes: the second phase only needs the socket.

## ssh-agent

> **Preview, not yet reviewed.** This backend has had no security review yet and its behaviour may still change. Do not rely on it for anything that matters until a review has been done and this note is removed.

`SshAgentClient` speaks the SSH agent protocol (draft-ietf-sshm-ssh-agent; OpenSSH `PROTOCOL.agent`) over the socket in `SSH_AUTH_SOCK` or `SshAgentOptions.SocketPath`. `ListIdentities` is `SSH_AGENTC_REQUEST_IDENTITIES`; `GetKey(sshPublicKey)` returns an `SshAgentKey` (an `ISigningKey`) for a key the agent offers, `FindKey(publicKeyInfo)` the same by X.509 public key.

- **Signing.** RSA signs PKCS #1 v1.5 with SHA-256 (`rsa-sha2-256`, flag 2) or SHA-512 (`rsa-sha2-512`, flag 4); the SHA-1 `ssh-rsa` form is never requested, and an agent that answers with it anyway is an `AgentProtocolException`. ECDSA signs with the curve's own hash (SHA-256, SHA-384, SHA-512 for P-256, P-384, P-521), returned as DER or fixed-width `r || s` as the spec says; Ed25519 signs the message. The agent hashes the data itself, so `SignDigest` is a `NotSupportedException`, and PSS and security-key (`sk-`) keys are not available (`AlgorithmNotSupportedException` for the latter). Certificates in the agent are used through their key.
- **SSHSIG and authentication.** `SshAgentKey.SignToSshSignature(data, spec)` returns the SSH signature blob (the algorithm name and the signature as two strings, RFC 4253 §6.6) that an SSHSIG file (`PROTOCOL.sshsig`) or a user-authentication request carries; the caller builds the signed-data structure. Signatures made this way verify under `ssh-keygen -Y verify`.
- **Checking and limits.** As for gpg-agent: the returned signature is checked against the public key unless `VerifySignatures` is off, and the algorithm name on it must be the requested one. A reply is at most `MaxMessageBytes` (default 256 KiB, OpenSSH's own limit) and the length is checked before anything is allocated; a key count the reply cannot hold, a wrong message type and a short read are `AgentProtocolException`. A request that does not fit one message is `AgentLimitException`.
- **Refusals.** `SSH_AGENT_FAILURE` is an `AgentRefusedException` with code 0: the agent says nothing about why (a key added with `ssh-add -c` whose confirmation was denied, a locked agent, a missing key). `OperationTimeout` defaults to 2 minutes because a confirmation or a token touch waits for the user.

## Checks

The agent backends are tested against real agents started by the tests in throwaway directories (`tools/oracles/gpg-agent-home.sh` makes the GnuPG home): gpg-agent 2.4 and 2.5 with RSA, P-256, Ed25519 and Cv25519 keys, OpenSSH ssh-agent with RSA, ECDSA (three curves) and Ed25519. OpenPGP signatures made through the agent verify under `gpg` and `sqop`, CMS signatures under `openssl cms` and (RSA, P-256) `gpgsm`, messages encrypted by `gpg` and `openssl cms` decrypt through the agent, SSHSIG files verify under `ssh-keygen -Y verify`. Fake agents that send garbage, oversized or endless replies, a downgraded `ssh-rsa` signature or a signature of another key, and a fuzz target for the Assuan, S-expression and ssh-agent readers cover the failure modes.
