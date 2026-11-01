# OpenPGP packet layer

`RecursiveAI.OneCrypto.OpenPgp` reads and writes the OpenPGP wire format: RFC 9580 (versions 4 and 6), RFC 9980 post-quantum key and PKESK formats, version 3 keys and signatures (read), and the LibrePGP version 5 packets (read). The packet layer only turns bytes into typed, immutable packets and back; messages (sign, verify, encrypt, decrypt) are built on it and described under [Messages](#messages).

Namespace: `RecursiveAI.OneCrypto.OpenPgp.Packets`. Spec: RFC 9580 §4 (packet syntax), §5 (packet types), §6 (armor), §10 (transferable keys); draft-koch-librepgp §5 for version 5.

## What is read

- **Headers** (§4.2): old and new format, every length form. Partial body lengths are read on any packet type, and the final chunk must be a definite length. Indeterminate length (old format) reads to the end of the input.
- **Packet types**: every tag of §5 plus the LibrePGP OCB-encrypted-data packet (tag 20). Typed: public and secret keys and subkeys (versions 2 to 6, fingerprint and key ID per §5.5.4, secret-key protection per §5.5.3, including the GnuPG "GNU dummy" S2K), signatures (3, 4, 5, 6) with every subpacket of §5.2.3.7, one-pass signatures, PKESK (3, 6), SKESK (4, 5, 6), SEIPD (1, 2), symmetrically encrypted data, literal, compressed, user ID and attribute, trust, marker, padding. An unknown tag, version or algorithm becomes an `UnrecognizedPacket` (or an unknown subpacket) carrying its bytes.
- **Signature counts**: the subpacket-area counts are two octets in versions 4 and 5 and four octets in version 6 (RFC 9580 §5.2.3, LibrePGP §5.2.3).
- **Critical bit**: a critical subpacket that is not understood is listed by `SubpacketArea.UnrecognizedCritical()`; the parser never discards it, and a verifier decides what to do with it (RFC 9580 §5.2.3.7 says to treat the signature as invalid).
- **Armor** (§6): `Armor.Decode`/`TryDecode`, `ArmorReadStream`, `ArmorWriteStream`. The CRC-24 is optional; when present it is checked. Headers are kept in order. `ArmorReadOptions.Strict` (used by `sop`) refuses leading and trailing text and over-long lines; `Lenient` is the default.
- **Transferable keys** (§10): `TransferableKey` groups a key's packets into primary key, direct and revocation signatures, user IDs and attributes with their certifications, and subkeys with their binding signatures. Anything that does not fit stays in order as trailing packets; `ToPublic()` derives the certificate from a secret key.

## Lossless

Every packet keeps the exact bytes it was read from (`OriginalEncoding`, including the header form and length encoding). Writing a parsed stream with `PacketParser.Write` reproduces the input byte for byte; `canonical: true` writes new-format headers with definite lengths instead. Hashing is always over the retained bytes (a signature's hashed region is a slice of the input, not a re-encoding).

## Limits (`OpenPgpLimits.Default`)

| Limit | Default |
|---|---|
| packet body | 16 MiB (stream readers expose larger bodies as a `Stream` and never buffer them) |
| packets per stream | 1,048,576 |
| subpackets per area | 4,096 |
| multiprecision integer | 65,535 bits |
| armor line | 8,192 bytes; 256 header lines |
| armored input | 64 GiB |

Violations raise `OpenPgpParseException` with an `OpenPgpError` code and the byte offset; every parse entry point has a `Try` form returning an `OpenPgpFailure`.

## Streaming

`PacketReader` walks a `Stream` frame by frame. `PacketFrame.Body` is a forward-only `Stream` over the body (partial chunks joined); a frame that is never turned into a typed packet costs no allocation. A synthetic 1 GiB literal-data packet in 64 KiB partial chunks is read with working-set growth far under 100 MiB (see the test `ALargeStreamedLiteralPassesInConstantMemory`, which measures the process working set while reading; set `ONECRYPTO_STREAM_CHUNKS=16384` for 1 GiB).

## Checked against

- RFC 9580 Appendix A samples (all parse and write back identically; fingerprints are the published ones).
- A generated corpus: keys, certificates, signatures and messages from GnuPG 2.4 and 2.5, Sequoia `sq` 1.5 (v4, v6, post-quantum), RNP 0.17, OpenPGP.js 6.3 and GopenPGP 3 (through gosop). Every file parses and writes back identically; fingerprints equal `gpg --with-colons` and the other tools' listings. Counts are in [sop.md](sop.md#corpus).
- A hand-built version 3 RSA key (MD5 fingerprint computed independently).
- A fuzz target (`pgppacket`) over packets and armor.

## Messages

Namespace `RecursiveAI.OneCrypto.OpenPgp`: `PgpMessageReader` (`Read`, `ReadSigned`, `VerifyDetached`, `VerifyCleartext`), `PgpMessageWriter` (`Write`, `SignDetached`, `SignCleartext`), each with an `...Async` twin, over `PgpCertificate` (a transferable key with its binding, expiry, revocation and usage evaluated at a given time), `PgpKey` and `PgpSecretKey` (an unlocked secret key; S2K-protected keys are opened with CFB-254/255, AEAD-253 and Argon2). Every call takes the reference time (`Now`) and a `CryptoPolicy`; results are `PgpReadResult` with one `PgpSignatureResult` per signature (signer, fingerprint, creation time, hash, policy verdict and reasons).

**Reading** (`PgpMessageReader.Read`)

- Signatures v3, v4 and v6 (binary, text, standalone, detached, one-pass, cleartext) over RSA, DSA, ECDSA (NIST and Brainpool), EdDSA (legacy and Ed25519/Ed448), and the RFC 9980 ML-DSA+Ed25519 / ML-DSA+Ed448 composites (both parts must verify; version 6 and a 256-bit digest or larger only). Bytes are hashed as received.
- Public-key encrypted session keys v3 and v6: RSA, ECDH (NIST, Brainpool, legacy Curve25519), X25519, X448, ML-KEM-768+X25519 and ML-KEM-1024+X448. Passwords: SKESK v4 (CFB), v5 (LibrePGP, OCB) and v6 (AEAD, Argon2 or iterated S2K). A session key can be supplied directly.
- Encrypted data: SEIPD v2 (EAX, OCB, GCM; chunked), SEIPD v1 with MDC, LibrePGP OCB Encrypted Data, and old Symmetrically Encrypted Data only with `AllowUnauthenticatedEncryption` (default refused with `PgpFailure.UnauthenticatedEncryption`). Ciphers: AES, Camellia, Twofish and the decrypt-only IDEA, TripleDES, CAST5 and Blowfish.
- Compression: ZIP and ZLIB, with an expansion ceiling of 1 MiB plus 1032 times the compressed octets read, and `MaxNesting` (8) layers. BZip2 is reported as unsupported.
- Not yet: LibrePGP Kyber (read as an unsupported algorithm), SLH-DSA, version 5 keys and signatures for message operations.

**Certificates at a point in time** (`PgpKey.StateAt`)

- A key is valid at time T when it exists, a binding signature in force at T covers it (newest first; a binding that has itself expired, or whose user ID was revoked since, is out; a signing subkey also needs an unexpired primary key binding signature), it has not expired and it is not revoked.
- Revocations: "no reason", "compromised" and unknown reason codes are hard and invalidate the key at every time; "superseded", "retired" and "user ID no longer valid" count only from their creation. An expired revocation signature is ignored.
- When a user ID is marked primary, the other user IDs do not decide flags or expiry. An empty Key Flags subpacket means the key may do nothing.
- Issuer subpackets are hints: a signature is tried against every key the hints name, then against every key of its algorithm, and only a key that verifies it counts. A binding is judged by the primary key's verification, not by what it claims about its issuer. A critical subpacket or notation we do not understand voids a signature (RFC 9580 §5.2.3.7).
- A secret key decrypts only when its flags allow encryption; keys that name a PKESK but are certify-, sign- or authenticate-only are skipped.

**Message grammar** (RFC 9580 §10.3): session key packets must be followed by encrypted data, a one-pass header must be closed by its signature, and a signature after the literal data needs its one-pass header; anything else is `PgpFailure.MalformedMessage`. Unknown packet versions, session keys with unknown string-to-key types, and signatures with unknown hash algorithms are skipped, not fatal. The first partial chunk of a packet must hold at least 512 octets. Armor headers may be UTF-8.

**Fail closed**

- SEIPD v1 (no chunking) is decrypted into a spool (memory up to a few MiB, then a temporary file) and released only after the MDC matches. SEIPD v2 and OCB Encrypted Data release a chunk only after its tag verifies; a bad final tag or chunk count throws after earlier chunks were delivered, so a streaming caller that must not act on partial data uses the `...Async` forms, which write to the caller's stream only after the whole operation has succeeded.
- Every decryption failure (wrong key, bad padding or checksum, bad unwrap) is the same `PgpFailure.CannotDecrypt`; `KeyIsProtected` appears only when a locked key that could open the message was seen and nothing else did. Session-key validation (padding, checksum) accumulates its verdict in a mask and tests it once (RFC 9580 §13); it has a timing test.
- Unauthenticated old SED output is released as it decrypts, which is why it needs the opt-in.

**Writing** (`PgpMessageWriter.Write`)

- The format is chosen from the recipients: SEIPD v2 when every recipient key is version 6 or advertises the AEAD feature, otherwise SEIPD v1; AES-256 with OCB (or the recipients' AEAD preferences; with SEIPD v1, the first of AES-256, AES-192, AES-128 that every recipient listing preferences accepts); ECDH recipients whose key names a key-wrap cipher other than AES or a KDF hash below SHA2-256 are refused; a version 6 padding packet of 16 to 255 random octets in v2 messages. `ForceSeipd1` overrides.
- PKESK v3/v6 for RSA, ECDH, X25519, X448, ML-KEM composites; SKESK v4 (iterated-salted SHA-256) or v6 (Argon2id, 3 passes, 4 lanes, 64 MiB) for passwords. A password message is never written with a legacy cipher.
- Signatures v4 and v6 through `ISigningKey`: default hash SHA-512 (the digest that matches the curve for ECDSA), salted for v6. Literal data keeps filename and date; text mode canonicalises line endings. Compression ZIP or ZLIB on request, none by default. Cleartext signing follows RFC 9580 §7 (dash-escaping, `Hash:` header).
- Armor is written with the CRC-24 line: GnuPG 2.4 and 2.5 refuse armor with neither padding nor CRC (data lengths that are multiples of 3). Readers keep the CRC optional.

**Limits**: `OpenPgpLimits` for packets; the expansion ceiling above; S2K cost from untrusted input is bounded by `CryptoPolicy.KdfLimits` (Argon2 memory 2 GiB by default); password and key passwords are tried against every candidate in turn.

**Async twins** spool their input (memory up to 4 MiB, then a temporary file) and run the synchronous pipeline: I/O does not block, memory is constant, the CPU work is not parallelised.

**Checked against**: RFC 9580 Appendix A (inline, cleartext, detached, X25519/OCB, password EAX/OCB/GCM, Argon2 SKESK, locked key), RFC 9980 Appendix A.1–A.4 (v6 and v4 ML-KEM-768+X25519 with SEIPD v1 and v2, ML-DSA-65+Ed25519, ML-DSA-87+Ed448/ML-KEM-1024+X448 messages and detached signatures), GnuPG-written messages in every legacy cipher, old SED and LibrePGP OCBED (`testdata/openpgp/legacy`, regenerated by `tools/oracles/legacy-ciphers-fixtures.sh`), two-way runs with GnuPG 2.4.4, 2.4.8 and 2.5.24, Sequoia sqop 0.38, gosop 1.1 and OpenPGP.js 6.3 (`tools/oracles/sop-matrix.sh`, `tools/oracles/gpg-messages.sh`), and the interoperability suite ([sop.md](sop.md)).

## Key management

Namespace `RecursiveAI.OneCrypto.OpenPgp`: `PgpKeyGenerator`, `PgpKeyEditor`, `PgpUserIds` and `PgpPreparedSignature`; the happy path is `Pgp.GenerateKey`, `Pgp.ChangePassword`, `Pgp.Revoke` and `Pgp.Certify` (RFC 9580 §5.2, §5.5, §10; RFC 9980 for the post-quantum composites). Every edit returns a new `PgpCertificate`; the packets an edit does not touch are kept byte for byte and in order (trust packets and unknown packets too). Reference times are always arguments: only the `Pgp.*` calls and the `sop` tool read the clock, through a `TimeProvider`.

**Generation** (`PgpKeyGenerator.Generate`). A primary key that may certify and sign, an encryption subkey unless `SigningOnly`, a direct-key signature (always for version 6, and for version 4 when there is no User ID) and one positive certification per User ID, each carrying key flags, the expiry if asked for, features and algorithm preferences. Only version 4 and 6 keys are written; a version 5 key is never generated.

| Profile | Version | Primary / subkey |
|---|---|---|
| `Rfc9580` (default) | 6 | Ed25519 / X25519 |
| `Rfc9580V4` | 4 | Ed25519 / X25519 (native algorithms) |
| `Rfc9580Ed448` | 6 | Ed448 / X448 |
| `Rfc9580Rsa`, `Rfc4880Rsa` | 6, 4 | RSA-3072 both |
| `Rfc4880Curve25519` | 4 | EdDSA legacy / ECDH Curve25519 |
| `NistP256`, `NistP384`, `NistP521` | 4 | ECDSA / ECDH |
| `Rfc9980Pqc`, `Rfc9980PqcHigh` | 6 | ML-DSA-65+Ed25519 / ML-KEM-768+X25519, ML-DSA-87+Ed448 / ML-KEM-1024+X448; `AlgorithmNotSupportedException` where the platform lacks ML-DSA or ML-KEM |

Preferences written: AES-256, AES-192, AES-128; SHA-512, SHA-256, SHA-384; zlib, zip, none; for the profiles that read SEIPD v2 also the AEAD suites AES-256/OCB and AES-128/OCB and the features octet `0x09`, otherwise `0x01`. RSA keys keep `p < q` (RFC 9580 §5.5.5.1): the platform's key is regenerated when its primes come out the other way round.

**Secret-key protection** (`PgpKeyEditor.SetPassword`, `PgpKeyGenerationOptions.Password`). Version 6: S2K usage 253, AES-256 with OCB, Argon2id (t = 3, p = 4, 64 MiB, the second recommendation of RFC 9580 §3.7.1.4), key from HKDF-SHA-256 with the packet tag, version, cipher and AEAD as info and the public part as associated data. Version 4: usage 254, AES-256 in CFB with a SHA-1 check and an iterated and salted SHA-256 S2K (count octet `0xF3`). The exception is a version 4 key with a legacy Curve25519 ECDH subkey, which carries the protection GnuPG itself writes (AES-128 and a SHA-1 S2K hash): observed with GnuPG 2.4.8, whose agent rejects the unlocked scalar of such a subkey as a bad secret key under any other protection. Passwords are UTF-8 octets; a key is unprotected only when the caller gives no password. Reading checks every S2K parameter against `KdfLimits` before it allocates.

**Edits** (`PgpKeyEditor`): `AddUserId`, `RemoveUserId`, `SetPrimaryUserId`, `SetExpiry` (primary or one subkey), `SetKeyFlags`, `SetPreferences`, `AddSubkey` (encryption, signing with its embedded primary key binding signature, authentication), `RemoveSubkey`, `Refresh` (re-issue the self-signatures, drop MD5, SHA-1, RIPEMD-160 and the old ciphers from the preferences, add an encryption subkey if there is none). A re-issued self-signature starts from the newest valid one and keeps every hashed subpacket it does not replace, unknown ones included; a new signature supersedes the old one by its creation time (of two in the same second, the later in the file wins), and the old ones stay.

**Revocation** (`RevokeKey`, `RevokeSubkey`, `RevokeUserId`, `CreateRevocationCertificate`, `AddRevocationSignature`): reasons are the RFC 9580 §5.2.3.31 codes; none and compromised are hard (the key is invalid at every time), superseded, retired and "user ID no longer valid" only count from their creation. A revocation certificate is the public primary key and one key revocation signature; `AddRevocationSignature` applies the bare signature form that GnuPG writes to the certificate it belongs to.

**Certification** (`Certify`, `RevokeCertification`, `PgpUserIds.IsCertified`): levels generic, persona, casual and positive (0x10 to 0x13), trust signatures with level, amount and regular expression, non-exportable and non-revocable marks, an expiry. `IsCertified` answers "does an authority vouch for this User ID at this time": the certification must verify against the authority's primary key, exist and be unexpired at that time, the authority key must be valid then and able to certify, and neither a later revocation by the authority nor a revocation of the User ID by the certificate's own key may have ended it. `Merge` unions two copies of a certificate without dropping anything (a signature of the primary key that does not verify is left out).

**Two-phase signing** (`PgpPreparedSignature`). `PrepareDetached(publicKey, data, now)` fixes the signature header (creation time, issuer fingerprint, the version 6 salt) and hashes the data; `ToSign` and `Spec` say what any `ISigningKey`, token or remote service has to sign; `Complete(rawSignature)` verifies the result against the signer's public key and returns the signature packet, so a signature by the wrong key or over other data never leaves the call. `Encode`/`Decode`/`TryDecode` serialise the state as DER, version 1: `SEQUENCE { version INTEGER, purpose UTF8String "openpgp.signature", signerKey OCTET STRING (the public key packet), type INTEGER, hash INTEGER, signedHeader OCTET STRING, unhashed OCTET STRING, salt OCTET STRING, digest OCTET STRING }`. It holds the digest and the public key, never the data or a private key. The ML-DSA composites sign with two components and are not offered.

**Checked against**: `KeyManagementTests` and `SopKeyTests` (every profile with and without a password through signing, encryption, revocation, certification and password changes; edits shown lossless on RFC 9580 Appendix A.4), the two-way scripts `tools/oracles/gpg-keys.sh`, `rnp-keys.sh` and `sop-keys-matrix.sh`, the interoperability suite ([sop.md](sop.md)), the `pgpkey` fuzz target and the `OpenPgpSecretKeyUnlock` timing target.

**Fuzzing** (`pgpkey`): the first three runs each found a defect, all fixed and kept as regression tests (`testdata/fuzz-repros/pgpkey-*`): a secret that unlocked but did not fit its public EC point escaped as a platform exception; a completed signature or key with too few fields was indexed; an Argon2 specifier with zero lanes escaped as an `ArgumentOutOfRangeException`. The run after the fixes: 900 s, 572,828 executions, 7,586 coverage features, 0 crashes.

**Interop results** (keys we generate, edit, revoke and certify, checked by other implementations; throwaway keys):

| Oracle | Result |
|---|---|
| GnuPG 2.4.8 (`gpg-keys.sh`) | 121 pass, 0 fail, 8 n/a (version 6 keys and the native Ed25519 algorithms are not readable by GnuPG 2.4) |
| GnuPG 2.5.24 | 113 pass, 10 n/a with the reasons below, 0 unexplained |
| RNP 0.17 (`rnp-keys.sh`) | 93 pass, 0 fail, 4 n/a (version 6 profiles) |
| sqop 0.38 / Sequoia 2.4.1 (`sop-keys-matrix.sh`, every non-post-quantum profile, with and without a password) | 294 pass, 0 fail, 2 unsupported |
| gosop 1.1 / GopenPGP 3.0 (same profiles) | 229 pass, 0 fail, 79 unsupported (gosop has no `update-key`, `merge-certs` or `validate-userid`) |
| OpenPGP.js 6.3 (our driver, same profiles) | 264 pass, 0 fail, 44 unsupported (same subcommands) |
| Post-quantum profiles (`pqc`, `pqc-high`) on OpenSSL 3.5.9, same matrices | sqop 50 pass / 0 fail / 6 unsupported, gosop 48 / 0 / 20, OpenPGP.js 56 / 0 / 12 (cells the other side cannot run are unsupported; our own round trips run in all) |
| Three-process two-phase signing, verified by our `verify`, sqop 0.38 and GnuPG 2.5.24 | 46 pass, 0 fail; GnuPG 2.4.8: 36 pass, 0 fail |

Differences that are the oracle's, not ours:

- GnuPG 2.5.24 does not import an unprotected ECDH subkey: `gpg -K` lists it as `ssb#` and decryption says "No secret key". Its own `--export-secret-keys` of a key without a passphrase behaves the same when imported into a new home. Protected keys work, and so does 2.4.8. The cells report n/a.
- GnuPG 2.5.24 as built for the oracle cache asks the terminal for `--gen-revoke` even with `--command-fd`; the six cells that use its revocation certificate run with 2.4.8 (pass).
- Sequoia's `sqop` is built on nettle, which has no ML-DSA or ML-KEM: it cannot generate or use `rfc9980` keys. The post-quantum profiles are checked against our own sign/verify/encrypt/decrypt round trip, and Sequoia's `sq` parses their certificates without complaint.
- A third-party certification is hashed with the key framed by the version of the *signature* (version 4: `0x99` and a two-octet length; version 6: `0x9B` and a four-octet length), not by the version of the certified key (RFC 9580 §5.2.4). Certifications between keys of different versions failed in both directions against Sequoia until the framing followed the signature.
