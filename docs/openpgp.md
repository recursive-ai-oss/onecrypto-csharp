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
- Compression: ZIP and ZLIB, with an expansion ceiling of 1 MiB plus 1032 times the compressed octets read, and `MaxNesting` (8) layers. BZip2 (algorithm 3, read only) is our own decompressor of the published format: it checks every block CRC and the stream CRC, refuses the obsolete randomised block form, holds one block (at most 900,000 entries) in memory and produces its output on demand; because one block of a repeated byte shrinks to a few dozen octets and expands to about 46 MB, its ceiling is 128 MiB plus 1032 times the compressed octets read (a larger output is `PgpFailure.LimitExceeded` before it is written). Writing BZip2 is not offered.
- LibrePGP, read: version 5 keys (certificates are evaluated and bound with version 5 signatures; secret keys unprotected, with CFB protection, or with OCB protection (usage 253: the string-to-key output is the OCB key, the first 15 octets of the 16-octet IV field are the nonce, the additional data is the tag, cipher, mode 2 and the public key packet from its version octet)), version 5 signatures (the trailer counts the hashed header in eight octets and a document signature also hashes the literal packet's format, name and date, six zero octets when detached, `t` and five zeros when cleartext), SKESK version 5, OCB Encrypted Data (OCB and EAX), and the Kyber composite (algorithm 8, X25519 + ML-KEM-768 and X448 + ML-KEM-1024: KMAC256 combiner, SHA3 key shares, a 32-octet version 5 fingerprint in the fixed information). GnuPG 2.5 exports a Kyber secret key as its own S-expression behind a private-use string-to-key (mode 3); that form and the draft's own layout are both read. Kyber over NIST and Brainpool curves is reported as unsupported: messages GnuPG 2.5.24 wrote for those did not open with the construction the draft describes (the key share and the combiner were varied: hash width, input order, compressed points), so nothing is written for them either. Without ML-KEM on the platform a Kyber message is `PgpFailure.Unsupported`.
- Not yet: SLH-DSA; SHA-224 and RIPEMD-160 (reported unsupported).

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

**Choosing the container when writing** (`PgpWriteResult.Format` and `Reason` report what was chosen). The recipients' keys decide, as their Features octet and key version announce what they read:

| Recipients | Container |
|---|---|
| every key is version 6 or announces SEIPD v2 (0x08), none is version 5 | SEIPD v2 (RFC 9580), PKESK v6, SKESK v6 |
| every key is version 5 or announces OCB Encrypted Data (0x02) | LibrePGP OCB Encrypted Data (tag 20, AES with OCB, 256 KiB chunks), PKESK v3, SKESK v5 for passwords |
| anything else, including a mix of the two | SEIPD v1 (the one container all of them read) |
| passwords only | SEIPD v2; `ForceLibrePgp` selects OCB Encrypted Data, `ForceSeipd1` SEIPD v1 |

A version 5 key signs with version 5 signatures (the only case in which they are written); version 5 keys are never generated. ECDH to a version 5 key names the leftmost 20 octets of its fingerprint in the KDF (draft-koch-librepgp §13.5). Encrypting to a Kyber key (X25519 or X448) writes the LibrePGP PKESK.

**Limits**: `OpenPgpLimits` for packets; the expansion ceiling above; S2K cost from untrusted input is bounded by `CryptoPolicy.KdfLimits` (Argon2 memory 2 GiB by default); password and key passwords are tried against every candidate in turn.

**Async twins** spool their input (memory up to 4 MiB, then a temporary file) and run the synchronous pipeline: I/O does not block, memory is constant, the CPU work is not parallelised.

**Checked against**: RFC 9580 Appendix A (inline, cleartext, detached, X25519/OCB, password EAX/OCB/GCM, Argon2 SKESK, locked key), RFC 9980 Appendix A.1–A.4 (v6 and v4 ML-KEM-768+X25519 with SEIPD v1 and v2, ML-DSA-65+Ed25519, ML-DSA-87+Ed448/ML-KEM-1024+X448 messages and detached signatures), GnuPG-written messages in every legacy cipher, old SED and LibrePGP OCBED (`testdata/openpgp/legacy`, regenerated by `tools/oracles/legacy-ciphers-fixtures.sh`), two-way runs with GnuPG 2.4.4, 2.4.8 and 2.5.24, Sequoia sqop 0.38, gosop 1.1 and OpenPGP.js 6.3 (`tools/oracles/sop-matrix.sh`, `tools/oracles/gpg-messages.sh`), and the interoperability suite ([sop.md](sop.md)).
