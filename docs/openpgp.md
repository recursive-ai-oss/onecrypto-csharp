# OpenPGP packet layer

`RecursiveAI.OneCrypto.OpenPgp` reads and writes the OpenPGP wire format: RFC 9580 (versions 4 and 6), RFC 9980 post-quantum key and PKESK formats, version 3 keys and signatures (read), and the LibrePGP version 5 packets (read). Message encryption, signing and verification are not in this layer; it only turns bytes into typed, immutable packets and back.

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
