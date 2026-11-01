# GnuPG home and the certificate directory

`RecursiveAI.OneCrypto.OpenPgp.GnuPG` reads the files of a GnuPG home directory; `RecursiveAI.OneCrypto.OpenPgp.CertD` reads and writes the shared OpenPGP certificate directory. The parsers work on spans and streams and do no file or network I/O of their own; `GnuPGHome` and `CertDirectory` are the thin layers that walk a directory. Nothing here starts gpg or an agent: the library is not a key store, it reads the formats other tools keep.

## What is read

| File | Type | Notes |
|---|---|---|
| `pubring.kbx` | `Keybox` | Header, OpenPGP and X.509 blobs. OpenPGP blobs give `TransferableKey`s; X.509 blobs are kept as DER, not interpreted. `Write` reproduces the file byte for byte (the SHA-1 blob checksum is verified on read and carried through). |
| `pubring.gpg`, `secring.gpg`, `gpg --export` output | `LegacyKeyring` | Concatenated transferable keys. GnuPG's ring-trust packets (tag 12) are kept in place and decoded by `RingTrust`. |
| `private-keys-v1.d/*.key` | `GnuPGKeyFile`, `GnuPGSecretKey` | Extended key format and canonical S-expressions. Unprotected keys, `openpgp-s2k3-ocb-aes` and `openpgp-s2k3-sha1-aes-cbc` protection. `Unlock` turns a key into `ISigningKey`, `IDecryptionKey` or `IAgreementKey`. |
| `trustdb.gpg` | `TrustDb` | Owner-trust records. The trust model computation is not done. |
| `gpg --export-ownertrust` text | `OwnerTrustExport` | Parse and format. |
| `GnuPGHome` | | Opens a directory: `ReadPublicKeys` (keybox, else `pubring.gpg`), `ReadKeyFiles`, `FindKeyFile` (by the key's public value), `ReadTrustDb`. |

Keys unlock with RSA, ECDSA (NIST P-256/384/521, Brainpool), Ed25519, Cv25519, Ed448 and X448. DSA, Elgamal and Kyber secret keys, shadowed (token) keys and `openpgp-native` protection are recognised and refused with `NotSupportedException`. A wrong passphrase raises `GnuPGWrongPassphraseException`; for CBC protection a wrong passphrase and damaged data cannot be told apart. The S2K iteration count of an untrusted file is limited (`GnuPGLimits.MaxS2kCount`, default 2^32-1) and over-limit files raise `KdfLimitExceededException` before any hashing.

Secrets: unlocked parameters live in pinned buffers zeroed on dispose; RSA and EC keys go into platform handles; the RSA CRT exponents are derived with the constant-time reduction. An unprotected key file keeps its secret in the parsed S-expression tree for the life of the `GnuPGKeyFile`; a garbage-collected runtime cannot promise erasure.

## Limits (`GnuPGLimits.Default`)

Keybox blob 16 MiB, 1,048,576 blobs; key file 1 MiB; S-expression depth 32 and 65,536 nodes; trust records 4,194,304; text lines 4,194,304; at most 65,536 key files per directory. Malformed input raises `GnuPGFormatException` (with `Try*` forms returning a `GnuPGFailure`); OpenPGP data inside a container raises `OpenPgpParseException`.

## The keybox layout, as settled

The layout comes from GnuPG's format documents, the output of the `kbxutil` binary and mutation probing (change a byte, see what `kbxutil` prints; `tools/oracles/kbx-probe.py`). All integers are big-endian; offsets are from the start of a blob. Every blob starts with its length (u32), type (u8: 1 header, 2 OpenPGP, 3 X.509) and version (u8).

- **Header** (32 bytes): flags u16 at 6 (bit 1: contains OpenPGP), magic `KBXf` at 8, creation time at 16, last maintenance at 20.
- **Key blob**: flags u16 at 6 (bit 0 secret, bit 1 ephemeral), data offset at 8, data length at 12, key count u16 at 16, key-info size u16 at 18, key table at 20. A key entry is the fingerprint (20 bytes, zero padded to 32 in version 2 entries), a key-ID offset (version 1 only), flags u16 and reserved bytes. Then, for X.509, the serial number; then the name table (offset, length, flags, validity per entry: user IDs, or issuer and subject), the signature-expiry table, and 20 bytes of owner trust, all-validity, reserved, recheck-after, latest timestamp, creation timestamp and reserved space; the data (the OpenPGP packets or the DER) follows; the last 20 bytes are the SHA-1 of the rest.

### Gaps

Fields whose meaning black-box probing could not settle are read and written back unchanged but not interpreted: the key flag `0x0080` (seen on a Kyber subkey), user-ID flags, the meaning of the validity values and of a zero signature-expiry, the reserved-space field, header bytes 12-15 and 24-31, padding between data and checksum, MD5-checksum blobs from GnuPG before 2.1, and the X.509 key-ID offset. GnuPG 2.2 to 2.5 write zero for blob flags, owner trust and validity, so those are not exercised by real files. A `trustdb.gpg` 20-byte fingerprint field is untested against version 5 or 6 primary keys. The trust database version byte is 3 in files written by 2.4; the format notes say 2.

## Certificate directory (draft-nwjw-openpgp-cert-d-00)

- **Layout**: a certificate is stored under its fingerprint, lower-case hex of 32, 40 or 64 digits, in a file named by the remaining digits inside a directory named by the first two; the special name `trust-root` holds the trust-root key. Names outside this shape are refused (`GnuPGFormatException`), so a name can never leave the directory.
- **Tags**: `CertEntry.Tag` is the last-write time plus the length; `GetIfChanged(tag, name)` returns null when nothing changed.
- **Insert** merges the incoming certificate into the stored one: signatures, user IDs and subkeys the store lacks are appended, everything stored keeps its bytes (packets are never re-serialised), trust packets of the incoming copy are dropped, and a secret key given to `Insert` is stored as its public certificate. `InsertTrustRoot` stores the key as given (the trust root is a key, usually secret) and merges only with the same primary key.
  A new user ID goes in before the first subkey. Two signatures are the same when they agree outside the unhashed area, so an update that only adds unhashed subpackets is not merged; this is a known limit. The merge hook (`merge` argument) lets a caller replace the rule.
- **Writing** takes the write lock (`writelock` in the directory): an exclusive open polled until `LockTimeout` (30 s default; `TimeoutException`), written to a temporary file and renamed into place. Readers take no lock.
- **Default location**: `PGP_CERT_D` if set, else the platform's data directory plus `pgp.cert.d`.
- Sequoia adds files starting with an underscore (an index and its own state); they are ignored.

## How it is checked

- GnuPG 2.2.45, 2.4.4, 2.4.8 and 2.5.24 homes (committed under `testdata/gnupg/`, made by `tools/oracles/gnupg-home.sh`): keybox fingerprints and user IDs equal `gpg --with-colons --list-keys`; blob fields equal `kbxutil` output; legacy ring and `--export` round-trip byte for byte; ownertrust equals `--export-ownertrust`; every key file opens and its signing, agreement or decryption matches the OpenPGP public key.
- With `ONECRYPTO_GPG` set to a gpg binary, signatures made with unlocked keys verify with `gpg --verify`, and messages gpg encrypts to RSA and ECDH keys are opened (the session key is unwrapped and the SEIPD packet read here; GnuPG 2.5's own AEAD container is not read, its session key is proven by the unwrap).
- With `ONECRYPTO_SQ` set to Sequoia's `sq`: `sq` lists and merges into stores we wrote, we read and merge into stores `sq` wrote, and `sq` waits for our write lock.
- Fuzz target `gnupghome`; timing target `GnuPGKeyFile` (`tools/timing.sh`).
