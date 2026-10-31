# Password-based key derivation

Argon2 (`Argon2`), scrypt (`Scrypt`) and bcrypt-pbkdf (`BcryptPbkdf`) in `RecursiveAI.OneCrypto.Primitives`. The platform has
none of them. PBKDF2, HMAC and SHA-2 come from the platform; BLAKE2b (needed inside Argon2) and Blowfish's key schedule
(needed inside bcrypt-pbkdf) are ours and internal.

## Behaviour

| Function | Specification | Notes |
|---|---|---|
| `Argon2.DeriveKey` (d, i, id) | RFC 9106, version 0x13 | All inputs of the RFC: password, salt (8 bytes or more), memory m in KiB (8 × lanes or more, rounded down to a multiple of 4 × lanes), passes t, lanes p, tag length (4 or more), secret K, associated data X. |
| `Argon2.Verify` | | Recomputes and compares with `CryptographicOperations.FixedTimeEquals`. |
| `Scrypt.DeriveKey` | RFC 7914 | N a power of two above 1 (and below 2^(16·r)), r ≥ 1, p ≥ 1, r × p < 2^30. PBKDF2-HMAC-SHA256 from the platform. |
| `BcryptPbkdf.DeriveKey` | OpenSSH `openssh-key-v1` (`PROTOCOL.key`), construction after Provos and Mazières (1999) | Output 1 to 1024 bytes; OpenSSH takes the cipher key followed by the IV. Salt not empty. Rounds ≥ 1. |

Invalid parameters raise `ArgumentException` / `ArgumentOutOfRangeException`. Parameters that are valid but too costly raise
`KdfLimitExceededException` (a `CryptographicException` carrying the algorithm, parameter, requested value and limit) before
anything is allocated.

## Limits

`KdfLimits.Default`, used when a call passes none, because the parameters usually come from a file or message someone else
wrote:

| Limit | Default | Why |
|---|---|---|
| `MaxMemoryBytes` | 2 GiB | Large enough for the first parameter set RFC 9106 §4 recommends (m = 2^21 KiB, which OpenPGP's Argon2 S2K also uses), small enough that one hostile header cannot ask for tens of gigabytes. |
| `MaxArgon2Passes` | 64 | Time cost. |
| `MaxArgon2Parallelism` | 64 | |
| `MaxScryptWork` | 2^26 (N × r × p) | The RFC's N = 2^20, r = 8 vector is 2^23. |
| `MaxBcryptRounds` | 4096 | OpenSSH's default is 16. |

Raise a limit by passing your own `KdfLimits`; the memory check also refuses sizes no .NET array can hold.

## Side channels

- **Argon2i:** every memory index is computed from the pass, lane, slice and block counters and the parameters, never from the
  password. Timing and cache observations reveal nothing about the password through addressing.
- **Argon2id:** the same for the first two slices of the first pass; after that, as in the RFC, reference blocks are chosen from
  block contents.
- **Argon2d, scrypt:** addresses depend on the data by definition (RFC 9106 §3.4.1.1, RFC 7914 §5). That is a property of the
  algorithms, not something to fix, and no constant-time claim is made.
- **bcrypt-pbkdf:** Blowfish indexes S-boxes by data. A full-table scan on every lookup would cost 256 times as much, so lookups
  are direct; an attacker would need to share the CPU cache while a key file is being unlocked.
- No branch, loop bound or early exit in any of them depends on the password. Working memory is pinned and zeroed before the call
  returns. A garbage-collected runtime cannot promise that no copy of a secret survives elsewhere.
- The timing tests (`tests/Timing/KdfTargets.cs`) check Argon2i and Argon2id with one pass and 64 KiB against a fixed and a
  random password.

## Threads and vectors

Argon2 with more than one lane runs the lanes of a slice in parallel when a segment is at least 256 blocks (1 MiB of memory per
lane); smaller work runs on the calling thread. Results do not depend on the thread count. scrypt and bcrypt-pbkdf are
single-threaded.

Argon2's compression function has a scalar version (the reference, used everywhere AVX2 is missing) and an AVX2 version
(`Argon2Avx2`, chosen once from `Avx2.IsSupported`) that computes one round on four 64-bit lanes at a time. A test runs both on
random blocks and requires identical output. scrypt's Salsa20/8 stays scalar: a 128-bit vector version was measured 1.8 times
slower than the scalar one on arm64, because the rotates are single instructions there and the vector round is a longer
dependency chain.

## Benchmarks

Rows live in `bench/OneCrypto.Benchmarks/Rows/Argon2Rows.cs` and `ScryptRows.cs`: Argon2id (m = 64 MiB, t = 3, p = 4 and
m = 19 MiB, t = 2, p = 1) and scrypt (N = 2^14 and 2^17, r = 8, p = 1), 32-byte outputs, against BouncyCastle, Konscious and
Isopoh (managed, gating) and the libsodium behind NSec (native, reported). `peak-kdf` in the same project prints the peak working
set of one derivation per implementation, each in its own process.

## Tests

- RFC 9106 §5 (Argon2d, i, id), RFC 7693 Appendix A (BLAKE2b-512 of "abc"), RFC 7914 §12 (all four vectors, the 1 GiB one when
  `ONECRYPTO_BIG_VECTORS=1`) and §13 (the derived key of the PKCS#8 example).
- RFC 9580 Appendix A.12: the Argon2id output for t = 1, p = 4, m = 2^21 KiB decrypts the v4 SKESK of each sample message to the
  session key printed there (`ONECRYPTO_BIG_VECTORS=1`, 2 GiB).
- `testdata/kdf/openssl-vectors.txt`, written by `tools/gen-kdf-vectors.sh` from `openssl kdf`: odd memory sizes, up to 8 lanes,
  tags of 4 to 1024 bytes, secret and associated data, the multi-threaded path, and scrypt with r up to 16 and p up to 5.
- `testdata/bcrypt-pbkdf/`, written by `tools/gen-bcrypt-pbkdf-fixtures.sh` with `ssh-keygen`: passphrase-protected keys whose
  private section must decrypt with the key and IV our derivation yields (checked by the two equal check integers).
- Wycheproof has no Argon2, scrypt or bcrypt files (only PBKDF2), so none is run.
