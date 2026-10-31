# Camellia and the legacy block ciphers

`RecursiveAI.OneCrypto.Primitives` has `Camellia` (RFC 3713, 128-, 192- and 256-bit keys) and four ciphers that OneCrypto reads
but never writes: `Cast5` (RFC 2144), `Idea`, `Blowfish` and `Twofish`. The platform has none of them.

## Surface

| | Camellia | CAST5 | IDEA | Blowfish | Twofish |
|---|---|---|---|---|---|
| Key | 16, 24, 32 bytes | 5 to 16 bytes | 16 bytes | 4 to 56 bytes | 16, 24, 32 bytes |
| Block | 16 | 8 | 8 | 8 | 16 |
| Encrypt | ECB, CBC, CFB | none | none | none | none |
| Decrypt | ECB, CBC, CFB, OpenPGP CFB | ECB, CBC, CFB, OpenPGP CFB | same | same | same |

- The legacy classes have no encryption method at all. CFB decryption runs the block function forwards, so the engines can encrypt
  internally (the tests use that to round-trip), but nothing public reaches it.
- CBC takes `PaddingMode.PKCS7` (RFC 5652 section 6.3, the default) or `PaddingMode.None`. Padding is checked over the last block with
  masks and no early exit; on failure the destination is zeroed before `CryptographicException`, so no plaintext leaves. Whether the
  padding was valid is visible only through the exception, as with any padded CBC, so protocols must authenticate before decrypting.
- CFB uses full-block segments (CFB128 for the 16-byte ciphers, CFB64 for the 8-byte ones, as OpenSSL's `-cfb` does) and accepts any
  length; the last block's keystream is truncated.
- `DecryptOpenPgpCfb(source, destination, resync)` decrypts OpenPGP symmetric data: zero IV over the random prefix and the data
  (RFC 9580 section 13.9). With `resync: true` it applies the older packet's variant (RFC 4880 section 13.9), reloading the feedback
  register with ciphertext bytes 3 to block size + 2 after the prefix. The prefix and its two check bytes are returned decrypted; the
  caller checks them.
- Spans may be the same (in place) or must not overlap. Calls do not allocate. Key schedules live in pinned arrays that `Dispose` zeroes.

## Constant time

Table-driven implementations index tables with secret bytes, which a co-resident observer of the cache can read. None of these
ciphers does that, in the rounds or the key schedule:

- **Camellia.** One lookup of the F-function is a vector operation on its eight bytes: each byte's low nibble indexes all sixteen
  16-entry rows of SBOX1 through a byte shuffle, and the high nibble selects a row through a tree of blends. SBOX2, SBOX3 and SBOX4 are
  derived exactly as RFC 3713 section 2.4.1 defines them (rotate the output or the input by one bit). The P-function is six shuffles.
- **CAST5 and Blowfish.** Every S-box lookup compares the index with all 256 positions and keeps the match (`CtLookup.Word`), vectorised
  over 8 (or 4) positions per step. The Blowfish key schedule performs its 521 block encryptions the same way.
- **Twofish.** The key-dependent S-boxes are never tabulated. Each S-box byte is computed from the two fixed byte permutations,
  which the paper builds from 4-bit permutations, and those are 16-entry shuffles; the key bytes are XORed in as the paper's h
  function does. The MDS and RS multiplications use shifts and masks.
- **IDEA.** No tables. Multiplication modulo 65537 uses masks instead of the zero test and division, and the decryption schedule's
  inverses are computed as x^65535 with a fixed sequence of multiplications.
- CAST5's rotation amounts come from the key; they are applied with a rotate instruction, whose time does not depend on the amount.

The cost is speed; see the numbers below. `ByteShuffle` picks `pshufb` (SSSE3) or `tbl` (Arm64) from the platform's capabilities and
falls back to `Vector128.Shuffle`, which gives the same results where it is the only option (it is a software loop where no vector
hardware exists, with the same access pattern).

JIT output was inspected with `DOTNET_JitDisasm` (full opts) for `CamelliaEngine.F`, `TwofishEngine.H`, `CtLookup.Word`,
`Cast5Engine.F`, `BlowfishEngine.F` and `IdeaEngine.Mul`: the only conditional jumps are the static-initialisation check, bounds checks,
and loops over public counts (stage, round, table position); no jump, `cmov` or address depends on a secret.

## Verification

- Camellia: RFC 3713 Appendix A (3 vectors); Wycheproof `camellia_cbc_pkcs5_test.json` (216 tests, both directions, invalid padding
  rejected); OpenSSL 3.5.9 CBC and CFB both ways for all three key sizes.
- CAST5: RFC 2144 Appendix B.1 (128-, 80- and 40-bit keys) and the B.2 maintenance test (one million iterations).
- IDEA, Blowfish, Twofish: the published known answers (IDEA key 0001..0008; the Blowfish variable-key set; the Twofish submission's
  128-, 192- and 256-bit known answers); OpenSSL 3.5.9 (legacy provider) for IDEA, CAST5 and Blowfish; GnuPG for all of them.
- OpenPGP CFB: fixtures written by GnuPG 2.4 (`tools/gen_gnupg_cfb_fixtures.py`) for IDEA, CAST5, Blowfish, Twofish and Camellia 128/192/256,
  both the protected packet and the older one with resynchronisation.
- Wycheproof has no files for CAST5, IDEA, Blowfish or Twofish, and none for Camellia ECB or CFB.

## Cost of avoiding table lookups

Indicative CBC rates on a loaded machine, ratio = ours / BouncyCastle 2.7.0 (below 1 is faster). AMD Ryzen 9 7950X3D (x64) and Apple M2 (arm64).

| Cipher | x64 ratio | arm64 ratio |
|---|---|---|
| Camellia (CBC encrypt and decrypt, 128 and 256-bit keys, 1 KiB and 64 KiB) | 1.84 to 2.21 (geomean 2.0) | 2.49 to 2.87 (geomean 2.7) |
| IDEA | 1.3 to 1.4 | 1.65 |
| Twofish | 8.0 to 8.1 | 13 to 14 |
| CAST5 | 15 | 32 to 33 |
| Blowfish | 18 to 19 | 44 to 45 |

Blowfish key setup takes about 1.2 ms (521 block encryptions), CAST5 and Twofish key setup 1 to 12 microseconds.
For reference OpenSSL 3.5.9 on the x64 machine: Camellia-128-CBC 310 MB/s, Camellia-256-CBC 225 MB/s, Blowfish 229 MB/s, CAST5 205 MB/s, IDEA 168 MB/s.
The timing tests (`tests/Timing/LegacyCipherTargets.cs`) run data, key and key-setup kinds plus an A/A control per cipher.
Camellia, CAST5, IDEA, Twofish: no leak in the indicative runs apart from the key-pool kind flagged under heavy load; see the report.
The pool of key objects is placed at random slots each batch, because a fixed even/odd split showed an address effect that the A/A control caught.
