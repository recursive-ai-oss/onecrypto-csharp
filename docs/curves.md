# Ed25519, Ed448, X25519 and X448

Normative notes for the curve primitives in `RecursiveAI.OneCrypto.Primitives`. The .NET base class library has none of these
curves, so they are implemented here from RFC 8032 and RFC 7748. Everything else in this repository defers to the platform.

## What is implemented

| Algorithm | Spec | Notes |
|---|---|---|
| Ed25519 | RFC 8032 section 5.1 | pure; Ed25519ctx (context 1 to 255 bytes); Ed25519ph (SHA-512 prehash, context 0 to 255 bytes) |
| Ed448 | RFC 8032 section 5.2 | context 0 to 255 bytes (empty by default); Ed448ph (SHAKE256 prehash of 64 bytes) |
| X25519 | RFC 7748 sections 5 and 6.1 | |
| X448 | RFC 7748 sections 5 and 6.2 | |

Each has span one-shots on a static class (`Ed25519.TrySign`, `Ed25519.Verify`, `X25519.TryDeriveSharedSecret`, ...) and key
objects. Private keys (`Ed25519PrivateKey`, ...) hold their secret in a pinned buffer that is zeroed on `Dispose`; public keys
are plain immutable byte holders. Signing is deterministic. `Verify` returns `false` for every malformed input and never
throws on data; signing and key-derivation methods throw `ArgumentException` for wrong lengths or an over-long context.

Ed448 hashes with SHAKE256: the platform's where it has one, otherwise a managed Keccak-f[1600] (xor, and, not and fixed
rotations only, so constant time by construction) with identical output. Ed448 therefore runs on every platform.

## Verification semantics

A signature verifies when all of these hold.

1. It has the exact length (64 bytes for Ed25519, 114 for Ed448) and the context is at most 255 bytes.
2. S, the second half, is **below the group order** (RFC 8032 sections 5.1.7 and 5.2.7). This removes S + L malleability. For
   Ed448 the 57th byte of S is padding and must be zero.
3. The public key A is a **canonical** point encoding: y below p, on the curve, and not "negative zero" (x = 0 with the sign bit
   set). Ed448 additionally requires the unused low bits of the last byte to be zero.
4. The **cofactorless** equation [S]B = R + [k]A holds. It is checked by computing [S]B - [k]A and comparing its encoding with
   the R bytes of the signature, so a **non-canonical R** can never verify. RFC 8032 allows the cofactorless form; the cofactored
   form [8][S]B = [8]R + [8][k]A accepts more signatures and is not used.
5. Small-order A and small-order R are **not** rejected as such: when the equation holds exactly, they verify.

Evidence, against the C2SP Ed25519 edge-case set (914 vectors, flags `low_order_A/R`, `non_canonical_A/R`,
`low_order_component_A/R`, `low_order_residue`, `reencoded_k`): 172 accepted and 742 rejected, matching this policy on every
vector. Non-canonical A or R and `low_order_residue` are rejected; everything else is accepted. This differs from the most common
deployed behaviour only in rejecting non-canonical A (the RFC requires it) and from ZIP-215 in not accepting non-canonical
encodings or cofactor-only matches. Batch verification is out of scope.

Wycheproof (`ed25519_test.json`, `ed448_test.json`): every `valid` case verifies and every `invalid` case is rejected. The
`acceptable` cases (small-order and mixed-order public keys, Ed25519 only) follow the rule above.

## X25519 and X448

The scalar is clamped as RFC 7748 section 5 says. The u-coordinate of X25519 has its top bit ignored; values of p or more are
read modulo p, as the RFC requires. The all-zero check of RFC 7748 section 6.1 is exposed as the return value of
`TryDeriveSharedSecret`: `false` means the peer's key had low order and the exchange must be abandoned. The shared-secret buffer
holds zeros in that case. Wycheproof: every `valid` case agrees, every `acceptable` case either agrees or reports the zero
secret, every `invalid` case (X448 keys of the wrong length) is refused.

## Constant time

Every path that touches a secret follows the repository's constant-time rules.

- **Field arithmetic** (`Fe25519`, five 51-bit limbs; `Fe448`, eight 56-bit limbs) is straight-line code on `ulong` limbs.
  Products are split at the limb width so column sums are plain additions: no 128-bit type, no carry comparison, no branch.
  The reduction constants are fixed. Inversion and square roots are fixed exponentiation chains.
- **Montgomery ladder** (X25519, X448): a fixed number of steps (255, 448); the two working points are swapped with a mask taken
  from the scalar bit, never a branch or an index.
- **Fixed-base multiplication** (Ed25519 and Ed448 signing, key derivation): the scalar is recoded into signed 4-bit digits.
  Each digit selects a table entry by reading **every** entry of its row and keeping one with a mask; the sign is applied with a
  mask. The sequence of group operations and the memory addresses touched are the same for every scalar. The group laws used
  are complete, so no point (identity, doubling, inverse) takes a special path.
- **Scalar arithmetic** (mod the group order): Montgomery multiplication on 64-bit limbs with a final masked conditional
  subtraction. Hash outputs are reduced with a fixed sequence of Montgomery steps.
- **Ed448 secret scalar** is reduced modulo the group order before use. The base point has exactly that order, so
  [s]B = [s mod L]B, and the reduced value stays inside the fixed-base table's digit range.
- Not constant time, by design and only on public data: signature verification, point decoding, and the final comparison of the
  recomputed R with the signature.

How this is checked: `DOTNET_JitDisasm` on the secret-path methods (field multiply and square, scalar Montgomery steps, table
select, fixed-base multiplication, the ladders) shows no conditional jump other than loop control over public counters, bounds
checks on public indices and stack-clearing loops; the multiply and square methods contain no jump at all. Statistical timing
tests are described in the repository's timing-test notes.

Memory: scratch values holding secrets are zeroed before return where the code controls them. The runtime cannot promise that
no other copy of a secret exists.

## Tables and start-up

The fixed-base tables (256 entries for Ed25519, 448 for Ed448) are built on first use from the base point, so the first
signature in a process pays a few milliseconds. They contain only public data.
