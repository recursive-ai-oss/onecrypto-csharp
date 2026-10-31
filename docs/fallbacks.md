# Platform dispatch and managed fallbacks

How the library chooses between the platform's cryptography, a narrow managed fallback and an error. The per-platform results are in
[availability.md](availability.md).

## Order

1. **The platform first.** The .NET base class library, backed by the operating system's cryptography. Support is read from the
   platform's own `IsSupported` properties (`SHA3_256`, `Shake128`, `Shake256`, `ChaCha20Poly1305`, `MLKem`, `MLDsa`, `SlhDsa`).
   Where there is no such property, a fact about the platform is used: the browser (and WASI) has hashes and HMAC only, so AES, RSA
   and ECDSA are absent there; the three Brainpool curves are probed once per process by making a key, because macOS lacks them.
   Nothing is decided by catching an exception on a hot path.
2. **A managed fallback**, only where the platform lacks the primitive, and only for the two kinds of work that can be done safely
   in managed code:
   - *constant time by construction*: SHA-3 and SHAKE (FIPS 202), ChaCha20-Poly1305 (RFC 8439);
   - *public data only*: RSA and ECDSA **verification**.
3. **`AlgorithmNotSupportedException`**, naming the algorithm, the platform (operating system, architecture, runtime, and the loaded
   OpenSSL version on Linux) and the reason. It is a `NotSupportedException`.

There is no managed RSA or ECDSA signing, decryption or key agreement, on any platform, ever. There is no managed AES.

## Behaviour that does not depend on the platform

The same answer comes out whichever implementation runs. Where the platform is more lenient than the specification, the library
checks first.

- **ECDSA, DER signatures** are strict DER (X.690 section 10): definite and minimal lengths, minimal positive INTEGERs, no trailing
  bytes. Some platform verifiers accept BER-encoded signatures; the library does not. Fixed-width signatures (`r || s`) must be
  exactly twice the field size. `r` and `s` must lie in 1 to n-1 (FIPS 186-5 section 6.4.2). A public key that is not an
  uncompressed point on the curve is an `ArgumentException`, not a false result.
- **RSA** signatures must be exactly as long as the modulus and numerically below it (RFC 8017 section 8.2.2 step 1). macOS accepts
  an unreduced signature; the library rejects it. PKCS#1 v1.5 verification builds the expected encoded message and compares it whole
  (RFC 8017 section 8.2.2), so no lenient reading of the DigestInfo (an absent NULL, trailing bytes) is accepted. PSS follows
  EMSA-PSS-VERIFY (section 9.1.2) with any salt length and a mask hash that may differ from the message hash; the platform's PSS
  fixes both, so other parameter sets always take the managed verifier. PKCS#1 over SHA-3 digests also does, since the platform's
  DigestInfo table has no SHA-3.
- **RSA key bounds** on public input: modulus at most 16384 bits and odd, exponent odd, between 3 and 2^256. An out-of-bounds key
  is an `ArgumentException`.
- **Hashes** known to the verifiers: SHA-1, SHA-256, SHA-384, SHA-512, SHA3-224/256/384/512. SHA-224, SHA-512/224 and SHA-512/256
  are not offered (the platform has none; they are not needed by any format here). Whether a hash is acceptable for a signature
  is a policy question, answered above this layer.
- **Brainpool** (brainpoolP256r1, P384r1, P512r1, RFC 5639): verification works everywhere, through the platform where it has the
  curve and through the managed verifier where it does not (macOS, the browser). The 224- and 320-bit Brainpool curves are not
  offered.
- **SHA3-224** is always the managed Keccak: the platform has never offered it.

## Constant time

- The Keccak permutation and ChaCha20 are xor, and, not, add and fixed rotations on 32- and 64-bit words. Poly1305 uses five
  26-bit limbs with 64-bit products and explicit carries, a masked final reduction (no branch on the accumulator) and a 128-bit
  addition of the key half. The tag is compared with `CryptographicOperations.FixedTimeEquals` after the whole computation, and a
  message with a wrong tag is never decrypted (the output is zeroed).
- The compiled form of `Keccak.Permute`, `ChaCha20Poly1305Managed.Block`, `Poly1305.Block` and `Poly1305.Finish` was inspected
  with `DOTNET_JitDisasm` under full optimisation: every conditional jump is a loop counter, a length test on public sizes or a
  bounds check that leads to a throw helper; none depends on key, nonce or data. Statistical timing tests for both are in
  `tests/Timing/FallbackTargets.cs` (see [timing.md](timing.md)).
- The verify-only RSA and ECDSA code uses `BigInteger` and handles only public values (keys, digests, signatures). It makes no
  constant-time claim and has no timing test.

## Testing the fallbacks on hosts that do not need them

`Platform.ForceFallbacks()` (internal, for tests) makes dispatch choose the managed implementation wherever one exists, for the
current async flow. The vector tests use it, so the fallbacks run on every machine, and they also compare the managed output with
the platform's where both exist.
