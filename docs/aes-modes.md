# AES modes: OCB3, EAX and key wrap

`RecursiveAI.OneCrypto.Primitives` has `AesOcb`, `AesEax` and `AesKeyWrap`: modes over the platform's AES, for the places the
platform has no mode of its own. The AES block function always comes from the platform (`Aes` ECB and CBC one-shots on spans);
OneCrypto writes only the mode. AES Key Wrap with Padding (RFC 5649) is in the platform (`Aes.EncryptKeyWrapPadded`,
`Aes.DecryptKeyWrapPadded`) and is not duplicated.

## Behaviour

| | OCB3 (RFC 7253) | EAX (Bellare, Rogaway, Wagner 2004) | Key wrap (RFC 3394, SP 800-38F KW) |
|---|---|---|---|
| Key | 16, 24 or 32 bytes | 16, 24 or 32 bytes | 16, 24 or 32 bytes |
| Nonce | 1 to 15 bytes | any length, including none | none |
| Tag | 8 to 16 bytes, fixed per key object | 8 to 16 bytes, fixed per key object | 8-byte integrity block |
| Data | any length | any length | a multiple of 8 bytes, 16 to 1 MiB |

- **Tag length per key object.** OCB binds the tag length into its nonce formatting (RFC 7253 §4.2), so a ciphertext made with
  one tag length does not authenticate under another. Both AEAD classes therefore fix the tag length when the key object is
  created and reject any other length.
- **Failure.** Decryption and unwrapping check the authentication value with `CryptographicOperations.FixedTimeEquals` after the
  whole message has been processed. On failure the destination is zeroed and `AuthenticationTagMismatchException` is thrown (the
  `Try…` forms return `false`). EAX computes the tag over the ciphertext first and produces no plaintext at all on failure; OCB
  and key wrap compute the plaintext and the check together and clear it.
- **Buffers.** Input and output may be the same span (in place) or must not overlap; a partial overlap is an `ArgumentException`.
  Key wrap does not allow in-place use.
- **Lengths** are public. Control flow depends on message, nonce and associated-data lengths and on nothing derived from the key.
- **Thread safety.** A key object is not safe for concurrent use. Give each thread its own.
- **Disposal.** The key-dependent tables (OCB's L table, EAX's CMAC subkeys) live in pinned buffers that `Dispose` zeroes.
  The AES key itself stays in the platform's handle. A garbage-collected runtime cannot guarantee that no other copy of a key
  exists.
- **Platforms without AES** (the browser) throw `PlatformNotSupportedException` from the constructor.

## Constant-time rules applied

- OCB: the L table and offsets are only XORed and passed to AES. `double` selects the reduction with a mask. The block index
  `i` is public, so `ntz(i)` may select a table entry. The nonce is public, so the position of the offset window inside the
  stretched nonce may index bytes.
- EAX: CMAC subkeys use the same masked doubling; the CTR counter increments with an arithmetic carry; the tag compare is
  fixed-time.
- Key wrap: the loop counts depend on the data length only; the integrity check is a fixed-time compare of 8 bytes.

## How it batches

The platform's one-shot `Aes.EncryptEcb` sets up a cipher context and key schedule on every call, which costs more than the AES of a
short message. Each key object therefore keeps long-lived ECB (and, for EAX, CBC) transforms and one working buffer of about 2 KiB,
and gathers work for the whole buffer into one call. OCB needs two calls to encrypt (the nonce block with the associated data;
then the data, the final partial block's pad and the tag together) and three or four to decrypt. EAX's CMAC runs on the CBC
transform, which carries its chaining value from call to call; the first block of each MAC is XORed with the value the transform
holds so that its effective input is the one the MAC defines, and the block after the tweak block is a per-key constant. Key wrap is
inherently sequential and calls AES once per step, so it costs 6n platform calls for n key blocks.

## Verification

- Vectors: RFC 7253 Appendix A (sixteen sample tuples, the 96-bit-tag tuple, and the iterated test for each key size and tag
  length given); the EAX paper's AES-128 vectors (Appendix G); RFC 3394 §4.1 to §4.6; Wycheproof `aes_eax_test.json`,
  `aes_wrap_test.json`, and `aes_kwp_test.json` (against the platform's KWP). Wycheproof has no OCB file.
- A block-at-a-time EAX built straight from the paper checks the batched code across every buffer boundary.
- Two-way with OpenSSL: OCB through `tools/openssl_aead.py` (the command line has no AEAD modes), key wrap through
  `openssl enc -id-aes*-wrap`.
- Tamper tests flip every tag, ciphertext and associated-data byte and check that nothing is released.
