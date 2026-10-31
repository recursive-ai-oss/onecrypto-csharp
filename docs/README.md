# docs

Normative, language-neutral notes on behaviour: verification semantics, policy presets, resource limits and the methods behind the tests and benchmarks.

- [cms.md](cms.md): CMS content types, verification rules, limits, failing closed, streaming and the openssl matrix.
- [legacy-ciphers.md](legacy-ciphers.md): Camellia and the decrypt-only CAST5, IDEA, Blowfish and Twofish; how they avoid secret-indexed tables, their cost, and how they are checked.
- [kdf.md](kdf.md): Argon2, scrypt and bcrypt-pbkdf: behaviour, limits, side channels, tests.
- [keys.md](keys.md): key interfaces, signature specs, operating-system keys and two-phase signing (with the serialised state).
- [policy.md](policy.md): `CryptoPolicy`, the reference-time contract, the dated rules and the presets.
