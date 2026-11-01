# docs

Normative, language-neutral notes on behaviour: verification semantics, policy presets, resource limits and the methods behind the tests and benchmarks.

- [conformance.md](conformance.md): what is tested, against what, documented deviations, speed against the bar, constant-time evidence.
- [browser.md](browser.md): what runs in the browser engine, how the suite is run and compared, what the browser cannot do.
- [cms.md](cms.md): CMS content types, verification rules, limits, failing closed, streaming and the openssl matrix.
- [issuance.md](issuance.md): the certificate authority, its profiles, serial numbers, CRLs and delta CRLs, and two-phase issuing.
- [tsp.md](tsp.md): RFC 3161 requests, responses and TSTInfo, the verifier's rules and the time-stamp authority handler.
- [ocsp-responder.md](ocsp-responder.md): the OCSP responder handler, its status mapping, preproduced responses and the openssl checks.
- [online.md](online.md): the online package: the guarded transport, the cache, the TSA, OCSP, CRL and issuer-certificate clients, the validator's sources, record and replay.
- [load.md](load.md): `Crypto.Load`: the formats it reads, the sniffing decision table, password rules, limits and errors.
- [legacy-ciphers.md](legacy-ciphers.md): Camellia and the decrypt-only CAST5, IDEA, Blowfish and Twofish; how they avoid secret-indexed tables, their cost, and how they are checked.
- [kdf.md](kdf.md): Argon2, scrypt and bcrypt-pbkdf: behaviour, limits, side channels, tests.
- [keys.md](keys.md): key interfaces, signature specs, operating-system keys and two-phase signing (with the serialised state).
- [policy.md](policy.md): `CryptoPolicy`, the reference-time contract, the dated rules and the presets.
