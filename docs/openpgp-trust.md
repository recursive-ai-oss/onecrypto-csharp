# OpenPGP trust models

Two ways to answer "is this User ID bound to this certificate, and how far can I rely on that?", both in `RecursiveAI.OneCrypto.OpenPgp.Trust`. Both are deterministic: the answer depends only on the certificates, the caller's roots or owner trust, the options and the reference time. Nothing is read from a store or fetched.

| | Flow model (`WebOfTrust`) | Classic model (`ClassicTrust`) |
|---|---|---|
| Roots | the caller's fingerprints | owner trust per key (the GnuPG home's trust database or an owner-trust export, or a dictionary) |
| Result | a trust amount 0–∞ and the paths that carry it; 120 is "authenticated" | `Unknown`, `Undefined`, `Marginal`, `Full`, `Ultimate`, `Expired`, `Revoked` per User ID and per key |
| Reference | draft-nhw-web-of-trust-00 | GnuPG's validity computation, as observed |
| Oracle | `sq pki authenticate` 1.5.0 | `gpg --with-colons` 2.4.8 and 2.5.24 |

## Building the network

`TrustNetwork.Build(certificates, at, policy, limits)` turns certificates into nodes and certification edges at the reference time. An edge exists only when the certification:

- verifies against the issuer's key (a subkey does not certify) under the hash and key-size policy (`CryptoPolicy.Standard` by default);
- is not yet expired and not yet in the future relative to `at`, and is the newest one by that issuer for that User ID (a later one supersedes it, a later revocation removes it, RFC 9580 §5.2.1);
- was made while the issuer's own key was valid, unless it is a self-certification;
- is over a User ID that its certificate binds (a self-certification exists and is not revoked by a self-revocation at least as new).

Everything dropped is listed in `TrustNetwork.Rejections` with the reason. Certificates with the same primary key are merged. `TrustNetwork.FromEdges` describes a network by hand (for tests and for graphs that did not come from OpenPGP data).

A trust signature (RFC 9580 §5.2.3.21) carries a depth and an amount; `Regex` subpackets (§5.2.3.22) scope it. A direct-key certification is a delegation: it applies to every User ID of the target in the flow model, and is ignored by the classic model.

## Flow model

`WebOfTrust.Authenticate(network, roots, target, userId, requiredAmount = 120, limits, stopAtRequired)`.

- Each root is an introducer of unlimited depth and amount 120. A path is a chain of certifications from a root to the User ID. Every certification except the last must be a trust signature that has depth left for the hops after it; the amount of a path is the minimum amount along it (capped by 120); a regular expression on a trust signature limits the User IDs it can lead on to.
- The total is a maximum flow: each certification carries at most its amount, so independent paths add up and shared edges are counted once. By default the full maximum flow is computed (as Sequoia does, so `Amount` can exceed 120). `stopAtRequired: true` stops as soon as the required amount is reached, which is cheaper on very large networks when only the verdict matters.
- `AuthenticationLevel` is `Authenticated` (amount ≥ required), `Partial` (some trust, less than required) or `NotAuthenticated`. `Paths` lists the paths with amounts; `Reasons` says why a result is not authenticated.

Behaviour the draft leaves open or Sequoia 1.5.0 does differently, settled by crafted scenarios (`testdata/openpgp/trust/f*`) and followed here:

- **W1.** A regular expression on a certification scopes only the certifications that lead on from it, not the terminal certification of the User ID itself (scenario f20). The draft's text can be read either way.
- **W2.** Certifications of different User IDs of one certificate by one issuer share capacity when trust passes *through* the certificate; the strongest stands (f40).
- Sequoia lists no paths for a root's own User ID or for a User ID that is not self-signed; we compare verdicts only there.
- Path order differs from Sequoia's; amounts are compared as sorted lists. The first path chosen for a root is the shortest, then the larger.

## Classic model

`ClassicTrust.Evaluate(network, ownerTrust, options, limits)`. Options: marginals needed (3), completes needed (1), maximum certification depth (5), minimum certification level (2, as GnuPG's `--min-cert-level`).

Rules, all observed identically in GnuPG 2.4.4, 2.4.8 and 2.5.24 unless noted:

- Keys with ultimate owner trust are valid and trusted. Validity spreads in rounds; the depth limit counts hops from an ultimate key (a chain of keys valid at hop 5 is valid, hop 6 is not).
- Only a **fully valid** key introduces others. A marginally valid key with full owner trust does not.
- A certification from a valid key with full owner trust counts as one complete, marginal trust as one marginal. One complete or three marginals make the User ID `Full`; at least one of either makes it `Marginal`; a User ID certified only by valid keys that lack usable trust is `Undefined` ("q"); with no counted certifier it is `Unknown` ("-"). A certification by an ultimate key alone makes a User ID `Full`, whatever the counts.
- Certification levels: generic (level 0) certifications are accepted; `--min-cert-level 2` drops only a persona certification.
- A trust signature from a trusted key gives the certified key trust for chains: amount ≥ 120 is full, ≥ 60 marginal, below that none. Its depth is hop-by-hop: the certified key may pass trust on for at most `min(level, issuer's allowance − 1)` more hops. Owner trust itself never passes through a key's own trust signatures; only trust signatures and ultimate trust are parents.
- A key that holds a trust signature is *governed* by it: its owner trust no longer applies to User IDs outside the signature's scope. A trust signature too weak to count (amount < 60) leaves owner trust alone unless it carries a regular expression, in which case it governs the key and the key says nothing about User IDs outside the scope (scenario c95-random-16; the only evidence for this corner is that scenario).
- A certifier whose scope excludes the User ID is ignored (the result may be `Unknown`); one with no trust at all (owner trust unknown or never) still counts as having certified it, which is why the result is `Undefined`.
- Only the **first** regular-expression subpacket of a trust signature counts. A regular expression on a trust signature does not restrict the validity of the key it certifies.
- A revoked or expired ultimate key vouches for nothing here. GnuPG still lets a revoked ultimate key vouch (scenario c44), and ignores a certification dated after the reference time (c27); we do not follow either.

### GnuPG's regular expressions

GnuPG treats a trust-signature regular expression in its own way; `GnuPGRegex` follows what the binaries do, probed with 25 expressions (scenario c55):

- The domain form `<[^>]+[@.]example\.org>$` is run as a regular expression.
- Any other pattern is matched as plain text with `.` as a wildcard; `\` followed by punctuation is that character literally.
- A backslash followed by a letter or digit, or any of `[ ] ( ) | * + ? { } ^ $` outside the domain form, matches nothing.

`TrustRegex` is the general, bounded matcher: POSIX extended syntax without back-references, compiled to a state machine and simulated without backtracking, so a hostile pattern costs time linear in the User ID times the state count. An unreadable pattern or one over the limits matches nothing (a scope that cannot be read restricts rather than widens).

## Limits

`TrustLimits`, on by default; a computation that reaches one throws `TrustLimitExceededException` (with `Limit`) and never returns a partial answer.

| Limit | Default |
|---|---|
| `MaxCertificates` | 50,000 |
| `MaxCertifications` (signatures examined and edges kept) | 2,000,000 |
| `MaxRoots` | 10,000 |
| `MaxWork` (search and validity steps) | 200,000,000 |
| `MaxRegexLength` | 1,024 characters |
| `MaxRegexStates` | 4,096 |

The classic model also bounds the distinct trust-signature grants one key can receive at 256 and the certification depth at 255. A dense network of 10,000 certificates with 400,000 certifications of depth 255 finishes well within the limits (x64, one core, debug build): flow to the first 120 in about 0.1 s, the full maximum flow (total 2,400) in about 0.3 s, the classic model in about 0.1 s.

## Tool

`onecrypto pgp authenticate --root FINGERPRINT... [--userid TEXT] [--time ISO-8601] FILE...` reads binary or armored certificates and prints, for each User ID of each certificate that is not a root, the level, the amount, the paths and the reasons. Exit 0 when every checked binding is authenticated, 1 when one is not, 2 for bad arguments or unreadable input. The stateless CLI specification has no trust operation, so this is a tool verb, not a `sop` subcommand.

## Checks

- `testdata/openpgp/trust/` holds 162 generated scenarios (72 flow, 90 classic, 30 of each random) with throwaway keys. `tools/oracles/trust-scenarios.py` generates them, asks the oracles and records the answers (`trust-regen.sh` runs it on a machine that has the oracles). The tests (`TrustScenarioTests`) compare every query; the deviations above (c27, c44) are listed in the test.
- `TrustLimitTests`: the matcher, the limits and the dense network.
- Fuzz target `trust`: a certificate bundle with roots and owner trust through the network builder and both models under small limits.
