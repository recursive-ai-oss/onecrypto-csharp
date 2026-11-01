# Recorded exchanges for the online clients

Every `*.exchanges.json` file is a list of HTTP exchanges recorded through `RecordingTransport` from the public endpoint named in the file, and replayed by `ReplayTransport` in `tests/OneCrypto.Online.Tests/PublicEndpointTests.cs`. They hold public data only: certificates, CRLs, OCSP responses, RFC 3161 replies and OpenPGP public keys, with the response headers as received. Request headers are not recorded.

| File | Endpoint | Recorded | What it holds |
|---|---|---|---|
| `globalsign-chain.exchanges.json` | `secure.globalsign.com`, `ocsp.globalsign.com`, `crl.globalsign.com` (the AIA, OCSP and CRL locations named by the certificates in `globalsign-leaf.pem`) | 2026-11-01 00:23 UTC | the issuer certificate, OCSP answers (GET form) and CRLs for the leaf and for the intermediate |
| `tsa-freetsa.exchanges.json` | `https://freetsa.org/tsr` | 2026-11-01 00:23 UTC | one time-stamp reply for a SHA-256 imprint with a fixed nonce |
| `tsa-digicert.exchanges.json` | `http://timestamp.digicert.com` | 2026-11-01 00:23 UTC | the same |
| `tsa-sectigo.exchanges.json` | `http://timestamp.sectigo.com` | 2026-11-01 00:23 UTC | the same |
| `wkd-dkg.exchanges.json` | `openpgpkey.fifthhorseman.net` and `fifthhorseman.net` (Web Key Directory) | 2026-11-01 17:19 UTC | the key for `dkg@fifthhorseman.net` by the advanced and the direct method, both policy files (empty), a 404 for the submission-address file |
| `wkd-missing-policy.exchanges.json` | `wiktor.eu` | 2026-11-01 17:19 UTC | the 404 for the policy file of a domain that serves none (direct method; the `openpgpkey` sub-domain does not resolve) |
| `wkd-not-found.exchanges.json` | `openpgpkey.fsfe.org` | 2026-11-01 17:19 UTC | the 404 for a key lookup (`info@fsfe.org`) |
| `hkp-keys-openpgp-org.exchanges.json` | `keys.openpgp.org` HKP interface | 2026-11-01 17:19 UTC | `op=get` and `op=index` for one published key by fingerprint, `op=vindex` (answered 400), a 404 |
| `vks-keys-openpgp-org.exchanges.json` | `keys.openpgp.org` VKS interface | 2026-11-01 17:19 UTC | the same key by fingerprint, key ID and email, and a 404 |

`globalsign-leaf.pem` is the public TLS certificate served by `www.globalsign.com` at that time; `globalsign-root-r46.pem` is GlobalSign Root R46 from the system trust store (SHA-256 `4FA3126D8D3A11D1C4855A4F807CBAD6CF919D3A5A88B03BEA2C6372D93C40C9`), used as the trust anchor.

The time-stamp requests use the fixed nonce `4f6e654372797074` and the data `OneCrypto online fixture`, so that the replayed request matches the recorded one. Never use a fixed nonce against a real authority outside this recording.

To record again, run the live tests with `ONECRYPTO_ONLINE_LIVE=1 ONECRYPTO_ONLINE_RECORD=<directory>` and copy the files over these. The live tests are never part of CI.
