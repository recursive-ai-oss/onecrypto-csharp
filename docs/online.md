# Online: the transport, the guards, the cache and the clients

Normative behaviour of `RecursiveAI.OneCrypto.Online`. The package references only core (`RecursiveAI.OneCrypto`); core has no network code. Nothing in it fetches unless a call asks: constructing a client, a fetcher or a source does no I/O, and a validation that is not given a source never touches the network (`PathValidator.Validate` cannot; `ValidateAsync` calls a source only when one was set in the options).

## Layers

| Type | Role |
|---|---|
| `ITransport`, `TransportRequest`, `TransportResponse`, `TransportException` | One HTTP exchange: no redirects, no cache, no limits. Implementations report their own failures as `TransportException` with a `TransportFailure`. |
| `HttpTransport` | The default, over `HttpClient`. |
| `RecordingTransport`, `ReplayTransport`, `ExchangeLog` | The same seam as the fixture harness. |
| `Fetcher`, `FetchRequest`, `FetchOptions`, `FetchResult` | Guards, limits, redirects, cache. Every failure is a `FetchOutcome`. |
| `NetworkGuard`, `IAddressResolver` | Which addresses may be reached. |
| `IFetchCache`, `MemoryFetchCache`, `CacheControl` | RFC 9111 storage. |
| `TsaClient`, `OcspClient`, `CrlClient`, `AiaClient` | The protocols. Each has a public static `Interpret` that turns a `FetchResult` into its result type, for callers with their own transport. |
| `OnlineCertificateSource`, `OnlineRevocationSource` | `ICertificateSource` and `IRevocationSource` for `PathValidator.ValidateAsync`. |

A client never throws for a network reason or because a server sent rubbish. It returns a result with an outcome enum and a reason sentence. The exceptions that do escape are `OperationCanceledException` when the caller's token is cancelled and argument exceptions for programming errors.

## Guards

On by default; each failure is a `FetchOutcome` with a reason, never a hang.

| Rule | Outcome |
|---|---|
| Only `http` and `https` URLs; no other method than GET and POST | `SchemeNotAllowed` |
| No user information (`user:password@`) in the URL, in a redirect target too | `UserInfoNotAllowed` |
| A URL that comes from a certificate or a message (`UrlOrigin.Certificate`: AIA, CDP, OCSP locations) cannot reach a blocked address; the clients mark these URLs, and the sources always do | `AddressBlocked` |
| Every redirect hop is checked like a new request and counts as `UrlOrigin.Certificate`, even when the first URL was written by the caller | `AddressBlocked`, `RedirectRejected` |
| At most `MaxRedirects` (default 3), no loops, no https to http downgrade, a `Location` is required | `TooManyRedirects`, `RedirectRejected` |
| Headers the caller added (API keys) are dropped when a redirect leaves the host; a POST becomes an empty GET on 301, 302 and 303 (RFC 9110 §15.4) | |
| Response body at most `MaxResponseBytes` (default 4 MiB; TSA and OCSP 1 MiB, AIA 1 MiB, CRL 32 MiB), judged on the declared `Content-Length` and again while reading | `ResponseTooLarge` |
| A body shorter than its declared length, or a connection that breaks while reading | `TruncatedBody` |
| One time limit (default 20 s) from the start of the request to the last body byte | `Timeout` (distinct from the caller's cancellation) |
| Name resolution, connection and TLS failures | `NetworkError` |
| Non-2xx answers | `HttpStatus` |

### Blocked addresses

`NetworkGuard.Default` refuses: IPv4 `0.0.0.0/8`, `10/8`, `100.64/10` (carrier-grade NAT), `127/8`, `169.254/16`, `172.16/12`, `192.0.0.0/24`, `192.0.2/24`, `192.88.99/24`, `192.168/16`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, `224/4` and `240/4`; IPv6 `::`, `::1`, `64:ff9b:1::/48`, `100::/64`, Teredo `2001::/32`, `2001:2::/48`, `2001:10::/28`, `2001:db8::/32`, `fc00::/7`, `fe80::/10`, `fec0::/10` and `ff00::/8`. Addresses that wrap an IPv4 address are judged by the wrapped address: IPv4-mapped `::ffff:a.b.c.d`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16` and the deprecated IPv4-compatible `::a.b.c.d`. `localhost` and `*.localhost` names are refused before any lookup. `NetworkGuard.AllowedNetworks` re-opens specific ranges (an internal responder); `AllowPrivateAddresses` turns the rules off.

### DNS rebinding

`HttpTransport` makes the connection itself for any request that carries a guard. It resolves the host name once, checks every address in the answer (one blocked address refuses the connection), and connects to one of those same addresses; TLS and SNI still use the original host name. The address that was checked is the address that is used, so an answer that changes between lookups has no effect. Connections are pooled per guard instance, so a connection opened under a permissive guard is not reused under a stricter one. `UseProxy` is off. Proxies would make the connected address the proxy's and defeat the check.

In a browser the runtime's fetch makes the connection and its address cannot be inspected: the literal checks of `Fetcher` still apply, and cross-origin rules (CORS) are the browser's. A request the browser refuses surfaces as `NetworkError` with the browser's reason, and the revocation source records it in `Attempts`; the validator then reports the certificate's revocation as unknown, never good.

## Cache

`FetchCacheMode.Http` is RFC 9111 for a GET: a stored 200 is fresh while `age + time since stored < lifetime`, with the lifetime from `max-age`, else `Expires` minus `Date`, else a tenth of the time since `Last-Modified` (at most a day), else `FetchOptions.DefaultFreshness` (zero: always ask). `Age` and an old `Date` count towards the age. `no-store` is not stored, `no-cache` and `max-age=0` are stored but always revalidated, a private cache ignores `s-maxage`. A stale entry with an `ETag` or `Last-Modified` is revalidated with `If-None-Match` / `If-Modified-Since`; a 304 renews it. `FetchCacheMode.Content` keys on method, URL and a hash of the body (OCSP over POST) and ignores HTTP freshness: the entry is reused exactly while `FetchRequest.IsReusable` accepts the stored body. Only 200 responses are stored; the default store holds at most 64 MiB and 1024 entries and evicts the oldest first.

HTTP freshness uses `FetchOptions.Time` (default the system clock; a test passes its own). The content's own validity is judged at the instant the caller gives, never the wall clock:

- **CRL:** reused only if `thisUpdate` is not after the reference time and `nextUpdate` is not before it. When the server cannot be reached, a stored CRL that is still current at the reference time is used and the result is marked `Stale`; one that has expired is not.
- **OCSP:** reused only if the stored response has a single response for the same CertID with `thisUpdate` not after and `nextUpdate` (or `thisUpdate` plus seven days when absent) not before the reference time. A request that carries a nonce is never cached.
- **Issuer certificates:** plain HTTP caching.

## Clients

**Time-stamps (RFC 3161 §3.4, RFC 5816).** `TsaClient.StampAsync` hashes the data (SHA-256, SHA-384 or SHA-512), sends a request with a fresh random nonce (disable with `UseNonce`) and `certReq`, POSTs it as `application/timestamp-query`, and checks the reply with `TimeStampVerifier.Verify` against that very request: status, token structure, signature, message imprint, nonce, requested policy and the `CryptoPolicy`; with trust anchors given, the authority's certificate chain at the token's genTime. A reply with another `Content-Type` is accepted and reported in `ContentTypeMatched`: the DER decides. Outcomes: `Granted`, `Rejected` (the authority's status and failure info), `InvalidToken` (the failed rule is in the reason), `MalformedResponse`, `FetchFailed`. A fixed `Nonce` option exists only so a recorded exchange can be replayed.

**OCSP (RFC 6960 Appendix A, RFC 5019).** `OcspClient.QueryAsync` builds the request with core's builder (CertID hash SHA-1 unless told otherwise, which every responder must accept). `Auto` uses GET (the Base64 request, percent-encoded, after the responder URL and a slash) when the request is at most 255 bytes and has no nonce, and repeats a failed GET as a POST; `Post` sends `application/ocsp-request`. The nonce (RFC 8954) is optional: a different nonce is `NonceMismatch`, a missing one is accepted unless `RequireNonce`. Outcomes: `Answered` (the single response for the certificate is in `Answer`), `ResponderError` (with the RFC 6960 §2.3 status), `FetchFailed`, `MalformedResponse`, `UnsupportedResponseType`, `CertIdMismatch`, `NonceMismatch`, `NoResponder`. The client does not verify the response signature or decide who may sign; give `Basic` to the validator, which does.

**CRLs (RFC 5280 §4.2.1.13, §5.2.6).** `CrlClient.FetchForAsync` follows the HTTP(S) distribution points of a certificate, then the `freshestCRL` locations of the certificate and of each complete CRL it fetched, for delta CRLs. LDAP and FTP locations are skipped with `SchemeNotSupported`. DER and PEM are accepted. Each result says whether the CRL is `Current`, `NotYetValid`, `Expired` or has `NoNextUpdate` at the reference time; the signature is the validator's to check.

**Issuer certificates (RFC 5280 §4.2.2.1).** `AiaClient` reads a single DER certificate, PEM certificates, or a certs-only CMS `SignedData` (the form served as `application/pkcs7-mime`), at most 32 certificates per response and 4 locations per certificate by default. `OnlineCertificateSource` keeps only candidates whose subject is the certificate's issuer name.

## The validator's sources

`OnlineRevocationSource` implements `IRevocationSource` and `OnlineCertificateSource` implements `ICertificateSource`; pass them in `ValidationOptions` and call `PathValidator.ValidateAsync`. Core's interfaces are unchanged. The revocation source gets no clock from the validator, so give it the validation's reference time (`OnlineRevocationOptions.ReferenceTime`) for the cache decisions; null uses the fetcher's clock. `OcspThenCrl` (default) asks OCSP first and falls back to the CRLs when OCSP gave no usable answer (a failed fetch, an error status, or the status "unknown"); `CrlThenOcsp` and `Both` are the other orders. Every request carries the address guard. Failures are not exceptions: the validator finds no data and reports the certificate's revocation as unknown, and `Attempts` lists each location tried, whether it worked and why not. Offline, or with every fetch failing, revocation is therefore unknown and never good.

## Record and replay

`RecordingTransport` wraps a real transport and keeps method, URL, a SHA-256 of the request body, status, response headers and body (request headers are not kept); `ExchangeLog.ToJson` writes them as indented JSON with Base64 bodies, and `ExchangeLog.Parse` reads them (source-generated JSON, no reflection). `ReplayTransport` serves them back and fails any other request with `TransportFailure.NoRecording`; `MatchBody = false` ignores the request body for requests with a fresh nonce. The replay transport uses no operating-system API, so the same fixtures run in a native test, a NativeAOT app and a browser. Recorded public exchanges live in `testdata/online/` with a manifest; the live tests that produced them run only with `ONECRYPTO_ONLINE_LIVE=1` and are never part of CI.

## Checks

- Unit tests in `tests/OneCrypto.Online.Tests`: every blocked range and notation, the fetcher's limits, a real-socket suite for the default transport (blocked loopback, a name resolving to a private address, a mixed answer, a rebinding resolver, redirects to private addresses, size, timeout and truncation), the cache rules with a test clock, each client against a CA, responder and authority built with core, and the validator integration (completed chain, revoked leaf through OCSP and CRL, unreachable responder, hostile addresses in a certificate).
- Replay of a recorded real chain with OCSP and CRL, and recorded replies from public authorities.
- OpenSSL as a black box, in both directions, over HTTP on the loopback interface: `openssl ocsp -port` answering our client (GET, POST, nonce), `openssl ts -reply` behind a small HTTP shim answering our client, and `openssl ocsp -url` and `openssl ts -verify` checking our responder and authority handlers served by a test host.
- A fuzz target (`online`) for the response handling: statuses, header blocks, lying or cut-short lengths, failing streams, the fetcher with its cache, each client's interpretation of what it returns, and the Cache-Control, HTTP-date and exchange-file parsers.
- The NativeAOT smoke app replays a fetch through the fetcher, the cache and the guard.
