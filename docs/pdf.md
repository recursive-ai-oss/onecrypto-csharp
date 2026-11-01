# PDF signatures: PAdES signing, augmentation and verification

`RecursiveAI.OneCrypto.Pdf` builds on OnePDF's public API (`RecursiveAI.OnePdf` 1.15.1) and the core package. It adds PAdES baseline signing from B-B to B-LTA with OneCrypto keys, augmentation of existing signed files, and a verifier that judges each signature with OneCrypto's CMS verifier, RFC 3161 verifier and path validator. It depends on the core package and OnePDF only: no network code. Time-stamp authorities and revocation sources are functions and interfaces the caller passes in (the `.Online` package's clients plug in there).

Normative references: ETSI EN 319 142-1 V1.1.1 (PAdES baseline), ISO 32000-1/-2 §12.8 (signatures, document time-stamps), RFC 5652, RFC 3161, RFC 5035/5816 (ESS signing certificate), RFC 5280 §6.

## Signing

```csharp
using var doc = PdfDocument.Open(bytes, new PdfOpenOptions { AllowEditing = true });
doc.SignPades(output, key, certificate, chain, new PadesSignOptions { Level = PadesLevel.LongTermArchive, Timestamp = tsa, ValidationData = data });
```

`PadesSigner.Sign` / `SignAsync` do the same. OnePDF writes the field, the byte range and the CMS (content type, message digest and ESS signing-certificate-v2 as signed attributes; no signing time; sub-filter `ETSI.CAdES.detached`: EN 319 142-1 §6.3). The key signs the digest of the DER signed attributes through OnePDF's external-signer seam, so any `ISigningKey` works (software, operating-system, PKCS #11, a remote service).

| Level | What is added | Where |
|---|---|---|
| B-B | the signature | one incremental update |
| B-T | a signature time-stamp over the signature value (RFC 3161), from the caller's `PadesTimestampFunction` | inside the signature (OnePDF calls the function) |
| B-LT | the document security store: certificates, CRLs and OCSP responses for the signer's chain and the time-stamp authority's | one incremental update |
| B-LTA | a document time-stamp over the whole file, made after the store | one incremental update |

* **Keys.** RSA (PKCS #1 v1.5 or RSASSA-PSS) and ECDSA (P-256, P-384, P-521). **EdDSA and ML-DSA keys are refused** (`PadesError.UnsupportedKey`): OnePDF's seam hands over a digest of the signed attributes and takes an RSA or ECDSA signature value; those schemes sign the attributes themselves. PDF readers' support for them is a separate question; the seam is the limit here. Two-phase signing across processes needs the prepare/complete seam listed under "What OnePDF would need to offer".
* **Policy.** `PadesSignOptions.Policy` (default `CryptoPolicy.Standard`) is asked about the signature hash and key as new data before anything is written: SHA-1 and RSA under 2048 bits raise `PolicyViolationException`.
* **Reserve.** The signature reserves 12 KiB for `/Contents` unless `Pdf.ContentsReserve` says otherwise: enough to time-stamp a B-B signature later (an RSA time-stamp authority with a two-certificate chain needs about 4.3 KiB of CMS).
* **Sources are the caller's.** `PadesValidationData` carries trust anchors, an intermediate pool, `RevocationData` the caller holds, and optional `IRevocationSource` / `ICertificateSource`. Nothing is fetched unless a source does it. `ReferenceTime` is required: the bridge reads no clock. (`PdfSigningOptions.SigningTime` and the time-stamp function decide the written time; with neither, OnePDF writes its own `/M`.)
* **Store contents** (EN 319 142-1 §6.3 (r), (t), (x)): every certificate of the signer's and each time-stamp authority's path, the trust anchor certificate included (`IncludeAnchors`, default true), and revocation data that applies to a certificate on those paths. The data for every earlier document time-stamp's authority is collected too, so calling the augmenter on a B-LTA file renews the archive time-stamp. A DSS update keeps the previous entries (§5.4.2.2). `/VRI` entries are off by default (`WriteVri`; §6.3 (v): "should not be used"); when written they are keyed by the SHA-1 of the DER signature (§5.4.2.2) with `/TU`. The verifier finds a VRI entry under the hash of the DER structure or of the whole padded string, because the clause words it loosely. The catalog gets the `ESIC` extension (level 2 with `ETSI.CAdES.detached`, §5.6) on files below PDF 2.0.
* **Augmentation.** `PadesAugmenter.AugmentAsync(pdf, options)` raises every signature in a file: it writes a signature time-stamp into a signature that lacks one (into its reserved `/Contents` space, which no byte range covers; the CMS is re-encoded only by adding the unsigned attribute, `PadesError.NoRoom` if it does not fit), appends the store, appends a document time-stamp. Steps with nothing to do are skipped. Level `LongTermArchive` always appends a new document time-stamp; on a B-LTA file that is the archive time-stamp renewal.
* **Async.** OnePDF signs synchronously and calls the time-stamp function from inside, so `SignAsync` and the document time-stamp step run OnePDF on a thread-pool thread and wait for the function there. The synchronous overloads block the caller on it.

## Verification

```csharp
PadesReport report = doc.VerifyPades(bytes, new PadesVerifyOptions { TrustAnchors = [...], ReferenceTime = now });
```

`PadesVerifier.Verify(pdf, options)` opens the file itself. The extension and `Verify(document, pdf, …)` take the bytes the document was opened from, because OnePDF's model does not expose them. Bad input is reported: unreadable files, missing catalogs, malformed stores and tokens give warnings and failed checks, never exceptions (`bridge-error` is a failed check that means a bug; the fuzz target treats it as a finding).

Per signature, `PadesSignatureReport` holds OnePDF's own `PdfSignatureVerification` untouched (`OnePdf`), the bridge's `Checks` (rule, status, reason, clause), the core `SignedDataReport` (`Cms`), the path validator's `ValidationReport` (`Chain`), the time-stamps, `ProofOfExistence`, `ValidationTime`, the PAdES `Level` and `IsValid`.

* **The verdict is both.** `IsValid` is true only when OnePDF's verdict is valid and no bridge check failed or went undecided. The bridge adds rules and never removes one. The test corpus (below) checks both directions on every OnePDF attack.
* **Rules** (names as in `Checks`): `byte-range` (the hole holds `/Contents`, ISO 32000-2 §12.8.1), `contents` (the model's `/Contents` equals the file's), `cms`, `single-signer` (exactly one SignerInfo; the seed verifier looked only at the first), `detached`, `cms-signature` and the failing `cms-*` rules of the core verifier (message digest, signature, key usage, ESS signing-certificate, algorithm policy at the validation time), `signature-timestamp`, `proof-of-existence`, `chain`, `level`, `onepdf`. A document time-stamp has `byte-range`, `subfilter`, `timestamp`, `timestamp-trust`.
* **Time.** A signature is judged at the earliest instant a *trusted* time-stamp proves it existed: its own signature time-stamp, or a document time-stamp made after it (§6.3 (n): either gives B-T). Trusted means every RFC 3161 rule passed (`docs/tsp.md`) and the authority chains to a given anchor as of `genTime`. Without one, at `ReferenceTime`. The signing time in the file is a claim and is never used. A time-stamp dated after the reference time is ignored and reported.
* **Revocation.** Data comes from the signature (CRLs), the store, the signature's VRI entry and `Revocation` in the options. A chain with no data reports revocation `Unknown` and the `chain` check is a warning, never "good"; `RevocationRequired` makes unknown fatal (verdict undecided). With a proven time the validator runs in the past-time model (`docs/validation.md`): a certificate revoked after the proven time for a reason other than compromise is good then. Freshness is judged as of the earliest trusted document time-stamp that covers all stored data (it proves the data existed then); without one, as of the newest issue time among the data, because when it was collected is not proven. `RevocationDataTime` overrides.
* **Level.** B-B: a CAdES signature that is valid with the ESS signing certificate. B-T: and a trusted time-stamp. B-LT: and the signer's chain has revocation status "good" from data the file carries (store, VRI or signature, computed apart from the caller's extra data) and the authority's chain is trusted with good status. B-LTA: and a trusted document time-stamp made after all stored data covers it. An invalid signature has level `None`.
* **Room for more.** Reports are classes with internal constructors, so the EN 319 102-1 process and TS 119 102-2 reports of the AdES package can be added as properties without breaking callers.

## Limits

A store array is read to 2,048 items and each item to 8 MiB decoded; a VRI dictionary to 2,048 entries; excess is ignored with a warning. Validation limits are the validator's (`PadesVerifyOptions.Limits`). OnePDF's own limits apply to parsing.

## What OnePDF would need to offer

The bridge uses only OnePDF's public API. Two things would remove its remaining limits:

1. **A prepare/complete signing seam.** OnePDF builds the CMS itself, so the bridge cannot embed a SignerInfo built by core, sign with Ed25519, Ed448 or ML-DSA, or run the two-phase signing of `docs/keys.md` across processes. The smallest API: `PdfDocument.AddSignaturePlaceholder(Stream output, PdfSigningOptions? options, int contentsReserve)` that writes the incremental update with the byte range filled and `/Contents` an empty reserved string, and returns the field name and the hole's start and end offsets. The caller hashes the two ranges, builds the CMS (core's `SignedData.Prepare` / `Complete`) and writes its hex into the hole. The document time-stamp could use the same call.
2. **The signed bytes.** `PdfSignature` or `PdfDocument` could expose the file bytes (or a `Stream` over a signature's two ranges), so `VerifyPades` need not be given the bytes.

`PdfDocument.GetSignatures()` throws `PdfFormatException` ("The document has no catalog") for a file that `TryOpen` accepted but whose catalog is lost; the bridge catches it and reports no signatures.

## Tests

`tests/OneCrypto.Pdf.Tests`: round trips for RSA (PKCS #1, PSS), P-256 and P-384 at every level, re-verified by the bridge and by OnePDF; augmentation B-B → B-T → B-LT → B-LTA and renewal; the past-time model (a certificate that expired after signing); revocation (revoked before and after the proven time); hostile stores; `openssl cms -verify` on each signature's CMS and `openssl ts -verify` on every signature and document time-stamp; OnePDF's signature attack corpus (`AttackCorpus/`: `AttackTests`, `SignatureModificationTests` and the builders, lifted from OnePDF; every verification they make is repeated through the bridge and a signature OnePDF rejects must be rejected by the bridge); a corpus run over real signed files (`ONECRYPTO_PDF_CORPUS`); a mutation smoke over the fuzz target's body. Fuzz target `pades` (`fuzz/README.md`).
