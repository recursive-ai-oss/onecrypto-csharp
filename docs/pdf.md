# PDF signatures: PAdES signing, augmentation and verification

`RecursiveAI.OneCrypto.Pdf` builds on OnePDF's public API (`RecursiveAI.OnePdf` 1.17.1) and the core package. It adds PAdES baseline signing from B-B to B-LTA with OneCrypto keys, augmentation of existing signed files, and a verifier that judges each signature with OneCrypto's CMS verifier, RFC 3161 verifier and path validator. It depends on the core package and OnePDF only: no network code. Time-stamp authorities and revocation sources are functions and interfaces the caller passes in (the `.Online` package's clients plug in there).

Normative references: ETSI EN 319 142-1 V1.1.1 (PAdES baseline), ISO 32000-1/-2 §12.8 (signatures, document time-stamps), RFC 5652, RFC 3161, RFC 5035/5816 (ESS signing certificate), RFC 5280 §6.

## Signing

```csharp
using var doc = PdfDocument.Open(bytes, new PdfOpenOptions { AllowEditing = true });
doc.SignPades(output, key, certificate, chain, new PadesSignOptions { Level = PadesLevel.LongTermArchive, Timestamp = tsa, ValidationData = data });
```

To reach B-LTA with revocation data that exists only after the time-stamp (the normal case), sign and archive in one call:

```csharp
using var doc = PdfDocument.Open(bytes, new PdfOpenOptions { AllowEditing = true });
var tsa = new TsaClient(new Fetcher(new HttpTransport()), new Uri("https://tsa.example.test/"));   // RecursiveAI.OneCrypto.Online
var afterTimestamp = new PadesValidationData { TrustAnchors = anchors, Intermediates = intermediates, ReferenceTime = now, RevocationSource = revocationSource };
doc.SignPadesArchive(output, key, certificate, chain, new PadesSignOptions { Timestamp = tsa.GetTimestampAsync }, afterTimestamp);
```

`Timestamp = tsa.GetTimestampAsync` is the `.Online` client's method, which has the shape of `PadesTimestampFunction` (docs/online.md); the bridge never references the network package. `PadesSigner.Sign` / `SignAsync` do the same as the first snippet. OnePDF writes the field, the byte range and an empty `/Contents` hole (`AddSignaturePlaceholder`); core then builds the CMS over the bytes outside the hole (content type, message digest and ESS signing-certificate-v2 as signed attributes; no signing time; sub-filter `ETSI.CAdES.detached`: EN 319 142-1 §6.3) and the key signs it. Any `ISigningKey` works (software, operating-system, PKCS #11, a remote service).

| Level | What is added | Where |
|---|---|---|
| B-B | the signature | one incremental update |
| B-T | a signature time-stamp over the signature value (RFC 3161), from the caller's `PadesTimestampFunction` | inside the signature, in the reserved `/Contents` space |
| B-LT | the document security store: certificates, CRLs and OCSP responses for the signer's chain and the time-stamp authority's | one incremental update |
| B-LTA | a document time-stamp over the whole file, made after the store | one incremental update |

* **Keys.** RSA (PKCS #1 v1.5 or RSASSA-PSS), ECDSA (P-256, P-384, P-521), Ed25519, Ed448 and ML-DSA. RSA and ECDSA sign a digest of the signed attributes in the hash `PadesSignOptions.Hash` names; Ed25519 uses SHA-512, Ed448 SHAKE256 with a 512-bit output, ML-DSA SHA-512 (RFC 8419 §3.1, RFC 9882). Which readers accept which: ISO/TS 32002 puts Ed25519 and Ed448 in PDF 2.0, so a reader that implements it can verify them and older readers report the signature as unverifiable; ML-DSA in PDF is not standardised and is **preview** (the BCL's ML-DSA, as in core), so expect no reader to verify it yet. RSA and ECDSA signatures are what every reader checks. Acrobat's behaviour with Ed25519 is recorded with the sample set (owner run, see the manifest).
* **Who gives the verdict.** OnePDF reports EdDSA and ML-DSA signatures as not checked. For those, `PadesVerifier` verifies the CMS signature itself, and the `onepdf` check in the report is a warning saying so; the verdict is the bridge's, not OnePDF's. For RSA and ECDSA both must agree, as before.
* **Policy.** `PadesSignOptions.Policy` (default `CryptoPolicy.Standard`) is asked about the signature hash and key as new data before anything is written: SHA-1 and RSA under 2048 bits raise `PolicyViolationException`.
* **Reserve.** The signature reserves 12 KiB for `/Contents` unless `Pdf.ContentsReserve` says otherwise: enough to time-stamp a B-B signature later (an RSA time-stamp authority with a two-certificate chain needs about 4.3 KiB of CMS).
* **Sources are the caller's.** `PadesValidationData` carries trust anchors, an intermediate pool, `RevocationData` the caller holds, and optional `IRevocationSource` / `ICertificateSource`. Nothing is fetched unless a source does it. `ReferenceTime` is required: the bridge reads no clock. (`PdfSigningOptions.SigningTime` and the time-stamp function decide the written time; with neither, OnePDF writes its own `/M`.)
* **Store contents** (EN 319 142-1 §6.3 (r), (t), (x)): every certificate of the signer's and each time-stamp authority's path, the trust anchor certificate included (`IncludeAnchors`, default true), and revocation data that applies to a certificate on those paths. The data for every earlier document time-stamp's authority is collected too, so calling the augmenter on a B-LTA file renews the archive time-stamp. A DSS update keeps the previous entries (§5.4.2.2). `/VRI` entries are off by default (`WriteVri`; §6.3 (v): "should not be used"); when written they are keyed by the SHA-1 of the DER signature (§5.4.2.2) with `/TU`. The verifier finds a VRI entry under the hash of the DER structure or of the whole padded string, because the clause words it loosely. The catalog gets the `ESIC` extension (level 2 with `ETSI.CAdES.detached`, §5.6) on files below PDF 2.0.
* **Augmentation.** `PadesAugmenter.AugmentAsync(pdf, options)` raises every signature in a file: it writes a signature time-stamp into a signature that lacks one (into its reserved `/Contents` space, which no byte range covers; the CMS is re-encoded only by adding the unsigned attribute, `PadesError.NoRoom` if it does not fit), appends the store, appends a document time-stamp. Steps with nothing to do are skipped. Level `LongTermArchive` always appends a new document time-stamp; on a B-LTA file that is the archive time-stamp renewal.
* **Getting to B-LTA.** Revocation data can show that a certificate was good at the time-stamp only if it was issued at or after that time (EN 319 102-1 §5.6.2.1). A one-step `PadesLevel.LongTermArchive` signature collects its data before the signature time-stamp exists, so the CRLs and OCSP responses it can carry predate the time-stamp. The file is then valid only as far as B-T, and revocation at the time-stamp stays unknown. That is correct, not a defect. The way to B-LTA is to time-stamp first and collect afterwards: `SignPadesArchive` (and `SignPadesArchiveAsync`, `PadesSigner.SignArchive`) signs at B-T and then augments with the `PadesValidationData` you pass for *after* the time-stamp, whose `RevocationSource` is asked then and whose `ReferenceTime` is at or after the time-stamp, so the data is issued afterwards. The verifier judges the authority's certificate for the signature time-stamp in the past-time model against the later document time-stamp that covers the store.
* **Async.** The signature itself involves no callback. OnePDF writes the document time-stamp synchronously and calls the time-stamp function from inside, so that step runs OnePDF on a thread-pool thread and waits for the function there; the synchronous overloads block the caller on it.

## Verification

```csharp
PadesReport report = doc.VerifyPades(new PadesVerifyOptions { TrustAnchors = [...], ReferenceTime = now });
```

`PadesVerifier.Verify(pdf, options)` opens the file itself. The extension and `Verify(document, …)` take no bytes: they read the document's original bytes through `PdfDocument.OpenRead()` (the file as opened, never in-memory edits), because the bridge reads the `/Contents` string, the store and the revision layout from the file itself. If the file changed on disk after the document was opened, they throw `PadesException` with `PadesError.SourceChanged` (the inner exception is OnePDF's `PdfSourceChangedException`); open the file again. The bytes a signature covers are read through `PdfSignature.OpenSignedData()` (null when the byte range is unusable; `signature.OpenSignedDataOrThrow()` raises `PadesException` with `PadesError.NotPresent` instead and `TryOpenSignedData` is the `Try` form), so the digest is over exactly the ranges OnePDF's model describes. Bad input is reported: unreadable files, missing catalogs, malformed stores and tokens give warnings and failed checks, never exceptions (`bridge-error` is a failed check that means a bug; the fuzz target treats it as a finding).

A time-stamp's `Report` is null when its value did not parse as a token: `RequireReport()` and `RequireToken()` on `PadesTimestamp` (and `RequireToken()` on core's `TimeStampReport`) return the non-null value or raise a typed error, and `TryGetReport` is the `Try` form, so straight-line code needs no null checks.

Per signature, `PadesSignatureReport` holds OnePDF's own `PdfSignatureVerification` untouched (`OnePdf`), the bridge's `Checks` (rule, status, reason, clause), the core `SignedDataReport` (`Cms`), the path validator's `ValidationReport` (`Chain`), the time-stamps, `ProofOfExistence`, `ValidationTime`, the PAdES `Level` and `IsValid`.

* **The verdict is both.** `IsValid` is true only when OnePDF's verdict is valid and no bridge check failed or went undecided. The bridge adds rules and never removes one. The test corpus (below) checks both directions on every OnePDF attack.
* **Rules** (names as in `Checks`): `byte-range` (the hole holds `/Contents`, ISO 32000-2 §12.8.1), `contents` (the model's `/Contents` equals the file's), `cms`, `single-signer` (exactly one SignerInfo; the seed verifier looked only at the first), `detached`, `cms-signature` and the failing `cms-*` rules of the core verifier (message digest, signature, key usage, ESS signing-certificate, algorithm policy at the validation time), `signature-timestamp`, `proof-of-existence`, `chain`, `level`, `onepdf`. A document time-stamp has `byte-range`, `subfilter`, `timestamp`, `timestamp-trust`.
* **Time.** A signature is judged at the earliest instant a *trusted* time-stamp proves it existed: its own signature time-stamp, or a document time-stamp made after it (§6.3 (n): either gives B-T). Trusted means every RFC 3161 rule passed (`docs/tsp.md`) and the authority chains to a given anchor as of `genTime`. Without one, at `ReferenceTime`. The signing time in the file is a claim and is never used. A time-stamp dated after the reference time is ignored and reported.
* **Revocation.** Data comes from the signature (CRLs), the store, the signature's VRI entry and `Revocation` in the options. A chain with no data reports revocation `Unknown` and the `chain` check is a warning, never "good"; `RevocationRequired` makes unknown fatal (verdict undecided). With a proven time the validator runs in the past-time model (`docs/validation.md`): a certificate revoked after the proven time for a reason other than compromise is good then. Freshness is judged as of the earliest trusted document time-stamp that covers all stored data (it proves the data existed then); without one, as of the newest issue time among the data, because when it was collected is not proven. `RevocationDataTime` overrides.
* **Level.** B-B: a CAdES signature that is valid with the ESS signing certificate. B-T: and a trusted time-stamp. B-LT: and the signer's chain has revocation status "good" from data the file carries (store, VRI or signature, computed apart from the caller's extra data) and the authority's chain is trusted with good status. B-LTA: and a trusted document time-stamp made after all stored data covers it. An invalid signature has level `None`.
* **Room for more.** Reports are classes with internal constructors, so the EN 319 102-1 process and TS 119 102-2 reports of the AdES package can be added as properties without breaking callers.

## Limits

A store array is read to 2,048 items and each item to 8 MiB decoded; a VRI dictionary to 2,048 entries; excess is ignored with a warning. Validation limits are the validator's (`PadesVerifyOptions.Limits`). OnePDF's own limits apply to parsing.

## Signing in two steps

`PadesTwoPhase.Prepare` writes the file with an empty signature hole and returns a `PadesPendingSignature`: field name, hole offsets, the digest of the two ranges and core's prepared CMS (`PreparedSignedData`). `Encode()` serialises it to DER (purpose `pades.pdf.signature`; it holds no secret). Any time later, in any process, `PadesTwoPhase.Complete(file, pending, key)` checks that the file still hashes to the recorded digest, signs `pending.ToSign` with the key (or takes a signature made elsewhere), checks the signature against the recorded public key, and fills the hole through `PdfSignatureHole.Fill`. Raise the result with `PadesAugmenter`.

```csharp
// process A: no key needed
using var doc = PdfDocument.Open(bytes, new PdfOpenOptions { AllowEditing = true });
using var file = File.Create("contract.pdf");
PadesPendingSignature pending = PadesTwoPhase.Prepare(doc, file, certificate, chain, at: DateTimeOffset.UtcNow);
File.WriteAllBytes("contract.pending", pending.Encode());

// process B: the key lives here
var state = PadesPendingSignature.Decode(File.ReadAllBytes("contract.pending"));
PadesTwoPhase.Complete("contract.pdf", state, key);
```

The same flow with a digest you computed yourself (the shape of the OnePDF external-signature recipe, where .NET's `SignedCms` cannot sign a precomputed digest):

```csharp
PdfSignaturePlaceholder hole = doc.AddSignaturePlaceholder(output, new PdfSigningOptions { SubFilter = "ETSI.CAdES.detached" }, contentsReserve: 16 << 10);
var signer = new CmsSignerSpec { Certificate = certificate, Key = key };
string digestOid = SignedData.DigestAlgorithmFor(signer);                 // SHA-256 for RSA/P-256, SHA-512 for Ed25519, SHAKE256 for Ed448
byte[] digest = SignedData.HashContent(digestOid, ranges);                // a stream over the two byte ranges
SignedData cms = SignedData.CreateDetachedFromDigest(digest, digestOid, [signer], new SignedDataOptions { Certificates = chain });
hole.Fill(output, cms.Encoded.Span);
```

The digest algorithm can also be named as a `HashAlgorithmName` (`SignedData.HashAlgorithmFor(signer)`, then `CreateDetachedFromDigest(digest, hash, ...)`; `DigestNames` maps both ways), and a mismatch is a `DigestMismatchException` naming both algorithms. `SignedData.PrepareDetachedFromDigest` is the two-step form of the same call; `CreateDetachedFromDigest` without a key points there. If the reserve is too small, `Fill` throws `PdfSigningException` (`ContentsTooSmall`) with the size needed and writes nothing; a wrong offset or an already-filled hole is `BadHole`.

The seams OnePDF 1.16.0 added (`AddSignaturePlaceholder`, `PdfSignatureHole`, `PdfSignature.OpenSignedData()`, the catalog fall-back in `TryOpen`) closed the first gaps, and 1.17 added `PdfDocument.OpenRead()`, which removed the last: verification no longer needs the bytes passed in.

## Signing errors and certified documents

OnePDF's typed signing errors pass through unchanged as `PdfSigningException` (read `Reason`); the bridge adds none of its own for them. A document with an empty page tree gives `PdfSigningError.NoPage` from signing and from the placeholder; a page index outside a document that has pages is an `ArgumentOutOfRangeException`. A document certified with DocMDP P=1 (`PdfCertificationLevel.NoChanges`) refuses another signature with `PdfSigningError.CertificationForbidsChanges` unless `PadesSignOptions.Pdf.AllowBreakingCertification` is set, and then any viewer reports the certification as broken. P=2 and P=3 take further signatures. Augmentation (signature and document time-stamps, the store) is allowed under P=1 (ISO 32000-2 Table 257), and a document time-stamp's own update does not break the certification.


## Tests

`tests/OneCrypto.Pdf.Tests`: round trips for RSA (PKCS #1, PSS), P-256 and P-384 at every level, re-verified by the bridge and by OnePDF; augmentation B-B → B-T → B-LT → B-LTA and renewal; the past-time model (a certificate that expired after signing); revocation (revoked before and after the proven time); hostile stores; `openssl cms -verify` on each signature's CMS and `openssl ts -verify` on every signature and document time-stamp; OnePDF's signature attack corpus (`AttackCorpus/`: `AttackTests`, `SignatureModificationTests` and the builders, lifted from OnePDF; every verification they make is repeated through the bridge and a signature OnePDF rejects must be rejected by the bridge); a corpus run over real signed files (`ONECRYPTO_PDF_CORPUS`); a mutation smoke over the fuzz target's body. Two-step signing across two processes (`PadesTwoPhaseTests`); the hole on encrypted files, on files that already carry two signatures, and on certified files (`PlaceholderIntegrationTests`); EdDSA and ML-DSA round trips at every level, checked by `openssl cms -verify`. Fuzz targets `pades` and `placeholder` (`fuzz/README.md`).
