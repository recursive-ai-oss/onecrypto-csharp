# Timing tests

Constant-time evidence for secret-handling code, in the style of Reparaz, Balasch and Verbauwhede, "Dude, is my code constant
time?" (DATE 2017). Project: `tests/Timing`. Runner: `tools/timing.sh`.

## Method

- Two input classes: a fixed secret and a fresh random secret per call (key-secret targets: see "Key-secret targets"). The class sequence is drawn from the CSPRNG before
  the run, so calls interleave at random.
- Each call is timed with `Stopwatch.GetTimestamp`. Inputs are prepared in batches outside the timed region; the timed region
  allocates nothing. A warm-up of at least half a second runs first so tiered compilation has settled; the runner also sets
  `DOTNET_TieredCompilation=0`, `DOTNET_TieredPGO=0` and `DOTNET_ReadyToRun=0` for full-opt JIT.
- The analysis runs Welch's t-test on the raw data and on 100 percentile crops (the k-th keeps the fastest
  1 − 0.5^(10(k+1)/100) of the calls), and reports the largest |t| and which crop gave it.
- Verdict: max |t| < 4.5 passes; anything else is reported as a leak.
- Presets: `short` (200 000 calls) for gating merges, `full` (5 000 000) for milestones, `--n` to choose.
- Timing runs are meaningless on a loaded machine. Publishable runs are exclusive benchmark jobs (`PERF_CLASS=bench`); day-to-day runs are indicative heavy jobs.
  `tools/perf-run.sh` also records CPU, cores and load before, during and after.

## Writing a target

Add a file under `tests/Timing/` with a static method returning your targets, and add it to the list in `Targets.cs`.
For one secret byte string going into one call:

```csharp
TimingTarget.FromBytes("X25519", "scalar-multiply", 32, secret => s_sink ^= Run(secret));
```

For anything with more structure, subclass `TimingTarget`: `Prepare` builds the inputs for a batch from the class sequence
(fixed secret or fresh random one), `Run(i)` is the timed call and must not allocate. Keep the result in a field so the JIT
cannot remove the call.

## Self-check

`timing selfcheck` runs an early-exit byte compare (must be flagged) and `CryptographicOperations.FixedTimeEquals` (must
pass). It is the proof that the harness sees leaks on the machine it runs on.

## Results and publishable runs

`tools/timing.sh <outdir> …` writes `timing.json`, `machine.txt`, `load.log` and `publishable.txt` under `<outdir>` (relative
to the repository root). A run is marked `publishable: NO` when it was not class `bench`, or when the 1-minute load average before or during it exceeds 2.0
(Linux) or 1.5 (macOS); set `PERF_MAX_LOAD` to change the limit. Only publishable runs count as evidence.

## Key-secret targets

When the secret is a key, the cost of building the key object (schedule, tables, pinned buffers) is not what is under test, but
the object's memory is what the operation reads. A first design kept a pool of 128 objects holding the fixed key and 128 holding
distinct random keys, and drew from them. It could not be made reliable: the A/A control flagged on x64, and on Apple M2
the Camellia and AES-KW key kinds flagged at |t| 8 to 15 (mean difference about 0.1 percent) while their controls passed.
Pool objects of one class differ from the other in more than the key (identical schedules in 128 places against 128 different
ones, placement, cache footprint), so a flag could not be attributed to the key.

The current design keeps everything but the key value equal:

- **One fresh key object per call, built in an untimed hook.** `TimingTarget.Before(i)` runs right before each timed `Run(i)`.
  A key target disposes the previous object, fills one reusable key buffer, builds a new object from it (and, for the AEADs and
  AES-KW, the message under that key), and `Run` only decrypts, encrypts or unwraps. Both classes therefore allocate the same
  objects in the same pattern, run the same constructor, and time a call on an object that was built a moment ago.
- **The class selects the key bytes with a mask, not a branch.** `FillKey` draws fresh random bytes for every call and then
  blends the fixed key over them with an all-ones or all-zero byte mask. Both classes execute the same instructions and branch
  history before the timed call. An earlier version copied the fixed key with an `if` for the fixed class only; with that,
  Twofish-128 decrypt-key on Apple M2 flagged in three of four runs (|t| 3.2 to 6.3; the sign of the mean difference changed
  with each run's fixed key) while its control stayed at or below 2.9, and the flags were gone once the branch became a mask.
- **An A/A control per key target.** The control uses the same code with the mask forced to zero, so both classes are fresh
  random keys. A key kind counts only if its control passes; a flagging control means the host, not the code, and the run is
  repeated.
- ChaCha20-Poly1305 uses the same hook and mask (one reusable key buffer). The curves take a fresh random scalar or seed per call
  in the random class and have no object to rebuild, so they have no control.

`tools/timing-keys.sh <outdir> [N]` runs the key-secret targets. `TIMING_ONLY=key` keeps only the key-related operations;
`TIMING_PRIMITIVES` chooses primitives, or `Primitive/operation` entries. Blowfish builds its key object in 0.5 to 1.3 ms, so each of
its targets takes 15 to 25 minutes at N = 1,000,000 and runs as its own job.

## Results (indicative)

N = 1,000,000 calls per target, full-opt JIT, run as shared-host jobs (not exclusive), so every number is indicative. Values are the
maximum |t| over the uncropped data and 100 crops; the pass threshold is 4.5. x64: AMD Ryzen 9 7950X3D, Linux, .NET 10.0.402 (the
host was busy, load 10 to 20, during part of the runs). arm64: Apple M2, macOS, .NET 10.0.403. "Setup" is the key schedule itself,
timed, with a fixed or a random key. Every key kind and control below passes on both machines.

| Primitive / operation | x64 key | x64 control | arm64 key | arm64 control |
|---|---|---|---|---|
| Camellia-128 decrypt-key | 1.80 | 2.13 | 1.31 | 3.36 |
| Camellia-128 encrypt-key | 1.58 | 2.39 | 1.45 | 0.75 |
| Camellia-128 key-setup | 3.21 | | 1.56 | |
| Camellia-256 decrypt-key | 2.84 | 2.06 | 1.05 | 1.58 |
| Camellia-256 encrypt-key | 1.71 | 2.28 | 1.52 | 1.97 |
| Camellia-256 key-setup | 1.42 | | 1.68 | |
| CAST5 decrypt-key / key-setup | 2.13 / 1.65 | 1.33 | 2.26 / 2.75 | 1.64 |
| IDEA decrypt-key / key-setup | 1.24 / 2.25 | 1.56 | 1.22 / 1.19 | 1.60 |
| Blowfish decrypt-key / key-setup | 1.93 / 1.70 | 2.14 | 1.73 / 2.19 | 1.24 |
| Twofish-128 decrypt-key / key-setup | 2.00 / 2.23 | 1.02 | 1.47 / 2.59 | 2.02 |
| Twofish-256 decrypt-key / key-setup | 1.64 / 2.30 | 1.36 | 1.60 / 1.65 | 1.23 |
| AES-OCB decrypt-key | 1.81 | 2.61 | 2.10 | 1.53 |
| AES-EAX decrypt-key | 1.86 | 2.08 | 1.96 | 1.74 |
| AES-KW unwrap-key | 2.98 | 1.95 | 2.53 | 0.77 |
| ChaCha20-Poly1305 encrypt-key, 1000 B | 3.24 | 1.35 | 3.20 | 2.47 |
| ChaCha20-Poly1305 encrypt-key, 17 B | 2.11 | 2.76 | 1.31 | 2.69 |
| ChaCha20-Poly1305 decrypt-wrong-tag-key, 100 B | 2.09 | 0.95 | 1.80 | 1.63 |
| Ed25519 sign | 2.55 | | 2.71 | |
| Ed448 sign | 1.76 | | 2.25 | |
| X25519 scalar-multiply / base-multiply | 1.16 / 2.60 | | 2.23 / 2.96 | |
| X448 scalar-multiply / base-multiply | 1.28 / 2.50 | | 1.96 / 2.59 | |

The Blowfish key-setup and the curve rows on x64 come from builds that differ from the final one only in the key-kind hook, which
those targets do not use. Data-secret targets are untouched by this design and keep their last results (all pass).

Before and after on the signals that started this work (maximum |t|, key kind with its control in brackets):

| Signal | Pool design | Per-call object |
|---|---|---|
| Apple M2, Camellia-256 decrypt-key | 15.48 (2.24) | 1.05 (1.58) |
| Apple M2, Camellia-256 encrypt-key | 14.28 (2.24) | 1.52 (1.97) |
| Apple M2, Camellia-128 decrypt-key | 8.11 (2.32) | 1.31 (3.36) |
| Apple M2, AES-KW unwrap-key | 9.34 (1.48) | 2.53 (0.77) |
| Ryzen, Camellia-128 decrypt-key | 10.23 (8.95) | 1.80 (2.13) |
| Ryzen, Blowfish decrypt-key | 14.10 (20.59) | 1.93 (2.14) |

### What the old signals were

None of the Camellia and AES-KW signals reproduces with a fresh object per call and a masked key select. No source file under
`src/` changed for these results, so the earlier flags came from how the harness built its two classes. The pool design was not
taken apart further: which of its differences (identical schedules, placement, footprint) caused the Camellia and AES-KW flags
is not isolated. The class-dependent copy branch was isolated for Twofish-128 (above). AES-KW runs on the platform's AES and passes.

## Results: decryption paths (indicative)

N = 200,000 calls per target, full-opt JIT, x64 Ryzen 9 7950X3D, .NET 10.0.402, shared-host heavy jobs (1-minute load 10 to 24), so not publishable.

| Target | max \|t\| | Fixed / random mean | Verdict |
|---|---|---|---|
| OpenPgpSessionKey checksum-unpadded-v6-key-bytes (control) | 2.36 (2.97) | 92.9 / 92.7 ns | pass |
| OpenPgpSessionKey checksum-padded-ecdh-key-bytes (control) | 3.11 (1.58) | 135.7 / 134.9 ns | pass |
| OpenPgpSessionKey checksum-padded-ecdh-bad-padding-vs-bad-checksum | 1.77 | 130.5 / 130.3 ns | pass |
| CmsCbc cbc-bad-padding-shape (bad against good padding, D12) | 1.08 | 1321.7 / 1321.2 ns | pass |
| OpenPgpSessionKey pkesk-rsa-bad-padding-vs-bad-checksum (D1) | 40.87 | 697.5 / 708.5 us | platform residual, no claim |

The earlier x64 flags on the key-bytes targets (7.73, 6.25) came from how the harness built its classes: the fixed class was built from
identical arrays and the random class from fresh bytes behind a branch. The messages are now built by a byte-mask blend with an A/A control
for each, and both targets pass with no source change to `FromChecksummed`, which has no branch, index or early exit on the bytes.

The RSA packet target differs by 11 us in 700 us (1.5%). The RSA private-key operation is the platform's. Bad PKCS #1 padding makes the
platform's `Decrypt` throw, which our reader catches; valid padding with a wrong checksum does not throw. The difference matches the cost
of one caught exception and is in the platform's call, not in our checksum glue. Both outcomes return the same failure with the same
message; the timing difference between them is a documented residual for RSA PKCS #1 session keys and no constant-time claim is made for
that path.

## Argon2id

Argon2i is the data-independent variant and has a timing target. Argon2id has no constant-time claim as a whole: only the first two
slices of its first pass are addressed from public values, and the rest picks reference blocks from block contents (RFC 9106 §3.4),
so password-dependent timing is expected. Measured once on Apple M2 (one pass, 64 KiB): |t| 12.05. The public API cannot time the
data-independent part alone, so there is no Argon2id target. Argon2d and scrypt are data-dependent by design and have none either.
