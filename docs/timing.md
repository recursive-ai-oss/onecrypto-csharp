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
to the repository root). A run is marked `publishable: NO` when it was not class `bench`, or when, on Linux, the share of all CPUs that were busy (sampled from `/proc/stat` every 5 s, iowait counted idle) averaged more
than 8% or any one sample exceeded 15% (`PERF_MAX_BUSY`, `PERF_MAX_BUSY_SAMPLE`), or on macOS when the CPU was less than 90% idle just
before it. The load average is recorded beside each sample but does not decide: it also counts processes waiting on disk, so on a
32-thread host a quiet machine can show a load of 4 to 6. The limits leave room for the run's own thread (one busy thread of 32 is
3.1%) and a few helpers; a sample over the limit also logs the busiest processes outside the run (`others:` lines in `load.log`) so a
busy slot can be explained. Only publishable runs count as evidence.

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

## Groups for stage-close runs

`tools/timing-groups.sh run <group> <outdir> [N]` runs one group of key-secret and glue targets through the queue (an indicative heavy
job; `PERF_CLASS=bench` for a publishable exclusive run, 20 minute limit). `list` prints the groups. Every group fits a 20 minute slot
on both reference machines; N is 1,000,000 calls per target except where noted. Blowfish builds a key object in 0.5 to 1.4 ms, so its four
targets run as two independent halves of 500,000 calls each (suffix `-1`, `-2`), and both halves must pass. The RSA PKESK target is a
platform residual with no timing claim and costs 2.7 ms a call on arm64, so it runs at 300,000.

Measured wall time per group (build excluded), indicative heavy jobs on a shared host: x64 Ryzen 9 7950X3D, 1-minute load 7 to 18,
mean CPU busy 33 to 41%; arm64 Apple M2, 65 to 85% idle at start.

| Group | Members | N | x64 | arm64 |
|---|---|---|---|---|
| `small-and-glue` | Camellia-128/256, CAST5, IDEA, Twofish-128/256, AES-OCB/EAX/KW, ChaCha20-Poly1305, OpenPgpSessionKey (five checksum targets), OpenPgpSecretKeyUnlock, CmsCbc | 1M | 6.7 min | 5.2 min |
| `curves` | Ed25519, Ed448, X25519, X448 | 1M | 9.7 min | 8.5 min |
| `glue-pkesk-rsa` | OpenPgpSessionKey/pkesk-rsa (no claim) | 300k | 3.3 min | 15.6 min |
| `blowfish-dk-1`, `-2` | Blowfish decrypt-key | 500k | 4.9, 5.0 min | 11.1, 11.1 min |
| `blowfish-ck-1`, `-2` | Blowfish control-decrypt-key | 500k | 4.7, 4.8 min | 11.1, 11.1 min |
| `blowfish-ks-1`, `-2` | Blowfish key-setup | 500k | 5.0, 5.0 min | 10.8, 11.1 min |
| `blowfish-cks-1`, `-2` | Blowfish control-key-setup, decrypt-data | 500k | 5.0, 5.2 min | 11.2, 11.2 min |

The longest slot is 15.6 min (arm64, RSA PKESK). Running them all end to end takes about 64 min on x64 and 2 h 10 min on arm64.

## Twofish key setup on x64: no constant-time claim, investigation open

The 0.3-close run flagged Twofish-128 key-setup (6.79) and Twofish-256 decrypt-key (12.72) on x64; the other Twofish targets and the
controls passed. What the follow-up runs show (N = 1,000,000 each; indicative, shared host):

- **Twofish-256 decrypt-key does not reproduce.** Max |t| over eight runs with the current harness is 2.97 (Twofish-128: 3.70) and
  1.46 to 2.97 in the other runs; the data and control targets also pass everywhere. The single 12.72 was a noisy shared-host run.
- **Key-setup flags on x64 only, and not consistently.** Fixed key against random keys: Twofish-128 flagged in 2 of 5 and 2 of 8
  runs (max 9.29), Twofish-256 in 2 of 5 and 0 of 8 (max 5.05). The A/A control (random keys in both classes) never flagged (0 of 26, max 3.30).
  arm64: 0 of 21 flagged (max 3.54), controls 0 of 21.
- **The JIT output has nothing key-dependent.** `DOTNET_JitDisasm` of `TwofishEngine..ctor`, `ReedSolomon` and `H` (full opts, x64): every
  conditional jump tests a loop counter, a span bound or a key length; the GF(2^8) multiply is `shrx`, `neg`, `and`, `xor`.
- **Two further controls.** `pair-key-setup` times two different keys, each repeated in its own class. On x64 it flagged in 5 of 8 runs
  for each of Twofish-128 and Twofish-256 (max 15.76), so a repeated constant differs from another repeated constant, not only from random keys. `lowbits-key-setup` times keys
  with every byte 0 or 1 against uniformly random keys, with no key repeated: 0 of 16 flagged (max 4.08), arm64 0 of 16.

What this settles and what it does not: no flag appears when no key repeats, and the code has no key-dependent branch or index, which
points at an effect of presenting the same bytes again and again to the timed constructor rather than at the key's value. But the pair
control shows that effect differs from one constant to another, and a key-dependent time would look the same, so the cause is not
isolated. Twofish key setup therefore carries **no constant-time claim on x64** until it is resolved. Twofish decrypt (data and key kinds) passes and is claimed as before.

Machines: x64 AMD Ryzen 9 7950X3D, .NET 10.0.402; arm64 Apple M2, .NET 10.0.403. The first x64 run used the earlier key-setup harness (Twofish-128 decrypt-key 1.39, key-setup 2.56, control 1.62; Twofish-256 1.49, 3.93, 2.19, all passing). One Ed448 sign flag (6.18) on arm64, taken while other jobs loaded the machine, did not repeat in two quiet runs (1.50, 1.35).

## Results: 0.3 release runs (publishable)

Every group of `tools/timing-groups.sh` ran as an exclusive benchmark job that passed the publishability check. x64: AMD Ryzen 9 7950X3D, Linux, .NET 10.0.402, mean CPU busy 3.3–3.5% during each run. arm64: Apple M2, macOS, .NET 10.0.403, at least 95.9% idle before each run. Values are the maximum |t| over the uncropped data and 100 crops; the threshold is 4.5, and **bold** marks a run over it. Blowfish targets ran as two halves of 500,000 (shown a / b), and both must pass. The `small-and-glue` group was run twice more on x64 after its first run flagged; a target is claimed on a machine only when every publishable run of it passes there.

Outcome:

- **Claimed on x64 and arm64:** every target below that is not listed next. This covers Ed25519/Ed448 signing, X25519/X448, Camellia-256, CAST5, Blowfish, Twofish decryption, AES-OCB/EAX/KW, the ChaCha20-Poly1305 key targets, the OpenPGP session-key checksum glue, OpenPGP secret-key unlock and the CMS CBC padding check.
- **Claimed on arm64 only; x64 investigation open:**
  - Twofish-128 and -256 key setup (see above);
  - Camellia-128 key setup: the low-bits key control flags in all three x64 runs, with a 5–15 ns difference in about 700 ns, while the fixed-against-random target passes;
  - ChaCha20-Poly1305 encryption with secret data: flags in two of three x64 runs, with a mean difference of at most 1.1 ns in 3 µs;
  - IDEA decryption with secret data: flags in one of three x64 runs, with a 0.1 ns difference.

  None of these code paths has a secret-dependent branch or index. Until the x64 cause is known, no claim is made there.
- **No claim:** the RSA PKCS #1 session-key path (`pkesk-rsa`), a residual in the platform's RSA decryption (below).

| Target | N | x64 | x64 re-runs | arm64 |
|---|---|---|---|---|
| Blowfish/control-decrypt-key | 500,000 | 1.66 / 1.88 |  | 2.20 / 1.83 |
| Blowfish/control-key-setup | 500,000 | 1.25 / 1.45 |  | 2.78 / 2.25 |
| Blowfish/decrypt-data | 500,000 | 1.90 / 1.20 |  | 2.11 / 1.35 |
| Blowfish/decrypt-key | 500,000 | 1.40 / 2.71 |  | 2.26 / 1.88 |
| Blowfish/key-setup | 500,000 | 1.80 / 3.72 |  | 2.71 / 1.68 |
| Ed25519/sign | 1,000,000 | 1.94 |  | 1.81 |
| Ed448/sign | 1,000,000 | 1.68 |  | 1.71 |
| X25519/scalar-multiply | 1,000,000 | 2.53 |  | 1.74 |
| X25519/base-multiply | 1,000,000 | 2.02 |  | 1.16 |
| X448/scalar-multiply | 1,000,000 | 1.94 |  | 2.09 |
| X448/base-multiply | 1,000,000 | 1.66 |  | 1.63 |
| OpenPgpSessionKey/pkesk-rsa-bad-padding-vs-bad-checksum | 300,000 | **197.02** |  | **195.39** |
| AES-EAX/decrypt-data-40B | 1,000,000 | 1.01 | 1.43 ; 1.92 | 1.56 |
| AES-EAX/decrypt-data-2100B | 1,000,000 | 2.21 | 2.93 ; 2.72 | 1.56 |
| AES-EAX/decrypt-key-40B | 1,000,000 | 0.99 | 1.72 ; 1.75 | 0.95 |
| AES-EAX/control-key-40B | 1,000,000 | 1.42 | 1.38 ; 1.73 | 1.80 |
| AES-KW/unwrap-data-32B | 1,000,000 | 2.27 | 1.52 ; 1.19 | 0.93 |
| AES-KW/unwrap-key-32B | 1,000,000 | 3.35 | 3.43 ; 1.87 | 0.61 |
| AES-KW/control-key-32B | 1,000,000 | 1.58 | 2.30 ; 3.23 | 2.07 |
| AES-OCB/decrypt-data-40B | 1,000,000 | 1.36 | 1.58 ; 2.16 | 0.96 |
| AES-OCB/decrypt-data-2100B | 1,000,000 | 1.82 | 1.85 ; 1.59 | 1.74 |
| AES-OCB/decrypt-key-40B | 1,000,000 | 2.42 | 2.55 ; 1.45 | 1.82 |
| AES-OCB/control-key-40B | 1,000,000 | 1.82 | 1.79 ; 1.44 | 1.35 |
| CAST5/decrypt-data | 1,000,000 | 2.43 | 1.60 ; 2.61 | 1.93 |
| CAST5/decrypt-key | 1,000,000 | 1.96 | 1.71 ; 2.29 | 1.83 |
| CAST5/key-setup | 1,000,000 | 1.82 | 2.44 ; 1.79 | 2.07 |
| CAST5/control-key-setup | 1,000,000 | 2.43 | 2.24 ; 1.64 | 2.54 |
| CAST5/pair-key-setup | 1,000,000 | 1.94 | 1.55 ; 1.99 | 1.63 |
| CAST5/lowbits-key-setup | 1,000,000 | 2.29 | 1.78 ; 3.26 | 2.49 |
| CAST5/control-decrypt-key | 1,000,000 | 1.87 | 1.69 ; 2.23 | 1.96 |
| Camellia-128/decrypt-data | 1,000,000 | 2.26 | 1.22 ; 1.91 | 0.69 |
| Camellia-128/decrypt-key | 1,000,000 | 1.15 | 1.42 ; 1.30 | 2.16 |
| Camellia-128/encrypt-data | 1,000,000 | 1.72 | 2.16 ; 2.01 | 1.71 |
| Camellia-128/encrypt-key | 1,000,000 | 3.97 | 0.99 ; 1.33 | 2.09 |
| Camellia-128/key-setup | 1,000,000 | 2.42 | 1.62 ; 2.98 | 2.13 |
| Camellia-128/control-key-setup | 1,000,000 | 2.28 | 2.37 ; 1.71 | 2.43 |
| Camellia-128/pair-key-setup | 1,000,000 | 1.92 | 2.85 ; 2.10 | 1.68 |
| Camellia-128/lowbits-key-setup | 1,000,000 | **5.86** | **4.90** ; **5.19** | 1.73 |
| Camellia-128/control-decrypt-key | 1,000,000 | 1.79 | 1.58 ; 1.60 | 2.47 |
| Camellia-128/control-encrypt-key | 1,000,000 | 1.31 | 1.02 ; 1.46 | 1.37 |
| Camellia-256/decrypt-data | 1,000,000 | 2.18 | 1.31 ; 0.74 | 1.07 |
| Camellia-256/decrypt-key | 1,000,000 | 1.50 | 2.39 ; 0.89 | 1.12 |
| Camellia-256/encrypt-data | 1,000,000 | 1.96 | 0.94 ; 1.47 | 1.25 |
| Camellia-256/encrypt-key | 1,000,000 | 2.43 | 2.07 ; 1.87 | 1.12 |
| Camellia-256/key-setup | 1,000,000 | 2.43 | 1.87 ; 2.62 | 2.31 |
| Camellia-256/control-key-setup | 1,000,000 | 2.08 | 2.29 ; 2.26 | 1.70 |
| Camellia-256/pair-key-setup | 1,000,000 | 3.93 | 1.53 ; 2.44 | 1.96 |
| Camellia-256/lowbits-key-setup | 1,000,000 | 1.90 | 2.00 ; 2.06 | 1.58 |
| Camellia-256/control-decrypt-key | 1,000,000 | 2.05 | 3.17 ; 1.48 | 1.31 |
| Camellia-256/control-encrypt-key | 1,000,000 | 2.33 | 1.35 ; 1.96 | 2.21 |
| ChaCha20-Poly1305/encrypt-key-1000B | 1,000,000 | 1.12 | 2.08 ; 2.59 | 1.19 |
| ChaCha20-Poly1305/encrypt-data-1000B | 1,000,000 | **6.54** | **5.46** ; 3.80 | 2.13 |
| ChaCha20-Poly1305/encrypt-key-17B | 1,000,000 | 1.01 | 1.43 ; 2.19 | 1.03 |
| ChaCha20-Poly1305/decrypt-wrong-tag-key-100B | 1,000,000 | 1.69 | 2.00 ; 1.35 | 1.99 |
| ChaCha20-Poly1305/control-encrypt-key-1000B | 1,000,000 | 1.97 | 1.81 ; 1.84 | 2.78 |
| ChaCha20-Poly1305/control-encrypt-key-17B | 1,000,000 | 1.31 | 0.86 ; 1.62 | 1.19 |
| ChaCha20-Poly1305/control-decrypt-wrong-tag-key-100B | 1,000,000 | 1.07 | 0.64 ; 1.20 | 2.21 |
| CmsCbc/cbc-bad-padding-shape | 1,000,000 | 1.13 | 1.94 ; 1.89 | 1.97 |
| IDEA/decrypt-data | 1,000,000 | 2.51 | **6.24** ; 1.07 | 0.55 |
| IDEA/decrypt-key | 1,000,000 | 2.59 | 1.97 ; 2.03 | 2.71 |
| IDEA/key-setup | 1,000,000 | 3.57 | 1.87 ; 1.72 | 1.86 |
| IDEA/control-key-setup | 1,000,000 | 1.94 | 1.98 ; 1.85 | 1.97 |
| IDEA/pair-key-setup | 1,000,000 | 1.99 | 1.12 ; 1.84 | 1.74 |
| IDEA/lowbits-key-setup | 1,000,000 | 1.82 | 1.81 ; 2.08 | 1.56 |
| IDEA/control-decrypt-key | 1,000,000 | 1.59 | 2.49 ; 1.37 | 1.50 |
| OpenPgpSecretKeyUnlock/unlock-aead-v6-secret-bytes | 1,000,000 | 1.89 | 2.46 ; 1.88 | 2.36 |
| OpenPgpSecretKeyUnlock/unlock-cfb-sha1-v4-secret-bytes | 1,000,000 | 2.19 | 1.48 ; 3.11 | 1.08 |
| OpenPgpSessionKey/checksum-padded-ecdh-bad-padding-vs-bad-checksum | 1,000,000 | 1.49 | 0.36 ; 1.77 | 2.04 |
| OpenPgpSessionKey/checksum-padded-ecdh-key-bytes-control | 1,000,000 | 2.29 | 1.45 ; 1.09 | 2.17 |
| OpenPgpSessionKey/checksum-padded-ecdh-key-bytes | 1,000,000 | 2.30 | 2.60 ; 0.96 | 2.39 |
| OpenPgpSessionKey/checksum-unpadded-v6-key-bytes-control | 1,000,000 | 1.69 | 1.60 ; 0.99 | 2.41 |
| OpenPgpSessionKey/checksum-unpadded-v6-key-bytes | 1,000,000 | 1.39 | 2.47 ; 2.24 | 3.00 |
| Twofish-128/decrypt-data | 1,000,000 | 3.12 | 2.64 ; 2.46 | 1.64 |
| Twofish-128/decrypt-key | 1,000,000 | 1.54 | 2.35 ; 2.03 | 1.58 |
| Twofish-128/key-setup | 1,000,000 | 1.52 | 2.84 ; 3.72 | 1.24 |
| Twofish-128/control-key-setup | 1,000,000 | 2.21 | 2.69 ; 1.90 | 1.80 |
| Twofish-128/pair-key-setup | 1,000,000 | **7.06** | 1.54 ; 1.91 | 2.13 |
| Twofish-128/lowbits-key-setup | 1,000,000 | 2.09 | 2.51 ; 2.84 | 1.67 |
| Twofish-128/control-decrypt-key | 1,000,000 | 2.32 | 1.94 ; 1.50 | 2.25 |
| Twofish-256/decrypt-data | 1,000,000 | 2.14 | 1.73 ; 2.41 | 1.32 |
| Twofish-256/decrypt-key | 1,000,000 | 3.24 | 2.17 ; 1.81 | 1.53 |
| Twofish-256/key-setup | 1,000,000 | **6.57** | 4.46 ; 3.34 | 1.22 |
| Twofish-256/control-key-setup | 1,000,000 | 1.72 | 1.61 ; 2.69 | 2.08 |
| Twofish-256/pair-key-setup | 1,000,000 | 3.10 | 2.31 ; **4.56** | 0.62 |
| Twofish-256/lowbits-key-setup | 1,000,000 | 4.29 | 2.89 ; 2.58 | 1.02 |
| Twofish-256/control-decrypt-key | 1,000,000 | 2.76 | 1.27 ; 2.32 | 0.93 |


## Earlier indicative results

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

## OpenPGP secret-key unlock

`OpenPgpSecretKeyUnlock` times the check that decides whether a secret-key packet opened: fixed secret bytes against random ones, through the AEAD (version 6) and the SHA-1 checked CFB (version 4) unlock paths. Indicative runs (heavy class beside other work, N = 1,000,000, full-opt JIT):

| Machine | AEAD v6 max \|t\| | CFB v4 max \|t\| |
|---|---|---|
| x64 (1-minute load up to 80) | 2.60 | 3.02 |
| arm64 (Apple M2) | 1.68 | 0.78 |

Both pass (threshold 4.5). The Argon2id step that derives the key is data-dependent by design and is not covered by the claim.
