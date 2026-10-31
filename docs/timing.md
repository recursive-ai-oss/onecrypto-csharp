# Timing tests

Constant-time evidence for secret-handling code, in the style of Reparaz, Balasch and Verbauwhede, "Dude, is my code constant
time?" (DATE 2017). Project: `tests/Timing`. Runner: `tools/timing.sh`.

## Method

- Two input classes: a fixed secret and a fresh random secret per call. The class sequence is drawn from the CSPRNG before
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
