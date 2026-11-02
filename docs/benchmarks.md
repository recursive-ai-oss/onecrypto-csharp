# Benchmarks

Project: `bench/OneCrypto.Benchmarks` (BenchmarkDotNet, in-process, `MemoryDiagnoser` on). Runner: `tools/bench.sh`.

## Method

- A row is one class under `bench/OneCrypto.Benchmarks/Rows/`: a class-level `[BenchmarkCategory("area")]`, a method named
  `Ours`, and one method per comparator named for it. Mark a native or native-backed comparator with
  `[BenchmarkCategory("native")]`. `Rows/Sha256Rows.cs` is the template; adding a row is adding one file.
- Inputs and work are matched between `Ours` and each comparator; parameters (`[Params]`) give the sizes.
- The summary compares medians. The ratio is ours ÷ comparator, so below 1 is faster. The gate uses the fastest *managed*
  comparator for each input. Per area it reports the geometric mean of those ratios and the worst row.
- The bar: geomean at most 1.0 and no row above 1.25 against managed comparators. Native comparators are reported against
  a non-gating 1.5.
- Allocated bytes per operation come from `MemoryDiagnoser`. Rows that must show constant memory while streaming measure
  their process's peak working set with `PeakMemory.Measure` and run alone in their own process.
- `--quick` runs fewer iterations to check a row; use the default for numbers that are reported.

## Running

`tools/bench.sh results/<name> --filter '*Sha256Rows*'` runs the selected rows as a heavy job on the machine's work queue
(indicative numbers; the label ends in 'indicative'). `PERF_CLASS=bench` asks for an exclusive benchmark job, for the publishable
run of a stage. `PERF_CORES` and `PERF_MAX` set the reservation and time limit. It leaves BenchmarkDotNet's reports, `summary.json`, `machine.txt` (CPU, cores, ISA flags, runtime), `load.log`
(load before, every 5 s during, after) and `publishable.txt` in the output folder. A run is marked not publishable unless it ran as
class `bench` and, on Linux, the share of all CPUs that were busy (`/proc/stat`, sampled every 5 s before the start and during the run, iowait counted idle) averaged at most 8% with no sample above 15% (`PERF_MAX_BUSY`, `PERF_MAX_BUSY_SAMPLE`); the load average is logged but does not decide, because it counts processes waiting on disk. A sample above the limit also logs the busiest processes outside the run. On macOS, whose idle load average sits near 2, the CPU must be at least 90% idle just before it started.

## Comparators (pinned, bench project only)

BouncyCastle.Cryptography 2.7.0, Konscious.Security.Cryptography.Argon2 1.3.1, Isopoh.Cryptography.Argon2 2.0.0,
System.Security.Cryptography.Pkcs 10.0.14, NSec.Cryptography 26.4.0 (native-backed: reported, not gating). They are restored
and called through their public API only.
