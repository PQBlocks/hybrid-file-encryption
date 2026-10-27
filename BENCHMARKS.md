# Benchmarks

There is **no competitor comparison**: no other file-encryption tool was benchmarked, so no claim of being faster or slower than any other implementation is made. What follows are two sets of timings of this package alone.

## A. Earlier command-line run (2026-09-20), raw data in `benchmarks/benchmark-summary.json`

**This run was taken before the security fixes in this release and has not been repeated.** Each trial ran `encrypt` and `decrypt` as separate command-line processes, so every figure includes Python start-up, public-key loading and one ML-KEM-768 + X25519 operation per command. Since then, private-key unlocking has changed (scrypt n=2^17 instead of a 100,000-iteration PBKDF2), so command-line decrypt timings today would differ (not measured).

Setup (from the summary file): Intel Core i9-13900K @ 3.00 GHz, 8 CPUs counted, 23.33 GB RAM, Linux 7.1.8-1-cachyos x86_64, Python 3.14.7, frequency scaling pinned, no concurrent load. 100 trials per size, 10 for 100 MB (a 100 MB decrypt took about 22 s, so fewer trials were run); 10,000 bootstrap resamples, 95% confidence intervals. 310 of 310 trials passed their round-trip check.

Medians, in seconds, with the `ci` field of the summary (a 95% bootstrap interval) in brackets; values from `sizes_tested`, rounded to 6 decimals:

| Size | Trials | Encrypt median | Decrypt median | Round-trip median |
|---|---|---|---|---|
| 1 KB | 100 | 0.125017 [0.123442, 0.127969] | 0.163195 [0.159814, 0.167393] | 0.28955 [0.284486, 0.294159] |
| 10 KB | 100 | 0.124257 [0.122456, 0.128209] | 0.161279 [0.15911, 0.165866] | 0.288434 [0.281777, 0.291629] |
| 1 MB | 100 | 0.147839 [0.143748, 0.154445] | 0.188587 [0.185853, 0.192048] | 0.341481 [0.329831, 0.347809] |
| 100 MB | 10 | 0.590352 [0.560247, 0.630942] | 22.893066 [21.552153, 24.507458] | 23.414165 [22.141076, 25.131109] |

99th percentiles of the round trip: 0.385522 s (1 KB), 0.386702 s (10 KB), 0.48172 s (1 MB), 30.38288 s (100 MB).

Reading it: small files cost about 0.29 s per round trip, dominated by fixed per-process costs rather than data size. At 100 MB, decrypt (22.9 s) was about 39 times slower than encrypt (0.59 s) in these runs. The cause was not profiled.

Caveat: a derived table in earlier notes for this run (not shipped) disagreed with the summary JSON on throughput at 10 KB by a factor of about 1000; the JSON is the source used here.

## B. Library-level timing on this release (2026-10-25)

`benchmarks/bench_roundtrip.py` calls `encrypt()` and `decrypt()` in-process for one recipient, with random data, and reports the median of 5 runs after one keygen. No warm-up run, no pinned frequency, other processes were running: indicative only.

Machine: Intel Core i5-10300H @ 2.50 GHz, 23 GB RAM, Linux, Python 3.14.8, liboqs 0.16.0.

| Size | Encrypt median (s) | Decrypt median (s) | Runs |
|---|---|---|---|
| 1 KB | 0.0004 | 0.0004 | 5 |
| 1 MB | 0.0039 | 0.0073 | 5 |
| 10 MB | 0.0218 | 0.1808 | 5 |

Decrypt grows faster than encrypt with size (at 10 MB it is about 8 times slower). The cause was not profiled.

The two sets of numbers come from different machines and different measurement scopes (processes against in-process calls) and must not be compared with each other.

## Losing cases

- Large-file decrypt is slow relative to encrypt (both sets above).
- Small files are dominated by the fixed per-recipient KEM cost when invoked as separate processes (set A).
- Everything is in memory, so peak memory scales with file size (memory not measured).

## Reproduce

```bash
export OQS_LIB_PATH=/path/to/liboqs.so.9      # if liboqs is not on the loader path
python benchmarks/bench_roundtrip.py 5         # set B
```

The command-line harness behind set A is not part of this repository; only its raw summary is.
