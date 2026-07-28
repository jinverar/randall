# SanitizerCoverage (sancov)

Randfuzz’s primary coverage sensor today is **DynamoRIO drcov** (`fuzz.coverageGuided`, `fuzz.stalkMode`). LLVM **SanitizerCoverage** (sancov) is a complementary edge source from ASan-instrumented builds — useful when the target is compiled with `-fsanitize-coverage=trace-pc-guard` (or `-fsanitize=fuzzer` no-link) and you want native PCs **without DynamoRIO**.

## Config: `coverage.backend`

```yaml
coverage:
  backend: auto          # auto | sancov | dynamorio | semantic
fuzz:
  coverageGuided: true
  stalkMode: auto
  # alias / legacy:
  # sanitizerCoverage: true
  # coverageBackend: sancov
```

| Token | Behavior |
|-------|----------|
| **auto** | DynamoRIO when present; else sancov ingest if requested; else semantic/path-novelty |
| **sancov** | Prefer `*.sancov` PC ingest (enables sanitizerCoverage path); DynamoRIO optional supplement |
| **dynamorio** | Force external drcov; warn + fall back when missing |
| **semantic** | Path-novelty / ReelDeck stages only — no BB edges expected |

Doctor row: `coverage.backend` + `sanitizerCoverage`.

When sancov is active (`coverage.backend: sancov` or `fuzz.sanitizerCoverage: true`):

- `SanitizerCoverageBackend.Resolve()` reports requested + availability
- **If DynamoRIO is present:** drcov remains active; Randfuzz also ingests `*.sancov` PCs from `corpus/traces` when drcov returns no new edges
- **If DynamoRIO is missing (typical Linux ASan lab):** ingest raw `*.sancov` PC lists into `edges.txt` as `sancov:<module>:0x<pc>` keys — corpus-novelty stalk still applies when no sancov files appear

## Linux ASan lab build (no DynamoRIO)

```bash
clang -fsanitize=address -fsanitize-coverage=trace-pc-guard -g target.c -o target
export ASAN_OPTIONS=coverage=1
# fuzz with coverage.backend: sancov — *.sancov under corpus/traces when the target writes them
```

Inline-guard registration inside the target process is still the target author’s responsibility; Randfuzz only **reads** emitted `.sancov` artifacts.

## Relationship to DynamoRIO

| Backend | When |
|---------|------|
| **drcov** | Default when `tools/dynamorio` or `DYNAMORIO_HOME` is installed (`coverage.backend: auto\|dynamorio`) |
| **sancov ingest** | `coverage.backend: sancov` or `fuzz.sanitizerCoverage: true` + `*.sancov` under trace dir |
| **semantic / corpus-novelty** | `coverage.backend: semantic`, or neither BB source produces edges |

## Hard limits

- No LibAFL sancov bitmap merge yet — PC keys only, not BB translation
- Windows sancov ingest is best-effort (needs ASan-built target writing `.sancov` beside traces)
- Does not replace sanitizer **fault** parsing (`SanitizerLogParser` on stderr) — coverage PCs ≠ crash class

## Related

- [STALKING.md](STALKING.md) — stalk loop + drcov
- [FILE_FUZZING.md](FILE_FUZZING.md) — file-format scorecard
- [FAULT_SIGNALS.md](FAULT_SIGNALS.md) — sanitizer faults vs coverage edges
