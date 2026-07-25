# SanitizerCoverage (sancov) — stub path

Randfuzz’s primary coverage sensor today is **DynamoRIO drcov** (`fuzz.coverageGuided`, `fuzz.stalkMode`). LLVM **SanitizerCoverage** (sancov) is a complementary edge bitmap from ASan/MSan-instrumented builds — useful when the target is already compiled with `-fsanitize-coverage=trace-pc-guard` and you want native edges without DynamoRIO.

## YAML flag (stub)

```yaml
fuzz:
  sanitizerCoverage: true   # soft hook — does not disable drcov today
  coverageGuided: true
  stalkMode: auto
```

When `sanitizerCoverage: true`:

- `SanitizerCoverageBackend.Resolve()` reports requested + availability
- **If DynamoRIO is present:** drcov remains active; flag notes sancov ingest is not wired yet
- **If DynamoRIO is missing:** corpus-novelty stalk only; doctor should warn on coverageGuided projects

Full sancov ingest (reading `.sancov` / inline guards) is on the roadmap — not a LibAFL port.

## Relationship to DynamoRIO

| Backend | When |
|---------|------|
| **drcov** | Default when `tools/dynamorio` or `DYNAMORIO_HOME` is installed |
| **sancov** | Future — same `ObservationKind.Coverage` bus events, different sensor source |
| **corpus-novelty** | Fallback when neither is available |

DynamoRIO and sancov can coexist on Linux lab builds; Randfuzz will prefer explicit stalk backend selection once sancov lands.

## Doctor / CLI

`randall doctor -c projects/….yaml` does not fail on `sanitizerCoverage: true` alone — it is advisory until ingest ships. Watch `stalk backend` rows for drcov availability.

## Related

- [STALKING.md](STALKING.md) — stalk loop + drcov
- [EXTERNAL_WORKERS.md](EXTERNAL_WORKERS.md) — LibAFL often pairs with sancov
- [FAULT_SIGNALS.md](FAULT_SIGNALS.md) — sanitizer faults vs coverage edges
