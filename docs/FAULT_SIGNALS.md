# Fault signals (Phase 4 sensors)

Randfuzz normalizes heterogeneous crash sensors into **`FaultSignal`** rows:

| Field | Meaning |
|-------|---------|
| `Kind` | Taxonomy: access violation, stack overrun, sanitizer, Page Heap, WER/!exploitable, hang, … |
| `Confidence` | 0–1 — higher when minidump/cdb/sanitizer text backs the class |
| `Severity` | `critical` / `high` / `medium` / `low` — aligned with scream + oracle ranks |
| `Source` | Sensor: `CrashTriage`, `MinidumpAnalysis`, `CdbAnalyze`, `PageHeap`, `SanitizerLog`, `RppPlugin`, `OracleRuntime` |

## Where signals come from

| Sensor | Mapper input |
|--------|----------------|
| **CrashTriage** | Exception code, RIP/fault PC, IP-control heuristics, stack smash |
| **Minidump / PE analysis** | `*_analysis.json` from auto-analyze |
| **cdb / !exploitable** | WER-ish classification (`EXPLOITABLE`, …) |
| **Page Heap** | `target.pageHeap: true` on the project YAML |
| **Sanitizer stderr** | ASan/UBSan/MSan/TSan tokens in target detail |
| **RPP post_crash** | Plugin tag → mapped kind |
| **Oracle runtime** | `runtime.crash` / `runtime.sanitizer` findings |

Implementation: `FaultSignalMapper` in `Randall.Infrastructure`.

## Surfacing

| Consumer | Fields |
|----------|--------|
| **Crash intelligence** | `CrashIntelligenceDto.PrimaryFault`, `FaultSignals` on `GET /api/crashes/{id}` |
| **Oracle FINDINGS** | Optional `Fault` on `OracleFindingDto` for runtime rules |
| **Observation bus** | `ObservationKind.Fault` via `ObservationEvents.Fault` each crash (and RPP observe) |

## Observation bus

Fault observations ride the same bus as coverage, path, oracle, and Ghidra hints:

```csharp
ObservationBus.Publish(ObservationEvents.Fault(runId, iteration, inputHash, primaryFault, project));
```

External workers ingest the same shape through `IExternalWorkerIngest` — see [EXTERNAL_WORKERS.md](EXTERNAL_WORKERS.md).

## Related

- [SCREAM_INTELLIGENCE.md](SCREAM_INTELLIGENCE.md) — scream rollup still owns `ScreamScore`; faults explain *why* severity is hot
- [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) — minidump + cdb pipeline
- [RPP.md](RPP.md) — `observe` hook for custom sensors
