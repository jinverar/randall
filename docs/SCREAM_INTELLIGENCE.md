# Scream Intelligence

Formal rollup of crash/scream signals for Investigation UI, canister mood, and CLI sorting.

## DTO: `CrashIntelligenceDto`

Built by `CrashIntelligenceBuilder` from the crash catalog, triage, sidecar, static function map, and cluster stats.

| Field | Source |
|-------|--------|
| `Severity` | `CrashTriageDto` |
| `Novelty` | 0–100 — cluster size, coverage Δ, oracle total |
| `ClusterKey` / `ClusterSize` / `SeenCount` | Cluster bucket |
| `CoverageDelta` | Sidecar `NewEdgesAtCrash` |
| `Function` | Ghidra / PE static map one-liner |
| `Offset` | Pattern depth in crashing input |
| `OracleScore` | Sidecar `RandallScore` (or `OracleScorer.CrashScore` fallback) |
| `Reproducible` | Input `.bin` + sidecar/run link present |
| `Minimized` | Shortest input in cluster |
| `FirstSeen` | Earliest `ObservedAt` in cluster |
| `Lineage` | Sidecar `MutatorChain` + journal replay when `iterations.jsonl` exists |
| `ScreamScore` | Unified rank for list / canister / Investigation |
| `PrimaryFault` / `FaultSignals` | `FaultSignalMapper` — triage, cdb, Page Heap, sanitizer, RPP ([FAULT_SIGNALS.md](FAULT_SIGNALS.md)) |

## API

- `GET /api/crashes` — list rows include `screamScore`, `novelty`, `oracleScoreTotal`, `seenCount`
- `GET /api/crashes/{id}` — full `intelligence` block on `CrashDetailDto`

## UI

- **Investigation** — “Scream intelligence” panel under “Why it crashed” (purple highlight when hot)
- **Canisters** — tooltip shows novelty · oracle for hot screams; purple mist when `novelty ≥ 70` and (`oracle ≥ 40` or unique)

Hot = high novelty + oracle + unique — the purple harvest signal.

## Sidecar

New crashes store `RandallScore` on `*_crash.json` when the oracle stack ran that iteration; otherwise a crash-only score is synthesized at catalog read time.
