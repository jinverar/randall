# Influence Engine — input → state map

Wave 1 Priority 2 maps **which input regions influence which program state** (length→alloc/copy, pointer→fault address, register→sink, heap object lifetime, …). Research-only — teaches control of state, not exploit payloads.

## Relationship to Hypothesis Engine

InfluenceEngine does **not** implement a new experiment framework. It:

1. **Observes** links from `InputAttributionEngine`, `CorruptionChain`, `DebuggerObservation`, and `BackwardTrace`.
2. **Suggests** confirmation using the same `HypothesisExperimentDto` kinds as Phase C (`SweepOffset`, `HoldMutator`, `ReplayLineage`, `BoundaryProbe`, `MinimizeHold`).
3. **Upgrades** link status when `HypothesisEngine.RecordOutcome` confirms or refutes a related hypothesis (`Observed` → `Confirmed`).

```text
Crash save → corruption chain + backward trace + root cause facts
      ↓
InfluenceEngine.Build → region → state links + EvidenceFact[]
      ↓
Persist {guid}_influence.json
      ↓
HypothesisEngine experiments (reuse queue / sweep / hold / replay)
      ↓
RecordOutcome → InfluenceEngine.RefreshFromHypotheses
```

## Artifact

| Path | Contents |
|------|----------|
| `data/crashes/<project>/{guid}_influence.json` | `CrashInfluenceMapDto` — links, facts, summary, narrative |

## Link shape

Each `InfluenceLinkDto` connects:

| Field | Example |
|-------|---------|
| **Region** | `input+20` (4B), field label, attributed mutator step |
| **State** | `Register RAX`, `FaultAddress`, `CopyLength`, `HeapObject` |
| **Mechanism** | `pointer→fault address`, `length→alloc/copy`, `input→register→sink`, `sentinel correlation (−1 / 0xFF..FF)` |
| **Status** | `Observed` / `Confirmed` / `Candidate` / `Unknown` (experiment confirmation) |
| **Honesty** | `Observed` / `Confirmed` / `Hypothesized` / `Unverified` — Candidate length→alloc/copy and sentinel correlations must not read as Observed facts |
| **Evidence refs** | `register:RAX@+20`, `corruption:HIGH`, `backwardTrace:MEDIUM` |
| **Suggested experiment** | Same kinds as Hypothesis Engine (when status is `Candidate`) |

Bare mutator name `boundary` does **not** create a `length→alloc/copy` / write-length candidate. That mechanism needs a real copy/alloc sink (or disasm) plus expand/insert/interesting (or repeated boundary causality). Null write on a teardown/exit path (`SafeExitProcess`) never invents `input → SafeExitProcess` length→alloc/copy.

## EvidenceFact consumption

When `RootCauseEngine.CollectEvidenceFacts` has run, those normalized facts are merged into the influence map's `Facts` array (deduped by id). InfluenceEngine also emits its own attribution facts when building from scratch.

## UI

Investigation panel → **Influence map** (between Scream Investigator and Corruption chain): table of region → state links, confirmation status, and top evidence facts.

## API

`GET /api/crashes/{id}` includes `influenceMap` on `CrashDetailDto` when the sidecar exists.

## CLI / fuzz logs

On crash save (after hypotheses):

```text
[influence] 3 link(s) [HIGH] — [HIGH] input+20 → RAX (input→register value) · +2 link(s)
```

## See also

- [HYPOTHESIS_ENGINE.md](HYPOTHESIS_ENGINE.md) — experiment loop reused for confirmation
- [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) — corruption chain and debugger observation inputs
