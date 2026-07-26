# Root Cause Engine (Wave 1)

Deterministic root-cause analysis for Randall crash canisters — **research only**, no LLM and no exploit automation.

## Artifacts

| File | Contents |
|------|----------|
| `{guid}_root_cause.json` | `RootCauseAnalysisDto` — primary `RootCauseCandidate`, educational summary, optional alternates |

Built automatically after corruption chain + backward trace when `fuzz.cdbAnalyzeCrash: true` (Windows), and on-demand in the Investigation catalog when the sidecar is missing.

## EvidenceFact coordination

Wave 1 defines a stable **`EvidenceFact`** record in `Randall.Contracts` as the evidence atom consumed by `RootCauseEngine`. A future EvidenceFact agent may populate richer facts; the engine's `CollectEvidenceFacts` method is the merge point.

Each fact carries:

- `Id`, `Kind`, `Source`, `Statement`, `Confidence`, optional `Detail`

Sources today: `debugger`, `ghidra`, `corruption_chain`, `backward_trace`, `oracle`, `sidecar`, `triage`.

## Categories

Assigned only when supporting evidence exists:

| Category | Typical signals |
|----------|-----------------|
| `BoundsViolation` | Write/read AV + pattern depth, stack smash, ASCII/small-offset control |
| `LifetimeViolation` | Freed heap class, UAF heap text, backward trace heap timeline |
| `SizeMismatch` | memcpy/strcpy-class sink + attributed length field |
| `IntegerConversion` | interesting/boundary mutators, oracle overflow terms |
| `ParserState` | Parse/decode/token symbols, session graph node |
| `FormatInterpretation` | ASCII register match + protocol field |
| `Uninitialized` | Null-page read without input register match |
| `UnexpectedObjectState` | Heapish fault without clear UAF |

## Investigation UI

The Crashes **Investigation** panel renders:

- Category + confidence badge
- Educational summary (teaching paragraph)
- Faulting/source/sink/input region/allocation/corruption fields
- Observed facts, inferences, unknowns
- Alternative categories when scores are close

Scream intelligence rollup also exposes `rootCauseCategory`, `rootCauseSummary`, and `rootCauseConfidence` for list chips.

## Tests

`tests/Randall.Tests/RootCauseEngineTests.cs` — ASCII write AV (bounds), heap UAF (lifetime), Ghidra fact collection, persistence, insufficient-evidence path.

## Related docs

- [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) — full crash artifact pipeline
- [CDB_PROBE_ENGINE.md](CDB_PROBE_ENGINE.md) — debugger observation probes
