# Hypothesis Engine — scientific loop

Phase C turns crash intelligence into **testable hypotheses** with a closed research loop: propose → queue → execute → confirm/refute → update confidence. No LLM on the hot path; no exploit payloads.

## Loop

```text
Crash save (sidecar + triage + debugger + corruption chain + evolution)
      ↓
HypothesisEngine.Build → ranked HypothesisDto list
      ↓
Persist per crash + project ledger
      ↓
HuntPolicy NeedsExperiment (confidence ≥50%) → Magician budget (≥65%)
      ↓
hypothesis_queue.json → FuzzEngine dequeues plan each iteration
      ↓
ApplyExperiment (sweep / hold / replay / boundary / minimize-hold)
      ↓
RecordOutcome → Confirmed | Refuted | Partial | Inconclusive + confidence delta
```

## Artifacts

| Path | Contents |
|------|----------|
| `data/crashes/<project>/_hypotheses/{guid}.json` | Ranked hypotheses for one crash |
| `data/crashes/<project>/_hypotheses/ledger.json` | Project aggregate (Investigation + API) |
| `data/stalk/<project>/hypothesis_queue.json` | Queued experiments + remaining budget |
| `data/crashes/<project>/_magician/rewind_scream_hint.md` | Human-readable experiment hints |
| Legacy `{guid}_hypotheses.json` in crash dir | Still read for backward compatibility |

## Experiment kinds (research only)

| Kind | Action |
|------|--------|
| `SweepOffset` | Deterministic bit flip around pattern-depth offset |
| `BoundaryProbe` | Probe 0 / MAX-1 / MAX at suspected field |
| `MinimizeHold` | Shrink tail while preserving held bytes |
| `ReplayLineage` | Replay crash input (sweep>0 may re-apply lineage mutators) |
| `HoldMutator` | Hold region + deterministic havoc elsewhere |

Default budget: **3 iterations** per hypothesis (`HypothesisExperimentDto.BudgetIterations`).

## Confidence updates

| Outcome | Status | Confidence |
|---------|--------|------------|
| Crash matches expectation | `Confirmed` | +8 (cap 95%) |
| No crash, budget left | `Inconclusive` | −12 |
| No crash, budget exhausted | `Refuted` | −20 |
| Crash, wrong signature, budget left | `Partial` | −5 |
| Crash, wrong signature, budget exhausted | `Refuted` | −10 |

`HypothesisResultDto` stores `confidenceBefore` and `confidenceAfter` for Investigation UI deltas.

## Hunt Policy + Magician

- `HuntPolicyEngine.ResolveExperiment` sets `NeedsExperiment` when top pending hypothesis ≥ **50%**.
- `MagicianEngine.OnHuntPolicyNeedsExperiment` enqueues and, at ≥ **65%**, casts `hypothesisExperiment` spell for execution budget.
- `FuzzEngine` dequeues plans when `NeedsExperiment` or top hypothesis confidence is high enough.

## API

- `GET /api/stalking/{project}/hypotheses` — queue, top hypothesis, project ledger

## CLI (verbose fuzz)

```text
[hypothesis] hyp-offset-28 SweepOffset conf=72% sweep=0
[hypothesis] recorded outcome for hyp-offset-28 crash=True
```

## Tests

`tests/Randall.Tests/HypothesisEngineTests.cs` — build, queue/dequeue, sweep determinism, confirm on crash, refute after budget, ledger persistence, Hunt Policy fusion.

See also [ROADMAP_INTELLIGENCE.md](ROADMAP_INTELLIGENCE.md) · [MAGICIAN.md](MAGICIAN.md) · [SCREAM_INTELLIGENCE.md](SCREAM_INTELLIGENCE.md).
