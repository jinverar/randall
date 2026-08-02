# Hypothesis Engine — scientific loop

Phase C turns crash intelligence into **testable hypotheses** with a closed research loop: propose → queue → execute → confirm/refute → update support score. No LLM on the hot path; no exploit payloads.

Schema **v2** (current): `HypothesisInstanceId` (Guid) ≠ `HypothesisTypeId` (string); confirmation via machine-readable `ExpectedPredicate` + `FaultComparison`. Legacy v1 files migrate on read — former `Confirmed` becomes `LegacyUnverified` (never silently re-interpreted as v2 Confirmed).

## Loop

```text
Crash save (sidecar + triage + debugger + corruption chain + evolution)
      ↓
    Artifact gates (primary fault / identity) — block if unavailable
      ↓
HypothesisEngine.Build → ranked HypothesisDto list (schema v2)
      ↓
Persist per crash + project ledger
      ↓
HuntPolicy NeedsExperiment (support ≥50) → Magician budget (≥65)
      ↓
hypothesis_queue.json → FuzzEngine dequeues plan each iteration
      ↓
ApplyExperiment (sweep / hold / replay / boundary / minimize-hold)
      ↓
RecordOutcome → evaluate ExpectedPredicate + FaultComparison
             → Confirmed | Supported | Weakened | Inconclusive | Refuted | …
```

## Artifacts

| Path | Contents |
|------|----------|
| `data/crashes/<project>/_hypotheses/{guid}.json` | Ranked hypotheses for one crash |
| `data/crashes/<project>/_hypotheses/ledger.json` | Project aggregate (Investigation + API) |
| `data/stalk/<project>/hypothesis_queue.json` | Queued experiments + remaining budget |
| `data/crashes/<project>/_magician/rewind_scream_hint.md` | Human-readable experiment hints |
| Legacy `{guid}_hypotheses.json` in crash dir | Still read for backward compatibility |

Incomplete / rejected / teardown-only artifacts → set `Ok=false` with `Manifest.BlockReason`; hypotheses are **unavailable**, not silently empty-success.

## Identity & evidence (v2)

| Field | Role |
|-------|------|
| `id` | **Instance** Guid (`N`) — unique per hypothesis row |
| `typeId` | Stable type string e.g. `hyp-oracle-correlate` (may repeat across crashes) |
| `kind` | Typed class: TriggerSensitivity, MutatorCorrelation, FamilyProgression, … |
| `expectedPredicate` | Machine-readable confirmation rule |
| `evidenceRefs` | Refs to `EvidenceFact` ids (not free-form `"corruption:MEDIUM"` tags) |
| `supportScore` | 0–100 ranking score (**not** a calibrated probability); JSON also emits `confidencePercent` for compat |
| `supportGrade` | Unsupported / Weak / Moderate / Strong / Confirmed |

## Experiment registry

Only registered `(HypothesisKind, HypothesisExperimentKind)` pairs may update support. Notably:

- **Counterfactual safe-adjacent** → `TriggerSensitivity` only
- **SweepOffset / Bit-flip** do **not** support `MutatorCorrelation` (oracle correlate)

## Confirmation rules (honesty)

| Observation | Result |
|-------------|--------|
| Generic exit / `0xC0000005` alone | At most **Supported** (“abnormal AV reproduced”) — **never Confirmed** |
| Same exit, different primary fault | Not reproduction Confirmed |
| Predicate + matching primary fault | **Confirmed** (when registered experiment) |
| 3 no-crash (flaky) | **Weakened** / **Inconclusive** — not Refuted (unless repro-required claim) |
| Family progression without progression signal | Supported / incomplete — not Confirmed from status alone |
| MutatorCorrelation crash-level replay | Supported until campaign gates (`exec≥20`, `crashes≥3`) |

## Statuses

`Proposed`, `Testing`, `Supported`, `Weakened`, `Inconclusive`, `Refuted`, `Confirmed`, `Blocked`, `Invalidated`, `LegacyUnverified`  
(Legacy JSON may still say `Pending`/`Running`/`Partial` — normalized on read.)

## Support-score deltas (named, not probabilities)

| Outcome | Status | Score delta |
|---------|--------|-------------|
| Predicate + primary fault | `Confirmed` | +8 (cap 95) |
| Abnormal exit only | `Supported` | +4 |
| Safe-adjacent (TriggerSensitivity) | `Supported` | +12 |
| No crash | `Inconclusive` / `Weakened` | −12 |
| No crash, repro-required exhausted | `Refuted` | −20 |
| Wrong primary fault | `Weakened` / `Inconclusive` | −5…−10 |

`HypothesisResultDto` stores before/after scores plus optional `FaultComparison` and support reasons.

## Hunt Policy + Magician

- `HuntPolicyEngine.ResolveExperiment` sets `NeedsExperiment` when top open hypothesis support ≥ **50**.
- `MagicianEngine.OnHuntPolicyNeedsExperiment` enqueues and, at ≥ **65**, casts `hypothesisExperiment` spell for execution budget.
- Queue keys use **instance** id; UI shows `typeId` with instance id in the tooltip.

## API

- `GET /api/stalking/{project}/hypotheses` — queue, top hypothesis, project ledger

## CLI (verbose fuzz)

```text
[hypothesis] hyp-offset-28 SweepOffset support=72 sweep=0
[hypothesis] recorded outcome for <instanceId> crash=True
```

## Tests

`tests/Randall.Tests/HypothesisEngineTests.cs` — build, instance≠type id, exit-alone not Confirmed, safe-adjacent leakage blocked, flaky weaken, legacy v1 migrate, artifact gate, invalidated evidence.

See also [EVIDENCE_FACT.md](EVIDENCE_FACT.md) · [ROADMAP_INTELLIGENCE.md](ROADMAP_INTELLIGENCE.md) · [MAGICIAN.md](MAGICIAN.md) · [SCREAM_INTELLIGENCE.md](SCREAM_INTELLIGENCE.md).
