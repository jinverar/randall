# Campaign intelligence stop goals

Stop fuzz runs or mark campaigns **complete** when scream-intelligence thresholds are met — without coupling to HuntPolicy, HypothesisEngine, or ScreamEvolution internals.

## Project YAML (`fuzz`)

Legacy single threshold (still supported):

```yaml
fuzz:
  screamScoreGoal: 55   # stop when max ScreamScore ≥ 55 OR hot/purple count ≥ 55
```

Structured goals (preferred):

```yaml
fuzz:
  stopGoals:
    legacyScreamScoreGoal: 55
    uniqueScreamsWithScore:
      count: 3
      minScore: 50
    uniqueScreamsWithMomentum:
      count: 2
      minMomentum: 40
    queueTopClustersOnGoal: true   # optional — enqueue replay/minimize via hypothesis queue
```

| Field | Meaning |
|-------|---------|
| `legacyScreamScoreGoal` | Same as `screamScoreGoal` — max score **or** hot scream count |
| `uniqueScreamsWithScore` | N **distinct cluster keys** each with ScreamScore ≥ `minScore` |
| `uniqueScreamsWithMomentum` | N **distinct evolution families** each with momentum ≥ `minMomentum` |
| `queueTopClustersOnGoal` | After goal met, enqueue top 3 clusters for hypothesis replay/minimize |

**Hot scream** = novelty ≥ 70 and (oracle ≥ 40 or first-in-cluster). See [CRASH_LOGGING.md](CRASH_LOGGING.md).

## Campaign YAML

Campaign-level goals apply across **all runs** (aggregate crash catalog). Per-run overrides merge on top of campaign + project goals.

```yaml
name: intel-smoke
description: Stop when we have two strong unique screams
stopGoals:
  uniqueScreamsWithScore:
    count: 2
    minScore: 45
runs:
  - project: projects/vulnserver.yaml
    maxIterations: 500
  - project: projects/vulnhttp.yaml
    maxIterations: 300
    stopGoals:
      uniqueScreamsWithScore:
        count: 1
        minScore: 50
```

Merge order: **project** → **campaign** → **run** (later wins for each field). Per-run fuzz evaluation uses **project + run** only; campaign thresholds aggregate across **all** campaign projects after each run.

Example lab campaign: [`campaigns/intel-stop-goals.yaml`](../campaigns/intel-stop-goals.yaml).

## Signals

| Surface | When goal met |
|---------|----------------|
| Fuzz analyst log | `Stop goal met: … — stopping` |
| CLI console | Same via `FuzzAnalystLog` |
| `GET /api/fuzz/status` | `stopGoalMet`, `stopReason`, `goalProgress` (items with current/needed) |
| `GET /api/campaign/status` | `stopGoalMet`, `stopReason`, `goalProgress` |
| Web UI | 🎯 chip + per-goal `current/needed (pct%)` in fuzz/campaign status line |

## Evaluation timing

- **Single fuzz run:** checked after each **new** crash, **after** sidecar/intel/scream-evolution write completes.
- **Campaign:** checked after each run completes (aggregate across all campaign projects). Per-run project goals may still stop an individual run early.

## Optional cluster queue

When `queueTopClustersOnGoal: true`, the top three scream clusters (by score) enqueue pending hypotheses via `HypothesisEngine.EnqueueFromHypothesis` — typically `ReplayLineage` or `MinimizeHold` when lineage sidecars exist. Lightweight; no changes to HuntPolicy or core evolution logic.

## Related

- [ROADMAP_INTELLIGENCE.md](ROADMAP_INTELLIGENCE.md) — Phase B/C campaign goals
- [CRASH_LOGGING.md](CRASH_LOGGING.md) — ScreamScore and hot canister rules
