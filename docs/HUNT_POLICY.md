# Hunt Policy (Phase B — campaign-ready)

Consolidates intelligence signals into one explainable **HuntValue** and an execution mode (lineage breed vs havoc vs Joker timing). No LLM; research-only steering.

## Formula

```text
HuntValue ≈ CoverageNovelty + StaticTargetValue + OracleInterestingness
          + CrashProgression/Momentum + MutationSuccess + FrontierDistance
          + TargetGravity − ExecutionCost − DuplicatePenalty
```

Each term category carries a **feedback-adapted weight** in `[0.5, 2.0]` (default `1.0`), persisted per project in `data/stalk/<project>/hunt_policy_weights.json`.

## Execution modes

| Mode | When |
|------|------|
| `LineageBreed` | Warming scream families (momentum ≥ 40) or strong lineage chains |
| `HavocExplore` | Frontier / static / gravity gaps dominate (HuntValue ≥ 32–35) |
| `JokerInvoke` | Low yield + high coverage, or ≥ 2 stagnant/saturated scream families |
| `Baseline` | Default mutator-credit steering |

### Mode hysteresis

Modes do not flip every iteration. When the raw scorer would switch:

- **LineageBreed → JokerInvoke** requires HuntValue &lt; 22 **and** ≥ 3 stagnant families (otherwise HOLD).
- **JokerInvoke → LineageBreed** requires momentum ≥ 52 on a warming family.
- **Baseline ↔ HavocExplore** sticks unless HuntValue crosses the havoc band by ≥ 8 points.

HOLD decisions appear in `hunt_policy_last.json` under `policy.actions`.

## Explicit actions

Each iteration emits zero or more actions in `hunt_policy_last.json`:

| Kind | Meaning |
|------|---------|
| `Boost` | Increase focus (gravity pressure, warming scream, debugger influence) |
| `Reduce` | Lower weight (low-ROI mutator, coverage exhaustion) |
| `Deprioritize` | Push to back (saturated scream, chronic mutator failure) |
| `Hold` | Mode hysteresis — keep previous execution mode |

Example verbose log:

```text
Hunt policy: LineageBreed [62] joker=5% chain=seed→splice
  · boost:scream:warming (2 warming familie(s))
  · hold:mode:LineageBreed (hysteresis — warming lineage still active)
  — +18 crash progression · +6 lineage generation
```

## Target gravity integration

When `data/stalk/<project>/target_gravity.json` exists:

- **Frontier / static** candidates get a `target gravity` term (threshold scales with aggregate pressure).
- **Gravity** candidates match wells by label and receive `gravity well match` + `gravity aggregate` terms.
- High aggregate pressure (≥ 55) adds a field-wide `target gravity field` term even when gravity is not the top focus.

Run `randall stalk map` / gravity scoring to populate the file; see [STALK_MAP.md](STALK_MAP.md).

## Feedback loop

Every **25 iterations** (`HuntPolicyEngine.FeedbackInterval`):

1. Accumulate predicted positive term points by category (scream, gravity, frontier, static, oracle, mutator).
2. Compare against observed new edges + unique crashes in the window.
3. If predicted ≥ 8 and **no yield** → weight − 0.05 for that category.
4. If predicted ≥ 8 and **yield observed** → weight + 0.05.
5. Clamp all weights to `[0.5, 2.0]` and persist.

Recent windows are kept in `hunt_policy_weights.json` for inspection.

## Mutator ROI and floors

Low-ROI mutators are penalized aggressively via `execution cost` in HuntValue and selection weight in `MutatorCreditTracker`:

| Signal | Hunt policy | Mutator credit |
|--------|-------------|----------------|
| `staleRuns ≥ 3` + no edges | execution cost | weight − up to 8 |
| `failureRate ≥ 0.75` (≥ 5 runs) | execution cost | weight − up to 4 |
| `failureRate ≥ 0.90` + stale ≥ 6 | DEPRIORITIZE | extra − 2 |

**Floor:** selection weight never drops below **1** (`MutatorCreditTracker.MinSelectionWeightFloor`). Mutators are deprioritized, not removed — a cold mutator can still be picked and recover credit on yield.

## Artifacts

| File | Contents |
|------|----------|
| `hunt_policy_last.json` | Last decision: HuntValue, mode, terms, actions, joker chance, lineage chain |
| `hunt_policy_weights.json` | Per-category weights, feedback windows, last adapt iteration |
| `brain_last.json` | Brain fusion snapshot (includes `huntPolicy`) |

## API / UI

- Verbose fuzz: `[hunt policy] Hunt policy: …`
- Scare Floor brain strip shows Hunt value + term chips
- `GET /api/fuzz/brain` and `brain-decision` expose `huntPolicy` including `actions`

See also [ROADMAP_INTELLIGENCE.md](ROADMAP_INTELLIGENCE.md) Phase B.
