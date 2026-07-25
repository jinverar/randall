# Fuzzing techniques in Randfuzz

Randall combines **generation** (Sulley-style block models) with **coverage-guided** mutation strategies borrowed from AFL++, libFuzzer, and research fuzzers.

## Built-in mutators

Enable via project YAML `mutators:` or **Fuzz → Case builder** checkboxes. New seeds/dicts: [CASE_BUILDER.md](CASE_BUILDER.md). Custom programs: [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md).

| Mutator | Technique | Origin / inspiration |
|---------|-----------|---------------------|
| `bitflip` | Single-bit flip at random offset | AFL bitflip stage |
| `arith` | Add small delta (-35…+35) to one byte | AFL arith stage |
| `boundary` | Replace byte with 0, 1, 0x7F, 0x80, 0xFF | Classic boundary testing |
| `interesting` | Inject known-dangerous integers at 1/2/4/8-byte alignment | libFuzzer `ExtractAndExecuteOne` |
| `havoc` | Stack 2–N random ops (flip, arith, truncate, expand, insert, duplicate, shuffle) | AFL havoc stage |
| `cyclic` / `pattern` | Metasploit-style cyclic buffer for EIP/RIP offset practice | mona `pattern_create` |
| `dictionary` | Overwrite or insert project tokens | AFL `-x` / Boofuzz `s_string` |
| `splice` | Crossover two corpus inputs at random split | AFL splice / genetic fuzzing |
| `expand` | Append large run (length / buffer stress) | Generation fuzzers |
| `truncate` | Cut input mid-record | Parser state confusion |
| `insert` | Append random blob tail | Tail parser bugs |
| `duplicate` | Repeat a random slice of the seed | AFL chunk duplication |
| `shuffle` | Swap two short spans inside the seed | Local reorder / confusion |

Enable in project YAML:

```yaml
mutators:
  - havoc
  - interesting
  - dictionary
  - splice
  - bitflip
dictionaryFile: dictionaries/fuzz.txt
dictionary:
  - "%s%s%s%s"
  - "hex:DEADBEEF"
fuzz:
  havocDepth: 8
  powerSchedule: true
```

## Dictionary tokens

- Plain UTF-8 strings (escape `\r`, `\n`, `\0`)
- `hex:41414141` for raw bytes
- File: one token per line, `#` comments ignored

Good tokens: format strings (`%s`, `%n`), long runs, nulls, path traversal, magic headers.

## Optional AI seed recipes

Propose starting seeds + dictionary tokens with an LLM (offline from the fuzz loop):

```bash
randall ai seed -c projects/vulnlab.yaml --dry-run
randall ai seed -c projects/vulnlab.yaml --fixture projects/fixtures/ai_seed_fixture.json
```

See [AI_SEED.md](AI_SEED.md).

## Corpus power schedule

When `fuzz.powerSchedule: true` (default), Randall tracks **energy** per corpus entry. Inputs that triggered new DynamoRIO edges get boosted weight — similar to AFL's favor high-performing seeds.

Corpus state: `data/corpus/<target>/corpus_energy.txt`

## Mutator credit (bandit-lite)

When `fuzz.mutatorCredit: true` (default), Randall tracks which **mutators** produce useful outcomes and softly biases random mutator selection toward them — similar in spirit to corpus energy, but for operators instead of seeds.

| Signal | Score term |
|--------|------------|
| New coverage edges | +10 per edge |
| Unique crash (deduped input) | +100 per crash |

**Selection bias:** each mutator gets roulette weight `max(1, floor(score / runs) + 1)`. Cold mutators stay at weight 1 (exploration never drops to zero). Joker and exhaustive modes still override selection when active.

**Persistence**

- Cross-run: `data/corpus/<target>/mutator_credit.txt`
- Per run (when execution log is on): `data/runs/<runId>/mutator_stats.json`

At the end of every fuzz run the CLI prints a mutator leaderboard (runs, edges, unique crashes, score, selection weight). Disable bias but keep stats with `fuzz.mutatorCredit: false`.

```yaml
fuzz:
  mutatorCredit: true
  powerSchedule: true
```

## Mutation-chain learning

When `fuzz.mutatorCredit: true`, Randall also learns **productive mutator sequences** (pairs, triples, and P(next|previous) transitions) from crash lineage and the iteration journal. Cross-iteration ancestry is rebuilt from `parentInputHash` plus each iteration's `mutatorChain` (Joker wrappers are skipped for credit).

| Signal | Score term |
|--------|------------|
| New coverage edges | +10 per edge (same as mutator credit) |
| Unique crash | +100 per crash |

**Bias (light — does not dominate single-mutator credit)**

- ~12% of picks follow P(next|previous) when the prior mutator is known
- Otherwise mutator-credit roulette with up to ~18% transition boost on the next operator
- RandallBrain adds a Why? term for the top chain and may hint the chain tail as `PreferredMutator` when mutator credit also ranks the chain head

**Persistence**

- Cross-run: `data/corpus/<target>/mutator_chains.json` (`pairs`, `triples`, `transitions`, `biasEnabled`)
- Per run (when execution log is on): `data/runs/<runId>/mutator_chains.json`
- End-of-run CLI leaderboard lists top pair/triple chains

Scare Floor intelligence shows **Top chains** chips when data exists. Toggled with the same `fuzz.mutatorCredit` flag (no separate YAML knob).

## RandallBrain (closed-loop hunt steering)

When `fuzz.brain: true` (default), Randall fuses stalk intelligence into **every iteration** — seed corpus bias, mutator pick, and corpus energy — producing an explainable **NextHuntDecision** with Why? terms.

| Signal | Role in brain |
|--------|----------------|
| `frontier.json` gray doors | Top focus when CFG/session forks rank highest |
| `randall-analysis.json` fuzzPriority | Static/patch targets; prefers `dictionary` / `havoc` |
| Oracle findings JSONL | Boosts semantic hunts; prefers `interesting` / `boundary` |
| Mutator credit | Blends with brain mutator preference (62% brain / 38% credit) |
| Mutator chains | Light P(next|previous) bias; top pair/triple in Why? terms |
| Scream clusters | Hot unique screams boost focus; saturated clusters get negative Why? terms |

**Behavior**

- **Default on** — soft no-op when frontier/static/oracle/scream data is missing (baseline AFL-style pick unchanged).
- **Corpus bias** — raises priority-corpus pick rate from 65% up to ~82% when hunting frontiers.
- **Energy** — adds +2…+8 corpus energy after novel coverage / oracle retains when brain is active.
- **Verbose** — `Brain: frontier parse→0x401020 [78] mutator=havoc corpus=82% energy+4 — +78 frontier rank · …`
- **Persistence** — last decision at `data/stalk/<project>/brain_last.json`
- **API** — `GET /api/fuzz/brain?project=<name>` and Scare Floor intelligence `lastBrainDecision`

Disable with:

```yaml
fuzz:
  brain: false
```

Populate signals: `randall stalk ghidra-analyze` (or manual export) → short fuzz with coverage → `randall stalk frontier -p <project>` → oracle/scream history from crashes.

### RandallDecision API mapping

External docs may refer to a central **`RandallDecision`** object. On disk and API this is the **`decision`** field on `BrainDecisionSnapshotDto` — a stable alias of **`NextHuntDecision`**:

| RandallDecision | NextHuntDecision / brain |
|-----------------|--------------------------|
| `inputId` | `{focusKind}:{focusLabel}` (e.g. `frontier:parse_input→0x401020`) |
| `score` | `scoreBreakdown.total` or `focusScore` |
| `reasons.*` | `whyTerms[]` normalized (`frontierProximity`, `staticTargetPriority`, `mutationSuccess`, `crashNovelty`, …) |
| `actions.preferredMutator` | `preferredMutator` |
| `actions.targetFunction` | `focusLabel` when kind is frontier/static/patch/scream |
| `actions.corpusPriorityBias` | `corpusPriorityBias` (0.65–0.88) |
| `actions.energyMultiplier` | `1 + recommendedEnergyBoost/4` |
| `actions.retainFocus` | `active` |

Endpoints: `GET /api/fuzz/brain?project=<name>` · Scare Floor **lastBrainDecision** · `data/stalk/<project>/brain_last.json`.

## Session flows (stateful TCP)

Random single-command fuzzing misses bugs that need a **probe** first (banner, STAT, GMON keepalive):

```yaml
sessionFlows:
  - name: stat_trun
    steps:
      - STAT_TRUN    # valid probe
      - TRUN         # mutated on last step only
fuzz:
  sessionFlowBias: 0.25   # 25% of iterations use a flow
```

All steps run on one TCP connection; only the **last** step is mutated.

## Field-aware model mutation

Block models (`docs/MODEL.md`) target named fields. Length fields get ~25% bias with off-by-one and max-integer tricks — classic **length-prefix** vulnerability class.

## Crash clustering

`GET /api/crashes/clusters` groups crashes by hash prefix + length bucket — dedupe triage before Ghidra export.

## Coverage-guided mode

Set `coverageGuided: true` + `DYNAMORIO_HOME`. Randall parses drcov traces, registers new edges, and prioritizes inputs that expand the frontier (PaiMei / AFL-style stalking).

## Oracle engine + Bug Hunter

Coverage finds new code. The **Oracle engine** judges **logic / auth / state / semantic-integer / structure / resource** bugs without needing a crash ([ORACLES.md](ORACLES.md)). The **Bug Hunter** analyzes AI/human sources and suggests which rules/dicts to arm ([BUG_HUNTER.md](BUG_HUNTER.md)). Opt in per project:

```yaml
oracles:
  enabled: true
  auth:
    - { id: no-ok-pre-auth, type: forbidUntil, forbidResponse: "RPC_OK", untilResponse: "BIND_ACK" }
  state:
    - { id: order, type: commandRequiresPrior, forCommand: REQUEST, priorCommand: BIND, priorResponse: BIND_ACK }
```

Seed recipes + mutators still own most memory-corruption hunting. See [ORACLES.md](ORACLES.md) · [AI_SEED.md](AI_SEED.md).  
Findings: `randall oracles -p <project>`.

## External engines (AFL++ / honggfuzz)

For market-grade coverage throughput on an authorized file/harness target:

```yaml
fuzz:
  engine: aflpp          # or honggfuzz | randall (default)
  engineTimeoutSec: 3600
  engineExtraArgs: ""    # e.g. -Q for QEMU mode
```

See [ENGINE_ADAPTERS.md](ENGINE_ADAPTERS.md). Crashes sync into the usual scream-canister paths.

## Research references

- **AFL++** — havoc stages, splice, power schedules, dictionaries ([github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus))
- **libFuzzer** — interesting value tables for integers
- **Sulley / Boofuzz** — block-based generation and session graphs
- **CANAPE** — MITM capture before fuzz (Randall Proxy tab)
- **PaiMei** — coverage novelty and crash stalking

## Leg 2 exercise

1. Dry-run with havoc only: `randall fuzz -c projects/vulnserver.yaml --dry-run`
2. Compare `bitflip` vs `interesting` on a length-prefixed file model
3. Add three custom dictionary tokens from your target's protocol
4. Review crash clusters in the web UI before exporting triage bundles

## Verbose console (`--verbose` / `fuzz.verbose`)

```bash
randall fuzz -c projects/vulnturret.yaml --verbose --max-iterations 40
```

Or in YAML:

```yaml
fuzz:
  verbose: true
```

Prints engine banner, per-finding Oracle lines, Magician spell details, Joker play/finish, coverage edges each iteration, longer TX hex, and INTEL blocks even on deduped crashes.
