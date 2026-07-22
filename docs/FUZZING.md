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

## Corpus power schedule

When `fuzz.powerSchedule: true` (default), Randall tracks **energy** per corpus entry. Inputs that triggered new DynamoRIO edges get boosted weight — similar to AFL's favor high-performing seeds.

Corpus state: `data/corpus/<target>/corpus_energy.txt`

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

## Hybrid semantic oracles

Coverage finds new code; oracles catch **logic / auth / state / semantic-integer / structure / resource** bugs without needing a crash — the high-value surface on memory-safe targets. Opt in per project:

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
