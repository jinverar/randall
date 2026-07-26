# In-Randall stalk map — RE for fuzzing

Randall does **enough reverse engineering to stalk itself**: sections, imports, and strings
from the target PE/ELF, overlaid on missed-block gaps. It does **not** replace Ghidra.

```text
coverage edges + optional BB inventory
        ↓
missed / frontier / baseline-only gaps
        ↓
BinarySurfaceMap (PE/ELF strings + imports + sections)
        ↓
hotspots ranked by string/import adjacency
        ↓
revise seeds / dictionary / mutators  →  remeasure
        ↓
(optional) Ghidra / Dragon Dance for deep dive
```

## CLI

```bash
randall stalk map -p <project> [-c projects/<project>.yaml] [--binary /path/to/target] [--limit 40]
```

Resolves the binary from (in order): `--binary`, `-c` YAML `target.executable`, project YAML by name, then a recent drcov module path.

## UI / API

- **Stalking bugs → Stalk map**
- `GET /api/stalking/{project}/map?limit=40&binary=`

## What you get

| Surface | Use |
|---------|-----|
| Interesting imports (`memcpy`, `recv`, …) | Bias length/framed mutators |
| Hot strings (errors, protocol tokens, …) | Dictionary / Scare Floor seeds |
| Hotspots (missed BB near string or import) | Highest-ROI gaps before opening Ghidra |

## Honest limits

- No disassembly UI, no decompiler, no full CFG
- Import thunk RVAs are PE IAT-oriented; ELF exposes `DT_NEEDED` + dynstr needles
- String → code xrefs are **proximity**, not real cross-references

For colored BB deep dives: [GHIDRA_INTEGRATION.md](GHIDRA_INTEGRATION.md).
For the PDF-style loop: [HOWTO_STALK_IDA_GHIDRA.md](HOWTO_STALK_IDA_GHIDRA.md).

## Target gravity (reachability pressure)

Complements frontier gray doors with **pull toward dangerous sinks** — strcpy-like calls,
allocators, Ghidra-marked dangerous sites, and oracle near-misses:

```text
TargetGravity ≈ risk × unexploredness / distance
```

(from nearest covered basic block toward each interesting sink)

```bash
randall stalk gravity -p <project> [--limit 40] [--json] [--binary path]
```

Persisted to `data/stalk/<project>/target_gravity.json`. The stalk map lightly boosts hotspots
when a well address overlaps a missed block. Brain adds optional `gravity` hunt candidates;
Hunt Policy may read aggregate pressure when scoring frontier/static picks (no conflict with
hypothesis or campaign goals).

API: `GET /api/stalking/{project}/gravity?limit=40`

## Frontier engine (gray doors)

When `randall-analysis.json` and coverage edges exist, Randall scores **unexplored CFG successors**
(the gray branches between covered and missed blocks):

```text
FrontierScore ≈ CFGDistance × Rarity × UnseenSuccessorCount × SinkProximity
```

Persisted to `data/stalk/<project>/frontier.json`. Without Ghidra static map, session-graph forks
and edge-gap heuristics still produce ranked frontiers.

```bash
randall stalk frontier -p <project> [--limit 40] [--json]
randall oracles -p <project>          # also prints top gray doors when analysis exists
```

UI: **Stalking bugs → Missed blocks** shows a **Frontier** score column when `frontier.json` is present.
API: `GET /api/stalking/{project}/frontier?limit=40`
