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
