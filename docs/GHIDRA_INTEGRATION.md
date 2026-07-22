# Ghidra integration — why Randfuzz exists for RE

Randfuzz’s job is not only to crash targets. It is to **stalk code**, then put that map under
your eyes in a reverse-engineering tool so you can see **what ran, what is still dark, and where
the crash path left the baseline**.

This document is the product path for **Ghidra**. IDA remains supported via IDC / Dynapstalker;
Ghidra is first-class here because it is free, scriptable, and pairs with optional Dragon Dance.

**Tutorial:** [HOWTO_STALK_IDA_GHIDRA.md](HOWTO_STALK_IDA_GHIDRA.md)

---

## Two paths (be clear)

| Path | What it is | When to use |
|------|------------|-------------|
| **Randfuzz → Ghidra scripts** (primary) | Our Script Manager Python paints full BBs from text edges / layers / crash packs | Default — works with Randfuzz’s `-dump_text` drcov |
| **Dragon Dance** (optional plugin) | Third-party Ghidra extension; imports **binary** drcov; intensity + set ops | When you want DD’s GUI / intersect / intensity on a binary log |

Randfuzz **does not ship Dragon Dance**. We emit honest notes (`DRAGON_DANCE.txt`) and keep
compatibility optional. Claiming “import `sample.drcov.log` into Dragon Dance” was wrong when
that file is text — fixed.

---

## Primary workflow (Randfuzz integration)

```text
coverageGuided / drcov -dump_text
        ↓
stalk layers (baseline → fuzzed → fuzzier)  +  crash packs
        ↓
ghidra_import.py / *_stalk_layers.py  (Script Manager)
        ↓
colored BBs in CodeBrowser · plain = missed
        ↓
revise fuzzer · randall stalk missed · repeat
```

### From stalk layers

```bash
randall stalk export -p <project> --format ghidra -o data/stalk/<project>/export
# Ghidra → Script Manager → run *_stalk_layers.py (oldest colors win)
```

### From a crash (the scream → RE handoff)

```bash
randall export -i <crash-guid>
# → data/exports/<id>/
#    ghidra_import.py   paints baseline-shared vs crash-novel, goTo focus RVA
#    coverage_edges.txt modules.txt GHIDRA_README.txt
```

### One-shot Dynapstalker-style

```bash
randall stalk dynapstalker fuzz.log myapp.exe out.py --format ghidra --color 0x00ff00
```

### Installable scripts

Repo folder [`tools/ghidra/`](../tools/ghidra/README.md):

- `RandfuzzImportEdges.py` — pick any `coverage_edges.txt`
- `RandfuzzImportLayers.py` — run a generated export script

Add that directory in Script Manager → Script Directories.

---

## What the scripts do (engine)

Implemented in `GhidraScriptBuilder`:

- `imageBase + drcov RVA` addressing
- Paint **full BB size** (`start` .. `start+size-1`), not a single pixel
- Skip already-colored addresses (baseline wins when loaded first)
- Crash pack: split **shared-with-baseline** vs **crash-novel**; jump to first novel RVA
- Emit `modules.txt` from the drcov Module Table when present

---

## Optional: Dragon Dance

1. Install the [Dragon Dance](https://github.com/0ffffffffh/dragondance) extension in Ghidra.
2. Capture **binary** coverage (note: **no** `-dump_text`):

```bash
drrun -t drcov -logdir OUT -- /path/to/target args...
# → OUT/drcov.target.*.proc.log  (binary)
```

3. Open the binary in Ghidra → Dragon Dance window → import that log.
4. Use DD for intensity / intersect / scripting; use Randfuzz scripts for layer + crash-novel packs.

You can run both on the same session: Randfuzz colors for stalk layers, DD for a binary campaign log.

---

## CLI / UI map

| Action | Where |
|--------|--------|
| Export layers to Ghidra | Stalking bugs → **Ghidra** · `stalk export --format ghidra` |
| Crash → Ghidra pack | Crashes → Export · `randall export -i <guid>` |
| Missed blocks + ideas | Stalking bugs → Missed · `stalk missed -p P` |
| Pack scripts into export dir | `randall stalk ghidra-pack -p P` |

---

## Roadmap (honest)

Done now: real scripts, crash novel focus, tools/ghidra installers, docs that match reality.

Later (not blocking):

- Optional dual-capture binary drcov sidecar during fuzz for one-click DD
- Headless Ghidra analyze+color in CI
- Richer multi-module rebase when image base ≠ logged module start
