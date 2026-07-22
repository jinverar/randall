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

Randfuzz **does not ship Dragon Dance**. We capture optional binary sidecars and emit honest notes
(`DRAGON_DANCE.txt`). Claiming “import `sample.drcov.log` into Dragon Dance” was wrong when
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
colored BBs + bookmarks in CodeBrowser · plain = missed
        ↓
revise fuzzer · randall stalk missed · repeat
```

### From stalk layers

```bash
randall stalk export -p <project> --format ghidra -o data/stalk/<project>/export
# or one-shot pack (scripts + Dragon Dance sidecars when present):
randall stalk ghidra-pack -p <project>
# Ghidra → Script Manager → run *_stalk_layers.py (oldest colors win)
```

### From a crash (the scream → RE handoff)

```bash
randall export -i <crash-guid>
# → data/exports/<id>/
#    ghidra_import.py   paints baseline-shared vs crash-novel, bookmarks + goTo focus RVA
#    coverage_edges.txt modules.txt GHIDRA_README.txt
#    binary_*.log       when captureBinaryDrcov / capture-binary was used
```

### One-shot Dynapstalker-style

```bash
randall stalk dynapstalker fuzz.log myapp.exe out.py --format ghidra --color 0x00ff00
```

### Installable scripts

Repo folder [`tools/ghidra/`](../tools/ghidra/README.md):

- `RandfuzzImportEdges.py` — pick any `coverage_edges.txt` (honors sibling `modules.txt`)
- `RandfuzzImportLayers.py` — run a generated export script

Add that directory in Script Manager → Script Directories.

---

## What the scripts do (engine)

Implemented in `GhidraScriptBuilder`:

- `imageBase + drcov RVA` addressing
- Paint **full BB size** (`start` .. `start+size-1`), not a single pixel
- Skip already-colored addresses (baseline wins when loaded first)
- Filter blocks to the **open program** when `modules.txt` / module table matches the binary name
- Warn when preferred module base ≠ Ghidra `imageBase` (still uses `imageBase+RVA`)
- Crash pack: split **shared-with-baseline** vs **crash-novel**; bookmark + jump to focus RVA
- Emit `modules.txt` as `id → path → start → end` when the drcov Module Table has bases

---

## Optional: Dragon Dance (binary sidecar)

Dragon Dance needs **binary** coverage logs. Randfuzz’s fuzz loop keeps `-dump_text` for our parser.

### Auto during fuzz (file / harness)

```yaml
fuzz:
  coverageGuided: true
  captureBinaryDrcov: true   # on novel (and crash) → data/corpus/<project>/traces-binary/
```

### One-shot CLI

```bash
randall stalk capture-binary -p <project> [-i seed.bin] [-o dir]
# → corpus/traces-binary/drcov.*.proc.log  (binary)
```

### Import in Ghidra

1. Install the [Dragon Dance](https://github.com/0ffffffffh/dragondance) extension.
2. Open the module binary → Dragon Dance window → import `traces-binary/*.log` or packed `binary_*.log`.
3. Use DD for intensity / intersect; use Randfuzz scripts for layer + crash-novel packs.

`ghidra-pack` and crash export copy the newest binary sidecars when present and document them in
`DRAGON_DANCE.txt`.

TCP long-lived targets: use `capture-binary` with a file seed that exercises the path, or a manual
`drrun -t drcov -logdir OUT -- target …` (no `-dump_text`).

---

## CLI / UI map

| Action | Where |
|--------|--------|
| Export layers to Ghidra | Stalking bugs → **Ghidra** · `stalk export --format ghidra` |
| Full Ghidra pack | `randall stalk ghidra-pack -p P` |
| Binary drcov for DD | `randall stalk capture-binary -p P` · YAML `captureBinaryDrcov` |
| Crash → Ghidra pack | Crashes → Export · `randall export -i <guid>` |
| Missed blocks + ideas | Stalking bugs → Missed · `stalk missed -p P` |

---

## Roadmap (honest)

Done now:

- Real Script Manager importers (layers, crash novel, tools/ghidra)
- Module table start/end → `modules.txt` + open-program filter
- Focus bookmarks + goTo
- Optional dual-capture binary drcov sidecar + `capture-binary` CLI
- Docs that match text vs binary reality

**In-Randall stalk map** (no Ghidra required for first pass): [STALK_MAP.md](STALK_MAP.md) —
PE/ELF strings/imports overlaid on missed blocks.

Later (not blocking):

- Headless Ghidra analyze+color in CI
- TCP auto binary sidecar without a file seed
