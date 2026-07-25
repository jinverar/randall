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

### Install Ghidra (optional app)

Randfuzz does **not** require the Ghidra GUI to fuzz or export `.py` scripts. For interactive RE:

**Windows**

```powershell
# Ghidra app only (~560 MB + JDK 21)
powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra.ps1

# Ghidra + Dragon Dance extension (clone/build; needs Gradle 8.5+)
powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra.ps1 -DragonDance

# Or extensions alone when Ghidra is already under tools/ghidra-app
powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-extensions.ps1

# Umbrella lab installer
powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1 -Ghidra -GhidraExtensions
```

Installs Ghidra to `tools/ghidra-app/` (gitignored). Dragon Dance is built from upstream
[`0ffffffffh/dragondance`](https://github.com/0ffffffffh/dragondance) @
`19e2ecefe4a29e682dd571454cef05743d1f409d`, cached under `tools/ghidra-extensions/dist/`, and
extracted into `<ghidra>/Ghidra/Extensions/` (same as **File → Install Extensions**).

Needs **JDK 21** (`winget install Microsoft.OpenJDK.21`) and **Gradle ≥ 8.5** for Ghidra 12.x
(`winget install Gradle.Gradle`). Manual Ghidra zip: [Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases) → `ghidra_*_PUBLIC_*.zip`.

**Linux**

Install Ghidra + JDK 21 from your distro, or extract the PUBLIC zip under `tools/ghidra-app/` and set `GHIDRA_INSTALL_DIR` if needed. Build Dragon Dance with `gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR buildExtension` from a clone of the repo (same SHA above), then **File → Install Extensions** with the zip from `dist/`.

Doctor: `randall doctor` reports `ghidra` and `java` readiness.

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

### Install Dragon Dance

| Step | Windows (automated) | Manual (any OS) |
|------|---------------------|-----------------|
| Prereqs | Ghidra in `tools/ghidra-app`, JDK 21, Gradle ≥ 8.5 | Same |
| Build | `.\scripts\install-ghidra-extensions.ps1` | Clone [dragondance](https://github.com/0ffffffffh/dragondance), checkout `19e2ecefe4a29e682dd571454cef05743d1f409d`, `gradle -PGHIDRA_INSTALL_DIR=<ghidra> buildExtension` |
| Install | Script extracts zip into `<ghidra>/Ghidra/Extensions/` | Ghidra → **File → Install Extensions** → green **+** → select `dist/*.zip` → restart |
| Enable | CodeBrowser → **File → Configure** → plug icon → enable **Dragon Dance** | Same |
| Import | **Window → Dragon Dance** → add `traces-binary/*.log` | Same |

**Note:** upstream Dragon Dance last shipped a pre-built zip for Ghidra 9.0.2 (2019). Ghidra 12 builds
from source; if `gradle buildExtension` fails on API drift, use Randfuzz Script Manager scripts (primary)
or [Cartographer](#other-ghidra-plugins-document-only) (maintained drcov plugin).

Pinned upstream SHA: `19e2ecefe4a29e682dd571454cef05743d1f409d` (merge VelocityRa patch, 2021-01-02).

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

1. Open the module binary → **Window → Dragon Dance** → import `traces-binary/*.log` or packed `binary_*.log`.
2. Use DD for intensity / intersect / distinct; use Randfuzz scripts for layer + crash-novel packs.

`ghidra-pack` and crash export copy the newest binary sidecars when present and document them in
`DRAGON_DANCE.txt`.

TCP long-lived targets: use `capture-binary` with a file seed that exercises the path, or a manual
`drrun -t drcov -logdir OUT -- target …` (no `-dump_text`).

---

## Other Ghidra plugins (document-only)

Curated extensions useful alongside Randfuzz stalking. **Primary path remains** `tools/ghidra/` Script
Manager scripts; these are optional RE accelerators.

| Plugin | What it does | Install difficulty | Randfuzz fit | Recommendation |
|--------|--------------|-------------------|--------------|----------------|
| **[Dragon Dance](https://github.com/0ffffffffh/dragondance)** | Binary drcov / Pin (ddph) import; intensity; intersect/diff/distinct/sum; fix-ups for missed disasm | **Medium** — build from source for Ghidra 12 (`install-ghidra-extensions.ps1`) | **High** — pairs with `captureBinaryDrcov` / `stalk capture-binary` sidecars | **Integrate** (installer + docs) |
| **[Cartographer](https://github.com/nccgroup/Cartographer)** | drcov + EZCOV; per-function coverage %; expression parser (`& \| ^ -`) for differential coverage | **Easy** — release zip per Ghidra minor ([releases](https://github.com/nccgroup/Cartographer/releases)); drcov v1–4 | **High** — modern drcov, set ops like DD; no Randfuzz-specific wiring | **Document** — best fallback if DD build fails on Ghidra 12 |
| **[flounderK/ghidra_scripts](https://github.com/flounderK/ghidra_scripts)** (`afl_coverage_visualizer.py`) | AFL++ SanCov PC-guard or QEMU trace → highlight visited/unvisited BBs | **Easy** — Script Manager script | **Medium** — only if you compile targets with `afl-clang-fast` / AFL++ showmap | **Document** — orthogonal to DynamoRIO/drcov path |
| **[BSim](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs/GhidraClass/BSim)** (built-in) | Decompiler feature-vector similarity across binaries (library ID, stripped firmware) | **Hard** — enable plugin + PostgreSQL/Elasticsearch DB for scale | **Low** for coverage — useful for naming/lib matching after a crash, not stalk layers | **Document** — RE enrichment, not coverage |
| **Lighthouse** (IDA/Binary Ninja) | Industry-standard coverage UI for IDA | N/A in Ghidra | Reference only — DD/Cartographer fill the Ghidra niche | **Document** — mention for IDA users |

**Differential coverage workflow:** Randfuzz stalk layers + `RandfuzzImportLayers.py` (baseline → fuzzed → fuzzier); for binary logs use DD/Cartographer set ops on two `capture-binary` runs or a crash vs baseline sidecar pair from `ghidra-pack`.

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
