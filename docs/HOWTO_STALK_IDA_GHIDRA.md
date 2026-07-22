# How to: stalk bugs with IDA Pro and Ghidra

End-to-end tutorial for the **Dynapstalker / PaiMei** workflow inside Randfuzz:

> You cannot find bugs in code you do not execute.  
> Color what baseline + fuzzer hit → remaining plain/white blocks are **missed** → revise the fuzzer → remeasure.

**Related:** [STALK_LOOP.md](STALK_LOOP.md) · [STALKING.md](STALKING.md) · [HOWTO_STALK_GENERIC_APP.md](HOWTO_STALK_GENERIC_APP.md)

---

## What you need

| Need | Notes |
|------|--------|
| Lab machine with the target binary | Prefer a VM snapshot |
| DynamoRIO (`drrun` + `drcov`) | `scripts/install-dynamorio.ps1` / `.sh`, or `DYNAMORIO_HOME` |
| Randfuzz on that same machine | `randall serve` / console at `http://127.0.0.1:5000` |
| **IDA Pro** and/or **Ghidra** | Free IDA demo works for the PDF-style exercise; Ghidra is fully free |
| A Target profile | Lab target (e.g. `vulnserver`) or your app ([HOWTO_STALK_GENERIC_APP.md](HOWTO_STALK_GENERIC_APP.md)) |

---

## The loop (same for IDA and Ghidra)

```text
1. Baseline under drcov   → yellow/cyan colors
2. Fuzz under drcov       → green colors (only new / still-uncolored)
3. Open binary in IDA or Ghidra
4. Load OLDEST script first, then newer ones
5. Plain / white blocks = missed
6. Inspect interesting missed (string copy, memcpy / rep movs*, error paths)
7. Revise seeds / dicts / mutators → fuzz again → new color layer
8. randall stalk missed -p <project> for in-product tips
```

Default layer colors (IDA BGR): baseline ≈ `0x00FFFF` (yellow/cyan), fuzzed ≈ `0x00FF00` (green).

---

## Part A — Capture coverage in Randfuzz

### A1. Baseline (normal use)

1. Start the target (Fuzz → Lab servers / Target Runtime).
2. Prefer `fuzz.coverageGuided: true` and DynamoRIO installed.
3. **Use the app normally** for ~1 minute (browser happy path, valid protocol commands, open a good file, trigger a 404 / error if relevant).
4. Stop the process so drcov flushes a log, **or** rely on corpus edges after a short valid-seed run.
5. **Stalking bugs**:
   - Project = your target  
   - Tag = **baseline**  
   - Paste **drcov log path** if you have one, else **From corpus edges**  
   - **Record layer**

### A2. Fuzzed pass

1. Run a campaign (Scare Floor / Campaign) with mutations.
2. **Stalking bugs** → Tag = **fuzzed** → **From corpus edges** (or paste the new drcov log).
3. Open **Compare** / **Block map** / **Missed blocks** in the UI.

### A3. Optional — raw drcov without layers

If you already have two `-dump_text` logs from class-style manual runs:

```bash
# IDA
randall stalk dynapstalker savant-base.log savant.exe savant-base.idc --color 0x00ffff
randall stalk dynapstalker savant-fuzz.log savant.exe savant-fuzz.idc --color 0x00ff00

# Ghidra (.py inferred, or --format ghidra)
randall stalk dynapstalker savant-base.log savant.exe savant-base.py --format ghidra --color 0x00ffff
randall stalk dynapstalker savant-fuzz.log savant.exe savant-fuzz.py --format ghidra --color 0x00ff00
```

Requires logs produced with **`-dump_text`**.

---

## Part B — Export color scripts from stalk layers

From the lab console or CLI (after A1 + A2):

**UI:** Stalking bugs → **IDA IDC** / **Ghidra**

**CLI:**

```bash
randall stalk export -p <project> --format idc    -o data/stalk/<project>/export
randall stalk export -p <project> --format ghidra -o data/stalk/<project>/export
```

Scripts only paint **still-uncolored** items so earlier (baseline) colors win when you load oldest first.

---

## Part C — IDA Pro

### C1. Open the binary

1. IDA → **New** → select the **same** module you filtered (e.g. `savant.exe` / your app).
2. Wait for auto-analysis to finish.
3. Prefer loading with a base that matches how you will navigate (PE preferred image base is fine).

### C2. Color hit blocks

1. **File → Script file…**
2. Load the **oldest** script first (`*baseline*.idc` or `savant-base.idc`).
3. Load the fuzzed script second (`*fuzzed*.idc` / green).
4. Optional later rounds: fuzzier / crash scripts with new colors.

### C3. Find missed (white) blocks

1. Open the function graph / proximity view for an interesting area.
2. **White** (default) blocks were hit by **neither** baseline nor fuzzer — that is the PDF definition of missed.
3. Yellow/cyan ≈ baseline; green ≈ fuzzer-only or later layers (depending on load order).
4. Press **G** to jump to addresses from **Stalking bugs → Missed blocks** or Compare.

### C4. What to look for in white blocks

- String APIs / manual copies (`strcpy`, `sprintf`, `rep movs*`)
- Error / auth / size gates (`cmp` / `test` / `jz` that skip the white region)
- Handlers your session graph never took

Then revise the fuzzer (Scare Floor seeds, dictionary, mutators, session steps) and remeasure with a new color.

---

## Part D — Ghidra

**Product path (why this fuzzer):** [GHIDRA_INTEGRATION.md](GHIDRA_INTEGRATION.md) — first-class Randfuzz scripts; optional Dragon Dance via `captureBinaryDrcov` / `randall stalk capture-binary`.

### D0. Install Randfuzz scripts (once)

1. Script Manager → **Script Directories** → add repo `tools/ghidra/`
2. You get **Analysis → Randfuzz → Import coverage edges** / **Run export script**

### D1. Open the binary

1. Ghidra → import the **same** module binary.
2. Open in CodeBrowser; finish analysis.
3. Randfuzz scripts use **`imageBase + drcov RVA`** — open the module that matches the process filter, not a random DLL.

### D2. Color hit blocks

1. **Window → Script Manager**
2. Run the **oldest** script first (`*_stalk_layers.py` from layer export, or `savant-base.py`).
3. Run the fuzzed script second.
4. Listing / Graph / Function Graph: colored = hit; **plain / default background = missed**.

### D3. Find missed (plain) blocks

1. Navigate with the addresses from **Missed blocks** (RVAs relative to the module — Ghidra shows VA = base + RVA).
2. Same review as IDA: string/memcpy surfaces, untaken branches, protocol error paths.
3. Optional: Dragon Dance / `coverage_edges.txt` from a crash triage bundle for crash-path focus.

### D4. Layer export vs one-shot

| Path | When |
|------|------|
| **Stalking bugs → Ghidra** / `stalk export --format ghidra` | You already recorded baseline + fuzzed layers in Randfuzz |
| `stalk dynapstalker … out.py --format ghidra` | You have raw `drcov -dump_text` logs (class exercise style) |

---

## Part E — In-product missed guidance

After layers exist:

```bash
randall stalk missed -p <project>
```

Or **Stalking bugs → Missed blocks**: categories (baseline-only, frontier gap, never-hit, …), *why missed*, and ranked fuzz ideas.

Optional true never-hit without staring at the CFG:

```bash
randall stalk inventory -p <project> --import path/to/blocks.txt
randall stalk missed -p <project>
```

---

## Quick reference

| Goal | Command / UI |
|------|----------------|
| Record baseline / fuzzed | Stalking bugs → Add layer |
| Export IDA | `randall stalk export -p P --format idc` |
| Export Ghidra | `randall stalk export -p P --format ghidra` |
| One-shot IDA | `randall stalk dynapstalker LOG EXE out.idc --color 0x00ffff` |
| One-shot Ghidra | `randall stalk dynapstalker LOG EXE out.py --format ghidra --color 0x00ffff` |
| Missed + ideas | `randall stalk missed -p P` |
| Load order | **Oldest script first** (both tools) |
| Missed definition | Still white (IDA) / still uncolored (Ghidra) |

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| 0 blocks in export | DynamoRIO not attached / no `-dump_text` / layer recorded before any edges |
| Ghidra colors land in the wrong place | Wrong binary open, or image base mismatch — open the filtered module |
| Fuzzed color overwrote baseline | Load order wrong, or old script without white-only guard — use current Randfuzz export |
| `dynapstalker` finds 0 edges | Process name must appear in the drcov **Module Table** (e.g. `savant.exe`) |
| Linux edges always 0 | Install DynamoRIO (`scripts/install-dynamorio.sh`) or accept corpus-novelty until SanCov lands |
