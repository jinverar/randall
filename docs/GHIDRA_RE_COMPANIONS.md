# Ghidra RE companions (document + optional install)

Randfuzz's **primary** Ghidra path is Script Manager importers under [`tools/ghidra/`](../tools/ghidra/README.md) plus headless `randall stalk ghidra-analyze`. These third-party extensions are **optional accelerators** — like [BinExport](GHIDRA_INTEGRATION.md#companion-tools-binexport-bindiff-patch-hunt), they are not required to fuzz or export coverage.

---

## Curated companions

| Extension | Role | Randfuzz fit | Install |
|-----------|------|--------------|---------|
| **[BinExport](https://github.com/google/binexport)** | Export `.BinExport` for BinDiff / JSON diff merge | Patch-hunt `stalk ghidra-diff` | `scripts/install-binexport.ps1` |
| **[GhidraMCP](https://github.com/bethington/ghidra-mcp)** | Live MCP/HTTP queries (imports, decompile, debugger) | `randall ghidra mcp …` | `scripts/install-ghidra-mcp.ps1` |
| **[GhidrAssist](https://github.com/jtang613/GhidrAssist)** | LLM-assisted renaming, comment, and analysis helpers in Ghidra | RE enrichment after crash handoff | Document + optional script below |
| **[C++ Class Analyzer](https://github.com/vic4key/Class-Analyzer)** | Recover C++ classes/vtables from RTTI and xref patterns | Naming + structure recovery on C++ targets | Document + optional script below |
| **Dragon Dance / Cartographer** | Binary drcov coverage UI | Stalk binary sidecars | [GHIDRA_INTEGRATION.md](GHIDRA_INTEGRATION.md) |

Randfuzz does **not** invoke GhidrAssist or Class Analyzer from the fuzz loop. Use them manually in Ghidra after importing a crash pack or opening the target binary.

---

## GhidrAssist (LLM-assisted RE)

**What it does:** Ghidra plugin that connects to an LLM provider for function summarization, variable renaming suggestions, and comment generation inside the CodeBrowser.

**When to use with Randfuzz:**

1. Fuzz → crash → `randall export -i <guid>` or `stalk ghidra-pack`
2. Open binary + run `ghidra_import.py` / stalk layers
3. Enable GhidrAssist → ask for summaries on **high `fuzzPriority`** functions from `randall oracles -p <project>`

**Install (manual):**

1. Ghidra → **File → Install Extensions** → **+** → select GhidrAssist release zip for your Ghidra version
2. Configure API key in GhidrAssist settings (provider-specific)
3. Restart Ghidra

**Install (Windows helper — clones upstream, no API keys):**

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-re-companions.ps1 -GhidrAssist
```

Clones to `tools/ghidra-extensions/src/ghidrassist/` (gitignored). Build/install steps print to the console; GhidrAssist often ships pre-built zips per Ghidra release.

---

## C++ Class Analyzer

**What it does:** Ghidra extension to infer C++ class layouts, vtables, and inheritance from RTTI and constructor/destructor patterns.

**When to use with Randfuzz:**

- C++ lab targets (`vulnserver`, native `vulnlab`, game-style binaries)
- After static map export — prioritize functions with high sink scores on `operator<<`, `memcpy`, virtual calls

**Install (manual):**

1. Download release from [vic4key/Class-Analyzer](https://github.com/vic4key/Class-Analyzer/releases)
2. Ghidra → **File → Install Extensions** → select zip → restart
3. Run **Class Analyzer** from the tool menu on the open program

**Install (Windows helper):**

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-re-companions.ps1 -CppClassAnalyzer
```

---

## Umbrella installer

```powershell
# Document-only status + clone/build hints (no secrets, no auto-enable in Ghidra)
powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-re-companions.ps1

# Stage GhidrAssist sources
powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-re-companions.ps1 -GhidrAssist

# Stage C++ Class Analyzer sources
powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-re-companions.ps1 -CppClassAnalyzer

# With Ghidra app present, attempt extension zip install (best-effort)
powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-re-companions.ps1 -GhidrAssist -InstallToGhidra
```

`randall doctor` reports these as optional **note** rows when the installer marker exists.

---

## Honest scope

| Item | Real today |
|------|------------|
| Docs + install script | ✅ |
| Randfuzz CLI/API integration | 🔲 Not planned — manual Ghidra UX |
| Auto-run LLM rename on crash | 🔲 Out of scope |

Primary integration surface remains `randall-analysis.json`, stalk layers, and GhidraMCP optional queries.
