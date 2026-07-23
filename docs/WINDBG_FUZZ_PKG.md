# RandfuzzDbg + ROP Studio

**RandfuzzDbg** is a WinDbg Preview / dbgeng analysis package for **fuzz crash dumps**.
**ROP Studio** is the host-side gadget catalog + constrained chain **sketch** tool.

Together they walk a crash from fault → CONTROL offset → candidate gadgets for
**authorized lab targets** (mitigation ladder / owned binaries). They do **not** emit
shellcode, NOP sleds, or weaponized exploit payloads.

### Start here (crash triage)

1. Open the scream in **Crashes** (or use the CLI with the crash guid).
2. Click **Run triage walk** — CONTROL → stack map → badchars → ROP sketch → debugger notes.
3. Open the dump in WinDbg Preview / GDB and use the exported walk script.
4. Climb the mitigation ladder (`basic` → `nx` → `aslr` → `modern`) and re-sketch.

Step tools (stack map, gadget search, ladder) stay under **Step tools** when you need them one at a time.

Related: [EXPLOIT_GUIDE.md](EXPLOIT_GUIDE.md) · [MITIGATION_LAB.md](MITIGATION_LAB.md) ·
[CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) · [RECORDING.md](RECORDING.md)

> SwishDbgExt (Magnet/Comae) is a kernel DFIR extension. We borrow UX ideas (DML, module
> scans) but do **not** fork it — wrong domain for user-mode fuzz→exploit-dev walks.

---

## Product boundary

| In scope | Out of scope |
|----------|----------------|
| Open dump in WinDbg Preview + Randfuzz commands | Shellcode / encoders / staged payloads |
| Register / stack / SEH walk from minidump | Auto-attack third-party software |
| Cyclic CONTROL @ offset (Windows twin of `exploitdev`) | “Paste this and pwn host X” recipes |
| Gadget harvest, badchar filter, chain **sketches** | Shipping packed exploits |
| Export walk JSON next to scream canister | Credential dumping / DFIR rootkit suites |

`randall exploit template` stays disabled for payload skeletons. Use **ROP Studio sketches**
(gadget ordered lists + constraints) and **RandfuzzDbg** walks instead.

---

## Architecture

```text
Scream dump (.dmp / .core)     Host (.NET)                    WinDbg Preview
─────────────────────────     ───────────                    ──────────────
minidump + input + guide  →   ROP Studio scan/search/sketch → !rf.* extension
                              RandfuzzDbgWalk JSON          → scripts/rf_walk.txt
                              Crashes UI / CLI / API
```

| Piece | Location | Role |
|-------|----------|------|
| ROP Studio | `src/Randall.Infrastructure/Rop/` | PE/ELF gadget harvest, search, sketch |
| Stack Lens | `StackLens` | Dump-native CONTROL map (stack slots × input) |
| Scream Walk | `ScreamWalk` | CONTROL → stack → badchars → sketch → WinDbg/GDB playbook |
| Walk export | `RandfuzzDbgWalk` / `RandfuzzGdbWalk` | `*_windbg_walk.json` / `*_gdb_walk.json` |
| Extension | `tools/randfuzzdbg/` · `tools/randfuzzgdb/` | dbgeng DLL + GDB scripts |
| CLI | `randall scream|stack|rop|windbg|gdb|ladder …` | Playbook / lens / scan / walk / ladder |
| API | `/api/scream/*` · `/api/stack/*` · `/api/rop/*` · `/api/windbg/*` · `/api/gdb/*` | UI + lab agent |

---

## Scream Walk (product verb)

One crash-guid playbook that chains the lab path:

```bash
randall scream walk -i <crash-guid> --goal auto
# API: POST /api/scream/walk
# UI: Crashes → Run triage walk
```

Order: CONTROL (guide/triage) → **Stack Lens** → badchars → tier-aware sketch goal → ROP sketch →
WinDbg walk JSON → GDB walk JSON → ladder hint. Writes `*_scream_walk.json`.

**Adaptive goals (`--goal auto`):** basic→`control` · NX→`pivot` · PIE→`leak` · canary→`canary`.

Also: `randall stack lens -i <guid>` · `randall ladder diff` · `randall gdb walk -i <guid>` · `tools/randfuzzgdb/`.

---

## Stack Lens (CONTROL map)

```bash
randall stack lens -i <crash-guid> [--window 128] [--json]
# API: POST /api/stack/lens
# UI: Crashes → Step tools → Stack map
```

Reads a stack window from the dump (gdb core / minidump Memory64) or falls back to registers +
exploit-guide CONTROL. Labels each word:

| Role | Meaning |
|------|---------|
| `controlled` | Value matches crashing input / cyclic pattern |
| `return-slot` | Near-SP (or controlled) value looks like a code pointer |
| `frame-ptr` | Matches RBP/EBP |
| `canary-suspect` | High-entropy / truncated cookie-shaped word |
| `unknown` | No match |

Writes `*_stack_lens.json`. Primary CONTROL feeds Scream Walk and `rop show`.
---

## ROP Studio (host)

```bash
randall rop scan --exe <path> [--out gadgets.json] [--arch x64|x86|auto]
randall rop search --exe <path> --need pop-rcx [--badchars "\x00\x0a"]
randall rop sketch --exe <path> --goal auto|pivot|write|control|leak|canary [--badchars …]
randall rop from-crash -i <crash-guid> [--goal auto] [--exe path] [--modules N]
randall rop search -i <crash-guid> --need pop-rdi
randall rop show -i <crash-guid>                    # existing sidecars
randall rop badchars -i <crash-guid>                    # write *_badchars.json
```

**Gadget kinds (v1+):** `ret`, `retn`, `pop-<reg>`, `pop3-ret`, `add-sp`, `sub-sp`, `xchg-sp`,
`jmp-reg`, `call-reg`, `leave-ret`, `pop-pop-ret`, `mov-rm` / `mov-rr`, `pushad-ret` / `popad-ret` (x86),
`nop-ret`. PE gadgets may carry a nearest **export** symbol (`Symbol` / `export:Name` tag).

**Multi-module:** `from-crash` ranks TargetDetail → project exe → loaded modules (system paths
deprioritized) and merges gadget pools (default 3 modules).
**Sketch goals:**

| Goal | Meaning |
|------|---------|
| `auto` | Tier-aware (basic→control · NX→pivot · PIE→leak · canary→canary) |
| `control` | Confirm ret-gadgets near controlled return |
| `pivot` | Prefer `xchg reg,esp/rsp` / `add rsp` / `leave;ret` |
| `write` | Sequence sketch toward write-what-where (register loads only — no payload bytes) |
| `leak` | Prefer PLT / GOT-adjacent / info-leak oriented pops |
| `canary` | Canary-aware sketch framing when stack cookies are on |

Sketches are **ordered gadget citations** with why/constraints — not an exploit blob.

**Badchar learning:** heuristics from the crashing input (null / CRLF / whitespace truncation
signals). Feeds `--badchars` and auto-filters `from-crash` sketches. Filters both **instruction
bytes** and **little-endian address bytes** (32-bit VAs as 4 bytes; larger as 8).

On-disk:

```
data/crashes/<project>/<guid>_scream_walk.json  # Scream Walk playbook
data/crashes/<project>/<guid>_stack_lens.json   # Stack Lens CONTROL map
data/crashes/<project>/<guid>_rop.json          # from-crash / sketch
data/crashes/<project>/<guid>_windbg_walk.json  # WinDbg walk export
data/crashes/<project>/<guid>_gdb_walk.json     # GDB/GEF walk export
data/crashes/<project>/<guid>_badchars.json     # learned filter
data/crashes/<project>/<guid>_ladder.json       # mitigation ladder (when run)
data/crashes/<project>/<guid>_exploit_guide.json  # CONTROL (when present)
data/rop/<sha256-of-module>.gadgets.json        # reusable module cache (read+write)
```

Triage export (`randall export` / Crashes UI) auto-runs Scream Walk (stack lens + badchars + sketch + walks)
and copies `scream_walk.json`, `stack_lens.json`, `rop_sketch.json`, `windbg_walk.json`, `gdb_walk.json`, and
`badchars.json` into `data/exports/<guid>/` when present.---

## RandfuzzDbg (WinDbg Preview)

### Scripts (available now)

```
tools/randfuzzdbg/scripts/rf_walk.txt   # classic WinDbg text script
tools/randfuzzdbg/scripts/rf_load.txt   # load hints + path notes
```

```bash
randall windbg scripts          # print install paths
randall windbg walk -i <guid>   # write *_windbg_walk.json + script snippet
randall debug open -i <guid> --kind windbg-preview
```

In WinDbg Preview (after opening the dump):

```
$$>a< C:\path\to\repo\tools\randfuzzdbg\scripts\rf_walk.txt
```

### Extension (Windows build)

```
tools/randfuzzdbg/
  README.md
  src/RandfuzzDbg.cpp       # dbgeng extension stub
  src/RandfuzzDbg.def
  CMakeLists.txt
```

Planned commands:

| Command | Job |
|---------|-----|
| `!rf.help` | Catalog |
| `!rf.walk` | Registers / stack / PEB / modules / exception |
| `!rf.crash [walk.json]` | Show linked Randfuzz walk JSON / crash guid |
| `!rf.regs` | Faulting context (`r`) |
| `!rf.control` | Pattern / CONTROL hint from walk file |
| `!rf.stack` | Stack / saved RET walk (`k`) |
| `!rf.modules` | Module list (`lm`) |
| `!rf.rop [rop.json]` | Print top gadgets from sibling `*_rop.json` |
| `!rf.badchars [json]` | Learned badchar filter |
| `!rf.export` | Refresh walk JSON path hint |

Build on a Windows lab with Debugging Tools SDK (see `tools/randfuzzdbg/README.md`).
Copy/rename the DLL to `rf.dll` (or use `!RandfuzzDbg.*`) so `!rf.walk` resolves.
Linux CI keeps host ROP Studio + scripts; DLL is Windows-only.

---

## Walk the scream (lab flow)

1. Fuzz until scream → minidump bottled  
2. `randall analyze -i <guid>` · Memory lens · `exploit guide` / CONTROL offset  
3. `randall stack lens -i <guid>` → CONTROL map (stack slots × input)  
4. `randall scream walk -i <guid> --goal auto` → playbook (lens → badchars → sketch → WinDbg/GDB)  
5. Open WinDbg Preview / GDB · run `rf_walk.txt` / `rf_gdb.txt`  
6. `randall ladder diff` — climb `vulnlab` → `vulnlab-nx` → … — sketches change with NX/ASLR  

---

## Why not SwishDbgExt?

| SwishDbgExt | RandfuzzDbg + ROP Studio |
|-------------|---------------------------|
| Kernel DFIR / IR | User-mode fuzz dumps |
| SSDT/IDT/credentials/YARA | Control offset + gadgets |
| Malware score / hives | Scream canisters + stalk |
| Fork maintenance risk | First-party, lab-scoped |

---

## Roadmap

- [x] Design + scope revise (`EXPLOIT_GUIDE.md`)
- [x] Host ROP scan / search / sketch / from-crash
- [x] WinDbg scripts + walk JSON export
- [x] Extension stub + Windows build notes
- [x] Crashes UI — ROP Studio panel (+ badchars / goal / search)
- [x] Badchar learning from crashing input
- [x] Address-byte badchar filter + gadget cache read
- [x] Deeper gadget decode (retn / pop3 / mov-rr / mov-rm / sub-sp / …)
- [x] ELF section hints (`.text` / `.plt`) + PE fixture tests
- [x] Triage export packs ROP + walk + badchars (auto-sketch)
- [x] CONTROL from `*_exploit_guide.json` into walk JSON
- [x] Mitigation annotations on sketches
- [x] dbgeng commands (`!rf.walk` / `!rf.crash` / `!rf.rop` / `!rf.badchars` / …)
- [x] Multi-module from-crash harvest (+ `rop show` / sidecars API)
- [x] PE export-table naming (nearest symbol tags)
- [x] Richer `!rf.regs` / `!rf.control` (IDebugRegisters + DML)
- [x] Crashes UI auto-load of existing ROP/walk/badchars sidecars
- [x] Scream Walk orchestrator (`randall scream walk` / UI)
- [x] Tier-adaptive goals (`auto` / `leak` / `canary`)
- [x] Mitigation ladder diff (`randall ladder diff`)
- [x] Linux GDB walk twin (`randall gdb walk` / `tools/randfuzzgdb`)
- [x] Stack Lens — dump-native CONTROL map (`randall stack lens` / Scream Walk step)
- [ ] Full Windows PDB/DIA naming (beyond export table)
- [ ] Richer dump Memory64 stack parse when light dumps omit RSP ranges