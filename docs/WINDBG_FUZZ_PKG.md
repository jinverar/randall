# RandfuzzDbg + ROP Studio

**RandfuzzDbg** is a WinDbg Preview / dbgeng analysis package for **fuzz crash dumps**.
**ROP Studio** is the host-side gadget catalog + constrained chain **sketch** tool.

Together they walk a scream from fault → control offset → candidate gadgets for
**authorized lab targets** (mitigation ladder / owned binaries). They do **not** emit
shellcode, NOP sleds, or weaponized exploit payloads.

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
| Walk export | `RandfuzzDbgWalk` | `*_windbg_walk.json` beside crash |
| Extension | `tools/randfuzzdbg/` | dbgeng DLL (Windows build) + scripts |
| CLI | `randall rop …` · `randall windbg …` | Scan / search / sketch / walk |
| API | `/api/rop/*` · `/api/windbg/*` | UI + lab agent |

---

## ROP Studio (host)

```bash
randall rop scan --exe <path> [--out gadgets.json] [--arch x64|x86|auto]
randall rop search --exe <path> --need pop-rcx [--badchars "\x00\x0a"]
randall rop sketch --exe <path> --goal pivot|write|control [--badchars …]
randall rop from-crash -i <crash-guid> [--goal pivot]
```

**Gadget kinds (v1):** `ret`, `pop-<reg>`, `add-sp`, `xchg-sp`, `jmp-reg`, `call-reg`,
`leave-ret`, `pop-pop-ret` (SEH-ish), `mov-rm`, `pushad-ret` (x86).

**Sketch goals (v1):**

| Goal | Meaning |
|------|---------|
| `control` | Confirm ret-gadgets near controlled return |
| `pivot` | Prefer `xchg reg,esp/rsp` / `add rsp` / `leave;ret` |
| `write` | Sequence sketch toward write-what-where (register loads only — no payload bytes) |

Sketches are **ordered gadget citations** with why/constraints — not an exploit blob.

On-disk:

```
data/crashes/<project>/<guid>_rop.json          # from-crash / sketch
data/crashes/<project>/<guid>_windbg_walk.json  # debugger walk export
data/rop/<sha256-of-module>.gadgets.json        # reusable module cache
```

---

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
| `!rf.crash` | Show linked Randfuzz walk JSON / crash guid if set |
| `!rf.regs` | Faulting context summary |
| `!rf.control` | Pattern / CONTROL hint from walk file |
| `!rf.stack` | Stack / saved RET walk |
| `!rf.modules` | Module list + rebase notes |
| `!rf.rop` | Print top gadgets from sibling `*_rop.json` |
| `!rf.export` | Refresh walk JSON path hint |

Build on a Windows lab with Debugging Tools SDK (see `tools/randfuzzdbg/README.md`).
Linux CI keeps host ROP Studio + scripts; DLL is Windows-only.

---

## Walk the scream (lab flow)

1. Fuzz until scream → minidump bottled  
2. `randall analyze -i <guid>` · Memory lens · `exploit guide` / CONTROL offset  
3. `randall rop from-crash -i <guid> --goal pivot` → gadget sketch  
4. `randall windbg walk -i <guid>` → open WinDbg Preview · run `rf_walk.txt`  
5. Climb mitigation ladder (`vulnlab` → `vulnlab-nx` → …) — sketches change with NX/ASLR  

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
- [ ] Full dbgeng DML commands (`!rf.*`)
- [ ] Crashes UI — ROP Studio panel
- [ ] ELF depth + Windows PDB-assisted naming
- [ ] Badchar learning from crashing input
