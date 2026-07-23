# RandfuzzDbg

WinDbg Preview / classic analysis package for **Randfuzz scream dumps**.

Host-side companion: **ROP Studio** (`randall rop …`) — see [docs/WINDBG_FUZZ_PKG.md](../../docs/WINDBG_FUZZ_PKG.md).

## Scripts (use today)

```powershell
randall windbg scripts
randall windbg walk -i <crash-guid>
randall debug open -i <crash-guid> --kind windbg-preview
```

In WinDbg Preview (dump already open):

```
$$>a< <repo>\tools\randfuzzdbg\scripts\rf_walk.txt
```

| Script | Purpose |
|--------|---------|
| `scripts/rf_walk.txt` | Registers, stack, modules, PEB — standard walk |
| `scripts/rf_load.txt` | Path / load notes for the `!rf.*` extension |

## Extension DLL (Windows lab)

`src/` contains a **dbgeng extension** for `RandfuzzDbg.dll` / `rf.dll`. Build on Windows with
Debugging Tools for Windows / Windows SDK:

```powershell
cd tools\randfuzzdbg
cmake -B build -A x64
cmake --build build --config Release
# Prefer copying as rf.dll so !rf.* resolves:
#   copy build\Release\RandfuzzDbg.dll <WinDbg>\winext\rf.dll
#   .load rf
```

| Command | Job |
|---------|-----|
| `!rf.help` | Catalog |
| `!rf.walk` | Registers / stack / PEB / modules / exception |
| `!rf.crash [walk.json]` | Linked walk JSON / crash guid (sets path for later cmds) |
| `!rf.regs` | Fault context (`r`) |
| `!rf.control` | CONTROL offset hint from walk file |
| `!rf.stack` | Stack walk (`k`) |
| `!rf.modules` | Module list (`lm`) |
| `!rf.rop [rop.json]` | Top gadgets from sibling `*_rop.json` |
| `!rf.badchars [json]` | Learned badchar filter from `*_badchars.json` |
| `!rf.export` | Host refresh hint (`randall windbg walk`) |

Typical flow after opening a dump:

```
!rf.crash C:\lab\data\crashes\vulnlab\<guid>_windbg_walk.json
!rf.walk
!rf.control
!rf.rop
!rf.badchars
```

## Boundary

Gadget catalogs + dump walks for **authorized lab targets**. No shellcode / weaponized
payload generation.
