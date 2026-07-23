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
| `scripts/rf_load.txt` | Path / load notes for the future `!rf.*` extension |

## Extension DLL (Windows lab)

`src/` contains a **dbgeng stub** for `RandfuzzDbg.dll`. Build on Windows with
Debugging Tools for Windows / Windows SDK:

```powershell
cd tools\randfuzzdbg
cmake -B build -A x64
cmake --build build --config Release
# copy build\Release\RandfuzzDbg.dll next to WinDbg or:
#   .load C:\path\to\RandfuzzDbg.dll
```

Planned commands (stub prints help until implemented):

| Command | Job |
|---------|-----|
| `!rf.help` | Catalog |
| `!rf.crash` | Linked walk JSON / crash guid |
| `!rf.regs` | Fault context |
| `!rf.control` | CONTROL offset hint from walk file |
| `!rf.stack` | Stack walk |
| `!rf.modules` | Module list |
| `!rf.rop` | Top gadgets from sibling `*_rop.json` |
| `!rf.export` | Refresh walk path hint |

## Boundary

Gadget catalogs + dump walks for **authorized lab targets**. No shellcode / weaponized
payload generation.
