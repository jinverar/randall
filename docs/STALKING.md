# Stalking bugs — pentest coverage workflow

Goal: never guess — **measure baseline, fuzz, crash, compare, export, refine**.

Inspired by DynamoRIO drcov + Dynapstalker / PaiMei Pstalker: you only find bugs in code you execute.

## Workflow

1. **Snapshot** the lab VM.
2. **Baseline** — run the target under `drrun -t drcov -dump_text`, use it normally (browser, happy-path traffic), stop the process, record a `baseline` layer in **Stalking bugs**.
3. **Fuzz** — instrument again (or use Randfuzz coverage-guided spawn), run a campaign, record a `fuzzed` layer (drcov log, corpus `edges.txt`, or crash id).
4. **Crash again** — record `fuzzier` / `crash` layers as many times as you want.
5. **Compare** in Randfuzz — union / shared / novel blocks.
6. **Export** IDA IDC or Ghidra Python colors (oldest layer first).
7. **Inspect** missed / novel blocks → change mutators, dictionaries, session graph → repeat.

## Local vs remote

| Mode | Coverage CFG | Crashes |
|------|----------------|---------|
| **Local** instrumented binary | Full drcov layers + IDA/Ghidra | Minidump + analyze + (planned) WinDbg |
| **Remote** service only | Protocol/session graph, not remote BB CFG | Need agent / ProcDump on target host |

Remote Apache/nginx without an on-box agent cannot produce Dynapstalker-style basic-block maps. Run **`randall agent --bind 0.0.0.0`** on the lab box and use:

- `GET /api/remote/tools` — probe DynamoRIO / Procmon / debuggers
- `POST /api/remote/procmon/start` · `stop` — quiet `.pml` capture on that host

Coverage CFG still needs an instrumented (or native-PC) process on the box that runs the binary.

## UI

**Stalking bugs** nav tab (not the live Dashboard):

- Add layers: baseline / fuzzed / fuzzier / crash
- Compare deltas and block map
- Export: IDA IDC, Ghidra script, raw edges
- Tool status: DynamoRIO, native PC stalk, Scream, Procmon, WinDbg, remote agent
- **Help** tab — served markdown (`CUSTOM_TARGETS`, `CASE_BUILDER`, this doc, …)

## Coverage backends (`fuzz.stalkMode`)

| Mode | Backend |
|------|---------|
| `auto` | DynamoRIO if installed, else **native PC stalk** |
| `external` | DynamoRIO drcov (full BB) |
| `native` | Debug-event PC samples → drcov-compatible log (coarse) |
| `none` | No coverage instrumentation |

Procmon bookends: `fuzz.procmonCapture: true` or the Fuzz tab checkbox → `fuzz.pml` under the run journal directory.

## API

- `GET /api/stalking/{project}` — workspace
- `POST /api/stalking/layers` — record layer
- `POST /api/stalking/layers/from-crash` — `{ crashId, tag? }`
- `POST /api/stalking/layers/from-corpus` — `{ project, tag? }`
- `GET /api/stalking/{project}/compare`
- `POST /api/stalking/export` — `{ project, layerIds, format: idc|ghidra|edges }`
- `GET /api/docs` · `GET /api/docs/{path}` — Help tab markdown
- `GET /api/remote/tools` · `POST /api/remote/procmon/start|stop` — lab agent

## CLI

```
randall stalk layers -p <project>
randall stalk compare -p <project> [layerId…]
randall stalk export -p <project> --format idc|ghidra|edges [-o dir]
randall stalk from-crash -i <crash-guid> [--tag crash]
```

Fuzz campaigns auto-record a `crash` stalk layer when a crash is saved (uses crash trace / corpus edges).

Crashes are clustered by **fault signature** (class + module + PC), with severity taxonomy on the Crashes tab.
Pattern-depth triage reports whether RIP/fault/RSP bytes appear in the crashing input (offset only — research metric).

Layers live under `data/stalk/{project}/`.

## Debugger attach / wait / analyze

For long-lived local targets (`target.longLived: true`):

| Mode | Behavior |
|------|----------|
| `none` | MiniDumpWriter on process exit (default) |
| `wait` | **Scream** (built-in) debug-attaches → second-chance minidump → auto-analyze |
| `attach` | Launch WinDbg / WinDbg Preview attached with `g` (interactive; only one debugger) |
| `both` | Scream wait during fuzz + open dump in GUI after crash |

Only one debugger can attach at a time — `both` does **not** live-attach WinDbg while Scream is watching.

YAML:

```yaml
fuzz:
  debuggerMode: wait          # none | attach | wait | both
  debuggerKind: windbg-preview  # auto | windbg | windbg-preview | cdb
  debuggerOpenOnCrash: true   # open dump in GUI after analyze
```

CLI:

```
randall scream selftest                # lab AV target → attach → dump (CI-friendly)
randall scream watch -p <pid>          # first-party watcher (no ProcDump)
randall fuzz -c projects/screamcrash.yaml --debugger wait
randall fuzz -c projects/vulnserver.yaml --debugger wait --open-on-crash
randall debug tools
randall debug attach -t vulnserver --kind windbg-preview
randall debug open -i <crash-guid> --kind windbg-preview
randall analyze -i <crash-guid>
```

Web: Fuzz tab debugger dropdown + **Attach debugger**; crash detail **Open WinDbg Preview** / **Open WinDbg**.

## Tooling roadmap

- **Scream watcher** — built-in wait-for-exception (`debuggerMode: wait`) — done
  - Ready handshake after loader breakpoint (target can accept I/O)
  - Fatal first-chance dump (AV/GS/heap) — .NET often never delivers second-chance
  - Full dump → light dump fallback; Wow64 register path
  - `randall scream selftest` — native `scream_crash.exe` ACCESS_VIOLATION regression
  - `projects/screamcrash.yaml` — TCP lab target using `scream_av.dll`
- **WinDbg + Preview** — attach live / open dumps (`randall debug`, `/api/debug`)
- **Procmon** — bookend captures around campaigns (planned)
- **Remote agent** — procmon + optional drcov on the fuzz box (planned)
