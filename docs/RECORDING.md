# Recording & process monitoring during fuzz runs

**Philosophy (2026):** Sysinternals is for **observing** what happened before, during, and after a crash — not for finding crashes. Randfuzz finds faults (mutators, coverage, Scream); Suite tools explain the blast radius.

There is no separate `target_recorder` binary. Recording is wired through **FuzzEngine** + **Target Runtime**. (`ProcessMonitor` is the internal long-lived start/detect-death/restart helper — not Sysinternals Procmon.)

**Related:** [STALKING.md](STALKING.md) · [TARGET_RUNTIME.md](TARGET_RUNTIME.md) · [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md) · [tools/README.md](../tools/README.md)

**Status legend**

| Status | Meaning |
|--------|---------|
| **Wired** | Soft-fail bookend / on-crash from Campaign YAML or UI |
| **GUI companion** | Run interactively on Monitor 2/3 — not automated |
| **External** | Install/run yourself; not exported by Randfuzz |

---

## Rule: record where the target runs

| Setup | What you get |
|-------|----------------|
| **Fuzz on the lab VM / bare metal** (`randall serve` or `randall agent`) | Full stack: Procmon, TCPVCon, DebugView, snapshots, Strings, pktmon, Scream/ProcDump, coverage |
| **Laptop Campaign + `target.agentUrl` only** | Remote process start/stop; debugger attach skipped; dumps stay thin on the laptop |

Prefer opening `http://<vm-ip>:5000` on the agent and fuzzing there; pull packs later ([TARGET_RUNTIME.md](TARGET_RUNTIME.md)#remote-lab-workflow-dumps--lens--offline-import).

---

## Recommendations (defaults)

| Scenario | Enable | Why / skip |
|----------|--------|------------|
| **Almost every session** | **Scream wait** + **Procmon** + **Sysinternals snapshots** | Crash dumps + file/registry/network activity + Handle/ListDLLs bookends (SigCheck/AccessChk when present) |
| **Crashes appearing, no Scream** | **+ ProcDump on crash** | Only when `debuggerMode: none`. Skipped if Scream/attach already holds the process |
| **ODS / DbgPrint logging** | **+ DebugView** | Win32 OutputDebugString → `debugview.log`. Kernel DbgPrint needs elevated DebugView `/k` (not armed by default) |
| **Network / protocol** | **+ TCPVCon** (optional **+ pktmon**) | Connection bookends; pktmon adds NIC ETL (often needs elevation) |
| **File format / parser** | Procmon + snapshots + **VMMap GUI** + Scream/ProcDump + DebugView | Procmon shows load paths/temp files; VMMap for heap growth (GUI companion; CLI best-effort if `vmmap64` present) |
| **Interesting crash payload** | **+ Strings on crash** | Opt-in — avoids surprise cost on huge inputs |
| **Drivers / services / kernel** | LiveKD, WinObj, AppVerifier, ProcMon boot logging | **External** / GUI — see Tier 3–4 below. Service restart via [Target Runtime](TARGET_RUNTIME.md) (`longLived` + restart); PsService/PsKill are companions |
| **Skip / interactive only** | Process Explorer, RAMMap, LiveKD, TCPView GUI, WPR/xperf, API Monitor, Frida | Not bookended |

Default campaign checklist: **Wait (Scream)** + **Procmon** + **Sysinternals snapshots**. Add TCPVCon for protocol targets; DebugView / ProcDump / Strings / pktmon when the row above applies.

---

## Tier matrices (Randfuzz mapping)

### Tier 1 — Must have (almost every session)

| Tool | Why | Status | Enable / place |
|------|-----|--------|----------------|
| **Process Monitor** | Registry, filesystem, process/thread, DLL load, pipes, ALPC — what input reached before the crash | **Wired** | `fuzz.procmonCapture: true` / UI **Procmon** → `tools/Procmon64.exe` → `data/runs/<id>/fuzz.pml` |
| **Process Explorer** | Live handles, threads, modules, privileges, parent/child | **GUI companion** | Monitor 2/3 — `procexp64.exe` (not bookended) |
| **Handle** | Leaked handles after many iterations | **Wired** (snapshots) | `fuzz.sysinternalsSnapshots: true` → `tools/handle64.exe` |
| **ListDLLs** | Loaded modules during the test | **Wired** (snapshots) | same → `tools/listdlls64.exe` |
| **VMMap** | Heap growth, fragmentation, VA exhaustion | **GUI companion** (+ best-effort CLI) | Prefer GUI on Monitor 2/3. If `vmmap64.exe` is present, snapshots may attempt `vmmap -accepteula -p <pid> out.txt` on arm/crash (soft-fail / timeout) |
| **RAMMap** | Kernel / physical resource leaks | **GUI companion** | Monitor 3 — not automated |
| **PsList** (+ optional PsInfo) | Process list / host info bookends | **Wired** (snapshots) | `tools/pslist64.exe`, optional `PsInfo64.exe` |

### Tier 2 — Memory & crash analysis

| Tool | Purpose | Status | Enable / place |
|------|---------|--------|----------------|
| **ProcDump** | Full dump on unhandled exception | **Wired** | `fuzz.procdumpOnCrash: true` when no Scream — `tools/procdump.exe` |
| **Scream** (`debuggerMode: wait`) | First-party second-chance minidump | **Wired** | UI **Wait** / `debuggerMode: wait` (preferred over ProcDump) |
| **LiveKD** | Kernel debug without reboot | **External** | Run interactively when investigating drivers |
| **DebugView** | OutputDebugString / app debug spew | **Wired** | `fuzz.debugViewCapture: true` → `tools/Dbgview.exe` → `debugview.log` |
| **Strings** | Inspect crashing / corpus inputs | **Wired** | `fuzz.stringsOnCrash: true` / UI checkbox → `tools/strings64.exe` → `*_strings.txt` beside crash `.bin` |
| **SigCheck** | Binary / signature / version at arm | **Wired** (snapshots) | Included when snapshots on + `sigcheck64.exe` → `sysinternals/sigcheck-target.txt` |

### Tier 3 — Driver / kernel fuzzing

| Tool | Status | Notes |
|------|--------|-------|
| LiveKD, RAMMap, WinObj, WinObjEx64 | **External** / **GUI companion** | Object namespace + kernel state — not bookended |
| **AccessChk** | **Wired** (optional in snapshots) | Process token (`-p -f`) when `accesschk64.exe` present |
| ProcMon boot logging | **External** | Configure ProcMon yourself for boot-time drivers |

### Tier 4 — Service fuzzing

| Tool | Status | Notes |
|------|--------|-------|
| **Target Runtime** restart | **Wired** | `target.longLived: true` — start/stop/restart after death ([TARGET_RUNTIME.md](TARGET_RUNTIME.md), [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md)) |
| PsService / PsExec / PsKill | **External** | Useful companions for SCM services; not automated by Randfuzz |
| Process Explorer / ProcDump | GUI / **Wired** | Same as Tier 1–2 |

### Tier 5 — File format fuzzing

Run together: **Procmon** (Wired) + **Process Explorer** (GUI) + **VMMap** (GUI) + **ProcDump/Scream** (Wired) + **DebugView** (Wired) + **snapshots** (Wired). You typically see malformed file load → decoder DLL → registry/temp paths → heap growth → dump.

### Tier 6 — COM / RPC / ALPC

| Tool | Status |
|------|--------|
| Procmon, Handle | **Wired** |
| Process Explorer, WinObj | **GUI companion** / **External** |
| AccessChk | **Wired** (optional in snapshots) |

---

## Companion tools (non-Sysinternals)

| Tool | Use | Status |
|------|-----|--------|
| **WinDbg Preview** | First-choice dump / live analysis | **Wired** attach/open (`debuggerMode`, open-on-crash) |
| **PageHeap (GFlags)** | Earlier heap corruption | **Wired** — `target.pageHeap: true` |
| **Application Verifier** | Handle/API misuse | **External** |
| **WinAFL / TinyInst** | Coverage-guided Windows user-mode | **External** (Randfuzz uses DynamoRIO drcov / native stalk) |
| **Boofuzz** | Network protocol fuzzing | Related lineage — Randfuzz Campaign |
| **Lighthouse / Ghidra / IDA / Binary Ninja / x64dbg** | Coverage viz / RE / triage | **External** — stalk export helps ([STALKING.md](STALKING.md)) |
| **pktmon** | NIC ETL | **Wired** — `fuzz.pktmonCapture` |
| **TCPVCon** | Connection snapshots (TCPView CLI) | **Wired** — `fuzz.tcpvconCapture` |
| **Sysmon** | Host-wide EVTX | **External only** — Randfuzz does **not** export Sysmon |

---

## Example workstation layout (Randfuzz)

```
Monitor 1
---------
WinDbg Preview (dumps / attach)
Randfuzz agent UI (Campaign + live log)
Scream / ProcDump status

Monitor 2
---------
ProcMon (filters: Process Name is <target.exe>; drop noise)
optional: TCPView GUI if not using TCPVCon bookends

Monitor 3
---------
Process Explorer
VMMap
DbgView (if not using fuzz.debugViewCapture)

Background
----------
randall agent / Campaign fuzz loop
DynamoRIO coverage (optional)
Crash artifact packs / triage
```

---

## Wired knobs (YAML / UI)

### Sysinternals snapshots bundle

`fuzz.sysinternalsSnapshots: true` — **one checkbox**, not five:

| Tool | When | Notes |
|------|------|-------|
| Handle | arm / disarm / crash | Soft-fail if missing |
| ListDLLs | arm / disarm / crash | Soft-fail |
| PsList | arm / disarm / crash | Soft-fail |
| **SigCheck** | arm once | `sigcheck-target.txt` on target exe |
| **AccessChk** | arm / disarm / crash | `-p <pid> -f` when present |
| **VMMap** | arm / crash | Best-effort CLI; prefer GUI if flaky |
| netstat `-ano` | each capture | Prefer **TCPVCon** for richer endpoints |
| PsInfo | arm only | Optional |

Artifacts: `data/runs/<runId>/sysinternals/`.

### Other `fuzz.*` keys

```yaml
fuzz:
  debuggerMode: wait              # none | wait | attach | both
  debuggerKind: auto
  debuggerOpenOnCrash: false
  procmonCapture: true            # → fuzz.pml
  tcpvconCapture: true            # → tcpvcon/
  debugViewCapture: false         # → debugview.log
  sysinternalsSnapshots: true     # → sysinternals/ (+ sigcheck/accesschk/vmmap if present)
  stringsOnCrash: false           # → <crash>_strings.txt (opt-in)
  procdumpOnCrash: false          # ProcDump -e -ma when no Scream
  pktmonCapture: false            # → fuzz-pktmon.etl
```

| Key | Notes |
|-----|-------|
| `fuzz.procmonCapture` | Procmon `.pml` bookend |
| `fuzz.tcpvconCapture` | TCPVCon arm/disarm/crash |
| `fuzz.debugViewCapture` | DebugView ODS log |
| `fuzz.sysinternalsSnapshots` | Snapshot bundle (Handle/ListDLLs/PsList + SigCheck/AccessChk/VMMap when present) |
| `fuzz.stringsOnCrash` | Strings on saved crashing input |
| `fuzz.procdumpOnCrash` | ProcDump `-e -ma` if no Scream/attach |
| `fuzz.pktmonCapture` | Windows pktmon ETL |
| `target.pageHeap` | GFlags Page Heap via Target Runtime |
| `target.longLived` | ProcessMonitor / Target Runtime ownership + restart |

Template: [templates/tcp-runtime.yaml](templates/tcp-runtime.yaml).

### UI (Fuzz → Campaign)

- **Debugger** → None / Wait (Scream) / Attach / Both  
- **Procmon** · **TCPVCon** · **ProcDump on crash** · **pktmon** · **DebugView**  
- **Sysinternals snapshots** (includes SigCheck/AccessChk/VMMap when binaries exist)  
- **Strings on crash** (opt-in)  
- **Doctor** probes the Suite tools above  

```powershell
randall fuzz -c projects/local/myapp.yaml --debugger wait
randall doctor -c projects/local/myapp.yaml
```

---

## Where to put tools (`tools/` or PATH)

Binaries are **not** committed. On the **fuzz host**, copy from the [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) / [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview):

| Tool | Placement | Status |
|------|-----------|--------|
| Procmon | `tools/Procmon64.exe` | Wired |
| ProcDump | `tools/procdump.exe` | Wired |
| TCPVCon | `tools/tcpvcon64.exe` | Wired |
| DebugView | `tools/Dbgview.exe` | Wired |
| Handle / ListDLLs / PsList | `tools/handle64.exe`, `listdlls64.exe`, `pslist64.exe` | Wired (snapshots) |
| SigCheck | `tools/sigcheck64.exe` | Wired (snapshots) |
| Strings | `tools/strings64.exe` | Wired (`stringsOnCrash`) |
| AccessChk | `tools/accesschk64.exe` | Wired (optional in snapshots) |
| VMMap | `tools/vmmap64.exe` | GUI + best-effort CLI |
| Process Explorer / RAMMap | `procexp64.exe` / `RAMMap.exe` | GUI companion |
| PsInfo | `tools/PsInfo64.exe` | Optional arm |
| pktmon | Built-in Windows | Wired |
| DynamoRIO / gflags / WinDbg | see [tools/README.md](../tools/README.md) | Wired / SDK |

```powershell
copy Procmon64.exe, procdump64.exe, tcpvcon64.exe, Dbgview.exe tools\
copy handle64.exe, listdlls64.exe, pslist64.exe, sigcheck64.exe, strings64.exe, accesschk64.exe tools\
# optional: vmmap64.exe, procexp64.exe, PsInfo64.exe
randall doctor -c projects/local/myapp.yaml
```

---

## ProcDump vs Scream

Only **one** debugger can attach. Prefer **Scream** (`debuggerMode: wait`). Use `procdumpOnCrash` when you want ProcDump `-e -ma` **instead** (`debuggerMode: none`). If Scream/attach is already on, ProcDump arm is skipped with a warning.

---

## Artifact locations

| Artifact | Path |
|----------|------|
| Procmon | `data/runs/<runId>/fuzz.pml` |
| TCPVCon | `data/runs/<runId>/tcpvcon/` + `tcpvcon-capture.txt` |
| DebugView | `data/runs/<runId>/debugview.log` |
| Snapshots | `data/runs/<runId>/sysinternals/` (`arm-*`, `disarm-*`, `crash_*`, `sigcheck-target.txt`, `snapshots.txt`) |
| Strings on crash | `data/crashes/<project>/<crash>_strings.txt` (beside `.bin`) |
| pktmon | `data/runs/<runId>/fuzz-pktmon.etl` |
| ProcDump / Scream dumps | `data/crashes/<project>/dumps/` |
| Crash sidecars / lens | `data/crashes/<project>/*_crash.json`, `*_memory_lens.*` |
| Coverage | `data/corpus/<project>/edges.txt` |

### UI review vs on-disk logs

Artifacts land in `data/runs/<runId>/` and `data/crashes/<project>/` on the fuzz host.

| In the UI today | Not in the UI yet |
|-----------------|-------------------|
| **Crashes** investigation | Browsing/viewing `.pml`, `debugview.log`, `tcpvcon/`, `sysinternals/`, pktmon ETL |
| **Dashboard** stalk timeline (from journal) | Full `run.json` / `iterations.jsonl` as a Runs browser |
| **Bundles** crash packs (optional include linked run journals) | **Open Folder** button |

Open the run folder on the fuzz host (path printed as `Run journal: ...` at start) or unzip a crash pack that included runs.

---

## Custom app on a VM (short path)

1. Snapshot the VM.  
2. Deploy Randfuzz + target; drop Suite tools under `tools/`.  
3. Create `projects/local/myapp.yaml` (Scare Floor or template).  
4. On the VM: `randall agent --port 5000` → open that URL.  
5. Target Runtime start → confirm listen port.  
6. Enable **Wait** + **Procmon** + **snapshots** (+ TCPVCon / DebugView / Strings as needed) → Campaign **Start**.  
7. Export crash packs from Bundles or `randall crashes pack`.
