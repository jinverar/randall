# Recording & process monitoring during fuzz runs

Operator guide for **Procmon**, **Sysmon export**, **DebugView**, **Sysinternals snapshots**, **pktmon**, **ProcDump**, **Scream / debugger wait**, **dumps**, **Page Heap**, **coverage**, and **postStart** — what each does, YAML keys, UI toggles, and where tools must live.

There is no separate `target_recorder` binary. Recording is wired through **FuzzEngine** + **Target Runtime** using the knobs below. (`ProcessMonitor` is the internal long-lived start/detect-death/restart helper — not Sysinternals Procmon.)

**Related:** [STALKING.md](STALKING.md) · [TARGET_RUNTIME.md](TARGET_RUNTIME.md) · [HOWTO_STALK_GENERIC_APP.md](HOWTO_STALK_GENERIC_APP.md) · [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md) · [tools/README.md](../tools/README.md)

---

## Rule: record where the target runs

| Setup | What you get |
|-------|----------------|
| **Fuzz on the lab VM / bare metal** (`randall serve` or `randall agent`, Campaign in that UI) | Procmon `.pml`, Sysmon EVTX, DebugView log, Sysinternals snapshots, pktmon ETL, Scream/ProcDump dumps, memory lens, coverage edges — full stack |
| **Laptop Campaign + `target.agentUrl` only** | Remote process start/stop; **debugger attach skipped**; dumps/lens stay thin on the laptop |

Same rule as Sulley-era procmon + crashbin: tools run **on the target host**. Prefer opening `http://<vm-ip>:5000` on the agent and fuzzing there; pull packs later ([TARGET_RUNTIME.md](TARGET_RUNTIME.md)#remote-lab-workflow-dumps--lens--offline-import).

---

## Recommendations

| Scenario | Enable | Why / skip |
|----------|--------|------------|
| **First triage (any target)** | Scream wait + Procmon + Sysmon | Best crash dumps + file/registry/network activity + process telemetry. Keep UI light. |
| **Protocol / network fuzz (TCP/UDP)** | First triage **+ pktmon** | NIC ETL for wire-level view; often needs elevation. Add **Sysinternals snapshots** if you suspect handle/socket leaks. |
| **File / parser fuzz** | First triage; snapshots optional | Procmon shows file I/O paths. Snapshots help on handle leaks after many iterations. |
| **App logs via OutputDebugString / DbgPrint** | **+ DebugView capture** | Captures Win32 ODS to `debugview.log`. Kernel DbgPrint needs elevated DebugView `/k` (not armed by default). |
| **Handle / DLL / process leaks** | **+ Sysinternals snapshots** | Handle + ListDLLs + PsList at arm/disarm/crash; netstat stand-in (TCPView is GUI-only). |
| **No Scream / debugger attach** | **ProcDump on crash** | Only when `debuggerMode: none`. Skipped if Scream/attach already holds the process. |
| **Heavy / skip for now** | TCPView GUI, VMMap GUI, WPR/xperf, API Monitor, Frida | Not bookended — use interactively if needed. |

Default campaign checklist: **Wait (Scream)** + **Procmon** + **Sysmon**. Add DebugView / snapshots / pktmon when the scenario above applies.

---

## What each recorder / monitor is

| Piece | When to use | How it turns on |
|-------|-------------|-----------------|
| **ProcessMonitor** (internal) | Long-lived TCP/UDP — restart after death | Automatic when `target.longLived: true` (Target Runtime path) |
| **Procmon capture** | File/registry/network activity for the whole run | `fuzz.procmonCapture: true` or Fuzz UI checkbox |
| **Sysmon export** | Process/network/file telemetry from Sysmon for the run window | `fuzz.sysmonCapture: true` or Fuzz UI checkbox — **Sysmon must already be installed** |
| **DebugView capture** | OutputDebugString from the target | `fuzz.debugViewCapture: true` — needs `Dbgview.exe` in `tools/` or PATH |
| **Sysinternals snapshots** | Handle / modules / process list bookends (+ netstat) | `fuzz.sysinternalsSnapshots: true` — Handle, ListDLLs, PsList from Suite |
| **pktmon capture** | NIC-level packet ETL for the run | `fuzz.pktmonCapture: true` or Fuzz UI checkbox (often needs elevation) |
| **ProcDump on crash** | Full dump on unhandled exception when Scream is not attached | `fuzz.procdumpOnCrash: true` — skipped if debugger wait/attach already holds the process |
| **Scream (`debuggerMode: wait`)** | Best crash dumps (second-chance exception → minidump) | `fuzz.debuggerMode: wait` (or UI **Wait**) |
| **WinDbg attach (`attach`)** | Live debug under fuzz | `fuzz.debuggerMode: attach` + Debugging Tools / Preview |
| **Both** | Scream during run + open dump in GUI after crash | `fuzz.debuggerMode: both` or wait + `debuggerOpenOnCrash: true` |
| **MiniDumpWriter (default)** | Basic dump on exit/hang when debugger is `none` | Always on for supported crash paths |
| **Page Heap** | Stronger UAF / heap corruption signals | `target.pageHeap: true` (needs `gflags.exe`) |
| **Coverage / stalk** | Novelty-guided corpus + stalk layers | `fuzz.coverageGuided: true` + DynamoRIO (or `stalkMode: native`) |
| **postStart** | Wait for listen port, prime PDU, open UI / harness | `target.postStart:` list |

Skipped as out of scope for bookends: API Monitor, Frida, **TCPView** (GUI-only — netstat snapshot used instead), **VMMap** (GUI / no stable CLI), WPR/xperf (heavy / interactive). Optional post-crash: Sysinternals `strings` / `sigcheck` on dumps (not wired).

### Sysmon honesty

Sysmon is a **system service**. Randfuzz does **not** run `Sysmon.exe` each campaign, reinstall it, or swap configs per run. Practical workflow:

1. Install once on the fuzz host: `sysmon64 -accepteula -i your-config.xml` (e.g. a trimmed SwiftOnSecurity / custom fuzz profile).
2. Leave the service running with that config.
3. Enable `fuzz.sysmonCapture` — Randfuzz records the run start time and on stop exports `Microsoft-Windows-Sysmon/Operational` for that window via `wevtutil` into the run journal.

Missing Sysmon → warn + continue (same soft-fail style as Procmon).

### ProcDump vs Scream

Only **one** debugger can attach. Prefer **Scream** (`debuggerMode: wait`) for exception dumps. Use `procdumpOnCrash` when you want Sysinternals ProcDump `-e -ma` **instead** (debugger mode `none`). If Scream/attach is already on, ProcDump arm is skipped with a warning.

### Sysinternals snapshots bundle

`fuzz.sysinternalsSnapshots: true` runs a **group** (not five UI checkboxes):

| Tool | When | Notes |
|------|------|-------|
| **Handle** (`handle64.exe -p <pid>`) | arm / disarm / crash | Soft-fail if missing |
| **ListDLLs** (`listdlls64.exe <pid>`) | arm / disarm / crash | Soft-fail if missing |
| **PsList** | arm / disarm / crash | Soft-fail if missing |
| **netstat -ano** | each capture | Stand-in for TCPView (no useful CLI) |
| **PsInfo** | arm only | Optional if present |

Artifacts under `data/runs/<runId>/sysinternals/`.

---

## YAML keys (copy-paste)

```yaml
name: myapp
kind: tcp
target:
  executable: C:/path/to/your/app.exe   # must exist on the fuzz host
  longLived: true
  timeoutMs: 5000
  pageHeap: false                       # true → gflags /p /enable <image> /full
  # agentUrl: http://192.168.2.10:5000  # optional process ownership only
  postStart:
    - op: wait-port
      host: 127.0.0.1
      port: 9999
      timeoutMs: 8000
transport:
  type: tcp
  host: 127.0.0.1
  port: 9999
fuzz:
  maxIterations: 500
  coverageGuided: true
  coverageTcpSpawn: true                # TCP: instrumented spawn per iter when using DynamoRIO
  stalkMode: auto                       # auto | external | native | none
  debuggerMode: wait                    # none | wait | attach | both  (not "scream")
  debuggerKind: auto                    # auto | windbg-preview | windbg | cdb
  debuggerOpenOnCrash: false
  procmonCapture: true                  # bookend → data/runs/<run>/fuzz.pml
  sysmonCapture: true                   # bookend → data/runs/<run>/sysmon-events.evtx
  debugViewCapture: false               # bookend → data/runs/<run>/debugview.log
  sysinternalsSnapshots: false          # arm/disarm/crash → data/runs/<run>/sysinternals/
  procdumpOnCrash: false                # arm ProcDump -e -ma when Scream is not attached
  pktmonCapture: false                  # bookend → data/runs/<run>/fuzz-pktmon.etl (admin often)
  corpusDir: ../data/corpus/myapp
  crashesDir: ../data/crashes/myapp
```

| Key | Values / notes |
|-----|----------------|
| `fuzz.debuggerMode` | `none` · `wait` (Scream) · `attach` · `both` |
| `fuzz.debuggerKind` | `auto` · `windbg-preview` · `windbg` · `cdb` |
| `fuzz.debuggerOpenOnCrash` | Open dump in GUI after save |
| `fuzz.procmonCapture` | Start/stop Sysinternals Procmon for the run |
| `fuzz.sysmonCapture` | Export Sysmon events for the run window (service pre-installed) |
| `fuzz.debugViewCapture` | Start/stop DebugView OutputDebugString log for the run |
| `fuzz.sysinternalsSnapshots` | Handle + ListDLLs + PsList (+ netstat) at arm/disarm/crash |
| `fuzz.procdumpOnCrash` | Arm ProcDump `-e -ma` on target PID if no Scream/attach |
| `fuzz.pktmonCapture` | Start/stop Windows `pktmon` ETL for the run |
| `fuzz.coverageGuided` | Prefer inputs that add edges |
| `fuzz.stalkMode` | Coverage backend selection |
| `fuzz.coverageTcpSpawn` | Long-lived TCP + coverage: spawn instrumented target per iteration |
| `target.pageHeap` | Enable Page Heap via gflags when starting via Target Runtime |
| `target.postStart` | `wait-port` · `sleep` · `exec` · `tcp-send` · `udp-send` · `http-get` |
| `target.longLived` | Keep server up; ProcessMonitor / Target Runtime ownership |

Template: [templates/tcp-runtime.yaml](templates/tcp-runtime.yaml). End-to-end custom app: [HOWTO_STALK_GENERIC_APP.md](HOWTO_STALK_GENERIC_APP.md).

---

## UI steps (Fuzz → Campaign)

1. Open the console **on the machine that runs the binary** (`serve` or `agent`).
2. **Fuzz → Campaign** → pick **Target profile**.
3. Toggles / selects:
   - **Coverage-guided** → `fuzz.coverageGuided`
   - **Debugger** → None / Wait (Scream) / Attach / Both
   - **Debugger kind** → Auto / WinDbg Preview / classic / cdb
   - **Open dump in debugger after crash** → `debuggerOpenOnCrash`
   - **Procmon capture** → `.pml` bookend (needs Procmon in `tools/` or PATH)
   - **Sysmon export** → run-window EVTX (Sysmon service already installed)
   - **ProcDump on crash** → `-e -ma` when not using Scream/attach
   - **pktmon capture** → ETL bookend (built-in; often needs elevation)
   - **DebugView capture** → OutputDebugString log (needs `Dbgview.exe`)
   - **Sysinternals snapshots** → Handle + ListDLLs + PsList + netstat bookends
4. **Doctor** (optional) — checks Procmon, Sysmon, ProcDump, pktmon, DebugView, snapshot tools, debugger mode, DynamoRIO.
5. **Start**. On stop, bookend artifacts land under the run directory (`data/runs/.../`).
6. Crashes → investigation → **Memory lens**; dumps under `data/crashes/<project>/dumps/`.

CLI equivalents:

```powershell
randall fuzz -c projects/local/myapp.yaml --debugger wait --open-on-crash
randall doctor -c projects/local/myapp.yaml
randall scream selftest
```

Remote Procmon API (agent host): `GET /api/remote/tools` · `POST /api/remote/procmon/start|stop`.

---

## Where to put tools (`tools/` or PATH)

Third-party binaries are **not** committed. On the **fuzz host**, copy from the [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite):

| Tool | Placement |
|------|-----------|
| **Procmon** | `tools/Procmon64.exe` (or `Procmon.exe`) **or** on `PATH` |
| **ProcDump** | `tools/procdump.exe` / `procdump64.exe` or PATH / `PROCDUMP_PATH` |
| **DebugView** | `tools/Dbgview.exe` or PATH |
| **Handle** | `tools/handle64.exe` (or `handle.exe`) |
| **ListDLLs** | `tools/listdlls64.exe` |
| **PsList** | `tools/pslist64.exe` |
| **PsInfo** (optional) | `tools/PsInfo64.exe` — used once at arm |
| **Sysmon** | Install as a **service** once (`Sysmon64.exe -i config.xml`) — not a per-run drop-in |
| **pktmon** | Built into Windows (`%SystemRoot%\System32\pktmon.exe`) — no download |
| **DynamoRIO** | `tools/dynamorio/bin64/drrun.exe` (or `DYNAMORIO_HOME`) — [tools/README.md](../tools/README.md) |
| **gflags / cdb / WinDbg** | Windows SDK Debugging Tools (Kit Debuggers) or PATH |
| **WinDbg Preview** | Microsoft Store / usual install paths (auto-discovered) |

```powershell
# Example Sysinternals drop-in (from Suite zip)
copy Procmon64.exe tools\
copy procdump64.exe tools\procdump.exe
copy Dbgview.exe tools\
copy handle64.exe tools\
copy listdlls64.exe tools\
copy pslist64.exe tools\
randall doctor -c projects/local/myapp.yaml
```

---

## Custom app on a VM (short path)

1. Snapshot the VM.
2. Deploy Randfuzz + your `.exe` on the VM; put Procmon / ProcDump / DebugView / Handle / ListDLLs / PsList / DynamoRIO under `tools/` if you want them. Install Sysmon once if you want EVTX export.
3. Create `projects/local/myapp.yaml` (Scare Floor **Create new target**, or copy the YAML above).
4. On the VM: `randall agent --port 5000` (or `serve`) → open that URL.
5. **Lab servers → Target Runtime** → start; confirm `postStart` / listen port.
6. Enable **Wait** + optional **Procmon** / **Sysmon** / **DebugView** / **snapshots** / **pktmon** / **Coverage-guided** → Campaign **Start**.
7. Export: **Bundles → Crash artifact pack**, or `randall crashes pack -p myapp`.

---

## Artifact locations

| Artifact | Path |
|----------|------|
| Procmon log | `data/runs/<runId>/fuzz.pml` |
| Sysmon export | `data/runs/<runId>/sysmon-events.evtx` (+ `sysmon-export.txt` meta; XML fallback if EVTX empty) |
| DebugView log | `data/runs/<runId>/debugview.log` (+ `debugview-capture.txt`) |
| Sysinternals snapshots | `data/runs/<runId>/sysinternals/` (`arm-*`, `disarm-*`, `crash_*`, `snapshots.txt`) |
| pktmon capture | `data/runs/<runId>/fuzz-pktmon.etl` (+ `pktmon-capture.txt`; optional `.txt` via `etl2txt`) |
| ProcDump dumps | `data/crashes/<project>/dumps/procdump_*.dmp` |
| Minidumps (Scream / default) | `data/crashes/<project>/dumps/*.dmp` |
| Crash sidecars / lens | `data/crashes/<project>/*_crash.json`, `*_memory_lens.*` |
| Coverage edges | `data/corpus/<project>/edges.txt` (+ stalk layers under `data/stalk/<project>/`) |
| Execution journal | `data/runs/<runId>/` (`fuzz.executionLog`) |
