# Recording & process monitoring during fuzz runs

Operator guide for **Procmon**, **Sysmon export**, **pktmon**, **ProcDump**, **Scream / debugger wait**, **dumps**, **Page Heap**, **coverage**, and **postStart** — what each does, YAML keys, UI toggles, and where tools must live.

There is no separate `target_recorder` binary. Recording is wired through **FuzzEngine** + **Target Runtime** using the knobs below. (`ProcessMonitor` is the internal long-lived start/detect-death/restart helper — not Sysinternals Procmon.)

**Related:** [STALKING.md](STALKING.md) · [TARGET_RUNTIME.md](TARGET_RUNTIME.md) · [HOWTO_STALK_GENERIC_APP.md](HOWTO_STALK_GENERIC_APP.md) · [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md) · [tools/README.md](../tools/README.md)

---

## Rule: record where the target runs

| Setup | What you get |
|-------|----------------|
| **Fuzz on the lab VM / bare metal** (`randall serve` or `randall agent`, Campaign in that UI) | Procmon `.pml`, Sysmon EVTX, pktmon ETL, Scream/ProcDump dumps, memory lens, coverage edges — full stack |
| **Laptop Campaign + `target.agentUrl` only** | Remote process start/stop; **debugger attach skipped**; dumps/lens stay thin on the laptop |

Same rule as Sulley-era procmon + crashbin: tools run **on the target host**. Prefer opening `http://<vm-ip>:5000` on the agent and fuzzing there; pull packs later ([TARGET_RUNTIME.md](TARGET_RUNTIME.md)#remote-lab-workflow-dumps--lens--offline-import).

---

## What each recorder / monitor is

| Piece | When to use | How it turns on |
|-------|-------------|-----------------|
| **ProcessMonitor** (internal) | Long-lived TCP/UDP — restart after death | Automatic when `target.longLived: true` (Target Runtime path) |
| **Procmon capture** | File/registry/network activity for the whole run | `fuzz.procmonCapture: true` or Fuzz UI checkbox |
| **Sysmon export** | Process/network/file telemetry from Sysmon for the run window | `fuzz.sysmonCapture: true` or Fuzz UI checkbox — **Sysmon must already be installed** |
| **pktmon capture** | NIC-level packet ETL for the run | `fuzz.pktmonCapture: true` or Fuzz UI checkbox (often needs elevation) |
| **ProcDump on crash** | Full dump on unhandled exception when Scream is not attached | `fuzz.procdumpOnCrash: true` — skipped if debugger wait/attach already holds the process |
| **Scream (`debuggerMode: wait`)** | Best crash dumps (second-chance exception → minidump) | `fuzz.debuggerMode: wait` (or UI **Wait**) |
| **WinDbg attach (`attach`)** | Live debug under fuzz | `fuzz.debuggerMode: attach` + Debugging Tools / Preview |
| **Both** | Scream during run + open dump in GUI after crash | `fuzz.debuggerMode: both` or wait + `debuggerOpenOnCrash: true` |
| **MiniDumpWriter (default)** | Basic dump on exit/hang when debugger is `none` | Always on for supported crash paths |
| **Page Heap** | Stronger UAF / heap corruption signals | `target.pageHeap: true` (needs `gflags.exe`) |
| **Coverage / stalk** | Novelty-guided corpus + stalk layers | `fuzz.coverageGuided: true` + DynamoRIO (or `stalkMode: native`) |
| **postStart** | Wait for listen port, prime PDU, open UI / harness | `target.postStart:` list |

Skipped as out of scope for bookends: API Monitor, Frida, TCPView GUI, WPR/xperf (heavy / interactive).

### Sysmon honesty

Sysmon is a **system service**. Randfuzz does **not** run `Sysmon.exe` each campaign, reinstall it, or swap configs per run. Practical workflow:

1. Install once on the fuzz host: `sysmon64 -accepteula -i your-config.xml` (e.g. a trimmed SwiftOnSecurity / custom fuzz profile).
2. Leave the service running with that config.
3. Enable `fuzz.sysmonCapture` — Randfuzz records the run start time and on stop exports `Microsoft-Windows-Sysmon/Operational` for that window via `wevtutil` into the run journal.

Missing Sysmon → warn + continue (same soft-fail style as Procmon).

### ProcDump vs Scream

Only **one** debugger can attach. Prefer **Scream** (`debuggerMode: wait`) for exception dumps. Use `procdumpOnCrash` when you want Sysinternals ProcDump `-e -ma` **instead** (debugger mode `none`). If Scream/attach is already on, ProcDump arm is skipped with a warning.

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
4. **Doctor** (optional) — checks Procmon, Sysmon, ProcDump, pktmon, debugger mode, DynamoRIO.
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

Third-party binaries are **not** committed. On the **fuzz host**:

| Tool | Placement |
|------|-----------|
| **Procmon** | `tools/Procmon64.exe` (or `Procmon.exe`) **or** on `PATH` |
| **ProcDump** | `tools/procdump.exe` / `procdump64.exe` or PATH / `PROCDUMP_PATH` |
| **Sysmon** | Install as a **service** once (`Sysmon64.exe -i config.xml`) — not a per-run drop-in |
| **pktmon** | Built into Windows (`%SystemRoot%\System32\pktmon.exe`) — no download |
| **DynamoRIO** | `tools/dynamorio/bin64/drrun.exe` (or `DYNAMORIO_HOME`) — [tools/README.md](../tools/README.md) |
| **gflags / cdb / WinDbg** | Windows SDK Debugging Tools (Kit Debuggers) or PATH |
| **WinDbg Preview** | Microsoft Store / usual install paths (auto-discovered) |

```powershell
# Example Procmon / ProcDump drop-in
copy Procmon64.exe tools\
copy procdump64.exe tools\procdump.exe
randall doctor -c projects/local/myapp.yaml
```

---

## Custom app on a VM (short path)

1. Snapshot the VM.
2. Deploy Randfuzz + your `.exe` on the VM; put Procmon / ProcDump / DynamoRIO under `tools/` if you want them. Install Sysmon once if you want EVTX export.
3. Create `projects/local/myapp.yaml` (Scare Floor **Create new target**, or copy the YAML above).
4. On the VM: `randall agent --port 5000` (or `serve`) → open that URL.
5. **Lab servers → Target Runtime** → start; confirm `postStart` / listen port.
6. Enable **Wait** + optional **Procmon** / **Sysmon** / **pktmon** / **Coverage-guided** → Campaign **Start**.
7. Export: **Bundles → Crash artifact pack**, or `randall crashes pack -p myapp`.

---

## Artifact locations

| Artifact | Path |
|----------|------|
| Procmon log | `data/runs/<runId>/fuzz.pml` |
| Sysmon export | `data/runs/<runId>/sysmon-events.evtx` (+ `sysmon-export.txt` meta; XML fallback if EVTX empty) |
| pktmon capture | `data/runs/<runId>/fuzz-pktmon.etl` (+ `pktmon-capture.txt`; optional `.txt` via `etl2txt`) |
| ProcDump dumps | `data/crashes/<project>/dumps/procdump_*.dmp` |
| Minidumps (Scream / default) | `data/crashes/<project>/dumps/*.dmp` |
| Crash sidecars / lens | `data/crashes/<project>/*_crash.json`, `*_memory_lens.*` |
| Coverage edges | `data/corpus/<project>/edges.txt` (+ stalk layers under `data/stalk/<project>/`) |
| Execution journal | `data/runs/<runId>/` (`fuzz.executionLog`) |
