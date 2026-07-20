# Recording & process monitoring during fuzz runs

**Philosophy (2026):** Observation tools explain what happened before, during, and after a crash — they do not find crashes. Randfuzz finds faults (mutators, coverage, Scream); Sysinternals + modern Windows instrumentation explain the blast radius.

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
| **Fuzz on the lab VM / bare metal** (`randall serve` or `randall agent`) | Full stack: Procmon, ETW/WPR, TCPVCon, DebugView, snapshots, Strings, pktmon, tshark pcap, Scream/ProcDump, coverage |
| **Laptop Campaign + `target.agentUrl` only** | Remote process start/stop; debugger attach skipped; dumps stay thin on the laptop |

Prefer opening `http://<vm-ip>:5000` on the agent and fuzzing there; pull packs later ([TARGET_RUNTIME.md](TARGET_RUNTIME.md)#remote-lab-workflow-dumps--lens--offline-import).

---

## Recommendations (defaults)

| Scenario | Enable | Why / skip |
|----------|--------|------------|
| **Almost every session** | **Scream wait** + **Procmon** + **Sysinternals snapshots** | Crash dumps + file/registry/network activity + Handle/ListDLLs bookends (SigCheck/AccessChk when present) |
| **Long campaigns** (hours+) | Prefer **ETW/WPR** (`fuzz.etwCapture`) over Procmon | Lower overhead than Procmon for multi-hour runs; open ETL in WPA / PerfView / UIforETW. Keep Procmon for short interactive drills |
| **Crashes appearing, no Scream** | **+ ProcDump on crash** | Only when `debuggerMode: none`. Skipped if Scream/attach already holds the process |
| **ODS / DbgPrint logging** | **+ DebugView** | Win32 OutputDebugString → `debugview.log`. Kernel DbgPrint needs elevated DebugView `/k` (not armed by default) |
| **Network / protocol** | **+ TCPVCon** + **pktmon** + **tshark pcap** | Connection bookends; pktmon ETL + Wireshark `fuzz.pcapng` (Npcap/admin often required) |
| **File format / parser deep dive** | Procmon or ETW + snapshots + **API Monitor** (GUI) + Scream + DebugView | Procmon/ETW show load paths; **API Monitor** shows call args (CreateFile, ReadFile, heap APIs) Procmon does not |
| **Internal buffers / no recompile** | **Frida** (GUI companion) beside the run | Dynamic hooks, dump buffers, stalk parsers without rebuilding |
| **Interesting crash payload** | **+ Strings on crash** | Opt-in — avoids surprise cost on huge inputs |
| **Hard-to-repro crashes** | **WinDbg TTD** (External) | Time-travel record/replay after you have a crashing case |
| **Drivers / services / kernel** | LiveKD, WinObj, AppVerifier, ProcMon boot logging | **External** / GUI — see Tier 3–4 below. Service restart via [Target Runtime](TARGET_RUNTIME.md) (`longLived` + restart); PsService/PsKill are companions |
| **Skip / interactive only** | Process Explorer, RAMMap, LiveKD, TCPView GUI, API Monitor, Frida, Detours toolkit, WinAFL | Not bookended (ETW/WPR is optional Wired via `fuzz.etwCapture`) |

Default campaign checklist: **Wait (Scream)** + **Procmon** (or **ETW** for long runs) + **Sysinternals snapshots**. Add TCPVCon / pktmon / tshark for protocol targets; DebugView / ProcDump / Strings when the row above applies.

**Sysmon footnote:** host-wide EVTX remains an optional **External** companion if you already run it on the lab box. Randfuzz does **not** export or configure Sysmon — it is not part of the fuzz product path.

---

## Beyond Sysinternals — modern observation stack

Sysinternals covers most day-to-day blast-radius work. For long campaigns, parser RE, and coverage viz, add these Windows / research tools beside Randfuzz. Status is honest: only soft-fail bookends are **Wired**.

| Tool | Role in fuzzing / RE | Status | Notes |
|------|----------------------|--------|-------|
| **ETW** via WPR → WPA / PerfView / UIforETW | File/registry/disk/network timeline at lower overhead than Procmon | **Wired** | `fuzz.etwCapture: true` → `data/runs/<id>/fuzz-etw.etl`. Light FileIO+Registry+DiskIO+Network profiles. Soft-fail if `wpr` missing/denied. Analyze offline in WPA/PerfView/UIforETW |
| **API Monitor** | API args & return values (deeper than Procmon’s high-level FS/Reg view) | **GUI companion** | Install separately; filter on target PID/module. Excellent for parser / file-format fuzzing. Not injected by Randfuzz |
| **Frida** | Dynamic hooks, dump internal buffers, no recompile | **GUI companion** / **External** | Run `frida -p <pid> -l hook.js` (or Frida GUI) on Monitor 2/3 while Campaign runs. Document scripts next to the project; do not expect Randfuzz to inject |
| **Intel PIN / DynamoRIO / TinyInst** | Coverage / DBI | **Wired** (DynamoRIO) · **External** (PIN, TinyInst) | Randfuzz coverageGuided uses DynamoRIO drcov / native stalk. PIN and TinyInst are external alternatives (e.g. WinAFL+TinyInst) |
| **WinDbg TTD** | Time-travel debugging for hard crashes | **External** | Record a repro, then step backward through the faulting path. Pair with Scream/ProcDump artifacts |
| **Detours** | Custom telemetry / API intercept toolkit | **External** | Build your own hooks when Frida scripts are not enough; not shipped with Randfuzz |
| **Sysmon** | Host-wide process/network EVTX | **External only** | Optional lab companion — not wired, not an EDR pitch. See footnote above |
| **WinDbg Preview** | Crash / live analysis | **Wired** | `debuggerMode`, open-on-crash — first-choice dump viewer |
| **Lighthouse / WinAFL coverage** | Coverage visualization | **External** | Import drcov / WinAFL traces into Lighthouse (IDA/Binary Ninja). Randfuzz stalk export helps ([STALKING.md](STALKING.md)) |

### When to reach for which

| Need | Prefer |
|------|--------|
| Short interactive session | Procmon (Wired) |
| Multi-hour campaign, Procmon too heavy | ETW/WPR (Wired) → WPA/PerfView |
| “Which API ate this buffer?” | API Monitor (GUI) |
| Dump heap/parser state without rebuild | Frida (GUI/External) |
| Edge feedback inside Randfuzz | DynamoRIO / `coverageGuided` (Wired) |
| Visualize coverage in IDA/BN | Lighthouse + stalk/drcov export (External) |
| One weird crash you cannot single-step | WinDbg TTD (External) |
| Custom long-lived telemetry DLL | Detours (External) |

<a id="api-monitor-frida"></a>

### API Monitor & Frida (RE companions)

⭐⭐⭐⭐⭐ for **parser RE** / dynamic instrumentation. **GUI companions** — install yourself, run on the **fuzz host** beside a Campaign. Randfuzz does **not** inject or bookend them (yet).

#### API Monitor

Hooks Windows API calls and shows **function parameters**, **return values**, **structures**, COM, Winsock, Crypto, Registry, File APIs, and hundreds of DLLs. For parser / file-format work it is often more informative than Procmon alone.

| Procmon (Wired) | API Monitor (GUI) |
|-----------------|-------------------|
| Shows a file was opened | Exact **CreateFile** parameters |
| Shows registry access | Exact **RegSetValueEx** data |
| Shows process creation | **CreateProcess** arguments |
| No function arguments | Full arguments + structures |

Install: [rohitab.com/apimonitor](http://www.rohitab.com/apimonitor) (or current mirror). Filter on target PID/module; enable File / Process / Memory categories you care about; save the session when a crash lands.

#### Frida

Dynamic instrumentation without rebuilding the target:

- Hook any function  
- Modify parameters  
- Dump internal buffers  
- Log API traffic  
- Instrument parsers / decoders live  

```powershell
# Via installer (default) or: python -m pip install frida-tools
# After Target Runtime starts — PID from UI / doctor / Process Explorer
frida -p <pid> -l projects/local/myapp/hooks.js
```

Keep scripts next to the project; do not expect Randfuzz to inject.

#### Run beside a Randfuzz campaign (fuzz host)

1. On the lab VM / bare metal: start Target Runtime (or Campaign with long-lived target).  
2. Note the target **PID**.  
3. Attach **API Monitor** and/or **Frida** to that PID (Monitor 2/3).  
4. In the UI, pick **First triage** or **Parser / RE** (Procmon + snapshots) — Debugger **Wait** separately.  
5. Start the Campaign. Wired bookends write under `data/runs/<id>/`; companion sessions you save yourself.  
6. On crash: keep the API Monitor / Frida session + Scream dump + Procmon `.pml`.

UI: Fuzz → Campaign → **RE companions** panel (guidance only). Help deep-link: this section.

**ETW viewers (for Wired or manual WPR)** — Windows Performance Analyzer (`wpa.exe` from ADK/WPT), [PerfView](https://github.com/microsoft/perfview), or [UIforETW](https://github.com/google/UIforETW). Manual bookend if not using `fuzz.etwCapture`:

```powershell
wpr -start FileIO.light -start Registry.light -start DiskIO.light -start Network.light -filemode
# … fuzz …
wpr -stop data\runs\<id>\manual-etw.etl "Randfuzz manual"
```

**WinAFL + TinyInst / Lighthouse** — External coverage pipeline; use when you want AFL-style Windows fuzzing or BB highlighting in a disassembler. Randfuzz’s DynamoRIO path stays the in-product coverageGuided option.

---

## Tier matrices (Randfuzz mapping)

### Tier 1 — Must have (almost every session)

| Tool | Why | Status | Enable / place |
|------|-----|--------|----------------|
| **Process Monitor** | Registry, filesystem, process/thread, DLL load, pipes, ALPC — what input reached before the crash | **Wired** | `fuzz.procmonCapture: true` / UI **Procmon** → `tools/Procmon64.exe` → `data/runs/<id>/fuzz.pml` |
| **ETW / WPR** | Same categories at lower overhead for long runs | **Wired** | `fuzz.etwCapture: true` / UI **ETW/WPR** → `wpr.exe` → `fuzz-etw.etl` |
| **Process Explorer** | Live handles, threads, modules, privileges, parent/child | **GUI companion** | Monitor 2/3 — `procexp64.exe` (not bookended) |
| **Handle** | Leaked handles after many iterations | **Wired** (snapshots) | `fuzz.sysinternalsSnapshots: true` → `tools/handle64.exe` |
| **ListDLLs** | Loaded modules during the test | **Wired** (snapshots) | same → `tools/listdlls64.exe` |
| **VMMap** | Heap growth, fragmentation, VA exhaustion | **Wired** (silent CLI in snapshots) + **GUI companion** | Snapshots run `vmmap -accepteula -p <pid> out.txt` **Hidden** on arm/crash (scan+exit). Soft-fail / kill on timeout. Prefer interactive GUI on Monitor 2/3 for live digs |
| **RAMMap** | Kernel / physical resource leaks | **GUI companion** | Monitor 3 — not automated |
| **PsList** (+ optional PsInfo) | Process list / host info bookends | **Wired** (snapshots) | `tools/pslist64.exe`, optional `PsInfo64.exe` |

### Tier 2 — Memory & crash analysis

| Tool | Purpose | Status | Enable / place |
|------|---------|--------|----------------|
| **ProcDump** | Full dump on unhandled exception | **Wired** | `fuzz.procdumpOnCrash: true` when no Scream — `tools/procdump.exe` |
| **Scream** (`debuggerMode: wait`) | First-party second-chance minidump | **Wired** | UI **Wait** / `debuggerMode: wait` (preferred over ProcDump) |
| **WinDbg Preview** | Dump / live analysis | **Wired** | `debuggerMode`, open-on-crash — install via `scripts/install-debuggers.ps1` (winget `Microsoft.WinDbg`) |
| **WinDbg (classic) / cdb** | Attach / open dump / wait fallback | **Wired** | Same installer → SDK Debugging Tools (`windbg.exe` / `cdb.exe`) |
| **WinDbg TTD** | Time-travel for hard crashes | **External** | Record/replay outside Randfuzz |
| **LiveKD** | Kernel debug without reboot | **External** | Run interactively when investigating drivers |
| **DebugView** | OutputDebugString / app debug spew | **Wired** | `fuzz.debugViewCapture: true` → `tools/Dbgview.exe` → `debugview.log` |
| **Strings** | Inspect crashing / corpus inputs | **Wired** | `fuzz.stringsOnCrash: true` / UI checkbox → `tools/strings64.exe` → `*_strings.txt` beside crash `.bin` |
| **SigCheck** | Binary / signature / version at arm | **Wired** (snapshots) | Included when snapshots on + `sigcheck64.exe` → `sysinternals/sigcheck-target.txt` |
| **PageHeap (GFlags)** | Earlier heap corruption | **Wired** | `target.pageHeap: true` |
| **Application Verifier** | Handle/API misuse | **External** | Enable via AppVerifier GUI / `appverif` |

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

Run together: **Procmon or ETW** (Wired) + **API Monitor** (GUI) + **Process Explorer** (GUI) + **VMMap** (GUI) + **ProcDump/Scream** (Wired) + **DebugView** (Wired) + **snapshots** (Wired). Optional **Frida** for decoder buffers. You typically see malformed file load → decoder DLL → registry/temp paths → heap growth → dump.

### Tier 6 — COM / RPC / ALPC

| Tool | Status |
|------|--------|
| Procmon, Handle, ETW/WPR | **Wired** |
| Process Explorer, WinObj, API Monitor | **GUI companion** / **External** |
| AccessChk | **Wired** (optional in snapshots) |

---

## Companion tools (coverage & RE)

| Tool | Use | Status |
|------|-----|--------|
| **DynamoRIO** (drcov) | Coverage-guided Campaign | **Wired** — `fuzz.coverageGuided: true` |
| **WinAFL / TinyInst** | Coverage-guided Windows user-mode (external pipeline) | **External** |
| **Intel PIN** | DBI / coverage research | **External** |
| **Lighthouse / Ghidra / IDA / Binary Ninja / x64dbg** | Coverage viz / RE / triage | **External** — stalk export helps ([STALKING.md](STALKING.md)) |
| **Boofuzz** | Network protocol fuzzing | Related lineage — Randfuzz Campaign |
| **pktmon** | NIC ETL | **Wired** — `fuzz.pktmonCapture` |
| **tshark** | Live pcapng | **Wired** — `fuzz.tsharkCapture` → `fuzz.pcapng` |
| **TCPVCon** | Connection snapshots (TCPView CLI) | **Wired** — `fuzz.tcpvconCapture` |
| **Frida / API Monitor / Detours** | Dynamic observation | **GUI companion** / **External** — see [API Monitor & Frida](#api-monitor-frida) |
| **Sysmon** | Host-wide EVTX | **External only** — Randfuzz does **not** export Sysmon |

---

## Example workstation layout (Randfuzz lab)

Fuzzing-focused layout (ignore EDR/validation framing):

| Role | Tools |
|------|-------|
| **Crash & control** | Randfuzz agent UI, Scream / ProcDump, WinDbg Preview (+ TTD when needed) |
| **Process / FS / Reg** | ProcMon *or* ETW/WPA (long campaigns), Sysinternals snapshots |
| **API / buffers** | API Monitor, Frida |
| **Coverage** | WinAFL+TinyInst **or** DynamoRIO (`coverageGuided`), Lighthouse offline |
| **Heap / verifier** | PageHeap + AppVerifier |
| **Optional host log** | Sysmon EVTX (external companion only) |

```
Monitor 1
---------
WinDbg Preview (dumps / attach / TTD replay)
Randfuzz agent UI (Campaign + live log)
Scream / ProcDump status

Monitor 2
---------
ProcMon (filters: Process Name is <target.exe>; drop noise)
  — or skip ProcMon and rely on fuzz.etwCapture + WPA later
optional: API Monitor / Frida attached to target PID
optional: TCPView GUI if not using TCPVCon bookends

Monitor 3
---------
Process Explorer
VMMap
DbgView (if not using fuzz.debugViewCapture)
optional: AppVerifier / coverage viz (Lighthouse in IDA/BN)

Background
----------
randall agent / Campaign fuzz loop
DynamoRIO coverage (optional) or external WinAFL+TinyInst
WPR ETW bookend (optional fuzz.etwCapture)
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
| **VMMap** | arm / crash | Silent Hidden CLI (`-p <pid> out.txt`); kill + soft-fail if GUI hangs |
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
  etwCapture: false               # → fuzz-etw.etl (WPR light profiles; opt-in)
  tcpvconCapture: true            # → tcpvcon/
  debugViewCapture: false         # → debugview.log
  sysinternalsSnapshots: true     # → sysinternals/ (+ sigcheck/accesschk/vmmap if present)
  stringsOnCrash: false           # → <crash>_strings.txt (opt-in)
  procdumpOnCrash: false          # ProcDump -e -ma when no Scream
  pktmonCapture: false            # → fuzz-pktmon.etl
  tsharkCapture: false            # → fuzz.pcapng (Wireshark tshark; Npcap/admin often required)
```

| Key | Notes |
|-----|-------|
| `fuzz.procmonCapture` | Procmon `.pml` bookend |
| `fuzz.etwCapture` | WPR ETW bookend (FileIO+Registry+DiskIO+Network light, `-filemode`) → `fuzz-etw.etl` |
| `fuzz.tcpvconCapture` | TCPVCon arm/disarm/crash |
| `fuzz.debugViewCapture` | DebugView ODS log |
| `fuzz.sysinternalsSnapshots` | Snapshot bundle (Handle/ListDLLs/PsList + SigCheck/AccessChk/VMMap when present) |
| `fuzz.stringsOnCrash` | Strings on saved crashing input |
| `fuzz.procdumpOnCrash` | ProcDump `-e -ma` if no Scream/attach |
| `fuzz.pktmonCapture` | Windows pktmon ETL |
| `fuzz.tsharkCapture` | Wireshark tshark → `fuzz.pcapng` (optional BPF from transport host/port; soft-fail if missing/denied) |
| `fuzz.coverageGuided` | DynamoRIO / native stalk coverage |
| `target.pageHeap` | GFlags Page Heap via Target Runtime |
| `target.longLived` | ProcessMonitor / Target Runtime ownership + restart |

Template: [templates/tcp-runtime.yaml](templates/tcp-runtime.yaml).

### UI (Fuzz → Campaign)

- **Debugger** → None / Wait (Scream) / Attach / Both  
- **Recording profile** → Off · First triage · Network / protocol · Deep dive · **Parser / RE** · Custom  
- **RE companions** → API Monitor + Frida guidance (not injected; expand with Parser / RE)  
- **Advanced** → Procmon · ETW/WPR · TCPVCon · ProcDump · pktmon · **tshark pcap** · DebugView · snapshots · Strings  
- **Doctor** probes the Suite tools + `wpr` / `pktmon` / `tshark` + WinDbg Preview / classic / cdb  

```powershell
# Debuggers for Scream wait / open dump (Admin for classic SDK tools):
powershell -ExecutionPolicy Bypass -File .\scripts\install-debuggers.ps1

randall fuzz -c projects/local/myapp.yaml --debugger wait
randall doctor -c projects/local/myapp.yaml
```

### Stopping captures

Armed bookends stop automatically when the run **completes**, the user hits **Stop**, or the engine faults (`try/finally` → `RecordingTeardown`). The live log shows a line like `Recording stopped: procmon → …, debugview → …`.

| Action | What it does |
|--------|----------------|
| **Stop** (Campaign) / cancel fuzz | Ends the run **and** stops every armed recorder |
| **Stop recording** (Campaign) | Emergency orphan cleanup only — kills leftover Procmon/DebugView/ProcDump/tshark and runs `wpr -cancel` / `pktmon stop` |
| `randall recorders stop` | Same orphan cleanup from the CLI (after a hard kill / agent disconnect) |
| `POST /api/recorders/stop` | Same as above on the lab agent / serve host |

Verify nothing is left running:

```powershell
Get-Process Procmon*, Dbgview*, procdump*, tshark, dumpcap -ErrorAction SilentlyContinue
wpr -status          # should show no active session (or cancel with recorders stop)
pktmon status        # capture should be stopped
```

Normal **Stop** is enough for day-to-day runs. Use **Stop recording** / `randall recorders stop` only if a GUI tool or WPR/pktmon/tshark session is still up after the fuzz exited.

---

## Where to put tools (`tools/` or PATH)

Binaries are **not** committed. On the **fuzz host**, prefer the installer (Suite zip → `tools/`):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1
# Sysinternals only / skip Frida:
#   ...\install-recording-tools.ps1 -SysinternalsOnly
#   ...\install-recording-tools.ps1 -SkipFrida
```

Or copy manually from the [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) / [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview):

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
| VMMap | `tools/vmmap64.exe` | Silent CLI in snapshots + GUI companion |
| Process Explorer / RAMMap | `procexp64.exe` / `RAMMap.exe` | GUI companion |
| PsInfo | `tools/PsInfo64.exe` | Optional arm |
| pktmon | Built-in Windows | Wired |
| tshark | Wireshark install / `tools/tshark.exe` / PATH | Wired (`tsharkCapture`) — optional; see [tools/README.md](../tools/README.md) |
| wpr (ETW) | Built-in Windows (`System32\wpr.exe`) | Wired (`etwCapture`) |
| DynamoRIO / gflags / WinDbg / cdb | `install-debuggers.ps1` / [tools/README.md](../tools/README.md) | Wired / SDK |
| API Monitor | `tools/API Monitor/apimonitor-x64.exe` (installer best-effort) | GUI companion |
| Frida | `pip install frida-tools` (installer default; `-SkipFrida`) | External companion |

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1
dotnet run --project src/Randall.Cli -- doctor -c projects/local/myapp.yaml
```

---

## ProcDump vs Scream

Only **one** debugger can attach. Prefer **Scream** (`debuggerMode: wait`). Use `procdumpOnCrash` when you want ProcDump `-e -ma` **instead** (`debuggerMode: none`). If Scream/attach is already on, ProcDump arm is skipped with a warning.

---

## What you see vs what runs in the background

**First triage** (UI default) only enables **Procmon + Sysinternals snapshots**. TCPVCon / ETW / DebugView / pktmon / tshark / ProcDump / Strings stay off until you pick **Network / protocol**, **Deep dive**, or **Custom**.

**Network / protocol** enables Procmon + TCPVCon + **pktmon** + **tshark pcap** + Sysinternals snapshots (real `fuzz.pcapng` beside pktmon ETL).

| Tool | Visible window? | When it runs | Elevation | Soft-fail | Verify under `data/runs/<runId>/` |
|------|-----------------|--------------|-----------|-----------|----------------------------------|
| **Procmon** | Yes — minimized (`/Quiet /Minimized`); taskbar/tray often visible | Whole run (bookend) | Usually fine as user; filter drivers may need admin | Missing exe / start fail → warn, campaign continues | `fuzz.pml` growing; stop → file remains |
| **Handle** | No — headless CLI | Snapshots: arm / disarm / crash | Rarely needed | Missing exe skipped | `sysinternals/arm-handle.txt` (also `disarm-*`, `crash_*`) |
| **ListDLLs** | No — headless CLI | Snapshots: arm / disarm / crash | Soft-fail if denied | Missing / access denied | `sysinternals/arm-listdlls.txt` |
| **PsList** | No — headless CLI | Snapshots: arm / disarm / crash (+ host-wide if no PID) | No | Missing exe skipped | `sysinternals/arm-pslist.txt` |
| **SigCheck** | No — headless CLI | Snapshots: **arm once** (target exe) | No | Missing path → stub note in file | `sysinternals/sigcheck-target.txt` |
| **AccessChk** | No — headless CLI | Snapshots: arm / disarm / crash (`-p -f`) | May need admin for some tokens | Missing / denied soft-fail | `sysinternals/arm-accesschk.txt` |
| **VMMap** | **No** (Hidden CLI). Interactive GUI is companion-only on Monitor 2/3 | Snapshots: **arm + crash** only (not disarm) | May need rights to open target | Timeout → process killed; no export → soft-fail | `sysinternals/arm-vmmap.txt` + `arm-vmmap-run.txt` |
| **netstat** (in snapshots) | No | Each snapshot | No | Unlikely | `sysinternals/arm-netstat.txt` |
| **PsInfo** | No — headless CLI | Snapshots: **arm only** (optional) | No | Missing skipped | `sysinternals/arm-psinfo.txt` |
| **TCPVCon** | No — headless CLI | Arm / disarm / crash (own knobs) | No | Missing → `tcpvcon-capture.txt` says skipped | `tcpvcon/arm.txt` + `tcpvcon-capture.txt` |
| **DebugView** | Tray (`/t`); may flash briefly | Whole run when enabled | Kernel `/k` needs admin (not default) | Missing exe soft-fail | `debugview.log` + `debugview-capture.txt` |
| **ETW / WPR** | No — headless `wpr.exe` | Whole run when enabled | **Often needs elevation**; denied → soft-fail | Missing/denied → warn | `fuzz-etw.etl` + `etw-capture.txt` |
| **pktmon** | No — headless | Whole run when enabled | **Often needs elevation**; denied → soft-fail | Missing/denied → warn | `fuzz-pktmon.etl` + `pktmon-capture.txt` |
| **tshark** | No — headless console | Whole run when enabled | **Npcap + often elevation**; try without UAC first, soft-fail if denied | Missing Wireshark/tshark → warn + install hint | `fuzz.pcapng` + `tshark-capture.txt` |
| **ProcDump** | No — headless console | Armed for duration; dump on exception | Usually fine | Skipped if Scream/attach already holds process; missing exe soft-fail | `data/crashes/<project>/dumps/procdump_*.dmp` (not under runs/) |

**Why First triage looked like “only Procmon + VMMap”:** Handle / ListDLLs / PsList / SigCheck / AccessChk / netstat run **headless** inside the snapshots bundle — no windows. Procmon is the long-lived visible bookend; older VMMap launches could pop a GUI (fixed: Hidden CLI + kill on timeout). Confirm the rest via files under `sysinternals/` and `snapshots.txt`.

---

## Artifact locations

| Artifact | Path |
|----------|------|
| Procmon | `data/runs/<runId>/fuzz.pml` |
| ETW / WPR | `data/runs/<runId>/fuzz-etw.etl` (+ `etw-capture.txt`) |
| TCPVCon | `data/runs/<runId>/tcpvcon/` + `tcpvcon-capture.txt` |
| DebugView | `data/runs/<runId>/debugview.log` |
| Snapshots | `data/runs/<runId>/sysinternals/` (`arm-*`, `disarm-*`, `crash_*`, `sigcheck-target.txt`, `snapshots.txt`) |
| Strings on crash | `data/crashes/<project>/<crash>_strings.txt` (beside `.bin`) |
| pktmon | `data/runs/<runId>/fuzz-pktmon.etl` |
| tshark pcap | `data/runs/<runId>/fuzz.pcapng` (+ `tshark-capture.txt`) |
| ProcDump / Scream dumps | `data/crashes/<project>/dumps/` |
| Crash sidecars / lens | `data/crashes/<project>/*_crash.json`, `*_memory_lens.*` |
| Coverage | `data/corpus/<project>/edges.txt` |

### UI review vs on-disk logs

Artifacts land in `data/runs/<runId>/` and `data/crashes/<project>/` on the fuzz host.

| In the UI today | Not in the UI yet |
|-----------------|-------------------|
| **Crashes** investigation | Browsing/viewing `.pml`, `debugview.log`, `tcpvcon/`, `sysinternals/`, ETW/pktmon ETL, `fuzz.pcapng` |
| **Dashboard** stalk timeline (from journal) | Full `run.json` / `iterations.jsonl` as a Runs browser |
| **Bundles** crash packs (optional include linked run journals) | **Open Folder** button |

Open the run folder on the fuzz host (path printed as `Run journal: ...` at start) or unzip a crash pack that included runs.

---

## Custom app on a VM (short path)

1. Snapshot the VM.  
2. Deploy Randfuzz + target; run `powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1` (or copy Suite tools under `tools/`).  
3. Create `projects/local/myapp.yaml` (Scare Floor or template).  
4. On the VM: `randall agent --port 5000` → open that URL.  
5. Target Runtime start → confirm listen port.  
6. Enable **Wait** + **Procmon** (or **ETW** for long runs) + **snapshots** (+ TCPVCon / DebugView / Strings as needed) → Campaign **Start**.  
7. Optional: attach API Monitor / Frida on Monitor 2 to the target PID.  
8. Export crash packs from Bundles or `randall crashes pack`.
