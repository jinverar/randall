# Lab tools (optional)

Third-party binaries used by Randall live here. They are **not** committed — install locally after clone.

## Quick install (recommended)

After clone, pull Sysinternals (+ optional Frida / API Monitor) into `tools/`:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1
# Sysinternals only:  ...\install-recording-tools.ps1 -SysinternalsOnly
# Skip Frida:         ...\install-recording-tools.ps1 -SkipFrida
# Optional Wireshark: ...\install-recording-tools.ps1 -IncludeWireshark
# Debuggers (WinDbg Preview + classic windbg / cdb):
powershell -ExecutionPolicy Bypass -File .\scripts\install-debuggers.ps1
# Umbrella (gcc + DynamoRIO + recording + debuggers):
powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1
# Skip debuggers:     ...\install-lab-tools.ps1 -SkipDebuggers
```

Idempotent — skips binaries already present unless `-Force`. Soft-fails per tool with a summary. See [docs/RECORDING.md](../docs/RECORDING.md).

**Daily updates:** use [update-lab.ps1](../scripts/update-lab.ps1) (`git pull` + rebuild). Re-run installers here only for first setup or when adding tools (`update-lab.ps1 -InstallTools`).

**Built-in (no download):** `wpr.exe` (ETW) and `pktmon.exe` ship with Windows.

**Optional (large):** Wireshark / `tshark` for `fuzz.tsharkCapture` → `fuzz.pcapng`. Not installed by default — use `-IncludeWireshark` on the recording installer, or install manually (see below).

## gcc / MinGW (Scream native helpers)

Needed for `scream_crash.exe` / `scream_av.dll`. Primary install is a **WinLibs zip** (no winget/admin) under `tools/mingw64` (gitignored) or `%LOCALAPPDATA%\Randfuzz\mingw64`, then user PATH.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Verbose
```

Order: WinLibs zip → optional winget / Chocolatey. Open a **new** shell after install if another window still lacks `gcc`. `build-all-lab-targets.ps1` runs this when gcc is missing unless you pass `-SkipGcc`. See [docs/INSTALL_WINDOWS.md](../docs/INSTALL_WINDOWS.md).
## Procmon (Sysinternals) — optional run bookends

For `fuzz.procmonCapture: true` / Fuzz UI **Procmon capture**, install via `install-recording-tools.ps1` or drop the binary on the **fuzz host**:

```
tools/Procmon64.exe
```

Also accepted: `tools/Procmon.exe`, or any of those names on `PATH`. Capture writes `data/runs/<runId>/fuzz.pml`. See [docs/RECORDING.md](../docs/RECORDING.md).

## ProcDump (Sysinternals) — optional crash arm

For `fuzz.procdumpOnCrash: true` / Fuzz UI **ProcDump on crash** (when Scream wait is not attached):

```
tools/procdump.exe
```

Also accepted: `tools/procdump64.exe`, `PATH`, or `PROCDUMP_PATH`. Dumps land under `data/crashes/<project>/dumps/procdump_*.dmp`. Prefer Scream (`debuggerMode: wait`) when you can — only one debugger can attach.

## TCPVCon (Sysinternals) — optional network connection bookends

For `fuzz.tcpvconCapture: true` / Fuzz UI **TCPVCon (network connections)**, the Suite installer copies the CLI (also in the [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) package) to:

```
tools/tcpvcon64.exe
```

Also accepted: `tools/tcpvcon.exe`, or those names on `PATH`. Captures at arm / disarm / crash under `data/runs/<runId>/tcpvcon/` (+ `tcpvcon-capture.txt` meta). Soft-fails if missing. (Sysmon is not exported by Randfuzz — run it externally if you still want EVTX.)

## pktmon — built into Windows

`fuzz.pktmonCapture` uses `%SystemRoot%\System32\pktmon.exe` (no download). **Requires an elevated Randfuzz process** (`randall serve` / `randall agent` as Administrator); otherwise soft-skips with a clear warning. Writes `data/runs/<runId>/fuzz-pktmon.etl`.

## tshark / Wireshark — optional pcap bookend

`fuzz.tsharkCapture` / Fuzz UI **tshark pcap** runs Wireshark’s `tshark` for the fuzz duration and writes `data/runs/<runId>/fuzz.pcapng` (+ `tshark-capture.txt`). Soft-fails with an install hint if missing.

**Not pulled by default** (Wireshark is a large install). Options:

```powershell
# Optional winget via recording installer (does not run unless you ask)
powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1 -IncludeWireshark

# Manual
winget install WiresharkFoundation.Wireshark
# or: choco install wireshark
```

Discovery order: `TSHARK_PATH` → `tools/tshark.exe` → `PATH` → `C:\Program Files\Wireshark\tshark.exe`.

**Npcap / UAC:** Live capture usually needs the Npcap driver (bundled with Wireshark). Randfuzz tries without elevation first; if start is denied, the campaign continues with a warning — re-run the agent/console elevated, or fix Npcap (WinPcap API compatibility). Open the pcap later in Wireshark GUI.

For TCP/UDP projects, tshark applies an optional BPF filter `host <transport.host> and port <transport.port>` when host/port are set; otherwise it captures on the first non-loopback interface (`tshark -D`).

## ETW / WPR — built into Windows

`fuzz.etwCapture` uses `%SystemRoot%\System32\wpr.exe` (Windows Performance Recorder). **Requires an elevated Randfuzz process**; also soft-fails if Windows performance profiling policy blocks WPR (`0xc5585011`). Starts light FileIO + Registry + DiskIO + Network profiles (`-filemode`), stops to `data/runs/<runId>/fuzz-etw.etl` (+ `etw-capture.txt` meta). Open in WPA / PerfView / UIforETW. Prefer over Procmon for long campaigns; see [docs/RECORDING.md](../docs/RECORDING.md).

## DebugView (Sysinternals) — optional OutputDebugString capture

For `fuzz.debugViewCapture: true` / Fuzz UI **DebugView capture**:

```
tools/Dbgview.exe
```

Also accepted on `PATH`. Capture writes `data/runs/<runId>/debugview.log` (Win32 OutputDebugString via `/o /l`). Soft-fails if missing.

## Sysinternals snapshots — Handle / ListDLLs / PsList (+ SigCheck / AccessChk / VMMap)

For `fuzz.sysinternalsSnapshots: true` / Fuzz UI **Sysinternals snapshots**, `install-recording-tools.ps1` copies from the [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite):

```
tools/handle64.exe
tools/listdlls64.exe
tools/pslist64.exe
tools/sigcheck64.exe     # optional — target exe at arm → sigcheck-target.txt
tools/accesschk64.exe    # optional — process token (-p -f) bookends
tools/vmmap64.exe        # optional — silent Hidden CLI on arm/crash; GUI companion for live digs
tools/PsInfo64.exe       # optional — host info at arm only
```

Also accepted: 32-bit names (`handle.exe`, …) or PATH / `C:\Sysinternals\`. Artifacts under `data/runs/<runId>/sysinternals/`. netstat `-ano` is the lightweight network snapshot (prefer `fuzz.tcpvconCapture`). Process Explorer / RAMMap remain **GUI companions** (not bookended). Soft-fails per missing binary.

## Strings on crash

For `fuzz.stringsOnCrash: true` / Fuzz UI **Strings on crash**:

```
tools/strings64.exe
```

Writes `data/crashes/<project>/<crash>_strings.txt` beside the crashing `.bin`. Opt-in (can be slow on huge payloads). Soft-fails if missing.

```powershell
# Preferred: Suite installer
powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1 -SysinternalsOnly

# Manual Suite drop-in (if you already extracted the zip)
copy Dbgview.exe tools\
copy tcpvcon64.exe tools\
copy handle64.exe tools\
copy listdlls64.exe tools\
copy pslist64.exe tools\
copy sigcheck64.exe tools\
copy strings64.exe tools\
copy accesschk64.exe tools\
```

## Frida / API Monitor (GUI companions)

- **Frida:** `install-recording-tools.ps1` installs Python 3 when missing (winget `Python.Python.3.12`, else python.org silent installer), then `python -m pip install frida-tools`. Use `-SkipFrida` / `-SkipPython` to opt out. Not injected by Randfuzz — attach yourself to the target PID.
- **API Monitor:** best-effort download from rohitab; on failure, print manual steps. Expected layout: `tools/API Monitor/apimonitor-x64.exe`.

## WinDbg Preview / classic WinDbg / cdb

Used for attach, open-dump (`randall debug open`), and cdb as a headless wait-mode fallback. Doctor / stalk tool status show **ready** when found.

| Tool | Typical path | Install |
|------|--------------|---------|
| WinDbg Preview | `%LOCALAPPDATA%\Microsoft\WindowsApps\WinDbgX.exe` or `DbgX.Shell.exe` | `winget install Microsoft.WinDbg` |
| WinDbg (classic) | `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe` | SDK **Debugging Tools for Windows** |
| cdb | same `Debuggers\x64\cdb.exe` | same SDK feature |

```powershell
# Prefer elevated console for classic Debuggers (winsdksetup)
powershell -ExecutionPolicy Bypass -File .\scripts\install-debuggers.ps1
```

Soft-fails with Store / SDK links if winget or elevation is unavailable. Also included by default in `install-lab-tools.ps1` (`-SkipDebuggers` to omit).

## DynamoRIO (coverage-guided stalking)

Randall uses DynamoRIO `drrun` + `drcov` for optional coverage feedback (`--coverage`, web **Coverage-guided** checkbox).

### Expected layout

After install, this file must exist:

```
# Windows
tools/dynamorio/bin64/drrun.exe
# Linux
tools/dynamorio/bin64/drrun
```

Randall also auto-detects `tools/DynamoRIO-*` (versioned extract folder) and `DYNAMORIO_HOME`.

### Install

DynamoRIO is **optional**. **Important:** the install script **may take a while** (large download; slow networks).

**Windows — script (progress + resume via curl/BITS)**

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1
```

**Linux — script**

```bash
scripts/install-dynamorio.sh
# or: scripts/install-dynamorio.sh --tarball ~/Downloads/DynamoRIO-Linux-*.tar.gz
```

**Manual download into `tools`**

1. Download the OS package from [DynamoRIO releases](https://github.com/DynamoRIO/dynamorio/releases)  
   (`DynamoRIO-Windows-*.zip` or `DynamoRIO-Linux-*.tar.gz` / AArch64 / ARM variants).
2. Extract, then move/rename the top-level folder to `tools/dynamorio` so `bin64/drrun[.exe]` exists  
   (or keep `tools/DynamoRIO-*` — Randall auto-detects it).
3. Or pass the archive to the script:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1 -ZipPath C:\path\to\DynamoRIO-Windows-*.zip
```

```bash
scripts/install-dynamorio.sh --tarball /path/to/DynamoRIO-Linux-*.tar.gz
```

> **Footnote — coverage later:** `install-dynamorio.ps1 -Skip` / `install-dynamorio.sh --skip` if you only need crash-finding for now.

### Verify

```powershell
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml
```

```bash
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml --platform linux
```

Web UI **Dashboard** should show **DynamoRIO: Ready** (not Missing).

See also [README.md](../README.md#optional--dynamorio-coverage-guided-stalking), [docs/INSTALL_LINUX.md](../docs/INSTALL_LINUX.md), and [docs/FUZZING.md](../docs/FUZZING.md).

## RandfuzzDbg (WinDbg Preview)

Fuzz-dump walk scripts + extension stub for exploit-dev lab analysis (no payloads):

- [randfuzzdbg/README.md](randfuzzdbg/README.md) — WinDbg Preview extension + scripts
- [randfuzzgdb/README.md](randfuzzgdb/README.md) — Linux GDB/GEF walk twin
- Docs: [WINDBG_FUZZ_PKG.md](../docs/WINDBG_FUZZ_PKG.md)
- Host CLI: `randall scream walk` · `randall stack lens` · `randall rop …` · `randall windbg|gdb walk|scripts` · `randall ladder diff`
