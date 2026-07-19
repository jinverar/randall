# Lab tools (optional)

Third-party binaries used by Randall live here. They are **not** committed — install locally after clone.

## gcc / MinGW (Scream native helpers)

Needed for `scream_crash.exe` / `scream_av.dll`. Primary install is a **WinLibs zip** (no winget/admin) under `tools/mingw64` (gitignored) or `%LOCALAPPDATA%\Randfuzz\mingw64`, then user PATH.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Verbose
```

Order: WinLibs zip → optional winget / Chocolatey. Open a **new** shell after install if another window still lacks `gcc`. `build-all-lab-targets.ps1` runs this when gcc is missing unless you pass `-SkipGcc`. See [docs/INSTALL_WINDOWS.md](../docs/INSTALL_WINDOWS.md).
## Procmon (Sysinternals) — optional run bookends

For `fuzz.procmonCapture: true` / Fuzz UI **Procmon capture**, drop the binary on the **fuzz host**:

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

For `fuzz.tcpvconCapture: true` / Fuzz UI **TCPVCon (network connections)**, drop the CLI from the [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) package on the **fuzz host**:

```
tools/tcpvcon64.exe
```

Also accepted: `tools/tcpvcon.exe`, or those names on `PATH`. Captures at arm / disarm / crash under `data/runs/<runId>/tcpvcon/` (+ `tcpvcon-capture.txt` meta). Soft-fails if missing. (Sysmon is not exported by Randfuzz — run it externally if you still want EVTX.)

## pktmon — built into Windows

`fuzz.pktmonCapture` uses `%SystemRoot%\System32\pktmon.exe` (no download). Often needs an elevated console/agent. Writes `data/runs/<runId>/fuzz-pktmon.etl`.

## DebugView (Sysinternals) — optional OutputDebugString capture

For `fuzz.debugViewCapture: true` / Fuzz UI **DebugView capture**:

```
tools/Dbgview.exe
```

Also accepted on `PATH`. Capture writes `data/runs/<runId>/debugview.log` (Win32 OutputDebugString via `/o /l`). Soft-fails if missing.

## Sysinternals snapshots — Handle / ListDLLs / PsList

For `fuzz.sysinternalsSnapshots: true` / Fuzz UI **Sysinternals snapshots**, copy from the [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite):

```
tools/handle64.exe
tools/listdlls64.exe
tools/pslist64.exe
tools/PsInfo64.exe   # optional — host info at arm only
```

Also accepted: 32-bit names (`handle.exe`, …) or PATH / `C:\Sysinternals\`. Artifacts under `data/runs/<runId>/sysinternals/` (`arm-*`, `disarm-*`, `crash_*`). VMMap is GUI-only and is **not** bookended; netstat `-ano` is the lightweight network snapshot in this bundle (prefer `fuzz.tcpvconCapture` for richer endpoints). Soft-fails per missing binary.

```powershell
# Typical Suite drop-in
copy Dbgview.exe tools\
copy tcpvcon64.exe tools\
copy handle64.exe tools\
copy listdlls64.exe tools\
copy pslist64.exe tools\
```

## DynamoRIO (coverage-guided stalking)

Randall uses DynamoRIO `drrun` + `drcov` for optional coverage feedback (`--coverage`, web **Coverage-guided** checkbox).

### Expected layout

After install, this file must exist:

```
tools/dynamorio/bin64/drrun.exe
```

Randall also auto-detects `tools/DynamoRIO-*` (versioned extract folder) and `DYNAMORIO_HOME`.

### Install

DynamoRIO is **optional**. **Important:** the install script **may take a while** (large download; slow networks).

**A. Script (progress + resume via curl/BITS)**

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1
```

**B. Manual download + unzip into `tools`**

1. Download `DynamoRIO-Windows-*.zip` from [DynamoRIO releases](https://github.com/DynamoRIO/dynamorio/releases)  
   (URL pattern: `https://github.com/DynamoRIO/dynamorio/releases/download/<tag>/DynamoRIO-Windows-<version>.zip`).
2. Extract the zip, then move/rename the top-level folder to `tools\dynamorio` so `tools\dynamorio\bin64\drrun.exe` exists  
   (or keep `tools\DynamoRIO-*` — Randall auto-detects it).
3. Or pass the zip to the script instead of extracting by hand:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1 -ZipPath C:\path\to\DynamoRIO-Windows-*.zip
```

> **Footnote — coverage later:** `...\install-dynamorio.ps1 -Skip` if you only need crash-finding for now.

### Verify

```powershell
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml
```

Web UI **Dashboard** should show **DynamoRIO: Ready** (not Missing).

See also [README.md](../README.md#optional--dynamorio-coverage-guided-stalking) and [docs/FUZZING.md](../docs/FUZZING.md).
