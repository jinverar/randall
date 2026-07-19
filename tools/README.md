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
