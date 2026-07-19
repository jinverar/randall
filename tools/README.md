# Lab tools (optional)

Third-party binaries used by Randall live here. They are **not** committed — install locally after clone.

## gcc / MinGW (Scream native helpers)

Not installed under `tools/` — system `PATH`. Needed for `scream_crash.exe` / `scream_av.dll`.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1
```

Prefers winget **WinLibs** (`BrechtSanders.WinLibs.POSIX.UCRT`), then Strawberry Perl, then Chocolatey. `build-all-lab-targets.ps1` runs this when gcc is missing unless you pass `-SkipGcc`. See [docs/INSTALL_WINDOWS.md](../docs/INSTALL_WINDOWS.md).

## DynamoRIO (coverage-guided stalking)

Randall uses DynamoRIO `drrun` + `drcov` for optional coverage feedback (`--coverage`, web **Coverage-guided** checkbox).

### Expected layout

After install, this file must exist:

```
tools/dynamorio/bin64/drrun.exe
```

Randall also auto-detects `tools/DynamoRIO-*` (versioned extract folder) and `DYNAMORIO_HOME`.

### Install

DynamoRIO is **optional**. Skip with `-Skip` if you only need crash-finding fuzzing.

**Script (progress + resume via curl/BITS)**

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1 -Skip
```

**Manual / slow network**

1. Download `DynamoRIO-Windows-*.zip` from [DynamoRIO releases](https://github.com/DynamoRIO/dynamorio/releases).
2. Either extract into `tools/` and rename to `dynamorio` (or keep `DynamoRIO-Windows-x.y.z`), **or**:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1 -ZipPath C:\path\to\DynamoRIO-Windows-*.zip
```

### Verify

```powershell
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml
```

Web UI **Dashboard** should show **DynamoRIO: Ready** (not Missing).

See also [README.md](../README.md#optional--dynamorio-coverage-guided-stalking) and [docs/FUZZING.md](../docs/FUZZING.md).
