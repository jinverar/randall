# Install on Windows 10 / 11 (VM or bare metal)

Fresh-box checklist for Randfuzz. Use this on a **Windows 10/11 VM** or a local machine.

**Time:** ~15–25 minutes (plus DynamoRIO download if you want coverage).

---

## 0. VM recommendations

| Setting | Suggestion |
|---------|------------|
| RAM | 4 GB minimum, **8 GB** better (DynamoRIO + lab targets) |
| Disk | ≥40 GB free |
| Network | NAT for solo use; **bridged** if the host will open the lab agent |
| Snapshot | Take one after Windows updates, before installing tools |

---

## 1. Install .NET 8 SDK

1. Open [.NET 8 downloads](https://dotnet.microsoft.com/download/dotnet/8.0)
2. Install **SDK 8.x** (x64)
3. Open a **new** PowerShell window:

```powershell
dotnet --version
```

Expect `8.0.x`.

---

## 2. Install Git

1. [Git for Windows](https://git-scm.com/download/win) — defaults are fine
2. Verify:

```powershell
git --version
```

---

## 3. Clone the repo

Prefer **git** over downloading a GitHub source ZIP — `git pull` picks up install-script fixes without re-unpacking.

```powershell
cd $env:USERPROFILE\Projects
# or: mkdir C:\src; cd C:\src
git clone https://github.com/jinverar/randall.git
cd randall
```

If you already unpacked a ZIP (e.g. under `Downloads\randall-main\`), either clone fresh as above, or replace that tree with a clone / pull so you have the latest scripts.

---

## 4. Build Randfuzz

```powershell
dotnet build
```

Expect `Build succeeded`.

---

## 5. Install gcc (MinGW) for Scream / native helpers

ScreamCrash native helpers (`scream_crash.exe`, `scream_av.dll`) need **gcc** on `PATH`. **winget is not required.** The install script tries, in order:

1. **Direct WinLibs zip** (primary; no admin) → `tools\mingw64` or `%LOCALAPPDATA%\Randfuzz\mingw64`, then prepends that `bin` to your **user PATH**  
2. **winget** [WinLibs](https://winlibs.com/) / Strawberry (optional, only if `winget` exists)  
3. **Chocolatey** `mingw` / `strawberryperl` (optional, if `choco` is on PATH)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1
# optional: powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Verbose
gcc --version
```

Idempotent — safe to re-run. Use `-Skip` to bail out without installing. Needs network for the ~260 MB WinLibs zip.

**After a successful install, open a new PowerShell window** before `gcc --version` in another shell — user PATH changes do not apply to shells that were already open.

Optional winget one-liner (only if App Installer / winget is installed):

```powershell
winget install -e --id BrechtSanders.WinLibs.POSIX.UCRT --accept-package-agreements --accept-source-agreements
```

Manual backup: [winlibs.com](https://winlibs.com/) (x86_64 POSIX UCRT `.zip`) / [strawberryperl.com](https://strawberryperl.com/), then open a **new** shell.

`build-all-lab-targets.ps1` calls this automatically when gcc is missing (unless you pass `-SkipGcc`).

---

## 5b. Install recording tools (Sysinternals + companions)

For Procmon / ProcDump / TCPVCon / DebugView / Handle / ListDLLs / snapshots / Strings bookends, download the official [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) into `tools/`:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1
# Sysinternals only:  ...\install-recording-tools.ps1 -SysinternalsOnly
# Skip Frida:         ...\install-recording-tools.ps1 -SkipFrida
```

Idempotent; soft-fails per tool. **Frida** (`pip install frida-tools`) runs by default when Python is present. **API Monitor** is best-effort (manual steps printed if the rohitab URL fails). **wpr** / **pktmon** are built into Windows — no download.

Umbrella (gcc + DynamoRIO + recording):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1
# Skip large DynamoRIO zip:  ...\install-lab-tools.ps1 -SkipDynamoRio
```

See [tools/README.md](../tools/README.md) and [RECORDING.md](RECORDING.md).

---

## 6. Build lab targets

Many Windows 10/11 images ship with PowerShell **ExecutionPolicy = Restricted**, so this fails:

```text
.\scripts\build-all-lab-targets.ps1 : ... cannot be loaded because running scripts is disabled on this system.
```

Use **Bypass for this file only** (recommended):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1
```

That installs gcc if needed, then compiles vulnserver, vulnhttp, vulnftp, ScreamCrash, and other practice targets under `targets\`.

Skip gcc/Scream (vulnserver-only style):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1 -SkipGcc
```

Or allow your own scripts for this user (one-time):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\scripts\build-all-lab-targets.ps1
```

---

## 7. (Optional) DynamoRIO — coverage stalking

Needed only for `+N edges` / coverage-guided corpus. **Crashes and basic fuzzing work without it.**

> **Important:** `powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1` **may take a while** — large download; slow networks can run for many minutes. That is normal.

**A. Install with the script** (progress + resume via `curl.exe` / BITS):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1
```

**B. Manual download + unzip into `tools`**

> **IMPORTANT:** The extracted folder **must** be named `tools\dynamorio` — **not** `tools\DynamoRIO-Windows-11.3.0` or any versioned name. After unzip, rename/move the top-level `DynamoRIO-Windows-*` folder to exactly `tools\dynamorio` so `tools\dynamorio\bin64\drrun.exe` exists.

1. Open [DynamoRIO releases](https://github.com/DynamoRIO/dynamorio/releases) and download the Windows asset `DynamoRIO-Windows-*.zip`  
   (URL pattern: `https://github.com/DynamoRIO/dynamorio/releases/download/<tag>/DynamoRIO-Windows-<version>.zip` — e.g. `.../download/release_11.3.0/DynamoRIO-Windows-11.3.0.zip`).
2. Extract the zip. The archive contains a single top-level folder (e.g. `DynamoRIO-Windows-11.3.0`).
3. **Rename/move** that folder to exactly `tools\dynamorio` (do **not** leave it as `tools\DynamoRIO-Windows-11.3.0`). Confirm:

```
tools\dynamorio\bin64\drrun.exe
```

Layout after install:

```
tools\
  dynamorio\          ← must be this exact name (not DynamoRIO-Windows-*)
    bin64\
      drrun.exe
    ...
```

Alternatively, pass a browser-downloaded zip to the script (no manual extract — the script renames for you):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1 -ZipPath C:\Users\007\Downloads\DynamoRIO-Windows-11.3.0.zip
```

Session env (or set a permanent user variable `DYNAMORIO_HOME`):

```powershell
$env:DYNAMORIO_HOME = (Resolve-Path tools\dynamorio).Path
Test-Path "$env:DYNAMORIO_HOME\bin64\drrun.exe"   # should be True
```

> **Footnote — coverage later / skip for now:**  
> `powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1 -Skip`

---

## 8. Doctor (preflight)

```powershell
dotnet run --project src\Randall.Cli -- doctor -c projects\vulnserver.yaml
```

Expect `[✓] project`, `[✓] target`, and **Ready to fuzz**.  
`[!] dynamorio` is OK if you skipped step 7.

---

## 9. Start the web UI

```powershell
dotnet run --project src\Randall.Server --urls http://127.0.0.1:5000
```

Open **http://127.0.0.1:5000** — Dashboard, Fuzz, Crashes, Case builder, Help.

### Smoke tests

```powershell
# Dry-run (no long live fuzz)
dotnet run --project src\Randall.Cli -- fuzz -c projects\vulnserver.yaml --dry-run

# Short live run
dotnet run --project src\Randall.Cli -- fuzz -c projects\vulnserver.yaml --max-iterations 50

# In-process harness demo
dotnet build targets\Randall.HarnessDemo
dotnet run --project src\Randall.Cli -- fuzz -c projects\harness-demo.yaml
```

---

## 10. Remote lab agent (optional)

On the VM (listens for LAN clients):

```powershell
dotnet run --project src\Randall.Cli -- agent --port 5000
```

From the host browser: `http://<vm-ip>:5000` (allow inbound TCP 5000 in Windows Firewall).  
For real dumps / memory lens, **fuzz on the agent UI** — see [LAB_AGENT.md](LAB_AGENT.md) and [TARGET_RUNTIME.md](TARGET_RUNTIME.md).

---

## Common gotchas

| Issue | Fix |
|-------|-----|
| `dotnet` not found | New PowerShell after SDK install; check PATH |
| **Scripts disabled / `PSSecurityException`** | `powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1` |
| Lab target missing | Re-run the Bypass command above |
| `gcc not found` / Scream skipped | `powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Verbose` (downloads WinLibs zip; no winget needed); open a **new** shell; re-run `build-screamcrash.ps1`; or `-SkipGcc` on build-all |
| DynamoRIO download “forever” | Patience (large zip), or browser-download + unzip then **rename** to exactly `tools\dynamorio` (not `tools\DynamoRIO-Windows-*`; or use `-ZipPath`); re-run resumes via curl/BITS; `-Skip` only if skipping coverage for now |
| Port 5000 in use | Stop other Server/agent processes |
| OOM / very slow | Raise VM RAM; avoid every lab + DynamoRIO at once |
| Old ZIP of the repo | Prefer `git clone` / `git pull` so install scripts stay current |
| Clone / TLS errors | Fix VM date/time; check proxy |

---

## Next

- Hands-on lab checklist: [LAB_PRACTICE.md](LAB_PRACTICE.md)
- Custom targets: [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md)
- Harness design: [HARNESS_DESIGN.md](HARNESS_DESIGN.md)
