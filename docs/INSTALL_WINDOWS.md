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

**One-liner (winget):**

```powershell
winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements
```

If Git is missing when you run `scripts\update-lab.ps1`, the update script tries that winget install automatically (then refreshes PATH so `git pull` works in the same run). Use `-SkipGitInstall` to skip auto-install, or `-SkipPull` to rebuild without pulling.

---

## 3. Clone the repo

Prefer **git** over downloading a GitHub source ZIP — `git pull` picks up install-script fixes without re-unpacking.

```powershell
cd $env:USERPROFILE\Projects
# or: mkdir C:\src; cd C:\src
git clone https://github.com/jinverar/randall.git
cd randall
```

If you already unpacked a ZIP (e.g. under `Downloads\randall-main\`), migrate once:

1. Clone fresh (commands above) into e.g. `%USERPROFILE%\Projects\randall`
2. **Copy** `tools\` from the old ZIP tree into the clone (DynamoRIO, MinGW, Sysinternals — not in git)
3. Use `git pull` + `update-lab.ps1` from then on; retire the Downloads folder

---

## Updating the VM (after first install)

Day-to-day updates: **pull source, rebuild** — no ZIP, no full tool reinstall. Stop **Randall.Server** first if it is running (locked DLLs). The script already runs `git pull` + `dotnet build` + lab targets — **no extra build step** after it unless you used `-SkipLabTargets` and need those binaries. See [README — Updating the VM](../README.md#updating-the-vm-after-first-install) for when to use full update vs `-SkipLabTargets`.

```powershell
cd $env:USERPROFILE\Projects\randall

powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1
# UI/server-only (faster):  ...\update-lab.ps1 -SkipLabTargets
```

What it does:

| Step | Action |
|------|--------|
| `git pull` | Latest source (fails clearly if this folder is not a clone) |
| `dotnet build` | Randall.Cli, Randall.Server, libraries |
| `build-all-lab-targets.ps1` | vulnserver, vulnhttp, vulnftp, vulnssh, vulntftp, vulnrpc, vulnsmb, ScreamCrash, ReelDeck (optional native) |
| `tools\` | **Not** touched unless you pass `-InstallTools` |

Useful flags:

```powershell
# Skip pull (already up to date / offline rebuild)
powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -SkipPull

# Skip winget Git auto-install (must have git on PATH for pull)
powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -SkipGitInstall

# Refresh third-party tools (idempotent; skips existing binaries)
powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -InstallTools

# .NET only — skip native lab targets
powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -SkipLabTargets
```

Then restart the UI if needed:

```powershell
dotnet run --project src\Randall.Server --urls http://127.0.0.1:5000
```

**Gitignored (safe across pulls):** `tools/dynamorio/`, `tools/mingw64/`, `tools/*.exe`, `data/`, `projects/local/`, `.env` — see [.gitignore](../.gitignore). Pull never deletes them.

### Offline tools (no network)

Keep a pre-downloaded `tools\` tree (MinGW, DynamoRIO, Sysinternals, etc.) outside git. After `git pull`, copy it into the clone, then register PATH — no downloads:

```powershell
cd $env:USERPROFILE\Projects\randall
# copy your saved tools\ here so e.g. tools\mingw64\bin\gcc.exe exists

powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1
# or register gcc + DynamoRIO + debuggers + recording tools:
powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1

powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1
gcc --version   # works in this same window after install-gcc
```

`install-gcc.ps1` detects `tools\mingw64\bin\gcc.exe`, prepends it to the **current session** and your **user PATH**, and skips the WinLibs zip when gcc is already present.

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

Idempotent — safe to re-run. Use `-Skip` to bail out without installing. Network is only needed when gcc is missing and must be downloaded (~260 MB WinLibs zip). If you copied `tools\mingw64\` offline, the script only updates PATH.

The script refreshes **this PowerShell session** so `gcc --version` works immediately afterward. **Other terminals** that were already open still need a new window (or prepend the `bin` folder manually).

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
scripts\install-recording-tools.cmd
# or: powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1
# Sysinternals only:  ...\install-recording-tools.ps1 -SysinternalsOnly
# Skip Frida:         ...\install-recording-tools.ps1 -SkipFrida
# Skip Python auto-install: ...\install-recording-tools.ps1 -SkipPython
```

Idempotent; soft-fails per tool. **Frida** installs into `tools\python` (never the Microsoft Store `python.exe` stub). If Frida fails, Sysinternals and the rest can still succeed — re-run or use `-SkipFrida`. **API Monitor** is best-effort (manual steps printed if the rohitab URL fails). **wpr** / **pktmon** are built into Windows — no download.

> **IMPORTANT:** **pktmon** and **ETW/WPR** need Randfuzz (`randall serve` / `randall agent`) from an **Administrator** terminal — see [RECORDING.md](RECORDING.md).

Umbrella (gcc + DynamoRIO + recording + debuggers):

```powershell
scripts\install-lab-tools.cmd
# or: powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1
# Skip large DynamoRIO zip:  ...\install-lab-tools.ps1 -SkipDynamoRio
# Skip WinDbg / cdb:         ...\install-lab-tools.ps1 -SkipDebuggers
```

Prefer the `.cmd` launchers (or `-File`) on Windows PowerShell 5.1. Do **not** paste script text into a new `.ps1` — that often strips the UTF-8 BOM and causes `Missing expression` / `Unexpected token` parse errors.
---

## 5c. Install debuggers (WinDbg Preview + classic / cdb)

For Scream wait fallbacks, attach, and open-dump from Crashes / `randall debug open`:

```powershell
# Standalone (Admin recommended for classic SDK Debuggers)
powershell -ExecutionPolicy Bypass -File .\scripts\install-debuggers.ps1
```

| Tool | Source | Notes |
|------|--------|--------|
| **WinDbg Preview** | `winget` `Microsoft.WinDbg` | Store/MSIX; may need interactive Store on some VMs |
| **WinDbg (classic)** + **cdb** | Windows SDK feature `OptionId.WindowsDesktopDebuggers` | Needs elevation; installs under `Windows Kits\10\Debuggers\x64` |

Manual: [WinDbg download](https://aka.ms/windbg/download) · [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) (select only **Debugging Tools for Windows**). Soft-fails print these links.

Doctor probes `debugger:windbg-preview`, `debugger:windbg`, `debugger:cdb` (paths match `DebuggerTools`).

---

## 6. Build lab targets

Many Windows 10/11 images ship with PowerShell **ExecutionPolicy = Restricted**, so this fails:

```text
.\scripts\build-all-lab-targets.ps1 : ... cannot be loaded because running scripts is disabled on this system.
```

Use **Bypass for this file only** (recommended):

```powershell
scripts\build-all-lab-targets.cmd
# or: powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1
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

If you see `Missing expression` / `Missing closing ')'` / strange quote errors while building labs, you are almost certainly on an old copy or a re-saved script without a UTF-8 BOM. Use the `.cmd` launcher from a fresh clone of this branch, or:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1
```

Do not copy-paste script contents into Notepad and save as a new `.ps1`.

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
After step 5c, debugger checks should be **ok** (paths to WinDbgX / `windbg.exe` / `cdb.exe`) instead of warn/missing.

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

## Uninstall

`scripts\uninstall-lab.ps1` stops everything Randfuzz started, then removes what the install/build scripts put in place. It never touches your git clone (`src\`, `docs\`, `projects\`, `.git\`) and never touches system-wide installs (.NET SDK, Git, WinDbg / Windows SDK debuggers, winget packages) — those aren't owned by these scripts.

**Always stops (regardless of flags):**

| Step | How |
|------|-----|
| `Randall.Server` (web UI) | Kill `dotnet` processes running `Randall.Server`, plus a standalone `randall`/`Randall.Server.exe` if published |
| `Randall.Cli` sessions (fuzz / agent / serve) | Kill `dotnet` processes running `Randall.Cli` |
| Vuln labs (vulnserver, vulnhttp, vulnftp, vulnssh, vulntftp, vulnrpc, vulnsmb, ScreamCrash) | `randall labs stop-all` / `randall runtime stop-all` via the built CLI, plus a raw process-name + port-listener backstop (9999, 8080, 2121, 2222, 6969, 1355, 4455) |
| Recorders | `randall recorders stop` (Procmon `/Terminate`, DebugView, ProcDump, `wpr -cancel`, `pktmon stop`, tshark/dumpcap), plus a raw process-name backstop |

**Then removes (unless skipped):**

```powershell
# Preview only - nothing stopped, nothing deleted
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -WhatIf

# Stop everything + remove tools\ and targets\ content (prompts y/N first)
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1

# Same, but skip the confirmation prompt
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -Force

# Only stop processes - leave every installed file in place
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -StopOnly

# Keep the large downloads (tools\dynamorio, tools\mingw64, Sysinternals, API Monitor)
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -Force -KeepTools

# Keep the built lab binaries (targets\vulnserver\*.exe, etc.) - rebuild is fast anyway
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -Force -KeepTargets

# Also wipe data\ (crash dumps, corpus, runtime-slots.json) - opt-in, NOT default
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -Force -RemoveData
```

| Removed by default | Kept by default |
|---------------------|------------------|
| `tools\dynamorio\`, `tools\DynamoRIO-*\`, `tools\mingw64\`, `tools\API Monitor\`, `tools\*.exe` (Sysinternals) | `tools\README.md`, `.gitkeep` files |
| `targets\<lab>\*` built binaries (`.exe`/`.dll`) | `targets\<lab>\.gitkeep` |
| Repo-local mingw entries this install added to your **user PATH** (`tools\mingw64\bin`, `%LOCALAPPDATA%\Randfuzz\mingw64\bin`) | Any pre-existing PATH entries (e.g. your own Strawberry Perl / system gcc) |
| — | `data\` (crash dumps, corpus, `runtime-slots.json`) — pass `-RemoveData` to include it |
| — | .NET SDK, Git, WinDbg Preview, Windows SDK Debugging Tools, Frida/pip packages, winget packages — not installed exclusively by these scripts |

Reinstall / rebuild afterward with the usual commands:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1
```

---

## Common gotchas

| Issue | Fix |
|-------|-----|
| `dotnet` not found | New PowerShell after SDK install; check PATH |
| **Scripts disabled / `PSSecurityException`** | `powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1` |
| **`Missing expression` / smart-quote parse errors** | Use `scripts\*.cmd` or `-File` from a fresh clone of this branch; do not re-save scripts in Notepad without UTF-8 BOM |
| **Frida failed / pip exit 9009 / Store python** | Re-run `scripts\install-recording-tools.cmd` (uses `tools\python` only). Or `-SkipFrida`. Turn OFF App execution aliases for `python.exe` |
| Lab target missing | Re-run the Bypass command above |
| `gcc not found` / Scream skipped | `powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Verbose` (downloads WinLibs zip; no winget needed); open a **new** shell; re-run `build-screamcrash.ps1`; or `-SkipGcc` on build-all |
| DynamoRIO download “forever” | Patience (large zip), or browser-download + unzip then **rename** to exactly `tools\dynamorio` (not `tools\DynamoRIO-Windows-*`; or use `-ZipPath`); re-run resumes via curl/BITS; `-Skip` only if skipping coverage for now |
| Port 5000 in use | Stop other Server/agent processes |
| OOM / very slow | Raise VM RAM; avoid every lab + DynamoRIO at once |
| Old ZIP of the repo | Clone once; copy `tools\` into clone; then `update-lab.ps1` |
| `git pull` / update fails | Confirm `.git` exists; not a ZIP extract — see [Updating the VM](#updating-the-vm-after-first-install) |
| Clone / TLS errors | Fix VM date/time; check proxy |

---

## Next

- Hands-on lab checklist: [LAB_PRACTICE.md](LAB_PRACTICE.md)
- Custom targets: [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md)
- Harness design: [HARNESS_DESIGN.md](HARNESS_DESIGN.md)
