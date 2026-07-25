# Crash analysis (Phase 16)

When a crash saves a Windows minidump, Randall extracts triage fields without opening WinDbg manually.

## Auto-analyze on crash

With `fuzz.autoAnalyzeCrash: true` (default), each new crash writes:

```
data/crashes/<project>/<crash-guid>_analysis.json
```

Fields include exception code, fault address, module+offset, and x64 register snapshot (RIP, RSP, …).

### Headless cdb `!analyze -v` (Windows)

When `fuzz.cdbAnalyzeCrash: true` (default, requires `autoAnalyzeCrash`), Randfuzz also runs **cdb** on the minidump:

| Artifact | Contents |
|----------|----------|
| `<guid>_analyze.txt` | Full `!analyze -v` text |
| `<guid>_exploitable.txt` | `!exploitable` output when **msec.dll** is available |
| `<guid>_cdb_triage.json` | Parsed summary + paths |

Soft-fails when cdb is missing (install `scripts/install-debuggers.ps1`). Does not block the fuzz loop — 90s timeout. Randfuzz passes `-y` (local cache + Microsoft symbol server) and runs `.sympath` before `!analyze`; see [WinDbg symbols](#windbg-symbols) below.

**msec.dll** (Microsoft Exploitability Index extension) is optional:

- Drop `msec.dll` into `tools/windbg-ext/` or set `MSEC_DLL_PATH`
- Some SDK installs include it under `Debuggers\x64\winext\`
- Without msec, `!analyze` still runs; heuristic triage in `CrashTriage` remains

Disable only cdb triage while keeping minidump JSON parsing:

```yaml
fuzz:
  autoAnalyzeCrash: true
  cdbAnalyzeCrash: false
```

UI: Fuzz tab → **cdb !analyze on crash dump** (Windows).

## WinDbg symbols

Idle **Symbolic Debugger for Windows** / WinDbg Preview processes (0% CPU, ~15–30 MB) are usually waiting on PDB downloads from `msdl.microsoft.com`, not hung.

Randfuzz sets a default symbol path when launching WinDbg Preview, classic WinDbg, or headless **cdb**:

| Mechanism | Value |
|-----------|--------|
| Env (wins) | `_NT_SYMBOL_PATH` if already set |
| Default | `srv*C:\Symbols*https://msdl.microsoft.com/download/symbols` |
| Cache override | `RANDFUZZ_SYMBOL_CACHE=C:\path\to\cache` |
| Offline / no MS server | `RANDFUZZ_NO_MS_SYMBOL_SERVER=1` (cache dir only) |

**Recommended (persistent, all debuggers):**

```powershell
[Environment]::SetEnvironmentVariable(
  "_NT_SYMBOL_PATH",
  "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols",
  "User")
mkdir C:\Symbols -Force
```

**Kill stuck symbol waiters:** Task Manager → end **WinDbg** / **WinDbgX** / **cdb** (or `taskkill /IM WinDbgX.exe /F`). Fuzzing continues — GUI open is fire-and-forget; headless cdb triage times out after 90s.

**cdb vs WinDbg Preview:**

| Use | When |
|-----|------|
| **cdb** (headless) | Auto `!analyze` on every crash — no windows, 90s cap, writes `*_analyze.txt` |
| **WinDbg Preview** | Interactive walk (`Both` mode, Crashes → WinDbg buttons, `randall debug open`) |

Re-opening the same dump from Randfuzz skips a second GUI launch if the prior WinDbg for that dump is still running.

## AeDebug + WER (opt-in)

Randfuzz **Scream** (`fuzz.debuggerMode: wait`) is the preferred in-campaign path. For system-wide post-mortem capture (outside Randfuzz or as fallback):

```powershell
# Preview (no changes):
powershell -ExecutionPolicy Bypass -File .\scripts\setup-windows-crash-capture.ps1 -WhatIf

# Apply (Admin): AeDebug via windbg -I, WER DontShowUI=1
powershell -ExecutionPolicy Bypass -File .\scripts\setup-windows-crash-capture.ps1

# Also enable WER LocalDumps → data/wer-dumps
powershell -ExecutionPolicy Bypass -File .\scripts\setup-windows-crash-capture.ps1 -LocalDumps

# Revert registry changes
powershell -ExecutionPolicy Bypass -File .\scripts\setup-windows-crash-capture.ps1 -Revert
```

Doctor checks: `cdbAnalyze`, `msec`, `aedebug`, `winafl`.

## CLI

```powershell
# By crash GUID (from randall crashes or web UI)
randall analyze -i 3fa85f64-5717-4562-b3fc-2c963f66afa6

# Direct minidump path
randall analyze -d data/crashes/vulnserver/crash_42.dmp

# Run cdb !analyze / !exploitable on demand (writes *_analyze.txt next to dump)
randall analyze -d crash.dmp --cdb

# JSON for scripts
randall analyze -i <guid> --json
```

## Stalk backend

Coverage traces use a pluggable backend (`fuzz.stalkMode`):

| Mode | Behavior |
|------|----------|
| `auto` | Native if available, else DynamoRIO drcov, else none |
| `external` | DynamoRIO only (optional third-party adapter) |
| `native` | Randall-owned stalk (in development) |
| `none` | No instrumentation |

Logging schema is Randall-owned either way — native stalk will emit the same journal and sidecar fields when it lands.

## WinAFL companion (external)

Randfuzz does **not** embed WinAFL. Use it as an external coverage grinder beside Randfuzz:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-winafl.ps1
# Build afl-fuzz.exe in Visual Studio — see script output
```

See [RECORDING.md](RECORDING.md) and [PERSISTENT.md](PERSISTENT.md) for harness patterns. Doctor `winafl` check confirms `tools/winafl/afl-fuzz.exe`.

## Hot edges

At run end, `data/runs/<runId>/run.json` includes `hotEdges`: basic blocks hit most often during the run (edge hit counters from drcov traces).

## Static function mapping (RIP → Ghidra / PE)

When a crash has a fault PC or RIP in `*_analysis.json` (or Linux core triage), Randall maps it to a **function name + offset**:

1. **`data/stalk/<project>/randall-analysis.json`** (from `randall stalk ghidra-analyze`) — preferred; uses module RVA from `faultModule` (`exe+0x…`) when ASLR rebases the image.
2. **PE export / section heuristics** — nearest export or section name from the target binary when no Ghidra map exists.

Enrichment surfaces:

| Surface | Field / command |
|---------|-------------------|
| Crashes → Investigation | `triage.staticFunction` |
| Crash list / canisters | `staticFunctionSummary` one-liner |
| `randall analyze -i <guid>` | `Static:` line |
| `randall scream walk` | `static` playbook step + summary |
| Memory lens API | prepended summary line |
| Crash intel FINDINGS | `static map: …` when intel is generated |

Dump-less crashes still work when triage carries RIP/fault from sidecar or exit metadata; mapping is skipped when no PC is available.

Example:

```text
Static:    handle_request+0x42 (ghidra) @ 0x7ff612340042 — calls memcpy · fuzz-priority 88/100
```
