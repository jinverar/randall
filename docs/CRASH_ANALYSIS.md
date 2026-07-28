# Crash analysis (Phase 16)

When a crash saves a Windows minidump, Randall extracts triage fields without opening WinDbg manually.

## How to capture dumps (Debugger vs ProcDump)

| Goal | Fuzz → Debugger | ProcDump on crash |
|------|-----------------|-------------------|
| Minidumps for Investigator / `!analyze` / WinDbg | **Wait** or **Both** | **Off** |
| No Scream; dump on unhandled exception only | **None** | **On** (optional) |

Windows allows **one** debugger attach. Scream (Wait/Both) and ProcDump `-e` both attach — leaving both on means ProcDump is skipped and dumps can end up empty (`unk:no-pc`). Details: [RECORDING.md — ProcDump vs Scream](RECORDING.md#procdump-vs-scream).

Lab targets such as **VulnDrone** call `Environment.Exit(0xC0000005)` instead of raising SEH. Scream captures those on `ExitProcess` **before** continuing the debug event (otherwise the process is already gone and you get 0-byte `tcp_*.dmp` fallbacks). Under `DebugActiveProcess` attach, `dwExitCode` sits at **DEBUG_EVENT.u+0** (not after `hProcess` in the union); mis-parsing it as zero skips the dump. Prefer `scream_<pid>_*.dmp` over empty `tcp_<pid>_*.dmp` placeholders.

## Auto-analyze on crash

With `fuzz.autoAnalyzeCrash: true` (default), each new crash writes:

```
data/crashes/<project>/<crash-guid>_analysis.json
```

Fields include exception code, fault address, module+offset, and x64 register snapshot (RIP, RSP, …).

### Headless cdb + Scream Investigator (Windows)

When `fuzz.cdbAnalyzeCrash: true` (default, requires `autoAnalyzeCrash`), Randfuzz runs **cdb** as an automated crash robot (not the WinDbg GUI). One session collects:

| Probe | CDB command | Purpose |
|-------|-------------|---------|
| Symbols | `.sympath`, `.symfix`, `.reload /f /n` | PDB load before analysis |
| Analysis | `!analyze -v` | Primary triage narrative |
| Exception | `.exr -1`, `.ecxr` | ACCESS_VIOLATION parameters + fault context |
| Registers | `r` | General-purpose + RIP/RSP snapshot |
| Stack | `kv` | Call stack for symbolization / stack hash |
| Modules | `lm` | Image ranges for fault-address class |
| Fault insn | `u @rip L1` (between `RANDFUZZ_INSTRUCTION` / `===RANDALL_INSTRUCTION===` markers) | Single faulting instruction — ignore symbol-path noise outside markers |
| Symbol | `ln @rip` (marker-bounded) | Resolve RIP → `module!function+offset` |
| Disasm | `u @rip-20 @rip+40` | Wider instruction window at fault PC |
| Stack memory | `dq @rsp L40` | QWORDs near stack pointer |
| Heap (best-effort) | `!heap -s` | Heap corruption / UAF hints |
| Address (best-effort) | `!address $exceptioninformation[1]` | Region type (stack/heap/free/image) |
| Exploitability (optional) | `!exploitable` | msec.dll classification |

Research-only — richer exploitability evidence for Scream Investigator; no shellcode or payload automation.

| Artifact | Contents |
|----------|----------|
| `<guid>_analyze.txt` | Full `!analyze -v` text |
| `<guid>_exploitable.txt` | `!exploitable` output when **msec.dll** is available |
| `<guid>_cdb_triage.json` | Parsed summary + paths |
| `<guid>_debugger_observation.json` | **Scream Investigator** — structured `DebuggerObservation` (READ/WRITE/EXECUTE access from `.exr`, fault address class from `!address`/`lm`/heuristics including null/ASCII/heap/stack/freed/module/non-canonical, stack hash, diagnosis, exploitability hint, input-influence guess) |
| `<guid>_corruption_chain.json` | **Corruption chain** — research-only input→mutation→fault attribution (lineage + register↔payload joins + pattern depth + debugger evidence) |
| `<guid>_influence.json` | **Influence map** — input region → program state links with confirmation status (see [INFLUENCE_ENGINE.md](INFLUENCE_ENGINE.md)) |
| `<guid>_backward_trace.json` | **Backward trace** — dump-only exploit narrative (mutation → register → bad-pointer source → fault instruction → crash); no live TTD |
| `<guid>_exploit_research.json` | **Exploit Research panel** — faulting insn + static EA reconstruction + register/input **control matrix** (UNKNOWN→CONFIRMED) + destination vs written-value split + control-test rows + next experiment; stamped with `engine` build identity |
| `<guid>_root_cause.json` | **Root cause** — deterministic `RootCauseCandidate` + educational summary from correlated evidence facts |
| `<guid>_scream_evolution.json` | **Scream evolution** — family phenotype, generation/ancestor, momentum (READ→WRITE→controlled WRITE), warming label |

**Semantic fingerprint** — each crash also gets a derived `SemanticFingerprint` on triage/intelligence (not a separate on-disk file). It buckets by exception class, access kind, fault address class, faulting function, top normalized stack frames, heap signal, controlled input offset, oracle violation, coverage tail, and corruption-chain signature hash. `CrashCluster` groups by this key when present (falls back to legacy `ClusterKey`). Existing clusters remain readable — fingerprints are computed from existing artifacts at catalog load time.

`DebuggerObservation` feeds FaultSignals, ScreamScore bonuses, and the Crashes Investigation UI (“Scream Investigator” line). When pattern depth or debugger evidence exists, `CrashCorruptionChainDto` is fused into scream intelligence and canister context. **Scream evolution** groups related crashes by phenotype (function + stack + seed lineage — not IP cluster alone), tracks `parentInputHash` generations, and scores momentum vs ancestors. High momentum (`warming` / `hot`) boosts corpus energy, mutator credit on the lineage chain, RandallBrain hunt bias, and Magician `evolutionBless` when enabled. Investigation panel shows family, generation, momentum, and progression step. WinDbg remains the human “open the dump” button — Randfuzz passes `-cf` with metadata when opening by crash GUID (see [WinDbg open script](#windbg-open-with-randfuzz-metadata)).

Soft-fails when cdb is missing (install `scripts/install-debuggers.ps1`). Does not block the fuzz loop — ~90–120s timeout. Randfuzz passes `-y` (local cache + Microsoft symbol server) and runs `.sympath` before probes; see [WinDbg symbols](#windbg-symbols) below.

### Input attribution (register ↔ payload ↔ mutation step)

When the crashing input is available beside the canister, `InputAttributionEngine` joins debugger registers with payload bytes:

| Signal | Meaning |
|--------|---------|
| `RegisterMatches[]` | RAX/RCX/RDX/… or fault/RIP dword/qword/ASCII found at `payload+N` |
| `PrimaryRegister` | Best register for the fault (fault address beats RIP beats GPRs) |
| `SuspectedMutatorStep` | 0-based lineage index — prefers expand/insert over last-mutator-only when ASCII/write AV evidence supports it |
| `Narrative` | Research triage story: `field → register → sink → write/read AV → heap` (e.g. controlled write, length→memcpy-style when `!func` / disasm support it) |
| `AttributionScreamBonus` | Extra 0–18 ScreamScore when confidence is HIGH/MEDIUM and write AV + controlled pointer + heap signals align |

**Honesty rules (debugger over-claiming):**

- **Address class:** `0x0` → `NULL` (`NullPage`); `0x1`–`0xFFFF` → `NEAR_NULL` (`NearNull`). Numeric null/near-null always wins over noisy `!address` HEAP text.
- **Zero-value attribution suppressed:** register values `0`, `1`, `2`, `4`, `8`, `16`, `0xFFFFFFFF` are excluded from raw `input.find` attribution (reason: *NULL/low value excluded from raw input-value attribution*).
- **CDB module/insn markers:** `ln @rip` / `u @rip L1` are marker-bounded. Exception banners (`BREAKPOINT_80000003_…`) never glue into `faultingModule`. Symbol-path lines (`Deferred srv*…`, `Expanded Symbol search path`) are rejected — Fault insn stays **UNKNOWN** rather than garbage. RIP on `SafeExitProcess` / coreclr exit after an AV is labeled **teardown/exit path**, not the primary fault site.
- **Effective-address reconstruction (static):** `EffectiveAddressReconstructor` decodes common x64 mem forms from `u @rip` + the register dump — `[reg]`, `[reg±disp]`, `[reg+reg*scale]`, `[reg+reg*scale+disp]`, `[reg*scale(+disp)]`, `[rip+disp]` (uses opcode-byte length when present). Computes destination EA, compares to debugger fault address when both exist, and surfaces written value/width when the source register is known. Fixture: `mov dword ptr [rax-2Ch],ecx` with RAX=`0x2C` → EA=`0`. Investigation **Exploit Research** panel shows Faulting instruction · EA breakdown · Written value; unknowns stay `UNKNOWN` (never a symbol-path line).
- **Register / input control matrix:** rows are Register · Value · Input relationship · Status (`UNKNOWN` / `CORRELATED` / `INFLUENCED` / `CONTROLLED` / `CONFIRMED`). Built from `InputAttribution` register matches, Influence links, and live Counterfactual deltas. **Never** promote zero/low-value coincidence to `CONFIRMED`. All-ones (`0xFF…FF` / −1) in the payload is at most `CORRELATED` (live CF can raise to `CONTROLLED`, still not `CONFIRMED`).
- **Destination vs written-value control:** the panel never says only “Controlled write”. It shows separate destination-control and written-value-control claims (plus width + counterfactual repeatability), wired from EA base/source regs, PrimitiveEngine (`InputInfluencedWrite` / `RegisterControl`), and Counterfactual trials.
- **Control tests table:** CounterfactualEngine / live-loop probes render as Input · Reg/EA · Fault address · Result (`follows` / `unchanged` / …). When no trials exist yet, a `planned` row surfaces the next ResearchPlanner / Skeptic experiment.
- **Controlled write / maturity:** do not claim controlled write or promote `InputInfluencedWrite` to Confirmed / R5 from zero-coincidence alone — require counterfactual/delta evidence or a strong non-zero pattern (e.g. `0x41414141`). Null write without destination/value/length/index control evidence caps at **R1–R2** (triaged / root-cause). Bare mutator name `boundary` ≠ write-length control; R3 needs repeated boundary causality; R4 needs real control evidence.
- **Influence honesty labels:** mechanisms show as Observed / Confirmed / Hypothesized / Unverified. Speculative `length→alloc/copy` is Hypothesized, never Observed. All-ones (`0xFF…FF` / qword −1) is **sentinel correlation** (Unverified experiment hint), not proven control.
- **Root cause:** null write alone → LOW–MEDIUM leading hypothesis (“NULL/invalid destination reached a write”), not “Parser state error HIGH”. Page Heap detected ≠ UAF.

`DebuggerObservation.RegisterMatches` / `PrimaryRegisterMatch` may be pre-filled by the headless CDB script; otherwise Scream Investigator and `CorruptionChainBuilder` compute them from `RegistersText` + input file. Investigation UI shows the narrative, register table, attributed mutation step, and bonus. **Research only** — no exploit payloads.

### Backward trace (dump-only, no TTD)

`BackwardTraceBuilder` fuses CDB post-mortem probes with mutation lineage into a step-by-step research story:

| Step kind | Source |
|-----------|--------|
| `mutation` | Lineage chain; attributed step when register↔payload match supports it |
| `register` | `RegisterPayloadMatchDto` — which GPR holds input bytes |
| `source` | Heuristic bad-pointer origin: input bytes, freed heap, stack slot, ASCII pattern |
| `heap-timeline` | `freed → reuse → crash` when `!address`/`!heap`/`!analyze` signal UAF |
| `instruction` | Faulting insn from `u @rip` disasm block |
| `sink` / `crash` | Faulting function + ACCESS_VIOLATION |

Artifacts feed **HypothesisEngine** (`hyp-btrace-*` hypotheses), **Deep Scream** TTD playbook (dump-only section first; live TTD remains external), and the Investigation **Backward trace** panel. Built automatically when `fuzz.cdbAnalyzeCrash: true` on Windows.

### Root cause engine (Wave 1 — deterministic)

`RootCauseEngine` correlates normalized **`EvidenceFact`** atoms from Ghidra static (when present), CDB/`DebuggerObservation`, mutation lineage, corruption chain, oracle score, and backward trace into a single **`RootCauseCandidate`**:

| Field | Source |
|-------|--------|
| `Category` | Scored rules — bounds violation, integer conversion, size mismatch, lifetime violation, unexpected object state, uninitialized, parser state, format interpretation |
| `FaultingFunction` / `SuspectedSink` | Debugger faulting symbol or Ghidra static map |
| `SuspectedSourceFunction` | Stack caller, attributed mutator, or static hint |
| `InputRegion` | Pattern depth / register↔payload offset |
| `AllocationSite` / `CorruptionSite` | Heap probes, fault instruction, fault address class |
| `Evidence[]` | `EvidenceFact` list (stub contract — EvidenceFact agent may extend kinds) |
| `ObservedFacts` / `Inferences` / `Unknowns` | Direct observations vs deterministic conclusions vs gaps |

Persisted as `<guid>_root_cause.json`. Investigation UI shows an educational summary plus observed/inferred/unknown lists. **Research only** — no LLM on the hot path.

When the dedicated EvidenceFact agent lands, it should emit `EvidenceFact[]`; `RootCauseEngine.CollectEvidenceFacts` remains the integration point until then.

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

## CDB wait attach exception policy

When the fuzz loop uses the optional **cdb** wait backend (`DebuggerSession.StartCdbWait`), Randfuzz runs a `CdbProbePlan.WaitAttach` script (see [CDB_PROBE_ENGINE.md](CDB_PROBE_ENGINE.md)) instead of the legacy `g; .dump; qd` one-liner.

| Step | Behavior |
|------|----------|
| Attach break-in | Expected — script sets `sxn` filters then `g` to resume |
| First-chance exceptions | Passed to the process (`sxn` = break on **second** chance only) |
| Unhandled / second-chance | Break → `RANDFUZZ_CRASH_CAPTURE` → `.dump /ma` → `qd` |

Filters include `sxn av`, `sxn bpe`, and common NTSTATUS codes (`c0000005`, `c000001d`, `c0000094`, `c00000fd`, `e06d7363`). Prefer **Scream watcher** (`fuzz.debuggerMode: wait`) for production campaigns; cdb wait is a fallback when ProcDump/Scream are unavailable.

## WinDbg open with Randfuzz metadata

When you open a crash by GUID (`randall debug open -i <guid>`, Crashes → WinDbg, or `POST /api/debug/open`), Randfuzz writes `{guid}_windbg_open.txt` beside the canister and passes **`-cf`** to WinDbg Preview / classic WinDbg:

- Symbol path (`.sympath+` — same defaults as headless cdb)
- Project / crash GUID echo lines
- Corruption chain summary + mutator / pattern depth (when `{guid}_corruption_chain.json` exists)
- Scream Investigator diagnosis (when `{guid}_debugger_observation.json` exists)
- Auto `r` / `k` / `lm`, plus a pointer to `tools/randfuzzdbg/scripts/rf_walk.txt`

Research triage only — no exploit automation. See `RandfuzzDbgWalk` / `randall windbg walk -i <guid>`.

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
