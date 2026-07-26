# CDB Probe Engine

Research-only architecture that centralizes headless **cdb** command scripts, transcript parsing, and provenance for Scream Investigator / crash triage.

## Components

| Type | Location | Role |
|------|----------|------|
| `CdbProbePlan` | `Randall.Contracts/CdbProbeModels.cs` | Script profile selector |
| `CdbScriptBuilder` | `Randall.Infrastructure/CdbScriptBuilder.cs` | Deterministic `.cmd`/`-c` scripts with `RANDFUZZ_*` markers |
| `CdbMarkerParser` | `Randall.Infrastructure/CdbMarkerParser.cs` | Marker-based transcript → section map |
| `DebuggerObservationProvenance` | `Randall.Contracts/CdbProbeModels.cs` | Source + confidence for key facts |

## Probe plans

| Plan | Used by | Probes |
|------|---------|--------|
| `StandardCrash` | `WindowsCdbCrashAnalysisWriter`, `ScreamInvestigator` | `.symfix`, `.reload`, `!analyze -v`, `.exr -1`, `.ecxr`, `r`, `kv`, `lm`, `u @rip`, `dq @rsp`, `!heap -s`, `!address`, optional `!exploitable` |
| `HeapCrash` | `HeapCdbLens` | `!heap -s`, `!heap -p` (page-heap) |
| `DeepScream` | Reserved (TTD / extended triage) | Same as `StandardCrash` today |
| `InteractiveOpen` | `RandfuzzDbgWalk.TryWriteOpenScript` | Symbol path + canister metadata + `r`/`k`/`lm` |
| `WaitAttach` | `DebuggerSession.StartCdbWait` | Second-chance exception policy + `.dump /ma` |

## Section markers

Each probe block is wrapped with `.echo RANDFUZZ_<SECTION>_BEGIN/END`:

```
RANDFUZZ_ANALYZE, RANDFUZZ_EXR, RANDFUZZ_REGS, RANDFUZZ_STACK,
RANDFUZZ_DISASM, RANDFUZZ_MEM, RANDFUZZ_HEAP, RANDFUZZ_PAGEHEAP,
RANDFUZZ_LM, RANDFUZZ_ADDRESS, RANDFUZZ_EXPLOITABLE,
RANDFUZZ_WAIT_ATTACH, RANDFUZZ_CRASH_CAPTURE
```

`CdbMarkerParser.Parse()` prefers markers; when `!analyze` text appears without markers (older runs), it falls back to treating the full transcript as the analyze block.

## Wait / attach exception policy

Legacy cdb wait scripts used `g; .dump; qd`, which could capture the **first** break after attach — often a benign first-chance exception.

`CdbProbePlan.WaitAttach` sets **second-chance-only** filters before `g`:

1. **Ignore attach break-in** — `g` resumes after `-cf` script starts at the initial break.
2. **Continue harmless first-chance** — `sxn` (notify/second-chance) for AV, BPE, common NTSTATUS codes; first-chance passes to the process.
3. **Dump on unhandled crash** — when second-chance fires, `.dump /ma` runs inside `RANDFUZZ_CRASH_CAPTURE` and `qd` detaches.

See [CRASH_ANALYSIS.md — Wait attach policy](CRASH_ANALYSIS.md#cdb-wait-attach-exception-policy).

## Provenance

`DebuggerObservation.Provenance` (optional) tracks:

- **value** — same as top-level observation fields where populated
- **source** — CDB command (e.g. `.exr -1`, `r`, `!analyze -v`)
- **confidence** — `High` / `Medium` / `Low` / `Unknown`
- **kind** — `Observed` (read from CDB) vs `Inferred` (heuristic, e.g. address class)

Scream Investigator and `CrashIntelligenceBuilder` consume top-level fields unchanged; provenance is additive for Investigation UI / future Deep Scream.

## Tests

`tests/Randall.Tests/CdbProbeEngineTests.cs` — script generation, marker parse, wait attach policy, provenance wiring.

## Related docs

- [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) — artifacts, msec.dll, symbols
- [WINDBG_FUZZ_PKG.md](WINDBG_FUZZ_PKG.md) — RandfuzzDbg walk scripts
