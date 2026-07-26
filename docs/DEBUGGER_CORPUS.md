# Debugger Regression Corpus

Research-only lab faults with **expected** `DebuggerObservation` sidecars for regression-testing Randfuzz headless cdb triage (Scream Investigator).

## Purpose

The corpus answers: *when we know exactly what fault occurred, does cdb → `DebuggerObservation` classify it correctly?*

Each case defines:

| Field | Source |
|-------|--------|
| `exception.code` / `hintContains` | `!analyze` / `.exr` |
| `access` | `.exr` Parameter[0] or AV text (`Read` / `Write` / `Execute`) |
| `addressClass` | fault address heuristics + optional `!address` / `lm` / `!heap` probes |
| `inputInfluence` | ASCII/register/sidecar heuristics |

Sidecars live under [`tests/debugger-corpus/`](../tests/debugger-corpus/README.md). JSON schema: [`tests/debugger-corpus/schema.json`](../tests/debugger-corpus/schema.json).

## Lab harness

Native fault process (no network, no exploit payloads):

```
targets/debugger-corpus/debugger_corpus_fault.exe <fault-id> [--delay-ms N]
```

Build:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-debugger-corpus.ps1
```

Default 1.5s delay gives Scream/cdb time to attach before the fault fires.

### Case → harness mapping

| Case | argv | Alternate lab target |
|------|------|----------------------|
| `null-deref` | `null-deref` | `scream_crash.exe` (`randall scream selftest`) |
| `av-read` | `av-read` | — |
| `av-write` | `av-write` | VulnDrone TCP `HELLO` + expand |
| `ascii-write` | `ascii-write` | `randall-screamcrash` + `SCREAM` |
| `divide-zero` | `divide-zero` | — |
| `illegal-instruction` | `illegal-instruction` | — |
| `heap-overflow` | stub (exit 2) | **TODO** |
| `uaf` | stub (exit 2) | **TODO** |

## cdb probe pipeline

Live integration tests call `ScreamInvestigator.Investigate`, which runs `CdbScriptBuilder.BuildInline(CdbProbePlan.StandardCrash)` and parses output between **`RANDFUZZ_*_BEGIN/END`** markers via `WindowsCdbCrashAnalysisWriter.ExtractBlock`.

Flow:

1. Start `debugger_corpus_fault.exe <case>`
2. `ScreamWatcher` attach → minidump on second-chance
3. Headless **cdb** on dump → marker blocks
4. `ScreamInvestigator` → `DebuggerObservation`
5. Loose assert against `tests/debugger-corpus/<case>/expected.json`

## Tests

```powershell
dotnet test tests/Randall.Tests --filter DebuggerCorpus
```

| Test | When it runs |
|------|----------------|
| `All_cases_have_valid_expected_sidecars` | always |
| `Fixture_blocks_match_expected_without_cdb` | always (synthetic CDB text) |
| `Live_cdb_cases_match_expected` | Windows + cdb + built harness only |
| `Stub_cases_are_marked_and_skipped_for_live_runs` | always |

Live tests **vacuously pass** on Linux CI or machines without cdb/gcc — they do not fail the build.

Easiest live cases today: `null-deref`, `av-read`, `divide-zero`.

## Manual workflow

```powershell
# Terminal A — build + start fault
scripts/build-debugger-corpus.ps1
$p = Start-Process .\targets\debugger-corpus\debugger_corpus_fault.exe -ArgumentList av-read -PassThru

# Terminal B — attach Scream
dotnet run --project src/Randall.Cli -- scream watch -p $p.Id -o data/crashes/debugger-corpus/dumps

# Headless triage on captured dump
dotnet run --project src/Randall.Cli -- analyze -d data/crashes/debugger-corpus/dumps/<dump>.dmp --cdb
```

## Roadmap (stubs)

- **heap-overflow** — one-byte heap overrun; PageHeap + `!heap` for `Heapish`
- **uaf** — malloc/free/use; `!address` → `Freed` class

Update `expected.json` and remove `"stub": true` when harness cases land.

## Related docs

- [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) — headless cdb + Scream Investigator
- [targets/debugger-corpus/README.md](../targets/debugger-corpus/README.md) — harness details
