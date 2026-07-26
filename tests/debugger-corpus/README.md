# Debugger Regression Corpus

Research-only lab faults with **expected** `DebuggerObservation` fields for headless cdb / Scream Investigator regression.

Each case folder contains:

- `README.md` — fault intent and harness invocation
- `expected.json` — loose match schema (`exception`, `access`, `addressClass`, `inputInfluence`)

## Cases

| Case | Status | Harness argv | Notes |
|------|--------|--------------|-------|
| `null-deref` | live | `null-deref` | NULL write |
| `null-read` | live | `null-read` | NULL read |
| `av-read` | live | `av-read` | wild read |
| `av-write` | live | `av-write` | wild write |
| `ascii-write` | live | `ascii-write` | ASCII-controlled write addr |
| `ascii-read` | live | `ascii-read` | ASCII-controlled read addr |
| `divide-zero` | live | `divide-zero` | arithmetic |
| `illegal-instruction` | live | `illegal-instruction` | #UD-style |
| `heap-overflow` | **stub** | exits 2 | managed Heapish fixture |
| `oob-write` | **stub** | exits 2 | OOB / heap overrun fixture |
| `uaf` | **stub** | exits 2 | Freed-class fixture |
| `double-free` | **stub** | exits 2 | Freed-class fixture |
| `stack-corrupt` | **stub** | exits 2 | Stackish fixture |
| `integer-trunc` | **stub** | exits 2 | size/truncation narrative fixture |

## expected.json fields

```json
{
  "caseId": "null-deref",
  "exception": { "code": "c0000005", "hintContains": "ACCESS_VIOLATION" },
  "access": "Write",
  "addressClass": "NullPage",
  "inputInfluence": "UNKNOWN",
  "stub": false
}
```

- `access` — `DebuggerAccessKind` name (`Read`, `Write`, `Execute`, `Unknown`)
- `addressClass` — `DebuggerAddressClass` name
- `inputInfluence` — `HIGH` / `MEDIUM` / `LOW` / `UNKNOWN`
- `stub: true` — integration tests skip live cdb runs; fixture-only until harness lands

## Running integration tests

Requires Windows + cdb (Debugging Tools). CI on Linux skips live cdb automatically; managed `ParseBlocks` fixtures still run.

```powershell
scripts/build-debugger-corpus.ps1
dotnet test tests/Randall.Tests --filter DebuggerCorpus
```

See [docs/DEBUGGER_CORPUS.md](../../docs/DEBUGGER_CORPUS.md).
