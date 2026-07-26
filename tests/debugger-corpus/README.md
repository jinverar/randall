# Debugger Regression Corpus

Research-only lab faults with **expected** `DebuggerObservation` fields for headless cdb / Scream Investigator regression.

Each case folder contains:

- `README.md` — fault intent and harness invocation
- `expected.json` — loose match schema (`exception`, `access`, `addressClass`, `inputInfluence`)

## Cases

| Case | Status | Harness argv |
|------|--------|--------------|
| `null-deref` | live | `null-deref` |
| `av-read` | live | `av-read` |
| `av-write` | live | `av-write` |
| `ascii-write` | live | `ascii-write` |
| `divide-zero` | live | `divide-zero` |
| `illegal-instruction` | live | `illegal-instruction` |
| `heap-overflow` | **stub** | exits 2 — TODO native heap bug |
| `uaf` | **stub** | exits 2 — TODO PageHeap / free-list |

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

Requires Windows + cdb (Debugging Tools). CI on Linux skips automatically.

```powershell
scripts/build-debugger-corpus.ps1
dotnet test tests/Randall.Tests --filter DebuggerCorpus
```

See [docs/DEBUGGER_CORPUS.md](../../docs/DEBUGGER_CORPUS.md).
