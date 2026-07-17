# Crash analysis (Phase 16)

When a crash saves a Windows minidump, Randall can extract triage fields without WinDbg.

## Auto-analyze on crash

With `fuzz.autoAnalyzeCrash: true` (default), each new crash writes:

```
data/crashes/<project>/<crash-guid>_analysis.json
```

Fields include exception code, fault address, module+offset, and x64 register snapshot (RIP, RSP, …).

## CLI

```powershell
# By crash GUID (from randall crashes or web UI)
randall analyze -i 3fa85f64-5717-4562-b3fc-2c963f66afa6

# Direct minidump path
randall analyze -d data/crashes/vulnserver/crash_42.dmp

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

## Hot edges

At run end, `data/runs/<runId>/run.json` includes `hotEdges`: basic blocks hit most often during the run (edge hit counters from drcov traces).
