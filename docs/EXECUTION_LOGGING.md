# Execution logging (Phase 15)

Randall records **what happened during every fuzz iteration** — not just crashes. Logs are backend-agnostic: coverage traces today may come from an external instrumenter; **Randall native stalk** (Phase 16+) will write the same fields without third-party runtimes.

## Enable / disable

```yaml
fuzz:
  executionLog: true          # default
  runsDir: ../data/runs
```

Set `executionLog: false` to skip journal I/O (crash sidecars still written on crash).

## Run journal layout

Each fuzz session creates:

```
data/runs/<project>_<timestamp>_<guid>/
  run.json           # manifest — project, config, stalk backend, totals
  iterations.jsonl   # one JSON object per iteration (append-only)
```

Console prints: `Run journal: <path>`

### `run.json` manifest

| Field | Meaning |
|-------|---------|
| `runId` | Links crashes and iterations to this session |
| `stalkBackend` | `none`, `external`, or `native` (future) |
| `stalkBackendNote` | Human-readable backend description |
| `coverageGuided` | Whether coverage feedback was enabled |
| `iterations` / `crashesFound` | Filled on completion |

### `iterations.jsonl` entry

Each line is an `IterationLogEntry`:

| Field | Meaning |
|-------|---------|
| `iteration` | 1-based counter |
| `command` | e.g. `TRUN/payload`, `flow/login_stor`, `graph/USER→PASS→STOR` |
| `mutator` | e.g. `havoc`, `bitflip` |
| `mutatorChain` | Mutation lineage (v1: single step; grows in future phases) |
| `parentInputHash` | Hash of corpus seed / model baseline before mutation |
| `seedSource` | `corpus`, `model`, `sessionFlow`, `sessionGraph`, `exhaustive`, … |
| `payloadHash` / `payloadLength` | Mutated input fingerprint |
| `crashed` | Target fault this iteration |
| `newEdges` / `totalEdges` | Coverage feedback (when enabled) |
| `elapsedMs` | Wall time for iteration |
| `exitCode` / `targetDetail` | Target outcome |
| `stalkBackend` | `none` or `external` |
| `tracePath` | Path to coverage trace file for this iteration (if any) |
| `runId` | Session link |
| `dryRun` | True when `--dry-run` |

## Stalk backends

| ID | Status | Description |
|----|--------|-------------|
| `none` | Now | No coverage instrumentation |
| `external` | Now | Optional DynamoRIO drcov (pluggable; not required to fuzz) |
| `native` | Phase 16+ | Randall-owned Windows stalk — same log schema |

See [CRASH_LOGGING.md](CRASH_LOGGING.md) for crash sidecars and [ROADMAP.md](ROADMAP.md) for native stalk plans.

## Query examples

```powershell
# Pretty-print last run manifest
Get-Content data/runs/vulnserver_*/run.json | ConvertFrom-Json

# Crashes only from a run
Select-String '"crashed":true' data/runs/vulnserver_*/iterations.jsonl

# Slow iterations (>500ms)
Get-Content data/runs/vulnserver_*/iterations.jsonl | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object elapsedMs -gt 500
```
