# Crash logging & triage (Phase 15)

Randall persists **reproducers plus structured metadata** for every unique crash (deduped by input hash).

## On-disk layout

```
data/crashes/<project>/
  index.jsonl                              # one line per unique crash
  <project>_<iter>_<hash>.bin              # exact input bytes
  <project>_<iter>_<hash>_crash.json       # rich sidecar (Phase 15)
  dumps/*.dmp                              # minidumps (when captured)
  traces/<crash-guid>.log                  # coverage trace copy at crash (if any)
```

## `index.jsonl` fields

| Field | Description |
|-------|-------------|
| `Id` | Crash GUID |
| `Project` / `Iteration` | Context |
| `Mutator` | `command/field/mutator` label |
| `InputHash` / `InputPath` | Dedup + reproducer file |
| `TargetExitCode` | Windows exit code string |
| `TriageTag` | RPP `post_crash` tag (e.g. `access_violation`) |
| `MiniDumpPath` | `.dmp` when available |
| `SidecarPath` | Path to `*_crash.json` |
| `RunId` | Links to `data/runs/<runId>/` journal |
| `At` | UTC timestamp |

## `*_crash.json` sidecar

Superset of index fields plus triage-oriented data:

| Field | Description |
|-------|-------------|
| `mutatorChain` | Lineage (v1: single mutator name) |
| `parentInputHash` | Pre-mutation input hash |
| `seedSource` / `seedFiles` | Where the baseline came from |
| `exceptionHint` | e.g. `0xC0000005 ACCESS_VIOLATION` |
| `targetDetail` | Runner detail string |
| `newEdgesAtCrash` / `totalEdgesAtCrash` | Coverage state at crash |
| `stalkBackend` | `none` or `external` |
| `tracePath` / `traceCopyPath` | Iteration trace + persisted copy |
| `responseHex` | Last TCP/UDP response preview |
| `transport` | Host, port, kind, TLS flag snapshot |
| `fuzzSnapshot` | Config path, coverageGuided flag |

API: `GET /api/crashes/{id}` returns `sidecar` when present.

## Scream canisters (UI)

The Crashes tab frames saved crashes as a **scare-floor harvest**: canisters fill as unique
crashes grow (one per Target profile by default). Canisters **on** by default; **animations off**
by default so fuzz campaigns keep the CPU. See [LORE.md](LORE.md) and `docs/assets/canisters/`.

## Minidumps

Captured on:

- File target **hang/timeout** (before kill)
- File target **abnormal exit** (Phase 15+)
- Long-lived **TCP server crash** (after exit, `allowExited: true`)

Dump type includes thread info for register/exception recovery in WinDbg:

```
.loadby sos coreclr   # or appropriate SOS
!analyze -v
```

Randall does **not** yet extract registers, disassembly, or stack hex into JSON — open the `.dmp` or use a future `randall crash analyze` command.

## Export bundle

```powershell
randall export -i <crash-guid>
```

Produces `data/exports/<id>/`:

- `crash_input.bin`
- `sample.drcov.log` (from sidecar trace when available)
- `coverage_edges.txt`
- `DRAGON_DANCE.txt`, `ghidra_import.py`
- minidump copy if present

## Still planned (Phase 16+)

| Item | Notes |
|------|-------|
| Register / PC / stack dump in JSON | Parse minidump or live `MiniDumpWithFullMemory` |
| ASLR/DEP/canary flags | PE + process mitigation query |
| Full mutation lineage tree | Parent crash/corpus id chain |
| Cmp/value maps | DynamoRIO client or native stalk |
| **Native stalk backend** | Replace external drcov; same log schema |

External tools (DynamoRIO today) are **optional adapters**. Randall’s logging schema is owned by us so native stalk drops in without changing your triage pipeline.
