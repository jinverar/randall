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

## Analysis intel (Linux-first)

On each **new** unique crash, Randfuzz attaches an `Intel` block to `*_crash.json` and writes:

```
data/crashes/<project>/<project>_<iter>_<hash>_intel.txt
data/crashes/<project>/<crash-guid>_intel.txt
```

The intel pack includes:

| Section | Purpose |
|---------|---------|
| **Findings** | What the scream looks like (command, mutator, exit, transport) + oracle/magician/joker arming status |
| **Coverage / depth / missed blocks** | Whether BB stalk ran; honest “unknown depth” when coverage was off |
| **Recipe recommendations** | Scare Floor / seed-ladder ideas for better crash cases |
| **Exploit-test recommendations** | Probes to run next (cyclic depth, checksec, heaptriage) — **not** payloads |
| **GDB commands** | Ready-to-paste `gdb`/`gef` triage lines |
| **Next CLI** | `stalk map`, `scream walk`, `gdb walk`, `exploit guide`, pack |

```bash
randall crashes -p vulnturret --intel
randall crashes show -i <crash-guid>
```

Scope stays triage/research: control offset → ROP Studio sketches → GDB/WinDbg walks. No shellcode or weaponized templates.

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

The Crashes tab frames saved crashes as a **scare-floor harvest**. Canisters do not
grade by fill % — the special seal is when triage reports **EIP/RIP control**.
Canisters **on** by default; continuous animations **off** by default. See [LORE.md](LORE.md)
and `docs/assets/canisters/`.

## Outbound notifications

When a project YAML enables `notifications:` and `CrashStore` saves a **new** hash, Randfuzz can post to Discord and/or email. Campaign YAML can alert on completion. See [NOTIFICATIONS.md](NOTIFICATIONS.md).

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
