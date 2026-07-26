# Debugger corpus lab harness

Research-only native process that triggers intentional Windows faults for the [Debugger Regression Corpus](../../tests/debugger-corpus/README.md).

No network listeners, no fuzz payloads — each fault is a single deterministic SEH event selected by argv.

## Build (Windows + gcc)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-debugger-corpus.ps1
```

Output: `targets/debugger-corpus/debugger_corpus_fault.exe`

## Run a fault

```powershell
.\targets\debugger-corpus\debugger_corpus_fault.exe null-deref
.\targets\debugger-corpus\debugger_corpus_fault.exe av-read
.\targets\debugger-corpus\debugger_corpus_fault.exe ascii-write --delay-ms 2000
```

Attach with Scream or cdb before the delay expires (default 1.5s):

```powershell
dotnet run --project src/Randall.Cli -- scream watch -p <pid> -o data/crashes/debugger-corpus/dumps
```

## Mapping to existing lab targets

| Corpus case | This harness | Existing target |
|-------------|--------------|-----------------|
| `null-deref` | `--` / default | `scream_crash.exe` (Scream selftest) |
| `ascii-write` | `ascii-write` | `randall-screamcrash` + `SCREAM` token → `scream_av.dll` |
| `av-write` | `av-write` | VulnDrone TCP `HELLO` expand path (controlled write) |
| others | matching argv | — |

Stubs (`heap-overflow`, `uaf`) exit with code 2 — expected sidecars live under `tests/debugger-corpus/`.
