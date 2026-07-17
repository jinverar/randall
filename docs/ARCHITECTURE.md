# Randfuzz by Randall — Architecture

## Design goals

1. **Speed** — in-place mutation, pooled buffers, native coverage backends
2. **Understandability** — visual pipeline (CANAPE-style) + typed C# APIs
3. **Crashes** — minidumps, dedup, one-click replay
4. **Portable** — single-folder standalone; web or CLI host
5. **Teachable** — eight legs map to docs and UI sections

## Layer diagram

```
┌─────────────────────────────────────────────────────────────┐
│ Hosts                                                       │
│  Randall.Cli (serve | fuzz | replay | export)               │
│  Randall.Server (ASP.NET Core + SignalR + static UI)        │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│ Randall.Core                                                │
│  ProtocolModel · MutationEngine · SessionRunner             │
│  CorpusStore · CrashStore · IFuzzEngine                     │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│ Randall.Infrastructure                                      │
│  SqliteCorpus · DynamoRioCoverage · ProcessMonitor          │
│  MiniDumpWriter · MitmTransport                             │
└─────────────────────────────────────────────────────────────┘
```

## Core interfaces (planned)

| Interface | Responsibility |
|-----------|----------------|
| `ITransport` | Send/receive bytes (TCP, UDP, MITM, file) |
| `ICoverageBackend` | Run target, return edge bitmap (DynamoRIO drcov) |
| `ICrashMonitor` | Detect crash/hang; write minidump |
| `IMutator` | Transform input bytes |
| `IProtocolModel` | Blocks/primitives → serialized message |
| `ICorpusStore` | Persist inputs, scores, parent links |
| `ICrashStore` | Dedup, compare, export crashes |

## Deployment

### Standalone folder

```
randall/
├── Randall.exe
├── appsettings.json
├── data/corpus.db
├── tools/dynamorio/
└── projects/
```

Publish:

```powershell
dotnet publish src/Randall.Cli -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o publish/standalone
```

### Web agent

`randall serve --config project.yaml` binds Kestrel; browser connects to corpus/crash API and live event stream.

## Coverage path

1. Spawn target under `drrun -t drcov`
2. Parse `.drcov` trace → basic block set
3. Hash to edge bitmap; XOR against global seen-set
4. Novelty score → corpus priority queue

## Crash path

1. Monitor raises exception / exit code / timeout
2. Write minidump + save input + attach drcov if available
3. Stack hash for dedup; compare coverage prefix for first-diverge
4. Export bundle for Ghidra + Dragon Dance

## Project bundles

Portable `.randall/` directory:

- `project.yaml` — targets, transport, session graph
- `seeds/` — initial inputs
- `templates/` — protocol definitions

`randall export` / `randall import` for lab mobility.
