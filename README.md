# Randall

<div align="center">
  <a href="docs/assets/randall.png">
    <img alt="Randall fuzzer mascot" src="docs/assets/randall.png" width="640" />
  </a>
  <br />
  <em>Stalk code paths. Scream on crash.</em>
</div>

**Generation + coverage-guided fuzzing for Windows** — a spiritual successor to Sulley/Boofuzz, CANAPE, and PaiMei Process Stalker, built in C#/.NET.

Named after **Randall Boggs** (*Monsters, Inc.*) — master of camouflage, competitive to a fault, always sneaking into places he shouldn't be. For fuzzing that's a feature:

| Randall | Fuzzer |
|---------|--------|
| 🦎 Camouflages — evades detection | Valid-looking shells, MITM blend-in |
| 🐛 Beats Sulley | Coverage-guided inputs that hit **new** paths |
| 🧪 Sneaks the factory | Stalk unexplored code with DynamoRIO |
| 💥 Scream Extractor energy | Scream on crash — dumps, dedup, Ghidra |
| 🕵️ Another trick up his sleeve | Havoc, dictionaries, session flows, plugins |

Full parody mapping: [docs/LORE.md](docs/LORE.md)

> *Stalk code paths. Scream on crash.*

## Why Randall?

| Legacy tool | What Randall inherits |
|-------------|----------------------|
| **Sulley / Boofuzz** | Block-based protocol models, sessions, mutations |
| **CANAPE** | MITM capture, parse, inject, fuzz in-stream |
| **PaiMei pStalker** | Coverage novelty, crash stalking, path dedup |
| **DynamoRIO** | Fast basic-block coverage (drcov) |
| **Dragon Dance / Ghidra** | Coverage export for reverse-engineering triage |

## Stalking bugs — PaiMei-style coverage map

<div align="center">
  <a href="docs/assets/randal_stalking_bugs.png">
    <img alt="Randall stalking bugs — color-coded control-flow graph inspired by PaiMei pStalker" src="docs/assets/randal_stalking_bugs.png" width="900" />
  </a>
  <br />
  <em>I don't just find bugs. I stalk them. I choose them. I crash them.</em>
</div>

This diagram is the **visual language Randall inherits from [PaiMei Process Stalker](https://github.com/OpenRCE/paimei)** (Pedram Amini's *pstalker*): a control-flow graph where **color tells the story** of how an input walked through the target until something broke.

### Color legend (pStalker method)

| Color | Meaning | Randall equivalent |
|-------|---------|-------------------|
| **Blue** | Blocks on the **executed path** — code this input actually ran through | Known corpus paths; replayed inputs that hit the same edges |
| **Green** | **New coverage** — basic blocks or edges seen for the first time | DynamoRIO drcov novelty; corpus entries that expand the frontier (`+N edges` in the fuzz log) |
| **Gray** | Existing blocks **not taken** on this run | Unexplored branches — the stalker's next hunting ground |
| **Red** | **Crash location** (e.g. `ACCESS_VIOLATION`) | `CrashRecord` + minidump + triage tag from RPP `post_crash` |

Solid arrows = **taken** edges. Dashed arrows = **not taken** — forks you haven't fuzzed yet.

### What the panels mean

| Panel | pStalker idea | In Randall |
|-------|---------------|------------|
| **Coverage overview** | How much of the target have we mapped? | Corpus stats, `/api/corpus/{project}`, DynamoRIO edge counts |
| **Path comparison** | Baseline run vs current run — did we learn anything? | Corpus energy / power schedule; inputs that add edges get kept |
| **First divergence** | Where did this input peel off from the last known good path? | Crash path dedup + cluster triage (Phase 4) |
| **Execution timeline** | Last N blocks before the scream | Live fuzz log (web UI + SignalR) — watch green `+edges` moments |
| **Crash log** | Which exceptions came with new coverage? | Crashes tab — filter by project, triage tags, export to Ghidra bundle |

Randall is **generation + stalking**: Boofuzz-style models get bytes in the door; PaiMei-style coverage decides which inputs are worth keeping and which path led to the crash. The [web UI](docs/LAB_PRACTICE.md#8-web-ui) (`randall serve`) is the lab console for that hunt — fuzz control, session graph, crashes, and coverage status on one screen.

Leg 4 deep dive: [docs/LEGS.md#leg-4--stalk-coverage](docs/LEGS.md#leg-4--stalk-coverage)

## Eight legs (feature map)

Randall has **eight legs** — each one teaches a fuzzing concept. See [docs/LEGS.md](docs/LEGS.md) for the learning path.

| Leg | Module | Concept |
|-----|--------|---------|
| 1 | **Model** | Define protocols with blocks and primitives |
| 2 | **Mutate** | Generation strategies and field-aware fuzzing |
| 3 | **Send** | Network, file, and stdin transports |
| 4 | **Stalk** | DynamoRIO coverage and frontier detection |
| 5 | **Scream** | Crash capture, dedup, minidumps |
| 6 | **Proxy** | CANAPE-style MITM and live traffic editing |
| 7 | **Web** | Browser UI + API for lab and remote use |
| 8 | **Pack** | Portable standalone folders and project bundles |

## Architecture

```
Randall.Core          Engine (models, mutations, corpus, crashes)
Randall.Infrastructure   SQLite, DynamoRIO, monitors
Randall.Server        ASP.NET Core API + web UI
Randall.Cli           Headless: fuzz, serve, replay, export
Randall.Contracts     Shared DTOs
```

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Lab targets

Default profiles: **vulnserver** (TCP lab) plus generic **file-text** / **file-framed** templates. Private targets go in gitignored `projects/local/`.

```powershell
dotnet run --project src/Randall.Cli -- targets
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml --dry-run
```

See [docs/TARGETS.md](docs/TARGETS.md) and [targets/README.md](targets/README.md).

**Hands-on lab walkthrough:** [docs/LAB_PRACTICE.md](docs/LAB_PRACTICE.md)

## Quick start (development)

Requires [.NET 8 SDK](https://dotnet.microsoft.com/download).

```powershell
git clone https://github.com/jinverar/randall.git
cd randall
dotnet build
dotnet run --project src/Randall.Cli -- --help
dotnet run --project src/Randall.Server
```

## Deployment modes

| Mode | Command | Use case |
|------|---------|----------|
| **Lab agent** | `randall agent [--bind 0.0.0.0]` | Fuzz box on LAN — web UI + API |
| **Web + local** | `randall serve` | Browser UI on localhost |
| **Headless** | `randall fuzz -c project.yaml` | Scripts, CI |
| **Standalone** | Self-contained publish → zip folder | Air-gapped / offline VM |

## Status

**Phase 14 complete — web session graph viewer + lab practice guide.** See [docs/LAB_PRACTICE.md](docs/LAB_PRACTICE.md).

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Use only on systems you own or have explicit permission to test. The authors are not responsible for misuse.
