# Randall

<div align="center">
  <a href="docs/assets/randall.png">
    <img alt="Randall fuzzer mascot" src="docs/assets/randall.png" width="640" />
  </a>
  <br />
  <em>Stalk code paths. Scream on crash.</em>
</div>

**Generation + coverage-guided fuzzing for Windows** — a spiritual successor to Sulley/Boofuzz, CANAPE, and PaiMei Process Stalker, built in C#/.NET.

Named after Randall Boggs (*Monsters, Inc.*): he **stalks** targets, finds **unexpected paths**, and blends into the environment — like good fuzzing should.

> *Stalk code paths. Scream on crash.*

## Why Randall?

| Legacy tool | What Randall inherits |
|-------------|----------------------|
| **Sulley / Boofuzz** | Block-based protocol models, sessions, mutations |
| **CANAPE** | MITM capture, parse, inject, fuzz in-stream |
| **PaiMei pStalker** | Coverage novelty, crash stalking, path dedup |
| **DynamoRIO** | Fast basic-block coverage (drcov) |
| **Dragon Dance / Ghidra** | Coverage export for reverse-engineering triage |

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
| **Web + local** | `randall serve` | Browser UI on localhost |
| **Lab agent** | `randall agent --bind 0.0.0.0` | Fuzz box on LAN |
| **Headless** | `randall fuzz -c project.yaml` | Scripts, CI |
| **Standalone** | Self-contained publish → zip folder | Air-gapped / offline VM |

## Status

**Phases 1–6 complete** — block models, coverage, proxy, triage export, RPP plugins, campaigns, portable pack, full web UI. See [docs/ROADMAP.md](docs/ROADMAP.md).

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Use only on systems you own or have explicit permission to test. The authors are not responsible for misuse.
