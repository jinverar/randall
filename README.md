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
| **Lab agent** | `randall agent [--bind 0.0.0.0]` | Fuzz box on LAN — web UI + API |
| **Web + local** | `randall serve` | Browser UI on localhost |
| **Headless** | `randall fuzz -c project.yaml` | Scripts, CI |
| **Standalone** | Self-contained publish → zip folder | Air-gapped / offline VM |

## Status

**Phases 1–9 complete** — doctor preflight, UDP, checksums, advanced mutators. See [docs/ROADMAP.md](docs/ROADMAP.md).

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Use only on systems you own or have explicit permission to test. The authors are not responsible for misuse.
