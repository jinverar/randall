# Randall

<div align="center">
  <a href="docs/assets/randall.png">
    <img alt="Randall fuzzer mascot" src="docs/assets/randall.png" width="640" />
  </a>
  <br />
  <em>Stalk code paths. Scream on crash.</em>
</div>

**Generation + coverage-guided fuzzing for Windows** — built in C#/.NET for lab and research workflows.

Randall **combines useful ideas** from several well-known fuzzing traditions — block-based protocol modeling ([Sulley](https://github.com/OpenRCE/sulley) / [Boofuzz](https://github.com/jtpereyda/boofuzz)), in-stream traffic analysis ([CANAPE](https://github.com/foxitcs/canape)), and coverage-guided path exploration ([PaiMei pStalker](https://github.com/OpenRCE/paimei)) — alongside modern instrumentation ([DynamoRIO](https://dynamorio.org/)). It is a learning and lab tool, not a replacement for any of the above.

Named after **Randall Boggs** (*Monsters, Inc.*) — master of camouflage, competitive to a fault, always sneaking into places he shouldn't be. The mascot is parody; the tooling is respectfully inspired by prior art:

| Randall (mascot) | Fuzzing idea |
|---------|--------|
| 🦎 Camouflages — blends in | Valid-looking shells, MITM traffic that looks normal |
| 🐛 Competitive scarer (film rivalry) | Coverage-guided inputs that reach **new** paths |
| 🧪 Sneaks the factory | Explore unexplored code with DynamoRIO |
| 💥 Scream Extractor energy | Crash capture — dumps, dedup, Ghidra export |
| 🕵️ Another trick up his sleeve | Havoc, dictionaries, session flows, plugins |

Full parody mapping: [docs/LORE.md](docs/LORE.md)

> *Stalk code paths. Scream on crash.*

## What Randall combines

Randall is our attempt to stitch together techniques that teams often run as separate tools — in one Windows-friendly workflow. We are grateful to the communities behind the projects below.

| Tool / tradition | Ideas Randall borrows |
|-------------|----------------------|
| **[Sulley / Boofuzz](https://github.com/jtpereyda/boofuzz)** | Block-based protocol models, sessions, mutations |
| **[CANAPE](https://github.com/foxitcs/canape)** | MITM capture, parse, inject, fuzz in-stream |
| **[PaiMei pStalker](https://github.com/OpenRCE/paimei)** | Coverage novelty, crash stalking, path dedup |
| **[DynamoRIO](https://dynamorio.org/)** | Fast basic-block coverage (drcov) |
| **Ghidra / triage workflows** | Coverage export for reverse-engineering |

If you already use Boofuzz or AFL-family fuzzers daily, keep using them — Randall may still help as a lab sandbox or for teaching how the pieces fit together.

## Stalking bugs — coverage map (PaiMei-inspired)

<div align="center">
  <a href="docs/assets/randal_stalking_bugs.png">
    <img alt="Randall stalking bugs — color-coded control-flow graph inspired by PaiMei pStalker" src="docs/assets/randal_stalking_bugs.png" width="900" />
  </a>
  <br />
  <em>I don't just find bugs. I stalk them. I choose them. I crash them.</em>
</div>

This diagram uses the **color-coded control-flow view** popularized by [PaiMei Process Stalker](https://github.com/OpenRCE/paimei) (Pedram Amini's *pstalker*): a graph where **color shows how an input moved through the target** until something broke. Randall's Leg 4 (Stalk) aims to support a similar mental model when working with DynamoRIO coverage and corpus triage.

### Color legend (pStalker method)

| Color | Meaning | How Randall uses this |
|-------|---------|-------------------|
| **Blue** | Blocks on the **executed path** — code this input actually ran through | Known corpus paths; replayed inputs that hit the same edges |
| **Green** | **New coverage** — basic blocks or edges seen for the first time | DynamoRIO drcov novelty; corpus entries that expand the frontier (`+N edges` in the fuzz log) |
| **Gray** | Existing blocks **not taken** on this run | Unexplored branches — the stalker's next hunting ground |
| **Red** | **Crash location** (e.g. `ACCESS_VIOLATION`) | `CrashRecord` + minidump + triage tag from RPP `post_crash` |

Solid arrows = **taken** edges. Dashed arrows = **not taken** — forks you haven't fuzzed yet.

### What the panels mean

| Panel | Classic idea (pStalker-style) | In Randall |
|-------|---------------|------------|
| **Coverage overview** | How much of the target have we mapped? | Corpus stats, `/api/corpus/{project}`, DynamoRIO edge counts |
| **Path comparison** | Baseline run vs current run — did we learn anything? | Corpus energy / power schedule; inputs that add edges get kept |
| **First divergence** | Where did this input peel off from the last known good path? | Crash path dedup + cluster triage (Phase 4) |
| **Execution timeline** | Last N blocks before the scream | Live fuzz log (web UI + SignalR) — watch green `+edges` moments |
| **Crash log** | Which exceptions came with new coverage? | Crashes tab — filter by project, triage tags, export to Ghidra bundle |

**Generation + coverage guidance:** protocol models (Boofuzz-style) produce structured inputs; coverage feedback (pStalker-style) helps decide what to keep and how to triage crashes. The [web UI](docs/LAB_PRACTICE.md#8-web-ui) (`randall serve`) is a single lab console for fuzz runs, session graphs, crashes, and coverage status.

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
| 6 | **Proxy** | MITM capture and live traffic editing (CANAPE-inspired) |
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

## Acknowledgments

Randall is a hobby/lab project that **builds on** excellent prior work — especially [Sulley](https://github.com/OpenRCE/sulley), [Boofuzz](https://github.com/jtpereyda/boofuzz), [CANAPE](https://github.com/foxitcs/canape), [PaiMei](https://github.com/OpenRCE/paimei), AFL/libFuzzer-style mutation strategies, and [DynamoRIO](https://dynamorio.org/). Thank you to everyone who maintained those tools and documented how to fuzz well. We welcome issues and PRs that improve interoperability (e.g. importing Boofuzz examples) rather than claiming superiority.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Use only on systems you own or have explicit permission to test. The authors are not responsible for misuse.
