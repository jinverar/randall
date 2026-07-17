# Randfuzz by Randall

<div align="center">
  <a href="docs/assets/randall.png">
    <img alt="Randall — Randfuzz mascot" src="docs/assets/randall.png" width="640" />
  </a>
  <br />
  <em>Stalk code paths. Scream on crash.</em>
</div>

**A next-generation fuzzer for Windows** — generation, coverage-guided stalking, and crash triage in native C#/.NET.

I don't just throw bytes at parsers and hope. I **camouflage** valid-looking traffic, **sneak** into code paths nobody's mapped yet, and **scream** when something breaks — minidump and all. Randfuzz pulls the good stuff from the giants before us ([Sulley](https://github.com/OpenRCE/sulley) / [Boofuzz](https://github.com/jtpereyda/boofuzz), [CANAPE](https://github.com/foxitcs/canape), [PaiMei pStalker](https://github.com/OpenRCE/paimei), [DynamoRIO](https://dynamorio.org/)) and runs it as **one stack** — CLI, web UI, portable deploy. Respect to the legends; I'm just the chameleon who wired it together.

**Randfuzz** is the product. **Randall** is the mascot — named after **Randall Boggs** (*Monsters, Inc.*): master of camouflage, competitive to a fault, always sneaking into places he shouldn't be. Yeah, that's the vibe:

| Randall (mascot) | What Randfuzz actually does |
|---------|--------|
| 🦎 **Camouflage** — blend in | Valid shells, plausible protocols, MITM that looks like normal traffic |
| 🐛 **Competitive** — always hunting the edge | Coverage-guided inputs that hit **new** paths |
| 🧪 **Sneak the factory** | Stalk unexplored code with DynamoRIO |
| 💥 **Scream Extractor energy** | Crash capture — dumps, dedup, Ghidra export |
| 🕵️ **Another trick up my sleeve** | Havoc, dictionaries, session flows, plugins |

Full parody mapping: [docs/LORE.md](docs/LORE.md)

> *Stalk code paths. Scream on crash.*

## Tricks borrowed from the greats

I'm not here to rewrite history. I'm here to **stop duct-taping six runtimes** every time you fuzz on Windows. These are the shoulders I stand on:

| Tool / tradition | What Randfuzz took and ran with |
|-------------|----------------------|
| **[Sulley / Boofuzz](https://github.com/jtpereyda/boofuzz)** | Block models, sessions, mutations — generation fuzzing done right |
| **[CANAPE](https://github.com/foxitcs/canape)** | MITM capture, parse, inject — see the wire before you break it |
| **[PaiMei pStalker](https://github.com/OpenRCE/paimei)** | Color-coded stalking — new edges, first divergence, crash paths |
| **[DynamoRIO](https://dynamorio.org/)** | Fast drcov instrumentation |
| **Ghidra / triage** | Export coverage and crashes for the reverse-engineering grind |

Boofuzz and AFL still slap. Randfuzz is for when you want **generation + stalking + proxy + triage** under one roof — next-gen pipeline, same ethics: **authorized targets only**.

## Stalking bugs — how I see the factory floor

<div align="center">
  <a href="docs/assets/randal_stalking_bugs.png">
    <img alt="Randall stalking bugs — color-coded control-flow graph inspired by PaiMei pStalker" src="docs/assets/randal_stalking_bugs.png" width="900" />
  </a>
  <br />
  <em>I don't just find bugs. I stalk them. I choose them. I crash them.</em>
</div>

This is the view [PaiMei pStalker](https://github.com/OpenRCE/paimei) made famous — **color tells you where the input went** before the scream. Blue path, green new territory, red crash site. I didn't invent it; I just think every fuzzer should *feel* like this when you're triaging.

### Color legend (pStalker method)

| Color | Meaning | How Randfuzz uses this |
|-------|---------|-------------------|
| **Blue** | Blocks on the **executed path** — code this input actually ran through | Known corpus paths; replayed inputs that hit the same edges |
| **Green** | **New coverage** — basic blocks or edges seen for the first time | DynamoRIO drcov novelty; corpus entries that expand the frontier (`+N edges` in the fuzz log) |
| **Gray** | Blocks you **didn't take** this run | Unexplored forks — dinner's still on the table |
| **Red** | **Crash location** (e.g. `ACCESS_VIOLATION`) | `CrashRecord` + minidump + triage tag from RPP `post_crash` |

Solid arrows = **taken**. Dashed = **not yet** — that's where I'm going next.

### What the panels mean

| Panel | Classic idea (pStalker-style) | In Randfuzz |
|-------|---------------|------------|
| **Coverage overview** | How much of the target have we mapped? | Corpus stats, `/api/corpus/{project}`, DynamoRIO edge counts |
| **Path comparison** | Baseline run vs current run — did we learn anything? | Corpus energy / power schedule; inputs that add edges get kept |
| **First divergence** | Where did this input peel off from the last known good path? | Crash path dedup + cluster triage (Phase 4) |
| **Execution timeline** | Last N blocks before the scream | Live fuzz log — green `+edges` moments are the good stuff |
| **Crash log** | Which exceptions came with new coverage? | Crashes tab — filter by project, triage tags, export to Ghidra bundle |

**Generation meets stalking:** models get weird bytes through the door; coverage tells me what's worth keeping. Fire up [`randall serve`](docs/LAB_PRACTICE.md#8-web-ui) — my web console for fuzz runs, session graphs, crashes, and coverage. *Chaos is my code*, but at least it's organized chaos.

Leg 4 deep dive: [docs/LEGS.md#leg-4--stalk-coverage](docs/LEGS.md#leg-4--stalk-coverage)

## Eight legs, zero mercy

Eight capability areas. One chameleon. See [docs/LEGS.md](docs/LEGS.md) for the full map.

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

## Factory floor (lab targets)

Built-in vulnerable targets for practice — **your** factory, **your** permission slip. Default profiles: **vulnserver** (TCP), plus **file-text** / **file-framed** templates. Got something private? `projects/local/` is gitignored.

```powershell
dotnet run --project src/Randall.Cli -- targets
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml --dry-run
```

See [docs/TARGETS.md](docs/TARGETS.md) and [targets/README.md](targets/README.md).

**Hands-on lab walkthrough:** [docs/LAB_PRACTICE.md](docs/LAB_PRACTICE.md)

## Optional — DynamoRIO (coverage-guided stalking)

Coverage is **optional**. Randfuzz finds crashes without it. Install DynamoRIO when you want `+N edges` in the fuzz log and corpus inputs ranked by new basic blocks.

### Install (pick one)

**A. Script (downloads latest release)**

```powershell
powershell -File scripts/install-dynamorio.ps1
```

**B. Manual zip** — download `DynamoRIO-Windows-*.zip` from [DynamoRIO releases](https://github.com/DynamoRIO/dynamorio/releases), extract, and place so this file exists:

```
tools/dynamorio/bin64/drrun.exe
```

Example: extract `DynamoRIO-Windows-11.3.0-1` and rename the folder to `tools/dynamorio`. Randfuzz also auto-detects `tools/DynamoRIO-*` if you keep the versioned folder name.

Optional env var: `DYNAMORIO_HOME=C:\path\to\tools\dynamorio`

### Verify

```powershell
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml
```

Web UI **Dashboard** should show **DynamoRIO: Ready** (not Missing).

### Run with coverage

**File targets** — set `coverageGuided: true` in project YAML, or use the web **Fuzz** tab checkbox.

**TCP lab (vulnserver)** — slower; spawns an instrumented server per iteration:

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml --coverage --max-iterations 200
```

Requires `coverageTcpSpawn: true` in `projects/vulnserver.yaml` (already set for the lab target).

See [docs/FUZZING.md](docs/FUZZING.md) and [docs/CRASH_ANALYSIS.md](docs/CRASH_ANALYSIS.md) (`stalkMode`: `auto` | `external` | `native` | `none`).

### Stalk bugs with the session graph (web UI)

1. Start the lab console: `dotnet run --project src/Randall.Server --urls http://127.0.0.1:5000`
2. Open **http://127.0.0.1:5000** — **Dashboard** should show **DynamoRIO: Ready** when `tools/dynamorio/bin64/drrun.exe` exists.
3. **Session graph** tab → select **vulnserver** → **Load graph** — Mermaid diagram shows STAT → TRUN branching (where mutation focuses).
4. **Fuzz** tab → target **vulnserver**, check **Coverage-guided**, Start — live log shows `+N edges` (green) when an input maps new code; **CRASH** when the target dies.
5. **Crashes** tab → click a row → ASCII payload + **Why** (e.g. `ACCESS_VIOLATION`) + command/mutator lineage.

CLI equivalent:

```powershell
dotnet run --project src/Randall.Cli -- graph -c projects/vulnserver.yaml
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml --coverage --max-iterations 100
```

## Quick start — sneak in

Requires [.NET 8 SDK](https://dotnet.microsoft.com/download). Clone, build, start breaking things (legally):

```powershell
git clone https://github.com/jinverar/randall.git
cd randall
dotnet build
dotnet run --project src/Randall.Cli -- --help
dotnet run --project src/Randall.Server
```

## How I deploy

| Mode | Command | When |
|------|---------|------|
| **Lab agent** | `randall agent [--bind 0.0.0.0]` | Fuzz box on the LAN — web UI + API, all interfaces |
| **Web + local** | `randall serve` | Browser console on localhost |
| **Headless** | `randall fuzz -c project.yaml` | Scripts, CI, no UI needed |
| **Standalone** | Self-contained publish → zip folder | Air-gapped VM — I travel light |

## Status

**Phase 15** — execution journal + crash sidecars. Logging: [docs/EXECUTION_LOGGING.md](docs/EXECUTION_LOGGING.md), [docs/CRASH_LOGGING.md](docs/CRASH_LOGGING.md).

**Phase 16** — edge hit counters, `randall analyze`, pluggable stalk backend. See [docs/CRASH_ANALYSIS.md](docs/CRASH_ANALYSIS.md). Native stalk scaffold is in place; DynamoRIO remains the optional external adapter until native lands.

## Acknowledgments

Massive respect to [Sulley](https://github.com/OpenRCE/sulley), [Boofuzz](https://github.com/jtpereyda/boofuzz), [CANAPE](https://github.com/foxitcs/canape), [PaiMei](https://github.com/OpenRCE/paimei), AFL/libFuzzer, and [DynamoRIO](https://dynamorio.org/) — the tools that taught the rest of us how to fuzz. Randfuzz combines their best ideas and pushes forward on Windows. Import your Boofuzz scripts, share your YAML, keep the community sharp.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Authorized targets only — systems you own or have **explicit permission** to test. I'm a fuzzer, not a lawyer. The authors aren't responsible for misuse.

*Monsters, Inc. and Randall Boggs are property of Disney/Pixar. This project is an independent parody for security research.*
