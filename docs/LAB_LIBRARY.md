# Lab library

Randfuzz ships a curated **lab library**: startable vulnerable-by-design servers plus linked fuzz profiles. Use it from the UI (**Fuzz → Lab servers**) or the HTTP API.

## Categories

| Category | What it covers |
|----------|----------------|
| **network** | TCP/UDP protocol labs (HTTP, FTP, SSH-shaped, TFTP, RPC, SMB-shaped, Vulnserver) |
| **drone** | Fictional RDL1 drone / GCS labs — see [DRONE_LAB.md](DRONE_LAB.md) |
| **exploit-dev** | Native mitigation-ladder ECHO (`vulnlab`) |

Every catalog start binds **127.0.0.1**. Pass `--host 0.0.0.0` only on an isolated lab network.

## Build

```bash
# Linux / macOS
scripts/build-lab-targets.sh

# Windows
powershell -File scripts/build-all-lab-targets.ps1
```

Per-target scripts: `scripts/build-vuln*.ps1`, `scripts/build-vulndrone.ps1`.

## UI

Fuzz → **Lab servers** shows category, difficulty, tags, port, PID, and Start/Stop. Filter with the category dropdown. Docs links point at `docs/*.md` (e.g. `DRONE_LAB.md`, `RPC_LAB.md`).

## API

| Route | Notes |
|-------|--------|
| `GET /api/labs?category=drone` | Status list (`LabServerInfoDto[]`) |
| `GET /api/labs/library` | Same labs + category index + counts |
| `POST /api/labs/{id}/start` | Start catalog entry (loopback) |
| `POST /api/labs/{id}/stop` | Stop one lab |
| `POST /api/labs/stop-all` | Stop every catalog lab |

Remote: append `?agent=http://…&agentToken=…` (see [LAB_AGENT.md](LAB_AGENT.md)).

## Catalog source

Definitions live in `LabCatalog` (`src/Randall.Infrastructure/LabCatalog.cs`). Start/stop lives in `LabServerManager`. Adding a lab:

1. Ship a target under `targets/` + `projects/<id>.yaml`
2. Add a `LabCatalog` entry (id, port, protocol, process name, exe path, tags, docs)
3. Wire `scripts/build-*.ps1` / `build-lab-targets.sh`
4. Document in `targets/README.md` and a focused `docs/*_LAB.md` when the protocol needs a walkthrough
