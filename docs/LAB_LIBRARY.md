# Lab library

Randfuzz ships a curated **lab library**: startable vulnerable-by-design servers plus linked fuzz profiles. Use it from the UI (**Fuzz → Lab library**) or the HTTP API.

## Categories

| Category | What it covers |
|----------|----------------|
| **network** | TCP/UDP protocol labs (HTTP, FTP, SSH-shaped, TFTP, RPC, SMB-shaped, Vulnserver) |
| **drone** | Fictional RDL1 drone / GCS labs — see [DRONE_LAB.md](DRONE_LAB.md) |
| **iot** | Fictional MQTT-shaped broker (RMQ1) — see [MQTT_LAB.md](MQTT_LAB.md) |
| **file** | Profile-only file parsers (`file-text`, `file-framed`, [ReelDeck](REELDECK.md)) — no Start/Stop listener |
| **exploit-dev** | Native mitigation-ladder ECHO (`vulnlab`) |

Listener labs bind **127.0.0.1** on start. Pass `--host 0.0.0.0` only on an isolated lab network.

**Profile-only** entries (`Startable: false`) show in the library so you can find build hints and the fuzz YAML, then run:

```bash
randall fuzz -c projects/file-text.yaml
randall fuzz -c projects/file-framed.yaml
randall fuzz -c projects/reeldeck.yaml
```

## Build

```bash
# Linux / macOS — network + drone (+ optional file targets via their scripts)
scripts/build-lab-targets.sh
scripts/build-file-text.sh
scripts/build-file-framed.sh
scripts/build-reeldeck.sh

# Windows
powershell -File scripts/build-all-lab-targets.ps1
powershell -File scripts/build-file-text.ps1
powershell -File scripts/build-file-framed.ps1
powershell -File scripts/build-reeldeck.ps1
```

Per-target scripts: `scripts/build-vuln*.ps1`, `scripts/build-vulndrone.ps1`, `scripts/build-vulnmqtt.ps1`.

## UI

Fuzz → **Lab library** shows category, difficulty, tags, endpoint, PID, and Start/Stop (or **Fuzz cmd** for profile-only). Filter with the category dropdown. Docs links point at `docs/*.md` (e.g. `DRONE_LAB.md`, `MQTT_LAB.md`, `REELDECK.md`, `RPC_LAB.md`).

## API

| Route | Notes |
|-------|--------|
| `GET /api/labs?category=iot` | Status list (`LabServerInfoDto[]`) |
| `GET /api/labs/library` | Same labs + category index + counts |
| `POST /api/labs/{id}/start` | Start catalog entry (loopback; refuses profile-only) |
| `POST /api/labs/{id}/stop` | Stop one lab |
| `POST /api/labs/stop-all` | Stop every **startable** catalog lab |

Remote: append `?agent=http://…&agentToken=…` (see [LAB_AGENT.md](LAB_AGENT.md)). Category filters are forwarded to the agent.

## Catalog source

Definitions live in `LabCatalog` (`src/Randall.Infrastructure/LabCatalog.cs`). Start/stop lives in `LabServerManager`. Adding a lab:

1. Ship a target under `targets/` + `projects/<id>.yaml`
2. Add a `LabCatalog` entry (id, category, port/protocol or `file` + `Startable: false`, exe path, tags, docs)
3. Wire `scripts/build-*.ps1` / `build-lab-targets.sh` (or the file-target scripts)
4. Document in `targets/README.md` and a focused `docs/*_LAB.md` / `REELDECK.md` when the format needs a walkthrough
