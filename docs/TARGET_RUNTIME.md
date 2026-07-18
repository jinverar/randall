# Target Runtime — Randfuzz process + memory ownership

**Status:** Phases A–F shipped (next-gen track complete for v1)  
**Last updated:** 2026-07-18  
**Codename:** one runtime for all — local or remote

---

## One-sentence goal

**One Target Runtime** (local or `randall agent`) that **starts, stops, restarts, talks to, and debugs** the app under test — with **human-readable memory/heap lens** (segments, link/unlink hints, UAF/freed garbage, optional Page Heap + cdb `!heap`).

---

## What shipped

| Phase | Capability |
|-------|------------|
| **A** | `TargetRuntimeService` + `/api/runtime/*` + CLI + `data/runtime-slots.json` persistence |
| **B** | FuzzEngine `longLived` + `target.agentUrl` remote ownership |
| **C** | `TcpTube` / `UdpTube` / `StdioTube` (pwntools-shaped I/O) |
| **D** | Memory lens v0 — fill patterns, regions, neighborhood, crash UI |
| **E** | Declarative `target.postStart` actions (wait-port / sleep / exec / tcp-send / udp-send / http-get) |
| **F** | Page Heap via `gflags` + cdb `!heap` enrichment on dumps |

Labs remain **presets** on the same runtime. UI automation is an **`exec`** escape hatch (AutoIt/pywinauto), not the core.

---

## Quick start

```powershell
# Own a project binary
dotnet run --project src/Randall.Cli -- runtime start -c projects/vulnserver.yaml
dotnet run --project src/Randall.Cli -- runtime
dotnet run --project src/Randall.Cli -- runtime restart vulnserver
dotnet run --project src/Randall.Cli -- runtime stop vulnserver

# Fuzz (engine uses Target Runtime automatically when longLived: true)
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml

# Memory lens after a crash
dotnet run --project src/Randall.Cli -- memory -i <crash-guid>
dotnet run --project src/Randall.Cli -- memory --pid <pid>

# Remote fuzz box
dotnet run --project src/Randall.Cli -- agent --port 5000
# YAML: target.agentUrl: http://<vm-ip>:5000
# Inspect: GET /api/runtime/inspect?pid=123&agent=http://<vm-ip>:5000
```

Template: [templates/tcp-runtime.yaml](templates/tcp-runtime.yaml)

---

## YAML — next-gen profile

```yaml
target:
  executable: ../targets/myapp/myapp.exe
  longLived: true
  pageHeap: true                 # gflags /full when Debugging Tools installed
  agentUrl: http://192.168.2.10:5000   # optional; omit = local
  postStart:
    - op: wait-port
      host: 127.0.0.1
      port: 9999
      timeoutMs: 5000
    - op: sleep
      ms: 200
    - op: exec                   # GUI / custom harness
      command: powershell
      args: ["-File", "tools/open-testcase.ps1", "{pid}", "{case}"]
    - op: tcp-send               # priming PDU
      host: 127.0.0.1
      port: 9999
      dataHex: "00 01 02 03"
```

**Tokens in postStart strings:** `{pid}` `{id}` `{exe}` `{host}` `{port}` `{case}` `{workdir}`

**postStart ops:** `wait-port` · `sleep` · `exec` · `tcp-send` · `udp-send` · `http-get`

---

## Memory lens (analyst-facing)

On crash (and via API/CLI):

1. Fault summary — exception, read/write AV, address, module  
2. Free-fill / UAF patterns — `FEEEFEEE`, `DDDDDDDD`, `CDCDCDCD`, …  
3. Link/unlink **hints** — register-pair LIST_ENTRY candidates (confidence labeled)  
4. Neighborhood hex from minidump Memory64 when present  
5. **Heap** — cdb `!heap -s` / `!heap -p` when Debugging Tools available  
6. Page Heap likely flag when gflags fingerprints appear  

Artifacts: `data/crashes/<project>/{guid}_memory_lens.json` + `.txt`  
UI: **Crashes → investigation → Memory lens**  
API: `GET /api/crashes/{id}/memory` · `GET /api/runtime/inspect?pid=` (+ `?agent=`)

---

## Remote lab workflow (dumps + lens + offline import)

**Rule:** dumps and memory lens are produced **where the fuzzer runs**.  
Laptop Campaign with only `target.agentUrl` owns the remote *process*, but crash artifacts stay thin on the laptop. For real remote fuzzing:

1. On the fuzz VM: `randall agent --port 5000`
2. Open `http://<vm-ip>:5000` in a browser — same console, tagged **Remote lab** (Target Runtime + Campaign + Crashes live there)
3. Fuzz / investigate on that UI (dumps + `*_memory_lens.*` land under the agent’s `data/crashes/`)
4. Backup offline:
   - Agent UI: **Bundles → Crash artifact pack → Export**
   - Or CLI on agent: `randall crashes pack -p <project>`
5. On the laptop console later:
   - **Bundles → Pull from remote agent** (or `randall crashes pull -a http://vm:5000 -p <project> --import`)
   - Or copy the zip and **Import crash pack**

| Artifact | In crash pack? |
|----------|----------------|
| Inputs (`*.bin`), `index.jsonl`, sidecars | yes |
| Minidumps (`dumps/`) | yes |
| `*_analysis.json`, `*_memory_lens.json/.txt` | yes |
| Linked `data/runs/<runId>/` | optional (default on) |
| Project YAML / seeds | no — use project **Bundles** for that |

APIs: `POST /api/crashes/pack` · `GET /api/crashes/pack/download` · `POST /api/crashes/pack/import` · `POST /api/crashes/pack/pull`

---

## Architecture

```
Laptop console                          Fuzz VM (randall agent)
    │                                         │
    ├─ Target Runtime proxy (?agent=) ──────► TargetRuntimeService
    │                                         │ Campaign / FuzzEngine
    │                                         │ dumps + memory lens
    │                                         ▼
    │                                    data/crashes/<project>/
    │                                         │
    └─ crashes pull / pack import ◄───────────┘  (offline zip)
```

No kernel driver. Agent URLs restricted to localhost / RFC1918.

---

## Non-goals (still)

- Kernel / hypervisor introspection  
- Full pwntools exploit kit  
- Shipping Linux GDB UIs (pwndbg/GEF/PEDA)  
- Perfect decode of every custom allocator  
- Public-internet agents  

---

## Related

- [STALK_LOOP.md](STALK_LOOP.md) — baseline → fuzz → learn → repeat  
- [LAB_AGENT.md](LAB_AGENT.md) · [STALKING.md](STALKING.md) · [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md) · [CRASH_LOGGING.md](CRASH_LOGGING.md) · [ROADMAP.md](ROADMAP.md)
