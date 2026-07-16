# Randall roadmap

<div align="center">
  <img alt="Randall fuzzer mascot" src="assets/randall.png" width="560" />
  <br />
  <em>Stalk code paths. Scream on crash.</em>
</div>

**Mission:** Intelligent, tricky fuzzing — not raw exec/s speed.

**Lab targets:** [vulnserver](TARGETS.md#vulnserver) · generic [file templates](TARGETS.md) · private configs in `projects/local/`

View live status: `randall serve` → http://localhost:5000 → **Roadmap** tab, or `GET /api/roadmap`.

---

## Phase 1 — Lab targets + crash loop ✅

| Item | Status |
|------|--------|
| Project YAML loader (`projects/*.yaml`) | ✅ |
| Built-in tricky mutators (bitflip, expand, truncate, boundary, insert) | ✅ |
| **vulnserver** TCP fuzz (session graph) | ✅ |
| **file-text** template (structured text / XML) | ✅ |
| **file-framed** template (length-prefixed binary) | ✅ |
| Crash save + `index.jsonl` per target under `data/crashes/<name>/` | ✅ |
| CLI: `targets`, `fuzz`, `crashes`, `--dry-run` | ✅ |
| Full `replay` — `randall replay -c projects/x.yaml -i crash.bin` | ✅ |
| Minidump on hang (file targets) via `MiniDumpWriteDump` → `dumps/*.dmp` | ✅ |
| Web UI crash browser + `/api/crashes`, `/api/targets`, `/api/roadmap` | ✅ |

**Try it:**
```powershell
dotnet build
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml --dry-run
dotnet run --project src/Randall.Cli -- serve
dotnet run --project src/Randall.Cli -- replay -c projects/vulnserver.yaml -i data/crashes/vulnserver/<crash>.bin
```

---

## Phase 2 — Stalk (DynamoRIO) ✅

| Item | Status |
|------|--------|
| `DrcovParser` + `CoverageSet` — parse drcov text traces | ✅ |
| `DynamoRioRunner` — discover `drrun.exe`, run with `-t drcov` | ✅ |
| `CorpusTracker` — priority queue for new-edge inputs | ✅ |
| Wire coverage into `FuzzEngine` | ✅ |
| Web UI — dashboard, fuzz control, live SignalR log | ✅ |
| API — `POST /api/fuzz/start`, `/api/fuzz/stop`, `/api/corpus/{project}` | ✅ |
| Coverage-guided file fuzz | ✅ (`coverageGuided: true` in YAML) |

**Web UI:** `randall serve` → http://localhost:5000

Set `DYNAMORIO_HOME` for coverage-guided file fuzzing.

---

## Phase 3 — Network + proxy ✅

| Item | Status |
|------|--------|
| Vulnserver **session graph** — TRUN, GMON, GTER, KSTET, HTER, STAT→TRUN | ✅ |
| `SessionGraph` — random command pick per iteration | ✅ |
| **TcpMitmProxy** — CANAPE-style TCP MITM | ✅ |
| Web **Proxy** tab — capture, hex edit, replay | ✅ |
| CLI — `randall proxy --listen 9998 --target 127.0.0.1:9999` | ✅ |

Point your fuzz client at `127.0.0.1:9998` while proxy forwards to vulnserver on 9999.

---

## Phase 4 — Crash stalking + Ghidra ✅

| Item | Status |
|------|--------|
| `CrashStalker.FindFirstDiverge` | ✅ |
| Triage bundle export | ✅ |
| `GhidraExporter` — `ghidra_import.py`, `DRAGON_DANCE.txt`, `coverage_edges.txt` | ✅ |

---

## Phase 5 — Polyglot plugins + autopilot ✅

| Item | Status |
|------|--------|
| **RPP** — Python/Node plugins over JSON stdin/stdout | ✅ |
| Example plugin `plugins/xor-silly` | ✅ |
| **Campaign scheduler** — `campaigns/lab-smoke.yaml`, `nightly-lab.yaml` | ✅ |
| CLI — `randall campaign`, `randall pack` | ✅ |
| Web **Campaign** tab + `/api/campaign/*` | ✅ |
| Portable pack — self-contained win-x64 folder | ✅ |
| Cursor Automations autopilot | 📋 see README / prior chat |

**Pack for lab VM:**
```powershell
dotnet run --project src/Randall.Cli -- pack -o publish/standalone
# or: .\scripts\publish-standalone.ps1
```

**Plugins:** [docs/RPP.md](RPP.md)

---

## Phase 6 — Intelligence + polish ✅

| Item | Status |
|------|--------|
| **Length-prefixed `sized` blocks** — off-by-one / overflow length mutation (~25% bias) | ✅ |
| **file-framed** block model — `protocols/file_framed.yaml` | ✅ |
| **`randall bundle import`** — unpack project zip to `bundles/imported/` | ✅ |
| **Bundle export** — includes protocols, seeds, plugins | ✅ |
| **Crash hash dedup** — skip duplicate inputs in `CrashStore` | ✅ |

**Leg 1 models:** [docs/MODEL.md](MODEL.md) · `projects/protocols/`

```powershell
randall bundle export -c projects/vulnserver.yaml -o bundles/vulnserver.zip
randall bundle import -i bundles/vulnserver.zip -o projects/imported
randall fuzz -c projects/file-framed.yaml --dry-run
```

Drop binaries into `targets/` per [TARGETS.md](TARGETS.md), then fuzz. Private profiles go in gitignored `projects/local/`.

---

## Phase 7 — Lab agent + mobility 🔄 active

| Item | Status |
|------|--------|
| **`randall agent`** — bind `0.0.0.0` for LAN lab boxes | ✅ |
| Web **Bundles** tab — export/import project zips | ✅ |
| Full vulnserver block models (GTER, KSTET, HTER) | ✅ |
| Discover `projects/local/` in targets API (gitignored) | ✅ |
| Cursor Automations nightly template | ✅ [docs/AUTOPILOT.md](AUTOPILOT.md) |

```powershell
randall agent --port 5000          # LAN: http://<ip>:5000
randall serve --bind 127.0.0.1     # localhost only
```

---

## Phase 8 — Advanced techniques ✅

| Item | Status |
|------|--------|
| **Havoc** — AFL-style stacked mutations | ✅ |
| **Interesting integers** — libFuzzer-style aligned values | ✅ |
| **Dictionary** — token injection from YAML/file | ✅ |
| **Splice** — corpus crossover | ✅ |
| **Power schedule** — energy-weighted corpus picks | ✅ |
| **Session flows** — multi-step TCP state (STAT→TRUN) | ✅ |
| **Crash clusters** — triage grouping API + web UI | ✅ |

**Techniques guide:** [docs/FUZZING.md](FUZZING.md)

---

## Phase 9 — Lab readiness ✅

| Item | Status |
|------|--------|
| **`randall doctor`** — seeds, target, DynamoRIO, TCP/UDP, plugins | ✅ |
| Web **Doctor** button on Fuzz tab | ✅ |
| **UDP** datagram transport (`kind: udp`) | ✅ |
| **CRC32 checksum** block + post-mutation resync | ✅ |
| Field-level **havoc** in model fuzzer (~15% on payload fields) | ✅ |

**Before tonight's run:**
```powershell
randall doctor -c projects/vulnserver.yaml
randall doctor -c projects/local/notepadpp.yaml   # private targets
randall fuzz -c projects/vulnserver.yaml --dry-run
randall serve
```

---

## Phase 10 — Kidnap Boo (boofuzz parity) ✅

| Item | Status |
|------|--------|
| **Typed primitives** — string, delim, word, dword, qword, choices | ✅ |
| **Exhaustive mode** — `fuzz.mode: exhaustive` | ✅ |
| **mutateStep** — last / all / indices on session flows | ✅ |
| **ProcessMonitor** — long-lived target restart | ✅ |
| **VulnHttp** — HTTP lab server (:8080) | ✅ |
| **VulnFtp** — FTP lab server (:2121) | ✅ |
| **VulnSsh** — SSH stub server (:2222) | ✅ |
| **examples/** — http-simple, ftp-simple | ✅ |

**Build lab floor:**
```powershell
.\scripts\build-all-lab-targets.ps1
randall fuzz -c projects/vulnhttp.yaml --dry-run
randall fuzz -c examples/ftp-simple/project.yaml --dry-run
```

**Docs:** [EXAMPLES.md](EXAMPLES.md) · [BOOFUZZ_PARITY.md](BOOFUZZ_PARITY.md)

---

## Phase 11 — Camouflage (TLS + responses) ✅

| Item | Status |
|------|--------|
| **TLS transport** — `transport.tls`, `tlsInsecure`, SNI | ✅ |
| **expectResponse** — session step response validation | ✅ |
| **RPP post_receive** — `plugins/ftp-response` | ✅ |
| **TCP minidumps** — dump on long-lived server crash | ✅ |
| **Boofuzz importer** — `scripts/import-boofuzz.py` | ✅ |
| **https-simple** example + expanded lab-smoke campaign | ✅ |

```powershell
python scripts/import-boofuzz.py https://raw.githubusercontent.com/.../ftp_simple.py -o projects/imported/ftp
# Or local clone:
python scripts/import-boofuzz.py path/to/boofuzz/examples/ftp_simple.py -o projects/imported/ftp -p 2121

randall fuzz -c examples/https-simple/project.yaml --dry-run
randall campaign -c campaigns/lab-smoke.yaml
```

---

## Phase 12 — Stalk the factory (TCP + TFTP) ✅

| Item | Status |
|------|--------|
| **VulnTftp** — UDP RRQ/WRQ lab server (:6969) | ✅ |
| **sessionGraph** — response-driven branching (s_switch) | ✅ |
| **RPP post_crash** — `plugins/crash-tag` triage tags | ✅ |
| **TCP coverage stalk** — instrumented spawn per iteration (drcov) | ✅ |
| **UDP monitor** — long-lived process crash detection | ✅ |

```powershell
.\scripts\build-vulntftp.ps1
randall fuzz -c projects/vulntftp.yaml --dry-run

# TCP coverage stalk (needs DYNAMORIO_HOME):
# Set coverageGuided: true + coverageTcpSpawn: true in project YAML
randall fuzz -c projects/vulnserver.yaml
```

**sessionGraph example** (in `projects/vulnftp.yaml`):
```yaml
sessionGraph:
  start: USER
  mutate: STOR
  edges:
    - { from: USER, when: "331", to: PASS }
    - { from: PASS, when: "230", to: STOR }
```
