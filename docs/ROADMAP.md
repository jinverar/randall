# Randfuzz by Randall — roadmap

<div align="center">
  <img alt="Randall — Randfuzz mascot" src="assets/randall.png" width="560" />
  <br />
  <em>Stalk code paths. Scream on crash.</em>
</div>

**Mission:** Intelligent, tricky fuzzing — not raw exec/s speed.

**Lab targets:** [vulnserver](TARGETS.md#vulnserver-notes) · generic [file templates](TARGETS.md) · private configs in `projects/local/`

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
| **Hybrid semantic oracles** (runtime / invariant / differential / metamorphic) | ✅ [ORACLES.md](ORACLES.md) — supplements coverage |
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
| **Discord + email notifications** | ✅ unique crash + campaign complete — [NOTIFICATIONS.md](NOTIFICATIONS.md) |

```powershell
randall agent --port 5000 --token lab-secret   # LAN: http://<ip>:5000 (token required)
randall serve --bind 127.0.0.1     # localhost only
randall notify test -c projects/local/myservice.yaml
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
| **Oracle** — semantic judgment + foresight needs | ✅ [ORACLES.md](ORACLES.md) |
| **Bug Hunter** — AI/robot code analysis + arming | ✅ [BUG_HUNTER.md](BUG_HUNTER.md) |
| **Magician** — spells + summons (knight/army/bots/hunter/joker) | ✅ [MAGICIAN.md](MAGICIAN.md) |
| **Joker** — chaotic random tricks; Magician capitalizes on crashes | ✅ [MAGICIAN.md#joker](MAGICIAN.md#joker) |
| **ReelDeck** — media file target + path-stalk maturity lab | ✅ [REELDECK.md](REELDECK.md) |

**Techniques guide:** [docs/FUZZING.md](FUZZING.md) · Oracle · Magician · Bug Hunter · Joker · ReelDeck file stalk

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

---

## Phase 13 — Night shift (graph + triage) ✅

| Item | Status |
|------|--------|
| **`randall graph`** — validate sessionGraph, export Mermaid | ✅ |
| **`/api/graph`** + doctor sessionGraph checks | ✅ |
| **Crash triage tags** — persisted in index, shown in web UI | ✅ |
| **CI smoke** — lab-smoke campaign on every push | ✅ |
| **`examples/tftp-simple`** | ✅ |

```powershell
randall graph -c projects/vulnftp.yaml
randall doctor -c projects/vulnftp.yaml
```

---

## Phase 14 — Graph editor (web UI) ✅

| Item | Status |
|------|--------|
| **Session graph tab** — Mermaid diagram in web UI | ✅ |
| **Edge table** — mutate target highlighted | ✅ |
| **YAML snippet** — copy to clipboard | ✅ |
| **Lab practice guide** | ✅ `docs/LAB_PRACTICE.md` |

```powershell
dotnet run --project src/Randall.Server
# Open http://127.0.0.1:5000 → Session graph → vulnftp → Load graph
```

---

## Phase 15 — Deep logging ✅

| Item | Status |
|------|--------|
| Execution journal (`iterations.jsonl`, `run.json`) | ✅ |
| Crash sidecars + trace copies | ✅ |
| Pluggable stalk backend IDs | ✅ |

## Phase 16 — Native stalk 🔄

| Item | Status |
|------|--------|
| Edge hit counters / hot spots | ✅ |
| `randall analyze` registers from dump | ✅ |
| Native PC stalk (debug events → drcov) | ✅ coarse — prefer DynamoRIO for full BB |
| Doctor / auto prefer external when present | ✅ |
| **In-process + out-of-process execution modes** | ✅ `fuzz.executionMode` · managed `IInProcessHarness` · native worker (`LLVMFuzzerTestOneInput`) — [IN_PROCESS.md](IN_PROCESS.md) |
| **Persistent mode + fork server (warm worker)** | ✅ `fuzz.persistent` / `fuzz.forkServer` / `harnessStrict` — warm, cold, recycle matrix; harness perf signals — [PERSISTENT.md](PERSISTENT.md) · [HARNESS_DESIGN.md](HARNESS_DESIGN.md) |
| AFL `FORKSRV_FD` native shim (Linux) | ✅ classic 198/199 via `AflForkServer` + `projects/forksrv-demo.yaml` (AFL++ feature negotiation still optional) |
| **AFL++ / honggfuzz campaign adapters** | ✅ `fuzz.engine: aflpp\|honggfuzz` → real `afl-fuzz`/`honggfuzz` run + crash/corpus sync — [ENGINE_ADAPTERS.md](ENGINE_ADAPTERS.md) |

## Phase 17 — Pentest stalker + case builder 🔄

| Item | Status |
|------|--------|
| Layered stalk compare + IDA/Ghidra export | ✅ |
| WinDbg attach / open dump + Scream watcher | ✅ |
| Case builder + Help tab (served docs) | ✅ |
| Procmon bookends (`fuzz.procmonCapture` / UI checkbox) | ✅ |
| TCPVCon network snapshots (`fuzz.tcpvconCapture`) | ✅ |
| ProcDump -e -ma arm (`fuzz.procdumpOnCrash`) | ✅ |
| pktmon ETL bookends (`fuzz.pktmonCapture`) | ✅ |
| tshark pcapng bookends (`fuzz.tsharkCapture`) | ✅ |
| DebugView OutputDebugString (`fuzz.debugViewCapture`) | ✅ |
| Sysinternals snapshots bundle (`fuzz.sysinternalsSnapshots`) | ✅ |
| Remote stalk APIs on `randall agent` | ✅ `/api/remote/procmon` · `/api/remote/tools` |

Custom targets: [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md) · Case builder: [CASE_BUILDER.md](CASE_BUILDER.md)

---

## Phase 18 — Scare Floor Network (app-layer packets) 🔄

**Goal:** Craft and send multi-message TCP/UDP cases from Scare Floor the way you already build file seeds — boofuzz-style app PDUs on sockets first; L2–L4 forge is Phase 24.

| Item | Status | Notes |
|------|--------|-------|
| Network recipe = **session steps** (not only one blob) | ✅ | `CaseSessionStepDto` + recipe JSON |
| Scare Floor UI: add / reorder / mutate-which-step | ✅ | PDU strip + mutate select |
| Preview shows per-step ASCII/hex + wire order | ✅ | `/api/case/preview-session` |
| **Apply to Campaign** → `sessionCommands` / `sessionFlows` | ✅ | `/api/case/apply-session` |
| FTP login flow multi-PDU preset | ✅ | USER → PASS → STOR |
| Import **Proxy capture** → network recipe | ✅ | Proxy → Send to Scare Floor / All C→S |
| Import hex/pcap **application payload** (TCP stream) | ✅ | Import as session / `from-stream` (not full pcap) |
| More network presets (SMTP, Redis RESP, custom binary) | ✅ | SMTP + Redis multi-PDU flows |
| expectResponse per PDU | ✅ | Written on Apply |
| Docs: “fuzz a remote TCP service from Scare Floor” | ✅ | CASE_BUILDER |

**Not in this phase (comes later):** Ethernet/IP/TCP-flag crafting and raw sockets — see Phase 24 (in-house packet forge). Phase 18 stays app-PDU on connected sockets so network Scare Floor ships sooner.

**Try shape (target UX):**
```
Scare Floor → kind: tcp → host:port
  Step 1: banner read (optional)
  Step 2: static "USER " + fuzzable name + CRLF
  Step 3: static "PASS " + fuzzable pass + CRLF
  Step 4: fuzzable command body
→ Save recipe → Campaign
```

---

## Phase 19 — Wire Scare Floor ↔ sessions/models 🔄

**Goal:** Scare Floor stops being “seed-only”; it authors the same YAML the engine already runs.

| Item | Status | Notes |
|------|--------|-------|
| Save recipe → `sessionFlows` / `sessionCommands` | ✅ | Apply to Campaign |
| Visual sessionGraph edges from UI (edit, not just view) | ✅ | Session graph → Save graph |
| `expectResponse` per step in Scare Floor | ✅ | PDU expect field |
| Promote step fields → `projects/protocols/*.yaml` model | ✅ | Promote PDU + Prefer models |
| Dictionary harvest across session steps | ✅ | Tokens from fuzzable fields |
| `randall case from-stream` / `apply-session` CLI | ✅ | + `promote` / `packs` |

---

## Phase 20 — Protocol packs (useful before SMB) ✅

**Goal:** Ship reusable PDU packs so users aren’t hand-hexing common services.

| Item | Status | Notes |
|------|--------|-------|
| Pack format: recipe + protocol YAML | ✅ | `projects/protocols/packs/` |
| HTTP/1.1 request pack | ✅ | `packs/http-get` |
| FTP full login → STOR flow pack | ✅ | `packs/ftp-login` |
| Generic **TLV / length-prefixed** pack | ✅ | `packs/tlv-frame` |
| DNS / mDNS UDP query pack (lab) | ✅ | `packs/dns-query` + UDP Apply (1 PDU) |
| Import boofuzz example → Scare Floor recipe | ✅ | `import-boofuzz.py --recipe` / `--pack` |
| Community: “custom protocol” wizard | ✅ | Scare Floor: magic + len + body + CRC32 |

---

## Phase 21 — RPC / DCE-RPC (first real hard protocol) ✅

**Goal:** Fuzz RPC-shaped services without pretending we have full IDL/NDR yet.

| Item | Status | Notes |
|------|--------|-------|
| DCE/RPC **bind** + **request** framing model | ✅ | `dce_bind.yaml` / `dce_request.yaml` |
| NDR stub as hex + sized fields (manual IDL) | ✅ | Stub `bytes` + opnum/call_id fields |
| Optional: parse simple IDL → stub field map | ✅ | `randall case idl` / Scare Floor IDL panel |
| Session: bind → alter_context? → request* | ✅ | bind → request (`sessionFlows` + pack) |
| Lab: tiny RPC stub server (crashable opnum) | ✅ | VulnRpc :1355 / `projects/vulnrpc.yaml` |
| Docs: “fuzz RPC with a known stub layout” | ✅ | `docs/RPC_LAB.md` |

**Honest limit:** Full Windows RPC + auth + complex NDR is months; start with **unauthenticated lab stub + known opnum layouts**.

---

## Phase 22 — SMB (session-aware, lab-first) ✅

**Goal:** Real SMB fuzzing path for lab VMs — negotiate → session → tree → command — not “hex dump at 445”.

| Item | Status | Notes |
|------|--------|-------|
| NetBIOS session service (NBT) framing | ✅ | NBSS prefix on SMB2 lab PDUs |
| SMB2 **Negotiate** + **Session Setup** (null/guest lab) | ✅ | `smb2_negotiate` / `smb2_session_setup` |
| Tree Connect + Create + Read/Write models | ✅ | `smb2_tree_connect` / create / read / write |
| sessionGraph: response status → next command | ✅ | `vulnsmb.yaml` ASCII status edges |
| Lab target guidance (vulnerable SMB in VM) | ✅ | VulnSmb :4455 + `docs/SMB_LAB.md` |
| Crash signal: TCP reset / process death / agent | ✅ | longLived process death (existing) |
| Optional: named-pipe → DCERPC reuse (Phase 21) | ✅ | pack `smb-pipe-dce` + VulnSmb Write→DCE |

**Honest limit:** Production SMB + signing + modern auth is a research product of its own. Phase 22 targets **lab parsers / legacy / intentionally weak services**.

---

## Phase 23 — Layered PDU builder (Scapy workflow, Randall-owned) ✅

**Goal:** In-house layered crafting for **application stacks** first — same mental model as Scapy (`A / B / C`), implemented in Scare Floor + YAML, not a Python sidecar.

| Item | Status | Notes |
|------|--------|-------|
| Layered PDU builder in Scare Floor | ✅ | Layers panel; flattens on Preview/Apply |
| Field table edit (name, type, endian, fuzzable) | ✅ | Field table view toggle |
| Stack templates (“SMB2 write”, “RPC request”) | ✅ | NBSS/SMB2, NBSS/SMB2/DCE, TLV |
| Recipe JSON as interchange (CLI + UI + optional scripts) | ✅ | `layers` on sessionSteps in recipe.json |
| Autocalc length/checksum across layers | ✅ | `len-prefix` `nbss`/`u24be-rest` + `crc32` |

```
Phase 23:     TCP socket  / NBSS / SMB2 / fields
Phase 24:     Ether / IP / TCP / …   (raw / pcap path)
```

Users should **not** need Scapy for normal Randfuzz work. Scapy remains an optional *interop* target (import/export), never a required dependency.

---

## Phase 24 — Packet forge (in-house L2–L4) 🔲

**Goal:** Own the Scapy-class surface inside Randfuzz — craft and send below the app stream when you need it (malformed TCP, IP options, VLAN, fuzzing parsers that sit under the socket).

| Item | Status | Notes |
|------|--------|-------|
| Layer model: Ether / VLAN / IP / IPv6 / TCP / UDP / ICMP | 🔲 | Field-aware + fuzzable |
| Build → bytes → mutate → rebuild (len/checksum fixups) | 🔲 | Core forge engine |
| Send paths: raw socket / pcap inject (Win + Linux) | 🔲 | Platform adapters; privilege-aware |
| Capture → dissect → Scare Floor layers | 🔲 | Round-trip with Proxy / pcap |
| TCP stream mode vs packet mode in Campaign | 🔲 | Same recipe language, different transport |
| Safety defaults | 🔲 | Lab-only warnings; no “scan internet” presets |
| Docs + lab: fuzz a userspace packet parser | 🔲 | Safer than attacking live stacks first |

**Why later:** Phases 18–22 make SMB/RPC *useful* on normal sockets. Phase 24 is the big platform bite (privileges, OS APIs, checksums, fragmentation). Still a **first-class product goal**, not “use Scapy instead.”

**Interop (optional, never required):** import a Scapy packet / hex dump into Randall layers; export Randall layers as hex/pcap for other tools.

---

## Phase 25 — Product maturity (serious indie → market-ready) 🔄

**Goal:** Close the “still lab” gaps without abandoning the Randall niche. Full write-up: [MATURITY.md](MATURITY.md).

| Item | Status | Notes |
|------|--------|-------|
| Maturity doc (honest unfinished map) | ✅ | [MATURITY.md](MATURITY.md) |
| Attribution confidence tiers + capped style scores | ✅ | Bug Hunter reports |
| Optional agent/serve shared-secret token | ✅ | `RANDALL_AGENT_TOKEN` / `--token` · [LAB_AGENT.md](LAB_AGENT.md) |
| Require token when bind ≠ loopback | ✅ | Refuse LAN bind; `--allow-open` escape |
| Win/Linux platform policy (no fake AFL++ port) | ✅ | [MATURITY.md](MATURITY.md)#6 |
| ReelDeck builders on Win + Linux | ✅ | `build-reeldeck.ps1` / `.sh` · [REELDECK.md](REELDECK.md) |
| In-repo file-text / file-framed parsers | ✅ | `targets/file-*` + builders |
| Bake-off scaffold (BENCHMARKS + script) | ✅ | [BENCHMARKS.md](BENCHMARKS.md) — fill numbers |
| Bake-off sample SUMMARY | ✅ | [bench-samples/SAMPLE_SUMMARY.md](bench-samples/SAMPLE_SUMMARY.md) (short budget) |
| Published quiet-box bake-off numbers | 🔲 | Longer BUDGET + edges/exec/s |
| Signed / versioned release packaging | 🔲 | Beyond portable folder |
| Multi-tenant / SaaS | 🔲 | Out of scope for single-box lab shape |
| Linux coverage without DynamoRIO | 🔲 | SanCov / perf (see STALKING) |

### Priority order (recommended)

1. Honesty in-product (this phase’s ✅ rows)
2. LAN token required ✅
3. Out-of-box file demos ✅
4. Bake-off scaffold ✅ → publish numbers
5. Grow automated tests
6. Release packaging cadence (tags + zips)
7. **Do not** port AFL++/forksrv to Windows — adapters stay Linux---

### Earlier phases — priority context

1. **Phase 18** — highest leverage (Scare Floor already exists; sessions already exist in YAML)
2. **Phase 19** — glue so UI authors what the engine runs
3. **Phase 20** — packs make demos/teaching fast ✅
4. **Phase 21** — RPC before SMB (smaller state machine; reusable under SMB pipes) ✅
5. **Phase 22** — SMB lab path ✅
6. **Phase 23** — layered app-PDU UX (Scapy workflow, our stack) ✅
7. **Phase 24** — in-house L2–L4 packet forge
8. **Phase 25** — product maturity ([MATURITY.md](MATURITY.md)) 🔄
9. **Target Runtime** ✅ — local/remote lifecycle, tubes, postStart, Page Heap, memory/heap lens; see [TARGET_RUNTIME.md](TARGET_RUNTIME.md)

### Near-term caution (not “never”)

These are **deferred product goals**, not permanent non-goals:

| Deferred | Why wait | Still in-house? |
|----------|----------|-----------------|
| L2–L4 forge (Phase 24) | Needs Phases 18–23 foundations + OS send/capture | **Yes** |
| Kerberos / NTLM / signing-heavy SMB | Huge auth surface after basic SMB PDUs work | **Yes**, lab-scoped |
| Internet-facing “scan SMB” UX | Safety / product ethics — lab + explicit target only | Features stay lab-oriented |
| Linux Scream/WinDbg parity | Separate stalk/scream track | **Yes**, when we port backends |

**Policy:** Prefer Randall-native builders and transports. External tools (Scapy, Wireshark, Impacket) are for *optional import/compare*, not the primary workflow.

Related: [BOOFUZZ_PARITY.md](BOOFUZZ_PARITY.md) · [MODEL.md](MODEL.md) · [CASE_BUILDER.md](CASE_BUILDER.md) · [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md) · [TARGET_RUNTIME.md](TARGET_RUNTIME.md) · [LAB_AGENT.md](LAB_AGENT.md)
