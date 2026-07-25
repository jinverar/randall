# Intelligence Loop — living roadmap

Randfuzz’s long-term bet: **Randall thinks** — structure, oracles, triage, and RE context drive what to run next. External engines and tools are **sensors and workers**, not the product identity.

| Role | Examples | What Randall owns |
|------|----------|-------------------|
| **Sensors** | DynamoRIO drcov, corpus novelty, sanitizer hints, Ghidra static map, WinDbg/cdb triage | Normalize into observations, scores, and priorities |
| **Workers** | AFL++/honggfuzz adapters, headless Ghidra analyze, BinExport/BinDiff companions, GhidraMCP | Run when asked; soft-fail when offline |
| **Brain** | Oracle engine, frontier scoring, mutator credit, scream intelligence, stalk map | Decide *what is interesting* and *what to try next* |

This doc tracks the **Intelligence Loop** specifically. Feature-phase history (lab targets, Scare Floor, SMB, …) lives in [ROADMAP.md](ROADMAP.md). Honest product tiers: [MATURITY.md](MATURITY.md).

---

## Four layers (who judges vs who acts)

Randfuzz separates **judgment** from **intervention** so the loop stays explainable:

| Layer | Role | Acts on target? | Primary artifact |
|-------|------|-----------------|------------------|
| **Brain** | Fuses frontier, static map, oracle/scream signals → `NextHuntDecision` (seed/mutator/energy pin) | Indirect (bias only) | `brain_last.json` · mutator credit · chains |
| **Oracle** | Judges each run → findings + `OracleNeedDto` | **No** — requests help only | `oracle_findings.jsonl` |
| **Magician** | Casts spells / summons when Oracle needs intervention; `playJokerCard` queues deck draws | **Yes** (campaign knobs) | `crashes/_magician/spells.jsonl` |
| **Joker** | Exploration pressure — chaotic tricks + **70/20/10** deck (chaos/remix/replay) against over-exploitation | **Yes** (iteration hijack) | `joker_deck.json` · `joker_watch.jsonl` |

**Closed loop:** Oracle need → Magician spell → feedback (scream / edges / Scare Door pressure) → Brain credit + chain learning + Joker card scoring.

### Three timescales

| Timescale | What updates | Examples |
|-----------|--------------|----------|
| **Per iteration** | Oracle eval, Joker trick, Magician auto-cast, Scare Door progress tick | Oracle score, door pressure, deck draw |
| **Per campaign** | Mutator credit, A→B→C chains, brain last decision, joker deck | `mutator_credit.txt`, `mutator_chains.json` |
| **Per target (binary)** | Brain memory fingerprint — 61% retention when executable hash changes | `brain_memory.json`, scaled credit/chains/frontier |

See [ORACLES.md](ORACLES.md) · [MAGICIAN.md](MAGICIAN.md) · [FUZZING.md](FUZZING.md#brain-randall-thinks).

---

## Vision

```text
Target + seeds
      ↓
Execute (Randfuzz engine · optional AFL++/DR worker)
      ↓
Observe → score → rank (coverage · path · oracle · crash · static map)
      ↓
Decide → corpus energy · mutator bias · frontier nudges · oracle needs
      ↓
Triage scream → Investigation · canisters · RE handoff (Ghidra / WinDbg)
      ↓
Revise seeds / rules / dictionary → repeat
```

**Thesis:** exec/s throughput is a commodity. Value is *judgment under uncertainty* — logic/auth/state bugs that never crash, crash clusters that matter, and gray doors worth opening before you live in Ghidra.

---

## Already shipped (high level)

These are **real today**, not slideware. Depth varies; see linked docs for limits.

| Area | Shipped | Notes |
|------|---------|-------|
| **Oracle stack** | Runtime, invariant, auth, state, structure, resource, differential, metamorphic rules | [ORACLES.md](ORACLES.md) · `OracleEngine` + findings JSONL |
| **OracleScore** | Explainable 0–100 score on iterations and crashes | `OracleScorer` · sidecar `RandallScore` · crash fallback |
| **Observation bus** | Unified event shape per fuzz run | `ObservationBus` + `ObservationEvents` in `FuzzEngine` |
| **Ghidra static map v2** | Headless analyze → `randall-analysis.json`; v2 priority overlays drcov on CFG BBs; full call graph + source→sink paths | `stalk ghidra-analyze` · optional `fuzz.ghidraStaticBias` |
| **RIP / fault PC map** | Crash PC → function + offset (Ghidra map or PE heuristics) | [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) · Investigation one-liner |
| **Stalk map (in-Randall RE)** | PE/ELF strings, imports, hotspots on missed blocks | [STALK_MAP.md](STALK_MAP.md) — proximity, not full CFG |
| **Frontier (gray doors)** | CFG/session fork scoring → `frontier.json` | `FrontierEngine` · `stalk frontier` |
| **Mutator credit** | Bandit-lite productive-mutator bias + persistence | `MutatorCreditTracker` · `fuzz.mutatorCredit` (default on) |
| **Joker Card deck** | 70/20/10 chaos/remix/replay recipe credit | `JokerCardDeck` · `joker.deckEnabled` · [MAGICIAN.md#joker](MAGICIAN.md#joker) |
| **RandallBrain** | Closed-loop seed/mutator/energy fusion | `RandallBrain` · `fuzz.brain` (default on) · `GET /api/fuzz/brain` · `decision` alias (`inputId`/`score`/`reasons`/`actions`) |
| **Scream Intelligence** | `CrashIntelligenceDto`, ScreamScore, novelty, lineage stub | [SCREAM_INTELLIGENCE.md](SCREAM_INTELLIGENCE.md) · Crashes / Investigation API |
| **Scream canisters** | Mood thresholds, EIP/RIP seal, harvest rack | UI Crashes tab · [canisters README](assets/canisters/README.md) |
| **Ghidra export + pack** | Script Manager importers, stalk layers, crash packs | [GHIDRA_INTEGRATION.md](GHIDRA_INTEGRATION.md) |
| **GhidraMCP (optional)** | Live import/caller queries from CLI; soft-fail offline | `randall ghidra mcp` · `oracles --mcp-import` |
| **BinDiff helpers** | JSON merge diff without BinDiff binary; BinExport path when installed | `stalk ghidra-diff` · `GhidraAnalysisDiff` |
| **WinDbg / cdb triage** | Auto `!analyze`, msec when present, symbol path defaults | [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) · [WINDBG_FUZZ_PKG.md](WINDBG_FUZZ_PKG.md) |
| **Differential oracle** | Reference executable compare (soft-skip missing ref) | YAML `oracles.differential` |
| **Engine adapters** | AFL++/honggfuzz as optional Linux grinders | [ENGINE_ADAPTERS.md](ENGINE_ADAPTERS.md) |
| **External worker ingest** | `IExternalWorkerIngest` stub for LibAFL/WinAFL companions | [EXTERNAL_WORKERS.md](EXTERNAL_WORKERS.md) |
| **FaultSignal taxonomy** | CrashTriage + cdb + Page Heap + sanitizer → unified DTO | [FAULT_SIGNALS.md](FAULT_SIGNALS.md) |
| **RPP plugins** | mutate · post_receive · post_crash · **observe** hooks | [RPP.md](RPP.md) |

---

## Phase 1 — Observation + OracleScore ✅ foundation

**Goal:** Every iteration emits comparable signals; interestingness is explainable, not a black box.

| Item | Status | Notes |
|------|--------|-------|
| `Observation` + `ObservationBus` | ✅ | Coverage, path, crash, oracle, Ghidra hint kinds |
| `OracleScorer` formula | ✅ | Documented terms; unit tests |
| Sidecar `RandallScore` on new crashes | ✅ | Synthesized at read time when missing |
| Findings → corpus retain / energy | ✅ | `retainOnViolation` / near-miss |
| Live observation stream in UI | 🔲 | Bus exists; SignalR surfacing still thin |
| Full mutator lineage from journal replay | ✅ | `CrashLineageResolver` walks `iterations.jsonl` via `parentInputHash` |

**Done when:** Investigation and Fuzz tabs show a per-run observation timeline; lineage is journal-backed, not sidecar-only.

---

## Phase 2 — Ghidra map provider (bridge maturation) ✅ capable

**Goal:** Mature the Ghidra static map as Randall’s primary RE sensor — full call graph, coverage-painted gaps as oracle “unopened doors”, fused canister context, live MCP path questions, and patch-hunt bias.

| Item | Status | Notes |
|------|--------|-------|
| Full call graph + v2 CFG in `randall-analysis.json` | ✅ | `RandfuzzExportAnalysis.py` exports all call edges + BB successors/predecessors; `GhidraCallGraphHelper` merges xrefs |
| Coverage overlay → Oracle “unopened doors” | ✅ | `GhidraAnalysisOracleHints.UnopenedDoorsSummary` fuses coverage gaps + `frontier.json` gray doors |
| Crash canister = RIP + function + oracle + frontier | ✅ | `CrashIntelligenceDto.CanisterContext` · `FrontierHint` · list API `canisterContext` |
| GhidraMCP deeper Oracle questions | ✅ | `oracles --mcp-path recv:memcpy` · `GhidraMcpClient.TryTraceInputToSinkPathAsync` |
| Patch-hunt `changedFunctions[]` first-class | ✅ | Oracle/brain/static bias · `stalk ghidra-diff` merge · Scare Floor `patch` targets |
| Source→sink static paths | ✅ | `SourceSinkPathScorer` · persisted `sourceSinkPaths[]` on enrich |

**Done when:** Scare Floor brain + Investigation show unopened doors and patch deltas without re-export; canister tooltips carry full static+frontier context.

---

## Phase 2 — Frontier (gray doors) ✅ capable

**Goal:** Rank *unexplored* branches and session forks so seeds and campaigns bias toward high-ROI gaps.

| Item | Status | Notes |
|------|--------|-------|
| `FrontierEngine` + `frontier.json` | ✅ | CFG branches, session forks, edge-gap fallback |
| CLI `stalk frontier` + API | ✅ | Persists under `data/stalk/<project>/` |
| Ghidra CFG + coverage overlay input | ✅ | Needs `randall-analysis.json` for best scores |
| Auto seed/dictionary nudge from top frontiers | ✅ | `RandallBrain` closed-loop picker; **rich `frontier.json`** (+5…+15 score boost, corpus bias up to ~88%) |
| Frontier-aware corpus energy in `FuzzEngine` | ✅ | Brain + `ghidraStaticBias` energy boosts |

**Done when:** Top-N frontiers automatically boost related dictionary tokens or Scare Floor suggestions after each stalk layer.

---

## Phase 3 — Mutation credit ✅ capable

**Goal:** Productive mutators earn selection weight; dead ends fade without manual YAML edits.

| Item | Status | Notes |
|------|--------|-------|
| `MutatorCreditTracker` | ✅ | edges×10 + uniqueCrash×100; weighted pick |
| Per-run + cumulative persistence | ✅ | `data/runs/` + corpus dir |
| YAML toggle `fuzz.mutatorCredit` | ✅ | Default on |
| Credit visible in UI / run summary | ✅ | Scare Floor command strip + mutator chips in brain foot |
| RPP `observe` hook feeding credit | 🔲 | Observe hook ships; credit wiring pending |

**Done when:** Run summary and doctor show mutator leaderboard; RPP observers can add custom credit signals.

---

## Phase 4 — Sensors & workers ✅ capable

**Goal:** Normalize crash/sanitizer/Page Heap/WER sensors into comparable fault rows; external grinders and RPP observers feed the observation bus.

| Item | Status | Notes |
|------|--------|-------|
| `FaultSignal` + `FaultSignalMapper` | ✅ | Kind / Confidence / Severity / Source |
| Crash intelligence + FINDINGS surface | ✅ | `PrimaryFault`, `FaultSignals`, oracle `Fault` |
| Observation bus `Fault` kind | ✅ | Published on crash + RPP observe |
| RPP `observe` hook + example plugin | ✅ | `plugins/edge-observer` |
| External worker ingest stub | ✅ | `IExternalWorkerIngest` · [EXTERNAL_WORKERS.md](EXTERNAL_WORKERS.md) |
| AFL++/LibAFL/WinAFL worker docs | ✅ | LibAFL/WinAFL companions documented, not ported |
| SanitizerCoverage YAML stub | ✅ | `fuzz.sanitizerCoverage` · [SANITIZER_COVERAGE.md](SANITIZER_COVERAGE.md) |
| Live sancov bitmap ingest | 🔲 | drcov remains default when DynamoRIO present |
| Streaming AFL++ observations during campaign | 🔲 | Post-run sync only today |

**Done when:** sancov edges merge with drcov on the bus; external workers stream observations live without waiting for campaign exit.

---

## Phase 5 — Scream Intelligence ✅ capable

**Goal:** Crashes sort by *story* — severity, novelty, oracle, cluster, static context — not just timestamp.

| Item | Status | Notes |
|------|--------|-------|
| `CrashIntelligenceBuilder` + `ScreamScore` | ✅ | Unified rank for list / canister / Investigation |
| API fields on `/api/crashes` | ✅ | `screamScore`, `novelty`, `oracleScoreTotal` |
| Investigation “Scream intelligence” panel | ✅ | Purple highlight when hot |
| Canister mood + EIP/RIP seal | ✅ | Harvest rack on by default |
| Minimization + reproducibility flags | ✅ | Cluster-shortest input heuristic |
| Journal-backed mutator lineage in Investigation | ✅ | `CrashLineageResolver` · seed + parent hash in panel |
| ScreamScore drives fuzz stop / campaign goals | 🔲 | Sorting only today; brain uses novelty for hunt bias ✅ |

**Done when:** Campaign YAML can target “N unique screams above score S” and auto-prioritize replay/minimize for top clusters.

---

## Phase 6 — Target Intelligence + mature RE pipe 🔄 active

**Goal:** One target profile accumulates static map, runtime observations, crash history, and patch deltas — Scare Floor and oracles consume it without re-exporting.

| Item | Status | Notes |
|------|--------|-------|
| Ghidra map v2 priority + static bias | ✅ | Sink × complexity × uncovered distance · patch-hunt boost |
| RIP → function + offset on crashes | ✅ | Ghidra map preferred, PE fallback · canister context fuse |
| GhidraMCP live queries | ✅ Capable | `--mcp-import` · `--mcp-path recv:memcpy` |
| BinDiff / JSON merge diff | ✅ Capable | `stalk ghidra-diff`; `changedFunctions[]` in oracle/brain/bias |
| Differential fuzz (oracle + ref harness) | ✅ Capable | Not full binary diff fuzzing |
| Scare Floor UX → session/model promotion | ✅ | Phases 18–19 in [ROADMAP.md](ROADMAP.md) |
| **Source→sink path scoring** (SaTC-style static) | ✅ Capable | `SourceSinkPathScorer` in Oracle hints + static bonus; BFS on call graph |
| **TraceRMI / debugger RIP annotate CLI** | ✅ Capable (stub) | `ghidra mcp crash` · decompile + debugger translate soft-fail · [GHIDRA_DEBUGGER.md](GHIDRA_DEBUGGER.md) |
| **RE companions docs** (GhidrAssist, Class Analyzer) | ✅ | [GHIDRA_RE_COMPANIONS.md](GHIDRA_RE_COMPANIONS.md) · `install-ghidra-re-companions.ps1` |
| **RPP community README** | ✅ | [plugins/README.md](../plugins/README.md) · CONTRIBUTING hook table |
| **Target Intelligence** profile (unified DTO + API) | ✅ | `target_intelligence.json` · `stalk intel` · `/api/stalking/{p}/target-intelligence` |
| Scare Floor command center (status strip + Why?) | ✅ | Coverage % · frontiers · canister moods · patch `changedFunctions` |
| Differential fuzz YAML/UI surfacing | ✅ | `oracles.differential` badge + `stalk intel` ref check · [ORACLES.md](ORACLES.md) |
| Ghidra map → auto oracle rule suggestions | 🔲 | CLI hints only |
| Crash-RIP → full decompiled context (MCP) | 🔲 | Snippet-only CLI today; not Investigation panel embed |
| RPP `observe` + Target Intelligence write-back | ✅ | Observe → bus + counters; auto-refresh on fuzz/frontier/oracle · `hunt_journal.jsonl` |
| Closed loop: frontier → Scare Floor → re-fuzz | ✅ Capable | `RandallBrain` steers seed/mutator/energy; `GET /api/fuzz/brain` |

**Done when:** `GET /api/stalking/{project}/target-intelligence` returns a merged profile (static, frontier, oracle history, top screams); one-click “bias campaign from frontier” from UI.

(FaultSignal taxonomy and bus publish — see **Phase 4 — Sensors & workers**.)

---

## Explicit non-goals

We will **not** optimize Randfuzz to win AFL++ exec/s bake-offs. Adapters exist for when you need raw throughput; they are not the identity.

| Non-goal | Why |
|----------|-----|
| Chase AFL++/libFuzzer exec/s leadership | Commodity; our niche is judgment + sessions + triage UX |
| Replace Ghidra / IDA as the RE workbench | We export, score, and hand off — not a decompiler product |
| Require Ghidra, BinDiff, or MCP to fuzz | All RE integrations soft-fail; YAML fuzz runs offline |
| Automatic exploit generation | Stops at offsets, mitigations, ROP *sketches* — [EXPLOIT_GUIDE.md](EXPLOIT_GUIDE.md) |
| Port AFL++ / FORKSRV to Windows as default | Linux adapters only; Windows uses Randfuzz engine + warm workers |
| Multi-tenant SaaS | Single-box lab tool; see [MATURITY.md](MATURITY.md) |

---

## How this relates to other docs

| Doc | Relationship |
|-----|----------------|
| [ROADMAP.md](ROADMAP.md) | Shipped feature phases (1–25); lab protocols, Scare Floor, maturity |
| [MATURITY.md](MATURITY.md) | Tier honesty (Solid / Capable / Lab / Missing) |
| [ORACLES.md](ORACLES.md) | Oracle rule types + static map pipe |
| [STALK_LOOP.md](STALK_LOOP.md) | Operator checklist for baseline → fuzz → learn |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Layer diagram and deployment |

**Living doc:** update this file when Intelligence Loop milestones ship or scope changes. Web UI Roadmap tab (`GET /api/roadmap`) tracks the broader phase list, not this loop-specific map.

---

## Operator 10-minute hunt

Windows one-shot script that walks the Intelligence Loop on a stock lab target (~10 minutes with Ghidra headless; faster without).

| Step | What it does | Soft-fail |
|------|----------------|-------------|
| Build | `file-text` (default) via `build-file-text.ps1`, or `harness-demo` DLL | Missing gcc / prior binary |
| Static map | `randall stalk ghidra-analyze` when `tools/ghidra-app` or `GHIDRA_INSTALL_DIR` is present | Skip + manual export path |
| Fuzz | 50 iterations, `fuzz.brain` default on; `--debugger wait` (Scream) for native `file-text` | Doctor/binary issues |
| Frontier | `randall stalk frontier -p <project>` | Empty without DynamoRIO layers |
| Intel | `randall stalk intel -p <project> --refresh` | Thin profile until artifacts exist |

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo-intelligence-hunt.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\demo-intelligence-hunt.ps1 -Project harness-demo -SkipBuild
```

**Next:** `dotnet run --project src\Randall.Server --urls http://127.0.0.1:5000` → **Fuzz → Scare Floor** → **Brain** panel + **Scare Doors** (frontier). API: `GET /api/fuzz/brain?project=<name>`.

Related: [STALK_LOOP.md](STALK_LOOP.md) · [FUZZING.md](FUZZING.md#randallbrain-closed-loop-hunt-steering) · [GHIDRA_INTEGRATION.md](GHIDRA_INTEGRATION.md).

---

## Verified (Windows E2E — 2026-07-25)

Smoke on `main` @ `39a4e27` (Release build, 231/231 tests after maturation fixes):

| Surface | Command / endpoint | Result |
|---------|-------------------|--------|
| CLI doctor | `doctor -c projects/harness-demo.yaml` | OK — in-process harness ready |
| CLI frontier | `stalk frontier -p harness-demo` | OK — empty mode, persists `frontier.json` |
| CLI intel | `stalk intel -p harness-demo --refresh` | OK — writes `target_intelligence.json` |
| CLI oracles | `oracles -p harness-demo` | OK — no findings (oracles off) |
| CLI fuzz | `fuzz … --max-iterations 20` (harness-demo + file-text) | OK — 20 iters each, no crash |
| CLI ghidra-analyze | `stalk ghidra-analyze -p file-text -c …` | Soft-fail — clear Ghidra-missing + manual export path |
| Server | `GET /api/stalking/{p}/intelligence`, `/target-intelligence`, `/api/crashes` | OK on current build (port 5001); stale server on :5000 may 404 new routes |
| file-text lab | `scripts/build-file-text.ps1` + doctor | OK — native `app.exe` resolves |

**Honest gaps on stock Windows lab:** DynamoRIO/Ghidra not installed → frontier stays empty, static map unavailable; corpus-novelty / path-coverage only until DR layers exist. Intelligence loop **consumes** artifacts correctly; producing Ghidra map + BB coverage remains operator/setup work.
