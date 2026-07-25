# Intelligence Loop — living roadmap

Randfuzz’s long-term bet: **Randall thinks** — structure, oracles, triage, and RE context drive what to run next. External engines and tools are **sensors and workers**, not the product identity.

| Role | Examples | What Randall owns |
|------|----------|-------------------|
| **Sensors** | DynamoRIO drcov, corpus novelty, sanitizer hints, Ghidra static map, WinDbg/cdb triage | Normalize into observations, scores, and priorities |
| **Workers** | AFL++/honggfuzz adapters, headless Ghidra analyze, BinExport/BinDiff companions, GhidraMCP | Run when asked; soft-fail when offline |
| **Brain** | Oracle engine, frontier scoring, mutator credit, scream intelligence, stalk map | Decide *what is interesting* and *what to try next* |

This doc tracks the **Intelligence Loop** specifically. Feature-phase history (lab targets, Scare Floor, SMB, …) lives in [ROADMAP.md](ROADMAP.md). Honest product tiers: [MATURITY.md](MATURITY.md).

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
| **Ghidra static map v2** | Headless analyze → `randall-analysis.json`; v2 priority overlays drcov on CFG BBs | `stalk ghidra-analyze` · optional `fuzz.ghidraStaticBias` |
| **RIP / fault PC map** | Crash PC → function + offset (Ghidra map or PE heuristics) | [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) · Investigation one-liner |
| **Stalk map (in-Randall RE)** | PE/ELF strings, imports, hotspots on missed blocks | [STALK_MAP.md](STALK_MAP.md) — proximity, not full CFG |
| **Frontier (gray doors)** | CFG/session fork scoring → `frontier.json` | `FrontierEngine` · `stalk frontier` |
| **Mutator credit** | Bandit-lite productive-mutator bias + persistence | `MutatorCreditTracker` · `fuzz.mutatorCredit` (default on) |
| **Scream Intelligence** | `CrashIntelligenceDto`, ScreamScore, novelty, lineage stub | [SCREAM_INTELLIGENCE.md](SCREAM_INTELLIGENCE.md) · Crashes / Investigation API |
| **Scream canisters** | Mood thresholds, EIP/RIP seal, harvest rack | UI Crashes tab · [canisters README](assets/canisters/README.md) |
| **Ghidra export + pack** | Script Manager importers, stalk layers, crash packs | [GHIDRA_INTEGRATION.md](GHIDRA_INTEGRATION.md) |
| **GhidraMCP (optional)** | Live import/caller queries from CLI; soft-fail offline | `randall ghidra mcp` · `oracles --mcp-import` |
| **BinDiff helpers** | JSON merge diff without BinDiff binary; BinExport path when installed | `stalk ghidra-diff` · `GhidraAnalysisDiff` |
| **WinDbg / cdb triage** | Auto `!analyze`, msec when present, symbol path defaults | [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) · [WINDBG_FUZZ_PKG.md](WINDBG_FUZZ_PKG.md) |
| **Differential oracle** | Reference executable compare (soft-skip missing ref) | YAML `oracles.differential` |
| **Engine adapters** | AFL++/honggfuzz as optional Linux grinders | [ENGINE_ADAPTERS.md](ENGINE_ADAPTERS.md) |
| **RPP plugins** | mutate · post_receive · post_crash hooks | [RPP.md](RPP.md) — `observe` hook planned |

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
| Full mutator lineage from journal replay | 🔲 | Sidecar chain is `Partial: true` today |

**Done when:** Investigation and Fuzz tabs show a per-run observation timeline; lineage is journal-backed, not sidecar-only.

---

## Phase 2 — Frontier (gray doors) ✅ capable

**Goal:** Rank *unexplored* branches and session forks so seeds and campaigns bias toward high-ROI gaps.

| Item | Status | Notes |
|------|--------|-------|
| `FrontierEngine` + `frontier.json` | ✅ | CFG branches, session forks, edge-gap fallback |
| CLI `stalk frontier` + API | ✅ | Persists under `data/stalk/<project>/` |
| Ghidra CFG + coverage overlay input | ✅ | Needs `randall-analysis.json` for best scores |
| Auto seed/dictionary nudge from top frontiers | 🔲 | Hint text today; closed loop pending |
| Frontier-aware corpus energy in `FuzzEngine` | 🔲 | Complements `ghidraStaticBias` |

**Done when:** Top-N frontiers automatically boost related dictionary tokens or Scare Floor suggestions after each stalk layer.

---

## Phase 3 — Mutation credit ✅ capable

**Goal:** Productive mutators earn selection weight; dead ends fade without manual YAML edits.

| Item | Status | Notes |
|------|--------|-------|
| `MutatorCreditTracker` | ✅ | edges×10 + uniqueCrash×100; weighted pick |
| Per-run + cumulative persistence | ✅ | `data/runs/` + corpus dir |
| YAML toggle `fuzz.mutatorCredit` | ✅ | Default on |
| Credit visible in UI / run summary | 🔲 | JSON exists; Fuzz tab surfacing thin |
| RPP `observe` hook feeding credit | 🔲 | [RPP.md](RPP.md) — planned |

**Done when:** Run summary and doctor show mutator leaderboard; optional RPP observers can add custom credit signals.

---

## Phase 4 — Scream Intelligence ✅ capable

**Goal:** Crashes sort by *story* — severity, novelty, oracle, cluster, static context — not just timestamp.

| Item | Status | Notes |
|------|--------|-------|
| `CrashIntelligenceBuilder` + `ScreamScore` | ✅ | Unified rank for list / canister / Investigation |
| API fields on `/api/crashes` | ✅ | `screamScore`, `novelty`, `oracleScoreTotal` |
| Investigation “Scream intelligence” panel | ✅ | Purple highlight when hot |
| Canister mood + EIP/RIP seal | ✅ | Harvest rack on by default |
| Minimization + reproducibility flags | ✅ | Cluster-shortest input heuristic |
| ScreamScore drives fuzz stop / campaign goals | 🔲 | Sorting only today |

**Done when:** Campaign YAML can target “N unique screams above score S” and auto-prioritize replay/minimize for top clusters.

---

## Phase 5 — Target Intelligence + mature RE pipe 🔄 active

**Goal:** One target profile accumulates static map, runtime observations, crash history, and patch deltas — Scare Floor and oracles consume it without re-exporting.

| Item | Status | Notes |
|------|--------|-------|
| Ghidra map v2 priority + static bias | ✅ | Sink × complexity × uncovered distance |
| RIP → function + offset on crashes | ✅ | Ghidra map preferred, PE fallback |
| GhidraMCP live queries | ✅ Capable | Optional; offline soft-fail |
| BinDiff / JSON merge diff | ✅ Capable | `stalk ghidra-diff`; BinDiff binary optional |
| Differential fuzz (oracle + ref harness) | ✅ Capable | Not full binary diff fuzzing |
| Scare Floor UX → session/model promotion | ✅ | Phases 18–19 in [ROADMAP.md](ROADMAP.md) |
| **Target Intelligence** profile (unified DTO + API) | 🔲 | Today: scattered JSON (analysis, frontier, findings) |
| **FaultSignal** taxonomy (controlled RIP, heap class, oracle-only) | 🔲 | Partial signals in triage + canisters; no unified enum/bus publish |
| Ghidra map → auto oracle rule suggestions | 🔲 | CLI hints only |
| Crash-RIP → decompiled context (MCP/decompiler) | 🔲 | Separate from one-line static summary |
| RPP `observe` + Target Intelligence write-back | 🔲 | Ambition: plugins as first-class sensors |
| Closed loop: frontier → Scare Floor → re-fuzz | 🔲 | Manual workflow documented |

**Done when:** `GET /api/targets/{project}/intelligence` returns a merged profile (static, frontier, oracle history, top screams); FaultSignal publishes on the observation bus; one-click “bias campaign from frontier” from UI.

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
