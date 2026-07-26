# Research Workbench Roadmap

Randfuzz as a **vulnerability research + fuzzing workbench** — evidence, root cause, influence, capability primitives, research plans, and teaching advisors. **No weaponized exploits**: no shellcode, ROP payloads, or auto-exploit generation.

Living inventory was historically tracked under [ROADMAP_INTELLIGENCE.md](ROADMAP_INTELLIGENCE.md) § *Exploit-research workbench stack*. This file is the honest overnight status board for research-workbench items.

**Maturity vocabulary (prefer these over bare ✅):** `STUB` → `EXPERIMENTAL` → `TESTED` → `INTEGRATED` → `VALIDATED`.

---

## Shipped (main)

| Item | Artifact | Status |
|------|----------|--------|
| EvidenceFact / RootCause / Influence | `{guid}_evidence/root_cause/influence.json` | TESTED · Wave 1 |
| Silent Screams | `SilentScreamBuilder` | TESTED · Wave 5 |
| Learning / Research modes | `academy.presentationMode` | STUB · Wave 5 — **presentation wiring only**; behavior mode not yet distinct from Research beyond UI copy |
| Differential Oracle stub | `DifferentialOracleHook` | STUB · Wave 5 |
| Academy lab INDEX | [ACADEMY_LAB_INDEX.md](ACADEMY_LAB_INDEX.md) | STUB |
| Debugger corpus | `tests/debugger-corpus` + managed fixtures | TESTED · null/ASCII/OOB/stack/UAF/trunc fixtures; live cdb soft-skips |
| Scream Evolution / Hunt / Hypothesis / Deep Scream | engines + sidecars | INTEGRATED |
| **PrimitiveEngine** | `{guid}_primitives.json` · maturity R0–R7 *computed* | TESTED · Wave 2 |
| **R0–R7 research maturity UI scale** | Investigation chips + progress + Crashes list column | INTEGRATED |
| **Research Planner + Skeptic** | `{guid}_research_plan.json` · `{guid}_skeptic.json` | TESTED · Skeptic is mandatory gate for R5+ / Confirmed |
| **ExploitabilityAdvisor** | `{guid}_exploitability_advisor.json` | TESTED · teaching packages |
| **Instructor levels 0–6** | `InstructorAssistance` · UI select · prefs | INTEGRATED |
| **Patch Hypothesis** | `{guid}_patch_hypothesis.json` | EXPERIMENTAL · remediation text |
| **Patch-analysis workflow v1** | `PatchAnalysisWorkflow` · Ghidra JSON diff | EXPERIMENTAL |
| **Temporal Bug Reasoning** | `{guid}_temporal.json` | TESTED |
| **Why Haven't I Found It?** | `barrier_diagnosis.json` | EXPERIMENTAL |
| **Campaign postmortem** | `campaign_postmortem_last.json` | EXPERIMENTAL |
| **Security-Invariant Language stub** | `SecurityInvariantCompiler` ASSERT→Oracle | STUB |
| **Research package / RF-#### report** | `{guid}_research_package.json` | TESTED · full teaching report + CLI/API export |
| README reposition | vulnerability research + fuzzing workbench | INTEGRATED |
| **Bug Genealogy** | `bug_genealogy.json` · N probable vulns / M failures | EXPERIMENTAL · v1 |
| **Counterfactual Fuzzing (live loop)** | `{guid}_counterfactual.json` · execute→observe→persist | TESTED · bounded post-crash live re-exec |
| **Vulnerability Twins / Variant Hunter v2** | `{guid}_vuln_twins.json` · structural signature + same-invariant hints | TESTED · graceful without Ghidra |

---

## Deferred (near-term / later)

| Item | Why deferred |
|------|----------------|
| Full Academy labs 01–12 content | Index stub only |
| Professor grading | Not started — blocked until 1–5 reliability work stays green |
| Historical vuln clones | Not started |
| Cross-campaign Knowledge Graph | Beyond Scream Evolution family index |
| Family Breeding beyond Scream Evolution | Partial via evolution; full breeding deferred |
| Patch→Variant Hunter full Ghidra climb | Structural signatures + twins shipped; deeper patch-diff coupling later |
| Twins Investigation UI chips | Engine + API/CLI shipped; richer UI later |
| `Randall.Research` project split | Explicitly deferred |

---

## Research maturity (R0–R7) status

| Layer | Status |
|-------|--------|
| `ResearchMaturity` enum + `PrimitiveEngine.ComputeMaturity` | ✅ shipped (study-depth ladder, not exploit completion) |
| **Skeptic promotion gate** | ✅ R5+ and Confirmed require Survived + observation + no Falsified |
| Persistence on `{guid}_primitives.json` | ✅ |
| CrashIntelligence fields (`ResearchMaturity`, label, rationale, primitive summary) | ✅ data fields |
| Investigation UI maturity scale / chips (R0 Crash … R7 Research package) | ✅ **DONE** |
| Crashes list maturity column | ✅ **DONE** |
| Learning mode explains each level; Research shows denser rationale | ✅ **DONE** (presentation); behavior mode still STUB |

Chip short names: **R0 Crash → R1 Triaged → R2 Root cause → R3 Attributed → R4 Primitive → R5 Observed → R6 Confirmed → R7 Research package**.

---

## Persistence / schemaVersion

| Item | Status |
|------|--------|
| `schemaVersion: 1` on research crash sidecars | **PARTIAL** — Evidence / RootCause / Influence / Primitive / Hypotheses / ResearchPlan / Skeptic / ResearchPackage / Counterfactual / Twins DTOs emit `schemaVersion` (default 1). Legacy files without the field deserialize to 1. Not yet universal across all stalk/campaign JSON. |
| End-to-end research pipeline reload | TESTED — `ResearchPipelineEndToEndTests` (harness-demo known-bad → research stack → reload) |
| Research artifact golden round-trip | TESTED — `ResearchArtifactPersistenceTests` |
| Counterfactual live loop | TESTED — `CounterfactualLiveLoopTests` (execute→observe→persist + budget + skeptic settle) |
| RF research package from fixtures | TESTED — `ResearchPackageReportBuilderTests` |
| Variant Hunter structural signature | TESTED — `VulnerabilityTwinEngineTests` |

## Nightly notes

- Interrupted Fable branches (`cursor/wave2-primitive-engine`, `cursor/wave3-research-planner-skeptic`) held uncommitted WIP only; salvage landed via Grok on `main`.
- Junk `scripts/_*.py` / tmp probes were **not** committed (remain in stash if needed).
- **Reliability pass (reviewer top 5):** Counterfactual live loop · Skeptic maturity gate · RF-#### research package · Debugger corpus expansion · Variant Hunter v2 — research/teaching only, no exploit payloads.
- API: `/api/stalking/{p}/genealogy`, `/api/crashes/{id}/counterfactual?live=`, `/api/crashes/{id}/twins`, `/api/crashes/{id}/research-package`, `/api/stalking/{p}/twin-hints`.
- CLI: `stalk genealogy|counterfactual [--live]|twins|research-package`.
- R0–R7 UI scale shipped after engine + intelligence DTO fields were already on `main`.
