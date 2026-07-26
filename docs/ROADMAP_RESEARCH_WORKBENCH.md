# Research Workbench Roadmap

Randfuzz as a **vulnerability research + fuzzing workbench** — evidence, root cause, influence, capability primitives, research plans, and teaching advisors. **No weaponized exploits**: no shellcode, ROP payloads, or auto-exploit generation.

Living inventory was historically tracked under [ROADMAP_INTELLIGENCE.md](ROADMAP_INTELLIGENCE.md) § *Exploit-research workbench stack*. This file is the honest overnight status board for research-workbench items.

---

## Shipped (main)

| Item | Artifact | Status |
|------|----------|--------|
| EvidenceFact / RootCause / Influence | `{guid}_evidence/root_cause/influence.json` | ✅ Wave 1 |
| Silent Screams | `SilentScreamBuilder` | ✅ Wave 5 |
| Learning / Research modes | `academy.presentationMode` | ✅ Wave 5 stub |
| Differential Oracle stub | `DifferentialOracleHook` | ✅ Wave 5 |
| Academy lab INDEX | [ACADEMY_LAB_INDEX.md](ACADEMY_LAB_INDEX.md) | ✅ stub |
| Debugger corpus | `tests` + `data/crashes/debugger-corpus` | ✅ foundation |
| Scream Evolution / Hunt / Hypothesis / Deep Scream | engines + sidecars | ✅ |
| **PrimitiveEngine** | `{guid}_primitives.json` · maturity R0–R7 *computed* | ✅ Wave 2 |
| **R0–R7 research maturity UI scale** | Investigation chips + progress + Crashes list column | ✅ DONE |
| **Research Planner + Skeptic** | `{guid}_research_plan.json` · `{guid}_skeptic.json` | ✅ Wave 3 foundations |
| **ExploitabilityAdvisor** | `{guid}_exploitability_advisor.json` | ✅ teaching packages |
| **Instructor levels 0–6** | `InstructorAssistance` · UI select · prefs | ✅ extends instructorMode |
| **Patch Hypothesis** | `{guid}_patch_hypothesis.json` | ✅ remediation text + patched-lab hook |
| **Patch-analysis workflow v1** | `PatchAnalysisWorkflow` · Ghidra JSON diff | ✅ security-relevant fn hints |
| **Temporal Bug Reasoning** | `{guid}_temporal.json` | ✅ Corruption→Crash→RootCause timeline |
| **Why Haven't I Found It?** | `barrier_diagnosis.json` | ✅ campaign barrier diagnosis |
| **Campaign postmortem** | `campaign_postmortem_last.json` | ✅ teaching narrative |
| **Security-Invariant Language stub** | `SecurityInvariantCompiler` ASSERT→Oracle | ✅ table-driven stub |
| **Research package / Wave7 report stub** | `{guid}_research_package.json` | ✅ checklist rollup |
| README reposition | vulnerability research + fuzzing workbench | ✅ one paragraph |
| **Bug Genealogy** | `bug_genealogy.json` · N probable vulns / M failures | ✅ v1 |
| **Counterfactual Fuzzing** | `{guid}_counterfactual.json` · sweep/boundary safe vs corrupt | ✅ v1 |
| **Vulnerability Twins** | `{guid}_vuln_twins.json` · `twin_hunt_hints.json` | ✅ v1 (Ghidra or stub) |

---

## Deferred (near-term / later)

| Item | Why deferred |
|------|----------------|
| Full Academy labs 01–12 content | Index stub only |
| Professor grading | Not started |
| Historical vuln clones | Not started |
| Cross-campaign Knowledge Graph | Beyond Scream Evolution family index |
| Family Breeding beyond Scream Evolution | Partial via evolution; full breeding deferred |
| Patch→Variant Hunter full | Patch-analysis v1 + hypothesis only |
| Counterfactual live re-exec in fuzz loop | v1 persists probe plans; live `stillCrashes` evaluate is API/test-ready |
| Twins Investigation UI chips | Engine + API/CLI shipped; richer UI later |

---

## Research maturity (R0–R7) status

| Layer | Status |
|-------|--------|
| `ResearchMaturity` enum + `PrimitiveEngine.ComputeMaturity` | ✅ shipped (study-depth ladder, not exploit completion) |
| Persistence on `{guid}_primitives.json` | ✅ |
| CrashIntelligence fields (`ResearchMaturity`, label, rationale, primitive summary) | ✅ data fields |
| Investigation UI maturity scale / chips (R0 Crash … R7 Research package) | ✅ **DONE** |
| Crashes list maturity column | ✅ **DONE** |
| Learning mode explains each level; Research shows denser rationale | ✅ **DONE** |

Chip short names: **R0 Crash → R1 Triaged → R2 Root cause → R3 Attributed → R4 Primitive → R5 Observed → R6 Confirmed → R7 Research package**.

---

## Nightly notes

- Interrupted Fable branches (`cursor/wave2-primitive-engine`, `cursor/wave3-research-planner-skeptic`) held uncommitted WIP only; salvage landed via Grok on `main`.
- Junk `scripts/_*.py` / tmp probes were **not** committed (remain in stash if needed).
- **Grok overnight killers landed (v1):** Bug Genealogy · Counterfactual Fuzzing · Vulnerability Twins — research/teaching only, no exploit payloads. API: `/api/stalking/{p}/genealogy`, `/api/crashes/{id}/counterfactual`, `/api/crashes/{id}/twins`, `/api/stalking/{p}/twin-hints`. CLI: `stalk genealogy|counterfactual|twins`.
- R0–R7 UI scale shipped after engine + intelligence DTO fields were already on `main`.
