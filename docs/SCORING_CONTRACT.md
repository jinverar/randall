# Scoring contract

Canonical meanings for Randfuzz scores and ranks. **Hard rule:** a score **MUST NOT** mean exploitability unless this contract explicitly says so.

Research maturity **R0–R7** is a *study-depth* ladder (how well the crash is understood), not exploit completion. See gates below and `PrimitiveEngine` / `ResearchMaturityGates`.

| Metric | Meaning | Range | Owner | May affect |
|--------|---------|-------|-------|------------|
| **Severity** | Crash triage class (`critical` / `high` / `medium` / `low`) from exception / fault signals — *not* exploitability | enum | `CrashTriage` / `FaultSignalMapper` | ScreamScore weight · list sort · stop-goal mood |
| **Confidence** | Per-atom or rollup belief that a *claim* is supported (fact / root-cause / influence / primitive) — *not* “how exploitable” | 0–1 or HIGH/MEDIUM/LOW/UNKNOWN | EvidenceFact · RootCause · Influence · Primitive | Court promotion · UI badges · demotions |
| **OracleScore** | Explainable interestingness of an iteration / crash (coverage, violations, semantic rules) | 0–100 | `OracleScorer` | Corpus energy · findings · Novelty / ScreamScore terms · HuntValue |
| **Novelty** | How new / rare this scream cluster looks (seen-count, coverage Δ, oracle) | 0–100 | `CrashIntelligenceBuilder` | Canister purple mist · list priority · HuntValue |
| **ScreamScore** | Unified *triage ranking* for list / canister / Investigation — hotness of the finding as a research lead | 0–100 | `CrashIntelligenceBuilder` | Sort · stop goals · Deep Scream eligibility · HuntValue |
| **HuntValue** | Campaign steering score (novelty + static + oracle + momentum − cost − duplicate) | ~0–100+ (clamped in UI) | `HuntPolicyEngine` | Mutator / mode selection · Joker timing — *not* exploitability |
| **Research Priority** | UI “Priority” badge — same family as ScreamScore / list rank for operator attention | 0–100 | Investigation UI (`scoreCrash` / intel.screamScore) | Display only · does **not** claim exploitability |
| **Evidence Quality** | Completeness of sensor evidence (debugger, facts, counterfactual outcomes, maturity) | 0–100 | Investigation UI heuristic | Display only · *not* severity and *not* exploitability |

## Explicit non-meanings

| Metric | Does **not** mean |
|--------|-------------------|
| Severity | Weaponizable / EXPLOITABLE |
| Confidence | Exploit readiness |
| OracleScore | Root-cause correctness |
| Novelty | Control of EIP/RIP |
| ScreamScore / Research Priority | Exploitability (despite historical “IP looks controlled” *bonus terms* — those are triage hints only) |
| HuntValue | Bug severity or exploitability |
| Evidence Quality | Claim truth — only how much evidence is present |
| Research maturity R0–R7 | Exploit completion or payload readiness |

`DebuggerObservation.ExploitabilityHint` and WinDbg `!exploitable`-style strings are **sensor labels**, not Randfuzz scores. They must not be folded into ScreamScore as “exploit confirmed.”

## Research maturity gates (R0–R7)

Computed by `ResearchMaturityGates` + `PrimitiveEngine` — levels are **capped** by evidence; callers cannot assign R5+ arbitrarily.

| Level | Label | Required evidence (minimum) |
|-------|-------|------------------------------|
| **R0** | Crash | Crash discovered / reproduced |
| **R1** | Triaged | Triage, debugger observation, or ≥1 EvidenceFact |
| **R2** | Root-caused | Deterministic root-cause category **and** fault site: parseable fault instruction **plus** fault address and/or written value |
| **R3** | Attributed | ≥1 influence link (input region → state) |
| **R4** | Candidate | ≥1 capability primitive (candidate or better) |
| **R5** | Observed | ≥1 Observed capability **and** Court gate: Skeptic Survived + ≥1 sensor EvidenceFact **and** counterfactual/delta observation on a Survived challenge |
| **R6** | Confirmed | ≥1 Confirmed capability under the same Court / Skeptic / counterfactual gate |
| **R7** | Research package | ≥2 Confirmed capabilities + HIGH-confidence root cause under the same gate |

Evidence Court lite (`EvidenceCourt`) demotes high-confidence claims with zero EvidenceFacts and blocks R5+ without Skeptic survival. **Oracle score atoms** (`oracle.*`) and bookkeeping tags (`honesty:` / `court:` / `skeptic:`) are not Court proof. Court confirmation needs a sensor fact (debugger / influence / corruption / counterfactual / fault*) or an allowed sensor citation.

When a crash carries a `CrashArtifactIdentity` envelope, Court confirmation also requires **Verified** or **VerifiedWithWarnings** integrity (Rejected / Unverified envelopes and teardown-only secondary exceptions cannot reach Confirmed / R5+). See [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md#crash-artifact-identity).

## Related docs

- [SCREAM_INTELLIGENCE.md](SCREAM_INTELLIGENCE.md) — ScreamScore / Novelty rollup
- [ORACLES.md](ORACLES.md) — OracleScore formula
- [HUNT_POLICY.md](HUNT_POLICY.md) — HuntValue
- [EVIDENCE_FACT.md](EVIDENCE_FACT.md) — EvidenceFact atoms
- [RESEARCH_BENCHMARK.md](RESEARCH_BENCHMARK.md) — accuracy scorecard scaffold
- [ROADMAP_RESEARCH_WORKBENCH.md](ROADMAP_RESEARCH_WORKBENCH.md) — workbench status
