# EvidenceFact — Wave 1 backbone

Randfuzz crash investigation uses **EvidenceFact** as the normalized atom for research-only triage. Every sensor (CDB/Scream Investigator, corruption chain, backward trace, oracle, hypotheses, sidecar lineage) adapts into the same shape so downstream engines do not parse ad-hoc strings.

## Contract

```text
EvidenceFact
├── name, value
├── source, sourceArtifact
├── observationType: Observed | ExperimentallyConfirmed | Inferred | Hypothesized
├── confidence (0–1)
├── timestamp
└── relatedFacts[]   (other fact names)
```

Defined in `src/Randall.Contracts/EvidenceFactModels.cs`. Persisted per crash as:

```text
data/crashes/<project>/{guid}_evidence.json
```

## Producers (adapters)

| Sensor | Adapter | Typical observationType |
|--------|---------|---------------------------|
| **ScreamInvestigator** / `DebuggerObservationProvenance` | `EvidenceFactBuilder.FromDebuggerProvenance` | Observed (CDB transcript) / Inferred (address class) |
| **CorruptionChainBuilder** | `FromCorruptionChain` | Inferred (attribution) / Observed (register match) |
| **BackwardTraceBuilder** | `FromBackwardTrace` | Inferred |
| **HypothesisEngine** | `FromHypotheses` | Hypothesized / ExperimentallyConfirmed — v2 hyps cite `evidenceRefs` (EvidenceFact ids); free-form tags are legacy-only |
| **OracleScorer** | `FromOracle` | Observed |
| **FaultSignalMapper** | `FromFaultSignals` | Observed or Inferred by source |
| **Crash sidecar / triage** | `FromLineage`, `FromTriage` | Observed |

`EvidenceFactBuilder.Build` fuses all available inputs. Called from:

- `WindowsCdbCrashAnalysisWriter.Analyze` (post-CDB, before root cause)
- `FuzzEngine.TryPersistHypotheses` (refresh after hypotheses)
- `CrashCatalog.GetDetail` (lazy build when JSON missing)

## Consumers

Engines should **read `CrashEvidenceDto.Facts` or call `EvidenceFactBuilder.CollectFacts`** — not re-parse `{guid}_corruption_chain.json` or hypothesis string tags.

| Engine | How to consume |
|--------|----------------|
| **RootCauseEngine** | `CollectEvidenceFacts` delegates to `EvidenceFactBuilder` |
| **InfluenceEngine** | `externalFacts` from evidence collect; adds attribution-specific facts |
| **CrashIntelligenceDto** | `EvidenceFacts` on intelligence rollup + Investigation API |
| **Future PrimitiveEngine** | Filter `ObservationType == Observed \| ExperimentallyConfirmed` for primitive candidates |
| **Future ResearchPlanner** | Join `Hypothesized` facts with experiment queue |

### CdbProbePlan

`CdbProbePlan.StandardCrash` remains the headless consumer that **emits Observed facts** via Scream Investigator provenance (`.exr -1`, `r`, `kv`, `!address`, …). No change to probe scripts — facts are derived from existing CDB blocks.

## Evidence Ledger (display taxonomy)

Investigation / Exploit Research show an **Evidence Ledger** derived from the same atoms (no parallel store). `EvidenceLedger.KindFor` maps `observationType` → Kind:

| Kind | From ObservationType |
|------|----------------------|
| **Observed** | `Observed` |
| **Confirmed** | `ExperimentallyConfirmed` |
| **Derived** | `Inferred` (confidence ≥ 0.55) |
| **Heuristic** | `Inferred` (confidence &lt; 0.55) |
| **Hypothesis** | `Hypothesized` |

## Investigation UI

Crashes → Investigation shows **Evidence Ledger** + **Evidence facts** with type badges:

- **Observed** — read from sensor output
- **Confirmed** — hypothesis experiment succeeded
- **Inferred** — heuristic join (chain, backward trace, address class)
- **Hypothesized** — ranked hypothesis pending experiment

## Next layers (roadmap)

Wave 1 stops at evidence normalization. Planned stack:

1. **EvidenceFact** (this doc) — shared vocabulary
2. **RootCauseEngine** — category from fact correlation (`{guid}_root_cause.json`)
3. **InfluenceEngine** — input region → state links (`{guid}_influence.json`)
4. **PrimitiveEngine** (future) — research-only control primitives, no payloads
5. **Learning vs Research modes** (future) — teaching path vs open-ended bench

See [ROADMAP_INTELLIGENCE.md](ROADMAP_INTELLIGENCE.md) and [EXPLOIT_GUIDE.md](EXPLOIT_GUIDE.md).

## Identity guardrails

EvidenceFact supports **EXP-301 / SEC760-style research** — reproduce, attribute, hypothesize, confirm with deterministic experiments. It does **not** generate shellcode, weaponized exploits, or auto-exploit writers.

### Observed vs Derived vs Hypothesis (honesty)

Only **raw debugger / file sensor facts** may be stored as `ObservationType.Observed` (exception code, fault address, RIP, register↔payload matches when fault insn + EA + stack/reg links exist, artifact hard-failure lines).

Interpretive atoms are **Inferred / Hypothesized**, never Observed:

| Atom | Kind |
|------|------|
| `corruption.summary`, `backwardTrace.story` | Inferred (Derived in Ledger) |
| `debugger.inputInfluence`, `debugger.diagnosis` | Inferred |
| `triage.summary`, `triage.ipControlled`, `oracle.*` | Inferred |
| `hypothesis.*` | Hypothesized (or ExperimentallyConfirmed) |

`EvidenceFactBuilder.EnforceObservationHonesty` demotes accidental Observed labels before persist. Ledger Kind maps Inferred ≥0.55 → **Derived**.

### Crash artifact identity

Strong research promotion (root-cause / influence / primitives / twins / genealogy / Court Confirmed) requires a non-**Rejected** `CrashArtifactIdentity` chain (`docs/CRASH_ANALYSIS.md`). Teardown / `NtTerminateProcess` secondary exceptions block promotion without a primary fault. Unexpected managed modules (`clrjit` / `coreclr`) on a native target are **warnings** — not auto Observed narrative promotion.
