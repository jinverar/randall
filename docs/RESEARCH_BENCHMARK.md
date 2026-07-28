# Research Accuracy Benchmark

Scaffold for scoring Randfuzz investigation honesty against known teaching bugs — **fixtures and unit tests only** (no long-lived lab listeners).

## Vision

A scorecard per fixture records whether the pipeline:

| Check | Meaning |
|-------|---------|
| Crash detection | Observation / triage recognizes a fault |
| Classification | Access kind / address class / fault family match envelope |
| PC when expected | RIP/fault PC present when fixture expects it |
| Root-cause family | Category in expected set (or Unknown when envelope says so) |
| Attribution | Influence / region only when evidence supports it |
| Primitive hypothesis level | Maturity ≤ max without Skeptic/Court; no unsupported R5+ |
| False confident claims | High-confidence claims without EvidenceFact / Court reject |

Expand toward ~20 teaching bugs over time. First wave: 5–8 cases (stack overwrite, null deref, OOB write, integer/boundary, UAF, oracle/silent) reusing `tests/debugger-corpus` where possible.

## Layout

```text
tests/Randall.Tests/ResearchBenchmark/
  ResearchBenchmarkModels.cs   # scorecard DTO + expected envelope
  ResearchBenchmarkFixtures.cs # catalog (live + stub TODO)
  ResearchBenchmarkRunner.cs   # ParseBlocks / engine scorecard
  ResearchBenchmarkTests.cs    # wired fixtures assert; stubs mark TODO
```

Filter (fast CI):

```bash
dotnet test tests/Randall.Tests -c Release --filter ResearchBenchmark
```

## Hard rules

- Scores follow [SCORING_CONTRACT.md](SCORING_CONTRACT.md) — ScreamScore / Priority ≠ exploitability.
- R0–R7 via `ResearchMaturityGates` — cannot invent R5+ without Skeptic survival + counterfactual delta + EvidenceFact.
- Do not start vuln lab TCP services for this harness; tear down anything started in `finally`.

## Status

See fixture table in `ResearchBenchmarkFixtures` (`Live` vs `Stub`). Docs track vision; expand envelopes as engines improve.
