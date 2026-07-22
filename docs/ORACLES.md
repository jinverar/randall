# Hybrid semantic oracles

Coverage answers: *did this input reach new code or crash?*  
Oracles additionally answer: *did the target behave incorrectly while staying alive?*

Randfuzz’s oracle stack **supplements** coverage — it does not replace it. Findings feed corpus energy and a dedicated `oracle_findings.jsonl` log.

## Stack (cheap → expensive)

```text
Input → Fuzz execution
          ↓
RuntimeRule      crash / timeout / sanitizer hint
InvariantRule    expect / forbid / max length / exit code / post_receive
DifferentialRule compare file target vs reference harness
MetamorphicRule  transform → re-exec → check relation
          ↓
Triage + corpus retention (interestingness score)
```

## Enable in a project

```yaml
oracles:
  enabled: true
  retainOnViolation: true
  retainOnNearMiss: true
  persistFindings: true
  promoteExpectResponse: true    # soft expect mismatches → oracle findings
  promotePostReceiveAbort: true
  invariantSeverity: violation   # or nearMiss
  invariants:
    - id: must-ack
      type: expectSubstring
      pattern: "OK"
      whenCommand: ECHO
    - id: no-priv-before-auth
      type: forbidSubstring
      pattern: "AUTH_OK"
  differential:                  # file harness only (v1)
    - id: vs-reference
      type: fileExit             # or fileResponse
      referenceExecutable: ../targets/local/ref_parser
      referenceArgs: ["@@"]
  metamorphic:
    - id: ws-insensitive
      type: whitespaceInsensitive
      severity: nearMiss
    - id: dup-idempotent
      type: duplicateIdempotent  # TCP
      severity: nearMiss
```

## Interestingness (feeds corpus energy)

```text
score ≈ new_edges×10 + confirmed_violation×100 + near_miss×12
```

Violations / near-misses call `CorpusTracker.SaveInteresting` + `BoostEnergy` so the power schedule evolves toward semantic failures, not only crashes.

## Findings

Written to:

```text
data/crashes/<project>/_oracles/oracle_findings.jsonl
```

Each record includes `rule_id`, `rule_class`, `severity`, `input_hash`, `expected_relation`, `actual_relation`, `normalized_observation`, `transformation_chain`, `coverage_signature`, `confidence`.

```bash
randall oracles -p vulnlab
randall oracles -p vulnlab --json
```

## Design rules (avoid junk)

- Prefer **normalized** comparisons (`status_class`, response class, lengths) — not raw logs/timestamps
- Differential soft-fails if the reference binary is missing
- Metamorphic rules skip binary payloads for whitespace transforms
- Bad oracles create noise — start with `promoteExpectResponse` + one forbid/expect rule

## What this is not

- Not a replacement for ASan/UBSan builds (still the best RuntimeRule signal)
- Not automatic exploit development
- Coverage + stalk remain the exploration engine

See also: [FUZZING.md](FUZZING.md) · [HARNESS_DESIGN.md](HARNESS_DESIGN.md) · [AI_SEED.md](AI_SEED.md)
