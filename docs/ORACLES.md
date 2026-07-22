# Oracle engine (judgment / reporting)

Coverage answers: *did this input reach new code or crash?*  
The **Oracle engine** answers: *did the target behave incorrectly while staying alive?*

**Scope:** evaluate observations against rules → emit findings → optional corpus retain/boost → **request help** (`OracleNeedDto`) when Magician should intervene.  
**Not in scope:** AI/human attribution or hunt planning (Bug Hunter); casting spells / summoning helpers (Magician — [MAGICIAN.md](MAGICIAN.md)).

```text
Bug Hunter suggests rules / focus     →     Oracle judges each run     →     Magician casts / summons
randall hunt …                              randall oracles …                randall magician …
```

Code: `Randall.Infrastructure.Oracles` (`OracleEngine`). Needs: `OracleNeeds.FromFindings`.

**Thesis:** as more targets become memory-safe (and more code is LLM-authored), high-value bugs are often **logic / auth / state / semantic** failures that never crash. Oracles carry that judgment half; Bug Hunter decides what to arm; the Magician acts when the Oracle needs a knight, army, bots, or hunter; seeds/mutators still chase memory corruption.

The oracle stack **supplements** coverage — it does not replace it. Findings feed corpus energy and `oracle_findings.jsonl`.

## Stack (cheap → expensive)

```text
Input → Fuzz execution
          ↓
RuntimeRule         crash / timeout / sanitizer hint
InvariantRule       expect / forbid / exit code / post_receive
AuthRule            forbidUntil · requireAuth
StateRule           commandRequiresPrior · forbidResponseInState
IntegerRule         lengthPrefix (claimed vs body / plausible / wrap)
StructureRule       min/max size · magic / prefix (esp. when accepted)
ResourceRule        max response/payload · response/payload ratio
DifferentialRule    file target vs reference harness
MetamorphicRule     whitespaceInsensitive · duplicateIdempotent
          ↓
Triage + corpus retention (interestingness score)
```

## Division of labour

| Concern | Prefer |
|---------|--------|
| Memory corruption, parser crashes, ASan | Seeds + mutators (+ sanitizer builds) · [AI_SEED.md](AI_SEED.md) |
| Logic / auth / state / semantic integers / structure | **Oracle** judgment (this doc) |
| AI vs human focus + which rules to arm | **Bug Hunter** ([BUG_HUNTER.md](BUG_HUNTER.md)) |
| Act on Oracle needs (spells / summons) | **Magician** ([MAGICIAN.md](MAGICIAN.md)) |
| Path discovery | Coverage / stalk / AFL++ adapter |

## Enable semantic rules

```yaml
oracles:
  enabled: true
  retainOnViolation: true
  retainOnNearMiss: true
  promoteExpectResponse: true

  auth:
    - id: no-ok-before-bind
      type: forbidUntil
      forbidResponse: "RPC_OK"
      untilResponse: "BIND_ACK"
    - id: request-needs-bind
      type: requireAuth
      whenCommand: REQUEST
      untilResponse: "BIND_ACK"

  state:
    - id: request-order
      type: commandRequiresPrior
      forCommand: REQUEST
      priorCommand: BIND
      priorResponse: BIND_ACK

  integer:
    - id: nbss-length
      type: lengthPrefix
      offset: 1          # after NBSS type byte
      width: 3           # use 2 or 4 in v1 if 3 unsupported — width 1|2|4
      endian: be
      covers: rest
      maxPlausible: 1048576

  structure:
    - id: smb-magic
      type: requireMagicHex
      hex: "FE534D42"
      onlyWhenAccepted: true

  resource:
    - id: huge-response
      type: maxResponseBytes
      maxBytes: 1048576
```

Session facts (`BIND_ACK` seen, commands observed) live in an in-run **OracleSessionTracker** and reset when the long-lived target crashes.

## Interestingness

```text
score ≈ new_edges×10 + confirmed_violation×100 + near_miss×12
```

Violations / near-misses → `SaveInteresting` + `BoostEnergy` so the schedule evolves toward **semantic** failures.

## Findings

```text
data/crashes/<project>/_oracles/oracle_findings.jsonl
```

```bash
randall oracles -p vulnrpc
randall oracles -p vulnrpc --json
```

Each finding: `rule_id`, `rule_class`, `severity`, `input_hash`, `expected_relation`, `actual_relation`, `normalized_observation`, `transformation_chain`, `coverage_signature`, `confidence`.

## Design rules (avoid junk)

- Normalize before compare (`status_class`, response class, lengths) — not timestamps/logs
- Structure rules default to **onlyWhenAccepted** (malformed input that was rejected is mutator noise)
- Length-prefix violations weight higher when the target **accepted** the PDU
- Differential soft-skips missing reference binaries
- Start narrow: one auth forbidUntil + one state order rule

## What this is not

- Not a bug-hunter / campaign planner (see [BUG_HUNTER.md](BUG_HUNTER.md))
- Not a replacement for ASan/UBSan on unsafe code
- Not automatic exploit development
- Coverage + stalk remain the exploration engine

See also: [BUG_HUNTER.md](BUG_HUNTER.md) · [FUZZING.md](FUZZING.md) · [HARNESS_DESIGN.md](HARNESS_DESIGN.md)
