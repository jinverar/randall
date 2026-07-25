# Oracle engine (judgment / reporting)

Coverage answers: *did this input reach new code or crash?*  
The **Oracle engine** answers: *did the target behave incorrectly while staying alive?*

**Scope:** evaluate observations against rules → emit findings → optional corpus retain/boost → **request help** (`OracleNeedDto`) when Magician should intervene.  
**Not in scope:** AI/human attribution or hunt planning (Bug Hunter); casting spells / summoning helpers (Magician — [MAGICIAN.md](MAGICIAN.md)). Joker Card deck credit (chaos/remix/replay) is owned by the Joker engine — see [MAGICIAN.md#joker-card-deck-702010](MAGICIAN.md#joker-card-deck-702010).

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
InvariantRule       expect / forbid / response class / exit code / post_receive
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

## Invariants (single-execution)

```yaml
oracles:
  enabled: true
  invariants:
    - id: need-http
      type: expectSubstring
      pattern: "HTTP/"
      severity: nearMiss
    - id: no-stack
      type: forbidSubstring
      pattern: "Stack overflow"
      severity: violation
    - id: want-2xx
      type: expectResponseClass   # 1xx|2xx|3xx|4xx|5xx|empty|non-http
      pattern: "2xx"
      severity: nearMiss
    - id: no-5xx
      type: forbidResponseClass
      pattern: "5xx"
      severity: violation
```

Aliases: `expect` / `forbid` / `expectClass` / `forbidClass` / `response_class`.

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

## Interestingness (Randall Intelligence Loop)

Each fuzz iteration emits unified **Observation** events on `FuzzEngine.ObservationBus` and an explainable **OracleScore** (0–100):

```text
Observation { Type, RunId, Confidence, Novelty, Severity, Data }
OracleScore   { Total, Terms[], Summary }
```

**Score formula** (additive, clamped to 100): new coverage min(30, edges×10); violation min(50, count×35); near miss min(24, count×12); state/auth +20; semantic +15; runtime min(40, count×25). Crashes: +80 crash + up to +20 coverage-at-crash.

**Where scores appear:** verbose fuzz log; `oracle_findings.jsonl` (`oracleScoreTotal` / `oracleScoreTerms`); crash sidecars (`randallScore`). `InterestingnessScore` == `Score.Total`.

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

## Static target map (Ghidra)

When `data/stalk/<project>/randall-analysis.json` exists (from `randall stalk ghidra-analyze`), the Oracle CLI surfaces **static fuzz priorities** and **coverage gaps** alongside runtime findings:

```bash
randall stalk ghidra-analyze -p vulnserver --binary path/to/target
# fuzz with coverageGuided + stalk layers (or corpus edges) to populate overlay
randall oracles -p vulnserver
```

The map lists functions, per-function CFG blocks, sink call graph edges, and a `fuzzPriority` heuristic. **v2** overlays stalk/drcov edges onto static BBs and recomputes priority using sink risk × complexity × uncovered CFG distance ÷ coverage fraction (blended with the v1 static score). Optional `fuzz.ghidraStaticBias: true` softly boosts corpus energy when novel edges arrive while high-priority functions remain uncovered.

**Source→sink paths:** when `randall-analysis.json` includes imports/sinks and call edges, `SourceSinkPathScorer` ranks input API → dangerous sink routes (SaTC-style static reachability, not a separate engine). Surfaces in `randall oracles -p <project>` and static-map score bonuses.

This does **not** replace coverage-guided exploration — it **closes the loop** via **RandallBrain** (`fuzz.brain: true`, default on). When `frontier.json`, oracle findings, scream clusters, or static map data exist, the brain fuses them into a **NextHuntDecision** (reviewer alias **`decision`** / `RandallDecision`: `inputId`, `score`, `reasons`, `actions`) each fuzz iteration:

| Brain action | Source |
|--------------|--------|
| Corpus priority bias (65–88%) | Top frontier / static / oracle / scream focus |
| Preferred mutator (62% blend with credit) | Focus kind → havoc, dictionary, interesting, … |
| Corpus energy +2…+8 | Novel coverage / oracle retains while brain active |
| Explainable Why? terms | Scare Floor factory map + `GET /api/fuzz/brain?project=` |

Without stalk/scream signals the brain **soft no-ops** — baseline AFL-style pick unchanged. Optional `fuzz.ghidraStaticBias: true` still adds per-edge energy when high-priority functions stay uncovered. Crash-RIP decompile snippets and TraceRMI translation are optional via `randall ghidra mcp crash` ([GHIDRA_DEBUGGER.md](GHIDRA_DEBUGGER.md)) — not automatic in canisters.

See [GHIDRA_INTEGRATION.md](GHIDRA_INTEGRATION.md) for headless vs Script Manager export and companion tools (GhidraMCP, BinExport).

## Design rules (avoid junk)

- Normalize before compare (`status_class`, response class, lengths) — not timestamps/logs
- Structure rules default to **onlyWhenAccepted** (malformed input that was rejected is mutator noise)
- Length-prefix violations weight higher when the target **accepted** the PDU
- Differential soft-skips missing reference binaries
- Start narrow: one auth forbidUntil + one state order rule

## Differential fuzzing (two-target compare)

Compare the **primary** target executable against a **reference** harness on the same input. Useful for patch-hunt regressions, parser forks, and “safe vs vulnerable” lab pairs.

```yaml
oracles:
  enabled: true
  differential:
    - id: safe-vs-vuln
      type: fileExit          # fileExit | fileResponse
      referenceExecutable: ../targets/file-text/randall-file-text-safe
      referenceArgs: ["@@"]
      timeoutMs: 2000
```

| Step | Command / UI |
|------|----------------|
| Arm rules | Add `oracles.differential` to project YAML (paths relative to YAML dir) |
| Doctor check | `randall doctor -c projects/<name>.yaml` — warns when reference binary missing |
| Target profile | `randall stalk intel -p <project>` — lists diff rules + ref existence |
| Scare Floor | **Randall thinks** command strip shows **diff oracle on** when armed |
| During fuzz | `OracleEngine` soft-skips missing refs; violations land in `_oracles/` findings |

Reference must accept `@@` or `{file}` like other file harnesses. This is **oracle differential**, not BinDiff instruction-level fuzzing — pair with `randall stalk ghidra-diff` for static `changedFunctions[]`.

## What this is not

- Not a bug-hunter / campaign planner (see [BUG_HUNTER.md](BUG_HUNTER.md))
- Not a replacement for ASan/UBSan on unsafe code
- Not automatic exploit development
- Coverage + stalk remain the exploration engine

See also: [BUG_HUNTER.md](BUG_HUNTER.md) · [FUZZING.md](FUZZING.md) · [HARNESS_DESIGN.md](HARNESS_DESIGN.md)
