# Differential Oracle (Wave 5 stub)

Compare a **target parser** against a **reference implementation** on the same input — catch logic bugs that never crash.

> Research-only judgment layer. No weaponized payloads or exploit automation.

## Status

| Piece | Today | Future |
|-------|-------|--------|
| YAML `oracles.differential[]` | ✅ file harness exit/response diff via `OracleEngine` | — |
| `DifferentialOracleHook` | ✅ armed/describe stub + `CompareParsersAsync` placeholder | A/B parser compare |
| Silent scream promotion | ✅ high invariant violations → canister + intelligence pipeline | — |
| AST / structural diff | 🔲 | normalized tree compare |

## Enable today (file harness A/B)

```yaml
oracles:
  enabled: true
  differential:
    - id: ref-exit-match
      type: fileExit          # fileExit | fileResponse
      referenceExecutable: tools/reference-parser.exe
      referenceArgs: ["@@"]
      timeoutMs: 2000
```

Rules run only for `kind: file` targets. The engine re-executes the payload against `referenceExecutable` and flags exit-class or normalized-response mismatches.

## Hook surface

`Randall.Infrastructure.Oracles.DifferentialOracleHook`:

- `IsArmed(project)` — true when differential rules are configured
- `Describe(project)` — one-line fuzz preflight status
- `CompareParsersAsync(...)` — **stub**; returns `Ok: false` with guidance until dual-parser harness lands

Fuzz preflight logs the hook when armed (`FuzzEngine` startup banner).

## Planned A/B parser compare

```text
Input bytes
    ├─► Target parser (fuzz profile executable)
    └─► Reference parser (oracles.differential.referenceExecutable)
              ↓
    Normalize (exit class · response text · future AST)
              ↓
    Oracle finding → optional Silent Scream → RootCause / Influence / Evidence
```

Future work (not implemented):

1. **Structural** — parse both sides to a canonical JSON/tree and diff nodes (length fields, magic, nested counts).
2. **Semantic** — metamorphic + differential fusion (whitespace-normalized re-exec already exists separately).
3. **Campaign** — retain corpus entries on mismatch even when both sides stay alive.

## Related

- [ORACLES.md](ORACLES.md) — full oracle stack
- [ACADEMY_LAB_INDEX.md](ACADEMY_LAB_INDEX.md) — lab paths for practising logic vs memory bugs
- [EVIDENCE_FACT.md](EVIDENCE_FACT.md) — facts emitted when differential rules fire
