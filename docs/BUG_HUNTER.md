# Bug Hunter engine

The **Bug Hunter** analyzes source (AI vs human), maps common LLM mistake classes, and **arms a fuzz campaign** (suggested oracle rules, dictionary, mutators).

It is a separate engine from the **Oracle** ([ORACLES.md](ORACLES.md)):

| Engine | Role |
|--------|------|
| **Bug Hunter** | *What should we look for?* — attribution, mistake catalog, hunt plan, campaign arming |
| **Oracle** | *Did this run behave wrongly?* — evaluate observations, emit findings, optional retain/boost |

```text
Bug Hunter                          Oracle
─────────                          ──────
scan sources                       observe execution
attribute AI / human               evaluate rules
plan mistake classes        →      findings.jsonl
suggest oracle rules / dict        corpus interestingness
```

Code: `Randall.Infrastructure.BugHunt` (`BugHunterEngine`).

## CLI

```bash
# Analyze + hunt plan
randall hunt -d examples/ai-code-sample

# Arm a project (writes bugHunter: + enables oracle suggestions)
randall hunt -d examples/ai-code-sample -c projects/ai-badcode-hunt.yaml --arm

# Subcommands
randall hunt attribution -d ./src
randall hunt mistakes
randall hunt mistakes --emit-yaml

# Legacy alias
randall ai …   # same as randall hunt …
```

## Project config

```yaml
bugHunter:                 # preferred (legacy key: aiCode)
  enabled: true
  sourceRoots:
    - ../examples/ai-code-sample
  persistReport: true
  scanOnFuzzStart: true
  autoArmOracles: true     # suggest rules into oracles: (Oracle still judges)
  autoArmDictionary: true

oracles:
  enabled: true            # Oracle engine — judgment only

dictionaryFile: dictionaries/ai_codegen_mistakes.txt
```

On `randall fuzz`, when `bugHunter.enabled` is true, `BugHunterEngine.PrepareForFuzz`:

1. Suggests/merges the AI-mistake **oracle rule pack** (empty sections only)
2. Ensures AI-mistake **dictionary** + recommended mutators
3. Scans `sourceRoots`, prints priority AI blocks, writes `corpus/_bug_hunter/`

The Oracle engine then judges each iteration independently.

## Annotate for high confidence

```c
/* BEGIN AI */
// … model-written handler …
/* END AI */

/* BEGIN HUMAN */
// … reviewed / hand-written …
/* END HUMAN */
```

Also: `AI-GENERATED`, Copilot/ChatGPT/Claude/Cursor markers. Attribution is **heuristic**.

## Mistake classes

| Id | Hunt signal |
|----|-------------|
| `auth-skip` | suggest `oracles.auth` |
| `state-order` | suggest `oracles.state` |
| `length-lie` | suggest `oracles.integer` + boundary mutators |
| `trust-input` | suggest `oracles.structure` |
| `resource` | suggest `oracles.resource` |
| `mem-classic` | seeds / ASan (not primary oracle) |

`randall hunt mistakes` prints the full catalog.

## Demo

`projects/ai-badcode-hunt.yaml` — VulnRpc-shaped target + AI sample sources.

## Related

- [ORACLES.md](ORACLES.md) — judgment / reporting engine
- `projects/dictionaries/ai_codegen_mistakes.txt`
- `examples/ai-code-sample/handler.c`
