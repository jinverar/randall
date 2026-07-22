# AI seed recipes (optional)

Propose **starting seeds + dictionary tokens** for a project with an LLM, then fuzz with the normal Randfuzz engine (or `fuzz.engine: aflpp` on Linux).

This is **not** in the fuzz hot path. It is an optional recipe step — same family as Scare Floor / case recipes.

> Authorized targets only. The prompt asks for valid-ish and edge-case inputs, not exploits or shellcode.

## Setup

```bash
export RANDALL_AI_API_KEY=sk-...          # or OPENAI_API_KEY
export RANDALL_AI_BASE_URL=https://api.openai.com/v1   # optional; OpenAI-compatible
export RANDALL_AI_MODEL=gpt-4o-mini                    # optional
```

Any OpenAI-compatible `/v1/chat/completions` endpoint works (local gateways included).

No key? Use `--dry-run` (prints the prompt) or `--fixture projects/fixtures/ai_seed_fixture.json`.

## Usage

```bash
# Preview prompt only
randall ai seed -c projects/vulnlab.yaml --dry-run

# Offline fixture (no network)
randall ai seed -c projects/vulnlab.yaml --fixture projects/fixtures/ai_seed_fixture.json

# Live API → write seeds + dictionary
randall ai seed -c projects/vulnlab.yaml --count 8

# Also append seed paths / dictionaryFile into the YAML
randall ai seed -c projects/vulnlab.yaml --fixture projects/fixtures/ai_seed_fixture.json --update-yaml

# Extra operator hint
randall ai seed -c projects/vulnlab.yaml --prompt "favor ECHO length edges and null bytes"
```

Then fuzz as usual:

```bash
randall fuzz -c projects/vulnlab.yaml
```

## What gets written

| Artifact | Location |
|----------|----------|
| Seed files | `projects/seeds/ai_*.bin` (or `--out-dir`) |
| Dictionary | `projects/dictionaries/ai_<project>.txt` |
| Recipe JSON | `data/corpus/<project>/_ai_recipes/*.json` |

## Doctor

`randall doctor` reports `ai.seed` as **ok** when a key is set, else **warn** (optional — never fails the run).
