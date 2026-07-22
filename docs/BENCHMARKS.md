# Engine bake-off (Randfuzz vs AFL++ / honggfuzz / libFuzzer)

Honest positioning: Randfuzz owns **structure + sessions + oracles + triage UX**.
AFL++ / honggfuzz own **raw coverage throughput** on Linux file harnesses.
Until numbers are published below, do **not** claim Randfuzz “beats AFL++.”

This doc + `scripts/bench-engines.sh` are the bake-off scaffold. Fill the results
table after you run the script on a quiet Linux box.

## Shared harness

Use the same entrypoint, seeds, and wall-clock budget:

| Piece | Path |
|-------|------|
| Harness source | `targets/aflpp-harness/crashy_parse.c` |
| Randfuzz profile | `projects/aflpp-smoke.yaml` (or local copy) |
| In-repo file demos | `projects/file-text.yaml`, `projects/file-framed.yaml`, `projects/reeldeck.yaml` |

Build the AFL harness:

```bash
# Prefer AFL instrumentation when available
afl-clang-fast -O2 -o targets/aflpp-harness/crashy_parse targets/aflpp-harness/crashy_parse.c
# Fallback:
# gcc -O2 -o targets/aflpp-harness/crashy_parse targets/aflpp-harness/crashy_parse.c
```

## Run the bake-off scaffold

```bash
chmod +x scripts/bench-engines.sh
# Default: 60s each engine that is installed
scripts/bench-engines.sh
# Custom budget (seconds):
BUDGET=120 scripts/bench-engines.sh
```

The script writes under `data/bench/<stamp>/`:

- `randall/` — Randfuzz engine corpus/crashes summary
- `aflpp/` — only if `afl-fuzz` is on PATH
- `honggfuzz/` — only if `honggfuzz` is on PATH
- `SUMMARY.md` — machine-filled stub for the table below

## Results table (fill after a run)

Sample (not a ranking — short budget on a cloud box): [bench-samples/SAMPLE_SUMMARY.md](bench-samples/SAMPLE_SUMMARY.md).

| Engine | Host | Budget | Exec/s (approx) | Unique crashes | Notes |
|--------|------|--------|-----------------|----------------|-------|
| Randfuzz (`fuzz.engine: randall`) | | | | | Structure + mutators |
| AFL++ (`afl-fuzz`) | | | | | Coverage grind |
| honggfuzz | | | | | Coverage grind |
| libFuzzer | | | | | Optional; not wired as `fuzz.engine` yet |

**Stalk profiles (in-engine only):** `randall stalk bench -c projects/….yaml` compares
`basic` / `fuzz` / `fuzzier` — not an external-engine bake-off. See [STALKING.md](STALKING.md).

## Rules for claims

1. Same binary (or same source built the same way), same seed corpus, same wall time.
2. Publish the `data/bench/<stamp>/SUMMARY.md` (or paste the table) — no vibes-only rankings.
3. Separate “first crash time” from “unique crashes @ budget” and from “edges” (needs coverage).
4. Windows labs: run Randfuzz column only; AFL++/honggfuzz stay Linux adapters ([MATURITY.md](MATURITY.md)#6).

Related: [ENGINE_ADAPTERS.md](ENGINE_ADAPTERS.md) · [MATURITY.md](MATURITY.md) · [FUZZING.md](FUZZING.md)
