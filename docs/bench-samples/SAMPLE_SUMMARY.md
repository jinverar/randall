# Bake-off sample (not a ranking)

Captured with `BUDGET=15 scripts/bench-engines.sh` on a Linux cloud box (2026-07-22).

**Host:** Linux-x86_64 · **Harness:** `targets/aflpp-harness/crashy_parse` (gcc build) · **Budget:** 15s wall each

| Engine | Exit/status | Unique crash `.bin` files (approx) | Notes |
|--------|-------------|-----------------------------|-------|
| Randfuzz (`fuzz.engine: randall`) | timeout (wall) | 61 | Mutators find `!` quickly; count is unique crash bins |
| AFL++ (`afl-fuzz`) | timeout (wall) | 2 | Present on PATH; short budget |
| honggfuzz | skipped | — | Not installed |

**How to reproduce**

```bash
BUDGET=60 scripts/bench-engines.sh
# → data/bench/<stamp>/SUMMARY.md  (gitignored; paste cleaned rows here or into BENCHMARKS.md)
```

**Rules:** same harness, same seeds, same wall time. Crash counts alone are not a winner — see [BENCHMARKS.md](../BENCHMARKS.md).
