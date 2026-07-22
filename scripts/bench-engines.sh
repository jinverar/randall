#!/usr/bin/env bash
# Engine bake-off scaffold — Randfuzz vs optional AFL++ / honggfuzz.
# Does NOT claim winners; writes data/bench/<stamp>/SUMMARY.md for humans to fill.
# See docs/BENCHMARKS.md.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BUDGET="${BUDGET:-60}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/data/bench/$STAMP"
mkdir -p "$OUT"

HARSH="$ROOT/targets/aflpp-harness/crashy_parse"
HSRC="$ROOT/targets/aflpp-harness/crashy_parse.c"
SEED_DIR="$OUT/seeds"
mkdir -p "$SEED_DIR"
printf 'hello' > "$SEED_DIR/seed0"
printf 'x!y' > "$SEED_DIR/seed_bang"

echo "==> Bake-off stamp=$STAMP budget=${BUDGET}s"
echo "    output: $OUT"

if [ ! -x "$HARSH" ]; then
  echo "==> Building crashy_parse harness"
  if command -v afl-clang-fast >/dev/null 2>&1; then
    afl-clang-fast -O2 -o "$HARSH" "$HSRC"
  else
    gcc -O2 -o "$HARSH" "$HSRC"
    echo "    (built with gcc — AFL++ may want -Q / binary-only)"
  fi
fi

# --- Randfuzz (always) ---
RAND_PROJ="$OUT/randall-bench.yaml"
cat > "$RAND_PROJ" <<YAML
name: bench-randall
kind: file
target:
  executable: $HARSH
  args: ["{file}"]
  timeoutMs: 2000
transport:
  type: file
fuzz:
  engine: randall
  maxIterations: 5000
  corpusDir: $OUT/randall/corpus
  crashesDir: $OUT/randall/crashes
seeds:
  - $SEED_DIR/seed0
  - $SEED_DIR/seed_bang
mutators: [bitflip, havoc, interesting, insert, expand, truncate]
YAML

echo "==> Randfuzz engine (${BUDGET}s wall / iter cap)"
mkdir -p "$OUT/randall/corpus" "$OUT/randall/crashes"
set +e
timeout "$BUDGET" dotnet run -c Release --project src/Randall.Cli --no-build -- \
  fuzz -c "$RAND_PROJ" >"$OUT/randall/fuzz.log" 2>&1
RC_RAND=$?
set -e
RAND_CRASHES=$(find "$OUT/randall/crashes" -type f ! -name '*.jsonl' 2>/dev/null | wc -l | tr -d ' ')

# --- AFL++ (optional) ---
RC_AFL="skipped"
AFL_CRASHES="—"
if command -v afl-fuzz >/dev/null 2>&1; then
  echo "==> AFL++ afl-fuzz (${BUDGET}s)"
  mkdir -p "$OUT/aflpp"
  set +e
  timeout "$BUDGET" afl-fuzz -i "$SEED_DIR" -o "$OUT/aflpp" -V "$BUDGET" -- "$HARSH" @@ \
    >"$OUT/aflpp/fuzz.log" 2>&1
  RC_AFL=$?
  set -e
  AFL_CRASHES=$(find "$OUT/aflpp" -path '*/crashes/*' -type f ! -name 'README*' 2>/dev/null | wc -l | tr -d ' ')
else
  echo "==> AFL++ skipped (afl-fuzz not on PATH)"
fi

# --- honggfuzz (optional) ---
RC_HF="skipped"
HF_CRASHES="—"
if command -v honggfuzz >/dev/null 2>&1; then
  echo "==> honggfuzz (${BUDGET}s)"
  mkdir -p "$OUT/honggfuzz/crashes" "$OUT/honggfuzz/corpus"
  set +e
  timeout "$BUDGET" honggfuzz -t "$BUDGET" -i "$SEED_DIR" -o "$OUT/honggfuzz/corpus" \
    --crashdir "$OUT/honggfuzz/crashes" -- "$HARSH" ___FILE___ \
    >"$OUT/honggfuzz/fuzz.log" 2>&1
  RC_HF=$?
  set -e
  HF_CRASHES=$(find "$OUT/honggfuzz/crashes" -type f 2>/dev/null | wc -l | tr -d ' ')
else
  echo "==> honggfuzz skipped (not on PATH)"
fi

SUMMARY="$OUT/SUMMARY.md"
cat > "$SUMMARY" <<MD
# Bake-off $STAMP

Budget: **${BUDGET}s** wall each · Host: \`$(uname -s)-$(uname -m)\` · Harness: \`targets/aflpp-harness/crashy_parse\`

| Engine | Exit/status | Unique crash files (approx) | Log |
|--------|-------------|-----------------------------|-----|
| Randfuzz | $RC_RAND | $RAND_CRASHES | \`randall/fuzz.log\` |
| AFL++ | $RC_AFL | $AFL_CRASHES | \`aflpp/fuzz.log\` |
| honggfuzz | $RC_HF | $HF_CRASHES | \`honggfuzz/fuzz.log\` |

Fill exec/s and edges by hand from the logs, then copy into docs/BENCHMARKS.md.

**Reminder:** crash counts alone are not a ranking — see docs/BENCHMARKS.md rules.
MD

echo
echo "Done. Summary → $SUMMARY"
cat "$SUMMARY"
