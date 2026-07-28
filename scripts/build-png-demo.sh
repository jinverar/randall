#!/usr/bin/env bash
# Build png-demo lab target: cold binary + native harness shared lib.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/targets/png-demo"
mkdir -p "$OUT"
CFLAGS=(-O1 -g -fno-omit-frame-pointer -Wall -Wextra -U_FORTIFY_SOURCE)
gcc "${CFLAGS[@]}" -o "$OUT/png-demo" "$OUT/png_parse.c" "$OUT/png_demo.c"
cp -f "$OUT/png-demo" "$OUT/app"
gcc "${CFLAGS[@]}" -shared -fPIC -o "$OUT/png-demo.so" "$OUT/png_parse.c" "$OUT/png_fuzz.c"
echo "Built $OUT/png-demo (+ app) and png-demo.so"
