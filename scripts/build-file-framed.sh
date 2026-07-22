#!/usr/bin/env bash
# Build in-repo file-framed lab target (projects/file-framed.yaml).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/targets/file-framed"
mkdir -p "$OUT"
gcc -O1 -g -fno-omit-frame-pointer -Wall -Wextra -U_FORTIFY_SOURCE \
  -o "$OUT/file-framed" "$OUT/file_framed.c"
chmod +x "$OUT/file-framed"
cp -f "$OUT/file-framed" "$OUT/app.exe" 2>/dev/null || ln -sfn file-framed "$OUT/app.exe"
cp -f "$OUT/file-framed" "$OUT/app" 2>/dev/null || true
echo "Built $OUT/file-framed (+ app.exe alias)"
