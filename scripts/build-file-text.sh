#!/usr/bin/env bash
# Build in-repo file-text lab target (projects/file-text.yaml).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/targets/file-text"
mkdir -p "$OUT"
gcc -O1 -g -fno-omit-frame-pointer -Wall -Wextra -U_FORTIFY_SOURCE \
  -o "$OUT/file-text" "$OUT/file_text.c"
chmod +x "$OUT/file-text"
ln -sfn file-text "$OUT/file-text.exe" 2>/dev/null || cp -f "$OUT/file-text" "$OUT/app.exe"
cp -f "$OUT/file-text" "$OUT/app" 2>/dev/null || true
# YAML historically pointed at app.exe — keep both names.
cp -f "$OUT/file-text" "$OUT/app.exe" 2>/dev/null || ln -sfn file-text "$OUT/app.exe"
echo "Built $OUT/file-text (+ app.exe alias)"
