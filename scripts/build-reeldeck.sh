#!/usr/bin/env bash
# Build ReelDeck lab media target (file-format fuzzing).
# Default: plain binary so SIGSEGV/SIGABRT map to 128+n for Randfuzz crash capture.
# Optional: ASAN=1 scripts/build-reeldeck.sh for AddressSanitizer triage builds.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/targets/reeldeck"
mkdir -p "$OUT"
CFLAGS="-O1 -g -fno-omit-frame-pointer -Wall -Wextra -U_FORTIFY_SOURCE"
if [ "${ASAN:-0}" = "1" ]; then
  CFLAGS="$CFLAGS -fsanitize=address"
  echo "Building with AddressSanitizer (ASAN=1)"
else
  echo "Building plain ReelDeck (set ASAN=1 for AddressSanitizer)"
fi
gcc $CFLAGS -o "$OUT/reeldeck" "$OUT/reeldeck.c"
chmod +x "$OUT/reeldeck"
ln -sfn reeldeck "$OUT/reeldeck.exe" 2>/dev/null || cp -f "$OUT/reeldeck" "$OUT/reeldeck.exe"
echo "Built $OUT/reeldeck"
