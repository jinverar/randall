#!/usr/bin/env bash
# Publish a portable Randfuzz lab folder (self-contained, host RID or --rid).
# Counterpart to scripts/publish-standalone.ps1
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-publish/standalone}"
RID="${2:-}"
cd "$ROOT"
ARGS=(pack -o "$OUT")
if [ -n "$RID" ]; then
  ARGS+=(--rid "$RID")
fi
echo "Building portable pack → $OUT ${RID:+(rid=$RID)}"
dotnet run --project src/Randall.Cli -c Release -- "${ARGS[@]}"
echo "Done. See $OUT/start.sh (or start.cmd on Windows packs)."
