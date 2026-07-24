#!/usr/bin/env bash
# Pull latest Randall source and rebuild CLI, Server, and lab targets.
# Does NOT re-download DynamoRIO or apt packages unless --install-tools.
#
# Examples:
#   scripts/update-lab.sh
#   scripts/update-lab.sh --install-tools
#   scripts/update-lab.sh --skip-pull
#   scripts/update-lab.sh --skip-lab-targets
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$ROOT/scripts"

INSTALL_TOOLS=0
SKIP_PULL=0
SKIP_LAB_TARGETS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --install-tools|-InstallTools) INSTALL_TOOLS=1 ;;
    --skip-pull|-SkipPull) SKIP_PULL=1 ;;
    --skip-lab-targets|-SkipLabTargets) SKIP_LAB_TARGETS=1 ;;
    -h|--help)
      sed -n '2,10p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
  shift
done

log() { printf '%s\n' "$*"; }
warn() { printf ' [!] %s\n' "$*" >&2; }
err() { printf '[x] %s\n' "$*" >&2; }

cd "$ROOT"
log "Randfuzz lab update (repo: $ROOT)"

if [ ! -d "$ROOT/.git" ]; then
  err "Not a git repository: $ROOT"
  warn "One-time setup - clone instead of a GitHub ZIP:"
  log "  git clone https://github.com/jinverar/randall.git"
  log "  cd randall"
  log "  scripts/install-linux-tools.sh"
  exit 1
fi

if pgrep -af '[R]andall\.Server' >/dev/null 2>&1; then
  warn ""
  warn "Randall.Server may be running. Stop it before rebuild if DLLs/binaries are locked."
  warn "Ctrl+C in the server terminal, then re-run this script."
fi

if [ "$SKIP_PULL" -eq 0 ]; then
  log ""
  log "======== git pull ========"
  git -C "$ROOT" pull --ff-only
else
  log ""
  warn "======== git pull ======== (skipped)"
fi

log ""
log "======== dotnet build ========"
dotnet build "$ROOT/Randall.sln"

if [ "$SKIP_LAB_TARGETS" -eq 0 ]; then
  log ""
  log "======== lab targets ========"
  bash "$SCRIPTS/build-lab-targets.sh"
else
  log ""
  warn "======== lab targets ======== (skipped)"
fi

if [ "$INSTALL_TOOLS" -eq 1 ]; then
  log ""
  log "======== install-linux-tools (--install-tools) ========"
  bash "$SCRIPTS/install-linux-tools.sh" || warn "install-linux-tools reported errors - see summary above."
else
  log ""
  log "Tool installs skipped (tools/ and apt packages preserved across pulls)."
  log "Re-run with --install-tools if needed."
fi

log ""
log "Update complete."
log "Restart the web UI if it was running:"
log "  dotnet run --project src/Randall.Server --urls http://127.0.0.1:5000"
log "Optional preflight: dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml --platform linux"
