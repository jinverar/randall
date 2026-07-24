#!/usr/bin/env bash
# Uninstall Randfuzz lab artifacts from this machine: stop everything first
# (server, CLI fuzz/agent, vuln labs), then remove what install/build scripts
# put in place. Safe by default:
#
#   - Never touches the git clone (src/, docs/, projects/, .git/)
#   - Never removes .NET SDK, apt packages, or system gdb/lldb installs
#   - Only removes tools/ and targets/ content the lab scripts created
#   - data/ is left alone unless --remove-data
#
# Examples:
#   scripts/uninstall-lab.sh
#   scripts/uninstall-lab.sh --what-if
#   scripts/uninstall-lab.sh --force
#   scripts/uninstall-lab.sh --stop-only
#   scripts/uninstall-lab.sh --force --keep-tools
#   scripts/uninstall-lab.sh --force --keep-targets
#   scripts/uninstall-lab.sh --force --remove-data
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FORCE=0
WHATIF=0
KEEP_TOOLS=0
KEEP_TARGETS=0
REMOVE_DATA=0
STOP_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --force|-Force) FORCE=1 ;;
    --what-if|-WhatIf) WHATIF=1 ;;
    --keep-tools|-KeepTools) KEEP_TOOLS=1 ;;
    --keep-targets|-KeepTargets) KEEP_TARGETS=1 ;;
    --remove-data|-RemoveData) REMOVE_DATA=1 ;;
    --stop-only|-StopOnly) STOP_ONLY=1 ;;
    -h|--help)
      sed -n '2,20p' "$0"
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

stop_pids() {
  local sig="${1:-TERM}"
  shift
  local pids
  pids="$(pgrep -f "$@" 2>/dev/null || true)"
  [ -z "$pids" ] && return 0
  if [ "$WHATIF" -eq 1 ]; then
    log "  Would stop ($sig): $* -> $pids"
    return 0
  fi
  # shellcheck disable=SC2086
  kill "-$sig" $pids 2>/dev/null || true
}

stop_dotnet_match() {
  local label="$1"
  local pattern="$2"
  local n=0
  while read -r pid cmd; do
    [ -z "${pid:-}" ] && continue
    case "$cmd" in
      *"$pattern"*)
        if [ "$WHATIF" -eq 1 ]; then
          log "  Would stop PID $pid ($label)"
        else
          kill -TERM "$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
        fi
        n=$((n + 1))
        ;;
    esac
  done < <(ps -eo pid=,args= 2>/dev/null | grep '[d]otnet' || true)
  log "  $label: stopped $n process(es)"
}

stop_port_listeners() {
  local port killed=0
  for port in "$@"; do
    if command -v fuser >/dev/null 2>&1; then
      if [ "$WHATIF" -eq 1 ]; then
        fuser "${port}/tcp" 2>/dev/null && log "  Would kill listener(s) on port $port" || true
      else
        fuser -k "${port}/tcp" 2>/dev/null && killed=$((killed + 1)) || true
      fi
    elif command -v lsof >/dev/null 2>&1; then
      local pids
      pids="$(lsof -ti ":$port" -sTCP:LISTEN 2>/dev/null || true)"
      if [ -n "$pids" ]; then
        if [ "$WHATIF" -eq 1 ]; then
          log "  Would kill listener(s) on port $port: $pids"
        else
          # shellcheck disable=SC2086
          kill -TERM $pids 2>/dev/null || true
          killed=$((killed + 1))
        fi
      fi
    fi
  done
  [ "$killed" -gt 0 ] && log "  Cleared $killed port listener(s)"
}

run_cli_subcommand() {
  local sub="$1"
  local dll
  dll="$(find "$ROOT/src/Randall.Cli/bin" -name 'Randall.Cli.dll' 2>/dev/null | sort | tail -n1 || true)"
  if [ -z "$dll" ]; then
    warn "  Randall.Cli.dll not built - skipping randall $sub"
    return 1
  fi
  if [ "$WHATIF" -eq 1 ]; then
    log "  Would run: dotnet $dll $sub"
    return 0
  fi
  log "  dotnet $(basename "$dll") $sub"
  dotnet "$dll" $sub 2>&1 | sed 's/^/    /' || warn "  randall $sub failed"
}

log "Randfuzz lab uninstaller"
log "  Repo: $ROOT"
[ "$WHATIF" -eq 1 ] && log "  Mode: --what-if (dry run - nothing stopped or deleted)"
log ""

if [ "$WHATIF" -eq 0 ]; then
  log "== Stopping processes =="
  stop_dotnet_match "Randall.Server" "Randall.Server"
  stop_dotnet_match "Randall.Cli" "Randall.Cli"
  stop_pids TERM '[R]andall\.Server' '[R]andall\.Cli'

  log "======== Vuln labs / Target Runtime ========"
  run_cli_subcommand "labs stop-all" || true
  run_cli_subcommand "runtime stop-all" || true

  lab_names=(
    randall-vulnserver randall-vulnhttp randall-vulnftp randall-vulnssh
    randall-vulntftp randall-vulnrpc randall-vulnsmb randall-screamcrash
    vulnlab-basic vulnlab-nx vulnlab-aslr vulnlab-modern
    file-text file-framed reeldeck scream_crash
  )
  for name in "${lab_names[@]}"; do
    if [ "$WHATIF" -eq 1 ]; then
      pgrep -f "$name" >/dev/null 2>&1 && log "  Would stop processes matching: $name" || true
    else
      pkill -TERM -f "$name" 2>/dev/null || true
    fi
  done
  stop_port_listeners 9999 8080 2121 2222 6969 1355 4455 5000
else
  log "== Stopping processes == (skipped for --what-if; use without --what-if to stop)"
fi

if [ "$STOP_ONLY" -eq 1 ]; then
  log ""
  log "-StopOnly requested - tools/ and targets/ left untouched."
  exit 0
fi

log ""
log "== Planning removal =="

plan=()
if [ "$KEEP_TOOLS" -eq 0 ]; then
  [ -d "$ROOT/tools/dynamorio" ] && plan+=("tools/dynamorio (DynamoRIO)")
  while IFS= read -r d; do
    [ -n "$d" ] && plan+=("$d (DynamoRIO extract)")
  done < <(find "$ROOT/tools" -maxdepth 1 -type d -name 'DynamoRIO-*' 2>/dev/null || true)
  while IFS= read -r f; do
    [ -n "$f" ] && plan+=("$f (DynamoRIO tarball)")
  done < <(find "$ROOT/tools" -maxdepth 1 -type f \( -name 'DynamoRIO-*.tar.gz' -o -name 'DynamoRIO-*.zip' \) 2>/dev/null || true)
fi

if [ "$KEEP_TARGETS" -eq 0 ]; then
  for lab in vulnserver vulnhttp vulnftp vulnssh vulntftp vulnrpc vulnsmb \
             vulndrone vulnuas vulnturret vulnmqtt vulnrobot vulnrosbus vulnrobotio vulnai \
             screamcrash file-text file-framed reeldeck vulnlab; do
    dir="$ROOT/targets/$lab"
    if [ -d "$dir" ]; then
      hits="$(find "$dir" -mindepth 1 ! -name '.gitkeep' 2>/dev/null | head -n1 || true)"
      [ -n "$hits" ] && plan+=("targets/$lab/* (built lab binaries)")
    fi
  done
fi

if [ "$REMOVE_DATA" -eq 1 ]; then
  [ -d "$ROOT/data" ] && plan+=("data/ (crash dumps, corpus, runtime state)")
fi

if [ ${#plan[@]} -eq 0 ]; then
  log "Nothing to remove (already clean, or --keep-tools/--keep-targets given)."
  exit 0
fi

log "Will remove:"
for item in "${plan[@]}"; do
  log "  - $item"
done
[ "$KEEP_TOOLS" -eq 1 ] && log "  (tools/ kept - --keep-tools)"
[ "$KEEP_TARGETS" -eq 1 ] && log "  (targets/ kept - --keep-targets)"
[ "$REMOVE_DATA" -eq 0 ] && log "  (data/ kept - pass --remove-data to also wipe crash/corpus/runtime state)"
log ""

if [ "$WHATIF" -eq 1 ]; then
  log "--what-if: no files removed."
  exit 0
fi

if [ "$FORCE" -eq 0 ]; then
  read -r -p "Proceed with removal above? [y/N] " answer
  case "$answer" in
    y|yes|Y|YES) ;;
    *)
      warn "Aborted - no files removed. Re-run with --force to skip this prompt."
      exit 1
      ;;
  esac
fi

log ""
log "== Removing files =="

remove_path() {
  local p="$1"
  [ -e "$p" ] || return 0
  if [ -d "$p" ]; then
    rm -rf "$p"
  else
    rm -f "$p"
  fi
}

if [ "$KEEP_TOOLS" -eq 0 ]; then
  remove_path "$ROOT/tools/dynamorio"
  find "$ROOT/tools" -maxdepth 1 -type d -name 'DynamoRIO-*' -exec rm -rf {} + 2>/dev/null || true
  find "$ROOT/tools" -maxdepth 1 -type f \( -name 'DynamoRIO-*.tar.gz' -o -name 'DynamoRIO-*.zip' \) -delete 2>/dev/null || true
fi

if [ "$KEEP_TARGETS" -eq 0 ]; then
  for lab in vulnserver vulnhttp vulnftp vulnssh vulntftp vulnrpc vulnsmb \
             vulndrone vulnuas vulnturret vulnmqtt vulnrobot vulnrosbus vulnrobotio vulnai \
             screamcrash file-text file-framed reeldeck vulnlab; do
    dir="$ROOT/targets/$lab"
    [ -d "$dir" ] || continue
    find "$dir" -mindepth 1 ! -name '.gitkeep' -exec rm -rf {} + 2>/dev/null || true
  done
fi

if [ "$REMOVE_DATA" -eq 1 ] && [ -d "$ROOT/data" ]; then
  rm -rf "$ROOT/data"
fi

log ""
log "Not touched (by design):"
log "  - git clone source (src/, docs/, projects/, .git/)"
log "  - .NET SDK / apt packages / system gdb, lldb, strace, ..."
[ "$REMOVE_DATA" -eq 0 ] && log "  - data/ (pass --remove-data to also remove crash dumps / corpus / runtime state)"
[ "$KEEP_TOOLS" -eq 1 ] && log "  - tools/ (--keep-tools)"
[ "$KEEP_TARGETS" -eq 1 ] && log "  - targets/ built binaries (--keep-targets)"
log ""
log "Reinstall later:  scripts/install-linux-tools.sh"
log "Rebuild targets:  scripts/build-lab-targets.sh"
