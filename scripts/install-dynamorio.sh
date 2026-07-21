#!/usr/bin/env bash
# Download DynamoRIO into tools/dynamorio (gitignored lab dependency).
# Optional for coverage-guided stalking; Randfuzz finds crashes without it.
# IMPORTANT: the download is large (~400MB+) and may take a while on slow networks.
#
# Usage:
#   scripts/install-dynamorio.sh              # fetch latest Linux package for this arch
#   scripts/install-dynamorio.sh --skip       # coverage later / skip for now
#   scripts/install-dynamorio.sh --force      # reinstall even if tools/dynamorio exists
#   scripts/install-dynamorio.sh --tarball /path/to/DynamoRIO-Linux-*.tar.gz
#   scripts/install-dynamorio.sh --version release_11.3.0
#
# After install: tools/dynamorio/bin64/drrun must exist.
# Or keep tools/DynamoRIO-* — Randall auto-detects it. Optional: export DYNAMORIO_HOME=...
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/tools/dynamorio"
TOOLS_DIR="$ROOT/tools"
MARKER="$DEST/bin64/drrun"

SKIP=0
FORCE=0
VERSION=""
TARBALL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --skip|-Skip) SKIP=1 ;;
    --force|-Force) FORCE=1 ;;
    --version|-Version)
      VERSION="${2:-}"
      shift
      ;;
    --tarball|--tar|-ZipPath)
      TARBALL="${2:-}"
      shift
      ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
  shift
done

if [ "$SKIP" -eq 1 ]; then
  echo "Skipping DynamoRIO install (--skip). Coverage is optional; fuzzing works without it."
  exit 0
fi

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) ASSET_PREFIX="DynamoRIO-Linux" ;;
  aarch64|arm64) ASSET_PREFIX="DynamoRIO-AArch64-Linux" ;;
  armv7l|armhf) ASSET_PREFIX="DynamoRIO-ARM-Linux-EABIHF" ;;
  *)
    echo "Unsupported architecture for prebuilt DynamoRIO: $arch" >&2
    echo "Build from source or place a package under tools/ and re-run." >&2
    exit 1
    ;;
esac

has_drrun() {
  local home="$1"
  [ -x "$home/bin64/drrun" ] || [ -f "$home/bin64/drrun" ] || \
    [ -x "$home/bin32/drrun" ] || [ -f "$home/bin32/drrun" ]
}

install_from_extract_root() {
  local inner="$1"
  if ! has_drrun "$inner"; then
    echo "Unexpected layout — expected bin64/drrun under $inner" >&2
    exit 1
  fi
  mkdir -p "$TOOLS_DIR"
  rm -rf "$DEST"
  mv "$inner" "$DEST"
  echo "Installed DynamoRIO to $DEST"
  echo "drrun: $MARKER"
}

extract_tarball() {
  local archive="$1"
  local extract
  extract="$(mktemp -d "${TMPDIR:-/tmp}/dynamorio-extract.XXXXXX")"
  echo "Extracting $archive ..."
  tar -xzf "$archive" -C "$extract"
  local inner
  inner="$(find "$extract" -mindepth 1 -maxdepth 1 -type d | head -n1)"
  if [ -z "$inner" ]; then
    echo "Unexpected archive layout — no top-level directory" >&2
    rm -rf "$extract"
    exit 1
  fi
  install_from_extract_root "$inner"
  rm -rf "$extract"
}

if [ -f "$MARKER" ] && [ "$FORCE" -eq 0 ]; then
  echo "DynamoRIO already installed: $MARKER"
  exit 0
fi

# Already-extracted versioned folder under tools/
if [ "$FORCE" -eq 0 ]; then
  shopt -s nullglob
  for dir in "$TOOLS_DIR"/DynamoRIO-*; do
    [ -d "$dir" ] || continue
    if has_drrun "$dir" && [ "$dir" != "$DEST" ]; then
      echo "Found existing extract: $dir"
      mkdir -p "$TOOLS_DIR"
      rm -rf "$DEST"
      mv "$dir" "$DEST"
      echo "Installed DynamoRIO to $DEST"
      echo "drrun: $MARKER"
      exit 0
    fi
  done
  shopt -u nullglob
fi

mkdir -p "$TOOLS_DIR"

# Local tarball path or auto-detect under tools/
if [ -z "$TARBALL" ]; then
  shopt -s nullglob
  candidates=("$TOOLS_DIR"/${ASSET_PREFIX}-*.tar.gz)
  shopt -u nullglob
  if [ ${#candidates[@]} -gt 0 ]; then
    TARBALL="$(ls -t "${candidates[@]}" | head -n1)"
  fi
fi

if [ -n "$TARBALL" ]; then
  if [ ! -f "$TARBALL" ]; then
    echo "Tarball not found: $TARBALL" >&2
    exit 1
  fi
  echo "Using local tarball: $TARBALL"
  extract_tarball "$TARBALL"
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to download DynamoRIO (or pass --tarball)." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1 && ! command -v jq >/dev/null 2>&1; then
  echo "python3 or jq is required to parse GitHub release metadata." >&2
  exit 1
fi

echo "Fetching DynamoRIO release metadata from GitHub..."
echo "IMPORTANT: large download — may take a while on slow networks."
echo "Or Ctrl+C and manually extract DynamoRIO-Linux-*.tar.gz into tools/dynamorio."

API_URL="https://api.github.com/repos/DynamoRIO/dynamorio/releases/latest"
if [ -n "$VERSION" ]; then
  API_URL="https://api.github.com/repos/DynamoRIO/dynamorio/releases/tags/${VERSION}"
fi

JSON="$(curl -fsSL "$API_URL")"

if command -v jq >/dev/null 2>&1; then
  ASSET_LINE="$(printf '%s' "$JSON" | jq -r --arg p "$ASSET_PREFIX" '
    [.assets[] | select(.name | test("^" + $p + "-.+\\.tar\\.gz$"))]
    | .[0]
    | select(.)
    | "\(.name)\t\(.browser_download_url)\t\(.size // 0)"
  ')"
else
  ASSET_LINE="$(printf '%s' "$JSON" | ASSET_PREFIX="$ASSET_PREFIX" python3 -c '
import json, os, re, sys
prefix = os.environ["ASSET_PREFIX"]
data = json.load(sys.stdin)
pat = re.compile(r"^" + re.escape(prefix) + r"-.+\.tar\.gz$")
for a in data.get("assets", []):
    name = a.get("name") or ""
    if pat.match(name):
        print(f"{name}\t{a.get("browser_download_url", "")}\t{a.get("size") or 0}")
        break
')"
fi

if [ -z "$ASSET_LINE" ] || [ "$ASSET_LINE" = "null" ]; then
  echo "No ${ASSET_PREFIX}-*.tar.gz asset found on the selected release." >&2
  echo "Manual: https://github.com/DynamoRIO/dynamorio/releases" >&2
  exit 1
fi

IFS=$'\t' read -r ASSET_NAME ASSET_URL ASSET_SIZE <<<"$ASSET_LINE"
CACHE="${TMPDIR:-/tmp}/${ASSET_NAME}"

echo "Asset: $ASSET_NAME"
echo "URL:   $ASSET_URL"
echo "Cache: $CACHE"
if [ -n "$ASSET_SIZE" ] && [ "$ASSET_SIZE" != "0" ]; then
  echo "Size:  $ASSET_SIZE bytes (large; slow networks may take many minutes)"
fi
echo
echo "Tips if this is too slow:"
echo "  - Cancel (Ctrl+C), download ${ASSET_PREFIX}-*.tar.gz from"
echo "      https://github.com/DynamoRIO/dynamorio/releases"
echo "    extract, then rename/move the top-level folder to exactly tools/dynamorio"
echo "    so tools/dynamorio/bin64/drrun exists."
echo "  - Or: scripts/install-dynamorio.sh --tarball /path/to/${ASSET_PREFIX}-*.tar.gz"
echo "  - Coverage later: scripts/install-dynamorio.sh --skip"
echo

if [ -f "$CACHE" ] && [ "$FORCE" -eq 0 ] && [ -n "$ASSET_SIZE" ] && [ "$ASSET_SIZE" != "0" ]; then
  got="$(wc -c <"$CACHE" | tr -d ' ')"
  if [ "$got" = "$ASSET_SIZE" ]; then
    echo "Reusing complete download: $CACHE"
    extract_tarball "$CACHE"
    exit 0
  fi
fi

echo "Downloading with curl (progress + resume)..."
curl -L --fail --retry 5 --retry-delay 2 -C - --progress-bar -o "$CACHE" "$ASSET_URL"

if [ -n "$ASSET_SIZE" ] && [ "$ASSET_SIZE" != "0" ]; then
  got="$(wc -c <"$CACHE" | tr -d ' ')"
  if [ "$got" != "$ASSET_SIZE" ]; then
    echo "Downloaded size mismatch: got $got, expected $ASSET_SIZE. Delete $CACHE and retry." >&2
    exit 1
  fi
fi

extract_tarball "$CACHE"
echo "Tarball kept at $CACHE (safe to delete after a successful install)."
