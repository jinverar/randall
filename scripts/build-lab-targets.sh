#!/usr/bin/env bash
# Build Randall's .NET lab targets on Linux/macOS — the cross-platform counterpart to the
# per-target build-*.ps1 scripts. Publishes each target's apphost (extensionless) into
# targets/<name>/randall-<name> so the stock projects/<name>.yaml profiles resolve on Linux
# (the .exe path in the YAML also matches the extensionless apphost via ExecutableResolver).
#
# Usage:
#   scripts/build-lab-targets.sh            # build all .NET lab targets
#   scripts/build-lab-targets.sh vulnserver # build one target
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Framework-dependent apphost (requires the installed .NET runtime; no self-contained bloat).
RID="linux-x64"
case "$(uname -s)-$(uname -m)" in
  Linux-aarch64|Linux-arm64) RID="linux-arm64" ;;
  Darwin-arm64)              RID="osx-arm64" ;;
  Darwin-x86_64)             RID="osx-x64" ;;
esac

# name -> project directory (AssemblyName is randall-<name>, matching projects/<name>.yaml)
TARGETS=(
  "vulnserver:Randall.Vulnserver"
  "vulnhttp:Randall.VulnHttp"
  "vulnftp:Randall.VulnFtp"
  "vulntftp:Randall.VulnTftp"
  "vulnssh:Randall.VulnSsh"
  "vulnrpc:Randall.VulnRpc"
  "vulnsmb:Randall.VulnSmb"
  "vulndrone:Randall.VulnDrone"
  "vulnmqtt:Randall.VulnMqtt"
  "vulnrobot:Randall.VulnRobot"
  "vulnrosbus:Randall.VulnRosBus"
  "vulnrobotio:Randall.VulnRobotIo"
  "vulnai:Randall.VulnAi"
  "screamcrash:Randall.ScreamCrash"
)

want="${1:-all}"
built=0
for entry in "${TARGETS[@]}"; do
  name="${entry%%:*}"
  proj="${entry##*:}"
  [ "$want" != "all" ] && [ "$want" != "$name" ] && continue

  csproj="$ROOT/targets/$proj/$proj.csproj"
  out="$ROOT/targets/$name"
  if [ ! -f "$csproj" ]; then
    echo "skip $name — $csproj not found"
    continue
  fi

  echo "==> building randall-$name ($RID) -> $out"
  mkdir -p "$out"
  dotnet publish "$csproj" -c Release -r "$RID" --self-contained false -o "$out" /p:UseAppHost=true
  chmod +x "$out/randall-$name" 2>/dev/null || true
  built=$((built + 1))
done

if [ "$built" -eq 0 ]; then
  echo "No targets matched '$want'. Known: vulnserver vulnhttp vulnftp vulntftp vulnssh vulnrpc vulnsmb vulndrone vulnmqtt vulnrobot vulnrosbus vulnrobotio vulnai screamcrash (+ reeldeck via build-reeldeck.sh)" >&2
  exit 1
fi

# Native file labs (optional; need gcc)
if [ "$want" = "all" ] || [ "$want" = "reeldeck" ]; then
  if [ -f "$ROOT/scripts/build-reeldeck.sh" ]; then
    echo "==> building reeldeck (native)"
    bash "$ROOT/scripts/build-reeldeck.sh" || echo "[!] reeldeck build skipped/failed (need gcc)"
  fi
fi
if [ "$want" = "all" ] || [ "$want" = "file-text" ]; then
  bash "$ROOT/scripts/build-file-text.sh" || echo "[!] file-text build skipped/failed (need gcc)"
fi
if [ "$want" = "all" ] || [ "$want" = "file-framed" ]; then
  bash "$ROOT/scripts/build-file-framed.sh" || echo "[!] file-framed build skipped/failed (need gcc)"
fi

echo
echo "Done ($built target(s)). Preflight + fuzz, e.g.:"
echo "  dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml"
echo "  dotnet run --project src/Randall.Cli -- fuzz   -c projects/vulnserver.yaml"
echo "  scripts/build-file-text.sh && dotnet run --project src/Randall.Cli -- fuzz -c projects/file-text.yaml"
echo "  scripts/build-reeldeck.sh && dotnet run --project src/Randall.Cli -- fuzz -c projects/reeldeck.yaml"
