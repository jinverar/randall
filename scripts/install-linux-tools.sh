#!/usr/bin/env bash
# Install the Linux fuzzing / triage toolchain — the cross-platform counterpart to the Windows
# scripts/install-lab-tools.ps1 (Sysinternals + WinDbg). Installs the vendor-neutral Unix tools
# Randfuzz's doctor looks for, plus GEF (the recommended gdb enhancement). Idempotent: safe to
# re-run; already-present tools are skipped by the package manager.
#
# Usage:
#   scripts/install-linux-tools.sh           # core triage/observation toolchain + GEF
#   scripts/install-linux-tools.sh --engines # also install optional AFL++ (external adapter)
#
# Optional coverage-guided ENGINE adapters (AFL++/honggfuzz) are NOT installed by default —
# Randfuzz's own engine is the default; enable them only if you explicitly want that adapter.
set -euo pipefail

WITH_ENGINES=0
[ "${1:-}" = "--engines" ] && WITH_ENGINES=1

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 && SUDO="sudo"
fi

if command -v apt-get >/dev/null 2>&1; then
  echo "==> apt-get: core Linux triage/observation toolchain"
  $SUDO apt-get update -y
  # gdb/lldb: crash triage · strace/ltrace: syscall/library trace · tcpdump: packet capture
  # linux-tools*: perf · valgrind: memory errors · clang/llvm: ASan/UBSan sanitizer builds
  $SUDO apt-get install -y \
    gdb lldb strace ltrace tcpdump valgrind clang llvm build-essential \
    linux-tools-common linux-tools-generic || true
  if [ "$WITH_ENGINES" -eq 1 ]; then
    echo "==> apt-get: optional external engine adapter (AFL++)"
    $SUDO apt-get install -y afl++ || echo "afl++ not in apt — build AFLplusplus from source if desired"
  fi
elif command -v dnf >/dev/null 2>&1; then
  echo "==> dnf: core Linux triage/observation toolchain"
  $SUDO dnf install -y gdb lldb strace ltrace tcpdump valgrind clang llvm perf gcc make || true
else
  echo "No supported package manager (apt-get/dnf) found — install gdb/strace/tcpdump/valgrind/clang manually." >&2
fi

# GEF — modern, actively-maintained gdb enhancement (preferred over PEDA). Detected by the doctor.
if command -v gdb >/dev/null 2>&1 && [ ! -f "$HOME/.gdbinit-gef.py" ]; then
  echo "==> installing GEF (gdb enhancement)"
  if curl -fsSL https://raw.githubusercontent.com/hugsy/gef/main/gef.py -o "$HOME/.gdbinit-gef.py"; then
    grep -q ".gdbinit-gef.py" "$HOME/.gdbinit" 2>/dev/null || echo "source $HOME/.gdbinit-gef.py" >> "$HOME/.gdbinit"
    echo "    GEF installed to ~/.gdbinit-gef.py"
  else
    echo "    GEF download failed (offline?) — install later: bash -c \"\$(curl -fsSL https://gef.blah.cat/sh)\""
  fi
fi

echo
echo "Optional — DynamoRIO coverage (large download; not installed by this script):"
echo "  scripts/install-dynamorio.sh"
echo
echo "Verify with the doctor (Linux scope):"
echo "  dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml --platform linux"
