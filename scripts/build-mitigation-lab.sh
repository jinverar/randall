#!/usr/bin/env bash
# Build the Randall VulnLab native service at several exploit-mitigation tiers so learners can go
# from a trivially exploitable overflow up to a modern hardened binary — "basic -> advanced".
#
# Tiers (same source, different compiler/linker hardening):
#   basic   no canary, executable stack (DEP/NX off), no PIE   -> classic ret-overwrite
#   nx      NX/DEP on (default), no canary, no PIE             -> ret2libc / ROP territory
#   aslr    NX on + PIE (position independent -> ASLR)          -> add an info leak
#   modern  canary + NX + PIE + full RELRO + FORTIFY + -O2      -> all modern tweaks on
#
# ASLR itself is a RUNTIME kernel setting (see scripts note): toggle system-wide with
#   sudo sysctl kernel.randomize_va_space=2   # on (full)   / =0 off
# or per-process with `setarch -R ./vulnlab-aslr` to disable ASLR for one run.
#
# Usage: scripts/build-mitigation-lab.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/targets/vulnlab/vulnlab.c"
OUT="$ROOT/targets/vulnlab"
CC="${CC:-gcc}"

[ -f "$SRC" ] || { echo "source not found: $SRC" >&2; exit 1; }
command -v "$CC" >/dev/null 2>&1 || { echo "$CC not found — apt install build-essential" >&2; exit 1; }
mkdir -p "$OUT"

# Common: keep the vulnerable strcpy/printf patterns compilable (warnings, not errors).
COMMON="-w"

echo "==> basic   (no canary, execstack/NX off, no PIE)"
$CC $COMMON -O0 -fno-stack-protector -z execstack -no-pie -D_FORTIFY_SOURCE=0 \
    "$SRC" -o "$OUT/vulnlab-basic"

echo "==> nx      (NX/DEP on, no canary, no PIE)"
$CC $COMMON -O0 -fno-stack-protector -no-pie -D_FORTIFY_SOURCE=0 \
    "$SRC" -o "$OUT/vulnlab-nx"

echo "==> aslr    (NX on + PIE/ASLR, no canary)"
$CC $COMMON -O0 -fno-stack-protector -fPIE -pie -D_FORTIFY_SOURCE=0 \
    "$SRC" -o "$OUT/vulnlab-aslr"

echo "==> modern  (canary + NX + PIE + full RELRO + FORTIFY, -O2)"
$CC $COMMON -O2 -fstack-protector-all -fPIE -pie -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 \
    "$SRC" -o "$OUT/vulnlab-modern"

chmod +x "$OUT"/vulnlab-* 2>/dev/null || true

echo
echo "Built tiers in $OUT :"
for t in basic nx aslr modern; do echo "  vulnlab-$t"; done
echo
echo "Inspect mitigations:   dotnet run --project src/Randall.Cli -- checksec --exe targets/vulnlab/vulnlab-modern"
echo "Fuzz the basic tier:   dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnlab.yaml"
echo "Current ASLR state:    cat /proc/sys/kernel/randomize_va_space   (2=full,1=partial,0=off)"
