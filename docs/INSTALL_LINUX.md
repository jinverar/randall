# Install Randfuzz on Linux

Randfuzz began as a Windows fuzzer; it now runs on **Linux too**. The engine (generation +
coverage stalking), CLI, web UI, and in-process harnesses are cross-platform .NET 8. This guide
sets up a Linux lab. For Windows, see [INSTALL_WINDOWS.md](INSTALL_WINDOWS.md).

> Pick your fuzzing platform in the UI (sidebar **Auto / Windows / Linux**) or with
> `randall doctor --platform linux`. The doctor then shows only that OS's tooling.

## 1. Prerequisites

- **.NET 8 SDK** — build + run. Ubuntu: `sudo apt-get install -y dotnet-sdk-8.0`
  (or the Microsoft feed). Verify: `dotnet --version`.
- **git**, and a normal build toolchain (`build-essential`).

## 2. Clone + build

```bash
git clone https://github.com/jinverar/randall.git
cd randall
dotnet build Randall.sln
```

## 3. Install the Linux toolchain (optional but recommended)

The Unix counterparts to the Windows Sysinternals/WinDbg stack — used for tracing and crash triage.
Randfuzz's `doctor` detects these; none are required to fuzz.

```bash
scripts/install-linux-tools.sh            # gdb, lldb, strace, ltrace, tcpdump, valgrind, clang + GEF
scripts/install-linux-tools.sh --engines  # also install AFL++ (optional external adapter)
```

| Tool | Role | Windows counterpart |
|------|------|---------------------|
| `gdb` / `lldb` | attach + core-dump crash triage | WinDbg / cdb |
| **GEF** | enhanced gdb (preferred; pwndbg/peda also detected) | — |
| `strace` / `ltrace` | syscall / library-call trace | Procmon |
| `tcpdump` | packet capture | pktmon |
| `perf` | sampling profile | ETW / WPR |
| `valgrind` | memory-error detection | Page Heap (partial) |
| `clang` | ASan/UBSan sanitizer builds | — |
| `afl-fuzz` / `honggfuzz` | **optional** external engine adapters (like DynamoRIO) | — |
| **DynamoRIO** (`drrun` + `drcov`) | **optional** coverage-guided stalking (`edges` / `novel`) | same (Windows zip) |

> **Own engine by default.** AFL++/honggfuzz are optional adapters, never required — Randfuzz's own
> generation + stalk engine drives fuzzing unless you explicitly opt into an adapter per project.

### Optional — DynamoRIO (edge coverage on Linux)

Coverage is optional. Without it, Linux stalking still works via **corpus-novelty** (`corpus+`).
Install DynamoRIO when you want real `edges` / `novel` counts (same drcov backend as Windows).

```bash
scripts/install-dynamorio.sh              # large download; may take a while
# or: scripts/install-dynamorio.sh --tarball ~/Downloads/DynamoRIO-Linux-*.tar.gz
# skip for now: scripts/install-dynamorio.sh --skip
export DYNAMORIO_HOME="$(pwd)/tools/dynamorio"   # optional; auto-detected under tools/
```

Expect `tools/dynamorio/bin64/drrun`. Verify:

```bash
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml --platform linux
# dynamorio row should be ok → path to drrun
```

## 4. Build the lab targets (Linux apphosts)

The stock `projects/*.yaml` reference Windows `.exe` paths; the same .NET targets build to an
extensionless apphost on Linux, and Randfuzz resolves either automatically.

```bash
scripts/build-lab-targets.sh              # all .NET lab targets
scripts/build-lab-targets.sh vulnserver   # just one
scripts/build-mitigation-lab.sh           # native vulnlab tiers (SIGSEGV practice)
# AFL FORKSRV demo (target + native helper):
gcc -O0 -g -o targets/forksrv-demo/forksrv_demo targets/forksrv-demo/forksrv_demo.c
gcc -O2 -o targets/forksrv-demo/randall_forksrv_helper targets/forksrv-demo/randall_forksrv_helper.c
```

## 5. Preflight + fuzz

```bash
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml   # Linux-scoped checks
dotnet run --project src/Randall.Cli -- fuzz   -c projects/vulnserver.yaml   # TCP network fuzz
```

In-process (no external target, fully cross-platform):

```bash
dotnet build targets/Randall.HarnessDemo
dotnet run --project src/Randall.Cli -- fuzz -c projects/harness-demo.yaml
```

Web UI:

```bash
dotnet run --project src/Randall.Server --urls http://127.0.0.1:5000
```

## 6. Linux heap-bug triage (basic → advanced)

Randfuzz classifies Linux memory-corruption crashes into named exploitation primitives — from plain
overflows to **tcache poisoning / double-free** — with a difficulty tier and training-audience tag
(PEN-301 → GXPN / SANS-760). It arms glibc's own heap hardening so latent bugs abort immediately.

```bash
# Run a target under glibc heap hardening and classify any crash:
randall heaptriage --exe ./my_target --input crashing_input.bin

# Or analyze an existing core dump with gdb + GEF:
randall heaptriage --exe ./my_target --core /path/to/core

# Or classify a captured stderr / ASan log:
randall heaptriage --text-file crash.log
```

Example classification (real glibc abort):

```
══ Memory-corruption finding ══
 primitive : tcache double-free
 category  : tcache-double-free   CWE-415
 severity  : critical
 tier      : advanced
 audience  : GXPN / SANS-760 (advanced heap exploitation)
```

For the sharpest signal, build the target under AddressSanitizer:
`clang -g -fsanitize=address,undefined target.c -o target` — ASan reports (UAF, heap/stack overflow,
double-free) are classified too.

## Crash cores (Linux Scream counterpart)

When a native target dies with a fatal signal (e.g. SIGSEGV → exit 139), Randfuzz copies the kernel
core into `data/crashes/<project>/dumps/*.core` (plus a `.linux.json` sidecar). Enable local cores:

```bash
ulimit -c unlimited
sudo sysctl -w kernel.core_pattern=/tmp/core.%e.%p
```

With `fuzz.autoAnalyzeCrash` (default **on**), each captured core also gets:
- `*_analysis.json` — signal / fault hint (catalog-compatible)
- `*_heap_triage.json` — gdb backtrace + heap/stack classifier
- `*_exploit_guide.json` — mitigation + next-step playbook (no payloads)

Manual: `randall heaptriage --exe <p> --core <core>` or `randall exploit guide --exe <p> --core <core>`.

## What is Windows-only

These features only execute on Windows (the doctor hides them under the Linux platform): minidumps
via the Scream watcher, Page Heap/gflags, pktmon, ETW/WPR, Procmon, WinDbg/cdb, and the Sysinternals
snapshots. On Linux the counterparts above (gdb/GEF, core capture, strace, tcpdump, perf, valgrind,
ASan) fill the same roles. **DynamoRIO coverage** is available on both OSes when installed
(`install-dynamorio.sh` on Linux, `install-dynamorio.ps1` on Windows).
