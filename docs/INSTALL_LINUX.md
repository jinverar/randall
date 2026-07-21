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

> **Own engine by default.** AFL++/honggfuzz are optional adapters, never required — Randfuzz's own
> generation + stalk engine drives fuzzing unless you explicitly opt into an adapter per project.

## 4. Build the lab targets (Linux apphosts)

The stock `projects/*.yaml` reference Windows `.exe` paths; the same .NET targets build to an
extensionless apphost on Linux, and Randfuzz resolves either automatically.

```bash
scripts/build-lab-targets.sh              # all .NET lab targets
scripts/build-lab-targets.sh vulnserver   # just one
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

## What is Windows-only

These features only execute on Windows (the doctor hides them under the Linux platform): minidumps
via the Scream watcher, Page Heap/gflags, pktmon, ETW/WPR, Procmon, WinDbg/cdb, and the Sysinternals
snapshots. On Linux the counterparts above (gdb/GEF, strace, tcpdump, perf, valgrind, ASan) fill the
same roles.
