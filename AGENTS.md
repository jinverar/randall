# AGENTS.md

## Git workflow rule (user-mandated)

- NEVER commit, push, or merge to `main`. `main` is the protected release branch.
- Do all programming on the `development` branch (active work) and the `test` branch (validation/testing). Push work to these branches only.
- When opening pull requests, always create them as **draft** and target `main`. Do not merge them.
- The repository owner reviews the accumulated changes and merges into `main` themselves (planned for end of week) once they feel secure about the changes.

## Cursor Cloud specific instructions

### What this is
Randfuzz ("Randall") is a Windows-oriented fuzzer written entirely in C#/.NET 8 (`net8.0`). One solution, `Randall.sln`, with 5 core projects under `src/` (`Randall.Core`, `Randall.Contracts`, `Randall.Infrastructure`, `Randall.Server`, `Randall.Cli`) plus optional lab-target apps under `targets/`. Only external NuGet dependency is YamlDotNet; storage is flat JSON/JSONL files under `data/` (no database, no Node, no Docker).

### Environment: this VM is Linux, the product is Windows-focused
- The build and the two entrypoints (CLI + ASP.NET Core server) are cross-platform and run fine on this Linux VM.
- Windows-only features are expected to soft-skip or be unavailable here: minidumps, Page Heap/gflags, pktmon, ETW/WPR, DynamoRIO coverage, and the PowerShell-built native `.exe` lab targets (e.g. `targets/vulnserver/randall-vulnserver.exe`). `dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml` reporting these as `[!]` missing is normal on Linux, not a setup failure.
- The `scripts/*.ps1` installers/build scripts are Windows/PowerShell only; do not run them here.

### Build / run / test
- Build everything: `dotnet build Randall.sln` (run from repo root; restores YamlDotNet automatically).
- Web console (primary product surface): `dotnet run --project src/Randall.Server --urls http://127.0.0.1:5000` then open `http://127.0.0.1:5000`. REST API is under `/api/*` (e.g. `/api/health`, `/api/targets`, `/api/fuzz/start`).
- CLI: `dotnet run --project src/Randall.Cli -- <command>` (e.g. `targets`, `doctor -c projects/vulnserver.yaml`, `fuzz -c projects/<profile>.yaml`).
- There is no automated test suite (no xunit/nunit/MSTest projects). "Testing" here means building + running the CLI/server and exercising a fuzz run.

### Fuzzing on Linux (cross-platform)
- The stock `projects/*.yaml` reference Windows `.exe` paths, but the same .NET lab targets build to an extensionless apphost on Linux and `ExecutableResolver` resolves either. Build them with `scripts/build-lab-targets.sh [name]` (publishes to `targets/<name>/randall-<name>`), then `doctor`/`fuzz` the stock profile works on Linux (verified: vulnserver fuzz finds crashes over TCP).
- The fully cross-platform, no-external-target path is the in-process managed harness: `dotnet build targets/Randall.HarnessDemo` then `dotnet run --project src/Randall.Cli -- fuzz -c projects/harness-demo.yaml` (reliably finds crashes, artifacts in `data/crashes/harness-demo/`).
- YAML `target.harness`/`executable` paths resolve relative to the YAML file's directory (`projects/`), not the process CWD.

### Platform selector + Linux toolchain
- Fuzzing platform is selectable (UI sidebar Auto/Windows/Linux, or `doctor --platform`, API `/api/doctor?platform=` and `/api/platform`). `doctor` tags each check `windows`/`linux`/`cross` and shows only the selected OS's rows — so on Linux the Windows tool noise is hidden and the Linux toolchain appears.
- Linux triage tools are installed via `scripts/install-linux-tools.sh` (gdb/lldb/strace/ltrace/tcpdump/valgrind/clang + GEF). GEF is the preferred gdb enhancement; detection also finds pwndbg/peda. AFL++/honggfuzz are OPTIONAL external engine adapters (like DynamoRIO) — never the default.
- `randall heaptriage --exe <p> [--input f | --core f | --text-file f]` runs a target under glibc heap hardening (or analyzes a core with gdb+GEF) and classifies memory-corruption crashes (tcache poisoning/double-free, UAF, heap/stack overflow) with CWE + difficulty tier + training audience.
- Core-dump triage needs a real core: on this VM `kernel.core_pattern` may pipe to systemd/apport — set `sudo sysctl -w kernel.core_pattern=/tmp/core.%e.%p` and `ulimit -c unlimited` to get local core files.

### Mitigation ladder + native vuln service
- `scripts/build-mitigation-lab.sh` compiles `targets/vulnlab/vulnlab.c` (native C TCP vuln service) at four tiers: `vulnlab-{basic,nx,aslr,modern}` (no-mitigation → canary+NX+PIE+RELRO+FORTIFY). Built binaries are gitignored; the `.c` source is committed.
- `randall checksec --exe <path>` reports NX/canary/PIE/RELRO/FORTIFY (via `readelf`) plus live ASLR state. ASLR is a runtime kernel setting: `sudo sysctl kernel.randomize_va_space=<0|1|2>` (or `setarch -R <exe>` per run). Changing it needs root (sudo works on this VM); restore to `2` after experiments.
- `projects/vulnlab.yaml` fuzzes the basic tier (real SIGSEGV over TCP, unlike the .NET lab targets which simulate a crash via `Environment.Exit`). Point `target.executable` at another tier to practise against NX/ASLR/canary. Details in `docs/MITIGATION_LAB.md`.
