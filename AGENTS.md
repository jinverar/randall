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

### Fuzzing without Windows targets
- Most `projects/*.yaml` profiles (vulnserver, vulnhttp, etc.) require a Windows lab-target `.exe` and will fail on Linux with "Executable not found".
- The fully cross-platform end-to-end path is the in-process managed harness: build it once with `dotnet build targets/Randall.HarnessDemo`, then run `dotnet run --project src/Randall.Cli -- fuzz -c projects/harness-demo.yaml`. This exercises the real fuzz engine (mutators, corpus, crash capture) and reliably finds crashes, writing artifacts to `data/crashes/harness-demo/`.
- YAML `target.harness`/`executable` paths are resolved relative to the YAML file's directory (`projects/`), not the process CWD.
