# Contributing to Randfuzz by Randall

Thanks for helping build a teachable, **cross-platform** fuzzer (Windows + Linux).

## Getting started

```bash
git clone https://github.com/jinverar/randall.git
cd randall
dotnet build Randall.sln
dotnet test Randall.sln -c Release
dotnet run --project src/Randall.Cli -- legs
dotnet run --project src/Randall.Server --urls http://127.0.0.1:5000
```

Fast first crash (file lab):

```bash
scripts/build-file-text.sh   # or scripts/build-file-text.ps1 on Windows
dotnet run --project src/Randall.Cli -- fuzz -c projects/file-text.yaml
```

## The eight legs

New features should map to a leg when possible — see [docs/LEGS.md](docs/LEGS.md). This keeps the tool learnable.

## Pull requests

- One logical change per PR
- `dotnet build` **and** `dotnet test` must pass
- Add or update docs when introducing a new leg or host mode
- Prefer project-aware doctor hints over generic “run build-vulnserver” for new lab targets

## Code layout

| Project | Purpose |
|---------|---------|
| `Randall.Core` | Engine interfaces and logic — no ASP.NET |
| `Randall.Infrastructure` | Flat JSON/JSONL, DynamoRIO, monitors, oracles |
| `Randall.Server` | Web API + UI |
| `Randall.Cli` | Headless entrypoint |
| `Randall.Contracts` | Shared DTOs |
| `tests/Randall.Tests` | xunit maturity / framing / oracle tests |

## Security

Randfuzz is a security research tool. Do not commit targets, crashes, or corpus data from systems you were not authorized to test.
