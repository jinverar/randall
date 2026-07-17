# Contributing to Randfuzz by Randall

Thanks for helping build a teachable, portable Windows fuzzer.

## Getting started

```powershell
git clone https://github.com/jinverar/randall.git
cd randall
dotnet build
dotnet run --project src/Randall.Cli -- legs
dotnet run --project src/Randall.Server
```

## The eight legs

New features should map to a leg when possible — see [docs/LEGS.md](docs/LEGS.md). This keeps the tool learnable.

## Pull requests

- One logical change per PR
- `dotnet build` must pass
- Add or update docs when introducing a new leg or host mode

## Code layout

| Project | Purpose |
|---------|---------|
| `Randall.Core` | Engine interfaces and logic — no ASP.NET |
| `Randall.Infrastructure` | SQLite, DynamoRIO, monitors |
| `Randall.Server` | Web API + UI |
| `Randall.Cli` | Headless entrypoint |
| `Randall.Contracts` | Shared DTOs |

## Security

Randfuzz is a security research tool. Do not commit targets, crashes, or corpus data from systems you were not authorized to test.
