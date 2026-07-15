# Randall lab targets

Public examples ship with **vulnserver** (TCP) plus generic **file** templates. Real binaries and private profiles stay local — see [targets/README.md](../targets/README.md) and `projects/local/` (gitignored).

| Project | Kind | What you learn |
|---------|------|----------------|
| **vulnserver** | TCP | Network generation, session graph, classic overflow path |
| **file-text** | File | Structured text / XML shell + mutable body |
| **file-framed** | File | Length-prefixed binary records (off-by-one length fields) |

## Quick start

```powershell
dotnet build

# List profiles
dotnet run --project src/Randall.Cli -- targets

# Dry-run (no target binary required)
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml --dry-run
dotnet run --project src/Randall.Cli -- fuzz -c projects/file-framed.yaml --dry-run

# Live fuzz (needs binary — see targets/README.md)
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml
```

## Tricky mutators (built-in)

| Mutator | Trick |
|---------|-------|
| `bitflip` | Single-bit corruption in valid shell |
| `expand` | Append huge run — length / buffer edge cases |
| `truncate` | Cut mid-record — parser state confusion |
| `boundary` | 0, 1, 0x7F, 0x80, 0xFF at random offset |
| `insert` | Random blob appended — strange tail parsing |
| `havoc` | Stacked random mutations (AFL-style) |
| `interesting` | Known-bad integers at aligned offsets |
| `dictionary` | Inject project tokens / format strings |
| `splice` | Crossover two corpus inputs |
| `arith` | Small integer delta on one byte |

See [FUZZING.md](FUZZING.md) for technique details and research references.

## Private targets

Copy your own YAML + seeds into `projects/local/` and binaries into `targets/local/`. Neither path is committed.

```powershell
randall fuzz -c projects/local/my-target.yaml
```

## vulnserver notes

- Build: `.\scripts\build-vulnserver.ps1` → `targets/vulnserver/randall-vulnserver.exe`
- Port **9999**, session graph (TRUN, GMON, GTER, RAND, …)
- Randall restarts vulnserver after each crash when `long_lived: true`
- Known crash: TRUN with ~2000+ byte payload (iteration count may vary)

## File target notes

- Point `target.executable` at your app under `targets/local/` or an absolute path
- Replace placeholder seeds with a valid sample from your format
- Enable `coverageGuided: true` in YAML for DynamoRIO on file targets

See [ROADMAP.md](ROADMAP.md).
