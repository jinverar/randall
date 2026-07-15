# Randall lab targets

Three default profiles for learning **tricky** fuzzing — not raw speed.

| Project | Kind | What you learn |
|---------|------|----------------|
| **vulnserver** | TCP | Network generation, classic overflow path (TRUN), server crash detection |
| **notepadpp** | File | GUI parser, XML/text edge cases, file-open fuzzing |
| **cfpass** | File | Proprietary / strange binary formats — valid shell, corrupt internals |

## Quick start

```powershell
cd C:\Users\007\Projects\randall
dotnet build

# List profiles
dotnet run --project src/Randall.Cli -- targets

# Dry-run (no target required)
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml --dry-run

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

## cfpass setup (important)

Randall ships **placeholder** binary seeds (`CFPS` magic + fake fields). Replace with your real format:

1. Capture one valid file from cfpass
2. Save as `projects/seeds/cfpass_valid.bin`
3. Update `projects/cfpass.yaml` seeds list
4. Fix `target.args` to match how cfpass opens files

## vulnserver notes

- Port **9999**, command prefix **`TRUN /.:/`** (classic lab path)
- Randall restarts vulnserver after each crash when `long_lived: true`
- Known crash: TRUN with ~2000+ byte payload (your iteration count may vary)

## notepadpp notes

- Spawns a new Notepad++ per iteration (slow but isolates crashes)
- Hang until timeout counts as crash
- Windows exit codes `0xC0000005` (AV) and `0xC0000409` (stack) detected

## Roadmap

- Phase 2: DynamoRIO coverage on vulnserver + cfpass
- Phase 3: CANAPE-style TCP proxy for other commands (STATS, GMON, …)
- Plugins: Python mutators for format-aware cfpass tricks

See [ROADMAP.md](ROADMAP.md).
