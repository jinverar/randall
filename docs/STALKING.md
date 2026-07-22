# Stalking: intensity profiles, comparison, and unlimited runs

"Stalking" is Randfuzz's coverage/feedback‑driven exploration — favoring inputs that reach new code
and branching through the session graph (the graph on the Dashboard / Session graph tab). This adds
three intensity presets, a side‑by‑side comparison, and unbounded ("unlimited") runs.

## Intensity profiles

| Profile | Iterations | Havoc depth | Power schedule | Graph bias | Coverage‑guided | Mutators |
|---------|-----------|-------------|----------------|------------|-----------------|----------|
| **basic** | 100 | 2 | off | 0.10 | off | bitflip, insert |
| **fuzz** | 500 | 8 | on | 0.25 | if available | + havoc, interesting, dictionary, arith |
| **fuzzier** | 2000 | 16 | on | 0.40 | if available | + expand, boundary, splice |

```bash
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml --profile fuzzier
```

## Compare intensities (stalk bench)

Runs the same target at each profile and prints a comparison:

```bash
dotnet run --project src/Randall.Cli -- stalk bench -c projects/vulnserver.yaml [--profiles basic,fuzz,fuzzier] [--scale N]
```

Example (vulnserver, `--scale 0.25`):

```
profile    iters  crashes  unique  corpus+  novel  edges    secs  crash/1k
--------------------------------------------------------------------------
basic         25        2       2       18      0      0    16.4      80.0
fuzz         125        8       8       64      0      0    78.7      64.0
fuzzier      500       56      56      196      0      0   332.1     112.0
```

- **corpus+** = inputs kept because they expanded the frontier — the stalking signal available on
  every platform.
- **edges/novel** = DynamoRIO coverage‑edge deltas (Windows, or Linux with DynamoRIO installed).
- **crash/1k** = crashes per 1000 iterations — efficiency of the profile.

`--scale` multiplies each profile's iteration budget (e.g. `--scale 2` doubles them).

## Unlimited bug stalking

Run until you stop it (Ctrl‑C) or the crash budget is hit — no fixed iteration cap:

```bash
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnlab.yaml --profile fuzzier --unlimited
```

## Coverage backend note

On Windows (or Linux with DynamoRIO), stalking uses drcov edge coverage. Install on Linux with
`scripts/install-dynamorio.sh` (expects `tools/dynamorio/bin64/drrun`). On stock Linux without
DynamoRIO the backend resolves to **corpus‑novelty** feedback (frontier growth), so `corpus+` is the
signal and `edges` is 0. Roadmap: a native Linux coverage backend (SanitizerCoverage / perf) to
populate `edges` without DynamoRIO.

## Missed blocks (Dynapstalker loop)

You cannot find bugs in code you do not execute. After baseline + fuzz layers, ask what is still
dark — and *why* — then revise seeds, dictionaries, and mutators.

```bash
# Relative gaps (baseline-only, sparse modules, frontier holes, session forks)
randall stalk missed -p vulnserver

# Optional: import a full basic-block inventory for true never-hit (IDA/Ghidra export or drcov)
randall stalk inventory -p vulnserver --import path/to/blocks.txt
randall stalk missed -p vulnserver
```

| Mode | Meaning |
|------|---------|
| **relative** | No inventory — gaps from layer compare + session graph |
| **inventory** | `inventory.blocks.txt` present — never-hit = inventory − hit union |

Categories include **never-hit**, **baseline-only**, **module-sparse**, **frontier-gap**, and
**session-unexplored**. Each row carries a short *why missed* note plus ranked fuzz ideas
(CLI/UI hints). UI: **Stalking bugs → Missed blocks**. API: `GET /api/stalking/{project}/missed`.

Inventory line format matches corpus edges: `moduleId:0xstart:size`.
