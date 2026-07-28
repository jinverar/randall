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
signal and `edges` is 0 — unless you set **`coverage.backend: sancov`** and the target emits
`*.sancov` under `corpus/traces` (see [SANITIZER_COVERAGE.md](SANITIZER_COVERAGE.md)).

```yaml
coverage:
  backend: sancov    # auto | sancov | dynamorio | semantic
```

### Empty stalker graph?

If **Stalker graph** is blank / 0% with Coverage-guided checked:

1. Run `randall doctor` — DynamoRIO must be Ready.
2. For **TCP** targets: stop Labs / anything already listening on the project port. Coverage-TCP
   cannot spawn `drrun` copies while `:9999` (etc.) is busy; Randfuzz will fuzz the existing
   listener instead and BB edges stay 0. Banner (Dashboard + Fuzz):
   **No BB graph: fuzzing existing listener without DynamoRIO. Stop Labs + Coverage-guided for
   edges, or Open completed run.**
3. After a completed run, use **Open completed run** on the dashboard to load that journal’s
   graph data (if any). Import archive walks folders for `run.json` → `data/runs/`.
4. Without BB edges the UI shows an honest corpus-novelty / session path plus a banner — not a
   spinner.

### Live UI (Status / Live log) over LAN

The web console pushes progress over SignalR (`/hubs/fuzz`) and **also polls**
`/api/fuzz/status` + `/api/fuzz/logs` while a session is active. If Live log sticks on
`Session accepted…` while the server console keeps printing test cases:

1. **Restart** `Randall.Server` / `randall serve` so it binds the host you open in the browser
   (e.g. `http://192.168.x.x:5000` — same IP the process listens on, not a different machine).
2. **Hard refresh** the browser (Ctrl+F5) so `app.js` + vendored `/js/signalr.min.js` reload.
3. Check **Live link:** in the Fuzz tab — `connected` means the hub is up; `disconnected` still
   streams via REST poll. Click **Reconnect** or refresh if the banner says the UI link was lost.
4. When `RANDALL_AGENT_TOKEN` is set (normal for `0.0.0.0` / LAN binds), paste the token when
   prompted so both REST and SignalR (`access_token`) authorize.

## Missed blocks (Dynapstalker / PDF loop)

**Step-by-step tutorial (IDA + Ghidra):** [HOWTO_STALK_IDA_GHIDRA.md](HOWTO_STALK_IDA_GHIDRA.md)  
**Ghidra product path (scripts + optional Dragon Dance):** [GHIDRA_INTEGRATION.md](GHIDRA_INTEGRATION.md)  
**Binary drcov for Dragon Dance:** `fuzz.captureBinaryDrcov: true` or `randall stalk capture-binary -p <project>`  
**In-Randall stalk map (strings/imports on missed):** [STALK_MAP.md](STALK_MAP.md) · `randall stalk map -p <project>`

**You cannot find bugs in code you do not execute.** After baseline + fuzz layers, ask what is still
dark — and *why* — then revise seeds, dictionaries, and mutators.

### PDF exercise → Randfuzz

| PDF step | Randfuzz |
|----------|----------|
| `drrun -t drcov -dump_text -- target` | Same (`fuzz.coverageGuided` / DynamoRIO), or manual drrun |
| Baseline: normal browse / use | **Stalking bugs** → tag `baseline` (or corpus edges after happy-path) |
| Fuzzer pass under drcov | Campaign / Scare Floor → tag `fuzzed` |
| Dynapstalker → IDC (yellow, then green) | `randall stalk dynapstalker <log> <exe> out.idc --color …` **or** Export → IDA IDC |
| Same colors in **Ghidra** | `randall stalk dynapstalker <log> <exe> out.py --format ghidra` **or** Export → Ghidra |
| Load **oldest script first** | Documented; scripts only paint still-uncolored items |
| White / plain blocks = missed | IDA white or Ghidra uncolored = ground truth; `randall stalk missed` approximates |
| Review string / `rep movs*` / interesting white | Missed-block fuzz ideas call this out explicitly |
| Revise fuzzer → remeasure → new color | Record `fuzzier` layer / new IDC color |

```bash
# One-shot Dynapstalker → IDA
randall stalk dynapstalker savant-base.log savant.exe savant-base.idc --color 0x00ffff
randall stalk dynapstalker savant-fuzz.log savant.exe savant-fuzz.idc --color 0x00ff00

# Same for Ghidra (imageBase + drcov RVA; Script Manager)
randall stalk dynapstalker savant-base.log savant.exe savant-base.py --format ghidra --color 0x00ffff
randall stalk dynapstalker savant-fuzz.log savant.exe savant-fuzz.py --format ghidra --color 0x00ff00
# or from stalk layers: randall stalk export -p <project> --format ghidra

# In-product gap report + ideas
randall stalk missed -p vulnserver

# Optional: import a full BB inventory for true never-hit without IDA
randall stalk inventory -p vulnserver --import path/to/blocks.txt
randall stalk missed -p vulnserver
```

| Mode | Meaning |
|------|---------|
| **relative** | No inventory — gaps from layer compare + session graph (approx. without IDA) |
| **inventory** | `inventory.blocks.txt` present — never-hit = inventory − hit union ≈ IDA white |

Categories include **never-hit**, **baseline-only**, **module-sparse**, **frontier-gap**, and
**session-unexplored**. Each row carries a short *why missed* note plus ranked fuzz ideas
(CLI/UI hints). UI: **Stalking bugs → Missed blocks**. API: `GET /api/stalking/{project}/missed`.

Inventory line format matches corpus edges: `moduleId:0xstart:size`. Requires drcov **`-dump_text`**.
