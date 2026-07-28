# Competitive file-format fuzzing — Randall vs Peach / Defensics / AFL++

Randall aims to be a **serious file-format fuzzer**: expressive block models, chunk mutations,
dependency policies, multi-file/output cases, corpus minimize, sanitizer-aware triage, and
coverage scoping — with **crash-research integration** as the differentiator vs raw AFL++/WinAFL.

| Competitor strength | Randall stance |
|---------------------|----------------|
| Peach / Defensics structure + relations | **Compete** — block models, length/checksum policies, chunk mutators, recipe catalog |
| AFL++ / WinAFL raw grind + SanCov | **Partner** — adapters + DynamoRIO; they still win pure exec/s |
| Crash triage / exploit research loop | **Lead** — scream canisters, intel, counterfactuals, R0–R7 research maturity |

## What is strong today

- Teaching + custom parsers, harness demos, ReelDeck path stalking
- Crash research workbench (Investigation / Exploit Research / Evidence)
- Block models with sized/checksum + expanded Peach-style types (uint/int, enum, flags, switch, array, padding, offset stubs)
- Chunk-aware mutators (delete/insert/replace/clone/move/swap/zero/fill/lengthen…)
- Explicit `lengthPolicy` / `checksumPolicy`
- File OOP exit honesty (tool reject ≠ AV) + sanitizer stderr
- Temp file lifecycle (unique paths, flush+close, crash inputs via CrashStore)
- Recipe quality tiers (Magic-only → Harness included); PNG/WAV/ZIP minimal-valid seeds
- `randall corpus minimize`

## Metrics (keep separate)

| Metric | Meaning | When empty |
|--------|---------|------------|
| **Edge coverage** | DynamoRIO/sancov BB edges | Show **Coverage unavailable** — never imply edges=0 is measured |
| **Block coverage** | Unique blocks from traces | Same as edges without a BB provider |
| **Semantic stage coverage** | ReelDeck `REELDECK_PATHLOG` / path novelty | Valid without DynamoRIO |

## Config highlights

```yaml
kind: file
target:
  executable: ../targets/myparser/myparser
  args: ["{file}", "{outputFile}"]
transport:
  type: file
  extension: .png
  extensions: [.png, .jpg, .bin]
  mismatchChance: 0.05
  outputFile: "{outputFile}"
  retainOnCrash: false   # also fuzz.retainOnCrash
  files:
    - name: sidecar
      placeholder: "{file2}"
      extension: .dat
model: protocols/png_minimal.yaml
mutators:
  - havoc
  - delete-range
  - insert-at-offset
  - replace-chunk
  - clone-chunk
  - lengthen-near-field
fuzz:
  lengthPolicy: valid          # valid|mutate|independent|off-by-one|wrap|actualPlusDelta|stale|zero
  checksumPolicy: valid
  lengthPolicyDelta: 0
  retainOnCrash: false
  coverageModules: [myparser]
  coverageExcludeModules: [ntdll.dll, libc.so.6]
  harnessDeterminismProbe: true
```

## ReelDeck

ReelDeck deepens a **known container** with structural seeds + pathlog stages — it is not
“discover grammar from scratch.” Pair with chunk mutators + policies for Peach-like campaigns.
See [REELDECK.md](REELDECK.md).

## Roadmap to parity / beyond (structure + research)

**NEXT**

- Full conditional/when evaluation + offset back-patch
- Richer ZIP/PDF/PE structured models (not magic-only)
- Live Edge | Block | Semantic counters in UI status strip
- Grammar-backed recipes where we own the format
- SanCov-native Linux without DynamoRIO

**Not claiming**

- AFL++-class throughput as the default engine
- Complete Peach PIT / Defensics XML parity overnight

Related: [MODEL.md](MODEL.md) · [FUZZING.md](FUZZING.md) · [MATURITY.md](MATURITY.md) · [RECIPE_CATALOG.md](RECIPE_CATALOG.md) · [STALKING.md](STALKING.md)
