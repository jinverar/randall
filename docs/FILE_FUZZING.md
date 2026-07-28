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
- Block models with sized/checksum + Peach-style types (uint/int, enum, flags, switch, array, padding)
- **`when` / conditional evaluation** against prior field values (`field == N` / `!=` / `whenEquals`)
- **`offset` / `relativeOffset` back-patch** after layout (named `targetField`)
- Checksum `coverFrom` (CRC over type+data for PNG-style chunks)
- Chunk-aware mutators (delete/insert/replace/clone/move/swap/zero/fill/lengthen…)
- Explicit `lengthPolicy` / `checksumPolicy`
- File OOP exit honesty (tool reject ≠ AV) + sanitizer stderr
- Temp file lifecycle (unique paths, flush+close, crash inputs via CrashStore)
- Recipe quality tiers — PNG / ZIP / WAV at **Structured model** (`protocols/*_structured.yaml`)
- `randall corpus minimize`
- Live UI **Edge | Block | Semantic** counters (honest `—` when BB provider missing)

## Scorecard (structure climb)

| Capability | Status |
|------------|--------|
| Minimal-valid PNG/WAV/ZIP seeds | Done |
| Structured model recipes (PNG/ZIP/WAV) | Done — IHDR/IDAT/IEND + ZIP local/CD/EOCD offsets + WAV chunks |
| `when` / conditional | Done — equality / inequality on prior fields |
| `offset` / `relativeOffset` back-patch | Done — absolute + relative after layout |
| Length / checksum policies | Done |
| Chunk mutators | Done |
| Live Edge \| Block \| Semantic status | Done — Fuzz STATUS + Dashboard |
| Grammar-backed recipes (owned formats) | Next |
| SanCov-native Linux (no DynamoRIO) | Next |
| Richer PDF / PE structured models | Next |

## Metrics (keep separate)

| Metric | Meaning | When empty |
|--------|---------|------------|
| **Edge coverage** | DynamoRIO/sancov BB edges | Show **Edge —** / Coverage unavailable — never imply edges=0 is measured |
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
model: protocols/png_structured.yaml
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

### Structured model sketch (ZIP offsets + PNG when)

```yaml
# ZIP — absolute offset back-patch to local_header / central_directory
- type: offset
  name: eocd_cd_offset
  targetField: central_directory
  littleEndian: true

# PNG — PLTE only when indexed color
- type: when
  when: "color_type == 3"
  children:
    - type: uint32
      name: plte_len
      value: "3"
      littleEndian: false
```

## ReelDeck

ReelDeck deepens a **known container** with structural seeds + pathlog stages — it is not
“discover grammar from scratch.” Pair with chunk mutators + policies for Peach-like campaigns.
See [REELDECK.md](REELDECK.md).

## Roadmap to parity / beyond (structure + research)

**NEXT**

- Grammar-backed recipes where we own the format
- Richer PDF/PE structured models (not magic-only)
- SanCov-native Linux without DynamoRIO

**Shipped this climb**

- Full conditional/`when` evaluation + offset back-patch
- Structured PNG / ZIP / WAV models + recipe catalog tier bump
- Live Edge | Block | Semantic counters in Fuzz/Dashboard status

**Not claiming**

- AFL++-class throughput as the default engine
- Complete Peach PIT / Defensics XML parity overnight

Related: [MODEL.md](MODEL.md) · [FUZZING.md](FUZZING.md) · [MATURITY.md](MATURITY.md) · [RECIPE_CATALOG.md](RECIPE_CATALOG.md) · [STALKING.md](STALKING.md)
