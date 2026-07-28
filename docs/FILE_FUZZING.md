# Competitive file-format fuzzing — Randall vs Peach / Defensics / AFL++

Randall aims to be a **serious file-format fuzzer**: expressive block models, chunk mutations,
dependency policies, multi-file/output cases, corpus minimize, sanitizer-aware triage, and
coverage scoping — with **crash-research integration** as the differentiator vs raw AFL++/WinAFL.

| Competitor strength | Randall stance |
|---------------------|----------------|
| Peach / Defensics structure + relations | **Compete** — block models, length/checksum policies, chunk mutators, recipe catalog |
| AFL++ / WinAFL raw grind + SanCov | **Partner** — adapters + DynamoRIO; `coverage.backend: sancov` for native PC ingest |
| Crash triage / exploit research loop | **Lead** — scream canisters, intel, counterfactuals, R0–R7 research maturity |

## What is strong today

- Teaching + custom parsers, harness demos, ReelDeck path stalking
- Crash research workbench (Investigation / Exploit Research / Evidence)
- Block models with sized/checksum + Peach-style types (uint/int, enum, flags, switch, array, padding)
- **`when` / conditional evaluation** against prior field values (`field == N` / `!=` / `whenEquals`)
- **`offset` / `relativeOffset` / ASCII decimal offset** back-patch after layout (`targetField`, `ascii: true` for PDF startxref)
- Checksum `coverFrom` (CRC over type+data for PNG-style chunks)
- Chunk-aware mutators (delete/insert/replace/clone/move/swap/zero/fill/lengthen…)
- Explicit `lengthPolicy` / `checksumPolicy`
- File OOP exit honesty (tool reject ≠ AV) + sanitizer stderr
- Temp file lifecycle (unique paths, flush+close, crash inputs via CrashStore)
- Recipe quality tiers — PNG / ZIP / WAV / **PDF / PE** at **Structured model**; **TLV** at **Grammar-backed**
- `randall corpus minimize`
- Live UI **Edge | Block | Semantic** counters (honest `—` when BB provider missing)
- **`coverage.backend: auto|sancov|dynamorio|semantic`** — clear native path without DynamoRIO

## Scorecard (structure climb)

| Capability | Status |
|------------|--------|
| Minimal-valid PNG/WAV/ZIP seeds | Done |
| Structured model recipes (PNG/ZIP/WAV/PDF/PE) | Done — IHDR/IDAT + ZIP local/CD/EOCD + WAV + PDF xref/startxref + PE DOS/COFF/section |
| `when` / conditional | Done — equality / inequality on prior fields |
| `offset` / `relativeOffset` / ASCII offset | Done — absolute + relative + PDF startxref digits |
| Length / checksum policies | Done |
| Chunk mutators | Done |
| Live Edge \| Block \| Semantic status | Done — Fuzz STATUS + Dashboard |
| Grammar-backed recipes (owned formats) | Done — `file-tlv` / `protocols/tlv_grammar.yaml` (switch + array) |
| SanCov-native Linux (no DynamoRIO) | Done — `coverage.backend: sancov` + `*.sancov` ingest plumbing |
| Richer PDF / PE structured models | Done — not magic-only |

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
  sanitizerCoverage: true      # or use coverage.backend below
coverage:
  backend: sancov              # auto | sancov | dynamorio | semantic
```

### Structured model sketch (ZIP offsets + PNG when + PDF startxref)

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

# PDF — ASCII decimal startxref → xref group
- type: offset
  name: startxref_off
  width: 10
  ascii: true
  targetField: xref
```

## ReelDeck

ReelDeck deepens a **known container** with structural seeds + pathlog stages — it is not
“discover grammar from scratch.” Pair with chunk mutators + policies for Peach-like campaigns.
See [REELDECK.md](REELDECK.md).

## Roadmap to parity / beyond (structure + research)

**NEXT**

- Deeper PDF object streams / PE data directories where honest
- Full LibAFL-style sancov bitmap merge (today: PC-key ingest)
- More owned grammar recipes beyond TLV

**Shipped this climb**

- Structured PE + PDF models + catalog tier bump
- `coverage.backend` plumbing (sancov | dynamorio | semantic)
- Grammar-backed TLV recipe (switch/array) + ZIP CD extra/comment completeness
- ASCII decimal offset for PDF startxref

**Not claiming**

- AFL++-class throughput as the default engine
- Complete Peach PIT / Defensics XML parity overnight
- Loadable PE images or full PDF ISO grammar

Related: [MODEL.md](MODEL.md) · [FUZZING.md](FUZZING.md) · [MATURITY.md](MATURITY.md) · [RECIPE_CATALOG.md](RECIPE_CATALOG.md) · [STALKING.md](STALKING.md) · [SANITIZER_COVERAGE.md](SANITIZER_COVERAGE.md)
