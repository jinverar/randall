# Randall roadmap

**Mission:** Intelligent, tricky fuzzing — not raw exec/s speed.

**Lab targets:** [vulnserver](docs/TARGETS.md#vulnserver) · [Notepad++](docs/TARGETS.md#notepadpp) · [cfpass](docs/TARGETS.md#cfpass) (strange file formats)

## Phase 1 — Lab targets + crash loop (in progress)

- [x] Project YAML loader (`projects/*.yaml`)
- [x] Built-in tricky mutators (bitflip, expand, truncate, boundary, insert)
- [x] **vulnserver** TCP fuzz (`TRUN /.:/` prefix)
- [x] **notepadpp** file fuzz (XML + weird text seeds)
- [x] **cfpass** file fuzz (placeholder binary seeds — replace with real format)
- [x] Crash save + `index.jsonl`
- [x] CLI: `targets`, `fuzz`, `crashes`, `--dry-run`
- [ ] Full `replay` (re-open file / resend TCP from saved crash)
- [ ] Minidump on crash
- [ ] Web UI crash browser

## Phase 2 — Stalk (DynamoRIO)

- [ ] drcov wrapper for vulnserver.exe
- [ ] Corpus priority by new edges
- [ ] cfpass / notepad++ coverage (where feasible)

## Phase 3 — Network + proxy

- [ ] More vulnserver commands (session graph)
- [ ] CANAPE-style MITM (future services)

## Phase 4 — Crash stalking + Ghidra

- [ ] Dedup, first-diverge, drcov export

## Phase 5 — Polyglot plugins + autopilot

- [ ] RPP process plugins (Python/Node/Rust)
- [ ] Portable publish + campaign scheduler

Current focus: **Phase 1** — drop vulnserver.exe and cfpass into `targets/`, run fuzz, collect crashes.
