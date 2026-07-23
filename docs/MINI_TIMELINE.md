# Mini-timeline (unique-scream enrichment)

**Philosophy:** Observation explains the blast radius — it does not find crashes.
Randfuzz finds faults (mutators, coverage, Scream). A **mini-timeline** bottles what
Windows recorded in a short window around a **unique** scream: event logs, filesystem
MACB, optional Prefetch/Amcache, and nearby WER reports.

This is **not** a Plaso super-timeline and **not** Magician. Magician steers fuzzing;
mini-timeline is post-crash enrichment next to `autoAnalyzeCrash` and recorders.

**Status:** Wired (optional, Windows). Default **off**. Soft-fails when Eric Zimmerman
(EZ) tools are missing.

Related: [RECORDING.md](RECORDING.md) · [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) ·
[CRASH_LOGGING.md](CRASH_LOGGING.md) · [STALKING.md](STALKING.md)

---

## Why (differentiator)

Most fuzzers stop at input + stack/dump. Randfuzz can also keep:

| Artifact | Source |
|----------|--------|
| Application / System / Security EVTX slice | **EvtxECmd** |
| `$MFT` rows in the same UTC window | **MFTECmd** |
| Prefetch execution evidence (optional) | **PECmd** |
| Amcache presence (optional) | **AmcacheParser** |
| Matching WER `Report.wer` copies | filesystem copy |

Join later with Procmon `.pml` bookends and stalk layers into a graph — post-process,
not on the hot path.

---

## Enable

```yaml
fuzz:
  miniTimeline: true           # default false
  miniTimelineWindowSeconds: 60  # ± around crash At (UTC); clamp 5–3600
```

CLI re-run / backfill:

```bash
randall timeline capture -p <project> -i <crash-guid> [--window 60]
randall timeline tools                         # discover EZ binaries
```

Doctor shows `miniTimeline` ready|warn when the flag is on or tools are present.

---

## When it runs

| Trigger | Behavior |
|---------|----------|
| Unique scream (`IsNew`) + `fuzz.miniTimeline: true` | Capture under the crash |
| Dedup crash | **Skipped** (no extra cost) |
| Linux | Soft-skip (journalctl twin is future work) |
| Tools missing | Warn once; fuzz continues |

Hot path stays clean: no per-iteration EZ work.

---

## On-disk layout

```
data/crashes/<project>/
  timeline/<crashId:N>/
    summary.json          # window, tool paths, row counts
    evtx.csv              # filtered EvtxECmd rows (when any)
    mft.csv               # filtered MFTECmd rows (when any)
    prefetch.csv          # optional PECmd filter
    amcache.csv           # optional AmcacheParser filter
    wer/                  # copied Report.wer files (best-effort)
    raw/                  # unfiltered tool dumps (debug)
```

`summary.json` is the stable join point for UI / graph export later.

---

## Tool install (free EZ CLIs)

Eric Zimmerman’s tools are free. Prefer **direct CLIs** under `tools/ez/` (or `tools/` / `PATH`).
[Get-ZimmermanTools](https://ericzimmerman.github.io/) can download them:

```powershell
# Example destination — adjust to your lab
powershell -ExecutionPolicy Bypass -File .\Get-ZimmermanTools.ps1 -NetVersion 9 -Dest .\tools\ez
```

**Phase-1 binaries Randfuzz discovers**

| Binary | Role |
|--------|------|
| `EvtxECmd.exe` | Event log CSV (required for a useful timeline) |
| `MFTECmd.exe` | `$MFT` CSV (live volume may need elevation) |
| `PECmd.exe` | Prefetch (optional) |
| `AmcacheParser.exe` | Amcache (optional) |

**Also useful later (documented, not required)**

| Binary | Role |
|--------|------|
| `RECmd.exe` / Registry Explorer | Narrow registry plugins |
| `AppCompatCacheParser.exe` | ShimCache |
| `bstrings.exe` | Strings/regex on dumps |
| `SrumECmd.exe` | SRUM resource usage |
| **Timeline Explorer** | Human review of CSVs |
| **KAPE** | Optional collector accelerator — free for personal / research / internal use; enterprise license for third-party paid engagements. Randfuzz does **not** depend on KAPE. |

---

## Process (manual or automated)

1. Anchor: crash `At` (UTC) from `*_crash.json` / index  
2. Window: `[At − N, At + N]` seconds  
3. Collect/parse with EvtxECmd (+ MFTECmd / PECmd / Amcache when present)  
4. Filter CSV rows into the window  
5. Copy recent WER reports whose timestamps fall in the window  
6. Review in Timeline Explorer; correlate with Procmon PML + stalk layer  

**Escalate** to a campaign-length KAPE/Plaso timeline only when the box is weird — not per crash.

---

## Performance

Mini-timeline does **not** run every iteration. Cost is per **unique** crash and is bounded
by EZ parse time + window filter. Keep Procmon/ETW as separate bookends; do not arm every
recorder plus mini-timeline on long campaigns unless you are debugging.

---

## Non-goals (for now)

- Magician ownership or Oracle auto-cast from timeline rows  
- TargetRunner integration  
- Full-disk Plaso on every scream  
- Graph UI (post-process phase later)  
- Shipping EZ binaries in the git repo  

---

## Future

- Slice Procmon `.pml` to the same window and merge CSVs  
- `timeline/` pane on the scream canister  
- Graph export: crash ↔ EVTX ↔ file ↔ stalk block  
- Linux: `journalctl --since/--until` twin  
