# Mini-timeline (unique-scream enrichment)

**Philosophy:** Observation explains the blast radius — it does not find crashes.
Randfuzz finds faults (mutators, coverage, Scream). A **mini-timeline** bottles what
Windows recorded in a short window around a **unique** scream: event logs, filesystem
MACB, optional Prefetch/Amcache/AppCompat, nearby WER reports, and (when armed) a
Procmon `.pml` bookend sliced to the same window — then a lightweight neighborhood
**graph** for review.

This is **not** a Plaso super-timeline and **not** Magician. Magician steers fuzzing;
mini-timeline is post-crash enrichment next to `autoAnalyzeCrash` and recorders.

**Status:** Wired (optional, Windows). Default **off**. Soft-fails when Eric Zimmerman
(EZ) tools and Procmon are missing.

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
| ShimCache / AppCompat (optional) | **AppCompatCacheParser** |
| Matching WER `Report.wer` copies | filesystem copy |
| Strings from dump/input (optional) | **bstrings** |
| Procmon ops in the same window | **Procmon** `.pml` → CSV slice |
| Crash neighborhood graph | `graph.json` + `merged.csv` |

Procmon stays a **run bookend** (`fuzz.procmonCapture`); the mini-timeline only
**slices** the existing PML after a unique scream — it does not start a new capture
on the hot path.

---

## Enable

```yaml
fuzz:
  miniTimeline: true           # default false
  miniTimelineWindowSeconds: 60  # ± around crash At (UTC); clamp 5–3600
  procmonCapture: true         # optional; enables PML bookend for Procmon slice
```

CLI re-run / backfill:

```bash
randall timeline capture -p <project> -i <crash-guid> [--window 60] [--pml path]
randall timeline graph -p <project> -i <crash-guid>   # rebuild graph.json + merged.csv
randall timeline tools                                 # discover EZ + Procmon
```

Doctor shows `miniTimeline` ready|warn when the flag is on or tools are present.

API:

- `GET /api/crashes/{id}/timeline` — `summary.json` DTO  
- `GET /api/crashes/{id}/timeline/graph` — `graph.json` (rebuilds from CSVs if missing)

---

## When it runs

| Trigger | Behavior |
|---------|----------|
| Unique scream (`IsNew`) + `fuzz.miniTimeline: true` | Capture under the crash |
| Dedup crash | **Skipped** (no extra cost) |
| Linux | Soft-skip (journalctl twin is future work) |
| Tools missing | Warn once; fuzz continues |

Hot path stays clean: no per-iteration EZ/Procmon convert work.

---

## On-disk layout

```
data/crashes/<project>/
  timeline/<crashId:N>/
    summary.json          # window, tool paths, row counts, graphPath
    evtx.csv              # filtered EvtxECmd rows (when any)
    mft.csv               # filtered MFTECmd rows (when any)
    prefetch.csv          # optional PECmd filter
    amcache.csv           # optional AmcacheParser filter
    appcompat.csv         # optional AppCompatCacheParser filter
    procmon.csv           # filtered Procmon CSV (when PML available)
    bstrings.txt          # optional
    graph.json            # crash ↔ events ↔ files ↔ ops
    merged.csv            # flat join of source CSVs for Timeline Explorer
    wer/                  # copied Report.wer files (best-effort)
    raw/                  # unfiltered tool dumps (debug)
```

`summary.json` is the stable join point for UI / API. `graph.json` is post-process
only and can be rebuilt with `randall timeline graph`.

Procmon PML source (first hit wins):

1. Explicit `--pml` / capture `procmonPmlPath`  
2. `data/runs/<runId>/fuzz.pml` from the crash’s run  
3. Newest `fuzz.pml` under `data/runs/` matching `project_*`

**Note:** CSV convert can fail if the PML is still locked by a live Procmon capture —
soft-fail with a note to stop capture first (`randall recorders stop`).

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
| `EvtxECmd.exe` | Event log CSV (core) |
| `MFTECmd.exe` | `$MFT` CSV (live volume may need elevation) |
| `PECmd.exe` | Prefetch (optional) |
| `AmcacheParser.exe` | Amcache (optional) |
| `AppCompatCacheParser.exe` | ShimCache / AppCompat (optional) |
| `bstrings.exe` | Strings from dump/input into `bstrings.txt` (optional) |
| `Procmon.exe` / `Procmon64.exe` | Convert run `.pml` → filtered `procmon.csv` |

EZ-only or Procmon-only captures are allowed; both together is best.

**Also useful later (documented, not required)**

| Binary | Role |
|--------|------|
| `RECmd.exe` / Registry Explorer | Narrow registry plugins (detected; deep batch later) |
| `SrumECmd.exe` | SRUM resource usage |
| **Timeline Explorer** | Human review of CSVs / `merged.csv` |
| **KAPE** | Optional collector accelerator — free for personal / research / internal use; enterprise license for third-party paid engagements. Randfuzz does **not** depend on KAPE. |

---

## Process (manual or automated)

1. Anchor: crash `At` (UTC) from `*_crash.json` / index  
2. Window: `[At − N, At + N]` seconds  
3. Collect/parse with EvtxECmd (+ MFTECmd / PECmd / Amcache / AppCompat when present)  
4. Filter CSV rows into the window  
5. Copy recent WER reports whose timestamps fall in the window  
6. Slice Procmon PML (if present) into `procmon.csv`  
7. Write `graph.json` + `merged.csv`  
8. Review in Timeline Explorer / Crashes UI; correlate with stalk layer  

**Escalate** to a campaign-length KAPE/Plaso timeline only when the box is weird — not per crash.

---

## Performance

Mini-timeline does **not** run every iteration. Cost is per **unique** crash and is bounded
by EZ parse time + optional Procmon CSV convert + window filter. Keep Procmon/ETW as
separate bookends; do not arm every recorder plus mini-timeline on long campaigns unless
you are debugging.

---

## Non-goals (for now)

- Magician ownership or Oracle auto-cast from timeline rows  
- TargetRunner integration  
- Full-disk Plaso on every scream  
- Interactive full-canvas graph UI (preview list only)  
- Shipping EZ binaries in the git repo  

---

## Future

- Flush/stop Procmon before convert for more reliable PML → CSV  
- Richer graph UI (force layout / filters)  
- Linux: `journalctl --since/--until` twin  
- RECmd batch plugins for Services / AppPaths around the crash  
