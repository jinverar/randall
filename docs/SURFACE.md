# Exploit Surface (stalk host assessor)

**Philosophy:** Observation captures what the host did. **Exploit Surface** suggests what
that means for exploitation research — DLL sideload paths, injection APIs, child
processes, listening sockets, unusual modules — and recommends how to fuzz next.

This is **not** Oracle (judgment of wrong behavior on a live fuzz run), **not** Magician
(spells), and **not** Bug Hunter (source/LLM mistake planning). It sits on stalk +
recording artifacts after a **baseline** (or any stalk phase).

```text
Baseline session (natural use)     Exploit Surface              Fuzz / Magician / Bug Hunter
──────────────────────────────     ───────────────              ──────────────────────────
Procmon · ListDLLs · timeline  →   findings + recommendations → arm seeds / dict / projects
ss · /proc/maps · ldd (Linux)  →   ideas.json + Missed/Stalk  → soft Magician needs
coverage layer recorded
```

Related: [STALK_LOOP.md](STALK_LOOP.md) · [MINI_TIMELINE.md](MINI_TIMELINE.md) ·
[RECORDING.md](RECORDING.md) · [ORACLES.md](ORACLES.md) · [BUG_HUNTER.md](BUG_HUNTER.md)

---

## Session model

1. **Start baseline session** — Procmon + Sysinternals (Windows) or `ss` + `/proc` maps + `ldd` (Linux)  
   Auto-attaches **Target Runtime** PID/exe when a matching slot is already running.  
   (`randall surface baseline start -p <project>` or Stalking bugs → **Start baseline session**)
2. Use the program **naturally** — no crash required
3. **Stop** — flush recorders, record stalk `baseline` layer, mini-timeline + Exploit Surface assess
4. Review findings / **Surface fuzz ideas** / surface compare; fuzz with armed dictionary tokens
5. Repeat for fuzzed / fuzzier phases as needed

Legacy: you can still **Record layer** manually after a short coverage run without a live session.

---

## Enable

```yaml
exploitSurface:
  enabled: true
  assessBaseline: true
  assessAllLayers: false   # also assess fuzzed / fuzzier
  persist: true
  writeHints: true         # → data/stalk/<p>/surface/hints.md
  armDictionary: true      # → dictionary-tokens.txt (auto-merged into fuzz dictionary)
  softSummonMagician: true # persist surface_needs.jsonl + optional Magician cast
```

CLI:

```bash
randall surface baseline start -p <project> [--pid N] [--exe path]
randall surface baseline stop  -p <project> [--no-layer]
randall surface baseline status -p <project>
randall surface assess -p <project> [--layer <id>] [--baseline] [--json]
randall surface list   -p <project>
randall surface compare -p <project> [layerId…]
randall surface ideas  -p <project> [--json]
randall surface apply  -p <project> [--port N|--idea id|--all]
randall stalk surface-assess -p <project>
```

API:

- `POST /api/stalking/{project}/baseline/start|stop`
- `GET  /api/stalking/{project}/baseline`
- `GET /api/stalking/{project}/surface`
- `GET /api/stalking/{project}/layers/{layerId}/surface`
- `POST /api/stalking/{project}/surface/assess`
- `GET /api/stalking/{project}/surface/compare`
- `GET /api/stalking/{project}/surface/ideas`
- `POST /api/stalking/{project}/surface/apply` — set listen port / ensure dictionary on campaign YAML

---

## On-disk layout

```
data/stalk/<project>/
  baseline-session.json      # live start/stop state
  surface/
    layer-<id>.json            # full report
    findings.jsonl             # append-only findings
    surface_needs.jsonl        # Magician needs (soft)
    ideas.json                 # MissedFuzzIdeaDto list (also folded into Missed / Stalk map)
    applied.jsonl              # audit of surface apply (port / dictionary)
    hints.md                   # ranked recommendations for analysts
    dictionary-tokens.txt      # auto-merged into fuzz dictionary mutator
data/runs/<project>_baseline_<ts>/
  fuzz.pml                     # Windows Procmon
  sysinternals/…               # Windows ListDLLs / netstat / SigCheck
  linux/…                      # Linux ss / maps / cmdline / ldd-target.txt
```

Inputs (best-effort):

| Artifact | Typical path |
|----------|----------------|
| Procmon CSV | `data/stalk/<p>/timeline/layer-<id>/procmon.csv` |
| ListDLLs | `data/runs/<p>_*/sysinternals/arm-listdlls.txt` |
| netstat | `…/arm-netstat.txt` |
| Handle / SigCheck | same sysinternals folder |
| `ss` listen | `data/runs/<p>_*/linux/arm-ss.txt` |
| `/proc/maps` | `…/linux/arm-maps.txt` |
| `ldd` | `…/linux/ldd-target.txt` |

Soft-fail when artifacts are missing — layer record never fails.

---

## Finding kinds (v1 heuristics)

| Kind | Signals | Typical rec |
|------|---------|-------------|
| `dllSideload` | Load Image / `.dll` under Temp/AppData/Users/Downloads · Linux `ldd` unusual `.so` | Decoy DLL/`.so` + path dictionary |
| `injection` | WriteProcessMemory / CreateRemoteThread / NtCreateThreadEx / … | IPC/spawn mutators; stalk module |
| `childProcess` | Process Create | Child cmdline fuzz; separate project |
| `networkListen` | TCP Listen / netstat LISTENING · Linux `ss` LISTEN | TCP/UDP project + session graph |
| `unusualModule` | ListDLLs paths outside System32/Program Files · `/proc/maps` unusual `.so` · `ldd` not found | SigCheck / RPATH; sideload if writable |
| `unsignedBinary` | SigCheck `Verified: Unsigned` (or Signed as info) | Lab tamper / sideload policy |

**Surface fuzz ideas:** after assess, findings become `ideas.json` and appear in Missed blocks /
Stalk map / the **Surface fuzz ideas** panel (`randall surface ideas`). Listen ideas carry an
**Apply** action that sets `transport.port` (or mints a TCP companion project); sideload/module
ideas re-ensure the dictionary mutator (`randall surface apply` / UI Apply button).

**Compare phases:** after assessing baseline + fuzzed (+ fuzzier), use
`randall surface compare` or the Stalking bugs **Surface compare** panel — novel findings
vs the previous phase (same idea as host timeline compare).

**Arming:** high/medium findings mint dictionary tokens (DLL basenames, `.so` names, ports, API names).
The next fuzz campaign auto-loads `dictionary-tokens.txt` into the dictionary mutator, and assess
soft-ensures `dictionary` is listed in the project YAML mutators when a YAML exists.
With `softSummonMagician`, findings also emit Magician needs (`surface_needs.jsonl`) and
may cast dictionary/army/knight/bots when Magician is enabled — post-assess only, never on
the fuzz hot path. Magician `dictionaryBoost` for surface rule classes prefers those same
surface tokens (not generic Bug Hunter defaults). When `softSummonMagician: false`, neither
needs nor cast run.

Baseline session **Stop** pins `runId` / Procmon PML into the stalk layer so mini-timeline and
Exploit Surface assess the artifacts from *that* session (not a random newer run).

---

## Division of labour

| Engine | Role |
|--------|------|
| **Exploit Surface** | *What host surface did baseline expose?* |
| **Oracle** | *Did this fuzz run behave wrongly?* |
| **Bug Hunter** | *What source/LLM mistakes should we arm?* |
| **Magician** | *What do we do next on Oracle needs?* |
| **Stalk / mini-timeline** | *What was recorded?* |

---

## Future

- Richer Authenticode / catalog parsing beyond SigCheck text
- ELF signature / package provenance probes on Linux
- Deeper Target Runtime multi-slot attach heuristics
- Scare Floor one-click “Apply listen port” from surface ideas ✅ (`surface apply`)
