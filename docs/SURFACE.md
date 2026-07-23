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
coverage layer recorded
```

Related: [STALK_LOOP.md](STALK_LOOP.md) · [MINI_TIMELINE.md](MINI_TIMELINE.md) ·
[RECORDING.md](RECORDING.md) · [ORACLES.md](ORACLES.md) · [BUG_HUNTER.md](BUG_HUNTER.md)

---

## Session model

1. Start the target; arm recorders (`procmonCapture`, `sysinternalsSnapshots`, mini-timeline).
2. Use the program **naturally** — no crash required (baseline).
3. Stop / quit; **Record layer** (tag `baseline`) in Stalking bugs.
4. Exploit Surface auto-assesses (default) → ranked findings + recommendations.
5. Repeat for fuzzed / fuzzier if you want phase-to-phase surface (optional).

---

## Enable

```yaml
exploitSurface:
  enabled: true            # default when key omitted: treat as enabled for auto baseline
  assessBaseline: true     # auto after baseline layer record
  assessAllLayers: false   # also assess fuzzed / fuzzier / custom
  persist: true

fuzz:
  procmonCapture: true
  sysinternalsSnapshots: true
  miniTimelineOnStalk: true
```

CLI:

```bash
randall surface assess -p <project> [--layer <id>] [--baseline] [--json]
randall surface list   -p <project>
randall stalk surface-assess -p <project>
```

API:

- `GET /api/stalking/{project}/surface`
- `GET /api/stalking/{project}/layers/{layerId}/surface`
- `POST /api/stalking/{project}/surface/assess`

---

## On-disk layout

```
data/stalk/<project>/surface/
  layer-<id>.json       # full report
  findings.jsonl        # append-only findings
```

Inputs (best-effort):

| Artifact | Typical path |
|----------|----------------|
| Procmon CSV | `data/stalk/<p>/timeline/layer-<id>/procmon.csv` |
| ListDLLs | `data/runs/<p>_*/sysinternals/arm-listdlls.txt` |
| netstat | `…/arm-netstat.txt` |
| Handle / SigCheck | same sysinternals folder |

Soft-fail when artifacts are missing — layer record never fails.

---

## Finding kinds (v1 heuristics)

| Kind | Signals | Typical rec |
|------|---------|-------------|
| `dllSideload` | Load Image / `.dll` under Temp/AppData/Users/Downloads | Decoy DLL + path dictionary |
| `injection` | WriteProcessMemory / CreateRemoteThread / NtCreateThreadEx / … | IPC/spawn mutators; stalk module |
| `childProcess` | Process Create | Child cmdline fuzz; separate project |
| `networkListen` | TCP Listen / netstat LISTENING | TCP/UDP project + session graph |
| `unusualModule` | ListDLLs paths outside System32/Program Files | SigCheck; sideload if writable |

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

- Wire high findings → Magician summons / dictionary inject
- Diff surface reports between baseline and fuzzed (like host timeline compare)
- Signed vs unsigned module scoring via SigCheck parse
- Linux twin (ldd /ss /proc maps)
