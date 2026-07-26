# Academy lab index (Wave 5 stub)

Curated entry points for **authorized lab practice** — memory corruption ladders, protocol surfaces, and debugger regression cases. No weaponized content; triage and learning only.

## Quick map

| Track | Start here | What you practise |
|-------|------------|-------------------|
| **Mitigation ladder** | [MITIGATION_LAB.md](MITIGATION_LAB.md) · `projects/vulnlab.yaml` | NX → ASLR → canary → FORTIFY (`vulnlab-{basic,nx,aslr,modern}`) |
| **Protocol labs** | [LAB_LIBRARY.md](LAB_LIBRARY.md) · Fuzz → Lab library | Vulnserver, HTTP, SMB-shaped, FTP, RPC, drone/defense fiction labs |
| **File / parser** | `projects/file-text.yaml` · `projects/file-framed.yaml` | In-process + file oracle invariants (silent screams when logic breaks) |
| **Debugger corpus** | [DEBUGGER_CORPUS.md](DEBUGGER_CORPUS.md) · `tests/debugger-corpus/` | Expected `DebuggerObservation` sidecars for cdb regression |
| **Harness demo** | `projects/harness-demo.yaml` | Cross-platform managed harness — fast first crash |
| **Exploit-dev triage** | [EXPLOIT_GUIDE.md](EXPLOIT_GUIDE.md) · `projects/vulnlab-offset.yaml` | Pattern offset / CONTROL register @ offset (research only) |

## Native vuln ladder (Linux / Windows)

Build:

```bash
scripts/build-mitigation-lab.sh
# Windows: scripts/build-mitigation-lab.ps1
```

| Tier | Binary | Profile tweak |
|------|--------|---------------|
| basic | `targets/vulnlab/vulnlab-basic` | default `projects/vulnlab.yaml` |
| nx | `vulnlab-nx` | point `target.executable` |
| aslr | `vulnlab-aslr` | `randall checksec` + ASLR sysctl |
| modern | `vulnlab-modern` | canary + full RELRO |

Commands: `ECHO` (stack), `FMT`, `HEAP`, `DFREE` — see [MITIGATION_LAB.md](MITIGATION_LAB.md).

## .NET / TCP lab targets

```bash
scripts/build-lab-targets.sh          # Linux
scripts/build-all-lab-targets.ps1     # Windows
```

Notable profiles: `vulnserver.yaml`, `vulnhttp.yaml`, `vulnsmb.yaml`, `vulndrone.yaml`, `vulnai.yaml`.

## Debugger corpus (regression)

| Path | Purpose |
|------|---------|
| [`tests/debugger-corpus/`](../tests/debugger-corpus/README.md) | Expected observation JSON per fault class |
| [`targets/debugger-corpus/`](../targets/debugger-corpus/README.md) | Native `debugger_corpus_fault.exe` harness |
| `dotnet test --filter DebuggerCorpus` | Schema + fixture tests; live cdb on Windows when built |

Cases: `null-deref`, `av-read`, `av-write`, `ascii-write`, `divide-zero`, `illegal-instruction` (+ heap/uaf stubs).

## Academy presentation modes

Configure per project or in the Crashes tab **Academy** selector:

```yaml
academy:
  presentationMode: learning   # learning | research
  instructorMode: false        # hide root-cause / offset panels
  silentScreams: true          # oracle violations → canisters
```

| Mode | UI behavior |
|------|-------------|
| **Learning** | “Why we’re doing this” blurbs on influence / root-cause / evidence |
| **Research** | Denser evidence tables (default) |
| **Instructor** | Hides root-cause, offset, pattern-depth for student-led discovery |

Console prefs persist under `data/ui-prefs.json` (`presentationMode`, `instructorMode`).

## Suggested progressions

1. **First scream** — `harness-demo.yaml` or `file-text.yaml` → Crashes tab canisters.
2. **Logic without crash** — file target + `oracles.invariants` → silent scream canister ([DIFFERENTIAL_ORACLE.md](DIFFERENTIAL_ORACLE.md)).
3. **Real SIGSEGV** — `vulnlab-basic` → minidump + Scream Investigator.
4. **Mitigations** — climb ladder; use `randall checksec`, `randall heaptriage`.
5. **Debugger quality** — build corpus harness; run `DebuggerCorpus` tests on Windows.

## Related docs

- [ROADMAP_INTELLIGENCE.md](ROADMAP_INTELLIGENCE.md) — intelligence loop + workbench stack
- [ROOT_CAUSE_ENGINE.md](ROOT_CAUSE_ENGINE.md) · [INFLUENCE_ENGINE.md](INFLUENCE_ENGINE.md) · [EVIDENCE_FACT.md](EVIDENCE_FACT.md)
- [SCREAM_INTELLIGENCE.md](SCREAM_INTELLIGENCE.md) — canister moods + silent screams
