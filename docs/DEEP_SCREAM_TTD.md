# Deep Scream — TTD Rewind Scream (research-only)

**Phase D+** deepens the Magician `rewindScream` spell for **marked Deep Scream crashes only**. Randfuzz still does **not** capture TTD traces on the fuzz hot path — Windows session policy, UAC, and target lifecycle block reliable in-process record. Instead, Randfuzz writes operator playbooks, record/replay launch scripts, and best-effort WinDbg Preview open when tools are detected.

## Eligibility gate

Deep Scream **marked** ⇔ all of:

- `screamScore ≥ 55`
- `seenCount ≤ 1` (unique in cluster)
- `reproducible` (sidecar + input ready)
- not family-deduped (one deep dive per scream family unless momentum jumps)

Only **marked** crashes trigger `rewindScream`. Candidates that fail the gate or are family-suppressed do not get TTD artifacts.

```yaml
fuzz:
  rewindScream: true          # enable Magician TTD path
  deepScreamAutoMinimize: true  # optional shrink before mark
magician:
  enabled: true
  allowRewindScream: true
```

## What Randfuzz writes (marked crashes)

| Artifact | Path |
|----------|------|
| Deep Scream gate | `{guid}_deep_scream.json` |
| TTD operator playbook | `{guid}_deep_scream_ttd.md` |
| WinDbg backward-query script | `{guid}_deep_scream_ttd_queries.txt` |
| Record launcher (when tools detected) | `{guid}_deep_scream_ttd_record.cmd` |
| Replay launcher (dump + Preview) | `{guid}_deep_scream_ttd_replay.cmd` |
| Magician index | `_magician/deep_scream_index.md` |
| Spell log | `_magician/spells.jsonl` → `rewindScream` |

## TTD toolchain probe

`DebuggerTools.ProbeTtd()` detects:

- **WinDbg Preview** (`WinDbgX.exe`) — attach + `!tt.record` / replay
- **tttracer** — `-out trace.run target.exe args`

Returns `CanRecord`, `CanReplay`, and `RecordVia` hints used in the playbook.

## Operator workflow

1. Confirm ⏪ **Deep Scream** badge / `{guid}_deep_scream.json` shows `"isMarked": true`.
2. Read `{guid}_deep_scream_ttd.md` — record/replay steps + exploit backward queries.
3. Reproduce: `randall replay -i <guid>`.
4. **Record** (pick one):
   - Run `{guid}_deep_scream_ttd_record.cmd` (edit TARGET/ARGS inside), or
   - WinDbg Preview: `.attach <pid>` → `!tt.record` … reproduce … `!tt.stop`, or
   - `tttracer -out deep_scream_<guid>.run <target> <args>`
5. **Replay**:
   - Run `{guid}_deep_scream_ttd_replay.cmd` (opens dump + query script), or
   - `randall debug open -i <guid> --kind windbg-preview`
6. In trace: `!tt` · `g-` · tailored queries from playbook.

## Exploit-focused backward queries

The playbook and `{guid}_deep_scream_ttd_queries.txt` include research-oriented steps:

| Goal | Commands |
|------|----------|
| Rewind toward fault | `!analyze -v` then `g-` / `!tt` |
| Where was RIP set? | `u @rip L20` · walk `g-` · `dx @rip` |
| Controlled register origin | Backward until write to fault/control register |
| Heap alloc/free history | `!heap -p -a <fault>` · `!address <fault>` · `!heap -stat` |
| Stack corruption source | `dps @rsp L20` · `g-` until stack slot changes |

When `{guid}_debugger_observation.json` exists, the playbook adds tailored lines for fault RIP, address class, and heap signals.

## Limits (honest)

- **No hot-path TTD capture** during fuzz — not a product guarantee; OS/driver/session may block record.
- **Best-effort WinDbg Preview launch** on marked save when a minidump exists — may fail under headless/CI; use `.cmd` scripts manually.
- **Replay scripts** open static dumps with query scripts; full time-travel requires a recorded `.run` trace.
- Pair with `{guid}_corruption_chain.json`, `{guid}_hypotheses.json`, and [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md).

## Related

- [RECORDING.md#windbg-ttd--rewind-scream](RECORDING.md#windbg-ttd--rewind-scream-stub)
- [MAGICIAN.md](MAGICIAN.md) — `rewindScream` spell
- [ROADMAP_INTELLIGENCE.md](ROADMAP_INTELLIGENCE.md) — Phase D gate
