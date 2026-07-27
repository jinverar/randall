# Operator wiki — cheat codes

Practical tricks operators forget. Keep this open in **Help → Operator wiki**.

## After `git pull`

| You run… | Do this |
|----------|---------|
| `dotnet run --project src/Randall.Server` | Pull + **restart** the process (rebuilds on start). Browser: **Ctrl+F5**. |
| Prebuilt `bin\Release\...\Randall.Server.exe` | `dotnet build Randall.sln -c Release`, restart the exe, **Ctrl+F5**. |
| Lab targets / native exes changed | `scripts/update-lab.ps1` (or `-SkipLabTargets` if UI-only). |

Honesty / NULL-write / Exploit Research fixes live in the **running** binary + `wwwroot`. Pull alone is not enough.

## Live link / LAN

- Sidebar **Live link** = SignalR hub for status + log push.
- If disconnected while fuzzing: STATUS/log still poll `/api/fuzz/status` + `/api/fuzz/logs`.
- Remote/LAN: set `RANDALL_AGENT_TOKEN`, paste token when prompted (or `localStorage.randallLocalToken`).
- Stuck “already running” but STATUS Idle → **Force clear**, then Start again.

## Coverage-guided TCP + Labs

- Lab already listening on `:9999` (or profile port) → DynamoRIO **cannot** spawn for BB edges.
- **Stop Labs** first, **or** uncheck **Coverage-guided**, then Start fuzz.
- While Tracing with Labs + Coverage on: banner is **LIVE (no BB edges…)** — session/corpus-novelty graph keeps refreshing. Do **not** need Open completed run for a live session.
- Banner *No BB graph… Open completed run* is for idle / completed only.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Stalk API / live log: `'0x00' is an invalid start of a value` in `CrashStore.List` | Corrupt `data/crashes/<project>/index.jsonl` line (partial write). Restart after pull — List skips + quarantines bad lines to `index.jsonl.corrupt`. Optional: rename suspicious `*_crash.json` that start with NUL to `.corrupt`. |
| Stalker graph empty mid-fuzz + "Open completed run" | Should no longer happen while STATUS is Tracing; Follow live + restart server after this fix. Without DynamoRIO expect LIVE novelty path, not a dead graph. |
| `/api/stalk` used to 500 mid-fuzz | Now returns 200 with partial/degraded graph + warning note. |

## Dashboard Current Session

| Action | Meaning |
|--------|---------|
| **Open run** | Load a completed `data/runs/<id>` journal into the stalker graph (pins that run). |
| **Close** | Return to live / latest. |
| **Save** | Snapshot under `data/sessions/saved/`. |
| **Export** | Zip run (+ linked crashes) → `data/exports/`. |
| **Import archive** | Folder or `.zip` with `run.json` trees → copy into `data/runs/`. Recursive scan is async; wait for the status line. |

Open ≠ Import. Open browses local journals; Import copies archives in.

## NULL-write honesty / re-analyze

- Boundary/teardown null writes are **not** automatic R4 primitives.
- After pull: restart server, open crash, **Re-analyze** if you see ⚠ older analysis engine.
- Exploit Research panel (Investigation): fault insn, EA, register matrix, control tests, next experiment.

## Common `doctor` warnings

| Check | Meaning |
|-------|---------|
| `dynamorio` warn | No BB edges; novelty/corpus stalking still works. |
| Windows tools `[!]` on Linux | Expected — switch platform selector to Linux. |
| Port busy / Coverage-TCP waiting | Stop lab listener or disable Coverage. |
| pktmon / ETW skip | Need Admin on Windows. |

## Quick start reminders

```text
dotnet run --project src/Randall.Server --urls http://127.0.0.1:5000
# Crashes tab → select crash → Investigation → Exploit Research panel
```

See also: [STALKING.md](STALKING.md) · [EXPLOIT_GUIDE.md](EXPLOIT_GUIDE.md) · [LAB_AGENT.md](LAB_AGENT.md) · [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md).
