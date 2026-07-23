# Lab practice guide

Hands-on checklist for validating Randall Phases 10–14 on your machine. Work through these in order the first time; later runs can skip to the sections you care about.

**Time:** ~30–45 minutes for the full walkthrough.

**Prerequisites**

- Windows 10/11
- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- PowerShell
- Repo cloned to a local folder (e.g. `C:\Users\007\Projects\randall`)

Optional (for coverage-guided fuzz):

- [DynamoRIO](https://dynamorio.org/) with `DYNAMORIO_HOME` set

---

## 1. Build everything

```powershell
cd C:\Users\007\Projects\randall
dotnet build
```

**Expect:** `Build succeeded` with 0 errors.

---

## 2. Build lab targets

Compiles the vulnerable lab servers (gitignored `.exe` files under `targets/`).

```powershell
.\scripts\build-all-lab-targets.ps1
```

Labs listen on **127.0.0.1** by default. Manage them from **Fuzz → Lab library** (category filter, status + PID; running count also on the Campaign strip). CLI: `randall labs` / `randall labs stop-all`. For a remote fuzz VM use `randall agent` — see [LAB_AGENT.md](LAB_AGENT.md) · [LAB_LIBRARY.md](LAB_LIBRARY.md).

**Expect:** Lab targets built:

| Target | Port | Profile |
|--------|------|---------|
| vulnserver | 9999 | `projects/vulnserver.yaml` |
| vulnhttp | 8080 | `projects/vulnhttp.yaml` |
| vulnftp | 2121 | `projects/vulnftp.yaml` |
| vulnssh | 2222 | `projects/vulnssh.yaml` |
| vulntftp | 6969 | `projects/vulntftp.yaml` |
| vulnrpc | 1355 | `projects/vulnrpc.yaml` |
| vulnsmb | 4455 | `projects/vulnsmb.yaml` |
| vulndrone-udp / tcp | 15550 / 15551 | `projects/vulndrone-*.yaml` — see [DRONE_LAB.md](DRONE_LAB.md) |
| vulnmqtt | 18883 | `projects/vulnmqtt.yaml` — see [MQTT_LAB.md](MQTT_LAB.md) |
| vulnrobot | 15560 | `projects/vulnrobot.yaml` — see [ROBOT_LAB.md](ROBOT_LAB.md) |

**File shelf** (profile-only — no Start/Stop listener; build separately):

```powershell
.\scripts\build-file-text.ps1
.\scripts\build-file-framed.ps1
.\scripts\build-reeldeck.ps1
```

| Lab | Profile | Docs |
|-----|---------|------|
| file-text | `projects/file-text.yaml` | [TARGETS.md](TARGETS.md) |
| file-framed | `projects/file-framed.yaml` | [TARGETS.md](TARGETS.md) |
| reeldeck | `projects/reeldeck.yaml` | [REELDECK.md](REELDECK.md) |
| vulnsmb | 4455 | `projects/vulnsmb.yaml` |

---

## 3. Preflight (doctor)

Run doctor on the main lab profiles. Fix any **fail** items before live fuzzing.

```powershell
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnftp.yaml
dotnet run --project src/Randall.Cli -- doctor -c projects/vulntftp.yaml
```

**Expect:**

- `[✓] project` — YAML loads
- `[✓] target` — executable exists (after step 2)
- `[✓] sessionGraph` on vulnftp — graph validates
- `[!] dynamorio` — warn is OK if DynamoRIO is not installed
- Final line: `Ready to fuzz …`

Strict mode (fails if target exe missing):

```powershell
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnserver.yaml --strict
```

---

## 4. Dry-run fuzz (no network needed)

Syntax-check mutation pipeline without hitting targets:

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml --dry-run
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnftp.yaml --dry-run
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulntftp.yaml --dry-run
dotnet run --project src/Randall.Cli -- fuzz -c examples/tftp-simple/project.yaml --dry-run
```

**Expect:** Lines like `[dry-run] #1 TRUN/payload/bitflip len=14` and `Done: N iterations, 0 crashes`.

---

## 5. Session graph (CLI)

Validate boofuzz-style `s_switch` branching and print a Mermaid diagram:

```powershell
dotnet run --project src/Randall.Cli -- graph -c projects/vulnftp.yaml
```

**Expect:**

- `Session graph: vulnftp (start=USER, mutate=STOR)`
- Mermaid block with `USER -->|331| PASS` etc.

JSON output (for scripts):

```powershell
dotnet run --project src/Randall.Cli -- graph -c projects/vulnftp.yaml --json
```

---

## 6. Campaign smoke

Runs all lab profiles + examples with short iteration counts (dry-run):

```powershell
dotnet run --project src/Randall.Cli -- campaign -c campaigns/lab-smoke.yaml
```

**Expect:** Summary table ending with `[ok]` for each project and `Total crashes: 0` (dry-run).

---

## 7. Live fuzz (short runs)

These start real lab servers and send mutated traffic. **Run one at a time** — each binds its port.

### Vulnserver (classic TRUN overflow)

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml
```

Stop with Ctrl+C after you see several iterations (or a crash). Default max is 1000; you can edit `fuzz.maxIterations` in the YAML for a shorter run.

### VulnFtp (session graph + RPP plugins)

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnftp.yaml
```

**Expect:** Mix of `flow/…` and `graph/…` mutator names when session graph mode runs.

### VulnTftp (UDP)

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulntftp.yaml
```

**Expect:** `RRQ/filename/…` and `WRQ/filename/…` iterations.

### Check crashes

```powershell
dotnet run --project src/Randall.Cli -- crashes
dotnet run --project src/Randall.Cli -- crashes -p vulnserver
```

**Expect:** If a crash occurred, entries with hash, mutator, and optional **triage tag** (`access_violation`, `probable_overflow`, etc. from `plugins/crash-tag`).

Replay a saved crash:

```powershell
# Replace with an actual .bin path from data/crashes/<project>/
dotnet run --project src/Randall.Cli -- replay -c projects/vulnserver.yaml -i data/crashes/vulnserver/<file>.bin
```

---

## 8. Web UI

Start the server:

```powershell
dotnet run --project src/Randall.Server
```

Open **http://127.0.0.1:5000** in a browser.

| Tab | What to try |
|-----|-------------|
| **Dashboard** | Target count, DynamoRIO status |
| **Fuzz** | Select `vulnftp`, 200 iterations, dry-run ✓ → Start |
| **Fuzz → Doctor** | Preflight for selected target |
| **Session graph** | Select `vulnftp` → Load graph → see Mermaid diagram + edge table |
| **Campaign** | Run `lab-smoke.yaml` |
| **Crashes** | Filter by project; click a row for hex preview + triage tag |
| **Roadmap** | Phases 10–14 marked complete |

Stop the server with Ctrl+C.

---

## 9. Optional — coverage-guided fuzz

Only if DynamoRIO is installed and `DYNAMORIO_HOME` points at it.

1. Confirm: `dotnet run --project src/Randall.Cli -- doctor -c projects/file-text.yaml` shows `[✓] dynamorio`.
2. Set `coverageGuided: true` in `projects/file-text.yaml` (or use the web UI checkbox for file targets).
3. Run:

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/file-text.yaml
```

For TCP coverage stalk (instrumented spawn per iteration), enable `coverageGuided: true` and `coverageTcpSpawn: true` in `projects/vulnserver.yaml` — slower, needs DynamoRIO.

---

## 10. Quick reference

```powershell
# Aliases after: dotnet tool install -g Randall.Cli  (or use dotnet run --project …)

dotnet build
.\scripts\build-all-lab-targets.ps1
randall doctor -c projects/vulnftp.yaml
randall graph -c projects/vulnftp.yaml
randall campaign -c campaigns/lab-smoke.yaml
randall fuzz -c projects/vulnserver.yaml
randall serve
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Missing: …randall-vulnftp.exe` | Run `.\scripts\build-vulntftp.ps1` or `build-all-lab-targets.ps1` |
| Port already in use | Stop leftover lab `.exe` in Task Manager or change port in project YAML |
| `graph/` iterations with `len=0` | Normal in dry-run for session graph setup on FTP |
| No triage tag on crash | Ensure project YAML lists `plugins/crash-tag` with `hook: post_crash` |
| Mermaid blank in web UI | Hard-refresh; check browser console; try CLI `randall graph` instead |

---

## What “done” looks like

You’ve successfully validated Randall when:

1. `dotnet build` succeeds
2. All five lab targets build
3. `randall doctor` is ready for vulnserver, vulnftp, vulntftp
4. `lab-smoke` campaign completes with all `[ok]`
5. `randall graph -c projects/vulnftp.yaml` prints a valid Mermaid diagram
6. Web UI **Session graph** tab renders the FTP login flow
7. (Optional) A live fuzz run finds at least one crash and it appears under **Crashes** with a triage tag

Good hunting. Randall’s watching the factory floor.
