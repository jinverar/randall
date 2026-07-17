# Cursor Automations — Randfuzz nightly lab

Use a **Cursor Automation** to run Randfuzz smoke campaigns on a schedule without babysitting the fuzz box.

## What to automate

Typical nightly flow:

1. `dotnet build` (or use a published standalone pack)
2. `randall campaign -c campaigns/lab-smoke.yaml` (dry-run smoke)
3. Optional: `randall campaign -c campaigns/nightly-lab.yaml` when vulnserver is installed
4. Post summary — iteration count, crashes found, corpus edges

## Suggested trigger

| Setting | Value |
|---------|--------|
| Trigger | **On a schedule** — weekdays at 2:00 AM (or after your lab VM boots) |
| Repo | `jinverar/randall` |
| Branch | `main` |

## Agent instructions (paste into automation prompt)

```
You are the Randfuzz lab autopilot on a Windows fuzz VM.

1. cd to the randall repo root.
2. dotnet build --no-restore if packages exist, else dotnet build.
3. Run: dotnet run --project src/Randall.Cli -- campaign -c campaigns/lab-smoke.yaml
4. If targets/vulnserver/vulnserver.exe exists, also run campaigns/nightly-lab.yaml with max 200 iterations.
5. Summarize: builds OK/fail, campaign runs, total crashes, any errors in output.
6. Do not commit or push unless explicitly asked.
```

## Tools to enable

- Shell / terminal access on the cloud agent or local runner
- Optional: **Comment on PR** if you wire this to a PR trigger instead of cron

## Local vs cloud

| Mode | Command | Notes |
|------|---------|-------|
| **Local VM** | Cursor Automation with local runner | Best when lab binaries live on the box |
| **Cloud agent** | Scheduled cloud run | Good for build + dry-run smoke only |
| **Manual** | `randall agent --port 5000` | LAN web UI; automation hits API instead |

## API-driven alternative

With `randall agent` listening on the LAN:

```http
POST /api/campaign/start
{ "campaignPath": "campaigns/lab-smoke.yaml" }
```

Poll `GET /api/campaign/status` until idle, then read `GET /api/crashes`.

## Private targets

Automations that fuzz **private** targets should reference `projects/local/*.yaml` on the VM only — those paths are gitignored and never pushed to GitHub.

## Create the automation in Cursor

1. Open **Automations** in Cursor
2. New automation → **Schedule** trigger
3. Paste the agent instructions above
4. Enable shell tools
5. Save and run once manually to verify

See also [ROADMAP.md](ROADMAP.md) Phase 7 and [RPP.md](RPP.md) for plugin hooks.
