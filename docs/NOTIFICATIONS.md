# Notifications — Discord + email

Randfuzz can **scream outbound** when a unique crash is saved, or when a campaign finishes.

Channels:

| Channel | Transport | Secrets |
|---------|-----------|---------|
| **Discord** | Incoming webhook (`POST`) | `RANDALL_DISCORD_WEBHOOK` |
| **Email** | SMTP (`System.Net.Mail`) | `RANDALL_SMTP_*` |

Notifications are **opt-in** via a `notifications:` block on a project or campaign YAML. Nothing is sent unless `enabled: true` and at least one channel is configured.

## Quick start

1. Create a Discord webhook (Server settings → Integrations → Webhooks) or note your SMTP host.
2. Put secrets in the environment (or a gitignored `.env` loaded by your shell) — never commit webhook URLs or passwords.
3. Copy the snippet below into `projects/local/myservice.yaml` (or a campaign YAML).
4. Preflight + test:

```powershell
$env:RANDALL_DISCORD_WEBHOOK = "https://discord.com/api/webhooks/…"
# optional email:
$env:RANDALL_SMTP_HOST = "smtp.example.com"
$env:RANDALL_SMTP_USER = "randall@lab.local"
$env:RANDALL_SMTP_PASSWORD = "…"
$env:RANDALL_SMTP_FROM = "randall@lab.local"
$env:RANDALL_SMTP_TO = "ops@lab.local"
$env:RANDALL_UI_BASE_URL = "http://127.0.0.1:5000"

randall doctor -c projects/local/myservice.yaml
randall notify test -c projects/local/myservice.yaml
randall fuzz -c projects/local/myservice.yaml
```

## Project YAML

```yaml
# projects/local/myservice.yaml
notifications:
  enabled: true
  onUniqueCrash: true          # default true — only NEW hashes (CrashStore dedup)
  onCampaignComplete: false    # usually set on campaign YAML instead
  uiBaseUrlEnv: RANDALL_UI_BASE_URL   # optional crash deep-link
  discord:
    enabled: true
    webhookUrlEnv: RANDALL_DISCORD_WEBHOOK
    username: Randfuzz
  email:
    enabled: true
    smtpHostEnv: RANDALL_SMTP_HOST
    smtpPort: 587
    useSsl: true
    fromEnv: RANDALL_SMTP_FROM
    toEnv: RANDALL_SMTP_TO        # comma/semicolon separated
    usernameEnv: RANDALL_SMTP_USER
    passwordEnv: RANDALL_SMTP_PASSWORD
```

Inline values (`webhookUrl`, `smtpHost`, `from`, `to: […]`, `username`, `password`) work too — prefer env vars for anything secret. Keep this under `projects/local/` (gitignored).

Full template: [templates/notifications.yaml](templates/notifications.yaml).

## Campaign YAML

```yaml
# campaigns/nightly-local.yaml  (keep private if it holds notify config)
name: nightly-local
notifications:
  enabled: true
  onUniqueCrash: false
  onCampaignComplete: true
  discord:
    enabled: true
    webhookUrlEnv: RANDALL_DISCORD_WEBHOOK
runs:
  - project: projects/vulnserver.yaml
    maxIterations: 2000
```

Per-project crash alerts still fire from each run’s project `notifications:` block. Campaign complete is a separate summary (totals + per-run table).

## What gets sent

### Unique crash

Fired only when `CrashStore.SaveEx` reports **IsNew** (same input hash → silent dedup).

Includes: project, crash GUID, iteration, mutator, exception hint, triage tag, detail, input/dump paths, optional UI deep-link (`{uiBaseUrl}/#crashes?id={guid}`).

### Campaign complete

Includes: campaign name, success flag, run count, crash totals, short per-run lines.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `RANDALL_DISCORD_WEBHOOK` | Discord incoming webhook URL |
| `RANDALL_SMTP_HOST` | SMTP hostname |
| `RANDALL_SMTP_USER` | SMTP auth user |
| `RANDALL_SMTP_PASSWORD` | SMTP auth password |
| `RANDALL_SMTP_FROM` | From address |
| `RANDALL_SMTP_TO` | Recipients (`,` or `;`) |
| `RANDALL_UI_BASE_URL` | Base URL for crash/campaign links (no trailing slash) |

YAML `*Env` fields override the default env names above when you need multiple lab profiles.

## Doctor + CLI

```powershell
randall doctor -c projects/local/myservice.yaml
# → notifications: ok  discord, email

randall notify test -c projects/local/myservice.yaml
# → [ok] discord  HTTP 204
# → [ok] email    sent to ops@lab.local via smtp.example.com:587
```

`notify test` temporarily treats `enabled: true` so you can dry-run a disabled block; channels still need `discord.enabled` / `email.enabled`.

## Failure behavior

Notify failures **never abort** the fuzz loop. Soft-fail messages appear in the live analyst log (`notify/discord failed: …`). Check webhook permissions, SMTP TLS/port, and that the lab VM can reach Discord / your mail host.

## Security notes

- Lab-oriented: do not point webhooks at public channels with sensitive crash payloads unless you intend to.
- Prefer env / `projects/local/` over committed YAML.
- Discord webhook URLs are bearer secrets — rotate if leaked.
- Email sends plaintext body (paths + exception hints); use an internal SMTP relay when possible.

Related: [CRASH_LOGGING.md](CRASH_LOGGING.md) · [AUTOPILOT.md](AUTOPILOT.md) · [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md)
