# Lab servers: local status & remote agent

See which practice vuln servers are running, start/stop them, and do the same on a remote fuzz box — without Process Explorer and without a kernel driver.

**Next evolution:** arbitrary apps + unified start/stop/restart/triage → [TARGET_RUNTIME.md](TARGET_RUNTIME.md) (quick text at repo root: `TARGET_RUNTIME_README.txt`).

## Where to look in the UI

1. Open **Fuzz**.
2. On **Campaign**, the **Lab servers** strip at the top shows how many labs are running (chips with name + port).
3. Open the **Lab servers** tab (badge count = how many are up) for the full table: status, PID, Start/Stop.

Campaign’s **Idle** box is only the *fuzz campaign* state, not lab process status.

Hard-refresh the browser (`Ctrl+F5`) after upgrading `randall serve` so you get the Lab servers tab and strip.

## Local (this machine)

```powershell
.\scripts\build-all-lab-targets.ps1
dotnet run --project src/Randall.Cli -- serve
```

Then **Fuzz → Lab servers** → Start / Stop / Stop all.

CLI:

```powershell
dotnet run --project src/Randall.Cli -- labs
dotnet run --project src/Randall.Cli -- labs start vulnserver
dotnet run --project src/Randall.Cli -- labs stop-all
```

New lab starts bind **127.0.0.1** on that host.

## Remote fuzz machine (user-mode agent)

Deploy the same Randfuzz build to the lab VM. Run the agent so it listens on the LAN:

```powershell
# On the remote fuzz box (after build + lab targets)
dotnet run --project src/Randall.Cli -- agent --port 5000
```

`randall agent` is the same web host as `serve`, bound to **0.0.0.0** by default. Opening `http://<lab-ip>:5000` in a browser is the **remote Target Runtime lab UI** (badge: Remote lab) — fuzz there when you need dumps + memory lens on the box.

On your laptop UI:

1. **Fuzz → Lab servers**
2. Set **Remote agent URL** to `http://<lab-ip>:5000` (private LAN only: `10.*`, `192.168.*`, `172.16–31.*`, or localhost)
3. **Test agent** → then Start/Stop as usual

The console proxies lab / Target Runtime APIs to that agent. No kernel driver: the agent process owns start/stop and reports running PIDs.

Leave the agent URL empty (or **Use local**) to manage labs on the machine running `serve`.

### Offline pull of dumps + lens

After fuzzing **on the agent**, back up and import into the laptop later:

```powershell
# On laptop
dotnet run --project src/Randall.Cli -- crashes pull -a http://<lab-ip>:5000 -p vulnserver --import
```

Or **Bundles → Pull from remote agent**. Details: [TARGET_RUNTIME.md](TARGET_RUNTIME.md)#remote-lab-workflow-dumps--lens--offline-import.

## Why not a kernel driver?

For practice labs and user-mode targets, a small agent is enough: spawn/kill processes, check PIDs, and expose status over HTTP. A driver would only matter for kernel targets or anti-tamper scenarios — not required for this workflow.

## Security notes

- Agent URL hosts are restricted to loopback / RFC1918 private addresses (MVP SSRF guard).
- Labs still default to loopback on the *target* machine; expose the agent port only on a trusted lab network.
- Do not put the agent on the public internet.
- **Optional shared secret:** set `RANDALL_AGENT_TOKEN` or pass `--token SECRET` to `randall agent` / `serve`. When set, `/api/*` and SignalR hubs require `Authorization: Bearer …` or `X-Randall-Token` (static UI + `/api/health` stay open). Laptop UI: **Lab servers → Agent token**. CLI pull: `randall crashes pull … --token SECRET`.
- Without a token on `0.0.0.0`, the CLI prints a WARN — this is still lab-grade, not multi-user IAM. See [MATURITY.md](MATURITY.md).

```powershell
# On the fuzz box
$env:RANDALL_AGENT_TOKEN = "lab-secret"
randall agent --port 5000
# or: randall agent --port 5000 --token lab-secret

# On the laptop
randall crashes pull -a http://192.168.2.10:5000 -p vulnserver --token lab-secret --import
```
