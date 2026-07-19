# Install on Windows 10 / 11 (VM or bare metal)

Fresh-box checklist for Randfuzz. Use this on a **Windows 10/11 VM** or a local machine.

**Time:** ~15–25 minutes (plus DynamoRIO download if you want coverage).

---

## 0. VM recommendations

| Setting | Suggestion |
|---------|------------|
| RAM | 4 GB minimum, **8 GB** better (DynamoRIO + lab targets) |
| Disk | ≥40 GB free |
| Network | NAT for solo use; **bridged** if the host will open the lab agent |
| Snapshot | Take one after Windows updates, before installing tools |

---

## 1. Install .NET 8 SDK

1. Open [.NET 8 downloads](https://dotnet.microsoft.com/download/dotnet/8.0)
2. Install **SDK 8.x** (x64)
3. Open a **new** PowerShell window:

```powershell
dotnet --version
```

Expect `8.0.x`.

---

## 2. Install Git

1. [Git for Windows](https://git-scm.com/download/win) — defaults are fine
2. Verify:

```powershell
git --version
```

---

## 3. Clone the repo

```powershell
cd $env:USERPROFILE\Projects
# or: mkdir C:\src; cd C:\src
git clone https://github.com/jinverar/randall.git
cd randall
```

---

## 4. Build Randfuzz

```powershell
dotnet build
```

Expect `Build succeeded`.

---

## 5. Build lab targets

```powershell
.\scripts\build-all-lab-targets.ps1
```

Compiles vulnserver, vulnhttp, vulnftp, and other practice targets under `targets\`.

---

## 6. (Optional) DynamoRIO — coverage stalking

Needed for `+N edges` / coverage-guided corpus. Crashes work without it.

```powershell
powershell -File scripts\install-dynamorio.ps1
```

Session env (or set a permanent user variable `DYNAMORIO_HOME`):

```powershell
$env:DYNAMORIO_HOME = (Resolve-Path tools\dynamorio).Path
Test-Path "$env:DYNAMORIO_HOME\bin64\drrun.exe"   # should be True
```

---

## 7. Doctor (preflight)

```powershell
dotnet run --project src\Randall.Cli -- doctor -c projects\vulnserver.yaml
```

Expect `[✓] project`, `[✓] target`, and **Ready to fuzz**.  
`[!] dynamorio` is OK if you skipped step 6.

---

## 8. Start the web UI

```powershell
dotnet run --project src\Randall.Server --urls http://127.0.0.1:5000
```

Open **http://127.0.0.1:5000** — Dashboard, Fuzz, Crashes, Case builder, Help.

### Smoke tests

```powershell
# Dry-run (no long live fuzz)
dotnet run --project src\Randall.Cli -- fuzz -c projects\vulnserver.yaml --dry-run

# Short live run
dotnet run --project src\Randall.Cli -- fuzz -c projects\vulnserver.yaml --max-iterations 50

# In-process harness demo
dotnet build targets\Randall.HarnessDemo
dotnet run --project src\Randall.Cli -- fuzz -c projects\harness-demo.yaml
```

---

## 9. Remote lab agent (optional)

On the VM (listens for LAN clients):

```powershell
dotnet run --project src\Randall.Cli -- agent --port 5000
```

From the host browser: `http://<vm-ip>:5000` (allow inbound TCP 5000 in Windows Firewall).  
For real dumps / memory lens, **fuzz on the agent UI** — see [LAB_AGENT.md](LAB_AGENT.md) and [TARGET_RUNTIME.md](TARGET_RUNTIME.md).

---

## Common gotchas

| Issue | Fix |
|-------|-----|
| `dotnet` not found | New PowerShell after SDK install; check PATH |
| Lab target missing | Re-run `.\scripts\build-all-lab-targets.ps1` |
| Port 5000 in use | Stop other Server/agent processes |
| OOM / very slow | Raise VM RAM; avoid every lab + DynamoRIO at once |
| Clone / TLS errors | Fix VM date/time; check proxy |

---

## Next

- Hands-on lab checklist: [LAB_PRACTICE.md](LAB_PRACTICE.md)
- Custom targets: [CUSTOM_TARGETS.md](CUSTOM_TARGETS.md)
- Harness design: [HARNESS_DESIGN.md](HARNESS_DESIGN.md)
