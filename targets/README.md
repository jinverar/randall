# Lab targets

Build all lab servers:

```powershell
.\scripts\build-all-lab-targets.ps1
```

**Bind address:** Labs listen on **127.0.0.1** by default (safe on public Wi‑Fi). Pass `--host 0.0.0.0` only on a private lab network.

**UI:** Fuzz → **Lab servers** — see running PIDs, Start / Stop / Stop all (no Process Explorer required).

## Randfuzz lab servers

| Target | Port | Profile | Source |
|--------|------|---------|--------|
| **Vulnserver** | 9999 | `projects/vulnserver.yaml` | [Randall.Vulnserver](Randall.Vulnserver/) |
| **VulnHttp** | 8080 | `projects/vulnhttp.yaml` | [Randall.VulnHttp](Randall.VulnHttp/) |
| **VulnFtp** | 2121 | `projects/vulnftp.yaml` | [Randall.VulnFtp](Randall.VulnFtp/) |
| **VulnSsh** | 2222 | `projects/vulnssh.yaml` | [Randall.VulnSsh](Randall.VulnSsh/) (stub, not real crypto) |
| **VulnTftp** | 6969 | `projects/vulntftp.yaml` | [Randall.VulnTftp](Randall.VulnTftp/) |
| **VulnRpc** | 1355 | `projects/vulnrpc.yaml` | [Randall.VulnRpc](Randall.VulnRpc/) (DCE-shaped lab) |
| **VulnSmb** | 4455 | `projects/vulnsmb.yaml` | [Randall.VulnSmb](Randall.VulnSmb/) (NBSS+SMB2-shaped lab) |

Examples ported from [boofuzz](https://github.com/jtpereyda/boofuzz): see [docs/EXAMPLES.md](../docs/EXAMPLES.md). Labs: [RPC_LAB.md](../docs/RPC_LAB.md) · [SMB_LAB.md](../docs/SMB_LAB.md).

## Randfuzz Vulnserver (included)

Build the custom lab server from source:

```powershell
.\scripts\build-vulnserver.ps1
```

This produces `targets/vulnserver/randall-vulnserver.exe` — compatible with `projects/vulnserver.yaml` (TRUN, GMON, GTER, KSTET, HTER, STAT, RAND).

```powershell
randall doctor -c projects/vulnserver.yaml
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml
```

Randall starts the server, connects to `127.0.0.1:9999`, and detects when the process crashes.

Source: [Randall.Vulnserver/README.md](Randall.Vulnserver/README.md)

## File labs (in-repo mini-parsers)

Out-of-box `doctor`/`fuzz` — no external exe required after build:

| Target | Profile | Build |
|--------|---------|-------|
| **file-text** | `projects/file-text.yaml` | `scripts/build-file-text.sh` / `.ps1` |
| **file-framed** | `projects/file-framed.yaml` | `scripts/build-file-framed.sh` / `.ps1` |
| **ReelDeck** | `projects/reeldeck.yaml` | `scripts/build-reeldeck.sh` / `.ps1` |

```bash
scripts/build-file-text.sh
dotnet run --project src/Randall.Cli -- fuzz -c projects/file-text.yaml
```

Point `target.executable` at your own parser when you outgrow the teaching floor.

### ReelDeck (media player / studio — deeper file lab)

Larger multi-path `.rndl` container (PCM / MAD / VID / studio). Built for the **fuzz → path-stalk → deepen** maturity loop:

```bash
scripts/build-reeldeck.sh && python3 scripts/gen-reeldeck-seeds.py
dotnet run --project src/Randall.Cli -- fuzz -c projects/reeldeck.yaml --profile fuzzier
cat data/corpus/reeldeck/paths.txt
```

Docs: [REELDECK.md](../docs/REELDECK.md)
## Private targets (not committed)

Keep real lab binaries and configs out of the public repo:

```
targets/local/          ← your executables
projects/local/         ← your YAML + seeds (gitignored)
```

```powershell
dotnet run --project src/Randall.Cli -- fuzz -c projects/local/my-target.yaml
```

## Crashes

Saved under `data/crashes/<target>/` with `index.jsonl` metadata.

```powershell
dotnet run --project src/Randall.Cli -- crashes
dotnet run --project src/Randall.Cli -- crashes -p vulnserver
```
