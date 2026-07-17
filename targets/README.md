# Lab targets

Build all lab servers:

```powershell
.\scripts\build-all-lab-targets.ps1
```

## Randfuzz lab servers

| Target | Port | Profile | Source |
|--------|------|---------|--------|
| **Vulnserver** | 9999 | `projects/vulnserver.yaml` | [Randall.Vulnserver](Randall.Vulnserver/) |
| **VulnHttp** | 8080 | `projects/vulnhttp.yaml` | [Randall.VulnHttp](Randall.VulnHttp/) |
| **VulnFtp** | 2121 | `projects/vulnftp.yaml` | [Randall.VulnFtp](Randall.VulnFtp/) |
| **VulnSsh** | 2222 | `projects/vulnssh.yaml` | [Randall.VulnSsh](Randall.VulnSsh/) (stub, not real crypto) |

Examples ported from [boofuzz](https://github.com/jtpereyda/boofuzz): see [docs/EXAMPLES.md](../docs/EXAMPLES.md).

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

## Generic file templates

`projects/file-text.yaml` and `projects/file-framed.yaml` are **placeholders**. Edit `target.executable`, seeds, and block models for your format.

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
