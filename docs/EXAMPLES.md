# Examples

Randall examples mirror [boofuzz/examples](https://github.com/jtpereyda/boofuzz/tree/master/examples) as **YAML projects** instead of Python scripts.

## Quick start

```powershell
dotnet build
.\scripts\build-all-lab-targets.ps1

# Dry-run an example (no target required for syntax check)
randall fuzz -c examples/http-simple/project.yaml --dry-run
randall fuzz -c examples/ftp-simple/project.yaml --dry-run

# Full lab run
randall fuzz -c projects/vulnhttp.yaml
randall fuzz -c projects/vulnftp.yaml
randall fuzz -c projects/vulnssh.yaml
```

## Example index

| Folder | Description | Lab target |
|--------|-------------|------------|
| `examples/http-simple/` | HTTP GET (boofuzz `http_simple.py`) | `projects/vulnhttp.yaml` |
| `examples/ftp-simple/` | FTP session (boofuzz `ftp_simple.py`) | `projects/vulnftp.yaml` |
| `examples/https-simple/` | TLS HTTP template | any HTTPS service |

## Boofuzz import

```powershell
python scripts/import-boofuzz.py path/to/boofuzz/examples/ftp_simple.py -o projects/imported/ftp --port 2121
randall fuzz -c projects/imported/ftp/project.yaml --dry-run
```

## Lab targets (Monsters Inc. factory floor)

| Target | Port | Build | Fuzz profile |
|--------|------|-------|--------------|
| Vulnserver | 9999 | `build-vulnserver.ps1` | `projects/vulnserver.yaml` |
| VulnHttp | 8080 | `build-vulnhttp.ps1` | `projects/vulnhttp.yaml` |
| VulnFtp | 2121 | `build-vulnftp.ps1` | `projects/vulnftp.yaml` |
| VulnSsh | 2222 | `build-vulnssh.ps1` | `projects/vulnssh.yaml` |
| VulnTftp | 6969 | `build-vulntftp.ps1` | `projects/vulntftp.yaml` |

Build all: `.\scripts\build-all-lab-targets.ps1`

## Exhaustive vs random

Boofuzz `session.fuzz()` walks every mutation. In Randall:

```yaml
fuzz:
  mode: exhaustive   # or random (default)
```

See [BOOFUZZ_PARITY.md](BOOFUZZ_PARITY.md).
