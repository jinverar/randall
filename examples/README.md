# Examples — Randfuzz for boofuzz users

Self-contained YAML projects ported from [boofuzz/examples](https://github.com/jtpereyda/boofuzz/tree/master/examples).

| Example | Boofuzz source | Randfuzz command |
|---------|----------------|-----------------|
| [http-simple](http-simple/) | `http_simple.py` | `randall fuzz -c examples/http-simple/project.yaml --dry-run` |
| [ftp-simple](ftp-simple/) | `ftp_simple.py` | `randall fuzz -c examples/ftp-simple/project.yaml --dry-run` |
| [ai-code-sample](ai-code-sample/) | (attribution fixture) | `randall hunt attribution -d examples/ai-code-sample` |

Pair with lab targets:

```powershell
.\scripts\build-all-lab-targets.ps1
randall fuzz -c projects/vulnhttp.yaml
randall fuzz -c projects/vulnftp.yaml
```

See [docs/BOOFUZZ_PARITY.md](../docs/BOOFUZZ_PARITY.md) for the feature matrix.
