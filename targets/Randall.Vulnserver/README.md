# Randall Vulnserver

Custom TCP lab server for Randall fuzzing — **vulnserver-compatible** command surface, ships with source.

## Build

```powershell
cd C:\Users\007\Projects\randall
.\scripts\build-vulnserver.ps1
```

Output: `targets/vulnserver/randall-vulnserver.exe`

## Run manually

```powershell
.\targets\vulnserver\randall-vulnserver.exe
# or custom port:
.\targets\vulnserver\randall-vulnserver.exe --port 9999
```

## Commands (intentionally vulnerable)

| Command | Bug class |
|---------|-----------|
| `TRUN /.:/` | Stack buffer overflow (~256 byte buffer) |
| `GMON /.:/` | Stack overflow (200 bytes) |
| `GTER ` | Stack overflow (128 bytes) |
| `KSTET /.:/` | Stack overflow (180 bytes) |
| `HTER /.:/` | Stack overflow (160 bytes) |
| `RAND ` | Randall easter-egg overflow (192 bytes) |
| `STAT` / `STATS` | Safe — stats probe for session flows |
| `HELP` | Safe — command list |

## Fuzz with Randall

```powershell
randall doctor -c projects/vulnserver.yaml
randall fuzz -c projects/vulnserver.yaml --dry-run
randall fuzz -c projects/vulnserver.yaml
```

**Authorized local testing only.** Do not expose to networks you do not control.
