# VulnDrone (RDL1 lab)

Fictional drone telemetry / GCS command target for Randfuzz. **Not** real MAVLink or vehicle control.

```bash
# from repo root
scripts/build-lab-targets.sh vulndrone
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulndrone-udp.yaml
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulndrone-tcp.yaml
```

CLI: `--mode udp|tcp`, `-p` / `--port`, `-h` / `--host` (default loopback).

Docs: [DRONE_LAB.md](../../docs/DRONE_LAB.md).
