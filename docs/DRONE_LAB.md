# Drone protocol labs (RDL1)

Fictional **RDL1** drone telemetry / GCS command labs for protocol fuzz practice. This is **not** MAVLink, ArduPilot, PX4, or any real vehicle stack — no RF, no arming, no autopilot control.

| Lab | Port | Profile | Binary |
|-----|------|---------|--------|
| **VulnDrone UDP** | **15550/udp** | `projects/vulndrone-udp.yaml` | `targets/vulndrone/randall-vulndrone` |
| **VulnDrone TCP** | **15551/tcp** | `projects/vulndrone-tcp.yaml` | same binary, `--mode tcp` |

Source: `targets/Randall.VulnDrone/`.

## Build

```bash
scripts/build-lab-targets.sh vulndrone
# or
powershell -File scripts/build-vulndrone.ps1
```

## Quick path

```bash
# UDP telemetry
dotnet run --project src/Randall.Cli -- doctor -c projects/vulndrone-udp.yaml
dotnet run --project src/Randall.Cli -- fuzz   -c projects/vulndrone-udp.yaml

# TCP GCS-shaped commands
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulndrone-tcp.yaml
```

UI: Fuzz → Lab servers → category **Drone** → Start **VulnDrone UDP** / **VulnDrone TCP**.

## Wire format (lab-only)

### UDP telemetry (`--mode udp`)

```
magic "RDL1" | msgId u8 | len u16 LE | payload[len]
```

Crash paths (deterministic lab exits):

- Claimed `len` **> 256**
- `msgId == 0xFF` with a body larger than the 64-byte debug slot
- Heartbeat / attitude / GPS bodies longer than their fixed slots

Model: `projects/protocols/vulndrone_udp.yaml`.

### TCP GCS link (`--mode tcp`)

Banner: `RDL1 GCS READY`. Frames:

| Type | Layout | Crash when |
|------|--------|------------|
| **H** HELLO | `RDL1H` + name + `NUL` | name length **> 64** |
| **C** CMD | `RDL1C` + cmd u8 + len u16 + args | claimed args len **> 128** |
| **M** MISSION | `RDL1M` + count u16 + waypoints | waypoint **count > 16** |

Models: `vulndrone_tcp_hello.yaml`, `vulndrone_tcp_cmd.yaml`, `vulndrone_tcp_mission.yaml`.

## Honest limits

- Loopback by default; do not expose on a public interface.
- Protocol shape is deliberately small so length-field and table-size bugs are easy to hit.
- Do not treat crashes as evidence about real drone products — use your own harnesses for those.
- Randfuzz will not ship weaponized vehicle control, shellcode, or exploit templates for this lab.

See also defense-shaped UAS / sentry labs: [DEFENSE_LAB.md](DEFENSE_LAB.md).
