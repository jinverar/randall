# Robot motion labs (RBT1)

Fictional **RBT1** robot-arm / motion-controller TCP lab for length-field and table-size fuzz practice. This is **not** ROS, DDS, URScript, Fanuc, ABB, KUKA, EtherCAT, or any real pendant / safety PLC / fieldbus — no motors, no RF, no industrial I/O.

| Lab | Port | Profile | Binary |
|-----|------|---------|--------|
| **VulnRobot** | **15560/tcp** | `projects/vulnrobot.yaml` | `targets/vulnrobot/randall-vulnrobot` |

Source: `targets/Randall.VulnRobot/`.

## Build

```bash
scripts/build-lab-targets.sh vulnrobot
# or
powershell -File scripts/build-vulnrobot.ps1
```

## Quick path

```bash
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnrobot.yaml
dotnet run --project src/Randall.Cli -- fuzz   -c projects/vulnrobot.yaml
```

UI: Fuzz → Lab library → category **Robot** → Start **VulnRobot**.

## Wire format (lab-only)

Banner: `RBT1 ROBOT READY`. Frames:

```
type_u8 | rem_len_u16_BE | body[rem_len]
```

| Type | Kind | Body sketch | Crash when |
|------|------|-------------|------------|
| `0x01` | HELLO | **name_len** + name | `name_len > 64` or name bytes `> 64` |
| `0x02` | JOINT | **joint_count** + angles (4 B each) | `count > 8` |
| `0x03` | TRAJ | **waypoint_count** + waypoints (8 B each) | `count > 16` |
| `0x04` | TOOL | **path_len** + toolpath blob | `path_len > 128` or path `> 128` |
| any | — | — | `rem_len > 512` |

Models: `protocols/vulnrobot_hello.yaml`, `vulnrobot_joint.yaml`, `vulnrobot_traj.yaml`, `vulnrobot_tool.yaml`.

## Honest limits

- Loopback by default; do not expose on a public interface.
- Packets are deliberately **not** accepted by real robot controllers — use this lab for Randfuzz practice only.
- Do not treat crashes as evidence about commercial robot products or safety systems.
- Randfuzz will not ship weaponized robot control, motion payloads, or exploit templates for this lab.
