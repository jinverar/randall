# Robot protocol labs (RBT1 / RRBS / RMB1)

Fictional robot-cell fuzz labs for length-field and table-size practice. These are **not** ROS, DDS, URScript, Fanuc, ABB, KUKA, EtherCAT, Modbus/TCP, or any real pendant / safety PLC / fieldbus — no motors, no RF, no industrial I/O.

| Lab | Port | Profile | Binary |
|-----|------|---------|--------|
| **VulnRobot TCP** | **15560/tcp** | `projects/vulnrobot.yaml` | `targets/vulnrobot/randall-vulnrobot` |
| **VulnRobot UDP** | **15561/udp** | `projects/vulnrobot-udp.yaml` | same binary (`--mode udp`) |
| **VulnRosBus** | **15562/tcp** | `projects/vulnrosbus.yaml` | `targets/vulnrosbus/randall-vulnrosbus` |
| **VulnRobotIo** | **15502/tcp** | `projects/vulnrobotio.yaml` | `targets/vulnrobotio/randall-vulnrobotio` |

Sources: `targets/Randall.VulnRobot/`, `Randall.VulnRosBus/`, `Randall.VulnRobotIo/`.

## Build

```bash
scripts/build-lab-targets.sh vulnrobot
scripts/build-lab-targets.sh vulnrosbus
scripts/build-lab-targets.sh vulnrobotio
# or
powershell -File scripts/build-vulnrobot.ps1
powershell -File scripts/build-vulnrosbus.ps1
powershell -File scripts/build-vulnrobotio.ps1
```

## Quick path

```bash
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnrobot.yaml
dotnet run --project src/Randall.Cli -- fuzz   -c projects/vulnrobot-udp.yaml
dotnet run --project src/Randall.Cli -- fuzz   -c projects/vulnrosbus.yaml
dotnet run --project src/Randall.Cli -- fuzz   -c projects/vulnrobotio.yaml
```

UI: Fuzz → Lab library → category **Robot** → Start any of the four labs.

---

## VulnRobot TCP (RBT1 motion)

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

## VulnRobot UDP (RBT1 telemetry)

```
"RBT1" | msgId_u8 | len_u16_BE | payload[len]
```

| msgId | Slot | Crash when |
|-------|------|------------|
| `0x10` pose | 48 B | `len > 256` or payload/claimed `> slot` |
| `0x11` force | 64 B | same |
| `0x1F` diag | 32 B | same |

Model: `protocols/vulnrobot_udp.yaml`.

## VulnRosBus (RRBS topic bus)

Fictional ROS-shaped topic/service/param framing — **not** ROS, DDS, or rcl.

```
magic_BE 0x5252 | ver 0x01 | type | topic_len_BE | topic | payload_len_BE | payload
```

| Type | Kind | Crash when |
|------|------|------------|
| `0x01` | TOPIC | `topic_len > 48`, `payload_len > 256`, `/cmd_vel` payload `> 48`, long name + big payload |
| `0x02` | SERVICE | `/trigger*` + request id `0xDEADBEEF`, or oversize request |
| `0x03` | PARAM | `__internal__*` key with value `> 128` |

Models: `protocols/vulnrosbus_topic.yaml`, `vulnrosbus_service.yaml`, `vulnrosbus_param.yaml`.

## VulnRobotIo (RMB1 cell I/O)

Fictional Modbus-shaped ADU — **not** Modbus/TCP or a PLC stack. Protocol id is `0x0001` (not Modbus `0`).

```
txId_BE | proto_BE 0x0001 | len_BE | unit | func | PDU…
```

| Func | Kind | Crash when |
|------|------|------------|
| `0x01` | READ_COILS | `qty > 200` (or out-of-range window) |
| `0x03` | READ_REGS | `qty > 64` out of range |
| `0x05` / `0x06` | WRITE_* | address past map; reg `0x7F`/`0xBEEF` |
| `0x08` | DIAG | subcode `0xFFFF` or PDU `> 64` |
| — | MBAP | `len > 512` or PDU buffer oversize |

Models: `protocols/vulnrobotio_read.yaml`, `vulnrobotio_write.yaml`, `vulnrobotio_diag.yaml`.

## Honest limits

- Loopback by default; do not expose on a public interface.
- Packets are deliberately **not** accepted by real robot controllers, ROS masters, or Modbus devices — use these labs for Randfuzz practice only.
- Do not treat crashes as evidence about commercial robot products or safety systems.
- Randfuzz will not ship weaponized robot control, motion payloads, or exploit templates for these labs.
