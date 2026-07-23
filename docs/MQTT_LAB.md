# MQTT-shaped IoT labs (RMQ1)

Fictional **RMQ1** broker-shaped TCP lab for IoT / length-field fuzz practice. This is **not** MQTT 3.1.1/5 wire format — remaining length is a fixed **u16 big-endian** (no MQTT varint), protocol name is `RMQ1`, and there is no TLS, password auth, or device control.

| Lab | Port | Profile | Binary |
|-----|------|---------|--------|
| **VulnMqtt** | **18883/tcp** | `projects/vulnmqtt.yaml` | `targets/vulnmqtt/randall-vulnmqtt` |

Source: `targets/Randall.VulnMqtt/`.

## Build

```bash
scripts/build-lab-targets.sh vulnmqtt
# or
powershell -File scripts/build-vulnmqtt.ps1
```

## Quick path

```bash
dotnet run --project src/Randall.Cli -- doctor -c projects/vulnmqtt.yaml
dotnet run --project src/Randall.Cli -- fuzz   -c projects/vulnmqtt.yaml
```

UI: Fuzz → Lab library → category **IoT** → Start **VulnMqtt**.

## Wire format (lab-only)

```
type_u8 | rem_len_u16_BE | body[rem_len]
```

| Type byte | Kind | Body sketch | Crash when |
|-----------|------|-------------|------------|
| `0x10` | CONNECT | proto_len + `RMQ1` + level/flags/keepalive + **client_id_len** + id | `client_id_len > 64` or id bytes `> 64` |
| `0x30` | PUBLISH | **topic_len** + topic + payload | `topic_len > 128`, topic bytes `> 128`, or payload `> 256` |
| `0x82` | SUBSCRIBE | pkt_id + **count** + (topic_len + topic + qos)×N | `count > 8` or any `topic_len > 96` |
| any | — | — | `rem_len > 512` |

Models: `protocols/vulnmqtt_connect.yaml`, `vulnmqtt_publish.yaml`, `vulnmqtt_subscribe.yaml`.

## Honest limits

- Loopback by default; do not expose on a public interface.
- Packets are deliberately **not** accepted by Mosquitto / real brokers — use this lab for Randfuzz practice only.
- Do not treat crashes as evidence about commercial MQTT products.
- Randfuzz will not ship weaponized IoT payloads or broker exploit templates for this lab.
