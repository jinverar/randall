# Defense-shaped protocol labs (UAS1 / STT1)

Fictional **tactical-link** and **sentry-station** fuzz labs for length-field practice. These sit beside the existing RDL1 drone labs and are **not** real military systems.

**Honest boundary:** no RF, no vehicle control, no fire control, no arming, no munitions, no IFF, no real GCS/autopilot/turret hardware. Sensor-bay and pan/tilt frames are teaching stubs only.

| Lab | Port | Profile | Binary |
|-----|------|---------|--------|
| **VulnUas TCP** | **15650/tcp** | `projects/vulnuas.yaml` | `targets/vulnuas/randall-vulnuas` |
| **VulnUas UDP** | **15651/udp** | `projects/vulnuas-udp.yaml` | same (`--mode udp`) |
| **VulnTurret TCP** | **15660/tcp** | `projects/vulnturret.yaml` | `targets/vulnturret/randall-vulnturret` |
| **VulnTurret UDP** | **15661/udp** | `projects/vulnturret-udp.yaml` | same (`--mode udp`) |

Related: existing RDL1 drone labs in [DRONE_LAB.md](DRONE_LAB.md) (`:15550` / `:15551`).

Sources: `targets/Randall.VulnUas/`, `targets/Randall.VulnTurret/`.

## Build

```bash
scripts/build-lab-targets.sh vulnuas
scripts/build-lab-targets.sh vulnturret
# or
powershell -File scripts/build-vulnuas.ps1
powershell -File scripts/build-vulnturret.ps1
```

## Quick path

```bash
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnuas.yaml
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnuas-udp.yaml
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnturret.yaml
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnturret-udp.yaml
```

UI: Fuzz → Lab library → category **Defense**.

---

## VulnUas (UAS1 tactical link)

Banner: `UAS1 LINK READY`. Frames: `type_u8 | rem_len_u16_BE | body`.

| Type | Kind | Crash when |
|------|------|------------|
| `0x01` | HELLO | callsign len `> 64` |
| `0x02` | ROUTE | waypoint count `> 16` |
| `0x03` | SENSOR | sensor-bay cfg len `> 128` (config only — not munitions) |
| `0x04` | TASK | task args len `> 96` |

UDP telemetry: `"UAS1" | msgId | len_BE | payload` — nav / link / bay slots; `len > 256` or oversize slot crashes.

## VulnTurret (STT1 sentry station)

Banner: `STT1 SENTRY READY`. Frames: `type_u8 | rem_len_u16_BE | body`.

| Type | Kind | Crash when |
|------|------|------------|
| `0x01` | HELLO | station name len `> 64` |
| `0x02` | SLEW | az/el pair count `> 8` |
| `0x03` | TRACK | track blob len `> 128` |
| `0x04` | CONFIG | value len `> 96` or `__internal__*` oversize |

UDP telemetry: `"STT1" | msgId | len_BE | payload` — pose / track / health slots.

## Honest limits

- Loopback by default; do not expose on a public interface.
- Packets are deliberately **not** accepted by real UAS / GCS / sentry products.
- Do not treat crashes as evidence about commercial or military systems.
- Randfuzz will not ship weaponized vehicle control, fire-control payloads, or exploit templates for these labs.
