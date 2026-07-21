# Mitigation Ladder + Vulnerable Services (Linux)

A graduated practice lab: the **same** vulnerable service compiled at rising exploit-mitigation
tiers, plus tooling to inspect mitigations and toggle ASLR/DEP. Designed for a basic → advanced
audience (buffer overflows → defeating NX/ASLR → modern hardened targets; PEN-301 → GXPN/SANS‑760).

> Authorized lab use only. These targets are intentionally vulnerable.

## Build the ladder

```bash
scripts/build-mitigation-lab.sh      # builds targets/vulnlab/vulnlab-{basic,nx,aslr,modern}
```

| Tier | Compile flags | Mitigations | What you practise |
|------|---------------|-------------|-------------------|
| **basic** | `-fno-stack-protector -z execstack -no-pie` | none (exec stack, no canary, no PIE) | classic saved-RIP overwrite, shellcode on stack |
| **nx** | `-fno-stack-protector -no-pie` | NX/DEP | ret2libc / ROP (no exec stack) |
| **aslr** | `-fno-stack-protector -fPIE -pie` | NX + PIE(ASLR) + full RELRO | add an info leak to beat ASLR |
| **modern** | `-fstack-protector-all -fPIE -pie -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -O2` | canary + NX + PIE + full RELRO + FORTIFY | everything on — leak + canary bypass |

## Inspect mitigations (checksec)

```bash
dotnet run --project src/Randall.Cli -- checksec --exe targets/vulnlab/vulnlab-modern
```

Reports NX/DEP, stack canary, PIE (ASLR-able), RELRO (none/partial/full), FORTIFY, an overall tier,
and the **current system ASLR** state.

## Toggle ASLR / DEP

- **ASLR** is a runtime kernel setting (`/proc/sys/kernel/randomize_va_space`): `2` full, `1` partial,
  `0` off.
  ```bash
  sudo sysctl kernel.randomize_va_space=0   # ASLR off (deterministic addresses for learning)
  sudo sysctl kernel.randomize_va_space=2   # ASLR on (full)
  setarch -R ./targets/vulnlab/vulnlab-aslr # disable ASLR for a single run only
  ```
- **DEP/NX** is a per-binary property — pick the tier: `vulnlab-basic` (NX off) vs `vulnlab-nx` (NX on).

## Fuzz a tier

```bash
# Default profile targets the basic tier (real SIGSEGV on overflow):
dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnlab.yaml
```

To fuzz a harder tier, point `projects/vulnlab.yaml` `target.executable` at `vulnlab-nx` / `-aslr` /
`-modern` (the modern tier trips the stack canary — `*** stack smashing detected ***` — instead of a
silent overwrite). Combine with `randall heaptriage` to classify heap-path crashes (`HEAP`/`DFREE`
commands → heap overflow / tcache double-free).

## Vulnerable services included

| Service | Kind | Profile | Notes |
|---------|------|---------|-------|
| **VulnLab** (native C) | TCP | `projects/vulnlab.yaml` | mitigation ladder; ECHO stack overflow, FMT format string, HEAP overflow, DFREE tcache double-free |
| **Vulnserver** (.NET) | TCP | `projects/vulnserver.yaml` | classic vulnserver command surface |
| **VulnHttp** (.NET) | TCP/HTTP | `projects/vulnhttp.yaml` | HTTP request fuzzing (modern web-server surface) |
| **VulnSmb** (.NET) | TCP | `projects/vulnsmb.yaml` | NBSS + SMB2-shaped (SMB/Samba-style protocol fuzzing) |
| **VulnFtp / VulnTftp / VulnSsh / VulnRpc** (.NET) | TCP/UDP | `projects/vuln*.yaml` | additional protocol surfaces |

Build the .NET services on Linux with `scripts/build-lab-targets.sh [name]`; build the native
VulnLab with `scripts/build-mitigation-lab.sh`.

> **Roadmap:** heavier real-world labs (a full Samba container, and modern web app labs such as
> DVWA / OWASP Juice Shop / a `vulnweb`-style stack) are best run as separate Docker services and
> pointed at via a TCP/HTTP profile — a `docker-compose` lab bundle is planned.
