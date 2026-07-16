# Boofuzz parity matrix

Randall vs [boofuzz](https://github.com/jtpereyda/boofuzz) — *Randall kidnapped Boo.*

| Boofuzz | Randall (Phase 10+) | Status |
|---------|---------------------|--------|
| `String`, `Delim`, `Static` | `string`, `delim`, `static` YAML blocks | ✅ |
| `Word`, `DWord`, `QWord` | `word`, `dword`, `qword` | ✅ |
| `Group` (choices) | `choices` block | ✅ |
| `Bytes`, `Sized`, checksum | `bytes`, `sized`, `checksum` | ✅ |
| `session.connect()` DAG | `sessionFlows` + `mutateStep` | ✅ partial |
| `session.fuzz()` exhaustive | `fuzz.mode: exhaustive` | ✅ |
| Mutate any request in chain | `mutateStep: all` / indices | ✅ |
| `TCPSocketConnection` | `kind: tcp` | ✅ |
| UDP | `kind: udp` | ✅ |
| SSL/TLS | `transport.tls: true` | ✅ |
| ProcessMonitor | `ProcessMonitor` + longLived restart | ✅ |
| Response validation | `expectResponse` on session commands | ✅ |
| post_receive plugins | RPP `post_receive` hook | ✅ |
| Boofuzz importer | `scripts/import-boofuzz.py` | ✅ |
| Web UI | `randall serve` | ✅ Randall ahead |
| Coverage | DynamoRIO (file + planned TCP) | ✅ partial |
| Examples folder | `examples/` | ✅ |
| FTP example | `examples/ftp-simple` + `vulnftp` | ✅ |
| HTTP example | `examples/http-simple` + `vulnhttp` | ✅ |

## Randall beats boofuzz

- Native C# — faster iteration, single binary deploy
- Havoc, splice, power schedule, corpus energy
- Crash clusters, Ghidra export, minidumps
- MITM proxy tab, lab agent, campaigns
- Coverage-guided file fuzz (DynamoRIO)

## Still planned

- Response-driven `s_switch` branching (full graph)
- RPP `post_crash` triage hook
- Boofuzz Python → YAML importer (complex scripts)
- Coverage on TCP lab servers
