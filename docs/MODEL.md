# Leg 1 — Block models (Sulley / Boofuzz style)

Randall describes **valid-ish message structure** with YAML block definitions. Mutations target **named mutable fields** instead of random byte soup.

## Protocol file (`projects/protocols/*.yaml`)

```yaml
name: vulnserver-trun
description: TRUN command
blocks:
  - type: static
    value: "TRUN /.:/"
  - type: bytes
    name: payload
    mutable: true
    minSize: 4
    maxSize: 8192
    seedFile: seeds/vulnserver_trun.txt
```

## Length-prefixed frames (Phase 6)

Classic **length + payload** layout — mutate the length field separately from the body (off-by-one, integer overflow):

```yaml
- type: sized
  lengthName: frame_len
  lengthBytes: 4        # 2 or 4
  littleEndian: true
  child:
    type: bytes
    name: payload
    seedFile: seeds/file_framed_record.bin
```

## Block types

| Type | Purpose |
|------|---------|
| `static` | Fixed bytes (command prefix, headers) |
| `string` | Mutable text field (boofuzz `String`) |
| `delim` | Separator — space, CRLF token (boofuzz `Delim`) |
| `choices` | Pick one of several values (boofuzz `Group`) |
| `word` / `dword` / `qword` | Fixed-width integers with endianness |
| `bytes` | Mutable binary payload with optional seed file |
| `sized` | Length prefix + nested payload (field-aware) |
| `checksum` | CRC32 over preceding bytes (auto-resync after mutation) |
| `group` | Nested children |

## Use in projects

**TCP session command:**
```yaml
sessionCommands:
  - name: TRUN
    model: protocols/vulnserver_trun.yaml
```

**File target:**
```yaml
model: protocols/file_text.yaml
```

Fuzz iterations render the model, pick a **mutable field** (length or payload), and apply built-in or RPP mutators.

## Session graph (boofuzz s_switch)

Branch TCP/UDP sessions on **live server responses** instead of fixed linear flows:

```yaml
sessionGraph:
  start: USER          # first command sent
  mutate: STOR         # which step receives mutations
  edges:
    - { from: USER, when: "331", to: PASS }
    - { from: PASS, when: "230", to: STOR }
    - { from: PASS, when: "230", to: RETR }
```

- `when` matches if the response **contains** the string (FTP codes, HTTP status, etc.)
- `fuzz.sessionGraphBias` controls how often graph mode runs vs linear `sessionFlows`
- Validate and export Mermaid: `randall graph -c projects/vulnftp.yaml`

## Bundles

```powershell
randall bundle export -c projects/vulnserver.yaml -o bundles/vulnserver.zip
randall bundle import -i bundles/vulnserver.zip -o projects/imported
```

## API / UI

- `GET /api/protocols` — list models and field map
- Web UI → **Models** tab

See also [LEGS.md](LEGS.md#leg-1--model-protocol-grammar).
