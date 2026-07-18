# Custom targets — YAML → Target profile

Once you add a project YAML under `projects/` or `projects/local/`, Randfuzz discovers it and shows the YAML **`name:`** field in the web UI **Target profile** dropdown (and in `randall targets`).

```
projects/my-thing.yaml     →  Target profile: my-thing
projects/local/foo.yaml    →  Target profile: foo   (gitignored private lab)
```

The file name is only a fallback if `name:` is missing. Prefer setting `name:` explicitly.

## Quick path (UI)

1. **Fuzz → Case builder → New project** — pick `tcp` / `udp` / `file`, host:port, optional exe.
2. YAML is written (default: `projects/local/{name}.yaml`).
3. Refresh / reopen Target profile — your name appears.
4. Build a seed (blocks → Preview → Save as seed), enable mutators (include `dictionary` if you saved tokens).
5. **Fuzz → Campaign** → select that profile → Start.

## Quick path (files + CLI)

```powershell
# Copy a template
copy docs\templates\tcp.yaml projects\local\myservice.yaml
# or: copy projects\_TEMPLATE_tcp.yaml projects\local\myservice.yaml
# Edit name:, host, port, seeds…

randall case new --name myservice --kind tcp --host 10.0.0.5 --port 8080
randall targets
randall fuzz -c projects/local/myservice.yaml --dry-run
randall fuzz -c projects/local/myservice.yaml
```

## Minimal TCP (remote service — no local binary)

```yaml
name: myservice          # ← appears in Target profile
description: Remote HTTP on lab VM
kind: tcp
target:
  executable: ""         # empty = do not spawn a process
  longLived: false
  timeoutMs: 5000
transport:
  type: tcp
  host: 10.0.0.5
  port: 8080
  receiveTimeoutMs: 2000
fuzz:
  maxIterations: 500
  corpusDir: ../data/corpus/myservice
  crashesDir: ../data/crashes/myservice
mutators:
  - bitflip
  - havoc
  - dictionary
  - expand
seeds:
  - seeds/myservice_seed.bin
dictionaryFile: dictionaries/myservice.txt
```

Start the remote program yourself (other host / VM). Randfuzz only sends mutated seeds to `host:port`.

## Local long-lived binary

```yaml
name: mylocal
kind: tcp
target:
  executable: ../targets/local/myapp.exe
  longLived: true        # Randall starts/restarts the process
  timeoutMs: 5000
transport:
  type: tcp
  host: 127.0.0.1
  port: 9999
# … seeds + mutators as above
```

## File targets

```yaml
name: myparser
kind: file
target:
  executable: ../targets/local/parser.exe
  args:
    - "{file}"           # fuzzer writes the case to a temp file
  timeoutMs: 8000
transport:
  type: file
  extension: .bin
```

Enable `fuzz.coverageGuided: true` when DynamoRIO is set up (see [FUZZING.md](FUZZING.md)).

## Where mutations come from

| Piece | Role |
|-------|------|
| **Seeds** | Valid-ish starting inputs (AFL `in/`) — Case builder or `seeds/` |
| **Dictionary** | Tokens injected by the `dictionary` mutator |
| **Mutators** | `bitflip`, `havoc`, `interesting`, `dictionary`, `expand`, … |
| **Protocol models** | Optional field-aware generators under `projects/protocols/` |

The Campaign tab does **not** type characters by hand. It mutates seeds according to the mutator list.

## Discovery rules

- Scanned: `projects/*.yaml`, `projects/*.yml`, `projects/local/*.{yaml,yml}`, `examples/*/project.yaml`
- Not auto-listed: nested dirs like `projects/protocols/*.yaml` (those are **models**, not full campaigns)
- Private lab: keep secrets under `projects/local/` and `targets/local/` (gitignored)

## Checklist before first live run

1. `randall doctor -c projects/local/myservice.yaml`
2. `randall fuzz -c … --dry-run` — confirms seeds load and mutators run
3. For remote: service listening on host:port
4. For local: executable path resolves; firewall allows loopback
5. Case builder seed saved and listed under `seeds:`

See also [CASE_BUILDER.md](CASE_BUILDER.md), [TARGETS.md](TARGETS.md), [FUZZING.md](FUZZING.md).
