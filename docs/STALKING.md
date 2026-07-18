# Stalking bugs — reference

**Start here for the research process:** [STALK_LOOP.md](STALK_LOOP.md) — baseline → basic fuzz → advanced → crash study → repeat.

This page is the short reference (UI tags, backends, API/CLI). Inspired by DynamoRIO drcov + Dynapstalker / PaiMei Pstalker: you only find bugs in code you execute.

---

## Where the loop runs

| Mode | Coverage layers + dumps | Notes |
|------|-------------------------|--------|
| **Lab host** (`randall serve` or `randall agent`, fuzz in that UI) | Full stalk loop | **Do this** for baseline / fuzzed / fuzzier |
| **Laptop + `target.agentUrl` only** | Process remote; coverage/dumps weak | Lifecycle control, not the stalk loop |

Details and click-path: [STALK_LOOP.md](STALK_LOOP.md). Offline dumps: [TARGET_RUNTIME.md](TARGET_RUNTIME.md)#remote-lab-workflow-dumps--lens--offline-import.

---

## Layer tags (Stalking bugs UI)

| Tag | Meaning |
|-----|---------|
| `baseline` | Normal use / happy path |
| `fuzzed` | First / basic fuzz campaign |
| `fuzzier` | Improved cases — record as many rounds as you want |
| `crash` | Path around a saved crash (often auto-recorded) |
| `custom` | Anything else (label it) |

Record via drcov path, crash id, or **From corpus edges**. Layers live under `data/stalk/<project>/`.

---

## Coverage backends (`fuzz.stalkMode`)

| Mode | Backend |
|------|---------|
| `auto` | DynamoRIO if installed, else **native PC stalk** |
| `external` | DynamoRIO drcov (full BB) |
| `native` | Debug-event PC samples → drcov-compatible log (coarse) |
| `none` | No coverage instrumentation |

Procmon bookends: `fuzz.procmonCapture: true` or the Fuzz tab checkbox.

---

## UI

**Stalking bugs** nav tab:

- Add layers: baseline / fuzzed / fuzzier / crash / custom  
- Compare deltas and block map  
- Export: IDA IDC, Ghidra script, raw edges  
- Tool status: DynamoRIO, native PC stalk, Scream, Procmon, WinDbg, remote agent  

---

## API

- `GET /api/stalking/{project}` — workspace  
- `POST /api/stalking/layers` — record layer  
- `POST /api/stalking/layers/from-crash` — `{ crashId, tag? }`  
- `POST /api/stalking/layers/from-corpus` — `{ project, tag? }`  
- `GET /api/stalking/{project}/compare`  
- `POST /api/stalking/export` — `{ project, layerIds, format: idc|ghidra|edges }`  
- `GET /api/remote/tools` · `POST /api/remote/procmon/start|stop` — lab agent  

---

## CLI

```
randall stalk layers -p <project>
randall stalk compare -p <project> [layerId…]
randall stalk export -p <project> --format idc|ghidra|edges [-o dir]
randall stalk from-crash -i <crash-guid> [--tag crash]
```

Fuzz campaigns auto-record a `crash` stalk layer when a crash is saved.

---

## Debugger attach / wait / analyze

For long-lived local targets (`target.longLived: true`):

| Mode | Behavior |
|------|----------|
| `none` | MiniDumpWriter on process exit (default) |
| `wait` | **Scream** → second-chance / fatal minidump → auto-analyze |
| `attach` | WinDbg / Preview attached with `g` |
| `both` | Scream wait during fuzz + open dump in GUI after crash |

```yaml
fuzz:
  debuggerMode: wait
  debuggerKind: windbg-preview
  debuggerOpenOnCrash: true
```

```
randall scream selftest
randall fuzz -c projects/vulnserver.yaml --debugger wait --open-on-crash
randall analyze -i <crash-guid>
randall memory -i <crash-guid>
```

---

## Related

- [STALK_LOOP.md](STALK_LOOP.md) — full process in research order  
- [TARGET_RUNTIME.md](TARGET_RUNTIME.md) · [LAB_AGENT.md](LAB_AGENT.md) · [CRASH_ANALYSIS.md](CRASH_ANALYSIS.md) · [CASE_BUILDER.md](CASE_BUILDER.md)
