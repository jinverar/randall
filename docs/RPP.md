# Randfuzz Process Plugins (RPP)

Polyglot plugins run as **child processes** and talk to Randfuzz over **line-delimited JSON** on stdin/stdout. The C# core owns the fuzz loop; plugins extend mutation, observation, or triage without recompiling Randfuzz.

## Manifest (`rpp.yaml`)

```yaml
name: xor-silly
runtime: python    # python | node | exe
entry: mutator.py
hook: mutate       # mutate | post_receive | post_crash | observe
```

## Wire protocol

**Request** (one JSON object per line):

```json
{"op":"mutate","input":"<base64 payload>"}
```

**Response**:

```json
{"output":"<base64 mutated>","name":"xor-silly"}
```

**post_receive request**:

```json
{"op":"post_receive","input":"<base64 sent>","response":"<base64 recv>"}
```

**post_receive response**:

```json
{"action":"continue","note":"logged_in","name":"ftp-response"}
```

`action` may be `continue` or `abort`.

**post_crash request**:

```json
{"op":"post_crash","input":"<base64 payload>","response":"<base64 recv>","exitCode":-1073741819,"signal":null}
```

**post_crash response**:

```json
{"tags":["overflow","access_violation"],"note":"heap smash","name":"crash-tag"}
```

Tags feed crash cluster metadata and web UI triage.

**observe request** (after each iteration — coverage/path/oracle already published):

```json
{"op":"observe","iteration":42,"input":"<base64>","newEdges":3,"totalEdges":120,"detail":"tcp ok"}
```

**observe response** — publish custom coverage novelty and/or fault hint:

```json
{"novelty":0.6,"confidence":0.7,"severity":"info","note":"+3 edges","name":"edge-observer"}
```

Or emit a fault-shaped signal (maps to `FaultSignal` + `ObservationKind.Fault`):

```json
{"signal":"sanitizer","confidence":0.85,"severity":"high","note":"saw ASan in detail","name":"edge-observer"}
```

## Enable in a project

```yaml
plugins:
  - path: ../plugins/xor-silly
    hook: mutate
  - path: ../plugins/edge-observer
    hook: observe
```

Randall adds `rpp:xor-silly` to the mutator pool alongside built-in strategies. `observe` plugins run through `RppObserveHook` and publish on the in-process **observation bus** (see [FAULT_SIGNALS.md](FAULT_SIGNALS.md)).

## Example: Python mutator

See `plugins/xor-silly/mutator.py` — xor bytes, insert `%s` patterns, run-length expand.

Run standalone test:

```powershell
echo '{"op":"mutate","input":"QUFBQQ=="}' | python plugins/xor-silly/mutator.py
```

## Example: observe observer

See `plugins/edge-observer/observer.py` — boosts novelty when `newEdges ≥ 3`, emits sanitizer fault when detail contains `asan`.

```powershell
echo '{"op":"observe","iteration":1,"input":"QUFB","newEdges":5,"totalEdges":40,"detail":""}' | python plugins/edge-observer/observer.py
```

## Runtimes

| Runtime | Command |
|---------|---------|
| `python` | `python.exe mutator.py` |
| `node` | `node.exe mutator.js` |
| `exe` | native binary (future) |

## Hooks

| Hook | Purpose |
|------|---------|
| `mutate` | Return mutated bytes |
| `post_receive` | Classify server response — continue or abort |
| `post_crash` | Tag/classify crash for triage |
| `observe` | Custom sensor — novelty and/or `FaultSignal` on the observation bus |

## Plugin model notes

- **Process boundary** — plugins never load into the fuzzer; JSON stdin/stdout keeps crashes isolated.
- **Hook = manifest + YAML ref** — same folder can ship multiple hooks by duplicating the plugin ref with different `hook:` overrides.
- **Observers are sensors** — they complement DynamoRIO/corpus stalking; they do not replace `FaultSignalMapper` on crashes.
- **External workers** (AFL++/LibAFL/WinAFL) use `IExternalWorkerIngest` instead of RPP — see [EXTERNAL_WORKERS.md](EXTERNAL_WORKERS.md).

## Related

- [FAULT_SIGNALS.md](FAULT_SIGNALS.md) — unified fault taxonomy
- [ORACLES.md](ORACLES.md) — oracle stack + observation bus
