# Randall Process Plugins (RPP)

Polyglot plugins run as **child processes** and talk to Randall over **line-delimited JSON** on stdin/stdout. The C# core owns the fuzz loop; plugins extend mutation, observation, or triage without recompiling Randall.

## Manifest (`rpp.yaml`)

```yaml
name: xor-silly
runtime: python    # python | node | exe
entry: mutator.py
hook: mutate       # mutate | post_receive | post_crash
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

## Enable in a project

```yaml
plugins:
  - path: ../plugins/xor-silly
    hook: mutate
```

Randall adds `rpp:xor-silly` to the mutator pool alongside built-in strategies.

## Example: Python

See `plugins/xor-silly/mutator.py` — xor bytes, insert `%s` patterns, run-length expand.

Run standalone test:

```powershell
echo '{"op":"mutate","input":"QUFBQQ=="}' | python plugins/xor-silly/mutator.py
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
| `observe` | Custom coverage signal (planned) |
