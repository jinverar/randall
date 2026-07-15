# Randall Process Plugins (RPP)

Polyglot plugins run as **child processes** and talk to Randall over **line-delimited JSON** on stdin/stdout. The C# core owns the fuzz loop; plugins extend mutation, observation, or triage without recompiling Randall.

## Manifest (`rpp.yaml`)

```yaml
name: xor-silly
runtime: python    # python | node | exe
entry: mutator.py
hook: mutate       # mutate | post_crash (post_crash planned)
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

## Hooks (roadmap)

| Hook | Purpose |
|------|---------|
| `mutate` | Return mutated bytes |
| `post_crash` | Triage / classify crash (planned) |
| `observe` | Custom coverage signal (planned) |
